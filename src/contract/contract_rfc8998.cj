package jinguissl.contract

import std.collection.ArrayList
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKeyFromUncompressed, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.sm3.sm3
import jinguissl_core.crypto.tls.*

public let CONTRACT_RFC8998_SM4_GCM_SM3: Int64 = 0x00c6
public let CONTRACT_RFC8998_SM4_CCM_SM3: Int64 = 0x00c7
public let CONTRACT_RFC8998_SM2_SM3: Int64 = 0x0708
public let CONTRACT_RFC8998_CURVE_SM2: Int64 = 41
public let CONTRACT_RFC8998_SM2_SIGNATURE_IDENTITY: String = "TLSv1.3+GM+Cipher+Suite"

public enum ContractGmTlsContentType <: Equatable<ContractGmTlsContentType> & ToString {
    | ChangeCipherSpec
    | Alert
    | Handshake
    | ApplicationData

    public operator func ==(right: ContractGmTlsContentType): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case ChangeCipherSpec => 0
            case Alert => 1
            case Handshake => 2
            case ApplicationData => 3
        }
    }

    public func toString(): String {
        match (this) {
            case ChangeCipherSpec => "change_cipher_spec"
            case Alert => "alert"
            case Handshake => "handshake"
            case ApplicationData => "application_data"
        }
    }
}

public class ContractRfc8998HelloPair {
    public let clientHello: Array<Byte>
    public let serverHello: Array<Byte>
    public let selectedCipherSuite: Int64
    public let transcriptHash: Array<Byte>
    public let clientPublicKey: Array<Byte>
    public let serverPublicKey: Array<Byte>

    public init(
        clientHello: Array<Byte>,
        serverHello: Array<Byte>,
        selectedCipherSuite: Int64,
        transcriptHash: Array<Byte>,
        clientPublicKey: Array<Byte>,
        serverPublicKey: Array<Byte>
    ) {
        if (clientHello.size == 0 || serverHello.size == 0) {
            throw ContractException(ContractErrorCode.BadInput, "RFC8998 hello messages must not be empty")
        }
        if (transcriptHash.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "RFC8998 transcript hash must be 32 bytes")
        }
        this.clientHello = clientHello.clone()
        this.serverHello = serverHello.clone()
        this.selectedCipherSuite = selectedCipherSuite
        this.transcriptHash = transcriptHash.clone()
        this.clientPublicKey = clientPublicKey.clone()
        this.serverPublicKey = serverPublicKey.clone()
    }
}

/** Opaque RFC 8998 key schedule with no exported Core or raw-key type. */
public class ContractRfc8998Secrets {
    internal let coreSecrets: Tls13HandshakeSecrets
    public let cipherSuite: Int64
    public let hashAlgorithm: String = "SM3"
    public let writeKeyLen: Int64
    public let writeIvLen: Int64

    internal init(coreSecrets: Tls13HandshakeSecrets, cipherSuite: Int64) {
        this.coreSecrets = coreSecrets
        this.cipherSuite = cipherSuite
        this.writeKeyLen = coreSecrets.clientWriteKey.size
        this.writeIvLen = coreSecrets.clientWriteIv.size
    }

    public func finishedVerifyData(
        transcriptHash: Array<Byte>, client!: Bool = true
    ): Array<Byte> {
        let baseSecret = if (client) {
            coreSecrets.clientHsTrafficSecret
        } else {
            coreSecrets.serverHsTrafficSecret
        }
        try {
            tls13ComputeFinishedVerifyDataForCipherSuite(
                baseSecret, transcriptHash, cipherSuite
            )
        } catch (e: CryptoException) {
            throw contractRfc8998Exception(e, "RFC8998 Finished computation")
        }
    }
}

public class ContractRfc8998PlainRecord {
    public let contentType: ContractGmTlsContentType
    public let fragment: Array<Byte>

    public init(contentType: ContractGmTlsContentType, fragment: Array<Byte>) {
        this.contentType = contentType
        this.fragment = fragment.clone()
    }
}

/** Stateful TLS 1.3 SM4 record endpoint. One instance must not be shared concurrently. */
public class ContractRfc8998RecordLayer {
    private let coreLayer: Tls13RecordLayerHandle
    public let cipherSuite: Int64
    public let clientRole: Bool

    internal init(coreLayer: Tls13RecordLayerHandle, cipherSuite: Int64, clientRole: Bool) {
        this.coreLayer = coreLayer
        this.cipherSuite = cipherSuite
        this.clientRole = clientRole
    }

    public func seal(
        contentType: ContractGmTlsContentType, plaintext: Array<Byte>
    ): Array<Byte> {
        try {
            coreLayer.seal(contractRfc8998CoreContentType(contentType), plaintext)
        } catch (e: CryptoException) {
            throw contractRfc8998Exception(e, "RFC8998 record sealing")
        }
    }

    public func open(encodedRecord: Array<Byte>): ContractRfc8998PlainRecord {
        try {
            let opened = coreLayer.open(encodedRecord)
            ContractRfc8998PlainRecord(
                contractRfc8998ContentType(opened.contentType), opened.fragment
            )
        } catch (e: CryptoException) {
            throw contractRfc8998VerifyException(e, "RFC8998 record opening")
        }
    }

    public func resetSequences(): Unit {
        try {
            coreLayer.resetSequences()
        } catch (e: CryptoException) {
            throw contractRfc8998Exception(e, "RFC8998 record sequence reset")
        }
    }
}

public func contractRfc8998BuildClientHello(
    clientPublicKey: Array<Byte>,
    cipherSuites!: Array<Int64> = [
        CONTRACT_RFC8998_SM4_GCM_SM3, CONTRACT_RFC8998_SM4_CCM_SM3
    ],
    sessionId!: Array<Byte> = []
): Array<Byte> {
    try {
        tls13BuildClientHelloSm2(
            sm2PublicKeyFromUncompressed(clientPublicKey),
            cipherSuites: cipherSuites,
            sessionId: sessionId
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 ClientHello building")
    }
}

public func contractRfc8998BuildServerHello(
    clientHello: Array<Byte>, serverPublicKey: Array<Byte>
): Array<Byte> {
    try {
        tls13BuildServerHelloForSm2(
            clientHello, sm2PublicKeyFromUncompressed(serverPublicKey)
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 ServerHello building")
    }
}

public func contractRfc8998ExtractClientKeyShare(clientHello: Array<Byte>): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(tls13ExtractClientSm2KeyShare(clientHello))
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 client key-share extraction")
    }
}

public func contractRfc8998ExtractServerKeyShare(serverHello: Array<Byte>): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(tls13ExtractServerSm2KeyShare(serverHello))
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 server key-share extraction")
    }
}

public func contractRfc8998SelectedCipherSuite(serverHello: Array<Byte>): Int64 {
    try {
        let suite = tlsDecodeServerHelloHandshake(serverHello).cipherSuite
        _ = tls13CipherSuiteAeadAlgorithm(suite)
        if (
            suite != CONTRACT_RFC8998_SM4_GCM_SM3 &&
            suite != CONTRACT_RFC8998_SM4_CCM_SM3
        ) {
            throw ContractException(
                ContractErrorCode.Unsupported, "server did not select an RFC8998 cipher suite"
            )
        }
        suite
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 cipher-suite extraction")
    }
}

public func contractRfc8998BuildHelloPair(
    clientPublicKey: Array<Byte>,
    serverPublicKey: Array<Byte>,
    cipherSuites!: Array<Int64> = [
        CONTRACT_RFC8998_SM4_GCM_SM3, CONTRACT_RFC8998_SM4_CCM_SM3
    ]
): ContractRfc8998HelloPair {
    let clientHello = contractRfc8998BuildClientHello(
        clientPublicKey, cipherSuites: cipherSuites
    )
    let serverHello = contractRfc8998BuildServerHello(clientHello, serverPublicKey)
    ContractRfc8998HelloPair(
        clientHello,
        serverHello,
        contractRfc8998SelectedCipherSuite(serverHello),
        contractRfc8998TranscriptHash([clientHello, serverHello]),
        contractRfc8998ExtractClientKeyShare(clientHello),
        contractRfc8998ExtractServerKeyShare(serverHello)
    )
}

public func contractRfc8998TranscriptHash(messages: Array<Array<Byte>>): Array<Byte> {
    let buffer = ArrayList<Byte>()
    for (message in messages) {
        for (value in message) { buffer.add(value) }
    }
    sm3(buffer.toArray())
}

public func contractRfc8998DeriveSecrets(
    privateKey: Array<Byte>,
    peerPublicKey: Array<Byte>,
    transcriptHash: Array<Byte>,
    cipherSuite: Int64,
    appTranscriptHash!: Array<Byte> = []
): ContractRfc8998Secrets {
    try {
        ContractRfc8998Secrets(
            tls13DeriveSecretsFromSm2ForCipherSuite(
                contractRfc8998PrivateKey(privateKey),
                sm2PublicKeyFromUncompressed(peerPublicKey),
                transcriptHash,
                cipherSuite,
                appTranscriptHash: appTranscriptHash
            ),
            cipherSuite
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 key-schedule derivation")
    }
}

public func contractRfc8998CreateClientRecordLayer(
    secrets: ContractRfc8998Secrets
): ContractRfc8998RecordLayer {
    try {
        ContractRfc8998RecordLayer(
            tls13CreateClientRecordLayerHandle(secrets.coreSecrets, secrets.cipherSuite),
            secrets.cipherSuite,
            true
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 client record-layer creation")
    }
}

public func contractRfc8998CreateServerRecordLayer(
    secrets: ContractRfc8998Secrets
): ContractRfc8998RecordLayer {
    try {
        ContractRfc8998RecordLayer(
            tls13CreateServerRecordLayerHandle(secrets.coreSecrets, secrets.cipherSuite),
            secrets.cipherSuite,
            false
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 server record-layer creation")
    }
}

public func contractRfc8998BuildServerCertificateVerify(
    privateKey: Array<Byte>, transcriptHash: Array<Byte>
): Array<Byte> {
    try {
        tls13BuildServerCertificateVerifySm2(
            contractRfc8998PrivateKey(privateKey), transcriptHash
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 server CertificateVerify building")
    }
}

public func contractRfc8998BuildClientCertificateVerify(
    privateKey: Array<Byte>, transcriptHash: Array<Byte>
): Array<Byte> {
    try {
        tls13BuildClientCertificateVerifySm2(
            contractRfc8998PrivateKey(privateKey), transcriptHash
        )
    } catch (e: CryptoException) {
        throw contractRfc8998Exception(e, "RFC8998 client CertificateVerify building")
    }
}

public func contractRfc8998VerifyServerCertificateVerify(
    encoded: Array<Byte>, publicKey: Array<Byte>, transcriptHash: Array<Byte>
): Bool {
    try {
        tls13VerifyServerCertificateVerifySm2(
            encoded, sm2PublicKeyFromUncompressed(publicKey), transcriptHash
        )
    } catch (e: CryptoException) {
        throw contractRfc8998VerifyException(e, "RFC8998 server CertificateVerify")
    }
}

public func contractRfc8998VerifyClientCertificateVerify(
    encoded: Array<Byte>, publicKey: Array<Byte>, transcriptHash: Array<Byte>
): Bool {
    try {
        tls13VerifyClientCertificateVerifySm2(
            encoded, sm2PublicKeyFromUncompressed(publicKey), transcriptHash
        )
    } catch (e: CryptoException) {
        throw contractRfc8998VerifyException(e, "RFC8998 client CertificateVerify")
    }
}

private func contractRfc8998PrivateKey(encoded: Array<Byte>): Sm2PrivateKey {
    if (encoded.size != CONTRACT_SM2_PRIVATE_KEY_LEN) {
        throw ContractException(ContractErrorCode.BadInput, "SM2 private key must be 32 bytes")
    }
    Sm2PrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractRfc8998CoreContentType(
    value: ContractGmTlsContentType
): TlsContentType {
    match (value) {
        case ContractGmTlsContentType.ChangeCipherSpec => TlsContentType.ChangeCipherSpec
        case ContractGmTlsContentType.Alert => TlsContentType.Alert
        case ContractGmTlsContentType.Handshake => TlsContentType.Handshake
        case ContractGmTlsContentType.ApplicationData => TlsContentType.ApplicationData
    }
}

private func contractRfc8998ContentType(value: TlsContentType): ContractGmTlsContentType {
    match (value) {
        case TlsContentType.ChangeCipherSpec => ContractGmTlsContentType.ChangeCipherSpec
        case TlsContentType.Alert => ContractGmTlsContentType.Alert
        case TlsContentType.Handshake => ContractGmTlsContentType.Handshake
        case TlsContentType.ApplicationData => ContractGmTlsContentType.ApplicationData
    }
}

private func contractRfc8998VerifyException(
    error: CryptoException, operation: String
): ContractException {
    if (error.code == CryptoErrorCode.InvalidArgument && error.message.contains("must")) {
        return ContractException(ContractErrorCode.BadInput, "${operation} failed: ${error.message}")
    }
    ContractException(ContractErrorCode.VerifyFailed, "${operation} failed: ${error.message}")
}

private func contractRfc8998Exception(error: CryptoException, operation: String): ContractException {
    let code = match (error.code) {
        case CryptoErrorCode.InvalidArgument => ContractErrorCode.BadInput
        case CryptoErrorCode.OutOfBounds => ContractErrorCode.BadInput
        case CryptoErrorCode.DivideByZero => ContractErrorCode.BadInput
        case CryptoErrorCode.NoModInverse => ContractErrorCode.BadInput
        case CryptoErrorCode.ParseError => ContractErrorCode.BadInput
        case CryptoErrorCode.ComplianceRejected => ContractErrorCode.ComplianceRejected
        case CryptoErrorCode.Unsupported => ContractErrorCode.Unsupported
        case CryptoErrorCode.InternalError => ContractErrorCode.InternalError
        case _ => ContractErrorCode.InternalError
    }
    ContractException(code, "${operation} failed: ${error.message}")
}
