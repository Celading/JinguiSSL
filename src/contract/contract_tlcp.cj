package jinguissl.contract

import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.error.{CryptoErrorCode, CryptoException}
import jinguissl_core.crypto.sm2.{Sm2PrivateKey, sm2PublicKeyFromUncompressed, sm2PublicKeyToUncompressed}
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x509.{X509Certificate, X509VerificationPolicy, x509ParseDer, x509ParsePem, x509ParsePemChain}

public let CONTRACT_TLCP_VERSION: Int64 = 0x0101
public let CONTRACT_TLCP_SM2_NAMED_GROUP: Int64 = 41
public let CONTRACT_TLCP_PREMASTER_SECRET_LEN: Int64 = 48
public let CONTRACT_TLCP_FINISHED_VERIFY_DATA_LEN: Int64 = 12
public let CONTRACT_DTLCP_REPLAY_WINDOW_SIZE: Int64 = 64

public enum ContractTlcpCipherSuite <: Equatable<ContractTlcpCipherSuite> & ToString {
    | EcdheSm4CbcSm3
    | EccSm4CbcSm3
    | EcdheSm4GcmSm3
    | EccSm4GcmSm3

    public operator func ==(right: ContractTlcpCipherSuite): Bool {
        ordinalValue() == right.ordinalValue()
    }

    public func ordinalValue(): Int64 {
        match (this) {
            case EcdheSm4CbcSm3 => 0
            case EccSm4CbcSm3 => 1
            case EcdheSm4GcmSm3 => 2
            case EccSm4GcmSm3 => 3
        }
    }

    public func wireValue(): Int64 {
        match (this) {
            case EcdheSm4CbcSm3 => 0xe011
            case EccSm4CbcSm3 => 0xe013
            case EcdheSm4GcmSm3 => 0xe051
            case EccSm4GcmSm3 => 0xe053
        }
    }

    public func usesEcdhe(): Bool {
        this == EcdheSm4CbcSm3 || this == EcdheSm4GcmSm3
    }

    public func usesGcm(): Bool {
        this == EcdheSm4GcmSm3 || this == EccSm4GcmSm3
    }

    public func toString(): String {
        match (this) {
            case EcdheSm4CbcSm3 => "TLCP_ECDHE_SM4_CBC_SM3"
            case EccSm4CbcSm3 => "TLCP_ECC_SM4_CBC_SM3"
            case EcdheSm4GcmSm3 => "TLCP_ECDHE_SM4_GCM_SM3"
            case EccSm4GcmSm3 => "TLCP_ECC_SM4_GCM_SM3"
        }
    }
}

public func contractTlcpDefaultCipherSuites(): Array<ContractTlcpCipherSuite> {
    [EcdheSm4CbcSm3, EccSm4CbcSm3, EcdheSm4GcmSm3, EccSm4GcmSm3]
}

public class ContractTlcpHelloSummary {
    public let random: Array<Byte>
    public let sessionId: Array<Byte>
    public let offeredCipherSuites: Array<ContractTlcpCipherSuite>
    public let selectedCipherSuite: ?ContractTlcpCipherSuite

    public init(
        random: Array<Byte>,
        sessionId: Array<Byte>,
        offeredCipherSuites!: Array<ContractTlcpCipherSuite> = [],
        selectedCipherSuite!: ?ContractTlcpCipherSuite = None
    ) {
        if (random.size != 32) {
            throw ContractException(ContractErrorCode.BadInput, "TLCP hello random must be 32 bytes")
        }
        this.random = random.clone()
        this.sessionId = sessionId.clone()
        this.offeredCipherSuites = offeredCipherSuites.clone()
        this.selectedCipherSuite = selectedCipherSuite
    }
}

public class ContractTlcpDualCertificateResult {
    public let signingCertificate: ContractGmCertificate
    public let encryptionCertificate: ContractGmCertificate
    public let signingChainLength: Int64
    public let encryptionChainLength: Int64

    public init(
        signingCertificate: ContractGmCertificate,
        encryptionCertificate: ContractGmCertificate,
        signingChainLength: Int64,
        encryptionChainLength: Int64
    ) {
        this.signingCertificate = signingCertificate
        this.encryptionCertificate = encryptionCertificate
        this.signingChainLength = signingChainLength
        this.encryptionChainLength = encryptionChainLength
    }
}

public class ContractTlcpClientKeyExchange {
    public let encoded: Array<Byte>
    public let preMasterSecret: Array<Byte>

    public init(encoded: Array<Byte>, preMasterSecret: Array<Byte>) {
        if (encoded.size == 0 || preMasterSecret.size != CONTRACT_TLCP_PREMASTER_SECRET_LEN) {
            throw ContractException(ContractErrorCode.BadInput, "TLCP ClientKeyExchange material is invalid")
        }
        this.encoded = encoded.clone()
        this.preMasterSecret = preMasterSecret.clone()
    }
}

/** Opaque TLCP key schedule shared by TLCP and DTLCP record endpoints. */
public class ContractTlcpSecrets {
    internal let coreSecrets: TlcpHandshakeSecrets
    public let cipherSuite: ContractTlcpCipherSuite
    public let masterSecretLen: Int64
    public let writeKeyLen: Int64
    public let writeIvLen: Int64

    internal init(coreSecrets: TlcpHandshakeSecrets) {
        this.coreSecrets = coreSecrets
        this.cipherSuite = contractTlcpSuite(coreSecrets.cipherSuite)
        this.masterSecretLen = coreSecrets.masterSecret.size
        this.writeKeyLen = coreSecrets.clientWriteKey.size
        this.writeIvLen = coreSecrets.clientWriteIv.size
    }

    public func buildFinished(
        handshakeTranscript: Array<Byte>, client!: Bool = true
    ): Array<Byte> {
        try {
            tlcpBuildFinishedHandshake(
                coreSecrets.masterSecret, handshakeTranscript, client
            )
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "TLCP Finished building")
        }
    }

    public func verifyFinished(
        encodedFinished: Array<Byte>,
        handshakeTranscript: Array<Byte>,
        client!: Bool = true
    ): Unit {
        try {
            tlcpVerifyFinishedHandshake(
                encodedFinished, coreSecrets.masterSecret, handshakeTranscript, client
            )
        } catch (e: CryptoException) {
            throw contractTlcpVerifyException(e, "TLCP Finished verification")
        }
    }
}

public class ContractTlcpPlainRecord {
    public let contentType: ContractGmTlsContentType
    public let fragment: Array<Byte>

    public init(contentType: ContractGmTlsContentType, fragment: Array<Byte>) {
        this.contentType = contentType
        this.fragment = fragment.clone()
    }
}

public class ContractTlcpRecordLayer {
    private let coreLayer: TlcpRecordLayer
    public let cipherSuite: ContractTlcpCipherSuite
    public let clientRole: Bool

    internal init(coreLayer: TlcpRecordLayer, clientRole: Bool) {
        this.coreLayer = coreLayer
        this.cipherSuite = contractTlcpSuite(coreLayer.cipherSuite)
        this.clientRole = clientRole
    }

    public prop writeSequence: Int64 { get() { coreLayer.writeSequence } }
    public prop readSequence: Int64 { get() { coreLayer.readSequence } }

    public func seal(
        contentType: ContractGmTlsContentType, plaintext: Array<Byte>
    ): Array<Byte> {
        try {
            coreLayer.seal(contractTlcpCoreContentType(contentType), plaintext)
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "TLCP record sealing")
        }
    }

    public func open(encoded: Array<Byte>): ContractTlcpPlainRecord {
        try {
            let opened = coreLayer.open(encoded)
            ContractTlcpPlainRecord(
                contractTlcpContentType(opened.contentType), opened.fragment
            )
        } catch (e: CryptoException) {
            throw contractTlcpVerifyException(e, "TLCP record opening")
        }
    }
}

public func contractTlcpBuildClientHello(
    cipherSuites!: Array<ContractTlcpCipherSuite> = contractTlcpDefaultCipherSuites(),
    sessionId!: Array<Byte> = []
): Array<Byte> {
    try {
        let suites = Array<TlcpCipherSuite>(cipherSuites.size, repeat: TlcpCipherSuite.ECDHE_SM4_CBC_SM3)
        var i: Int64 = 0
        while (i < cipherSuites.size) {
            suites[i] = contractTlcpCoreSuite(cipherSuites[i])
            i += 1
        }
        tlcpBuildClientHello(cipherSuites: suites, sessionId: sessionId)
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ClientHello building")
    }
}

public func contractTlcpBuildServerHello(
    clientHello: Array<Byte>,
    supportedSuites!: Array<ContractTlcpCipherSuite> = contractTlcpDefaultCipherSuites()
): Array<Byte> {
    try {
        let suites = Array<TlcpCipherSuite>(
            supportedSuites.size, repeat: TlcpCipherSuite.ECDHE_SM4_CBC_SM3
        )
        var i: Int64 = 0
        while (i < supportedSuites.size) {
            suites[i] = contractTlcpCoreSuite(supportedSuites[i])
            i += 1
        }
        tlcpBuildServerHello(clientHello, supportedSuites: suites)
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ServerHello building")
    }
}

public func contractTlcpDecodeClientHello(encoded: Array<Byte>): ContractTlcpHelloSummary {
    try {
        let hello = tlcpDecodeClientHello(encoded)
        let suites = Array<ContractTlcpCipherSuite>(
            hello.cipherSuites.size, repeat: EcdheSm4CbcSm3
        )
        var i: Int64 = 0
        while (i < hello.cipherSuites.size) {
            suites[i] = contractTlcpSuite(hello.cipherSuites[i])
            i += 1
        }
        ContractTlcpHelloSummary(hello.random, hello.sessionId, offeredCipherSuites: suites)
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ClientHello parsing")
    }
}

public func contractTlcpDecodeServerHello(encoded: Array<Byte>): ContractTlcpHelloSummary {
    try {
        let hello = tlcpDecodeServerHello(encoded)
        ContractTlcpHelloSummary(
            hello.random,
            hello.sessionId,
            selectedCipherSuite: Some(contractTlcpSuite(hello.cipherSuite))
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ServerHello parsing")
    }
}

public func contractTlcpBuildDualCertificateHandshake(
    signingCertificateDer: Array<Byte>,
    encryptionCertificateDer: Array<Byte>,
    intermediateDer!: Array<Array<Byte>> = []
): Array<Byte> {
    try {
        tlcpBuildDualCertificateHandshake(
            signingCertificateDer, encryptionCertificateDer, intermediateDer: intermediateDer
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP dual-certificate handshake building")
    }
}

public func contractTlcpVerifyDualCertificateHandshake(
    encoded: Array<Byte>,
    trustAnchorsPem: String,
    validationTime!: String = ""
): ContractTlcpDualCertificateResult {
    try {
        let bundle = tlcpParseDualCertificateHandshake(encoded)
        let verified = tlcpVerifyDualCertificateBundle(
            bundle,
            X509VerificationPolicy(
                x509ParsePemChain(trustAnchorsPem), validationTime: validationTime
            )
        )
        ContractTlcpDualCertificateResult(
            contractTlcpCertificate(bundle.signingCertificate),
            contractTlcpCertificate(bundle.encryptionCertificate),
            verified.signingResult.chain.size,
            verified.encryptionResult.chain.size
        )
    } catch (e: CryptoException) {
        throw contractTlcpVerifyException(e, "TLCP dual-certificate verification")
    }
}

public func contractTlcpBuildStaticServerKeyExchange(
    signingPrivateKey: Array<Byte>,
    encryptionCertificatePem: String,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): Array<Byte> {
    try {
        tlcpBuildEccServerKeyExchange(
            contractTlcpPrivateKey(signingPrivateKey),
            x509ParsePem(encryptionCertificatePem),
            clientRandom,
            serverRandom,
            signerIdentity: signerIdentity
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP static ServerKeyExchange building")
    }
}

public func contractTlcpVerifyStaticServerKeyExchange(
    encoded: Array<Byte>,
    signingCertificatePem: String,
    encryptionCertificatePem: String,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): Unit {
    try {
        tlcpVerifyEccServerKeyExchange(
            encoded,
            x509ParsePem(signingCertificatePem),
            x509ParsePem(encryptionCertificatePem),
            clientRandom,
            serverRandom,
            signerIdentity: signerIdentity
        )
    } catch (e: CryptoException) {
        throw contractTlcpVerifyException(e, "TLCP static ServerKeyExchange verification")
    }
}

public func contractTlcpBuildStaticClientKeyExchange(
    serverEncryptionPublicKey: Array<Byte>
): ContractTlcpClientKeyExchange {
    try {
        let (encoded, preMaster) = tlcpBuildEccClientKeyExchange(
            sm2PublicKeyFromUncompressed(serverEncryptionPublicKey)
        )
        ContractTlcpClientKeyExchange(encoded, preMaster)
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP static ClientKeyExchange building")
    }
}

public func contractTlcpProcessStaticClientKeyExchange(
    serverEncryptionPrivateKey: Array<Byte>, encoded: Array<Byte>
): Array<Byte> {
    try {
        tlcpProcessEccClientKeyExchange(
            contractTlcpPrivateKey(serverEncryptionPrivateKey), encoded
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP static ClientKeyExchange processing")
    }
}

public func contractTlcpDeriveSecretsFromPreMaster(
    preMasterSecret: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: ContractTlcpCipherSuite
): ContractTlcpSecrets {
    try {
        ContractTlcpSecrets(tlcpDeriveSecretsFromPreMaster(
            preMasterSecret, clientRandom, serverRandom, contractTlcpCoreSuite(cipherSuite)
        ))
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP key-schedule derivation")
    }
}

public func contractTlcpBuildEcdheServerKeyExchange(
    serverEphemeralPublicKey: Array<Byte>,
    signingPrivateKey: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): Array<Byte> {
    try {
        tlcpBuildEcdheServerKeyExchange(
            sm2PublicKeyFromUncompressed(serverEphemeralPublicKey),
            contractTlcpPrivateKey(signingPrivateKey),
            clientRandom,
            serverRandom,
            signerIdentity: signerIdentity
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ECDHE ServerKeyExchange building")
    }
}

public func contractTlcpParseAndVerifyEcdheServerKeyExchange(
    encoded: Array<Byte>,
    signingCertificatePem: String,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    signerIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(tlcpParseAndVerifyEcdheServerKeyExchange(
            encoded,
            x509ParsePem(signingCertificatePem),
            clientRandom,
            serverRandom,
            signerIdentity: signerIdentity
        ))
    } catch (e: CryptoException) {
        throw contractTlcpVerifyException(e, "TLCP ECDHE ServerKeyExchange verification")
    }
}

public func contractTlcpBuildEcdheClientKeyExchange(
    clientEphemeralPublicKey: Array<Byte>
): Array<Byte> {
    try {
        tlcpBuildEcdheClientKeyExchange(
            sm2PublicKeyFromUncompressed(clientEphemeralPublicKey)
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ECDHE ClientKeyExchange building")
    }
}

public func contractTlcpParseEcdheClientKeyExchange(encoded: Array<Byte>): Array<Byte> {
    try {
        sm2PublicKeyToUncompressed(tlcpParseEcdheClientKeyExchange(encoded))
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ECDHE ClientKeyExchange parsing")
    }
}

public func contractTlcpDeriveEcdheClientSecrets(
    clientStaticPrivateKey: Array<Byte>,
    clientEphemeralPrivateKey: Array<Byte>,
    serverStaticPublicKey: Array<Byte>,
    serverEphemeralPublicKey: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: ContractTlcpCipherSuite,
    clientIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray(),
    serverIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractTlcpSecrets {
    try {
        ContractTlcpSecrets(tlcpDeriveEcdheClientSecrets(
            contractTlcpPrivateKey(clientStaticPrivateKey),
            contractTlcpPrivateKey(clientEphemeralPrivateKey),
            sm2PublicKeyFromUncompressed(serverStaticPublicKey),
            sm2PublicKeyFromUncompressed(serverEphemeralPublicKey),
            clientRandom,
            serverRandom,
            contractTlcpCoreSuite(cipherSuite),
            clientIdentity: clientIdentity,
            serverIdentity: serverIdentity
        ))
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ECDHE client key schedule")
    }
}

public func contractTlcpDeriveEcdheServerSecrets(
    serverStaticPrivateKey: Array<Byte>,
    serverEphemeralPrivateKey: Array<Byte>,
    clientStaticPublicKey: Array<Byte>,
    clientEphemeralPublicKey: Array<Byte>,
    clientRandom: Array<Byte>,
    serverRandom: Array<Byte>,
    cipherSuite: ContractTlcpCipherSuite,
    clientIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray(),
    serverIdentity!: Array<Byte> = CONTRACT_GM_DEFAULT_SIGNER_IDENTITY.toArray()
): ContractTlcpSecrets {
    try {
        ContractTlcpSecrets(tlcpDeriveEcdheServerSecrets(
            contractTlcpPrivateKey(serverStaticPrivateKey),
            contractTlcpPrivateKey(serverEphemeralPrivateKey),
            sm2PublicKeyFromUncompressed(clientStaticPublicKey),
            sm2PublicKeyFromUncompressed(clientEphemeralPublicKey),
            clientRandom,
            serverRandom,
            contractTlcpCoreSuite(cipherSuite),
            clientIdentity: clientIdentity,
            serverIdentity: serverIdentity
        ))
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "TLCP ECDHE server key schedule")
    }
}

public func contractTlcpCreateClientRecordLayer(
    secrets: ContractTlcpSecrets
): ContractTlcpRecordLayer {
    ContractTlcpRecordLayer(tlcpCreateClientRecordLayer(secrets.coreSecrets), true)
}

public func contractTlcpCreateServerRecordLayer(
    secrets: ContractTlcpSecrets
): ContractTlcpRecordLayer {
    ContractTlcpRecordLayer(tlcpCreateServerRecordLayer(secrets.coreSecrets), false)
}

public class ContractDtlcpPlainRecord {
    public let contentType: ContractGmTlsContentType
    public let epoch: Int64
    public let sequence: Int64
    public let fragment: Array<Byte>

    public init(
        contentType: ContractGmTlsContentType,
        epoch: Int64,
        sequence: Int64,
        fragment: Array<Byte>
    ) {
        this.contentType = contentType
        this.epoch = epoch
        this.sequence = sequence
        this.fragment = fragment.clone()
    }
}

public class ContractDtlcpRecordLayer {
    private let coreLayer: DtlcpRecordLayer
    public let clientRole: Bool

    internal init(coreLayer: DtlcpRecordLayer, clientRole: Bool) {
        this.coreLayer = coreLayer
        this.clientRole = clientRole
    }

    public prop epoch: Int64 { get() { coreLayer.epoch } }
    public prop writeSequence: Int64 { get() { coreLayer.writeSequence } }
    public prop highestReadSequence: Int64 { get() { coreLayer.highestReadSequence } }

    public func setEpoch(epoch: Int64): Unit {
        try {
            coreLayer.setEpoch(epoch)
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP epoch transition")
        }
    }

    public func seal(
        contentType: ContractGmTlsContentType, plaintext: Array<Byte>
    ): Array<Byte> {
        try {
            coreLayer.seal(contractTlcpCoreContentType(contentType), plaintext)
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP record sealing")
        }
    }

    public func open(encoded: Array<Byte>): ContractDtlcpPlainRecord {
        try {
            let opened = coreLayer.open(encoded)
            ContractDtlcpPlainRecord(
                contractTlcpContentType(opened.contentType),
                opened.epoch,
                opened.sequence,
                opened.fragment
            )
        } catch (e: CryptoException) {
            throw contractTlcpVerifyException(e, "DTLCP record opening")
        }
    }
}

public func contractDtlcpCreateClientRecordLayer(
    secrets: ContractTlcpSecrets, epoch!: Int64 = 0
): ContractDtlcpRecordLayer {
    try {
        ContractDtlcpRecordLayer(
            dtlcpCreateClientRecordLayer(secrets.coreSecrets, epoch: epoch), true
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "DTLCP client record-layer creation")
    }
}

public func contractDtlcpCreateServerRecordLayer(
    secrets: ContractTlcpSecrets, epoch!: Int64 = 0
): ContractDtlcpRecordLayer {
    try {
        ContractDtlcpRecordLayer(
            dtlcpCreateServerRecordLayer(secrets.coreSecrets, epoch: epoch), false
        )
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "DTLCP server record-layer creation")
    }
}

public func contractDtlcpFragmentHandshake(
    encodedHandshake: Array<Byte>, messageSequence: Int64, maxFragmentBody: Int64
): Array<Array<Byte>> {
    try {
        dtlcpFragmentHandshake(encodedHandshake, messageSequence, maxFragmentBody)
    } catch (e: CryptoException) {
        throw contractTlcpException(e, "DTLCP handshake fragmentation")
    }
}

public class ContractDtlcpHandshakeReassembler {
    private let core: DtlcpHandshakeReassembler

    public init(messageType: Byte, messageLength: Int64, messageSequence: Int64) {
        try {
            core = DtlcpHandshakeReassembler(messageType, messageLength, messageSequence)
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP reassembler creation")
        }
    }

    public prop complete: Bool { get() { core.complete } }

    public func accept(encodedFragment: Array<Byte>): Bool {
        try {
            core.accept(encodedFragment)
        } catch (e: CryptoException) {
            throw contractTlcpVerifyException(e, "DTLCP fragment acceptance")
        }
    }

    public func encodedHandshake(): Array<Byte> {
        try {
            core.encodedHandshake()
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP handshake reassembly")
        }
    }
}

public class ContractDtlcpFlightRetransmitter {
    private let core: DtlcpFlightRetransmitter

    public init(
        initialTimeoutMillis!: Int64 = 1000,
        maxTimeoutMillis!: Int64 = 60000,
        maxAttempts!: Int64 = 6
    ) {
        try {
            core = DtlcpFlightRetransmitter(
                initialTimeoutMillis: initialTimeoutMillis,
                maxTimeoutMillis: maxTimeoutMillis,
                maxAttempts: maxAttempts
            )
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP retransmission policy creation")
        }
    }

    public prop attempts: Int64 { get() { core.attempts } }
    public prop timeoutMillis: Int64 { get() { core.timeoutMillis } }
    public prop hasPendingFlight: Bool { get() { core.hasPendingFlight } }

    public func cacheFlight(datagrams: Array<Array<Byte>>): Unit {
        try {
            core.cacheFlight(datagrams)
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP flight caching")
        }
    }

    public func nextFlight(): Array<Array<Byte>> {
        try {
            core.nextFlight()
        } catch (e: CryptoException) {
            throw contractTlcpException(e, "DTLCP flight retransmission")
        }
    }

    public func acknowledgeFlight(): Unit { core.acknowledgeFlight() }
}

private func contractTlcpCertificate(certificate: X509Certificate): ContractGmCertificate {
    contractGmParseCertificatePem(certificate.toPem())
}

private func contractTlcpPrivateKey(encoded: Array<Byte>): Sm2PrivateKey {
    if (encoded.size != CONTRACT_SM2_PRIVATE_KEY_LEN) {
        throw ContractException(ContractErrorCode.BadInput, "SM2 private key must be 32 bytes")
    }
    Sm2PrivateKey(BigNum.fromBytesBE(encoded))
}

private func contractTlcpCoreSuite(value: ContractTlcpCipherSuite): TlcpCipherSuite {
    match (value) {
        case ContractTlcpCipherSuite.EcdheSm4CbcSm3 => TlcpCipherSuite.ECDHE_SM4_CBC_SM3
        case ContractTlcpCipherSuite.EccSm4CbcSm3 => TlcpCipherSuite.ECC_SM4_CBC_SM3
        case ContractTlcpCipherSuite.EcdheSm4GcmSm3 => TlcpCipherSuite.ECDHE_SM4_GCM_SM3
        case ContractTlcpCipherSuite.EccSm4GcmSm3 => TlcpCipherSuite.ECC_SM4_GCM_SM3
    }
}

private func contractTlcpSuite(value: TlcpCipherSuite): ContractTlcpCipherSuite {
    match (value) {
        case TlcpCipherSuite.ECDHE_SM4_CBC_SM3 => ContractTlcpCipherSuite.EcdheSm4CbcSm3
        case TlcpCipherSuite.ECC_SM4_CBC_SM3 => ContractTlcpCipherSuite.EccSm4CbcSm3
        case TlcpCipherSuite.ECDHE_SM4_GCM_SM3 => ContractTlcpCipherSuite.EcdheSm4GcmSm3
        case TlcpCipherSuite.ECC_SM4_GCM_SM3 => ContractTlcpCipherSuite.EccSm4GcmSm3
    }
}

private func contractTlcpCoreContentType(value: ContractGmTlsContentType): TlsContentType {
    match (value) {
        case ContractGmTlsContentType.ChangeCipherSpec => TlsContentType.ChangeCipherSpec
        case ContractGmTlsContentType.Alert => TlsContentType.Alert
        case ContractGmTlsContentType.Handshake => TlsContentType.Handshake
        case ContractGmTlsContentType.ApplicationData => TlsContentType.ApplicationData
    }
}

private func contractTlcpContentType(value: TlsContentType): ContractGmTlsContentType {
    match (value) {
        case TlsContentType.ChangeCipherSpec => ContractGmTlsContentType.ChangeCipherSpec
        case TlsContentType.Alert => ContractGmTlsContentType.Alert
        case TlsContentType.Handshake => ContractGmTlsContentType.Handshake
        case TlsContentType.ApplicationData => ContractGmTlsContentType.ApplicationData
    }
}

private func contractTlcpVerifyException(
    error: CryptoException, operation: String
): ContractException {
    ContractException(ContractErrorCode.VerifyFailed, "${operation} failed: ${error.message}")
}

private func contractTlcpException(error: CryptoException, operation: String): ContractException {
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
