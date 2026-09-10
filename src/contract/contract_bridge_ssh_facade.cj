package jinguissl.contract

import jinguissl.live as livecontract
import jinguissl_core.crypto.error.CryptoException

/** Contract-owned host-signing result for Bridge adapters. */
public class ContractBridgeSshHostSigningResult {
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>

    public init(
        serverHostKey: Array<Byte>,
        hostSignature: Array<Byte>,
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>
    ) {
        if (
            serverHostKey.size == 0 ||
            hostSignature.size == 0 ||
            hostKeyAlgorithm.trimAscii().size == 0 ||
            hostSignatureAlgorithm.trimAscii().size == 0 ||
            hostKeySha256.size != 32
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH host-signing result fields are invalid"
            )
        }
        this.serverHostKey = serverHostKey.clone()
        this.hostSignature = hostSignature.clone()
        this.hostKeyAlgorithm = hostKeyAlgorithm.trimAscii()
        this.hostSignatureAlgorithm = hostSignatureAlgorithm.trimAscii()
        this.hostKeySha256 = hostKeySha256.clone()
    }
}

public class ContractBridgeSshHostSigningOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractBridgeSshHostSigningResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractBridgeSshHostSigningResult = None
    ) {
        let hasResult = match (result) {
            case Some(_) => true
            case None => false
        }
        contractBridgeRequireOutcomeShape(ok, message, code, igniteCode, hasResult)
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractBridgeSshServerHandshakeOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshServerHandshakeResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshServerHandshakeResult = None
    ) {
        let hasResult = match (result) {
            case Some(_) => true
            case None => false
        }
        contractBridgeRequireOutcomeShape(ok, message, code, igniteCode, hasResult)
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

public class ContractBridgeSshClientHandshakeOutcome {
    public let ok: Bool
    public let message: String
    public let code: ?ContractErrorCode
    public let igniteCode: ?ContractIgniteCryptoErrorCode
    public let result: ?ContractSshClientHandshakeResult

    public init(
        ok: Bool,
        message: String,
        code!: ?ContractErrorCode = None,
        igniteCode!: ?ContractIgniteCryptoErrorCode = None,
        result!: ?ContractSshClientHandshakeResult = None
    ) {
        let hasResult = match (result) {
            case Some(_) => true
            case None => false
        }
        contractBridgeRequireOutcomeShape(ok, message, code, igniteCode, hasResult)
        this.ok = ok
        this.message = message.trimAscii()
        this.code = code
        this.igniteCode = igniteCode
        this.result = result
    }
}

/**
 * Contract-owned adapter for Bridge's typed SSH facade.
 *
 * These functions intentionally accept Contract DTOs/keys so downstream bridge
 * packages never need to import Core merely to reach the live SSH runtime.
 */
public func contractBridgeSshEncodeRsaHostPublicKey(
    publicKey: ContractRsaPublicKey
): Array<Byte> {
    livecontract.contractSshEncodeRsaHostPublicKey(contractRsaCorePublicKey(publicKey))
}

public func contractBridgeSshSignExchangeHashRsa(
    privateKey: ContractRsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): Array<Byte> {
    livecontract.contractSshSignExchangeHashRsa(
        contractRsaCorePrivateKey(privateKey),
        exchangeHash,
        signatureAlgorithm: signatureAlgorithm
    )
}

public func contractBridgeSshEncodeEcdsaHostPublicKey(
    publicKey: ContractEcPublicKey
): Array<Byte> {
    livecontract.contractSshEncodeEcdsaHostPublicKey(contractEcCorePublicKey(publicKey))
}

public func contractBridgeSshSignExchangeHashEcdsa(
    privateKey: ContractEcKeyPair,
    exchangeHash: Array<Byte>
): Array<Byte> {
    livecontract.contractSshSignExchangeHashEcdsa(
        contractEcPrivateKey(privateKey.curve, privateKey.privateKey),
        exchangeHash
    )
}

public func contractBridgePrepareSshHostSigningRsa(
    privateKey: ContractRsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractBridgeSshHostSigningResult {
    try {
        contractBridgeWrapHostSigning(livecontract.contractPrepareSshHostSigningRsa(
            contractRsaCorePrivateKey(privateKey),
            exchangeHash,
            signatureAlgorithm: signatureAlgorithm
        ))
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH RSA host signing")
    }
}

public func contractBridgeTryPrepareSshHostSigningRsa(
    privateKey: ContractRsaPrivateKey,
    exchangeHash: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256"
): ContractBridgeSshHostSigningOutcome {
    try {
        ContractBridgeSshHostSigningOutcome(
            true,
            "OK",
            result: Some(contractBridgePrepareSshHostSigningRsa(
                privateKey,
                exchangeHash,
                signatureAlgorithm: signatureAlgorithm
            ))
        )
    } catch (e: ContractException) {
        contractBridgeHostSigningFailure(e)
    }
}

public func contractBridgePrepareSshHostSigningEcdsa(
    privateKey: ContractEcKeyPair,
    exchangeHash: Array<Byte>
): ContractBridgeSshHostSigningResult {
    try {
        contractBridgeWrapHostSigning(livecontract.contractPrepareSshHostSigningEcdsa(
            contractEcPrivateKey(privateKey.curve, privateKey.privateKey),
            exchangeHash
        ))
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH ECDSA host signing")
    }
}

public func contractBridgeTryPrepareSshHostSigningEcdsa(
    privateKey: ContractEcKeyPair,
    exchangeHash: Array<Byte>
): ContractBridgeSshHostSigningOutcome {
    try {
        ContractBridgeSshHostSigningOutcome(
            true,
            "OK",
            result: Some(contractBridgePrepareSshHostSigningEcdsa(privateKey, exchangeHash))
        )
    } catch (e: ContractException) {
        contractBridgeHostSigningFailure(e)
    }
}

public func contractBridgePrepareSshHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractBridgeSshHostSigningResult {
    try {
        contractBridgeWrapHostSigning(livecontract.contractPrepareSshHostSigningEd25519(
            privateKeySeed,
            exchangeHash
        ))
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH Ed25519 host signing")
    }
}

public func contractBridgeTryPrepareSshHostSigningEd25519(
    privateKeySeed: Array<Byte>,
    exchangeHash: Array<Byte>
): ContractBridgeSshHostSigningOutcome {
    try {
        ContractBridgeSshHostSigningOutcome(
            true,
            "OK",
            result: Some(contractBridgePrepareSshHostSigningEd25519(
                privateKeySeed,
                exchangeHash
            ))
        )
    } catch (e: ContractException) {
        contractBridgeHostSigningFailure(e)
    }
}

public func contractBridgeSshCompleteServerInitialHandshakeX25519Rsa(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: ContractRsaPrivateKey,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractSshServerHandshakeResult {
    try {
        contractWrapSshServerHandshake(
            livecontract.contractSshCompleteServerInitialHandshakeX25519RsaRequest(
                livecontract.ContractSshServerInitialHandshakeX25519RsaRequest(
                    contractBridgeToLiveSshTranscript(transcript),
                    serverPrivateKey,
                    encodedClientInit,
                    contractRsaCorePrivateKey(hostPrivateKey),
                    contractBridgeToLiveSshNegotiated(negotiated),
                    encodedClientNewKeys,
                    encodedServerNewKeys,
                    signatureAlgorithm: signatureAlgorithm,
                    serverPublicKey: serverPublicKey
                )
            )
        )
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH RSA server initial handshake")
    }
}

public func contractBridgeTrySshCompleteServerInitialHandshakeX25519Rsa(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: ContractRsaPrivateKey,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    signatureAlgorithm!: String = "rsa-sha2-256",
    serverPublicKey!: Array<Byte> = []
): ContractBridgeSshServerHandshakeOutcome {
    try {
        ContractBridgeSshServerHandshakeOutcome(
            true,
            "OK",
            result: Some(contractBridgeSshCompleteServerInitialHandshakeX25519Rsa(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKey,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                signatureAlgorithm: signatureAlgorithm,
                serverPublicKey: serverPublicKey
            ))
        )
    } catch (e: ContractException) {
        contractBridgeServerHandshakeFailure(e)
    }
}

public func contractBridgeSshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: ContractEcKeyPair,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerHandshakeResult {
    try {
        contractWrapSshServerHandshake(
            livecontract.contractSshCompleteServerInitialHandshakeX25519EcdsaRequest(
                livecontract.ContractSshServerInitialHandshakeX25519EcdsaRequest(
                    contractBridgeToLiveSshTranscript(transcript),
                    serverPrivateKey,
                    encodedClientInit,
                    contractEcPrivateKey(hostPrivateKey.curve, hostPrivateKey.privateKey),
                    contractBridgeToLiveSshNegotiated(negotiated),
                    encodedClientNewKeys,
                    encodedServerNewKeys,
                    serverPublicKey: serverPublicKey
                )
            )
        )
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH ECDSA server initial handshake")
    }
}

public func contractBridgeTrySshCompleteServerInitialHandshakeX25519Ecdsa(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKey: ContractEcKeyPair,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractBridgeSshServerHandshakeOutcome {
    try {
        ContractBridgeSshServerHandshakeOutcome(
            true,
            "OK",
            result: Some(contractBridgeSshCompleteServerInitialHandshakeX25519Ecdsa(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKey,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                serverPublicKey: serverPublicKey
            ))
        )
    } catch (e: ContractException) {
        contractBridgeServerHandshakeFailure(e)
    }
}

public func contractBridgeSshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractSshServerHandshakeResult {
    try {
        contractWrapSshServerHandshake(
            livecontract.contractSshCompleteServerInitialHandshakeX25519Ed25519Request(
                livecontract.ContractSshServerInitialHandshakeX25519Ed25519Request(
                    contractBridgeToLiveSshTranscript(transcript),
                    serverPrivateKey,
                    encodedClientInit,
                    hostPrivateKeySeed,
                    contractBridgeToLiveSshNegotiated(negotiated),
                    encodedClientNewKeys,
                    encodedServerNewKeys,
                    serverPublicKey: serverPublicKey
                )
            )
        )
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH Ed25519 server initial handshake")
    }
}

public func contractBridgeTrySshCompleteServerInitialHandshakeX25519Ed25519(
    transcript: ContractSshKexExchangeTranscript,
    serverPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    hostPrivateKeySeed: Array<Byte>,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    serverPublicKey!: Array<Byte> = []
): ContractBridgeSshServerHandshakeOutcome {
    try {
        ContractBridgeSshServerHandshakeOutcome(
            true,
            "OK",
            result: Some(contractBridgeSshCompleteServerInitialHandshakeX25519Ed25519(
                transcript,
                serverPrivateKey,
                encodedClientInit,
                hostPrivateKeySeed,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                serverPublicKey: serverPublicKey
            ))
        )
    } catch (e: ContractException) {
        contractBridgeServerHandshakeFailure(e)
    }
}

public func contractBridgeSshCompleteClientInitialHandshakeX25519(
    transcript: ContractSshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractSshClientHandshakeResult {
    try {
        contractWrapSshClientHandshake(
            livecontract.contractSshCompleteClientInitialHandshakeX25519Request(
                livecontract.ContractSshClientInitialHandshakeX25519Request(
                    contractBridgeToLiveSshTranscript(transcript),
                    clientPrivateKey,
                    encodedClientInit,
                    encodedServerReply,
                    contractBridgeToLiveSshNegotiated(negotiated),
                    encodedClientNewKeys,
                    encodedServerNewKeys,
                    policy: contractBridgeToLiveSshPolicy(policy)
                )
            )
        )
    } catch (e: livecontract.ContractException) {
        throw contractBridgeSshException(e)
    } catch (e: CryptoException) {
        throw contractBridgeSshCryptoException(e, "SSH client initial handshake")
    }
}

public func contractBridgeTrySshCompleteClientInitialHandshakeX25519(
    transcript: ContractSshKexExchangeTranscript,
    clientPrivateKey: Array<Byte>,
    encodedClientInit: Array<Byte>,
    encodedServerReply: Array<Byte>,
    negotiated: ContractSshNegotiatedAlgorithms,
    encodedClientNewKeys: Array<Byte>,
    encodedServerNewKeys: Array<Byte>,
    policy!: ContractSshHostVerificationPolicy = ContractSshHostVerificationPolicy()
): ContractBridgeSshClientHandshakeOutcome {
    try {
        ContractBridgeSshClientHandshakeOutcome(
            true,
            "OK",
            result: Some(contractBridgeSshCompleteClientInitialHandshakeX25519(
                transcript,
                clientPrivateKey,
                encodedClientInit,
                encodedServerReply,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                policy: policy
            ))
        )
    } catch (e: ContractException) {
        contractBridgeClientHandshakeFailure(e)
    }
}

private func contractBridgeToLiveSshTranscript(
    value: ContractSshKexExchangeTranscript
): livecontract.ContractSshKexExchangeTranscript {
    livecontract.ContractSshKexExchangeTranscript(
        value.clientBannerLine,
        value.serverBannerLine,
        value.clientKexInitPayload,
        value.serverKexInitPayload
    )
}

private func contractBridgeToLiveSshNegotiated(
    value: ContractSshNegotiatedAlgorithms
): livecontract.ContractSshNegotiatedAlgorithms {
    livecontract.ContractSshNegotiatedAlgorithms(
        value.kexAlgorithm,
        value.serverHostKeyAlgorithm,
        value.encryptionAlgorithmClientToServer,
        value.encryptionAlgorithmServerToClient,
        value.macAlgorithmClientToServer,
        value.macAlgorithmServerToClient,
        compressionAlgorithmClientToServer: value.compressionAlgorithmClientToServer,
        compressionAlgorithmServerToClient: value.compressionAlgorithmServerToClient
    )
}

private func contractBridgeToLiveSshPolicy(
    value: ContractSshHostVerificationPolicy
): livecontract.ContractSshHostVerificationPolicy {
    livecontract.ContractSshHostVerificationPolicy(
        negotiatedHostKeyAlgorithm: value.negotiatedHostKeyAlgorithm,
        expectedHostKeySha256: value.expectedHostKeySha256,
        requireKnownHost: value.requireKnownHost,
        requireHostSignature: value.requireHostSignature,
        allowLegacyRsaSha1: value.allowLegacyRsaSha1,
        requireVerifiedHost: value.requireVerifiedHost
    )
}

private func contractBridgeWrapHostSigning(
    result: livecontract.ContractSshHostSigningResult
): ContractBridgeSshHostSigningResult {
    ContractBridgeSshHostSigningResult(
        result.serverHostKey,
        result.hostSignature,
        result.hostKeyAlgorithm,
        result.hostSignatureAlgorithm,
        result.hostKeySha256
    )
}

private func contractBridgeHostSigningFailure(
    exception: ContractException
): ContractBridgeSshHostSigningOutcome {
    ContractBridgeSshHostSigningOutcome(
        false,
        exception.message,
        code: Some(exception.code),
        igniteCode: Some(contractMapToIgniteCryptoErrorCode(exception.code))
    )
}

private func contractBridgeServerHandshakeFailure(
    exception: ContractException
): ContractBridgeSshServerHandshakeOutcome {
    ContractBridgeSshServerHandshakeOutcome(
        false,
        exception.message,
        code: Some(exception.code),
        igniteCode: Some(contractMapToIgniteCryptoErrorCode(exception.code))
    )
}

private func contractBridgeClientHandshakeFailure(
    exception: ContractException
): ContractBridgeSshClientHandshakeOutcome {
    ContractBridgeSshClientHandshakeOutcome(
        false,
        exception.message,
        code: Some(exception.code),
        igniteCode: Some(contractMapToIgniteCryptoErrorCode(exception.code))
    )
}

private func contractBridgeSshException(
    exception: livecontract.ContractException
): ContractException {
    ContractException(
        contractBridgeSshErrorCode(exception.code.toString()),
        exception.message
    )
}

private func contractBridgeSshCryptoException(
    exception: CryptoException,
    operation: String
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}

private func contractBridgeSshErrorCode(code: String): ContractErrorCode {
    match (code) {
        case "BAD_INPUT" => ContractErrorCode.BadInput
        case "KEY_NOT_FOUND" => ContractErrorCode.KeyNotFound
        case "VERIFY_FAILED" => ContractErrorCode.VerifyFailed
        case "CRYPTO_UNAVAILABLE" => ContractErrorCode.CryptoUnavailable
        case "COMPLIANCE_REJECTED" => ContractErrorCode.ComplianceRejected
        case "UNSUPPORTED" => ContractErrorCode.Unsupported
        case _ => ContractErrorCode.InternalError
    }
}

private func contractBridgeRequireOutcomeShape(
    ok: Bool,
    message: String,
    code: ?ContractErrorCode,
    igniteCode: ?ContractIgniteCryptoErrorCode,
    hasResult: Bool
): Unit {
    if (message.trimAscii().size == 0) {
        throw ContractException(ContractErrorCode.BadInput, "SSH outcome message must not be empty")
    }
    let hasCode = match (code) {
        case Some(_) => true
        case None => false
    }
    let hasIgniteCode = match (igniteCode) {
        case Some(_) => true
        case None => false
    }
    if (ok && (hasCode || hasIgniteCode || !hasResult)) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "successful SSH outcome must contain only a result"
        )
    }
    if (!ok && (!hasCode || !hasIgniteCode || hasResult)) {
        throw ContractException(
            ContractErrorCode.BadInput,
            "failed SSH outcome must contain error codes and no result"
        )
    }
}
