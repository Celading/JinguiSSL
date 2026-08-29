package jinguissl.contract

import jinguissl.live as livecontract
import jinguissl_core.crypto.error.CryptoException
import jinguissl_core.crypto.ssh.{
    sshBuildDefaultKexInit,
    sshBuildKexEcdhInitX25519,
    sshBuildVersionBanner,
    sshEncodeKexInit,
    sshEncodeNewKeys,
    sshEncodeVersionBanner
}

/** Contract-owned SSH client KEX prelude. */
public class ContractSshX25519ClientInit {
    public let encodedInit: Array<Byte>
    public let publicKey: Array<Byte>

    public init(encodedInit: Array<Byte>, publicKey: Array<Byte>) {
        if (encodedInit.size == 0 || publicKey.size != 32) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH X25519 client init fields are invalid"
            )
        }
        this.encodedInit = encodedInit.clone()
        this.publicKey = publicKey.clone()
    }
}

/** Contract-owned host verification result. */
public class ContractSshHostVerificationResult {
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    public let hostSignatureVerified: Bool

    public init(
        hostKeyAlgorithm: String,
        hostSignatureAlgorithm: String,
        hostKeySha256: Array<Byte>,
        hostSignatureVerified: Bool
    ) {
        if (
            hostKeyAlgorithm.trimAscii().size == 0 ||
            hostSignatureAlgorithm.trimAscii().size == 0 ||
            hostKeySha256.size != 32
        ) {
            throw ContractException(
                ContractErrorCode.BadInput,
                "SSH host verification result fields are invalid"
            )
        }
        this.hostKeyAlgorithm = hostKeyAlgorithm.trimAscii()
        this.hostSignatureAlgorithm = hostSignatureAlgorithm.trimAscii()
        this.hostKeySha256 = hostKeySha256.clone()
        this.hostSignatureVerified = hostSignatureVerified
    }
}

/** Contract-owned server handshake result. */
public class ContractSshServerHandshakeResult {
    public let encodedReply: Array<Byte>
    public let sharedSecret: Array<Byte>
    public let exchangeHash: Array<Byte>
    public let sessionId: Array<Byte>
    public let clientEphemeralPublicKey: Array<Byte>
    public let serverEphemeralPublicKey: Array<Byte>
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>

    init(result: livecontract.ContractSshServerInitialHandshakeResult) {
        this.encodedReply = result.encodedReply.clone()
        this.sharedSecret = result.sharedSecret.clone()
        this.exchangeHash = result.exchangeHash.clone()
        this.sessionId = result.sessionId.clone()
        this.clientEphemeralPublicKey = result.clientEphemeralPublicKey.clone()
        this.serverEphemeralPublicKey = result.serverEphemeralPublicKey.clone()
        this.serverHostKey = result.serverHostKey.clone()
        this.hostSignature = result.hostSignature.clone()
        this.hostKeyAlgorithm = result.hostKeyAlgorithm
        this.hostSignatureAlgorithm = result.hostSignatureAlgorithm
        this.hostKeySha256 = result.hostKeySha256.clone()
    }
}

/** Contract-owned client handshake result. */
public class ContractSshClientHandshakeResult {
    public let sharedSecret: Array<Byte>
    public let exchangeHash: Array<Byte>
    public let sessionId: Array<Byte>
    public let clientEphemeralPublicKey: Array<Byte>
    public let serverEphemeralPublicKey: Array<Byte>
    public let serverHostKey: Array<Byte>
    public let hostSignature: Array<Byte>
    public let hostKeyAlgorithm: String
    public let hostSignatureAlgorithm: String
    public let hostKeySha256: Array<Byte>
    let _hostVerification: ?ContractSshHostVerificationResult

    init(result: livecontract.ContractSshClientInitialHandshakeResult) {
        this.sharedSecret = result.sharedSecret.clone()
        this.exchangeHash = result.exchangeHash.clone()
        this.sessionId = result.sessionId.clone()
        this.clientEphemeralPublicKey = result.clientEphemeralPublicKey.clone()
        this.serverEphemeralPublicKey = result.serverEphemeralPublicKey.clone()
        this.serverHostKey = result.serverHostKey.clone()
        this.hostSignature = result.hostSignature.clone()
        this.hostKeyAlgorithm = result.hostKeyAlgorithm
        this.hostSignatureAlgorithm = result.hostSignatureAlgorithm
        this.hostKeySha256 = result.hostKeySha256.clone()
        this._hostVerification = contractSshHostVerification(result.hostVerification)
    }

    public func hostVerification(): ?ContractSshHostVerificationResult {
        _hostVerification
    }

    public func requireHostVerification(): ContractSshHostVerificationResult {
        match (_hostVerification) {
            case Some(value) => value
            case None =>
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "SSH host identity verification is unavailable"
                )
        }
    }
}

/** Decoded SSH transport packet without live/Core-owned public types. */
public class ContractSshTransportPacket {
    public let packetLength: Int64
    public let payload: Array<Byte>
    public let padding: Array<Byte>

    init(packet: livecontract.ContractSshTransportPacket) {
        this.packetLength = packet.packetLength
        this.payload = packet.payload.clone()
        this.padding = packet.padding.clone()
    }
}

/** Contract-owned server transport channel. */
public class ContractSshServerRuntime {
    let _runtime: livecontract.ContractSshServerRuntime

    init(runtime: livecontract.ContractSshServerRuntime) {
        this._runtime = runtime
    }

    public prop writeSequence: Int64 {
        get() { _runtime.writeSequence }
    }

    public prop readSequence: Int64 {
        get() { _runtime.readSequence }
    }

    public func sessionId(): Array<Byte> {
        _runtime.sessionId().clone()
    }

    public func resetTransportCounters(): Unit {
        _runtime.resetTransportCounters()
    }

    public func seal(payload: Array<Byte>, randomPadding!: Array<Byte> = []): Array<Byte> {
        try {
            _runtime.seal(payload, randomPadding: randomPadding)
        } catch (e: livecontract.ContractException) {
            throw contractSshFacadeException(e)
        } catch (e: CryptoException) {
            throw contractSshFacadeCryptoException(e, "SSH server packet sealing")
        }
    }

    public func open(encodedPacket: Array<Byte>): ContractSshTransportPacket {
        try {
            ContractSshTransportPacket(_runtime.open(encodedPacket))
        } catch (e: livecontract.ContractException) {
            throw contractSshFacadeException(e)
        } catch (e: CryptoException) {
            throw contractSshFacadeCryptoException(e, "SSH server packet opening")
        }
    }
}

/** Contract-owned client transport channel. */
public class ContractSshClientRuntime {
    let _runtime: livecontract.ContractSshClientRuntime

    init(runtime: livecontract.ContractSshClientRuntime) {
        this._runtime = runtime
    }

    public prop writeSequence: Int64 {
        get() { _runtime.writeSequence }
    }

    public prop readSequence: Int64 {
        get() { _runtime.readSequence }
    }

    public func sessionId(): Array<Byte> {
        _runtime.sessionId().clone()
    }

    public func hostVerification(): ?ContractSshHostVerificationResult {
        contractSshHostVerification(_runtime.hostVerification())
    }

    public func requireHostVerification(): ContractSshHostVerificationResult {
        match (hostVerification()) {
            case Some(value) => value
            case None =>
                throw ContractException(
                    ContractErrorCode.VerifyFailed,
                    "SSH host identity verification is unavailable"
                )
        }
    }

    public func resetTransportCounters(): Unit {
        _runtime.resetTransportCounters()
    }

    public func seal(payload: Array<Byte>, randomPadding!: Array<Byte> = []): Array<Byte> {
        try {
            _runtime.seal(payload, randomPadding: randomPadding)
        } catch (e: livecontract.ContractException) {
            throw contractSshFacadeException(e)
        } catch (e: CryptoException) {
            throw contractSshFacadeCryptoException(e, "SSH client packet sealing")
        }
    }

    public func open(encodedPacket: Array<Byte>): ContractSshTransportPacket {
        try {
            ContractSshTransportPacket(_runtime.open(encodedPacket))
        } catch (e: livecontract.ContractException) {
            throw contractSshFacadeException(e)
        } catch (e: CryptoException) {
            throw contractSshFacadeCryptoException(e, "SSH client packet opening")
        }
    }
}

public func contractSshBuildVersionBannerLine(
    softwareVersion: String, comments!: String = ""
): Array<Byte> {
    try {
        sshEncodeVersionBanner(sshBuildVersionBanner(softwareVersion, comments: comments))
    } catch (e: CryptoException) {
        throw contractSshFacadeCryptoException(e, "SSH version banner building")
    }
}

public func contractSshBuildDefaultKexInitPayload(
    cookie!: Array<Byte> = []
): Array<Byte> {
    try {
        sshEncodeKexInit(sshBuildDefaultKexInit(cookie: cookie))
    } catch (e: CryptoException) {
        throw contractSshFacadeCryptoException(e, "SSH KEXINIT building")
    }
}

public func contractSshBuildKexEcdhInitX25519(
    clientPrivateKey: Array<Byte>
): ContractSshX25519ClientInit {
    try {
        let (encodedInit, publicKey) = sshBuildKexEcdhInitX25519(clientPrivateKey)
        ContractSshX25519ClientInit(encodedInit, publicKey)
    } catch (e: CryptoException) {
        throw contractSshFacadeCryptoException(e, "SSH X25519 client init building")
    }
}

public func contractSshEncodeNewKeys(): Array<Byte> {
    try {
        sshEncodeNewKeys()
    } catch (e: CryptoException) {
        throw contractSshFacadeCryptoException(e, "SSH NEWKEYS encoding")
    }
}

func contractWrapSshServerHandshake(
    result: livecontract.ContractSshServerInitialHandshakeResult
): ContractSshServerHandshakeResult {
    ContractSshServerHandshakeResult(result)
}

func contractWrapSshClientHandshake(
    result: livecontract.ContractSshClientInitialHandshakeResult
): ContractSshClientHandshakeResult {
    ContractSshClientHandshakeResult(result)
}

func contractWrapSshServerRuntime(
    runtime: livecontract.ContractSshServerRuntime
): ContractSshServerRuntime {
    ContractSshServerRuntime(runtime)
}

func contractWrapSshClientRuntime(
    runtime: livecontract.ContractSshClientRuntime
): ContractSshClientRuntime {
    ContractSshClientRuntime(runtime)
}

private func contractSshHostVerification(
    result: ?livecontract.ContractSshHostVerificationResult
): ?ContractSshHostVerificationResult {
    match (result) {
        case Some(value) => Some(ContractSshHostVerificationResult(
            value.hostKeyAlgorithm,
            value.hostSignatureAlgorithm,
            value.hostKeySha256,
            value.hostSignatureVerified
        ))
        case None => None
    }
}

private func contractSshFacadeException(
    exception: livecontract.ContractException
): ContractException {
    ContractException(
        contractSshFacadeMapLiveErrorCode(exception.code.toString()),
        exception.message
    )
}

private func contractSshFacadeCryptoException(
    exception: CryptoException, operation: String
): ContractException {
    ContractException(
        contractMapCoreCryptoException(exception),
        "${operation} failed: ${exception.message}"
    )
}

private func contractSshFacadeMapLiveErrorCode(code: String): ContractErrorCode {
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
