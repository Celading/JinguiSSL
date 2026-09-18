package jinguissl.contract

import std.collection.ArrayList
import jinguissl_core.crypto.ssh.{SshPacketProtectionLayer, SshKexExchangeTranscript,
    SshNegotiatedAlgorithms, SshHostVerificationPolicy, SshHostVerificationConfig,
    sshCompleteClientInitialHandshakeX25519WithHostVerificationConfig}
import jinguissl_core.crypto.error.CryptoException

/// Serialized SSH encrypted stream. Channel/authentication/application messages remain caller-owned.
/// Partial headers cannot advance crypto state; malformed/authentication failures close the stream.
public class ContractSshPacketStream {
    private var layer: ?SshPacketProtectionLayer
    private let pending = ArrayList<Byte>()
    private let maximum: Int64
    private var expected: Int64 = 0
    public let hostVerification: ContractSshHostVerificationResult

    init(layer: SshPacketProtectionLayer, hostVerification: ContractSshHostVerificationResult, maximum: Int64) {
        this.layer = Some(layer)
        this.hostVerification = hostVerification
        this.maximum = maximum
    }
    public prop isClosed: Bool { get() { layer.isNone() } }
    public prop writeSequence: Int64 { get() { requireLayer().writeSequence } }
    public prop readSequence: Int64 { get() { requireLayer().readSequence } }

    public func receive(bytes: Array<Byte>): Array<Array<Byte>> {
        let channel = requireLayer()
        let messages = ArrayList<Array<Byte>>()
        try {
            if (bytes.size > 1048576) { throw ContractException(ContractErrorCode.BadInput, "SSH input budget exceeded") }
            for (b in bytes) {
                pending.add(b)
                if (expected == 0 && pending.size == channel.readPrefixLength) {
                    expected = channel.encodedPacketSize(pending.toArray(), maximum: maximum)
                }
                if (expected > 0 && pending.size == expected) {
                    messages.add(channel.open(pending.toArray()).payload)
                    pending.clear()
                    expected = 0
                }
            }
            messages.toArray()
        } catch (e: CryptoException) {
            close()
            throw ContractException(ContractErrorCode.VerifyFailed, "SSH stream authentication or framing failed")
        } catch (e: ContractException) { close(); throw e }
    }

    public func seal(payload: Array<Byte>): Array<Byte> {
        let channel = requireLayer()
        if (payload.size > maximum - 512) {
            throw ContractException(ContractErrorCode.BadInput, "SSH payload exceeds packet budget")
        }
        try { channel.seal(payload) }
        catch (e: CryptoException) { close(); throw ContractException(ContractErrorCode.CryptoUnavailable, e.message) }
    }

    public func finishInput(): Unit {
        _ = requireLayer()
        let truncated = pending.size != 0
        close()
        if (truncated) { throw ContractException(ContractErrorCode.BadInput, "SSH truncated protected packet at EOF") }
    }
    /// Revokes access and releases state. Legacy Core key schedules have no full erasure guarantee.
    public func close(): Unit { pending.clear(); expected = 0; layer = None }
    private func requireLayer(): SshPacketProtectionLayer {
        match (layer) {
            case Some(value) => value
            case None => throw ContractException(ContractErrorCode.BadInput, "SSH stream is closed")
        }
    }
}

/// Verify the initial server KEX and install fresh keys with exact connection-wide packet counts.
/// Counts include KEXINIT, KEX_ECDH and NEWKEYS plus any ignored transport messages, not banners.
public func contractSshOpenClientPacketStream(request: ContractSshClientInitialHandshakeX25519Request,
    sentPacketCount!: Int64, receivedPacketCount!: Int64, maximumPacketBytes!: Int64 = 262144): ContractSshPacketStream {
    if (sentPacketCount < 3 || receivedPacketCount < 3 || maximumPacketBytes < 1024 || maximumPacketBytes > 1048576 ||
        !request.policy.requireHostSignature || !request.policy.requireVerifiedHost) {
        throw ContractException(ContractErrorCode.BadInput, "SSH stream requires verified KEX, packet counts and bounded framing")
    }
    let t = request.transcript
    let a = request.negotiated
    if (a.compressionAlgorithmClientToServer != "none" || a.compressionAlgorithmServerToClient != "none" ||
        a.encryptionAlgorithmClientToServer == "none" || a.encryptionAlgorithmServerToClient == "none") {
        throw ContractException(ContractErrorCode.BadInput, "SSH stream requires encryption and no compression")
    }
    if ((a.encryptionAlgorithmClientToServer.endsWith("-ctr") && a.macAlgorithmClientToServer == "none") ||
        (a.encryptionAlgorithmServerToClient.endsWith("-ctr") && a.macAlgorithmServerToClient == "none") ||
        (request.policy.negotiatedHostKeyAlgorithm.size > 0 &&
            request.policy.negotiatedHostKeyAlgorithm != a.serverHostKeyAlgorithm)) {
        throw ContractException(ContractErrorCode.BadInput, "SSH integrity or host algorithm policy mismatch")
    }
    try {
        let result = sshCompleteClientInitialHandshakeX25519WithHostVerificationConfig(
            SshKexExchangeTranscript(t.clientBannerLine, t.serverBannerLine, t.clientKexInitPayload, t.serverKexInitPayload),
            request.clientPrivateKey, request.encodedClientInit, request.encodedServerReply,
            SshNegotiatedAlgorithms(a.kexAlgorithm, a.serverHostKeyAlgorithm,
                a.encryptionAlgorithmClientToServer, a.encryptionAlgorithmServerToClient,
                a.macAlgorithmClientToServer, a.macAlgorithmServerToClient, "none", "none"),
            request.encodedClientNewKeys, request.encodedServerNewKeys,
            config: SshHostVerificationConfig(policy: SshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: a.serverHostKeyAlgorithm,
                expectedHostKeySha256: request.policy.expectedHostKeySha256,
                requireKnownHost: request.policy.requireKnownHost, requireHostSignature: true,
                allowLegacyRsaSha1: request.policy.allowLegacyRsaSha1), requireVerifiedHost: true))
        let keys = result.coordinator.derivedKeys()
        let verification = result.requireHostVerification()
        ContractSshPacketStream(SshPacketProtectionLayer(keys.clientToServer, keys.serverToClient,
            initialWriteSequence: sentPacketCount, initialReadSequence: receivedPacketCount),
            ContractSshHostVerificationResult(verification.hostKeyAlgorithm, verification.hostSignatureAlgorithm,
                verification.hostKeySha256, verification.hostSignatureVerified), maximumPacketBytes)
    } catch (e: CryptoException) {
        throw ContractException(ContractErrorCode.VerifyFailed, "SSH verified stream setup failed: ${e.message}")
    }
}
