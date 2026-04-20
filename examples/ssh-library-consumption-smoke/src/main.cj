package jinguissl_ssh_library_consumption_smoke

import std.collection.ArrayList
import jinguissl.contract.*

main(): Int64 {
    try {
        runSshLibraryGateDemo()
        runSshLibraryStartupSmoke()
        runSshKnownHostFailureSmoke()
        0
    } catch (e: Exception) {
        println("fatal=${e}")
        1
    }
}

private func runSshLibraryGateDemo(): Unit {
    let clientGate = contractRequireProviderConsumptionGate(
        ContractProviderConsumptionPath.SshClientLibrary
    )
    let serverGate = contractRequireProviderConsumptionGate(
        ContractProviderConsumptionPath.SshServerLibrary
    )
    let clientProfile = contractDescribeHttpSshStartupProfile(
        ContractHttpSshStartupProfile.SshClientLibrary
    )
    let serverProfile = contractDescribeHttpSshStartupProfile(
        ContractHttpSshStartupProfile.SshServerLibrary
    )

    println("== ssh-library-gate ==")
    println("client_gate_status=${clientGate.status}")
    println("client_gate_public_path=${clientGate.publicPath}")
    println("client_gate_release_path=${clientGate.releasePath}")
    println("client_gate_risk_level=${clientGate.riskLevel}")
    println("client_gate_ready_now=${clientGate.readyNow}")
    println("client_gate_selected_entry=${clientGate.selectedEntryId}")
    println("client_gate_candidate_order=${joinStrings(clientGate.candidateOrder)}")
    println("client_gate_fallback_chain=${joinStrings(clientGate.fallbackChain)}")
    println("client_gate_observability_tags=${joinStrings(clientGate.observabilityTags)}")
    println("client_profile_label=${clientProfile.label}")
    println("client_profile_notes=${joinStrings(clientProfile.notes)}")
    println("server_gate_status=${serverGate.status}")
    println("server_gate_public_path=${serverGate.publicPath}")
    println("server_gate_release_path=${serverGate.releasePath}")
    println("server_gate_risk_level=${serverGate.riskLevel}")
    println("server_gate_ready_now=${serverGate.readyNow}")
    println("server_gate_selected_entry=${serverGate.selectedEntryId}")
    println("server_gate_candidate_order=${joinStrings(serverGate.candidateOrder)}")
    println("server_gate_fallback_chain=${joinStrings(serverGate.fallbackChain)}")
    println("server_gate_observability_tags=${joinStrings(serverGate.observabilityTags)}")
    println("server_profile_label=${serverProfile.label}")
    println("server_profile_notes=${joinStrings(serverProfile.notes)}")
    println("gate_note=SSH library paths are stable contract surfaces; they do not depend on stdx TLS attach glue and they are not default HTTPS promotion")
}

private func runSshLibraryStartupSmoke(): Unit {
    let clientBanner = contractSshBuildVersionBanner(
        "jinguiSSL-ssh-client-smoke",
        comments: "library-consumption"
    )
    let serverBanner = contractSshBuildVersionBanner(
        "jinguiSSL-ssh-server-smoke",
        comments: "library-consumption"
    )
    let clientKexInit = contractSshBuildDefaultKexInit(
        cookie: incrementalBytes(16, start: 32)
    )
    let serverKexInit = contractSshBuildDefaultKexInit(
        cookie: incrementalBytes(16, start: 64)
    )
    let transcript = contractSshBuildKexExchangeTranscriptFromPrelude(
        clientBanner,
        serverBanner,
        clientKexInit,
        serverKexInit
    )
    let negotiated = contractSshNegotiateKexInit(clientKexInit, serverKexInit)
    let clientPrivate = hexToBytes(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    let serverPrivate = hexToBytes(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
    )
    let ed25519Seed = hexToBytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let initResult = contractSshBuildKexEcdhInitX25519(clientPrivate)
    let encodedClientNewKeys = contractSshEncodeNewKeys()
    let encodedServerNewKeys = contractSshEncodeNewKeys()
    let serverBundle = contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
        ContractSshServerLibraryStartupX25519Ed25519SeedRequest(
            transcript,
            serverPrivate,
            initResult.encodedInit,
            ed25519Seed,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys
        )
    )
    let clientBundle = contractPrepareSshClientLibraryStartupX25519Request(
        ContractSshClientLibraryStartupX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                transcript,
                clientPrivate,
                initResult.encodedInit,
                serverBundle.handshake.encodedReply,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
                    expectedHostKeySha256: serverBundle.handshake.hostKeySha256,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
    )
    let verification = clientBundle.handshake.requireHostVerification()
    let clientPacket = clientBundle.runtime.seal(
        "ssh-library-client-payload".toArray(),
        randomPadding: incrementalBytes(48, start: 96)
    )
    let serverOpened = serverBundle.runtime.open(clientPacket)
    let serverPacket = serverBundle.runtime.seal(
        "ssh-library-server-payload".toArray(),
        randomPadding: incrementalBytes(48, start: 160)
    )
    let clientOpened = clientBundle.runtime.open(serverPacket)

    println("== ssh-library-startup-smoke ==")
    println("ssh_client_banner=${formatBanner(clientBanner)}")
    println("ssh_server_banner=${formatBanner(serverBanner)}")
    println("ssh_kex_algorithm=${negotiated.kexAlgorithm}")
    println("ssh_server_hostkey_algorithm=${negotiated.serverHostKeyAlgorithm}")
    println("ssh_server_profile_label=${serverBundle.template.label}")
    println("ssh_server_overall_ready=${serverBundle.readiness.overallReady}")
    println("ssh_server_random_ready=${serverBundle.readiness.randomAvailable}")
    println("ssh_server_ssh_ready=${serverBundle.readiness.sshReady}")
    println("ssh_server_acceleration_ready=${serverBundle.readiness.aes.acceleratedBackendReady}")
    println("ssh_server_warning_count=${serverBundle.readiness.warnings.size}")
    println("ssh_client_profile_label=${clientBundle.template.label}")
    println("ssh_client_overall_ready=${clientBundle.readiness.overallReady}")
    println("ssh_client_random_ready=${clientBundle.readiness.randomAvailable}")
    println("ssh_client_ssh_ready=${clientBundle.readiness.sshReady}")
    println("ssh_client_acceleration_ready=${clientBundle.readiness.aes.acceleratedBackendReady}")
    println("ssh_client_warning_count=${clientBundle.readiness.warnings.size}")
    println("ssh_session_id_hex=${bytesToHexLower(clientBundle.handshake.sessionId)}")
    println("ssh_host_key_sha256_hex=${bytesToHexLower(serverBundle.handshake.hostKeySha256)}")
    println("ssh_host_signature_verified=${verification.hostSignatureVerified}")
    println("ssh_encoded_init_len=${initResult.encodedInit.size}")
    println("ssh_encoded_reply_len=${serverBundle.handshake.encodedReply.size}")
    println("ssh_client_packet_len=${clientPacket.size}")
    println("ssh_server_opened_payload=${String.fromUtf8(serverOpened.payload)}")
    println("ssh_server_packet_len=${serverPacket.size}")
    println("ssh_client_opened_payload=${String.fromUtf8(clientOpened.payload)}")
    println("ssh_note=stable SSH consumption stays at startup bundle -> handshake -> runtime; channel/subsystem orchestration still belongs to your upper layer")
}

private func runSshKnownHostFailureSmoke(): Unit {
    let clientBanner = contractSshBuildVersionBanner(
        "jinguiSSL-ssh-client-smoke",
        comments: "known-host-failure"
    )
    let serverBanner = contractSshBuildVersionBanner(
        "jinguiSSL-ssh-server-smoke",
        comments: "known-host-failure"
    )
    let clientKexInit = contractSshBuildDefaultKexInit(
        cookie: incrementalBytes(16, start: 192)
    )
    let serverKexInit = contractSshBuildDefaultKexInit(
        cookie: incrementalBytes(16, start: 224)
    )
    let transcript = contractSshBuildKexExchangeTranscriptFromPrelude(
        clientBanner,
        serverBanner,
        clientKexInit,
        serverKexInit
    )
    let negotiated = contractSshNegotiateKexInit(clientKexInit, serverKexInit)
    let clientPrivate = hexToBytes(
        "5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71"
    )
    let serverPrivate = hexToBytes(
        "4f2f6c59b0d4f52b8c0db0ce1d77c4f1e1dcb3ea65b31f8f5a6c6e7f8899aabb"
    )
    let ed25519Seed = hexToBytes(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    let initResult = contractSshBuildKexEcdhInitX25519(clientPrivate)
    let encodedClientNewKeys = contractSshEncodeNewKeys()
    let encodedServerNewKeys = contractSshEncodeNewKeys()
    let serverBundle = contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(
        ContractSshServerLibraryStartupX25519Ed25519SeedRequest(
            transcript,
            serverPrivate,
            initResult.encodedInit,
            ed25519Seed,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys
        )
    )
    let wrongKnownHost = incrementalBytes(32, start: 1)
    let outcome = contractTryPrepareSshClientLibraryStartupX25519Request(
        ContractSshClientLibraryStartupX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                transcript,
                clientPrivate,
                initResult.encodedInit,
                serverBundle.handshake.encodedReply,
                negotiated,
                encodedClientNewKeys,
                encodedServerNewKeys,
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
                    expectedHostKeySha256: wrongKnownHost,
                    requireKnownHost: true,
                    requireHostSignature: true,
                    requireVerifiedHost: true
                )
            )
        )
    )

    println("== ssh-library-known-host-failure ==")
    println("failure_ok=${outcome.ok}")
    println("failure_code=${optionalContractCodeText(outcome.code)}")
    println("failure_ignite_code=${optionalIgniteCodeText(outcome.igniteCode)}")
    println("failure_message=${outcome.message}")
    println("failure_expected_host_sha256_hex=${bytesToHexLower(wrongKnownHost)}")
    println("failure_actual_host_sha256_hex=${bytesToHexLower(serverBundle.handshake.hostKeySha256)}")
    println("failure_note=known-host mismatch must fail closed during SSH client library startup rather than silently downgrading verification")
}

private func formatBanner(banner: ContractSshVersionBanner): String {
    if (banner.comments.size == 0) {
        return "${banner.protocolVersion}-${banner.softwareVersion}"
    }
    "${banner.protocolVersion}-${banner.softwareVersion} ${banner.comments}"
}

private func joinStrings(values: Array<String>): String {
    var out = ""
    var i = 0
    while (i < values.size) {
        if (i > 0) {
            out += ","
        }
        out += values[i]
        i += 1
    }
    out
}

private func optionalContractCodeText(code: ?ContractErrorCode): String {
    match (code) {
        case Some(value) => value.toString()
        case None => "none"
    }
}

private func optionalIgniteCodeText(code: ?ContractIgniteCryptoErrorCode): String {
    match (code) {
        case Some(value) => value.toString()
        case None => "none"
    }
}

private func incrementalBytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i = 0
    while (i < size) {
        out[i] = UInt8((start + i) & 0xff)
        i += 1
    }
    out
}

private func bytesToHexLower(bytes: Array<Byte>): String {
    let out = ArrayList<Byte>()
    for (value in bytes) {
        let current = UInt8(value)
        out.add(hexNibbleLower((Int64(current) >> 4) & 0xf))
        out.add(hexNibbleLower(Int64(current) & 0xf))
    }
    String.fromUtf8(out.toArray())
}

private func hexNibbleLower(value: Int64): Byte {
    if (value < 10) {
        return UInt8(Int64(b'0') + value)
    }
    UInt8(Int64(b'a') + (value - 10))
}

private func hexToBytes(hex: String): Array<Byte> {
    let normalized = hex.trimAscii()
    if ((normalized.size % 2) != 0) {
        throw Exception("hex string length must be even")
    }
    let bytes = normalized.toArray()
    let out = ArrayList<Byte>()
    var i = 0
    while (i < normalized.size) {
        out.add(UInt8(parseHexByte(UInt8(bytes[i]), UInt8(bytes[i + 1]))))
        i += 2
    }
    out.toArray()
}

private func parseHexByte(high: UInt8, low: UInt8): Int64 {
    (parseHexNibble(high) << 4) | parseHexNibble(low)
}

private func parseHexNibble(ch: UInt8): Int64 {
    if (ch >= b'0' && ch <= b'9') {
        return Int64(ch) - Int64(b'0')
    }
    let lower = if (ch >= b'A' && ch <= b'F') { ch + UInt8(32) } else { ch }
    if (lower >= b'a' && lower <= b'f') {
        return Int64(lower) - Int64(b'a') + 10
    }
    throw Exception("invalid hex digit")
}
