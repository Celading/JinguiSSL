package jinguissl_handshake_interface_demo

import std.collection.ArrayList
import std.fs.File
import jinguissl.contract.*

main(): Int64 {
    try {
        runTlsHttpFirstFlightDemo()
        runTlsHttpVerifiedSessionDemo()
        runSshLibraryHandshakeDemo()
        0
    } catch (e: Exception) {
        println("fatal=${e}")
        1
    }
}

private func runTlsHttpFirstFlightDemo(): Unit {
    let serverName = "www.example.com"
    let alpnProtocols = ["h2", "http/1.1"]
    let hello = contractTls13BuildHttpClientHelloX25519(
        serverName,
        alpnProtocols: alpnProtocols,
        clientPrivateKey: Some(incrementalBytes(32, start: 17))
    )
    let firstRecord = contractTlsEncodePlaintextRecord(
        ContractTlsVersion.Tls12,
        ContractTlsRecordContentType.Handshake,
        hello.encodedClientHello
    )

    println("== tls-http-first-flight ==")
    println("tls_server_name=${serverName}")
    println("tls_alpn=${joinStrings(alpnProtocols)}")
    println("tls_client_hello_len=${hello.encodedClientHello.size}")
    println("tls_first_record_len=${firstRecord.size}")
    println("tls_client_public_key_hex=${bytesToHexLower(hello.clientPublicKey)}")
    println("tls_first_record_prefix_hex=${hexPrefix(firstRecord, 24)}")
    println("tls_note=write tls_first_record bytes to socket; encodedClientHello alone is not wire-ready")
}

private func runTlsHttpVerifiedSessionDemo(): Unit {
    let serverName = "www.example.com"
    let alpnProtocols = ["h2", "http/1.1"]
    let leafPem = readText("../../testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("../../testdata/x509/policy_intermediate.pem")
    let rootPem = readText("../../testdata/x509/policy_root.pem")
    let leafKeyPem = readText("../../testdata/x509/policy_leaf_key_pkcs8.pem")
    let policy = ContractTlsHttpNegotiationPolicy(
        requireServerName: true,
        allowedServerNames: [serverName],
        alpnPreference: alpnProtocols
    )
    let clientHello = contractTls13BuildHttpClientHelloX25519Request(
        ContractTls13HttpClientHelloX25519Request(
            serverName,
            alpnProtocols: alpnProtocols,
            clientPrivateKey: Some(incrementalBytes(32, start: 48))
        )
    )
    let serverFlight = contractTls13BuildHttpServerFlightX25519Request(
        ContractTls13HttpServerFlightX25519Request(
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 80),
            "${leafPem}\n${intermediatePem}",
            leafKeyPem,
            policy: policy
        )
    )
    let verifiedSession = contractTls13VerifyHttpServerFlightX25519WithSessionRequest(
        ContractTls13HttpVerifyServerFlightX25519Request(
            clientHello,
            serverFlight,
            ContractHttpClientTlsTrustRequest(
                rootPem,
                intermediatesPemBundle: intermediatePem,
                hostname: serverName,
                validationTime: "230101000000Z",
                policy: policy
            )
        )
    )
    let runtime = contractTls13CreateVerifiedSessionChannelSetRequest(
        ContractTls13HttpVerifiedSessionRequest(verifiedSession)
    )
    let ciphertext = runtime.clientChannel.sealApplicationData(
        "tls-verified-session-runtime".toArray()
    )
    let opened = runtime.serverChannel.openApplicationData(ciphertext)
    let localTrafficUpdate = contractTls13RotateClientTrafficInVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionKeyUpdateRequest(
            verifiedSession,
            requestPeerUpdate: true
        )
    )
    let localUpdateCiphertext = localTrafficUpdate.runtime.clientChannel.sealApplicationData(
        "tls-key-update-local".toArray()
    )
    let localUpdateOpened = localTrafficUpdate.runtime.serverChannel.openApplicationData(
        localUpdateCiphertext
    )
    let peerTrafficUpdate = contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
            verifiedSession,
            localTrafficUpdate.encodedKeyUpdate
        )
    )
    let peerUpdateCiphertext = peerTrafficUpdate.runtime.serverChannel.sealApplicationData(
        "tls-key-update-peer".toArray()
    )
    let peerUpdateOpened = peerTrafficUpdate.runtime.clientChannel.openApplicationData(
        peerUpdateCiphertext
    )
    let encryptedCloseNotify = runtime.clientChannel.sendCloseNotify()
    let decodedCloseNotify = runtime.serverChannel.openAlert(encryptedCloseNotify)

    println("== tls-http-verified-session ==")
    println("tls_server_hello_len=${serverFlight.serverHello.size}")
    println("tls_encrypted_extensions_len=${serverFlight.encryptedExtensions.size}")
    println("tls_finished_len=${serverFlight.finishedHandshake.size}")
    println("tls_verified_selected_alpn=${verifiedSession.result.selectedAlpn}")
    println("tls_verified_chain_length=${verifiedSession.result.chainLength}")
    println("tls_runtime_opened_payload=${String.fromUtf8(opened)}")
    println("tls_key_update_request_peer=${localTrafficUpdate.requestPeerUpdate}")
    println("tls_key_update_len=${localTrafficUpdate.encodedKeyUpdate.size}")
    println("tls_key_update_local_payload=${String.fromUtf8(localUpdateOpened)}")
    println("tls_key_update_peer_payload=${String.fromUtf8(peerUpdateOpened)}")
    println("tls_close_notify=${decodedCloseNotify.isCloseNotify}")
    println("tls_note=verified session is stable at contract object/runtime level; raw response framing still belongs to your adapter")
}

private func runSshLibraryHandshakeDemo(): Unit {
    let clientBanner = contractSshBuildVersionBanner("jinguiSSL-demo-client", comments: "handshake-interface")
    let serverBanner = contractSshBuildVersionBanner("jinguiSSL-demo-server", comments: "handshake-interface")
    let clientKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 64))
    let serverKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 96))
    let transcript = contractSshBuildKexExchangeTranscriptFromPrelude(
        clientBanner,
        serverBanner,
        clientKexInit,
        serverKexInit
    )
    let negotiated = contractSshNegotiateKexInit(clientKexInit, serverKexInit)
    let clientPrivate = hexToBytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    let serverPrivate = hexToBytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    let ed25519Seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    let initResult = contractSshBuildKexEcdhInitX25519(clientPrivate)
    let encodedClientNewKeys = contractSshEncodeNewKeys()
    let encodedServerNewKeys = contractSshEncodeNewKeys()

    let serverHandshake = contractSshCompleteServerInitialHandshakeX25519Ed25519Request(
        ContractSshServerInitialHandshakeX25519Ed25519Request(
            transcript,
            serverPrivate,
            initResult.encodedInit,
            ed25519Seed,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys
        )
    )
    let clientHandshake = contractSshCompleteClientInitialHandshakeX25519Request(
        ContractSshClientInitialHandshakeX25519Request(
            transcript,
            clientPrivate,
            initResult.encodedInit,
            serverHandshake.encodedReply,
            negotiated,
            encodedClientNewKeys,
            encodedServerNewKeys,
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
                expectedHostKeySha256: serverHandshake.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
    )

    let serverRuntimeBundle = contractPrepareSshServerRuntimeRequest(
        ContractSshServerRuntimeRequest(serverHandshake)
    )
    let clientRuntimeBundle = contractPrepareSshClientRuntimeRequest(
        ContractSshClientRuntimeRequest(clientHandshake)
    )
    let clientPacket = clientRuntimeBundle.runtime.seal(
        "hello-over-ssh-contract".toArray(),
        randomPadding: incrementalBytes(48, start: 160)
    )
    let serverOpened = serverRuntimeBundle.runtime.open(clientPacket)
    let rekeyClientKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 192))
    let rekeyServerKexInit = contractSshBuildDefaultKexInit(cookie: incrementalBytes(16, start: 224))
    let rekeyTranscript = contractSshBuildKexExchangeTranscriptFromPrelude(
        clientBanner,
        serverBanner,
        rekeyClientKexInit,
        rekeyServerKexInit
    )
    let rekeyClientPrivate = hexToBytes("5c3a3d02825f2a5f6905aef0d8c8d3f0a4f8df94d153c5e8e91c1f1f9a8e6f71")
    let rekeyServerPrivate = hexToBytes("4f2f6c59b0d4f52b8c0db0ce1d77c4f1e1dcb3ea65b31f8f5a6c6e7f8899aabb")
    let rekeyInit = contractSshBuildKexEcdhInitX25519Request(
        ContractSshBuildKexEcdhInitX25519Request(rekeyClientPrivate)
    )
    let rekeyServerHandshake = contractSshCompleteServerInitialHandshakeX25519Ed25519Request(
        ContractSshServerInitialHandshakeX25519Ed25519Request(
            rekeyTranscript,
            rekeyServerPrivate,
            rekeyInit.encodedInit,
            ed25519Seed,
            negotiated,
            contractSshEncodeNewKeys(),
            contractSshEncodeNewKeys()
        )
    )
    let rekeyServerSession = contractSshServerProcessKexEcdhInitX25519Request(
        ContractSshServerProcessKexEcdhInitX25519Request(
            rekeyTranscript,
            rekeyServerPrivate,
            rekeyInit.encodedInit,
            ContractSshHostSigningResult(
                rekeyServerHandshake.serverHostKey,
                rekeyServerHandshake.hostSignature,
                rekeyServerHandshake.hostKeyAlgorithm,
                rekeyServerHandshake.hostSignatureAlgorithm,
                rekeyServerHandshake.hostKeySha256
            )
        )
    )
    let rekeyClientSession = contractSshClientProcessKexEcdhReplyX25519Request(
        ContractSshClientProcessKexEcdhReplyX25519Request(
            rekeyTranscript,
            rekeyClientPrivate,
            rekeyInit.encodedInit,
            rekeyServerSession.encodedReply,
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
                expectedHostKeySha256: serverHandshake.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
    )
    let serverRekeyBundle = contractPrepareSshServerRuntimeRekeyFromSessionStateRequest(
        ContractSshServerRuntimeSessionRekeyRequest(
            serverRuntimeBundle.runtime,
            rekeyServerSession.session,
            contractSshEncodeNewKeys(),
            contractSshEncodeNewKeys()
        )
    )
    let clientRekeyBundle = contractPrepareSshClientRuntimeRekeyFromSessionStateRequest(
        ContractSshClientRuntimeSessionRekeyRequest(
            clientRuntimeBundle.runtime,
            rekeyClientSession,
            contractSshEncodeNewKeys(),
            contractSshEncodeNewKeys(),
            policy: ContractSshHostVerificationPolicy(
                negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
                expectedHostKeySha256: serverHandshake.hostKeySha256,
                requireKnownHost: true,
                requireHostSignature: true,
                requireVerifiedHost: true
            )
        )
    )
    let rekeyPacket = clientRekeyBundle.runtime.seal(
        "hello-after-ssh-rekey".toArray(),
        randomPadding: incrementalBytes(48, start: 240)
    )
    let rekeyOpened = serverRekeyBundle.runtime.open(rekeyPacket)

    println("== ssh-library-handshake ==")
    println("ssh_client_banner=${formatBanner(clientBanner)}")
    println("ssh_server_banner=${formatBanner(serverBanner)}")
    println("ssh_kex_algorithm=${negotiated.kexAlgorithm}")
    println("ssh_server_hostkey_algorithm=${negotiated.serverHostKeyAlgorithm}")
    println("ssh_session_id_hex=${bytesToHexLower(clientHandshake.sessionId)}")
    println("ssh_host_key_sha256_hex=${bytesToHexLower(serverHandshake.hostKeySha256)}")
    println("ssh_encoded_init_len=${initResult.encodedInit.size}")
    println("ssh_encoded_reply_len=${serverHandshake.encodedReply.size}")
    println("ssh_runtime_packet_len=${clientPacket.size}")
    println("ssh_runtime_opened_payload=${String.fromUtf8(serverOpened.payload)}")
    println("ssh_rekey_exchange_hash_hex=${bytesToHexLower(clientRekeyBundle.session.exchangeHash)}")
    println("ssh_rekey_packet_len=${rekeyPacket.size}")
    println("ssh_rekey_opened_payload=${String.fromUtf8(rekeyOpened.payload)}")
    println("ssh_note=carry handshake result into runtime bundle, then replace runtime from session-state rekey instead of rebuilding transport state from raw bytes")
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

private func incrementalBytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i = 0
    while (i < size) {
        out[i] = UInt8((start + i) & 0xff)
        i += 1
    }
    out
}

private func hexPrefix(bytes: Array<Byte>, limitBytes: Int64): String {
    let clamped = if (bytes.size < limitBytes) { bytes.size } else { limitBytes }
    let prefix = Array<Byte>(clamped, repeat: 0)
    var i = 0
    while (i < clamped) {
        prefix[i] = bytes[i]
        i += 1
    }
    let rendered = bytesToHexLower(prefix)
    if (clamped == bytes.size) {
        return rendered
    }
    "${rendered}..."
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

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}
