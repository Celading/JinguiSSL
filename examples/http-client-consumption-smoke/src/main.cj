package jinguissl_http_client_consumption_smoke

import std.collection.ArrayList
import std.fs.File
import jinguissl.contract.*

main(): Int64 {
    try {
        runHttpClientProviderGateDemo()
        runHttpClientFallbackGuidanceDemo()
        runTlsHttpClientRuntimeSmoke()
        0
    } catch (e: Exception) {
        println("fatal=${e}")
        1
    }
}

private func runHttpClientProviderGateDemo(): Unit {
    let gate = contractRequireProviderConsumptionGate(
        ContractProviderConsumptionPath.HttpClientTls
    )
    let profile = contractDescribeProviderSmokeProfile(
        ContractProviderSmokeProfile.ProviderCandidate
    )
    let readiness = contractRequireProviderSmokeProfile(
        ContractProviderSmokeProfile.ProviderCandidate
    )

    println("== http-client-provider-gate ==")
    println("gate_path=${gate.path}")
    println("gate_status=${gate.status}")
    println("gate_selected_entry=${gate.selectedEntryId}")
    println("gate_public_path=${gate.publicPath}")
    println("gate_release_path=${gate.releasePath}")
    println("gate_risk_level=${gate.riskLevel}")
    println("gate_ready_now=${gate.readyNow}")
    println("gate_candidate_order=${joinStrings(gate.candidateOrder)}")
    println("gate_fallback_target=${gate.fallbackTarget}")
    println("gate_attach_plan_meaning=${gate.guide.attachPlanMeaning}")
    println("gate_observability_tags=${joinStrings(gate.observabilityTags)}")
    println("smoke_profile_label=${profile.label}")
    println("smoke_overall_ready=${readiness.overallReady}")
    println("smoke_has_provider_selection_coverage=${readiness.hasProviderSelectionCoverage}")
    println("smoke_has_handshake_coverage=${readiness.hasHandshakeCoverage}")
    println("smoke_warning_count=${readiness.warnings.size}")
    println("gate_note=published as provider-candidate only; keep stdx-default as stable fallback and do not present this path as default HTTPS attach")
}

private func runHttpClientFallbackGuidanceDemo(): Unit {
    let providerUnavailable = contractResolveProviderFallbackOutcome(
        ContractProviderFallbackResolutionRequest(
            ContractProviderFallbackCauseCode.ProviderUnavailable
        )
    )
    let verifyFailure = contractResolveProviderFallbackOutcome(
        ContractProviderFallbackResolutionRequest(
            ContractProviderFallbackCauseCode.TlsVerifyError
        )
    )
    let consumedHandshakeFailure = contractResolveProviderFallbackOutcome(
        ContractProviderFallbackResolutionRequest(
            ContractProviderFallbackCauseCode.TlsHandshakeError,
            connectionConsumed: true
        )
    )

    println("== http-client-fallback-guidance ==")
    println("provider_unavailable_outcome=${providerUnavailable.finalOutcome}")
    println("provider_unavailable_target=${providerUnavailable.fallbackTarget}")
    println("verify_error_outcome=${verifyFailure.finalOutcome}")
    println("verify_error_must_surface=${verifyFailure.mustSurface}")
    println("consumed_handshake_outcome=${consumedHandshakeFailure.finalOutcome}")
    println("consumed_handshake_target=${consumedHandshakeFailure.fallbackTarget}")
    println("fallback_note=verify/precheck failures stay surfaced; only provider-candidate selection/runtime-unavailable style failures may suggest stdx-default")
}

private func runTlsHttpClientRuntimeSmoke(): Unit {
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
    let firstRecord = contractTlsEncodePlaintextRecord(
        ContractTlsVersion.Tls12,
        ContractTlsRecordContentType.Handshake,
        clientHello.encodedClientHello
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
        "http-client-consumption-smoke".toArray()
    )
    let opened = runtime.serverChannel.openApplicationData(ciphertext)
    let localTrafficUpdate = contractTls13RotateClientTrafficInVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionKeyUpdateRequest(
            verifiedSession,
            requestPeerUpdate: true
        )
    )
    let peerTrafficUpdate = contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
        ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
            verifiedSession,
            localTrafficUpdate.encodedKeyUpdate
        )
    )
    let peerUpdateCiphertext = peerTrafficUpdate.runtime.serverChannel.sealApplicationData(
        "http-client-peer-update".toArray()
    )
    let peerUpdateOpened = peerTrafficUpdate.runtime.clientChannel.openApplicationData(
        peerUpdateCiphertext
    )
    let encryptedCloseNotify = runtime.clientChannel.sendCloseNotify()
    let decodedCloseNotify = runtime.serverChannel.openAlert(encryptedCloseNotify)

    println("== http-client-runtime-smoke ==")
    println("tls_server_name=${serverName}")
    println("tls_alpn=${joinStrings(alpnProtocols)}")
    println("tls_client_hello_len=${clientHello.encodedClientHello.size}")
    println("tls_first_record_len=${firstRecord.size}")
    println("tls_first_record_prefix_hex=${hexPrefix(firstRecord, 24)}")
    println("tls_server_hello_len=${serverFlight.serverHello.size}")
    println("tls_verified_selected_alpn=${verifiedSession.result.selectedAlpn}")
    println("tls_verified_chain_length=${verifiedSession.result.chainLength}")
    println("tls_runtime_payload=${String.fromUtf8(opened)}")
    println("tls_key_update_len=${localTrafficUpdate.encodedKeyUpdate.size}")
    println("tls_peer_update_payload=${String.fromUtf8(peerUpdateOpened)}")
    println("tls_close_notify=${decodedCloseNotify.isCloseNotify}")
    println("tls_note=wire-ready first flight is the plaintext record; response-side stable contract begins at serverFlight/verifiedSession/runtime, not raw socket framing")
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

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}
