package jinguissl.tests

import std.collection.ArrayList
import std.fs.File
import jinguissl.live.*
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.tls.{TLS13_CIPHER_SUITE_AES_256_GCM_SHA384, tls13DeriveSecretsFromX25519ForCipherSuite, tls13ExtractServerX25519KeyShare}

private let LIVE_SOURCE_ROOT: String = ""
private let TEST_HOST_WWW: String = "www." + "example.com"

private class WireDerivedFixture {
    let clientHello: ContractTls13HttpClientHelloX25519
    let serverFlight: ContractTls13HttpServerFlight
    let trust: ContractHttpClientTlsTrustRequest
    let records: Array<Array<Byte>>

    init(
        clientHello: ContractTls13HttpClientHelloX25519,
        serverFlight: ContractTls13HttpServerFlight,
        trust: ContractHttpClientTlsTrustRequest,
        records: Array<Array<Byte>>
    ) {
        this.clientHello = clientHello
        this.serverFlight = serverFlight
        this.trust = trust
        this.records = records
    }
}

private func readText(path: String): String {
    String.fromUtf8(File.readFrom("${LIVE_SOURCE_ROOT}${path}"))
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

private func concatRecords(records: Array<Array<Byte>>): Array<Byte> {
    let out = ArrayList<Byte>()
    for (record in records) {
        for (b in record) {
            out.add(b)
        }
    }
    out.toArray()
}

private func tamperByte(input: Array<Byte>, offsetFromEnd!: Int64 = 0): Array<Byte> {
    let out = input.clone()
    let index = out.size - 1 - offsetFromEnd
    if (out[index] == UInt8(0)) {
        out[index] = UInt8(1)
    } else {
        out[index] = UInt8(0)
    }
    out
}

private func buildWireFixture(): WireDerivedFixture {
    let serverName = TEST_HOST_WWW
    let leafPem = readText("testdata/x509/policy_leaf.pem")
    let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
    let rootPem = readText("testdata/x509/policy_root.pem")
    let certChainPem = "${leafPem}\n${intermediatePem}"
    let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")
    let policy = ContractTlsHttpNegotiationPolicy(
        requireServerName: true,
        allowedServerNames: [serverName],
        alpnPreference: ["h2", "http/1.1"]
    )
    let plan = contractPlanHttpServerAttachRequest(
        ContractHttpServerLibraryStartupRequest(
            ContractHttpServerTlsConfigRequest(
                certChainPem,
                leafKeyPem,
                alpnProtocols: ["h2", "http/1.1"],
                requireHttp2Alpn: true
            ),
            aesBackendHint: "shim"
        )
    )
    let clientHello = contractTls13BuildHttpClientHelloX25519(
        serverName,
        alpnProtocols: ["h2", "http/1.1"],
        clientPrivateKey: Some(incrementalBytes(32, start: 48))
    )
    let session = contractAttachStableAcceptedTransportTls13X25519(
        ContractAcceptedTransportDescriptor(
            "c188-wire-derived-client-runtime",
            localEndpoint: "127.0.0.1:443",
            remoteEndpoint: "127.0.0.1:55443"
        ),
        plan,
        clientHello.encodedClientHello,
        incrementalBytes(32, start: 80),
        policy: policy
    )
    let trust = ContractHttpClientTlsTrustRequest(
        rootPem,
        intermediatesPemBundle: intermediatePem,
        hostname: serverName,
        policy: policy
    )
    WireDerivedFixture(
        clientHello,
        session.result.serverFlight,
        trust,
        session.initialHandshake.records
    )
}

private func collectRecords(records: Array<Array<Byte>>): ContractTls13IncrementalHandshakeResult {
    contractTls13CollectIncrementalHandshakeRecords([], concatRecords(records))
}

private func rebuildProtectedRecords(
    fixture: WireDerivedFixture,
    certificateVerifyOverride!: ?Array<Byte> = None,
    finishedOverride!: ?Array<Byte> = None,
    fragments!: ?Array<Array<Byte>> = None,
    compatibilityCcs!: Bool = false
): Array<Array<Byte>> {
    let binding = contractTls13ResolveCipherBindingFromServerFlight(fixture.serverFlight)
    let serverPublicKey = tls13ExtractServerX25519KeyShare(fixture.serverFlight.serverHello)
    let helloTranscript = concatRecords([
        fixture.clientHello.encodedClientHello,
        fixture.serverFlight.serverHello
    ])
    let helloTranscriptHash = if (
        binding.cipherSuite == TLS13_CIPHER_SUITE_AES_256_GCM_SHA384
    ) {
        sha384(helloTranscript)
    } else {
        sha256(helloTranscript)
    }
    let secrets = tls13DeriveSecretsFromX25519ForCipherSuite(
        fixture.clientHello.clientPrivateKey,
        serverPublicKey,
        helloTranscriptHash,
        binding.cipherSuite
    )
    let (clientHandshakeKey, clientHandshakeIv) = contractTls13DeriveApplicationTrafficKeyIv(
        secrets.clientHsTrafficSecret,
        keyLen: binding.keyLen,
        ivLen: binding.ivLen
    )
    let (serverHandshakeKey, serverHandshakeIv) = contractTls13DeriveApplicationTrafficKeyIv(
        secrets.serverHsTrafficSecret,
        keyLen: binding.keyLen,
        ivLen: binding.ivLen
    )
    let channel = contractTls13CreateServerRecordChannel(
        ContractTls13ApplicationKeyMaterial(
            clientHandshakeKey,
            clientHandshakeIv,
            serverHandshakeKey,
            serverHandshakeIv
        ),
        algorithm: binding.algorithm
    )
    let certificateVerify = match (certificateVerifyOverride) {
        case Some(value) => value
        case None => fixture.serverFlight.certificateVerifyHandshake
    }
    let finished = match (finishedOverride) {
        case Some(value) => value
        case None => fixture.serverFlight.finishedHandshake
    }
    let output = ArrayList<Array<Byte>>()
    output.add(contractTlsEncodePlaintextRecord(
        ContractTlsVersion.Tls12, ContractTlsRecordContentType.Handshake, fixture.serverFlight.serverHello
    ))
    if (compatibilityCcs) {
        output.add(contractTlsEncodePlaintextRecord(
            ContractTlsVersion.Tls12, ContractTlsRecordContentType.ChangeCipherSpec, [UInt8(1)]
        ))
    }
    let pieces = fragments ?? [fixture.serverFlight.encryptedExtensions,
        fixture.serverFlight.certificateHandshake, certificateVerify, finished]
    for (piece in pieces) {
        output.add(channel.seal(ContractTlsRecordContentType.Handshake, piece))
    }
    output.toArray()
}

private func openWireDerived(
    fixture: WireDerivedFixture,
    records: Array<Array<Byte>>
): ContractTls13WireDerivedClientHandshakeOutcome {
    contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
        fixture.clientHello,
        fixture.trust,
        collectRecords(records)
    )
}

@Test
public class ContractTls13WireDerivedClientRuntimeTestSuite {
    @TestCase
    public func testWireDerivedRuntimeCompletesFromFragmentedServerRecords(): Unit {
        let fixture = buildWireFixture()
        let wire = concatRecords(fixture.records)
        let needMore = contractTls13CollectIncrementalHandshakeRecords([], wire[0..3])
        let needMoreOutcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            fixture.trust,
            needMore
        )
        @Assert(needMoreOutcome.ok, false)
        @Assert(needMoreOutcome.status.toString(), "NEED_MORE_BYTES")
        @Assert(needMoreOutcome.needBytes, Int64(2))

        let collected = contractTls13CollectIncrementalHandshakeRecords(needMore.pendingBytes, wire[3..])
        let outcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            fixture.trust,
            collected
        )
        @Assert(outcome.ok, true)
        @Assert(outcome.status.toString(), "COMPLETED")
        if (let Some(result) <- outcome.result) {
            @Assert(result.runtime.status.toString(), "READY")
            @Assert(result.runtime.result.selectedAlpn, "h2")
            @Assert(result.mappedFlight.serverFlight.selectedAlpn, "h2")
            @Assert(result.mappedFlight.serverHello, fixture.serverFlight.serverHello)
            @Assert(result.clientFinished.encodedFinishedHandshake[0], UInt8(20))
            @Assert(result.clientFinished.encodedRecord[0], UInt8(23))
        } else {
            @Fail("wire-derived success should carry result")
        }
    }

    @TestCase
    public func testWireDerivedRuntimeCompletesFromCoalescedServerRecordsAndAppDataWorks(): Unit {
        let fixture = buildWireFixture()
        let outcome = openWireDerived(fixture, fixture.records)

        @Assert(outcome.ok, true)
        @Assert(outcome.recordsObserved, Int64(5))
        if (let Some(result) <- outcome.result) {
            @Assert(result.runtime.secureSessionReady, true)
            @Assert(result.runtime.result.chainLength, Int64(3))
            @Assert(result.mappedFlight.encryptedExtensions, fixture.serverFlight.encryptedExtensions)
            @Assert(result.mappedFlight.certificateHandshake, fixture.serverFlight.certificateHandshake)
            let encodedAppData = result.runtime.channelSet.clientChannel.sealApplicationData("ping".toArray())
            let opened = result.runtime.channelSet.serverChannel.openApplicationData(encodedAppData)
            @Assert(opened, "ping".toArray())
        } else {
            @Fail("wire-derived coalesced success should carry result")
        }
    }

    @TestCase
    public func testWireDerivedRequestWrapper(): Unit {
        let fixture = buildWireFixture()
        let runtime = contractTls13OpenHttpClientRuntimeFromWireDerivedServerFlightRequest(
            ContractTls13WireDerivedClientHandshakeRequest(
                fixture.clientHello,
                fixture.trust,
                collectRecords(fixture.records)
            )
        )

        @Assert(runtime.runtime.status.toString(), "READY")
        @Assert(runtime.mappedFlight.decodedProtectedRecordCount, Int64(4))
        @Assert(runtime.clientFinished.writeSurface, "tls13-client-finished-record")
    }

    @TestCase
    public func testWireDerivedRuntimeSurfacesPeerAlertAndMalformedRecord(): Unit {
        let fixture = buildWireFixture()
        let alert = contractTls13CollectIncrementalHandshakeRecords(
            [],
            contractTlsEncodeAlertRecord(
                ContractTlsVersion.Tls13,
                ContractTlsAlertLevel.AlertFatal,
                ContractTlsAlertDescription.AlertHandshakeFailure
            )
        )
        let alertOutcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            fixture.trust,
            alert
        )
        @Assert(alertOutcome.ok, false)
        @Assert(alertOutcome.status.toString(), "PEER_ALERT")
        if (let Some(peerAlert) <- alertOutcome.peerAlert) {
            @Assert(peerAlert.description.toString(), "HANDSHAKE_FAILURE")
        } else {
            @Fail("peer alert outcome should carry alert")
        }

        let malformed = contractTls13CollectIncrementalHandshakeRecords(
            [],
            [UInt8(0xff), UInt8(0x03), UInt8(0x04), UInt8(0x00), UInt8(0x00)]
        )
        let malformedOutcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            fixture.trust,
            malformed
        )
        @Assert(malformedOutcome.ok, false)
        @Assert(malformedOutcome.status.toString(), "MALFORMED")
    }

    @TestCase
    public func testWireDerivedRuntimeSurfacesTrustHostnameAndAlpnRejections(): Unit {
        let fixture = buildWireFixture()
        let collected = collectRecords(fixture.records)
        let trustRejected = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            ContractHttpClientTlsTrustRequest(
                readText("testdata/x509/crl_test_root.pem"),
                intermediatesPemBundle: fixture.trust.intermediatesPemBundle,
                hostname: TEST_HOST_WWW,
                policy: fixture.trust.policy
            ),
            collected
        )
        @Assert(trustRejected.ok, false)
        @Assert(trustRejected.status.toString(), "VERIFICATION_FAILED")

        let hostnameRejected = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            ContractHttpClientTlsTrustRequest(
                fixture.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: fixture.trust.intermediatesPemBundle,
                hostname: "wrong.example.com",
                policy: fixture.trust.policy
            ),
            collected
        )
        @Assert(hostnameRejected.ok, false)
        @Assert(hostnameRejected.status.toString(), "VERIFICATION_FAILED")

        let alpnRejected = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(
            fixture.clientHello,
            ContractHttpClientTlsTrustRequest(
                fixture.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: fixture.trust.intermediatesPemBundle,
                hostname: TEST_HOST_WWW,
                policy: ContractTlsHttpNegotiationPolicy(
                    requireServerName: true,
                    allowedServerNames: [TEST_HOST_WWW],
                    alpnPreference: ["http/1.1"]
                )
            ),
            collected
        )
        @Assert(alpnRejected.ok, false)
        @Assert(alpnRejected.status.toString(), "VERIFICATION_FAILED")
        @Assert(alpnRejected.message.contains("ALPN"), true)
    }

    @TestCase
    public func testWireDerivedRuntimeRejectsBadCertificateVerifyAndFinished(): Unit {
        let fixture = buildWireFixture()
        let badCertificateVerifyRecords = rebuildProtectedRecords(
            fixture,
            certificateVerifyOverride: Some(tamperByte(fixture.serverFlight.certificateVerifyHandshake))
        )
        let badCertificateVerify = openWireDerived(fixture, badCertificateVerifyRecords)
        @Assert(badCertificateVerify.ok, false)
        @Assert(badCertificateVerify.status.toString(), "VERIFICATION_FAILED")
        @Assert(badCertificateVerify.message.contains("CertificateVerify"), true)

        let badFinishedRecords = rebuildProtectedRecords(
            fixture,
            finishedOverride: Some(tamperByte(fixture.serverFlight.finishedHandshake))
        )
        let badFinished = openWireDerived(fixture, badFinishedRecords)
        @Assert(badFinished.ok, false)
        @Assert(badFinished.status.toString(), "VERIFICATION_FAILED")
        @Assert(badFinished.message.contains("Finished"), true)
    }

    @TestCase
    public func testHandshakeMessagesCoalescedIntoOneProtectedRecord(): Unit {
        let fixture = buildWireFixture()
        assertFramedRuntime(fixture, rebuildProtectedRecords(fixture, fragments: Some([flightMessages(fixture)])))
    }

    @TestCase
    public func testCoalescedHandshakeWithCompatibilityCcs(): Unit {
        let fixture = buildWireFixture()
        assertFramedRuntime(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([flightMessages(fixture)]), compatibilityCcs: true))
    }

    @TestCase
    public func testHandshakeHeaderAndBodySplitAcrossProtectedRecords(): Unit {
        let fixture = buildWireFixture()
        let messages = flightMessages(fixture)
        assertFramedRuntime(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([messages[0..1], messages[1..3], messages[3..19], messages[19..]])))
    }

    @TestCase
    public func testEveryHandshakeMessageSplitAndCoalescedWithNext(): Unit {
        let fixture = buildWireFixture()
        let messages = flightMessages(fixture)
        let chunks = ArrayList<Array<Byte>>()
        var offset: Int64 = 0
        while (offset < messages.size) {
            let end = if (offset + 37 < messages.size) { offset + 37 } else { messages.size }
            chunks.add(messages[offset..end])
            offset = end
        }
        assertFramedRuntime(fixture, rebuildProtectedRecords(fixture, fragments: Some(chunks.toArray())))
    }

    @TestCase
    public func testCompatibilityCcsBeforeServerHelloAndRepeatedCcs(): Unit {
        let fixture = buildWireFixture()
        let records = rebuildProtectedRecords(fixture, fragments: Some([flightMessages(fixture)]), compatibilityCcs: true)
        assertFramedRuntime(fixture, [records[1], records[0], records[1], records[1], records[2]])
        @Assert(openWireDerived(fixture, [records[1]]).status.toString(), "NEED_MORE_BYTES")
    }

    @TestCase
    public func testCoalescedFlightPreservesPinningAndHostnamePolicy(): Unit {
        let fixture = buildWireFixture()
        let records = collectRecords(rebuildProtectedRecords(fixture, fragments: Some([flightMessages(fixture)])))
        for (wrongHost in [true, false]) {
            let trust = ContractHttpClientTlsTrustRequest(fixture.trust.trustAnchorsPemBundle,
                intermediatesPemBundle: fixture.trust.intermediatesPemBundle,
                hostname: if (wrongHost) { "wrong.example.com" } else { TEST_HOST_WWW },
                pinPolicy: if (wrongHost) { ContractX509PinPolicy() } else {
                    ContractX509PinPolicy(allowedLeafDerSha256: [Array<Byte>(32, repeat: 0)])
                }, policy: fixture.trust.policy)
            let outcome = contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight(fixture.clientHello, trust, records)
            @Assert(outcome.ok, false)
            @Assert(outcome.status.toString(), "VERIFICATION_FAILED")
        }
    }

    @TestCase
    public func testMalformedOrDuplicateEncryptedExtensionsRejected(): Unit {
        let fixture = buildWireFixture()
        let invalid: Array<Array<Byte>> = [
            [8,0,0,10,0,8,0,0,0,0,0,0,0,0],
            [8,0,0,6,0,4,0x12,0x34,0,0],
            [8,0,0,6,0,4,0,16,0,0]
        ]
        for (extensions in invalid) {
            let messages = concatRecords([extensions, fixture.serverFlight.certificateHandshake,
                fixture.serverFlight.certificateVerifyHandshake, fixture.serverFlight.finishedHandshake])
            @Assert(openWireDerived(fixture, rebuildProtectedRecords(fixture,
                fragments: Some([messages]))).status.toString(), "MALFORMED")
        }
    }

    @TestCase
    public func testIncompleteHandshakeMessageNeedsMoreBytes(): Unit {
        let fixture = buildWireFixture()
        let messages = flightMessages(fixture)
        let outcome = openWireDerived(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([messages[0..messages.size - 1]])))
        @Assert(outcome.ok, false)
        @Assert(outcome.status.toString(), "NEED_MORE_BYTES")
    }

    @TestCase
    public func testInvalidCompatibilityCcsRejected(): Unit {
        let fixture = buildWireFixture()
        let records = rebuildProtectedRecords(fixture, compatibilityCcs: true)
        records[1] = contractTlsEncodePlaintextRecord(
            ContractTlsVersion.Tls12, ContractTlsRecordContentType.ChangeCipherSpec, [UInt8(2)]
        )
        @Assert(openWireDerived(fixture, records).status.toString(), "MALFORMED")
    }

    @TestCase
    public func testCcsCannotInterruptFragmentedHandshakeMessage(): Unit {
        let fixture = buildWireFixture()
        let messages = flightMessages(fixture)
        let records = rebuildProtectedRecords(fixture, fragments: Some([messages[0..2], messages[2..]]))
        let ccs = contractTlsEncodePlaintextRecord(
            ContractTlsVersion.Tls12, ContractTlsRecordContentType.ChangeCipherSpec, [UInt8(1)]
        )
        @Assert(openWireDerived(fixture, [records[0], records[1], ccs, records[2]]).status.toString(), "MALFORMED")
    }

    @TestCase
    public func testOversizeHandshakeLengthRejectedBeforeWaitingForBody(): Unit {
        let fixture = buildWireFixture()
        let header = [UInt8(8), UInt8(255), UInt8(255), UInt8(255)]
        @Assert(openWireDerived(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([header]))).status.toString(), "MALFORMED")
    }

    @TestCase
    public func testCoalescedWrongOrderAndBytesAfterFinishedRejected(): Unit {
        let fixture = buildWireFixture()
        let wrong = concatRecords([fixture.serverFlight.certificateHandshake,
            fixture.serverFlight.encryptedExtensions, fixture.serverFlight.certificateVerifyHandshake,
            fixture.serverFlight.finishedHandshake])
        @Assert(openWireDerived(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([wrong]))).status.toString(), "MALFORMED")
        let extra = concatRecords([flightMessages(fixture), [UInt8(0)]])
        @Assert(openWireDerived(fixture, rebuildProtectedRecords(fixture,
            fragments: Some([extra]))).status.toString(), "MALFORMED")
    }

    @TestCase
    public func testIncrementalEntryAuthenticatesReceivedCiphertext(): Unit {
        let fixture = buildWireFixture()
        let records = fixture.records.clone()
        records[2] = tamperByte(records[2])
        let outcome = contractTryTls13OpenHttpClientVerifiedSessionRuntimeFromIncrementalServerFlight(
            fixture.clientHello, fixture.serverFlight, fixture.trust, collectRecords(records))
        @Assert(outcome.ok, false)
        @Assert(outcome.status.toString(), "VERIFICATION_FAILED")
    }
}

private func flightMessages(fixture: WireDerivedFixture): Array<Byte> {
    concatRecords([fixture.serverFlight.encryptedExtensions, fixture.serverFlight.certificateHandshake,
        fixture.serverFlight.certificateVerifyHandshake, fixture.serverFlight.finishedHandshake])
}

private func assertFramedRuntime(fixture: WireDerivedFixture, records: Array<Array<Byte>>): Unit {
    let collected = collectRecords(records)
    let wire = openWireDerived(fixture, records)
    @Assert(wire.ok, true)
    @Assert(wire.status.toString(), "COMPLETED")
    let protected = contractTryTls13OpenHttpClientRuntimeFromProtectedServerFlight(
        fixture.clientHello, fixture.serverFlight, fixture.trust, collected)
    @Assert(protected.ok, true)
    let incremental = contractTryTls13OpenHttpClientVerifiedSessionRuntimeFromIncrementalServerFlight(
        fixture.clientHello, fixture.serverFlight, fixture.trust, collected)
    @Assert(incremental.ok, true)
    if (let Some(result) <- wire.result) {
        @Assert(result.runtime.secureSessionReady, true)
        @Assert(result.mappedFlight.certificateHandshake, fixture.serverFlight.certificateHandshake)
    } else { @Fail("completed wire flight must carry a verified runtime") }
}
