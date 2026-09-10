package jinguissl.tests

import std.collection.ArrayList
import std.fs.File
import jinguissl.contract.*
// Provider-level adversarial fixture only. Standalone consumer examples do not import Core.
import jinguissl_core.crypto.digest.{sha256, sha384}
import jinguissl_core.crypto.ecc.{EcPrivateKey, NamedCurve}
import jinguissl_core.crypto.bignum.BigNum
import jinguissl_core.crypto.compliance.TlsVersion
import jinguissl_core.crypto.tls.*
import jinguissl_core.crypto.x25519.{x25519GeneratePrivateKey, x25519PublicFromPrivate}
import jinguissl_core.crypto.x509.{x509ParsePem, x509ParseEcPrivateKeyPkcs8Pem}

private func engineText(name: String): String { String.fromUtf8(File.readFrom("testdata/x509/${name}")) }
private func engineJoin(parts: Array<Array<Byte>>): Array<Byte> {
    let out = ArrayList<Byte>()
    for (part in parts) { for (b in part) { out.add(b) } }
    out.toArray()
}
private func engineHash(suite: Int64, bytes: Array<Byte>): Array<Byte> {
    if (suite == 0x1302) { sha384(bytes) } else { sha256(bytes) }
}
private func newEngine(suite!: Int64 = 0x1301, quic!: Bool = false, hostname!: String = "www.example.com"): ContractTls13ClientEngine {
    ContractTls13ClientEngine(
        engineText("engine_root.pem"), hostname, "270101000000Z",
        alpnProtocols: ["mqtt"], requireAlpn: true, cipherSuites: [suite],
        quicTransportParameters: if (quic) { Some([UInt8(1), UInt8(0)]) } else { None }
    )
}

private class EngineFixture {
    let messages: Array<Array<Byte>>
    let secrets: Tls13HandshakeSecrets
    init(messages: Array<Array<Byte>>, secrets: Tls13HandshakeSecrets) {
        this.messages = messages
        this.secrets = secrets
    }
}

private func engineFixture(
    client: ContractTls13ClientEngine,
    quic!: Bool = false,
    wrongContext!: Bool = false,
    wrongSigner!: Bool = false,
    alpn!: String = "mqtt",
    extraExtensions!: Array<TlsExtension> = [], request!: Array<Byte> = [], omitRequestFromAuth!: Bool = false
): EngineFixture {
    engineFixtureForHello(client.clientHello(), quic: quic, wrongContext: wrongContext,
        wrongSigner: wrongSigner, alpn: alpn, extraExtensions: extraExtensions,
        request: request, omitRequestFromAuth: omitRequestFromAuth)
}

private func engineFixtureForHello(
    hello: Array<Byte>, quic!: Bool = false, wrongContext!: Bool = false,
    wrongSigner!: Bool = false, alpn!: String = "mqtt", extraExtensions!: Array<TlsExtension> = [],
    request!: Array<Byte> = [], omitRequestFromAuth!: Bool = false
): EngineFixture {
    let key = x25519GeneratePrivateKey()
    let sh = tls13BuildServerHelloForX25519(hello, x25519PublicFromPrivate(key))
    let suite = tlsDecodeServerHelloHandshake(sh).cipherSuite
    let extensions = ArrayList<TlsExtension>()
    if (alpn.size > 0) { extensions.add(tlsBuildAlpnExtension([alpn])) }
    if (quic) { extensions.add(TlsExtension(0x39, [UInt8(3), UInt8(0)])) }
    for (ext in extraExtensions) { extensions.add(ext) }
    let ee = tlsEncodeEncryptedExtensionsHandshake(TlsEncryptedExtensionsMessage(extensions: extensions.toArray()))
    let cert = tls13BuildCertificateHandshakeFromDerChain([
        x509ParsePem(engineText("engine_leaf.pem")).der
    ])
    let signer = if (wrongSigner) {
        EcPrivateKey(NamedCurve.P256, BigNum.fromHex("02"))
    } else { x509ParseEcPrivateKeyPkcs8Pem(engineText("policy_leaf_key_pkcs8.pem")) }
    let prefix = engineJoin([hello, sh, ee, if (omitRequestFromAuth) { [] } else { request }])
    let cvHash = engineHash(suite, engineJoin([prefix, cert]))
    let cv = if (wrongContext) {
        tls13BuildClientCertificateVerifyEcdsa(signer, cvHash)
    } else {
        tls13BuildServerCertificateVerifyEcdsa(signer, cvHash)
    }
    let first = tls13DeriveSecretsFromX25519ForCipherSuite(
        key, tls13ExtractClientX25519KeyShare(hello), engineHash(suite, engineJoin([hello, sh])), suite
    )
    let finished = tlsEncodeFinishedHandshake(tls13ComputeFinishedVerifyDataForCipherSuite(
        first.serverHsTrafficSecret, engineHash(suite, engineJoin([prefix, cert, cv])), suite
    ))
    first.destroy()
    let secrets = tls13DeriveSecretsFromX25519ForCipherSuite(
        key, tls13ExtractClientX25519KeyShare(hello), engineHash(suite, engineJoin([hello, sh])), suite,
        appTranscriptHash: engineHash(suite, engineJoin([prefix, cert, cv, finished]))
    )
    EngineFixture([sh, ee, cert, cv, finished], secrets)
}

private func assertEngineClosed(client: ContractTls13ClientEngine): Unit {
    @Assert(client.isClosed)
    @Assert(!client.authenticated)
    var rejected = false
    try { _ = client.applicationSecrets() } catch (_: ContractException) { rejected = true }
    @Assert(rejected)
    rejected = false
    try { _ = client.handshakeSecrets() } catch (_: ContractException) { rejected = true }
    @Assert(rejected)
}

private func serverEngineLayer(secrets: Tls13HandshakeSecrets, suite: Int64, handshake: Bool): Tls13RecordLayerHandle {
    let size = if (suite == 0x1301) { 16 } else { 32 }
    let (clientKey, clientIv) = tls13DeriveApplicationTrafficKeyIv(
        if (handshake) { secrets.clientHsTrafficSecret } else { secrets.clientAppTrafficSecret }, keyLen: size)
    let (serverKey, serverIv) = tls13DeriveApplicationTrafficKeyIv(
        if (handshake) { secrets.serverHsTrafficSecret } else { secrets.serverAppTrafficSecret }, keyLen: size)
    if (suite == 0x1303) {
        Tls13RecordLayerHandle(TlsAeadAlgorithm.CHACHA20_POLY1305,
            chachaLayer: Some(TlsChacha20Poly1305RecordLayer(serverKey, serverIv,
                readKey: clientKey, readIv: clientIv, version: TlsVersion.TLS1_3)))
    } else {
        Tls13RecordLayerHandle(TlsAeadAlgorithm.AES_GCM,
            aesLayer: Some(TlsAeadRecordLayer(serverKey, serverIv,
                readKey: clientKey, readIv: clientIv, version: TlsVersion.TLS1_3)))
    }
}

@Test
public class ContractTls13ClientEngineTest {
    @TestCase
    public func testServerSupportedGroupsPreferencesDoNotRenegotiate(): Unit {
        for (quic in [false, true]) {
            let client = newEngine(quic: quic)
            // Unknown and unoffered groups are informational server preferences.
            let fixture = engineFixture(client, quic: quic,
                extraExtensions: [TlsExtension(10, [UInt8(0), 4, 0x11, 0xec, 0, 0x17])])
            client.receiveInitial(fixture.messages[0])
            client.receiveHandshake(engineJoin(fixture.messages[1..]))
            @Assert(client.authenticated)
            let phase = client.applicationSecrets()
            @Assert(phase.serverTrafficSecret(), fixture.secrets.serverAppTrafficSecret)
            phase.destroy()
            client.close()
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testMalformedOrDuplicateServerSupportedGroupsAreTerminal(): Unit {
        let vectors: Array<Array<Byte>> = [[], [0, 0], [0, 1, 0], [0, 4, 0, 0x1d], [0, 2, 0, 0x1d]]
        for (i in 0..vectors.size) {
            let client = newEngine()
            let ext = TlsExtension(10, vectors[i])
            let fixture = engineFixture(client, extraExtensions: if (i == 4) { [ext, ext] } else { [ext] })
            client.receiveInitial(fixture.messages[0])
            var rejected = false
            try { client.receiveHandshake(engineJoin(fixture.messages[1..])) } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testAllSuitesFragmentedAndCoalescedAuthenticated(): Unit {
        for (suite in [0x1301, 0x1302, 0x1303]) {
            let client = newEngine(suite: suite)
            let fixture = engineFixture(client)
            for (b in fixture.messages[0]) { client.receiveInitial([b]) }
            @Assert(!client.authenticated)
            let hs = client.handshakeSecrets()
            @Assert(hs.phase, "handshake")
            @Assert(hs.clientTrafficSecret(), fixture.secrets.clientHsTrafficSecret)
            var blocked = false
            try { _ = client.applicationSecrets() } catch (_: ContractException) { blocked = true }
            @Assert(blocked)
            let flight = engineJoin(fixture.messages[1..])
            client.receiveHandshake(flight[..3])
            client.receiveHandshake(flight[3..])
            @Assert(client.authenticated)
            @Assert(client.selectedAlpn(), "mqtt")
            @Assert(client.peerCertificateChainDer().size, 2)
            let app = client.applicationSecrets()
            @Assert(app.phase, "application")
            @Assert(app.clientTrafficSecret(), fixture.secrets.clientAppTrafficSecret)
            let (key, iv) = app.clientTlsKeyIv()
            @Assert(key, fixture.secrets.clientWriteKey)
            @Assert(iv, fixture.secrets.clientWriteIv)
            @Assert(hs.clientTrafficSecret() != app.clientTrafficSecret())
            let expectedFinished = tlsEncodeFinishedHandshake(tls13ComputeFinishedVerifyDataForCipherSuite(
                fixture.secrets.clientHsTrafficSecret,
                engineHash(suite, engineJoin([client.clientHello(), engineJoin(fixture.messages)])), suite
            ))
            @Assert(client.clientFinished(), expectedFinished)
            client.close()
            client.close()
            assertEngineClosed(client)
            @Assert(!hs.isDestroyed) // exported copy remains caller-owned
            hs.destroy()
            app.destroy()
            app.destroy()
            @Assert(app.isDestroyed)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testQuicRawStreamParametersAuthenticatedOnlyAfterFinished(): Unit {
        let client = newEngine(quic: true)
        let fixture = engineFixture(client, quic: true)
        @Assert(client.clientHello()[0], UInt8(1)) // no record header
        client.receiveInitial(fixture.messages[0])
        client.receiveHandshake(engineJoin(fixture.messages[1..4]))
        var blocked = false
        try { _ = client.peerTransportParameters() } catch (_: ContractException) { blocked = true }
        @Assert(blocked)
        for (b in fixture.messages[4]) { client.receiveHandshake([b]) }
        @Assert(client.authenticated)
        @Assert(client.peerTransportParameters(), [UInt8(3), UInt8(0)])
        let copy = client.peerTransportParameters()
        copy[0] = 99
        @Assert(client.peerTransportParameters()[0], UInt8(3))
        client.close()
        fixture.secrets.destroy()
    }

    @TestCase
    public func testWrongContextSignerHostnameAndTamperFailBeforeAppKeys(): Unit {
        for (kind in 0..5) {
            let client = newEngine(hostname: if (kind == 2) { "wrong.example.com" } else { "www.example.com" })
            let fixture = engineFixture(client, wrongContext: kind == 0, wrongSigner: kind == 1)
            client.receiveInitial(fixture.messages[0])
            if (kind == 3) { fixture.messages[3][fixture.messages[3].size - 1] ^= UInt8(1) }
            if (kind == 4) { fixture.messages[4][fixture.messages[4].size - 1] ^= UInt8(1) }
            var rejected = false
            try { client.receiveHandshake(engineJoin(fixture.messages[1..])) } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testWrongLevelOrderRecordHeaderAndBudgetAreTerminal(): Unit {
        for (kind in 0..5) {
            let client = newEngine()
            let fixture = engineFixture(client)
            var rejected = false
            try {
                if (kind == 0) { client.receiveHandshake(fixture.messages[0]) }
                if (kind == 1) { client.receiveInitial([UInt8(22), UInt8(3), UInt8(3), UInt8(255), UInt8(255)]) }
                if (kind == 2) { client.receiveInitial([UInt8(2), UInt8(255), UInt8(255), UInt8(255)]) }
                if (kind == 3) { client.receiveInitial(engineJoin([fixture.messages[0], fixture.messages[1]])) }
                if (kind == 4) {
                    client.receiveInitial(fixture.messages[0])
                    client.receiveHandshake(fixture.messages[2])
                }
            } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testQuicMissingParametersAndAlpnPolicyFailClosed(): Unit {
        for (kind in 0..4) {
            let client = newEngine(quic: true)
            let fixture = engineFixture(client, quic: kind != 0,
                alpn: if (kind == 1) { "h3" } else if (kind == 2) { "" } else { "mqtt" },
                extraExtensions: if (kind == 3) { [tlsBuildAlpnExtension(["mqtt"])] } else { [] }
            )
            client.receiveInitial(fixture.messages[0])
            var rejected = false
            try { client.receiveHandshake(engineJoin(fixture.messages[1..])) } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            if (kind == 0) { @Assert(client.failureAlertDescription, Some(109)) }
            if (kind == 1 || kind == 2) { @Assert(client.failureAlertDescription, Some(120)) }
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testUntrustedExpiredAndWrongKeyUsageCannotAuthenticate(): Unit {
        for (kind in 0..3) {
            let client = ContractTls13ClientEngine(
                engineText(if (kind == 0 || kind == 2) { "policy_root.pem" } else { "engine_root.pem" }),
                "www.example.com", if (kind == 1) { "20990101000000Z" } else { "270101000000Z" },
                alpnProtocols: ["mqtt"], requireAlpn: true
            )
            let fixture = engineFixture(client)
            if (kind == 2) {
                fixture.messages[2] = tls13BuildCertificateHandshakeFromDerChain([
                    x509ParsePem(engineText("policy_leaf.pem")).der,
                    x509ParsePem(engineText("policy_intermediate.pem")).der
                ])
            }
            client.receiveInitial(fixture.messages[0])
            var rejected = false
            try { client.receiveHandshake(engineJoin(fixture.messages[1..])) } catch (e: ContractException) {
                rejected = true
                if (kind == 2) { @Assert(e.message.contains("keyUsage")) }
            }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testRetryUnofferedSuiteAndDuplicateServerExtensionsRejected(): Unit {
        for (kind in 0..3) {
            let client = newEngine()
            let fixture = engineFixture(client)
            let sh = tlsDecodeServerHelloHandshake(fixture.messages[0])
            let extensions = ArrayList<TlsExtension>()
            for (ext in sh.extensions) { extensions.add(ext) }
            if (kind == 2) { extensions.add(sh.extensions[0]) }
            let malformed = tlsEncodeServerHelloHandshake(TlsServerHello(
                if (kind == 0) { sha256("HelloRetryRequest".toArray()) } else { sh.random },
                if (kind == 1) { 0x1302 } else { sh.cipherSuite }, extensions: extensions.toArray()
            ))
            var rejected = false
            try { client.receiveInitial(malformed) } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testTicketFragmentsDiscardedWithoutResumptionAndKeyUpdateTerminal(): Unit {
        let client = newEngine(quic: true)
        let fixture = engineFixture(client, quic: true)
        client.receiveInitial(fixture.messages[0])
        client.receiveHandshake(engineJoin(fixture.messages[1..]))
        let before = client.applicationSecrets()
        let ticket = tls13EncodeNewSessionTicketHandshake(Tls13NewSessionTicketMessage(60, 7, [UInt8(1)], [UInt8(2)]))
        for (b in ticket) { client.receivePostHandshake([b]) }
        client.receivePostHandshake(engineJoin([ticket, ticket]))
        let after = client.applicationSecrets()
        @Assert(before.clientTrafficSecret(), after.clientTrafficSecret())
        var rejected = false
        try { client.receivePostHandshake(tls13BuildKeyUpdateHandshake()) } catch (_: ContractException) { rejected = true }
        @Assert(rejected)
        assertEngineClosed(client)
        before.destroy()
        after.destroy()
        fixture.secrets.destroy()
    }

    @TestCase
    public func testOptionalCertificateRequestFullTranscriptAndEmptyResponse(): Unit {
        for (scenario in 0..6) {
            let suite = [0x1301, 0x1302, 0x1303][scenario / 2]
            let quic = scenario % 2 == 1
            let client = newEngine(suite: suite, quic: quic)
            let request = tlsEncodeCertificateRequestHandshakeTls13(Tls13CertificateRequestMessage(extensions: [
                TlsExtension(13, [UInt8(0), UInt8(2), UInt8(8), UInt8(8)]),
                TlsExtension(0xfafa, [UInt8(9)])
            ])) // no matching client identity; unknown extensions must be ignored, not removed from transcript
            let fixture = engineFixture(client, request: request, quic: quic)
            let hello = client.clientHello()
            client.receiveInitial(fixture.messages[0])
            for (b in engineJoin([fixture.messages[1], request])) { client.receiveHandshake([b]) }
            client.receiveHandshake(engineJoin(fixture.messages[2..]))
            @Assert(client.authenticated)
            let empty = tlsEncodeCertificateHandshakeTls13(Tls13CertificateMessage())
            @Assert(client.clientCertificate(), empty)
            @Assert(client.clientHandshakeOutput(), engineJoin([empty, client.clientFinished()]))
            let expected = tls13ComputeFinishedVerifyDataForCipherSuite(fixture.secrets.clientHsTrafficSecret,
                engineHash(suite, engineJoin([hello, fixture.messages[0], fixture.messages[1], request,
                    fixture.messages[2], fixture.messages[3], fixture.messages[4], empty])), suite)
            @Assert(tlsDecodeFinishedHandshake(client.clientFinished()), expected)
            let app = client.applicationSecrets()
            @Assert(app.clientTrafficSecret(), fixture.secrets.clientAppTrafficSecret)
            @Assert(app.serverTrafficSecret(), fixture.secrets.serverAppTrafficSecret)
            app.destroy()
            client.close()
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testCertificateRequestInvalidOrUnauthenticatedIsTerminal(): Unit {
        for (kind in 0..11) {
            let client = newEngine()
            let valid = tls13BuildCertificateRequestHandshake(signatureSchemes: [0x0403])
            let sig = TlsExtension(13, [UInt8(0), UInt8(2), UInt8(4), UInt8(3)])
            let request = if (kind == 2) {
                tls13BuildCertificateRequestHandshake(requestContext: [UInt8(1)], signatureSchemes: [0x0403])
            } else if (kind == 3) {
                tlsEncodeCertificateRequestHandshakeTls13(Tls13CertificateRequestMessage())
            } else if (kind == 4) {
                tlsEncodeCertificateRequestHandshakeTls13(Tls13CertificateRequestMessage(extensions: [sig, sig]))
            } else if (kind == 5) {
                tlsEncodeCertificateRequestHandshakeTls13(Tls13CertificateRequestMessage(
                    extensions: [TlsExtension(13, [UInt8(0), UInt8(1), UInt8(4)])]))
            } else { valid }
            let fixture = engineFixture(client, request: request, omitRequestFromAuth: kind == 6,
                wrongSigner: kind == 7, wrongContext: kind == 8)
            if (kind == 10) { fixture.messages[4][fixture.messages[4].size - 1] ^= UInt8(1) }
            client.receiveInitial(fixture.messages[0])
            var rejected = false
            try {
                if (kind == 0) { client.receiveHandshake(request) }
                if (kind == 9) {
                    client.receiveHandshake(engineJoin([fixture.messages[1], fixture.messages[2]]))
                    client.receiveHandshake(request)
                }
                client.receiveHandshake(engineJoin([fixture.messages[1], request]))
                if (kind == 1) { client.receiveHandshake(request) }
                client.receiveHandshake(engineJoin(fixture.messages[2..]))
            } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            assertEngineClosed(client)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testStreamCertificateRequestResponseRecordsAndApplicationCounters(): Unit {
        for (suite in [0x1301, 0x1302, 0x1303]) {
            let client = ContractTls13StreamClient(engineText("engine_root.pem"), "www.example.com", "270101000000Z",
                alpnProtocols: ["mqtt"], requireAlpn: true, cipherSuites: [suite])
            let hello = tlsDecodeRecord(client.takeHandshakeOutput()).fragment
            let request = tls13BuildCertificateRequestHandshake(signatureSchemes: [0x0403])
            let fixture = engineFixtureForHello(hello, request: request)
            let hs = serverEngineLayer(fixture.secrets, suite, true)
            let app = serverEngineLayer(fixture.secrets, suite, false)
            _ = client.receive(tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, fixture.messages[0]))
            _ = client.receive(hs.seal(TlsContentType.Handshake, engineJoin([fixture.messages[1], request])))
            @Assert(!client.authenticated)
            @Assert(client.takeHandshakeOutput().size, 0)
            _ = client.receive(hs.seal(TlsContentType.Handshake, engineJoin(fixture.messages[2..])))
            let wire = client.takeHandshakeOutput()
            let firstLength = 5 + (Int64(wire[3]) << 8) + Int64(wire[4])
            let certificate = hs.open(wire[..firstLength]).fragment
            @Assert(certificate, tlsEncodeCertificateHandshakeTls13(Tls13CertificateMessage()))
            let finished = hs.open(wire[firstLength..]).fragment
            let expected = tls13ComputeFinishedVerifyDataForCipherSuite(fixture.secrets.clientHsTrafficSecret,
                engineHash(suite, engineJoin([hello, fixture.messages[0], fixture.messages[1], request,
                    fixture.messages[2], fixture.messages[3], fixture.messages[4], certificate])), suite)
            @Assert(tlsDecodeFinishedHandshake(finished), expected)
            @Assert(app.open(client.sealApplicationData("ping".toArray())).fragment, "ping".toArray())
            @Assert(client.receive(app.seal(TlsContentType.ApplicationData, "pong".toArray()))[0], "pong".toArray())
            client.close()
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testStreamPhasesTicketsAndPeerCloseNotify(): Unit {
        for (suite in [0x1301, 0x1302, 0x1303]) {
            let client = ContractTls13StreamClient(engineText("engine_root.pem"), "www.example.com", "270101000000Z",
                alpnProtocols: ["mqtt"], requireAlpn: true, cipherSuites: [suite])
            let fixture = engineFixtureForHello(tlsDecodeRecord(client.takeHandshakeOutput()).fragment)
            let hs = serverEngineLayer(fixture.secrets, suite, true)
            let app = serverEngineLayer(fixture.secrets, suite, false)
            let flight = engineJoin([
                tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, fixture.messages[0]),
                hs.seal(TlsContentType.Handshake, engineJoin(fixture.messages[1..]))
            ])
            for (b in flight) { @Assert(client.receive([b]).size, 0) }
            @Assert(client.authenticated)
            var rejected = false
            try { _ = client.sealApplicationData([UInt8(1)]) } catch (_: ContractException) { rejected = true }
            @Assert(rejected) // Finished must be drained before application writes
            let finished = hs.open(client.takeHandshakeOutput())
            @Assert(finished.contentType, TlsContentType.Handshake)
            @Assert(app.open(client.sealApplicationData("ping".toArray())).fragment, "ping".toArray())
            let ticket = tls13EncodeNewSessionTicketHandshake(Tls13NewSessionTicketMessage(60, 7, [UInt8(1)], [UInt8(2)]))
            let wire = engineJoin([
                app.seal(TlsContentType.Handshake, ticket),
                app.seal(TlsContentType.ApplicationData, "pong".toArray()),
                app.seal(TlsContentType.Alert, [UInt8(1), UInt8(0)])
            ])
            let data = client.receive(wire)
            @Assert(data.size, 1)
            @Assert(data[0], "pong".toArray())
            @Assert(client.isClosed)
            @Assert(app.open(client.takeHandshakeOutput()).contentType, TlsContentType.Alert)
            fixture.secrets.destroy()
        }
    }

    @TestCase
    public func testStreamTamperEarlyAppAndWrongRecordPhaseAreTerminal(): Unit {
        for (kind in 0..3) {
            let client = ContractTls13StreamClient(engineText("engine_root.pem"), "www.example.com", "270101000000Z",
                alpnProtocols: ["mqtt"], cipherSuites: [0x1301])
            let fixture = engineFixtureForHello(tlsDecodeRecord(client.takeHandshakeOutput()).fragment)
            _ = client.receive(tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, fixture.messages[0]))
            let hs = serverEngineLayer(fixture.secrets, 0x1301, true)
            let record = if (kind == 2) {
                tlsEncodeRecord(TlsContentType.Handshake, TlsVersion.TLS1_2, fixture.messages[1])
            } else {
                hs.seal(if (kind == 1) { TlsContentType.ApplicationData } else { TlsContentType.Handshake },
                    engineJoin(fixture.messages[1..]))
            }
            if (kind == 0) { record[record.size - 1] ^= UInt8(1) }
            var rejected = false
            try { _ = client.receive(record) } catch (_: ContractException) { rejected = true }
            @Assert(rejected)
            @Assert(client.isClosed)
            @Assert(!client.authenticated)
            fixture.secrets.destroy()
        }
    }
}
