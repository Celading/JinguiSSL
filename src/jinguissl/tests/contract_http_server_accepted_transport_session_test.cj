package JinguiSSL.jinguissl.tests

import std.fs.File
import JinguiSSL.jinguissl.live.*

private let LIVE_SOURCE_ROOT: String = ""

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

@Test
public class ContractHttpServerAcceptedTransportSessionTestSuite {
    @TestCase
    public func testContractAcceptedTransportSessionReadyAndClosed(): Unit {
        let serverName = "www.example.com"
        let leafPem = readText("testdata/x509/policy_leaf.pem")
        let intermediatePem = readText("testdata/x509/policy_intermediate.pem")
        let certChainPem = "${leafPem}\n${intermediatePem}"
        let leafKeyPem = readText("testdata/x509/policy_leaf_key_pkcs8.pem")

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

        let session = contractAttachAcceptedTransportTls13X25519(
            ContractAcceptedTransportDescriptor(
                "test-accepted-transport",
                localEndpoint: "127.0.0.1:443",
                remoteEndpoint: "127.0.0.1:55443"
            ),
            plan,
            clientHello.encodedClientHello,
            incrementalBytes(32, start: 80)
        )

        @Assert(session.status.toString(), "READY")
        @Assert(session.secureSessionReady, true)
        @Assert(session.result.secureSessionReady, true)
        @Assert(session.result.negotiatedAlpn, "h2")
        @Assert(session.result.requestedServerName, serverName)
        @Assert(session.result.acknowledgedServerName, true)
        @Assert(session.result.tlsVersion.toString(), "TLS1.3")
        @Assert(session.result.cipherSuite, "TLS_AES_128_GCM_SHA256")
        @Assert(session.result.attachSurface, "accepted-transport-session")
        @Assert(session.recordChannel.version.toString(), "TLS1.3")

        let closed = contractCloseAcceptedTransportSession(session, reason: "test-close")
        @Assert(closed.status.toString(), "CLOSED")
        @Assert(closed.secureSessionReady, false)
        @Assert(closed.result.secureSessionReady, false)
        @Assert(closed.closeReason, "test-close")
        @Assert(closed.result.negotiatedAlpn, "h2")
        @Assert(closed.result.requestedServerName, serverName)
        @Assert(closed.result.tlsVersion.toString(), "TLS1.3")
        @Assert(closed.result.cipherSuite, "TLS_AES_128_GCM_SHA256")
    }
}
