package jinguissl.tests

import jinguissl.live.*
// Provider imports here construct an adversarial wire fixture; application
// consumption tests remain Contract-only.
import jinguissl_core.crypto.tls.{TlsSessionIdentity, TlsSessionTicket,
    tlsEncodeSessionTicket, tls13BuildClientHelloPskWithBinder, tls13VerifyClientPskBinder}
import jinguissl_core.crypto.compliance.TlsVersion

private func selfDescribingEarlyDataHello(): Array<Byte> {
    let secret = Array<Byte>(32, repeat: 0x31)
    let identity = TlsSessionIdentity(TlsVersion.TLS1_3, [UInt8(1)], serverName: "example.test")
    let ticket = TlsSessionTicket(identity, secret, [], 1, 2000000000)
    let hello = tls13BuildClientHelloPskWithBinder(tlsEncodeSessionTicket(ticket), secret)
    @Assert(tls13VerifyClientPskBinder(hello, secret, selectedIdentityIndex: 0), true)
    hello
}

@Test
public class ContractEarlyDataClosedTestSuite {
    @TestCase
    public func testPrepareRoutesAreClosedBeforeCacheLookup(): Unit {
        let id = ContractTlsSessionIdentity(ContractTlsVersion.Tls13, [UInt8(1)])
        let ticket = ContractTlsSessionTicket(1, id, [UInt8(1)], [], 1, 2000000000)
        let cache = ContractTlsSessionCache()
        for (variant in 0..4) {
            try {
                match (variant) {
                    case 0 => _ = contractTls13PreparePskEarlyDataFromSessionTicket(ticket)
                    case 1 => _ = contractTls13PreparePskEarlyDataFromSessionTicketRequest(
                        ContractTls13PskEarlyDataFromSessionTicketRequest(ticket))
                    case 2 => _ = contractTls13PreparePskEarlyDataFromSessionCache(cache, id)
                    case _ => _ = contractTls13PreparePskEarlyDataFromSessionCacheRequest(
                        ContractTls13PskEarlyDataFromSessionCacheRequest(cache, id))
                }
                @Fail("all legacy prepare routes must report unsupported")
            } catch (e: ContractException) {
                @Assert(e.code, ContractErrorCode.Unsupported)
            }
        }
    }

    @TestCase
    public func testRequestAndReplayWrappersStayClosed(): Unit {
        let hello = selfDescribingEarlyDataHello()
        let cache = ContractTls13EarlyDataReplayCache()
        for (variant in 0..6) {
            try {
                match (variant) {
                    case 0 => _ = contractTls13AcceptPskEarlyDataFromClientHelloRequest(
                        ContractTls13PskEarlyDataAcceptRequest(hello, selectedIdentityIndex: 0))
                    case 1 => _ = contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCache(
                        hello, cache, selectedIdentityIndex: 0)
                    case 2 => _ = contractTls13AcceptPskEarlyDataFromClientHelloWithReplayCacheRequest(
                        ContractTls13PskEarlyDataAcceptWithReplayCacheRequest(hello, cache, selectedIdentityIndex: 0))
                    case 3 => _ = contractTls13AcceptPskEarlyDataForHttpRequest(
                        ContractTls13PskEarlyDataHttpAcceptRequest(hello, selectedIdentityIndex: 0))
                    case 4 => _ = contractTls13AcceptPskEarlyDataForHttpWithReplayCache(
                        hello, cache, selectedIdentityIndex: 0)
                    case _ => _ = contractTls13AcceptPskEarlyDataForHttpWithReplayCacheRequest(
                        ContractTls13PskEarlyDataHttpAcceptWithReplayCacheRequest(hello, cache, selectedIdentityIndex: 0))
                }
                @Fail("request/replay wrappers must not reopen early data")
            } catch (e: ContractException) {
                @Assert(e.code, ContractErrorCode.Unsupported)
            }
        }
    }

    @TestCase
    public func testSelfDescribingTicketCannotAuthenticateEarlyData(): Unit {
        let hello = selfDescribingEarlyDataHello()
        for (index in [Int64(-1), Int64(0), Int64(65536)]) {
            try {
                _ = contractTls13AcceptPskEarlyDataFromClientHello(hello, selectedIdentityIndex: index)
                @Fail("legacy early data must stay closed for every identity selection")
            } catch (e: ContractException) {
                @Assert(e.code, ContractErrorCode.Unsupported)
            }
        }
    }

    @TestCase
    public func testHttpWrapperCannotReopenEarlyData(): Unit {
        try {
            _ = contractTls13AcceptPskEarlyDataForHttp(selfDescribingEarlyDataHello(),
                selectedIdentityIndex: 0)
            @Fail("HTTP wrapper must stay closed")
        } catch (e: ContractException) {
            @Assert(e.code, ContractErrorCode.Unsupported)
        }
    }

    @TestCase
    public func testMalformedHelloStillReportsUnsupported(): Unit {
        try {
            _ = contractTls13AcceptPskEarlyDataFromClientHello([], selectedIdentityIndex: 0)
            @Fail("disabled capability must not parse attacker input")
        } catch (e: ContractException) {
            @Assert(e.code, ContractErrorCode.Unsupported)
        }
    }
}
