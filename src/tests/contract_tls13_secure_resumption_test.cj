package jinguissl.tests

import jinguissl.contract.*

private let C207_SERVER_NAME: String = "www." + "example.com"
private let C207_ALPN: String = "h2"
private let C207_AES_128_GCM_SHA256: Int64 = 0x1301
private let C207_NOW_MILLISECONDS: Int64 = 1_800_000_000_000

private func c207Bytes(size: Int64, start!: Int64 = 0): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    var i: Int64 = 0
    while (i < size) {
        out[i] = UInt8((start + i) & 0xff)
        i += 1
    }
    out
}

private func c207ResumedClientHello(
    store: ContractTls13OpaqueTicketStore,
    nowUnixMilliseconds: Int64
): Array<Byte> {
    let resumptionMasterSecret = c207Bytes(32, start: 16)
    let encodedTicket = store.issueNewSessionTicket(
        resumptionMasterSecret,
        C207_SERVER_NAME,
        C207_ALPN,
        C207_AES_128_GCM_SHA256,
        nowUnixMilliseconds
    )
    let clientTicket = contractTls13CreateClientResumptionTicket(
        encodedTicket,
        resumptionMasterSecret,
        C207_SERVER_NAME,
        C207_ALPN,
        C207_AES_128_GCM_SHA256,
        nowUnixMilliseconds
    )
    contractTls13BuildClientHelloFromResumptionTicketX25519(
        clientTicket,
        nowUnixMilliseconds + 1_000,
        clientPrivateKey: Some(c207Bytes(32, start: 64))
    ).encodedClientHello
}

@Test
public class ContractTls13SecureResumptionTestSuite {
    @TestCase
    public func testOpaqueTicketRoundTripConsumesExactlyOnce(): Unit {
        let store = ContractTls13OpaqueTicketStore(maxEntries: 4)
        let clientHello = c207ResumedClientHello(store, C207_NOW_MILLISECONDS)
        @Assert(store.size, 1)

        let validated = store.validateAndConsumeClientHello(
            clientHello,
            C207_NOW_MILLISECONDS + 1_000
        )
        @Assert(validated.resumptionPsk.size, 32)
        @Assert(validated.serverName, C207_SERVER_NAME)
        @Assert(validated.alpnProtocol, C207_ALPN)
        @Assert(validated.cipherSuite, C207_AES_128_GCM_SHA256)
        @Assert(store.size, 0)

        try {
            _ = store.validateAndConsumeClientHello(
                clientHello,
                C207_NOW_MILLISECONDS + 1_000
            )
            @Fail("opaque TLS1.3 ticket replay must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testRotationInvalidatesOutstandingTicket(): Unit {
        let store = ContractTls13OpaqueTicketStore(maxEntries: 4)
        let clientHello = c207ResumedClientHello(store, C207_NOW_MILLISECONDS)
        let generation = store.rotationGeneration
        store.rotate()

        @Assert(store.size, 0)
        @Assert(store.rotationGeneration, generation + 1)
        try {
            _ = store.validateAndConsumeClientHello(
                clientHello,
                C207_NOW_MILLISECONDS + 1_000
            )
            @Fail("rotated opaque TLS1.3 ticket must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }
    }

    @TestCase
    public func testInvalidStoreAndValidationInputsMapToBadInput(): Unit {
        try {
            _ = ContractTls13OpaqueTicketStore(maxEntries: 0)
            @Fail("zero-capacity opaque ticket store must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }

        let store = ContractTls13OpaqueTicketStore()
        try {
            _ = store.validateAndConsumeClientHello([], C207_NOW_MILLISECONDS)
            @Fail("empty ClientHello must fail before verification")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }

    @TestCase
    public func testExpiredTicketIsRejectedBeforeClientHelloBuild(): Unit {
        let store = ContractTls13OpaqueTicketStore()
        let secret = c207Bytes(32, start: 32)
        let encodedTicket = store.issueNewSessionTicket(
            secret,
            C207_SERVER_NAME,
            C207_ALPN,
            C207_AES_128_GCM_SHA256,
            C207_NOW_MILLISECONDS,
            ticketLifetimeSeconds: 1
        )
        let clientTicket = contractTls13CreateClientResumptionTicket(
            encodedTicket,
            secret,
            C207_SERVER_NAME,
            C207_ALPN,
            C207_AES_128_GCM_SHA256,
            C207_NOW_MILLISECONDS
        )
        let base = contractTls13BuildClientHelloFromResumptionTicketX25519(
            clientTicket,
            C207_NOW_MILLISECONDS,
            clientPrivateKey: Some(c207Bytes(32, start: 96))
        )
        try {
            _ = contractTls13BuildClientHelloFromResumptionTicketX25519(
                clientTicket,
                C207_NOW_MILLISECONDS + 1_000,
                clientPrivateKey: Some(base.privateKey)
            )
            @Fail("expired client resumption ticket must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }
}
