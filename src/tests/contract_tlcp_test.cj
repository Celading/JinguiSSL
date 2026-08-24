package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractTlcpTestSuite {
    @TestCase
    public func testTlcpHelloAndDualCertificateRoles(): Unit {
        let credentials = contractTlcpCredentials()
        let clientHello = contractTlcpBuildClientHello(
            cipherSuites: [EccSm4GcmSm3, EcdheSm4CbcSm3],
            sessionId: [UInt8(1), UInt8(2)]
        )
        let client = contractTlcpDecodeClientHello(clientHello)
        @Assert(client.sessionId, [UInt8(1), UInt8(2)])
        @Assert(client.offeredCipherSuites.size, 2)
        let serverHello = contractTlcpBuildServerHello(
            clientHello, supportedSuites: [EcdheSm4CbcSm3, EccSm4GcmSm3]
        )
        let server = contractTlcpDecodeServerHello(serverHello)
        match (server.selectedCipherSuite) {
            case Some(value) => @Assert(value, EcdheSm4CbcSm3)
            case None => @Assert(false, true)
        }
        @Assert(CONTRACT_TLCP_VERSION, 0x0101)

        let encoded = contractTlcpBuildDualCertificateHandshake(
            credentials.signingCertificate.der, credentials.encryptionCertificate.der
        )
        let verified = contractTlcpVerifyDualCertificateHandshake(
            encoded, credentials.rootCertificate.pem, validationTime: "270101000000Z"
        )
        @Assert(verified.signingChainLength, 2)
        @Assert(verified.encryptionChainLength, 2)
    }

    @TestCase
    public func testTlcpStaticEccBothRecordProfilesAndFinished(): Unit {
        let credentials = contractTlcpCredentials()
        let clientRandom = tlcpBytes(32, UInt8(0x21))
        let serverRandom = tlcpBytes(32, UInt8(0x81))
        let serverKeyExchange = contractTlcpBuildStaticServerKeyExchange(
            credentials.signingPrivateKey,
            credentials.encryptionCertificate.pem,
            clientRandom,
            serverRandom
        )
        contractTlcpVerifyStaticServerKeyExchange(
            serverKeyExchange,
            credentials.signingCertificate.pem,
            credentials.encryptionCertificate.pem,
            clientRandom,
            serverRandom
        )
        let clientKeyExchange = contractTlcpBuildStaticClientKeyExchange(
            contractSm2PublicFromPrivate(credentials.encryptionPrivateKey)
        )
        let serverPreMaster = contractTlcpProcessStaticClientKeyExchange(
            credentials.encryptionPrivateKey, clientKeyExchange.encoded
        )
        @Assert(serverPreMaster, clientKeyExchange.preMasterSecret)
        let transcript = tlcpJoin([serverKeyExchange, clientKeyExchange.encoded])

        for (suite in [EccSm4CbcSm3, EccSm4GcmSm3]) {
            let clientSecrets = contractTlcpDeriveSecretsFromPreMaster(
                clientKeyExchange.preMasterSecret, clientRandom, serverRandom, suite
            )
            let serverSecrets = contractTlcpDeriveSecretsFromPreMaster(
                serverPreMaster, clientRandom, serverRandom, suite
            )
            let client = contractTlcpCreateClientRecordLayer(clientSecrets)
            let server = contractTlcpCreateServerRecordLayer(serverSecrets)
            let message = "authenticated TLCP".toArray()
            @Assert(
                server.open(client.seal(ContractGmTlsContentType.ApplicationData, message)).fragment,
                message
            )
            let finished = clientSecrets.buildFinished(transcript)
            serverSecrets.verifyFinished(finished, transcript)
            let tampered = finished.clone()
            tampered[tampered.size - 1] ^= UInt8(1)
            tlcpAssertContractRejected({ => serverSecrets.verifyFinished(tampered, transcript) })
        }
    }

    @TestCase
    public func testTlcpEcdheBothRecordProfiles(): Unit {
        let credentials = contractTlcpCredentials()
        let clientStatic = tlcpHex(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        )
        let clientEphemeral = tlcpHex(
            "d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3"
        )
        let serverEphemeral = tlcpHex(
            "7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6"
        )
        let clientRandom = tlcpBytes(32, UInt8(0x31))
        let serverRandom = tlcpBytes(32, UInt8(0x91))
        let serverKeyExchange = contractTlcpBuildEcdheServerKeyExchange(
            contractSm2PublicFromPrivate(serverEphemeral),
            credentials.signingPrivateKey,
            clientRandom,
            serverRandom
        )
        let serverEphemeralPublic = contractTlcpParseAndVerifyEcdheServerKeyExchange(
            serverKeyExchange,
            credentials.signingCertificate.pem,
            clientRandom,
            serverRandom
        )
        let clientKeyExchange = contractTlcpBuildEcdheClientKeyExchange(
            contractSm2PublicFromPrivate(clientEphemeral)
        )
        let clientEphemeralPublic = contractTlcpParseEcdheClientKeyExchange(clientKeyExchange)
        for (suite in [EcdheSm4CbcSm3, EcdheSm4GcmSm3]) {
            let clientSecrets = contractTlcpDeriveEcdheClientSecrets(
                clientStatic,
                clientEphemeral,
                contractSm2PublicFromPrivate(credentials.encryptionPrivateKey),
                serverEphemeralPublic,
                clientRandom,
                serverRandom,
                suite
            )
            let serverSecrets = contractTlcpDeriveEcdheServerSecrets(
                credentials.encryptionPrivateKey,
                serverEphemeral,
                contractSm2PublicFromPrivate(clientStatic),
                clientEphemeralPublic,
                clientRandom,
                serverRandom,
                suite
            )
            let request = "TLCP ECDHE".toArray()
            @Assert(
                contractTlcpCreateServerRecordLayer(serverSecrets).open(
                    contractTlcpCreateClientRecordLayer(clientSecrets).seal(
                        ContractGmTlsContentType.Handshake, request
                    )
                ).fragment,
                request
            )
        }
    }

    @TestCase
    public func testDtlcpOutOfOrderReplayAndEpochTransition(): Unit {
        for (suite in [EcdheSm4CbcSm3, EcdheSm4GcmSm3]) {
            let secrets = contractTlcpDeriveSecretsFromPreMaster(
                tlcpBytes(48, UInt8(0x11)),
                tlcpBytes(32, UInt8(0x41)),
                tlcpBytes(32, UInt8(0x81)),
                suite
            )
            let sender = contractDtlcpCreateClientRecordLayer(secrets, epoch: 1)
            let receiver = contractDtlcpCreateServerRecordLayer(secrets, epoch: 1)
            let first = sender.seal(ContractGmTlsContentType.ApplicationData, "zero".toArray())
            let second = sender.seal(ContractGmTlsContentType.Handshake, "one".toArray())
            @Assert(receiver.open(second).sequence, 1)
            @Assert(receiver.open(first).sequence, 0)
            tlcpAssertContractRejected({ => _ = receiver.open(first) })
            sender.setEpoch(2)
            receiver.setEpoch(2)
            let next = sender.seal(ContractGmTlsContentType.ApplicationData, "epoch-two".toArray())
            @Assert(receiver.open(next).epoch, 2)
            tlcpAssertContractRejected({ => receiver.setEpoch(1) })
        }
    }

    @TestCase
    public func testDtlcpFragmentReassemblyAndFlightBackoff(): Unit {
        let body = tlcpBytes(173, UInt8(0x30))
        let handshake = tlcpHandshake(UInt8(0x0b), body)
        let fragments = contractDtlcpFragmentHandshake(handshake, 7, 41)
        @Assert(fragments.size, 5)
        let reassembler = ContractDtlcpHandshakeReassembler(UInt8(0x0b), body.size, 7)
        @Assert(reassembler.accept(fragments[4]), false)
        @Assert(reassembler.accept(fragments[2]), false)
        @Assert(reassembler.accept(fragments[0]), false)
        @Assert(reassembler.accept(fragments[1]), false)
        @Assert(reassembler.accept(fragments[3]), true)
        @Assert(reassembler.encodedHandshake(), handshake)

        let retransmitter = ContractDtlcpFlightRetransmitter(
            initialTimeoutMillis: 100, maxTimeoutMillis: 350, maxAttempts: 3
        )
        retransmitter.cacheFlight(fragments)
        @Assert(retransmitter.nextFlight().size, 5)
        @Assert(retransmitter.timeoutMillis, 200)
        @Assert(retransmitter.nextFlight().size, 5)
        @Assert(retransmitter.timeoutMillis, 350)
        @Assert(retransmitter.nextFlight().size, 5)
        @Assert(retransmitter.hasPendingFlight, false)
        tlcpAssertContractRejected({ => _ = retransmitter.nextFlight() })
        retransmitter.acknowledgeFlight()
        @Assert(retransmitter.attempts, 0)
    }
}

private class ContractTlcpTestCredentials {
    let rootCertificate: ContractGmCertificate
    let signingCertificate: ContractGmCertificate
    let encryptionCertificate: ContractGmCertificate
    let signingPrivateKey: Array<Byte>
    let encryptionPrivateKey: Array<Byte>

    init(
        rootCertificate: ContractGmCertificate,
        signingCertificate: ContractGmCertificate,
        encryptionCertificate: ContractGmCertificate,
        signingPrivateKey: Array<Byte>,
        encryptionPrivateKey: Array<Byte>
    ) {
        this.rootCertificate = rootCertificate
        this.signingCertificate = signingCertificate
        this.encryptionCertificate = encryptionCertificate
        this.signingPrivateKey = signingPrivateKey
        this.encryptionPrivateKey = encryptionPrivateKey
    }
}

private func contractTlcpCredentials(): ContractTlcpTestCredentials {
    let rootPrivate = tlcpHex(
        "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
    )
    let signingPrivate = tlcpHex(
        "59276e27d506861a16680f3ad9c02dcca6c3f21bdf45a6cdbf1a5c27b4062cc8"
    )
    let encryptionPrivate = tlcpHex(
        "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
    )
    let root = contractGmCreateSelfSignedCertificate(
        ContractGmCertificateConfig(
            "TLCP Contract Root",
            serialNumber: [UInt8(0x41)],
            keyUsageMask: CONTRACT_GM_KEY_USAGE_KEY_CERT_SIGN |
                CONTRACT_GM_KEY_USAGE_CRL_SIGN
        ),
        rootPrivate
    )
    let signing = contractGmIssueCertificate(
        ContractGmCertificateConfig(
            "tlcp-sign.example",
            serialNumber: [UInt8(0x42)],
            notAfter: "300101000000Z",
            keyUsageMask: CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE |
                CONTRACT_GM_KEY_USAGE_CONTENT_COMMITMENT
        ),
        contractSm2PublicFromPrivate(signingPrivate),
        root.pem,
        rootPrivate
    )
    let encryption = contractGmIssueCertificate(
        ContractGmCertificateConfig(
            "tlcp-enc.example",
            serialNumber: [UInt8(0x43)],
            notAfter: "300101000000Z",
            keyUsageMask: CONTRACT_GM_KEY_USAGE_KEY_ENCIPHERMENT |
                CONTRACT_GM_KEY_USAGE_DATA_ENCIPHERMENT |
                CONTRACT_GM_KEY_USAGE_KEY_AGREEMENT
        ),
        contractSm2PublicFromPrivate(encryptionPrivate),
        root.pem,
        rootPrivate
    )
    ContractTlcpTestCredentials(root, signing, encryption, signingPrivate, encryptionPrivate)
}

private func tlcpAssertContractRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (_: ContractException) {
        rejected = true
    }
    @Assert(rejected, true)
}

private func tlcpHandshake(messageType: Byte, body: Array<Byte>): Array<Byte> {
    let output = Array<Byte>(body.size + 4, repeat: UInt8(0))
    output[0] = messageType
    output[1] = UInt8((body.size >> 16) & 0xff)
    output[2] = UInt8((body.size >> 8) & 0xff)
    output[3] = UInt8(body.size & 0xff)
    var i: Int64 = 0
    while (i < body.size) { output[4 + i] = body[i]; i += 1 }
    output
}

private func tlcpJoin(values: Array<Array<Byte>>): Array<Byte> {
    var size: Int64 = 0
    for (value in values) { size += value.size }
    let output = Array<Byte>(size, repeat: UInt8(0))
    var offset: Int64 = 0
    for (value in values) {
        var i: Int64 = 0
        while (i < value.size) { output[offset + i] = value[i]; i += 1 }
        offset += value.size
    }
    output
}

private func tlcpBytes(size: Int64, start: Byte): Array<Byte> {
    let output = Array<Byte>(size, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < size) { output[i] = UInt8((Int64(start) + i) & 0xff); i += 1 }
    output
}

private func tlcpHex(value: String): Array<Byte> {
    let chars = value.toArray()
    let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < output.size) {
        output[i] = UInt8(tlcpNibble(chars[i * 2]) * 16 + tlcpNibble(chars[i * 2 + 1]))
        i += 1
    }
    output
}

private func tlcpNibble(value: Byte): Int64 {
    if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
        return Int64(value - UInt8(0x30))
    }
    if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
        return Int64(value - UInt8(0x61)) + 10
    }
    Int64(value - UInt8(0x41)) + 10
}
