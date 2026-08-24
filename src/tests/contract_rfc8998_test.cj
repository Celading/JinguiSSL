package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractRfc8998TestSuite {
    @TestCase
    public func testRfc8998HelloRegistryAndKeyShares(): Unit {
        let clientPrivate = rfc8998Bytes(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        )
        let serverPrivate = rfc8998Bytes(
            "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
        )
        let pair = contractRfc8998BuildHelloPair(
            contractSm2PublicFromPrivate(clientPrivate),
            contractSm2PublicFromPrivate(serverPrivate)
        )
        @Assert(pair.selectedCipherSuite, CONTRACT_RFC8998_SM4_GCM_SM3)
        @Assert(pair.transcriptHash.size, 32)
        @Assert(pair.clientPublicKey, contractSm2PublicFromPrivate(clientPrivate))
        @Assert(pair.serverPublicKey, contractSm2PublicFromPrivate(serverPrivate))
        @Assert(CONTRACT_RFC8998_SM2_SM3, 0x0708)
        @Assert(CONTRACT_RFC8998_CURVE_SM2, 41)
    }

    @TestCase
    public func testRfc8998BothCipherSuitesRecordRoundTrip(): Unit {
        let clientPrivate = rfc8998Bytes(
            "81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029"
        )
        let serverPrivate = rfc8998Bytes(
            "785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5"
        )
        let clientPublic = contractSm2PublicFromPrivate(clientPrivate)
        let serverPublic = contractSm2PublicFromPrivate(serverPrivate)
        for (suite in [CONTRACT_RFC8998_SM4_GCM_SM3, CONTRACT_RFC8998_SM4_CCM_SM3]) {
            let pair = contractRfc8998BuildHelloPair(
                clientPublic, serverPublic, cipherSuites: [suite]
            )
            let clientSecrets = contractRfc8998DeriveSecrets(
                clientPrivate, serverPublic, pair.transcriptHash, suite
            )
            let serverSecrets = contractRfc8998DeriveSecrets(
                serverPrivate, clientPublic, pair.transcriptHash, suite
            )
            @Assert(clientSecrets.hashAlgorithm, "SM3")
            @Assert(clientSecrets.writeKeyLen, 16)
            @Assert(clientSecrets.writeIvLen, 12)
            @Assert(
                clientSecrets.finishedVerifyData(pair.transcriptHash),
                serverSecrets.finishedVerifyData(pair.transcriptHash)
            )
            let client = contractRfc8998CreateClientRecordLayer(clientSecrets)
            let server = contractRfc8998CreateServerRecordLayer(serverSecrets)
            let request = "RFC8998 request".toArray()
            let opened = server.open(client.seal(ContractGmTlsContentType.ApplicationData, request))
            @Assert(opened.contentType, ContractGmTlsContentType.ApplicationData)
            @Assert(opened.fragment, request)
            let response = "RFC8998 response".toArray()
            @Assert(
                client.open(server.seal(ContractGmTlsContentType.Handshake, response)).fragment,
                response
            )
        }
    }

    @TestCase
    public func testRfc8998Sm2CertificateVerifyRoles(): Unit {
        let privateKey = rfc8998Bytes(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        )
        let publicKey = contractSm2PublicFromPrivate(privateKey)
        let transcriptHash = contractSm3("RFC8998 certificate transcript".toArray())
        let server = contractRfc8998BuildServerCertificateVerify(privateKey, transcriptHash)
        let client = contractRfc8998BuildClientCertificateVerify(privateKey, transcriptHash)
        @Assert(
            contractRfc8998VerifyServerCertificateVerify(server, publicKey, transcriptHash),
            true
        )
        @Assert(
            contractRfc8998VerifyClientCertificateVerify(client, publicKey, transcriptHash),
            true
        )
        @Assert(
            contractRfc8998VerifyClientCertificateVerify(server, publicKey, transcriptHash),
            false
        )
        @Assert(
            CONTRACT_RFC8998_SM2_SIGNATURE_IDENTITY,
            "TLSv1.3+GM+Cipher+Suite"
        )
    }
}

private func rfc8998Bytes(hex: String): Array<Byte> {
    let chars = hex.toArray()
    let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < output.size) {
        output[i] = UInt8(rfc8998Nibble(chars[i * 2]) * 16 + rfc8998Nibble(chars[i * 2 + 1]))
        i += 1
    }
    output
}

private func rfc8998Nibble(value: Byte): Int64 {
    if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
        return Int64(value - UInt8(0x30))
    }
    if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
        return Int64(value - UInt8(0x61)) + 10
    }
    Int64(value - UInt8(0x41)) + 10
}
