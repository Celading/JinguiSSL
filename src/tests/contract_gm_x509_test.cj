package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractGmX509TestSuite {
    @TestCase
    public func testSm2KeyContainersAndCertificateRequest(): Unit {
        let privateKey = gmX509Bytes(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        )
        let containers = contractGmSm2KeyContainers(privateKey)
        @Assert(contractGmParseSm2PublicKeyPem(containers.publicKeyPem), containers.keyPair.publicKey)
        @Assert(contractGmParseSm2PrivateKeySec1Pem(containers.sec1Pem), privateKey)
        @Assert(contractGmParseSm2PrivateKeyPkcs8Pem(containers.pkcs8Pem), privateKey)

        let request = contractGmCreateCertificateRequest("gm-client.example", privateKey)
        @Assert(request.commonName, "gm-client.example")
        @Assert(request.publicKey, containers.keyPair.publicKey)
        let parsed = contractGmParseAndVerifyCertificateRequestPem(request.pem)
        @Assert(parsed.der, request.der)
    }

    @TestCase
    public func testSm2CertificateIssuanceAndChainVerification(): Unit {
        let rootPrivate = gmX509Bytes(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        )
        let leafPrivate = gmX509Bytes(
            "59276e27d506861a16680f3ad9c02dcca6c3f21bdf45a6cdbf1a5c27b4062cc8"
        )
        let root = contractGmCreateSelfSignedCertificate(
            ContractGmCertificateConfig(
                "GM Contract Root",
                serialNumber: [UInt8(0x10)],
                keyUsageMask: CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE |
                    CONTRACT_GM_KEY_USAGE_KEY_CERT_SIGN |
                    CONTRACT_GM_KEY_USAGE_CRL_SIGN
            ),
            rootPrivate
        )
        @Assert(root.selfIssued, true)
        let leaf = contractGmIssueCertificate(
            ContractGmCertificateConfig(
                "gm-leaf.example",
                serialNumber: [UInt8(0x20)],
                notAfter: "300101000000Z",
                keyUsageMask: CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE
            ),
            contractSm2PublicFromPrivate(leafPrivate),
            root.pem,
            rootPrivate
        )
        @Assert(leaf.selfIssued, false)
        @Assert(contractGmParseCertificatePem(leaf.pem).der, leaf.der)
        let verified = contractGmVerifyCertificateChainPem(
            leaf.pem,
            root.pem,
            validationTime: "270101000000Z",
            requiredLeafKeyUsageMask: CONTRACT_GM_KEY_USAGE_DIGITAL_SIGNATURE
        )
        @Assert(verified.chainPem.size, 2)
        @Assert(verified.trustAnchorPem, root.pem)
    }

    @TestCase
    public func testSm2CrlLifecycleAndRevocationGate(): Unit {
        let rootPrivate = gmX509Bytes(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        )
        let leafPrivate = gmX509Bytes(
            "59276e27d506861a16680f3ad9c02dcca6c3f21bdf45a6cdbf1a5c27b4062cc8"
        )
        let root = contractGmCreateSelfSignedCertificate(
            ContractGmCertificateConfig(
                "GM CRL Root",
                keyUsageMask: CONTRACT_GM_KEY_USAGE_KEY_CERT_SIGN |
                    CONTRACT_GM_KEY_USAGE_CRL_SIGN
            ),
            rootPrivate
        )
        let leaf = contractGmIssueCertificate(
            ContractGmCertificateConfig(
                "revoked.example",
                serialNumber: [UInt8(0x33)],
                notAfter: "300101000000Z"
            ),
            contractSm2PublicFromPrivate(leafPrivate),
            root.pem,
            rootPrivate
        )
        let crl = contractGmCreateCrl(
            "270101000000Z",
            root.pem,
            rootPrivate,
            nextUpdate: "280101000000Z",
            revokedCertificates: [ContractGmRevokedCertificate(
                leaf.serialNumber, "270101000000Z"
            )]
        )
        let parsed = contractGmParseAndVerifyCrlPem(crl.pem, root.pem)
        @Assert(parsed.revokedSerialHexLower.size, 1)
        gmX509AssertRejected({ =>
            _ = contractGmVerifyCertificateChainPem(
                leaf.pem,
                root.pem,
                validationTime: "270201000000Z",
                crlPem: crl.pem,
                requireCrlForAllIssuers: true
            )
        })
    }
}

private func gmX509AssertRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (e: ContractException) {
        rejected = e.code == ContractErrorCode.VerifyFailed
    }
    @Assert(rejected, true)
}

private func gmX509Bytes(hex: String): Array<Byte> {
    let chars = hex.toArray()
    let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < output.size) {
        output[i] = UInt8(gmX509Nibble(chars[i * 2]) * 16 + gmX509Nibble(chars[i * 2 + 1]))
        i += 1
    }
    output
}

private func gmX509Nibble(value: Byte): Int64 {
    if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
        return Int64(value - UInt8(0x30))
    }
    if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
        return Int64(value - UInt8(0x61)) + 10
    }
    Int64(value - UInt8(0x41)) + 10
}
