package jinguissl.tests

import std.fs.File
import jinguissl.contract.*

@Test
public class ContractKemX509GeneralTestSuite {
    @TestCase
    public func testTraditionalRsaAndEcdhKemRoundTrips(): Unit {
        let rsaPrivate = contractX509ParseRsaPrivateKeyPkcs8Pem(readText("testdata/x509/rsa_2048_pkcs8.pem"))
        let rsaEncapsulation = contractRsaKemEncapsulate(
            rsaPrivate.publicKey,
            sharedSecretLen: 48,
            info: "contract-rsa-kem".toArray()
        )
        @Assert(
            contractRsaKemDecapsulate(
                rsaPrivate,
                rsaEncapsulation.encapsulatedKey,
                sharedSecretLen: 48,
                info: "contract-rsa-kem".toArray()
            ),
            rsaEncapsulation.sharedSecret
        )

        let ecPrivate = scalarOne(32)
        let ecPublic = contractEcPublicFromPrivate(ContractEcCurve.P256, ecPrivate)
        let ecEncapsulation = contractEcdhKemEncapsulate(
            ecPublic,
            info: "contract-ecdh-kem".toArray()
        )
        @Assert(
            contractEcdhKemDecapsulate(
                ContractEcCurve.P256,
                ecPrivate,
                ecEncapsulation.encapsulatedKey,
                info: "contract-ecdh-kem".toArray()
            ),
            ecEncapsulation.sharedSecret
        )
    }

    @TestCase
    public func testGeneralX509SummaryAndKeyContainers(): Unit {
        let summary = contractX509ParseCertificatePem(readText("testdata/x509/policy_leaf.pem"))
        @Assert(summary.der.size > 0, true)
        @Assert(summary.subjectCommonName.size > 0, true)
        @Assert(summary.issuerCommonName.size > 0, true)
        @Assert(summary.subjectAlternativeDnsNames.contains("www.example.com"), true)
        @Assert(summary.certificateAuthority, false)

        let ecKey = contractX509ParseEcPrivateKeyPkcs8Pem(
            readText("testdata/x509/policy_leaf_key_pkcs8.pem")
        )
        let ecPublic = contractX509ExtractEcPublicKeyPem(readText("testdata/x509/policy_leaf.pem"))
        @Assert(ecKey.publicKey.uncompressed, ecPublic.uncompressed)

        let rsaPkcs1 = contractX509ParseRsaPrivateKeyPkcs1Pem(
            readText("testdata/x509/rsa512_pkcs1.pem")
        )
        @Assert(rsaPkcs1.publicKey.modulus.size > 0, true)
    }
}

private func readText(path: String): String {
    String.fromUtf8(File.readFrom(path))
}

private func scalarOne(size: Int64): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    out[size - 1] = UInt8(1)
    out
}
