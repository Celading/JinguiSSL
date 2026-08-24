package jinguissl.tests

import std.fs.File
import jinguissl.contract.*

@Test
public class ContractAsymmetricTestSuite {
    @TestCase
    public func testEccP256SignVerifyAndEcdh(): Unit {
        let privateA = scalarOne(32)
        let privateB = scalarTwo(32)
        let publicA = contractEcPublicFromPrivate(ContractEcCurve.P256, privateA)
        let publicB = contractEcPublicFromPrivate(ContractEcCurve.P256, privateB)
        let signature = contractEcdsaSign(
            ContractEcCurve.P256,
            privateA,
            "contract-ecc".toArray()
        )
        @Assert(contractEcdsaVerify(publicA, "contract-ecc".toArray(), signature), true)
        @Assert(contractEcdsaVerify(publicA, "contract-ecc!".toArray(), signature), false)
        @Assert(
            contractEcdh(ContractEcCurve.P256, privateA, publicB),
            contractEcdh(ContractEcCurve.P256, privateB, publicA)
        )

        for (curve in [
            ContractEcCurve.P384,
            ContractEcCurve.P521,
            ContractEcCurve.Secp256k1
        ]) {
            let privateKey = scalarOne(curve.fieldLen())
            let publicKey = contractEcPublicFromPrivate(curve, privateKey)
            let curveSignature = contractEcdsaSign(curve, privateKey, "curve-shape".toArray())
            @Assert(contractEcdsaVerify(publicKey, "curve-shape".toArray(), curveSignature), true)
        }

        let generated = contractEcGenerateKeyPair(ContractEcCurve.P256)
        @Assert(generated.privateKey.size, 32)
        @Assert(generated.publicKey.uncompressed.size, 65)
    }

    @TestCase
    public func testEd25519PublishedVectorShapeAndTamper(): Unit {
        let seed = hexToBytes("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        let publicKey = contractEd25519PublicFromSeed(seed)
        @Assert(
            contractBytesToHexLower(publicKey),
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        let signature = contractEd25519Sign(seed, [])
        @Assert(contractEd25519Verify(publicKey, [], signature), true)
        @Assert(contractEd25519Verify(publicKey, [UInt8(1)], signature), false)
    }

    @TestCase
    public func testRsaPssAndPkcs1MessageFacade(): Unit {
        let privateKey = contractX509ParseRsaPrivateKeyPkcs8Pem(
            String.fromUtf8(File.readFrom("testdata/x509/rsa_2048_pkcs8.pem"))
        )
        let message = "contract-rsa-message".toArray()
        let pss = contractRsaSign(privateKey, message)
        @Assert(contractRsaVerify(privateKey.publicKey, message, pss), true)
        @Assert(contractRsaVerify(privateKey.publicKey, "tampered".toArray(), pss), false)

        let pkcs1 = contractRsaSign(
            privateKey,
            message,
            scheme: ContractRsaSignatureScheme.Pkcs1v15
        )
        @Assert(
            contractRsaVerify(
                privateKey.publicKey,
                message,
                pkcs1,
                scheme: ContractRsaSignatureScheme.Pkcs1v15
            ),
            true
        )
    }
}

private func scalarOne(size: Int64): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    out[size - 1] = UInt8(1)
    out
}

private func scalarTwo(size: Int64): Array<Byte> {
    let out = Array<Byte>(size, repeat: 0)
    out[size - 1] = UInt8(2)
    out
}

private func hexToBytes(hex: String): Array<Byte> {
    let out = Array<Byte>(hex.size / 2, repeat: 0)
    var i: Int64 = 0
    while (i < hex.size) {
        out[i / 2] = UInt8((hexNibble(hex[i]) << 4) | hexNibble(hex[i + 1]))
        i += 2
    }
    out
}

private func hexNibble(ch: Byte): Int64 {
    if (ch >= b'0' && ch <= b'9') { return Int64(ch - b'0') }
    if (ch >= b'a' && ch <= b'f') { return 10 + Int64(ch - b'a') }
    if (ch >= b'A' && ch <= b'F') { return 10 + Int64(ch - b'A') }
    throw Exception("invalid hex")
}
