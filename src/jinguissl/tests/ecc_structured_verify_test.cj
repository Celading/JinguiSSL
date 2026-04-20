package jinguissl.tests

import std.collection.ArrayList
import jinguissl.crypto.bignum.BigNum
import jinguissl.crypto.digest.sha256
import jinguissl.crypto.ecc.*
import jinguissl.crypto.error.CryptoException

@Test
public class EccStructuredVerifyTestSuite {
    @TestCase
    public func testEs256P256StructuredVerifyRoundTrip(): Unit {
        let privateKey = EcPrivateKey(P256, BigNum.one())
        let publicKey = ecPublicFromPrivateKey(privateKey)
        let signedBytes = "webauthn-structured-verify".toArray()
        let digest = sha256(signedBytes)
        let (r, s) = ecdsaSign(privateKey, digest)
        let request = Es256P256StructuredVerifyRequest(
            publicKey.x.toBytesBE(paddedLen: 32),
            publicKey.y.toBytesBE(paddedLen: 32),
            signedBytes,
            encodeEcdsaDerSignature(r, s)
        )

        let result = es256P256VerifyStructuredRequest(request)
        @Assert(result.signatureVerified, true)
        @Assert(result.digestSha256, digest)

        let outcome = tryEs256P256VerifyStructuredRequest(request)
        @Assert(outcome.ok, true)
        @Assert(outcome.message, "ES256/P-256 signature verified")
        match (outcome.code) {
            case Some(_) =>
                @Fail("successful ES256/P-256 verify outcome must not carry an error code")
            case None => ()
        }
        match (outcome.result) {
            case Some(value) =>
                @Assert(value.signatureVerified, true)
            case None =>
                @Fail("successful ES256/P-256 verify outcome must carry a result")
        }
    }

    @TestCase
    public func testEs256P256StructuredVerifyRejectsWrongSignatureWithoutThrowing(): Unit {
        let privateKey = EcPrivateKey(P256, BigNum.one())
        let publicKey = ecPublicFromPrivateKey(privateKey)
        let originalSignedBytes = "webauthn-structured-verify-ok".toArray()
        let digest = sha256(originalSignedBytes)
        let (r, s) = ecdsaSign(privateKey, digest)
        let tamperedSignedBytes = "webauthn-structured-verify-bad".toArray()
        let request = Es256P256StructuredVerifyRequest(
            publicKey.x.toBytesBE(paddedLen: 32),
            publicKey.y.toBytesBE(paddedLen: 32),
            tamperedSignedBytes,
            encodeEcdsaDerSignature(r, s)
        )

        let result = es256P256VerifyStructuredRequest(request)
        @Assert(result.signatureVerified, false)
        @Assert(result.digestSha256, sha256(tamperedSignedBytes))

        let outcome = tryEs256P256VerifyStructuredRequest(request)
        @Assert(outcome.ok, true)
        @Assert(outcome.message, "ES256/P-256 signature did not verify")
        match (outcome.result) {
            case Some(value) =>
                @Assert(value.signatureVerified, false)
            case None =>
                @Fail("verification-false ES256/P-256 outcome should still carry a result")
        }
    }

    @TestCase
    public func testTryEs256P256StructuredVerifyRejectsInvalidPoint(): Unit {
        let request = Es256P256StructuredVerifyRequest(
            Array<Byte>(32, repeat: 0),
            Array<Byte>(32, repeat: 0),
            "signed".toArray(),
            minimalDummyDerSignature()
        )

        let outcome = tryEs256P256VerifyStructuredRequest(request)
        @Assert(outcome.ok, false)
        @Assert(outcome.message, "public key point is not on curve")
        match (outcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "INVALID_ARGUMENT")
            case None =>
                @Fail("invalid point ES256/P-256 outcome must carry an error code")
        }
        match (outcome.result) {
            case Some(_) =>
                @Fail("invalid point ES256/P-256 outcome must not carry a result")
            case None => ()
        }

        try {
            _ = es256P256VerifyStructuredRequest(request)
            @Fail("invalid point ES256/P-256 verify should throw in non-try form")
        } catch (e: CryptoException) {
            @Assert(e.code.toString(), "INVALID_ARGUMENT")
        }
    }

    @TestCase
    public func testTryEs256P256StructuredVerifyRejectsMalformedDerSignature(): Unit {
        let privateKey = EcPrivateKey(P256, BigNum.one())
        let publicKey = ecPublicFromPrivateKey(privateKey)
        let request = Es256P256StructuredVerifyRequest(
            publicKey.x.toBytesBE(paddedLen: 32),
            publicKey.y.toBytesBE(paddedLen: 32),
            "signed".toArray(),
            [UInt8(0x30), UInt8(0x01), UInt8(0x00)]
        )

        let outcome = tryEs256P256VerifyStructuredRequest(request)
        @Assert(outcome.ok, false)
        match (outcome.code) {
            case Some(value) =>
                @Assert(value.toString(), "PARSE_ERROR")
            case None =>
                @Fail("malformed DER ES256/P-256 outcome must carry an error code")
        }
    }
}

private func minimalDummyDerSignature(): Array<Byte> {
    encodeEcdsaDerSignature(BigNum.one(), BigNum.one())
}

private func encodeEcdsaDerSignature(r: BigNum, s: BigNum): Array<Byte> {
    let encodedR = encodeDerPositiveInteger(r.toBytesBE())
    let encodedS = encodeDerPositiveInteger(s.toBytesBE())
    let payload = ArrayList<Byte>()
    appendBytes(payload, encodedR)
    appendBytes(payload, encodedS)
    wrapDerElement(0x30, payload.toArray())
}

private func encodeDerPositiveInteger(raw: Array<Byte>): Array<Byte> {
    let magnitude = trimLeadingZeroBytes(raw)
    if (magnitude.size == 0) {
        return wrapDerElement(0x02, [UInt8(0)])
    }
    if ((UInt8(magnitude[0]) & UInt8(0x80)) != UInt8(0)) {
        let padded = Array<Byte>(magnitude.size + 1, repeat: 0)
        padded[0] = UInt8(0)
        var i = 0
        while (i < magnitude.size) {
            padded[i + 1] = magnitude[i]
            i += 1
        }
        return wrapDerElement(0x02, padded)
    }
    wrapDerElement(0x02, magnitude)
}

private func wrapDerElement(tag: Int64, value: Array<Byte>): Array<Byte> {
    let length = encodeDerLength(value.size)
    let out = Array<Byte>(1 + length.size + value.size, repeat: 0)
    out[0] = UInt8(tag)

    var i = 0
    while (i < length.size) {
        out[1 + i] = length[i]
        i += 1
    }

    i = 0
    while (i < value.size) {
        out[1 + length.size + i] = value[i]
        i += 1
    }
    out
}

private func encodeDerLength(length: Int64): Array<Byte> {
    if (length < 128) {
        return [UInt8(length)]
    }

    let tmp = ArrayList<Byte>()
    var x = length
    while (x > 0) {
        tmp.add(UInt8(x & 0xff))
        x >>= 8
    }

    let out = Array<Byte>(1 + tmp.size, repeat: 0)
    out[0] = UInt8(0x80 | UInt8(tmp.size))
    var i = 0
    while (i < tmp.size) {
        out[1 + i] = tmp[tmp.size - 1 - i]
        i += 1
    }
    out
}

private func appendBytes(buffer: ArrayList<Byte>, bytes: Array<Byte>): Unit {
    for (byte in bytes) {
        buffer.add(byte)
    }
}

private func trimLeadingZeroBytes(bytes: Array<Byte>): Array<Byte> {
    var offset = 0
    while (offset < bytes.size && UInt8(bytes[offset]) == UInt8(0)) {
        offset += 1
    }
    if (offset == 0) {
        return bytes.clone()
    }
    if (offset >= bytes.size) {
        return []
    }
    bytes[offset..]
}
