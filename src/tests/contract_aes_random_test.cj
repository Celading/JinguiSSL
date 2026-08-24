package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractAesRandomTestSuite {
    @TestCase
    public func testAesPublishedBlockAndGcmRoundTrips(): Unit {
        let key = hexToBytes("000102030405060708090a0b0c0d0e0f")
        let block = hexToBytes("00112233445566778899aabbccddeeff")
        let encrypted = contractAesEncrypt(ContractAesMode.AesEcb, key, block)
        @Assert(contractBytesToHexLower(encrypted), "69c4e0d86a7b0430d8cdb78070b4c55a")
        @Assert(contractAesDecrypt(ContractAesMode.AesEcb, key, encrypted), block)

        let gcm = contractAesGcmEncrypt(
            key,
            hexToBytes("101112131415161718191a1b"),
            "contract-aes-gcm".toArray(),
            aad: "aad".toArray()
        )
        @Assert(
            contractAesGcmDecrypt(
                key,
                hexToBytes("101112131415161718191a1b"),
                gcm.ciphertext,
                gcm.tag,
                aad: "aad".toArray()
            ),
            "contract-aes-gcm".toArray()
        )
    }

    @TestCase
    public func testAesGcmTamperAndRandomBoundary(): Unit {
        let key = Array<Byte>(16, repeat: 0)
        let nonce = Array<Byte>(12, repeat: UInt8(1))
        let result = contractAesGcmEncrypt(key, nonce, "secret".toArray())
        let badTag = result.tag.clone()
        badTag[0] = UInt8(badTag[0]) ^ UInt8(1)
        try {
            _ = contractAesGcmDecrypt(key, nonce, result.ciphertext, badTag)
            @Fail("tampered AES-GCM tag must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "VERIFY_FAILED")
        }

        @Assert(contractRandomAvailable(), true)
        @Assert(contractRandomBytes(32).size, 32)
        try {
            _ = contractRandomBytes(0)
            @Fail("zero random size must fail")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }

        try {
            _ = contractAesGcmDecrypt(Array<Byte>(15, repeat: 0), nonce, result.ciphertext, result.tag)
            @Fail("invalid AES key shape must fail before authentication")
        } catch (e: ContractException) {
            @Assert(e.code.toString(), "BAD_INPUT")
        }
    }
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
