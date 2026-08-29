package jinguissl.tests

import jinguissl.contract.*

@Test
public class ContractGmPrimitivesTestSuite {
    @TestCase
    public func testSm3HashHmacAndKdf(): Unit {
        @Assert(
            gmHex(contractSm3("abc".toArray())),
            "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
        )
        @Assert(contractHmacSm3("key".toArray(), "message".toArray()).size, 32)
        @Assert(contractSm3Kdf("shared-secret".toArray(), 47).size, 47)
    }

    @TestCase
    public func testSm4BlockStreamWideAndMacSurfaces(): Unit {
        let key = gmBytes("0123456789abcdeffedcba9876543210")
        let block = gmBytes("0123456789abcdeffedcba9876543210")
        let encrypted = contractSm4Encrypt(Ecb, key, block)
        @Assert(gmHex(encrypted), "681edf34d206965e86b3e94f536e4246")
        @Assert(contractSm4Decrypt(Ecb, key, encrypted), block)

        let iv = Array<Byte>(16, repeat: UInt8(3))
        let streamMessage = "SM4 stream contract".toArray()
        for (mode in [Ctr, Cfb, Ofb]) {
            let ciphertext = contractSm4Encrypt(mode, key, streamMessage, parameter: iv)
            @Assert(contractSm4Decrypt(mode, key, ciphertext, parameter: iv), streamMessage)
        }

        let wideKey = contractConcat([key, gmBytes("000102030405060708090a0b0c0d0e0f")])
        let wideMessage = Array<Byte>(37, repeat: UInt8(0x5a))
        for (mode in [Xts, Hctr]) {
            let ciphertext = contractSm4Encrypt(mode, wideKey, wideMessage, parameter: iv)
            @Assert(contractSm4Decrypt(mode, wideKey, ciphertext, parameter: iv), wideMessage)
        }
        @Assert(contractSm4Cmac(key, streamMessage).size, 16)
        @Assert(contractSm4CbcMac(key, streamMessage, tagLen: 8).size, 8)
    }

    @TestCase
    public func testSm4AeadRoundTripAndTamperRejection(): Unit {
        let key = gmBytes("0123456789abcdeffedcba9876543210")
        let plaintext = "authenticated Chinese cipher".toArray()
        let aad = "contract-aad".toArray()
        for (algorithm in [Gcm, Ccm]) {
            let nonce = if (algorithm == Gcm) {
                Array<Byte>(12, repeat: UInt8(7))
            } else {
                Array<Byte>(11, repeat: UInt8(7))
            }
            let sealed = contractSm4AeadEncrypt(
                algorithm, key, nonce, plaintext, aad: aad, tagLen: 12
            )
            @Assert(
                contractSm4AeadDecrypt(
                    algorithm, key, nonce, sealed.ciphertext, sealed.tag, aad: aad
                ),
                plaintext
            )
            let badTag = sealed.tag.clone()
            badTag[0] ^= UInt8(1)
            contractAssertRejected({ =>
                _ = contractSm4AeadDecrypt(
                    algorithm, key, nonce, sealed.ciphertext, badTag, aad: aad
                )
            })
        }
    }

    @TestCase
    public func testSm2StableByteFacade(): Unit {
        let privateKey = gmBytes(
            "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
        )
        let publicKey = contractSm2PublicFromPrivate(privateKey)
        @Assert(publicKey.size, CONTRACT_SM2_PUBLIC_KEY_LEN)
        let identity = "1234567812345678".toArray()
        let message = "message digest".toArray()
        let signature = contractSm2Sign(privateKey, identity, message)
        @Assert(signature.encoded.size, CONTRACT_SM2_SIGNATURE_LEN)
        @Assert(contractSm2Verify(publicKey, identity, message, signature), true)
        @Assert(contractSm2ComputeZa(identity, publicKey).size, CONTRACT_SM3_DIGEST_LEN)

        let ciphertext = contractSm2Encrypt(publicKey, message)
        @Assert(contractSm2Decrypt(privateKey, ciphertext), message)
        let generated = contractSm2GenerateKeyPair()
        @Assert(generated.privateKey.size, CONTRACT_SM2_PRIVATE_KEY_LEN)
        @Assert(generated.publicKey.size, CONTRACT_SM2_PUBLIC_KEY_LEN)
    }

    @TestCase
    public func testSm2KeyExchangeConfirmations(): Unit {
        let identity = "1234567812345678".toArray()
        let aStatic = gmBytes("81eb26e941bb5af16df116495f90695272ae2cd63d6c4ae1678418be48230029")
        let aEphemeral = gmBytes("d4de15474db74d06491c440d305e012400990f3e390c7e87153c12db2ea60bb3")
        let bStatic = gmBytes("785129917d45a9ea5437a59356b82338eaadda6ceb199088f14ae10defa229b5")
        let bEphemeral = gmBytes("7e07124814b309489125eaed101113164ebf0f3458c5bd88335c1f9d596243d6")
        let a = contractSm2InitiatorKeyExchange(
            aStatic, aEphemeral,
            contractSm2PublicFromPrivate(bStatic), contractSm2PublicFromPrivate(bEphemeral),
            identity, identity, 16
        )
        let b = contractSm2ResponderKeyExchange(
            bStatic, bEphemeral,
            contractSm2PublicFromPrivate(aStatic), contractSm2PublicFromPrivate(aEphemeral),
            identity, identity, 16
        )
        @Assert(a.key, b.key)
        @Assert(contractSm2VerifyConfirmation(a.expectedPeerConfirmation, b.sendConfirmation), true)
        @Assert(contractSm2VerifyConfirmation(b.expectedPeerConfirmation, a.sendConfirmation), true)
    }

    @TestCase
    public func testGmDrbgContextsDoNotExposeCoreTypes(): Unit {
        let entropy = Array<Byte>(32, repeat: UInt8(0x41))
        let nonce = Array<Byte>(16, repeat: UInt8(0x42))
        let hashDrbg = ContractSm3HashDrbg(entropy, nonce)
        let ctrDrbg = ContractSm4CtrDrbg(entropy, nonce)
        @Assert(hashDrbg.generate(65).size, 65)
        @Assert(ctrDrbg.generate(65).size, 65)
        @Assert(hashDrbg.reseedCounter() > UInt64(1), true)
        @Assert(ctrDrbg.reseedCounter() > UInt64(1), true)
        hashDrbg.reseed(Array<Byte>(32, repeat: UInt8(0x43)))
        ctrDrbg.reseed(Array<Byte>(32, repeat: UInt8(0x44)))
        @Assert(hashDrbg.reseedCounter(), UInt64(1))
        @Assert(ctrDrbg.reseedCounter(), UInt64(1))
        hashDrbg.uninstantiate()
        ctrDrbg.uninstantiate()
        contractAssertRejected({ => _ = hashDrbg.generate(1) })
        contractAssertRejected({ => _ = ctrDrbg.generate(1) })
    }
}

private func contractAssertRejected(action: () -> Unit): Unit {
    var rejected = false
    try {
        action()
    } catch (_: ContractException) {
        rejected = true
    }
    @Assert(rejected, true)
}

private func contractConcat(values: Array<Array<Byte>>): Array<Byte> {
    var size: Int64 = 0
    for (value in values) { size += value.size }
    let output = Array<Byte>(size, repeat: UInt8(0))
    var offset: Int64 = 0
    for (value in values) {
        var i: Int64 = 0
        while (i < value.size) {
            output[offset + i] = value[i]
            i += 1
        }
        offset += value.size
    }
    output
}

private func gmHex(bytes: Array<Byte>): String {
    let digits: Array<String> = [
        "0", "1", "2", "3", "4", "5", "6", "7",
        "8", "9", "a", "b", "c", "d", "e", "f"
    ]
    var output = ""
    for (value in bytes) {
        output += digits[Int64(value >> UInt8(4))]
        output += digits[Int64(value & UInt8(0x0f))]
    }
    output
}

private func gmBytes(hex: String): Array<Byte> {
    let chars = hex.toArray()
    let output = Array<Byte>(chars.size / 2, repeat: UInt8(0))
    var i: Int64 = 0
    while (i < output.size) {
        output[i] = UInt8(gmNibble(chars[i * 2]) * 16 + gmNibble(chars[i * 2 + 1]))
        i += 1
    }
    output
}

private func gmNibble(value: Byte): Int64 {
    if (value >= UInt8(0x30) && value <= UInt8(0x39)) {
        return Int64(value - UInt8(0x30))
    }
    if (value >= UInt8(0x61) && value <= UInt8(0x66)) {
        return Int64(value - UInt8(0x61)) + 10
    }
    Int64(value - UInt8(0x41)) + 10
}
