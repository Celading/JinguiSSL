package jinguissl_contract_application_smoke

import jinguissl.contract.*

private let SHA256_ABC: String =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

main(): Int64 {
    let payload: Array<Byte> = [0x61, 0x62, 0x63]
    let digest = contractBytesToHexLower(contractSha256(payload))

    if (digest != SHA256_ABC) {
        println("fatal=JinguiSSLContract SHA-256 application smoke mismatch")
        println("actual=${digest}")
        return 1
    }
    if (contractHash(HashAlgorithm.SHA256, payload) != contractSha256(payload)) {
        println("fatal=JinguiSSLContract Contract-owned hash enum mismatch")
        return 1
    }

    let sessionCache = ContractTlsSessionCache(maxEntries: 2, defaultTtlSeconds: 60)
    let sessionIdentity = ContractTlsSessionIdentity(
        ContractTlsVersion.Tls13,
        [UInt8(0x01), UInt8(0x02)],
        serverName: "API.EXAMPLE.COM",
        alpnProtocol: "H2"
    )
    _ = sessionCache.storeFromSecret(
        sessionIdentity,
        Array<Byte>(32, repeat: UInt8(0x33)),
        nowUnixSeconds: 1_800_000_000,
        ttlSeconds: 60
    )
    if (sessionCache.load(sessionIdentity, nowUnixSeconds: 1_800_000_001).isNone()) {
        println("fatal=JinguiSSLContract session cache application smoke miss")
        return 1
    }

    let aesKey: Array<Byte> = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ]
    let aesBlock: Array<Byte> = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    ]
    let aesCiphertext = contractAesEncrypt(ContractAesMode.AesEcb, aesKey, aesBlock)
    if (contractBytesToHexLower(aesCiphertext) != "69c4e0d86a7b0430d8cdb78070b4c55a") {
        println("fatal=JinguiSSLContract AES application smoke mismatch")
        return 1
    }

    let signingKey = contractEd25519GenerateKeyPair()
    let signature = contractEd25519Sign(signingKey.privateKeySeed, payload)
    if (!contractEd25519Verify(signingKey.publicKey, payload, signature)) {
        println("fatal=JinguiSSLContract Ed25519 application smoke mismatch")
        return 1
    }

    let sm3Digest = contractBytesToHexLower(contractSm3(payload))
    if (sm3Digest != "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0") {
        println("fatal=JinguiSSLContract SM3 application smoke mismatch")
        return 1
    }
    let sm4Key: Array<Byte> = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10
    ]
    let sm4Block = sm4Key.clone()
    let sm4Ciphertext = contractSm4Encrypt(ContractSm4Mode.Ecb, sm4Key, sm4Block)
    if (contractBytesToHexLower(sm4Ciphertext) != "681edf34d206965e86b3e94f536e4246") {
        println("fatal=JinguiSSLContract SM4 application smoke mismatch")
        return 1
    }
    if (contractSm4Decrypt(ContractSm4Mode.Ecb, sm4Key, sm4Ciphertext) != sm4Block) {
        println("fatal=JinguiSSLContract SM4 application roundtrip mismatch")
        return 1
    }

    let quicKey: Array<Byte> = [
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d
    ]
    let quicIv: Array<Byte> = [
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3,
        0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c
    ]
    let quicPlaintext = "contract quic consumer".toArray()
    let quicAad = "consumer aad".toArray()
    let sealed = contractQuicAeadEncrypt(
        quicKey, quicIv, 9, quicPlaintext, quicAad,
        ContractQuicAeadAlgorithm.Aes128Gcm
    )
    let recovered = contractQuicAeadDecrypt(
        quicKey, quicIv, 9, sealed, quicAad,
        ContractQuicAeadAlgorithm.Aes128Gcm
    )
    if (recovered != quicPlaintext) {
        println("fatal=JinguiSSLContract QUIC application smoke mismatch")
        return 1
    }

    try {
        _ = contractQuicAeadEncrypt(
            Array<Byte>(32, repeat: 0), quicIv, 9, quicPlaintext, quicAad,
            ContractQuicAeadAlgorithm.Aes128Gcm
        )
        println("fatal=JinguiSSLContract QUIC mismatch was not rejected")
        return 1
    } catch (e: ContractException) {
        if (e.code != ContractErrorCode.BadInput) {
            println("fatal=JinguiSSLContract QUIC mismatch error mapping is wrong")
            return 1
        }
    }

    println("jinguissl_contract_application_smoke=pass")
    println("sha256_abc=${digest}")
    println("aes128_ecb=pass")
    println("ed25519=pass")
    println("tls_session_cache=pass")
    println("sm3_abc=${sm3Digest}")
    println("sm4_ecb=pass")
    println("quic_aead=${ContractQuicAeadAlgorithm.Aes128Gcm}")
    0
}
