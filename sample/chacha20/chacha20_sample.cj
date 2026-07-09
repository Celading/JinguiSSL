/**
 * ChaCha20-Poly1305 流加密与 AEAD 示例
 */
package jinguissl.sample.chacha20

import jinguissl.contract.*

main() {
    println("=== ChaCha20 / Poly1305 Sample ===")

    // 1. 算法名称
    println("Algorithm: ${contractChacha20Poly1305AlgorithmName()}")

    // 2. 流加密 — ChaCha20 XOR
    let key = Array<Byte>(32, repeat: 0x42)
    let nonce = Array<Byte>(12, repeat: 0x01)
    let plaintext = "Hello, JinguiSSL ChaCha20!".toArray()
    let ciphertext = contractChacha20Xor(key, nonce, plaintext, initialCounter: 0)
    println("Stream Encrypted (${ciphertext.size} bytes)")
    let decrypted = contractChacha20Xor(key, nonce, ciphertext, initialCounter: 0)
    println("Stream Decrypted: ${String.fromUtf8(decrypted)}")

    // 3. AEAD — ChaCha20-Poly1305 加密与认证
    let aeadKey = Array<Byte>(32, repeat: 0x11)
    let aeadNonce = Array<Byte>(12, repeat: 0x22)
    let aeadPlain = "Authenticated encryption with ChaCha20-Poly1305".toArray()
    let aad = "additional-data".toArray()
    let (ct, tag) = contractChacha20Poly1305Encrypt(aeadKey, aeadNonce, aeadPlain, aad: aad)
    println()
    println("AEAD Ciphertext (${ct.size} bytes): ${contractBytesToHexLower(ct)}")
    println("AEAD Tag: ${contractBytesToHexLower(tag)}")

    // 4. 解密验证
    let opened = contractChacha20Poly1305Decrypt(aeadKey, aeadNonce, ct, tag, aad: aad)
    println("Decrypted: ${String.fromUtf8(opened)}")

    // 5. 常量确认
    println()
    println("Constants: KEY_LEN=${CHACHA20_KEY_LEN} NONCE_LEN=${CHACHA20_NONCE_LEN} TAG_LEN=${CHACHA20_POLY1305_TAG_LEN}")
    println("ChaCha20-Poly1305 sample completed.")
}
