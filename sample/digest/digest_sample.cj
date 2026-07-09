/**
 * Digest / HMAC / HKDF 使用示例
 */
package jinguissl.sample.digest

import jinguissl.contract.*

main() {
    let data = "JinguiSSL digest sample data".toArray()
    let key = "secret-key-12345678".toArray()
    let empty: Array<Byte> = []

    println("=== Digest / HMAC / HKDF Sample ===")

    // 1. 各种散列算法
    println("MD5:      ${contractBytesToHexLower(contractMd5(empty))}")
    println("SHA-1:    ${contractBytesToHexLower(contractSha1(empty))}")
    println("SHA-256:  ${contractBytesToHexLower(contractSha256(empty))}")
    println("SHA-384:  ${contractBytesToHexLower(contractSha384(empty))}")
    println("SHA-512:  ${contractBytesToHexLower(contractSha512(empty))}")

    // 2. 通用哈希分发器
    println()
    println("Generic Hash Dispatcher:")
    println("  MD5:    ${contractBytesToHexLower(contractHash(HashAlgorithm.MD5, empty))}")
    println("  SHA256: ${contractBytesToHexLower(contractHash(HashAlgorithm.SHA256, empty))}")

    // 3. HMAC
    let hmacResult = contractHmac(HashAlgorithm.SHA256, key, data)
    println()
    println("HMAC-SHA256: ${contractBytesToHexLower(hmacResult)}")

    // 4. HKDF — 完整流程
    let ikm = "input-key-material".toArray()
    let salt = "salt-value".toArray()
    let info = "context-info".toArray()
    let prk = contractHkdfExtract(HashAlgorithm.SHA256, salt, ikm)
    println("HKDF PRK: ${contractBytesToHexLower(prk)}")
    let okm = contractHkdfExpand(HashAlgorithm.SHA256, prk, info, 32)
    println("HKDF OKM(32): ${contractBytesToHexLower(okm)}")

    // 5. HKDF 一步完成
    let okmFull = contractHkdf(HashAlgorithm.SHA256, ikm, info, 16, salt: salt)
    println("HKDF Full(16): ${contractBytesToHexLower(okmFull)}")
    println()
    println("Digest/HMAC/HKDF sample completed.")
}
