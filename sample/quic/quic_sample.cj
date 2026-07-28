/**
 * QUIC 初始密钥派生、Header Protection 与重试完整性示例
 */
package jinguissl.sample.quic

import jinguissl.contract.*

main() {
    println("=== QUIC Key Derivation & Retry Integrity Sample ===")

    // 1. QUIC 版本 Salt（常量，非函数）
    let saltV1 = QUIC_SALT_V1
    let saltV2 = QUIC_SALT_V2
    println("QUIC v1 Salt: ${contractBytesToHexLower(saltV1)}")
    println("QUIC v2 Salt: ${contractBytesToHexLower(saltV2)}")

    // 2. 初始密钥派生（v1）；isV2=false 表示 v1
    let connId = "test-conn-id".toArray()
    let (clientSecret, serverSecret) = contractQuicInitialSecrets(connId, false)
    println()
    println("Initial Secrets (v1):")
    println("  Client: ${contractBytesToHexLower(clientSecret)}")
    println("  Server: ${contractBytesToHexLower(serverSecret)}")

    // 3. 从 client secret 派生密钥与 IV
    let (clientKey, clientIv) = contractQuicInitialKeyIv(clientSecret, false)
    println()
    println("Client Keys/IV (v1):")
    println("  Client Key: ${contractBytesToHexLower(clientKey)}")
    println("  Client IV:  ${contractBytesToHexLower(clientIv)}")

    // 4. 从 server secret 派生密钥与 IV
    let (serverKey, serverIv) = contractQuicInitialKeyIv(serverSecret, false)
    println()
    println("Server Keys/IV (v1):")
    println("  Server Key: ${contractBytesToHexLower(serverKey)}")
    println("  Server IV:  ${contractBytesToHexLower(serverIv)}")

    // 5. Header Protection Key
    let hpKeyV1 = contractQuicInitialHpKey(clientSecret, false)
    println()
    println("HP Key (v1): ${contractBytesToHexLower(hpKeyV1)}")

    // 6. 一次性密钥派生（v2）
    let connId2 = "different-conn-id".toArray()
    let (oneShotKey, oneShotIv, oneShotHp) = contractQuicInitialKeyDerive(connId2, true)
    println()
    println("One-Shot Keys (v2):")
    println("  Key:   ${contractBytesToHexLower(oneShotKey)}")
    println("  IV:    ${contractBytesToHexLower(oneShotIv)}")
    println("  HP Key: ${contractBytesToHexLower(oneShotHp)}")

    // 7. 不同 connection ID 产生不同密钥
    let (s1, _) = contractQuicInitialSecrets(connId, false)
    let (s2, _) = contractQuicInitialSecrets(connId2, false)
    let keysDiffer = s1 != s2
    println()
    println("Different connId -> different secrets: ${keysDiffer}")

    // 8. QUIC AEAD 加解密
    let pt = "hello quic".toArray()
    let aad = "aad".toArray()
    let sealed = contractQuicAeadEncrypt(clientKey, clientIv, 42, pt, aad)
    let recovered = contractQuicAeadDecrypt(clientKey, clientIv, 42, sealed, aad)
    println()
    println("AEAD round-trip: ${String.fromUtf8(recovered)}")

    // 9. Header Protection mask（AES）
    let hpSample = "sample1234567890".toArray()
    let (firstByteMask, pnMask) = contractQuicHpAesEncrypt(hpSample, hpKeyV1)
    println()
    println("HP AES mask: firstByte=${UInt8(firstByteMask)}, pnMask=${pnMask.size}b")

    // 10. QUIC Retry 完整性标签
    let retryPacket = "retry-pseudo-packet".toArray()
    let origDestConnId = "my-orig-dest-conn-id".toArray()
    let retryTag = contractQuicRetryIntegrityTag(retryPacket, origDestConnId, false)
    println()
    println("Retry Tag (v1): ${contractBytesToHexLower(retryTag)}")

    println()
    println("QUIC sample completed.")
}
