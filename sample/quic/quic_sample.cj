/**
 * QUIC 初始密钥派生与重试完整性示例
 */
package jinguissl.sample.quic

import jinguissl.contract.*

main() {
    println("=== QUIC Initial Key Derivation Sample ===")

    // 1. QUIC 版本 Salt
    let saltV1 = contractQuicInitialSaltV1()
    let saltV2 = contractQuicInitialSaltV2()
    println("QUIC v1 Salt: ${contractBytesToHexLower(saltV1)}")
    println("QUIC v2 Salt: ${contractBytesToHexLower(saltV2)}")

    // 2. 初始密钥派生（v1）
    let connId = "test-conn-id".toArray()
    let secretsV1 = contractQuicDeriveInitialSecrets(connId, ContractQuicVersion.V1)
    println()
    println("Initial Secrets (v1):")
    println("  Client: ${contractBytesToHexLower(secretsV1.clientSecret)}")
    println("  Server: ${contractBytesToHexLower(secretsV1.serverSecret)}")

    // 3. 密钥与 IV 派生
    let keyIvV1 = contractQuicDeriveInitialKeyIv(connId, ContractQuicVersion.V1)
    println()
    println("Keys/IV (v1):")
    println("  Client Key: ${contractBytesToHexLower(keyIvV1.clientKey)}")
    println("  Server Key: ${contractBytesToHexLower(keyIvV1.serverKey)}")
    println("  Client IV:  ${contractBytesToHexLower(keyIvV1.clientIv)}")
    println("  Server IV:  ${contractBytesToHexLower(keyIvV1.serverIv)}")

    // 4. Header Protection Key
    let hpKeyV1 = contractQuicDeriveHpKey(connId, ContractQuicVersion.V1)
    println()
    println("HP Key (v1): ${contractBytesToHexLower(hpKeyV1)}")

    // 5. 一次性密钥派生
    let oneShotV1 = contractQuicOneShotInitialKeyDerivation(connId, ContractQuicVersion.V1)
    println("One-Shot Keys (v1) derived successfully")

    // 6. 不同 connection ID 产生不同密钥
    let connId2 = "different-conn-id".toArray()
    let secretsV1b = contractQuicDeriveInitialSecrets(connId2, ContractQuicVersion.V1)
    let keysDiffer = secretsV1.clientSecret != secretsV1b.clientSecret
    println()
    println("Different connId -> different keys: ${keysDiffer}")

    // 7. QUIC Retry 完整性标签
    let retryTag = contractQuicComputeRetryIntegrityTag(
        "retry-pseudo-packet".toArray(),
        ContractQuicVersion.V1
    )
    println()
    println("Retry Tag (v1): ${contractBytesToHexLower(retryTag)}")

    println()
    println("QUIC sample completed.")
}
