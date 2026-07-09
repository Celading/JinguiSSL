/**
 * X25519 密钥协商示例
 *
 * 演示两方使用 X25519 曲线进行 Diffie-Hellman 密钥协商。
 */
package jinguissl.sample.x25519

import jinguissl.contract.*

main() {
    println("=== X25519 Key Agreement Sample ===")

    // 1. 生成密钥对
    let alice = contractX25519GenerateKeyPair()
    let bob = contractX25519GenerateKeyPair()
    println("Alice private key (clamped): ${contractBytesToHexLower(contractX25519ClampPrivateKey(alice.privateKey))}")
    println("Alice public key:  ${contractBytesToHexLower(alice.publicKey)}")
    println("Bob public key:    ${contractBytesToHexLower(bob.publicKey)}")

    // 2. 派生共享密钥（请求对象方式）
    let request = ContractX25519KeyAgreementRequest(alice.privateKey, bob.publicKey)
    let result = contractX25519DeriveKeyAgreement(request)
    println()
    println("Shared secret:     ${contractBytesToHexLower(result.sharedSecret)}")
    println("Algorithm:         ${result.algorithm}")
    println("Alice public key:  ${contractBytesToHexLower(result.publicKey)}")

    // 3. 反向推导（确认一致）
    let reverseResult = contractX25519DeriveKeyAgreement(bob.privateKey, alice.publicKey)
    let match = result.sharedSecret == reverseResult.sharedSecret
    println("Secrets match:     ${match}")

    // 4. Try 版本（错误输入不会 panic）
    println()
    let outcome = contractTryX25519DeriveKeyAgreement([0x01], bob.publicKey)
    println("Bad input outcome: ok=${outcome.ok} msg=${outcome.message}")
    match (outcome.code) {
        case Some(code) => println("  code: ${code.toString()}")
        case None => ()
    }
    match (outcome.igniteCode) {
        case Some(ic) => println("  ignite: ${ic.toString()}")
        case None => ()
    }

    println()
    println("X25519 key agreement sample completed.")
}
