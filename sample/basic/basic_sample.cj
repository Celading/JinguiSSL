/**
 * 基础示例 — 获取 JinguiSSL contract facade 信息和能力概览
 *
 * 编译前提：在项目的 cjpm.toml 中添加 jinguissl 依赖
 *
 * 运行方式：
 *   cjpm build
 *   cjpm run
 */
package jinguissl.sample.basic

import jinguissl.contract.*

main() {
    // 1. 获取 facade 元数据
    let info = contractFacadeInfo()
    println("=== JinguiSSL Contract Facade ===")
    println("API Version:    ${info.apiVersion}")
    println("Stability:      ${info.stabilityLevel}")
    println("Freeze Date:    ${info.freezeDate}")
    println("Stable Domains: ${info.stableDomains}")
    println("Import Rule:    ${info.importRule}")
    println()

    // 2. 获取能力概览
    let capability = contractCapabilityInfo()
    println("=== Capability Overview ===")
    println("HTTP/TLS Features:  ${capability.httpTlsFeatures}")
    println("SSH Features:       ${capability.sshFeatures}")
    println("X.509 Features:     ${capability.x509Features}")
    println()

    // 3. 测试 SHA-256 摘要
    let data = "hello jingui".toArray()
    let digest = contractSha256(data)
    println("SHA-256(\"hello jingui\") = ${contractBytesToHexLower(digest)}")
    println()
    println("JinguiSSL contract facade is ready.")
}
