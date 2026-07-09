/**
 * HTTP/TLS 启动材料示例
 *
 * 演示服务端和客户端的 TLS 配置验证与启动材料准备。
 */
package jinguissl.sample.http_tls

import std.fs.File
import jinguissl.contract.*

main() {
    println("=== HTTP/TLS Startup Material Sample ===")

    let chainPem = String.fromUtf8(File.readFrom("testdata/x509/rsa_2048_chain.pem"))
    let keyPem = String.fromUtf8(File.readFrom("testdata/x509/rsa_2048_pkcs8.pem"))
    let trustPem = String.fromUtf8(File.readFrom("testdata/x509/rsa_2048_trust_anchor.pem"))

    // 1. HTTP/TLS 启动就绪检查
    let readiness = contractHttpSshStartupReadinessReport()
    println("Readiness: httpTls=${readiness.httpTlsReady} x509=${readiness.x509Ready} overall=${readiness.overallReady}")

    // 2. 验证服务端 TLS 配置
    let validation = contractValidateHttpServerTlsConfigInput(
        chainPem, keyPem,
        alpnProtocols: ["h2", "http/1.1"]
    )
    println()
    println("Server Config Validation:")
    println("  Cert Chain: ${validation.certificateChainLength}")
    println("  Subject: ${validation.leafSubjectCommonName}")
    println("  Key: ${validation.keyAlgorithm}")

    // 3. Try 版本（安全处理错误）
    let outcome = contractTryValidateHttpServerTlsConfigInput(
        chainPem, keyPem,
        alpnProtocols: ["h2", "http/1.1"]
    )
    println()
    println("Try Validation: ok=${outcome.ok} msg=${outcome.message}")

    // 4. 客户端 TLS 信任材料
    let trustReq = ContractHttpClientTlsTrustRequest(
        trustPem,
        hostname: "jingui.example.com"
    )
    let trustMaterial = contractPrepareHttpClientTlsTrustMaterial(trustReq)
    println()
    println("Client Trust Material:")
    println("  Anchors: ${trustMaterial.validation.trustAnchorCount}")
    println("  Hostname: ${trustMaterial.validation.normalizedHostname}")

    // 5. HTTP/TLS 启动捆绑包（服务端）
    let httpRequest = ContractHttpServerTlsConfigRequest(
        chainPem, keyPem,
        alpnProtocols: ["h2", "http/1.1"]
    )
    let httpBundle = contractPrepareHttpServerLibraryStartup(
        httpRequest,
        profile: ContractHttpSshStartupProfile.HttpServerLibrary,
        aesBackendHint: "shim"
    )
    println()
    println("Server Startup Bundle: profile=${httpBundle.result.match {
        case Some(bundle) => bundle.template.profile.toString()
        case None => "N/A"
    }}")

    // 6. ALPN 规范化
    let normalized = contractNormalizeAlpnProtocols(["H2", "http/1.1", "h2"])
    println("Normalized ALPN: ${normalized}")

    println()
    println("HTTP/TLS startup material sample completed.")
}
