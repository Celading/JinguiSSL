/**
 * X.509 / PEM 证书处理示例
 *
 * 演示证书链验证、pin 计算、客户端/服务端 TLS 信任材料准备。
 */
package jinguissl.sample.x509

import std.fs.File
import jinguissl.contract.*

main() {
    println("=== X.509 / TLS Certificate Sample ===")

    // 1. 服务端 TLS 材料 — 验证证书链与私钥匹配
    let serverCertPem = String.fromUtf8(
        File.readFrom("testdata/x509/rsa_2048_chain.pem")
    )
    let serverKeyPem = String.fromUtf8(
        File.readFrom("testdata/x509/rsa_2048_pkcs8.pem")
    )
    let validation = contractValidateHttpServerTlsConfigInput(
        serverCertPem, serverKeyPem,
        alpnProtocols: ["h2", "http/1.1"],
        requireHttp2Alpn: true
    )
    println("Server TLS Config Validation:")
    println("  Chain Length: ${validation.certificateChainLength}")
    println("  Key Algorithm: ${validation.keyAlgorithm}")
    println("  Subject: ${validation.leafSubjectCommonName}")
    println("  ALPN: ${validation.normalizedAlpnProtocols}")

    // 2. 准备服务端 TLS 材料
    let material = contractPrepareHttpServerTlsMaterial(
        ContractHttpServerTlsConfigRequest(
            serverCertPem, serverKeyPem,
            alpnProtocols: ["h2", "http/1.1"],
            requireHttp2Alpn: true
        )
    )
    println()
    println("Server TLS Material Ready: ${material.validation.certificateChainLength} certs")

    // 3. 客户端 TLS 信任材料
    let trustAnchorsPem = String.fromUtf8(
        File.readFrom("testdata/x509/rsa_2048_trust_anchor.pem")
    )
    let trustMaterial = contractPrepareHttpClientTlsTrustMaterial(
        ContractHttpClientTlsTrustRequest(
            trustAnchorsPem, hostname: "example.com"
        )
    )
    println()
    println("Client TLS Trust Material:")
    println("  Trust Anchors: ${trustMaterial.validation.trustAnchorCount}")
    println("  Hostname: ${trustMaterial.validation.normalizedHostname}")

    // 4. vverify 服务端证书
    let chainPem = String.fromUtf8(
        File.readFrom("testdata/x509/rsa_2048_chain.pem")
    )
    let intermediatesPem = String.fromUtf8(
        File.readFrom("testdata/x509/rsa_2048_intermediates.pem")
    )
    let result = contractVerifyServerCertificateChainPem(
        chainPem, trustAnchorsPem,
        intermediatesPemBundle: intermediatesPem,
        hostname: "example.com"
    )
    println()
    println("Certificate Chain Verification: chain_length=${result.chainLength}")
    println("Leaf Subject: ${result.leafSubjectCommonName}")

    println()
    println("X.509 sample completed.")
}
