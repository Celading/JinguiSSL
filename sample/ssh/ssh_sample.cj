/**
 * SSH 启动捆绑包示例
 *
 * 演示服务端和客户端的 SSH key exchange 启动材料准备。
 */
package jinguissl.sample.ssh

import jinguissl.contract.*
import jinguissl_core.crypto.ssh.*

main() {
    println("=== SSH Startup Bundle Sample ===")

    // 1. 生成 X25519 密钥对
    let serverPrivate = contractX25519GenerateKeyPair().privateKey
    let clientPrivate = contractX25519GenerateKeyPair().privateKey

    // 2. 构建 KEX 交互记录
    let clientBanner = "SSH-2.0-jinguissl-client\r\n".toArray()
    let serverBanner = "SSH-2.0-jinguissl-server\r\n".toArray()
    let clientKexInit = sshEncodeKexInit(
        sshBuildDefaultKexInit(cookie: Array<Byte>(16, repeat: 0x10))
    )
    let serverKexInit = sshEncodeKexInit(
        sshBuildDefaultKexInit(cookie: Array<Byte>(16, repeat: 0x20))
    )
    let transcript = ContractSshKexExchangeTranscript(
        clientBanner, serverBanner, clientKexInit, serverKexInit
    )

    // 3. 构建 ECDH 初始化
    let (encodedInit, _) = sshBuildKexEcdhInitX25519(clientPrivate)

    // 4. 协商算法
    let negotiated = ContractSshNegotiatedAlgorithms(
        "curve25519-sha256", "rsa-sha2-256",
        "aes128-ctr", "aes128-ctr",
        "hmac-sha2-256", "hmac-sha2-256"
    )

    // 5. 服务端启动
    let serverBundle = contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request(
        ContractSshServerLibraryStartupX25519RsaPkcs8Request(
            transcript, serverPrivate, encodedInit,
            readPem("testdata/x509/rsa_2048_pkcs8.pem"),
            negotiated,
            sshEncodeNewKeys(), sshEncodeNewKeys(),
            profile: ContractHttpSshStartupProfile.SshServerLibrary,
            aesBackendHint: "shim"
        )
    )
    println("Server Bundle Ready:")
    println("  Profile: ${serverBundle.template.profile.toString()}")
    println("  SSH Ready: ${serverBundle.readiness.sshReady}")
    println("  Host Key Algorithm: ${serverBundle.handshake.hostSignatureAlgorithm}")
    println("  Session ID: ${contractBytesToHexLower(serverBundle.runtime.sessionId())}")

    // 6. 客户端启动
    let clientBundle = contractPrepareSshClientLibraryStartupX25519Request(
        ContractSshClientLibraryStartupX25519Request(
            ContractSshClientInitialHandshakeX25519Request(
                transcript, clientPrivate, encodedInit,
                serverBundle.handshake.encodedReply, negotiated,
                sshEncodeNewKeys(), sshEncodeNewKeys(),
                policy: ContractSshHostVerificationPolicy(
                    negotiatedHostKeyAlgorithm: "rsa-sha2-256",
                    expectedHostKeySha256: serverBundle.handshake.hostKeySha256,
                    requireKnownHost: true, requireHostSignature: true,
                    requireVerifiedHost: true
                )
            ),
            profile: ContractHttpSshStartupProfile.SshClientLibrary,
            aesBackendHint: "shim"
        )
    )
    println()
    println("Client Bundle Ready:")
    println("  Profile: ${clientBundle.template.profile.toString()}")
    println("  SSH Ready: ${clientBundle.readiness.sshReady}")
    println("  Host Verified: ${clientBundle.handshake.requireHostVerification().hostSignatureVerified}")

    println()
    println("SSH startup bundle sample completed.")
}

private func readPem(path: String): String {
    String.fromUtf8(std.fs.File.readFrom(path))
}
