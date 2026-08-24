# JinguiSSL Contract 使用手册

## 目录

1. [概述](#1-概述)
2. [依赖集成](#2-依赖集成)
3. [快速开始](#3-快速开始)
4. [核心模块](#4-核心模块)
5. [错误处理模式](#5-错误处理模式)
6. [Outcome 模式](#6-outcome-模式)
7. [构建与测试](#7-构建与测试)
8. [常见问题](#8-常见问题)

## 1. 概述

JinguiSSL 是面向仓颉（Cangjie）应用的密码学、证书、TLS 与 SSH 契约层。仓库定位：

| 仓库 | 角色 |
|------|------|
| JinguiSSL-contract | 稳定 facade / contract（本仓库） |
| JinguiSSL-core | 算法与协议底层 |
| JinguiSSL-bridge | 动态桥接与运行时接入辅助 |

### 当前能力矩阵

公开能力使用 `production-candidate-with-limits`、`implemented-local-test`、
`internal-or-placeholder`、`blocked-or-deferred` 与 `legacy-only` 五级词汇。
机器可检验的完整矩阵见 [capability-matrix.md](capability-matrix.md)。

尤其需要区分：

- Digest、ChaCha20-Poly1305、X25519、X.509 材料与 QUIC 包保护是较稳定的 facade 候选，但仍无外部认证。
- ECC、Ed25519、RSA 当前主要是 capability probe；SM2/SM3/SM4、SM9、GM X.509、RFC 8998 与 TLCP/DTLCP 已有独立 Contract facade 和本地测试。
- KEM 是 profile placeholder，不是 ML-KEM/PQC 实现。
- TLS 1.3 live runtime 已有 caller-owned transport 测试，但不是浏览器级 HTTPS 或外部 H2 证明。

## 2. 依赖集成

### cjpm.toml

```toml
[dependencies]
jinguissl = { git = "https://gitcode.com/cinyu/jinguiSSL.git" }
```

### import 方式

```cangjie
// 导入全部 contract 类型和函数
import jinguissl.contract.*

// 导入 live 层（TLS 握手、SSH 运行时等）
import jinguissl.live.*

// 按需导入 core 层（仅当直接使用底层算法时）
import jinguissl_core.crypto.digest.{sha256, bytesToHexLower}
```

## 3. 快速开始

### SHA-256 摘要

```cangjie
import jinguissl.contract.*

main() {
    let data = "hello jingui".toArray()
    let digest = contractSha256(data)
    println(contractBytesToHexLower(digest))
}
```

### X25519 密钥协商

```cangjie
import jinguissl.contract.*

main() {
    let alice = contractX25519GenerateKeyPair()
    let bob = contractX25519GenerateKeyPair()

    let shared1 = contractX25519DeriveKeyAgreement(alice.privateKey, bob.publicKey)
    let shared2 = contractX25519DeriveKeyAgreement(bob.privateKey, alice.publicKey)
    println("Match: ${shared1.sharedSecret == shared2.sharedSecret}")
}
```

### 证书链验证

```cangjie
import jinguissl.contract.*

main() {
    let result = contractVerifyServerCertificateChainPem(
        chainPem, rootPem, hostname: "example.com"
    )
    println("Chain: ${result.chainLength}, anchor: ${result.trustAnchorCommonName}")
}
```

## 4. 核心模块

参考各模块的独立文档：

| 文档 | 说明 |
|------|------|
| [getting-started.md](getting-started.md) | 快速开始 + 完整示例 |
| [overview.md](overview.md) | 项目总览 |
| [digest.md](digest.md) | Digest / HMAC / HKDF |
| [chacha20-poly1305.md](chacha20-poly1305.md) | ChaCha20 / Poly1305 AEAD |
| [x25519.md](x25519.md) | X25519 密钥协商 |
| [x509-and-http-tls.md](x509-and-http-tls.md) | X.509 证书 / HTTP/TLS |
| [ssh.md](ssh.md) | SSH 启动捆绑包 |
| [quic.md](quic.md) | QUIC 初始密钥派生 |
| [aes-readiness.md](aes-readiness.md) | AES 后端探测 |
| [tls-session-cache.md](tls-session-cache.md) | TLS 会话缓存 |
| [china-crypto.md](china-crypto.md) | SM2/SM3/SM4/SM9、GM X.509、RFC 8998 与 TLCP/DTLCP |
| [gm-test-manifest.md](gm-test-manifest.md) | 国密 Contract 公开测试面与重放命令 |
| [provider-gate.md](provider-gate.md) | 提供商门禁 |
| [error-handling.md](error-handling.md) | 错误处理模型 |
| [ecc-ed25519-rsa.md](ecc-ed25519-rsa.md) | ECC / Ed25519 / RSA |
| [kem.md](kem.md) | KEM 密钥封装机制 |

`contractTls13CipherSuiteAeadAlgorithm(...)` 现在识别 RFC 8998 的
`TLS_SM4_GCM_SM3` 与 `TLS_SM4_CCM_SM3`，分别返回 `Sm4Gcm` 与 `Sm4Ccm`。
完整国密握手应使用 `contractRfc8998*` facade；遗留 AES/ChaCha live 路径不会静默把
SM4 suite 当作普通 TLS 1.3 runtime 处理。

## 5. 错误处理模式

JinguiSSL 使用分层错误模型：

```
ContractException
  └── code: ContractErrorCode
  └── message: String
```

捕获方式：

```cangjie
try {
    let result = contractRequireAesAcceleratedBackend()
} catch (e: ContractException) {
    println("Error: ${e.code.toString()} — ${e.message}")
}
```

`ContractErrorCode` 包括：`BadInput`, `KeyNotFound`, `VerifyFailed`, `CryptoUnavailable`, `ComplianceRejected`, `Unsupported`, `InternalError`。

详细文档：[error-handling.md](error-handling.md)

## 6. Outcome 模式

JinguiSSL 为关键操作提供了 `try-` 前缀的非抛出变体，返回 `Outcome` 类型：

```cangjie
let outcome = contractTryX25519DeriveKeyAgreement(alicePriv, bobPub)
if (outcome.ok) {
    let result = outcome.result  // ?ContractX25519KeyAgreementResult
} else {
    let code = outcome.code      // ?ContractErrorCode
}
```

所有 Outcome 类型共有的字段：
- `ok: Bool` — 操作是否成功
- `message: String` — 描述信息
- `code: ?ContractErrorCode` — 错误码（成功时为 None）
- `igniteCode: ?ContractIgniteCryptoErrorCode` — 保留的下游兼容错误码字段
- `result: ?ResultType` — 成功时的结果（类型因操作而异）

## 7. 构建与测试

```bash
# 构建
cjpm build

# 运行所有测试
cjpm test

# 运行示例（详见 examples/ 目录）
cd examples/<scenario>
cjpm run

# 基准测试
cd benchmark
cjpm build
cjpm run
```

## 8. 常见问题

### Q: contract 和 live 有什么区别？
A: `contract` 包（jinguissl.contract.\*）优先提供 facade、DTO 和能力探测；部分高层入口会与较厚的 live 编排配合。`live` 包（jinguissl.live.\*）承载 caller-owned transport 上的握手与运行时状态。一般场景先从 `contract.*` 开始，再按需要进入 `live.*`。

### Q: AES 硬件加速如何启用？
A: 通过 `contractAesProbeHardware()` 探测硬件支持，使用 `contractResolveAesEngine(requestedEngine: Hardware)` 请求硬件加速引擎。不满足时自动回退到软件实现。

### Q: startup profile 通过是否等于生产认证？
A: 不等于。`contractRequireHttpSshStartupReadiness(...)` 只检查当前 profile 定义的启动条件；它不能替代恒定时间审计、平台验证、证书策略、外部互操作或安全认证。

### Q: Outcome 模式有什么好处？
A: 避免 try/catch 控制流，将错误作为值显式传递，更适合组合式调用和异步编程模式。
