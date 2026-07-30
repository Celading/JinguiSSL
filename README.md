<p align="center">
  <img src="https://img.shields.io/badge/Cangjie-JinguiSSL-c96b2c?style=for-the-badge&labelColor=1f2430" alt="JinguiSSL" />
  <img src="https://img.shields.io/badge/version-0.7.7-c96b2c?style=for-the-badge&labelColor=1f2430" alt="Version 0.7.7" />
  <img src="https://img.shields.io/badge/package-static-2f855a?style=for-the-badge&labelColor=1f2430" alt="Static Package" />
  <img src="https://img.shields.io/badge/surface-contract%20first-3182ce?style=for-the-badge&labelColor=1f2430" alt="Contract First" />
  <img src="https://img.shields.io/badge/license-Apache%202.0-1f9d55?style=for-the-badge&labelColor=1f2430" alt="Apache 2.0" />
</p>
<div align="center">
<span style="font-weight:300;font-size:38px">JinguiSSL / 金匮主桥</span><br/>
<span style="font-weight:100;font-size:24px">面向仓颉应用的密码、证书与协议契约层</span>
<p align="center">
  <strong>应用先依赖稳定 facade，再按需下钻到 Core 或 Bridge</strong><br/>
  <sub>Digest · ChaCha20-Poly1305 · X25519 · X.509 · TLS startup · SSH startup · QUIC protection</sub>
</p>
</div>

## 为什么是 JinguiSSL

应用接入密码、证书、TLS、SSH 或 QUIC 时，通常需要的不只是算法函数，还需要统一的输入约束、错误模型、DTO、启动材料和调用边界。`JinguiSSL-contract` 把这些能力组织成更适合应用与框架消费的 facade。

它是 JinguiSSL 家族当前最推荐的应用入口，但不是所有底层密码与协议面的统一“生产认证层”。

| 仓库 | 中文名 | 角色 |
|:--|:--|:--|
| `JinguiSSL-contract` | 金匮主桥 | 应用 facade、DTO、错误和运行时组合入口 |
| `JinguiSSL-core` | 金匮内核 | 算法、证书、TLS/SSH/QUIC 底层构件 |
| `JinguiSSL-bridge` | 金匮代桥 | 动态库、FFI 与运行时桥接辅助 |

## 当前分层

本仓库不是纯瘦 facade。`src/live/live.cj` 仍包含较厚的 TLS、SSH、X.509 与 provider 编排逻辑；较新的 TLS 1.3 增量 client/server runtime 已拆到 `src/live/tls13_*.cj` 等文件中。

- `jinguissl.contract.*` 优先提供应用 contract、DTO 与 facade
- `jinguissl.live.*` 提供 caller-owned transport 上的运行时组合
- 底层密码、握手、record 与包保护细节由 `JinguiSSL-core` 负责

## 能力概览

| 类别 | 当前公开面 | 状态速记 |
|:--|:--|:--|
| 基础 facade | `ContractErrorCode`、`ContractException`、metadata 与 outcome | production candidate with limits |
| Digest / HMAC / HKDF | SHA-256/384/512、HMAC、HKDF；MD5/SHA-1 仅兼容 | production candidate with limits |
| ChaCha20 / Poly1305 | 流密码、MAC 与 AEAD facade | production candidate with limits |
| X25519 contract | key pair、公钥派生、key agreement request/outcome | production candidate with limits |
| X.509 / PEM contract | 证书链、pin 与 HTTP TLS trust/server material | production candidate with limits |
| AES backend readiness | backend 探测、引擎选择与启动检查 | implemented local test |
| SSH startup bundle | KEX 输入、主机验证策略与启动 DTO | implemented local test |
| Provider readiness | capability、self-check、smoke 与 fallback 描述 | 部分 smoke 为 metadata/precheck |
| ECC capability probe | 曲线、ECDSA/ECDH availability 探测 | capability only，不是操作 facade |
| Ed25519 capability probe | key/signature shape 与 availability 探测 | capability only，不是签名 facade |
| RSA capability probe | key size、scheme 与 hash policy 探测 | capability only，不是私钥操作 facade |
| SM3 / SM4 capability probe | availability 与参数形状 | capability only，不是完整操作 facade |
| KEM profile placeholder | KEM profile metadata | 不是 ML-KEM/PQC 实现 |
| QUIC v1/v2 protection facade | Initial、显式 AEAD、Header Protection、Retry integrity | 不含 transport/HTTP3 |
| TLS session cache | bounded cache、ticket identity 与 replay helper | implemented local test |
| TLS cipher-suite / PSK contracts | cipher suite、PSK 与 server-handshake DTO | implemented local test |
| Incremental TLS 1.3 live runtime | caller-owned transport 的 client/server handshake 与 verified channel | 非浏览器级 HTTPS 证明 |
| Runtime compatibility profiles | runtime marker 与 startup profile catalog | 不等于多平台实机证明 |

完整证据、manual 映射与限制见 [Capability Matrix](docs/capability-matrix.md)。

## 快速开始

```toml
[dependencies]
jinguissl = { git = "https://gitcode.com/cinyu/jinguiSSL.git" }
```

```cangjie
import jinguissl.contract.*

main() {
    let digest = contractSha256("hello jingui".toArray())
    println(contractBytesToHexLower(digest))
}
```

Contract 源码采用 `Apache-2.0`，依赖的 Core 当前源码线采用 `LGPL-3.0-only`。组合分发、链接或打包时，需要同时核对 Core 的许可证要求。

## 常见入口

### 证书与 HTTP/TLS 材料

- `contractComputeLeafPinsFromPem(...)`
- `contractVerifyServerCertificateChainPem(...)`
- `contractPrepareHttpClientTlsTrustMaterial(...)`
- `contractPrepareHttpServerTlsMaterial(...)`

### QUIC 包保护

- `contractQuicInitialSecrets(...)`
- `contractQuicAeadEncrypt(...)` / `contractQuicAeadDecrypt(...)`
- `contractQuicHpAesEncrypt(...)` / `contractQuicHpChaChaEncrypt(...)`
- `contractQuicRetryIntegrityTag(...)`

### TLS 1.3 caller-owned transport

`jinguissl.live.*` 提供增量 client/server record 输入输出、protected flight、client Finished 验证和 verified application channel。调用方仍负责 socket、读写调度、超时和上层协议。

## 构建、测试与提交前门禁

```bash
cjpm build
cjpm test
bash scripts/jinguissl_pre_review.sh <base-ref>
```

提交前门禁会检查公开残留、托管依赖图、依赖锁、能力矩阵、README/manual 同步、包构建测试和 standalone application consumer。

## 文档与示例

- [使用手册](docs/usage-guide.md)
- [能力矩阵](docs/capability-matrix.md)
- [快速开始](docs/getting-started.md)
- [错误处理](docs/error-handling.md)
- [QUIC](docs/quic.md)
- [X.509 与 HTTP/TLS](docs/x509-and-http-tls.md)
- [开发示例](examples/README.md)

当前完整测试覆盖：**282 项**。基准目录只提供非正式量级采样，不构成性能承诺。

## 安全与生产边界

Contract 的安全边界继承 Core。Core 中尚未完成恒定时间证明的私钥路径，不能因为套上 Contract facade 就被描述为已认证的生产级密码后端。

当前不声明法律或安全认证、完整恒定时间保证、浏览器级 HTTPS、外部 OpenSSL/curl/SSH/QUIC 在线互操作完成、完整 thin facade、全平台原生系统信任库、QUIC transport 或 HTTP/3。

## 许可证

本仓库源码采用 `Apache License 2.0`，详见 `LICENSE`。其 Apache 源码许可不取消 Core 依赖在组合分发、链接或打包场景中的 LGPL 义务。
