# JinguiSSL Sample 目录

本目录包含 JinguiSSL Contract API 的使用示例。每个场景独立一个子目录，可以直接 `cjpm run` 运行。

## 场景列表

| 目录 | 说明 |
|------|------|
| digest | SHA-256/384/512 摘要、HMAC、HKDF |
| chacha20 | ChaCha20-Poly1305 AEAD 加解密 |
| x25519 | X25519 密钥对生成与密钥协商 |
| x509 | X.509 证书链验证与指纹计算 |
| tls-client | TLS 1.3 客户端验证会话 |
| tls-server | TLS 1.3 服务端 Accepted Transport |
| quic | QUIC 初始密钥派生与 Header Protection |
| ssh | SSH 启动捆绑包（KEX 握手） |
| aes | AES 后端探测与引擎解析 |
| sm | SM3 杂凑、SM4 加密（国密） |
| hmac-hkdf | HMAC 认证与 HKDF 密钥派生 |
| provider-gate | 提供商门禁（错误映射、降级） |
| tls-session-cache | TLS 会话缓存 |

## 运行方式

每个示例子目录是一个独立的 CangJie 项目：

```bash
cd sample/<scenario>
cjpm run
```

如需在外部项目中使用 JinguiSSL，请添加以下依赖：

```toml
[dependencies]
  jinguissl = { git = "https://gitcode.com/changeden/JinguiSSL-contract.git" }
```
