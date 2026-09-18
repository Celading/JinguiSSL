# 0.9.0

直接依赖 `jinguissl = "0.9.0"`，导入 `jinguissl.contract.*`。
主桥传递依赖中心仓 `jinguissl_core = "0.9.0"`，不使用本地或 Git 回退。
版本说明描述源码内容，不代表中心仓审核或索引已经完成。

## 更新 / Changes

- 主桥提供 BLAKE2s 增量上下文、HChaCha20、XChaCha20-Poly1305。
- 自有 AES-GCM 上下文与 Into 接口复用密钥扩展，认证失败清理输出，销毁后拒绝复用。
- SSH 流消费接入已验证密钥交换和主机策略，保留实际包计数与加密状态。
- 通用 TLS 1.3 服务端支持 P-256/X25519、三种密码套件和显式 ALPN；不继承 HTTP 默认策略。
- 更新运行时/provider 版本报告为0.9.0；保留已有 DTLS、TLS/QUIC 与国密接口。

The public facade adds BLAKE2s contexts, HChaCha20, XChaCha20-Poly1305,
owned AES-GCM contexts and Into operations, bounded SSH stream consumers,
and a general TLS 1.3 server engine. Applications need only the facade;
the core is a transitive registry dependency, without local or Git fallback.

详见 [协议消费指南](protocol-consumption.md) 和 [能力矩阵](capability-matrix.md)。
此版本不等于完整 SSH 登录、所有平台设备验证或安全认证。
This release does not claim a complete SSH client, certification, or
validation on every supported platform.
