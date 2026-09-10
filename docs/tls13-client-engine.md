# 通用 TLS / QUIC 客户端

直接依赖包 `jinguissl`，导入 `jinguissl.contract.*`。本页描述当前源码候选，
不表示既有中心包 0.7.7 已包含新接口。集成时固定已审阅的 Contract Git 提交，
保留其 `cjpm.lock` 指定的 Core 传递依赖；不要添加 Core 直接依赖或本机缓存绝对路径。

## 选择入口

| 入口 | 输入 | 主桥拥有 | 调用方拥有 |
| --- | --- | --- | --- |
| `ContractTls13StreamClient` | 有序 TCP/TLS record 字节，可分片或合并 | 认证、握手与应用 record 的独立计数器、Finished、票据丢弃与关闭通知 | socket、发送顺序、超时、EOF/截断判定、应用协议 |
| `ContractTls13ClientEngine` | 有序且已按加密级别解密的原始 handshake 字节 | 消息重组、认证、ALPN、阶段秘密、认证后的 QUIC 参数 | QUIC packet number、CRYPTO offset/重传重组、HP/AEAD、传输参数语义与连接关闭 |

不需要把 Core 的 AuthFlight、X509VerificationPolicy、密钥或 record DTO 改成 public。
九个历史 internal wrapper 保持内部；新接口使用 Contract 自有对象和字节。

## TLS 字节流

构造函数要求 PEM 信任根、DNS 主机名、校验时间。时间采用 ASN.1 UTC 或 Generalized
形式，例如测试固定时间 `270101000000Z`；生产调用方必须传入当前可信时间，不能照抄测试时间。
证书策略要求 digitalSignature Key Usage 与 serverAuth EKU，并校验证书链、有效期和 DNS。
没有 skipVerify 或“证书失败后仅验 Finished”的降级入口。

```cangjie
let client = ContractTls13StreamClient(
    trustPem, serverName, currentValidationTime,
    alpnProtocols: ["mqtt"], requireAlpn: true
)
// 发送 client.takeHandshakeOutput() 得到的 ClientHello。
// 每次从 socket 读到 bytes：
let applicationFragments = client.receive(bytes)
// 再取并发送 takeHandshakeOutput()：可能包含空 Certificate、client Finished 或 close_notify。
// authenticated 后，先发完 Finished，再发送 sealApplicationData(payload)。
```

空 ALPN 默认保持空，不替换成 HTTP 协议；`requireAlpn: true` 必须有明确 offer。
服务器可以在 EE 中返回合法的 `supported_groups` 偏好列表（包括客户端未提供的组）。
主桥校验其向量结构并保留认证转录，不据此重选本次 X25519 或缓存后续连接偏好；
这不是对列表中其他算法的支持声明。重复扩展和畸形向量仍失败。
每次应用写入最多 16 KiB。record 输入单次最多 1 MiB；握手总明文最多 256 KiB、
握手 record 最多 4096 条。调用方仍需总时限，不能把字节预算当成超时。
正常退出用 `closeNotify()` 取得并发送关闭记录；`close()` 只清理本地状态。
收到 peer close_notify 后 `isClosed` 为真，可最后一次取出关闭响应；裸 TCP EOF 不等于可信关闭。

## QUIC 无 record 握手

用 `quicTransportParameters: Some(opaqueBytes)` 构造 `ContractTls13ClientEngine`。
这会要求明确 ALPN，并在 ClientHello 写入扩展 0x39。返回的 `clientHello()`
是 handshake 字节，不含 TLS record 头。

1. Initial 级别解密后的有序字节交给 `receiveInitial()`；仅接受 ServerHello，允许分片。
2. 取 `handshakeSecrets()`，用客户端/服务端 traffic secret 派生对应 QUIC packet keys。
   不要将 `clientTlsKeyIv()` 的 TLS 标签结果当作 QUIC keys；QUIC 使用自己的 HKDF 标签。
3. Handshake 级别字节交给 `receiveHandshake()`；验证 EE → 可选 CertificateRequest → Certificate → CV → Finished，允许同级分片/合并。
4. `authenticated` 后取 `clientHandshakeOutput()` 并在 Handshake 级别发送；它包含可选的空 Certificate 和 Finished。此时才能取得
   `applicationSecrets()`、`selectedAlpn()`、`peerCertificateChainDer()` 和认证过的 `peerTransportParameters()`。
5. One-RTT CRYPTO 中的票据可交给 `receivePostHandshake()` 校验后丢弃，不会启用 PSK 或 0-RTT。

缺失 QUIC 参数或 ALPN 失败时，`failureAlertDescription` 分别提供 109/120；
已知的非法 EE 扩展为 110。其他错误可能无精确 alert 映射，调用方必须关闭连接，
不得靠字符串匹配错误消息继续握手。QUIC 连接错误的编码和发送仍由传输层实现。
参数内容只做认证，不替消费者检查 QUIC 版本、连接 ID 或流控限制。

## 可选客户端证书请求

初始握手接受一次位于 EE 与服务器 Certificate 之间的 CertificateRequest。
请求必须使用空 context、合法且必需的 signature_algorithms，不得重复扩展；未知扩展忽略，
但所有原始字节保留在认证转录中。主桥没有客户端身份配置，因此按
[RFC 8446 §4.4.2](https://www.rfc-editor.org/rfc/rfc8446.html#section-4.4.2)
回应空 Certificate、不发送客户端 CertificateVerify，再发送覆盖该空 Certificate 的 Finished。
这允许“请求但不强制证书”的服务端继续；强制客户端证书的服务端仍会拒绝。

raw engine 调用者应发送 `clientHandshakeOutput()`，不能只发送 `clientFinished()`。
若分别取消息，`clientCertificate()` 在未请求时返回空数组，否则必须先发送它，再发送
`clientFinished()`。stream adapter 自动按两个独立握手 record 排序发送。
`authenticated` 只表示服务器身份已验证，不代表服务器已经接受客户端空证书。
后握手 CertificateRequest 仍拒绝；没有开启 post_handshake_auth。

## 秘密与失败

`ContractTls13PhaseSecrets` 明确标注 `handshake` 或 `application`，持有私有秘密副本；
getter 返回独立快照。调用 `destroy()` 可重复执行，销毁后不能再次导出。
引擎失败/close 会销毁自己持有的秘密，但不会修改此前交给调用方的独立副本。
调用方必须销毁导出的 phase 对象，并管理另外导出的数组。
公开状态对象通过互斥锁串行化访问；不在锁内执行调用方回调。

这是托管内存中显式、尽力的清理，不是 GC 副本、临时原语分配或物理内存擦除证明。
旧 Core record context 暂无完整 destroy API；stream close 会撤销访问并释放引用，
不能因此声称所有派生轮密钥都被主动清零。

## 验证和限制

支持 X25519 与 TLS_AES_128_GCM_SHA256、TLS_AES_256_GCM_SHA384、TLS_CHACHA20_POLY1305_SHA256。
不支持 HRR、PSK/resumption、0-RTT、客户端证书认证、KeyUpdate 或新通用服务端引擎。
新入口不自动替换既有国密协议面或 legacy live runtime。

四个独立消费者只直接声明 `jinguissl`：

- `examples/webauthn-crypto-smoke`：独立 OpenSSL ES256 DER 签名、篡改拒绝、SHA-256；不实现 WebAuthn ceremony。
- `examples/webdav-digest-smoke`：摘要和 hex 固定向量；MD5 仅遗留兼容，不拥有 nonce/replay 策略。
- `examples/tls-client-smoke`：与本机 OpenSSL 对端验证非 HTTP ALPN、双向 Finished、票据与双向应用数据。
- `examples/quic-crypto-smoke`：Initial/HP/AEAD/Retry；与 aioquic 1.3.0 raw TLS engine 验证 Finished 及四个阶段/方向秘密。

```bash
bash scripts/jinguissl_consumer_smokes.sh
python3 scripts/tls_client_openssl_smoke.py
# OpenSSL CLI (可用 OPENSSL 指定可执行文件)：可选请求成功 / 强制证书拒绝
python3 scripts/tls_client_certificate_request_smoke.py
# 使用隔离 venv 中安装了 aioquic==1.3.0 的解释器：
python scripts/quic_handshake_aioquic_smoke.py
```

外部参考仅用于测试，不进入金匮运行时。参考脚本只使用本机回环，QUIC 参考的长度前缀
是测试载体，不是 QUIC 包格式。上述证明不等于 QUIC transport/HTTP3、全平台运行、
远端 CI、消费者迁移或发布完成。
