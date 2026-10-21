# TLS 1.3 客户端 wire-flight 读取合同

以下入口使用同一消息重组和密文认证逻辑：

- `contractTryTls13OpenHttpClientRuntimeFromWireDerivedServerFlight`
- `contractTryTls13OpenHttpClientRuntimeFromProtectedServerFlight`
- `contractTryTls13OpenHttpClientVerifiedSessionRuntimeFromIncrementalServerFlight`

TLS record 的数量与握手消息数量不同。握手消息可合并或分片；读取方应继续提供累积的完整握手记录，直到结果为 `ok=true` 且 `status=Completed`。`NeedMoreBytes` 不能作为认证成功。合法 CCS 可以出现在 ServerHello 前后，但不能打断一个正在跨 record 组装的消息。CCS 不占用加密序号，也不进入握手转录。

这些入口是无状态的收集结果适配器。未完成时需要保留先前收到的完整记录及部分 record，下一次提供累积输入；仅传最后一条 record 或丢弃已有记录会丢失上下文。`pendingBytes` 表示收集器的部分 record，并不是可单独恢复整个握手的状态。拥有持续字节流的集成也可选择 `ContractTls13StreamClient`。

当前 wire-flight 适配器处理 ServerHello、EncryptedExtensions、Certificate、CertificateVerify、Finished。需要初始 CertificateRequest 或更完整流式会话管理时使用 `ContractTls13StreamClient`，不要删除认证步骤以绕过不支持的消息。

单条握手消息体上限 1 MiB，受保护握手总明文上限 4 MiB，输入 flight 上限 4096 条 record。超过上限返回失败；Finished 必须结束在 record 边界。`recordsObserved` 是输入记录数，`decodedProtectedRecordCount` 是实际解密记录数。

对于完成后已预读的后续记录，调用者应保留并转交应用/会话层；这些函数不接管 socket，也不消费后续字节流。证书、主机名、ALPN、pinning 和握手签名校验失败时不会返回可用会话。不要通过关闭验证来适配一个无法认证的服务端。

独立互操作示例：从仓库构建 `examples/tls-wire-client-smoke`，再在仓库根执行 `python3 scripts/tls_wire_client_openssl_smoke.py`。它仅启动本机 TLS 对端，不访问外部网络；使用测试证书验证兼容 CCS、Finished 及双向应用数据。

协议依据：[TLS 1.3 record 层](https://www.rfc-editor.org/rfc/rfc8446#section-5.1)。
