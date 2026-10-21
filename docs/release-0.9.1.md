# 0.9.1

修复 TLS 1.3 客户端 wire-derived、protected-flight 和 incremental 入口的握手分帧：

- 支持一条 record 内合并多个握手消息，以及消息头和消息体跨 record 分片。
- 忽略合法兼容 CCS；拒绝在消息分片中插入 CCS、非法消息顺序、超长消息及 Finished 后同 record 残留字节。
- 增量入口认证实际接收密文，拒绝与传入握手对象不一致的内容。
- 保留证书链、主机名、ALPN、pinning、CertificateVerify 和 Finished 验证；扩展不再靠固定字节候选猜测，仍拒绝重复、未请求或位置不合法的扩展。

正式依赖 `jinguissl_core = "0.9.1"`；Core 本次只更新供给版本，算法实现不变。
接口签名保持兼容。调用者应依照完成状态读取，不应固定等待五条 record。
具体大小、读取与能力边界见 [TLS 1.3 分帧合同](tls13-wire-client.md)。

验证覆盖库级回归和本机独立 OpenSSL 对端。应用接入、设备下载、特征库及扫描验收不包含在本库发布结论中。
