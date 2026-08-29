# TLS 会话缓存与安全恢复 API

本页覆盖两个不同层次：轻量的会话缓存，以及 TLS 1.3 server-owned opaque ticket 恢复门面。两者都由 JinguiSSL Contract 提供，应用不需要导入 `jinguissl_core.*`。

## ContractTlsSessionCache

`ContractTlsSessionCache(maxEntries, defaultTtlSeconds)` 创建有限容量缓存。`ContractTlsVersion`、`ContractTlsSessionIdentity` 和 `ContractTlsSessionTicket` 都是 Contract-owned 类型，不再要求调用方导入 Core。稳定面公开：

- `cache.size`：当前条目数；
- `cache.stats()`：返回 `ContractTlsSessionCacheStats`；
- `cache.store(ticket)`：存入 Contract-owned ticket；
- `cache.storeFromSecret(identity, secret, ...)`：创建并存入 ticket；
- `cache.load(identity, ...)`：读取未过期 ticket；
- `cache.remove(identity)`：移除 ticket；
- `cache.purgeExpired(...)`：清理过期 ticket；
- `cache.clear()`：清空条目并重置统计。

`maxEntries <= 0` 或非法 TTL 会抛出 `ContractException(BAD_INPUT, ...)`。

该缓存用于进程内保管恢复状态，不会把 `secret` 序列化成线上 ticket。为了兼容旧签名，`contractTls13BuildClientHelloPskFromSessionTicket(s)` 仍接受 Contract-owned ticket，但对这类本地缓存 ticket 会以 `UNSUPPORTED` 失败闭合；真实 TLS 1.3 恢复必须使用下方的 opaque ticket 路径。

旧的 `jinguissl.live` 中仍保留同名运行时类型以维持兼容；新应用应优先使用 `jinguissl.contract` 的稳定类型，并避免同时 wildcard 导入两个包。

## ContractTls13OpaqueTicketStore

这是安全敏感的单进程 TLS 1.3 ticket owner。线上 ticket 只是随机 lookup label；resumption PSK 保留在服务端 store，不会编码进 ticket。

```cangjie
import jinguissl.contract.*

let store = ContractTls13OpaqueTicketStore(maxEntries: 1024)
let encodedNewSessionTicket = store.issueNewSessionTicket(
    resumptionMasterSecret,
    "api.example.com",
    "h2",
    0x1301,
    nowUnixMilliseconds
)
```

客户端收到 NewSessionTicket 后创建 Contract-owned 本地状态，再构造与 ticket cipher 精确匹配的 X25519 PSK+DHE ClientHello：

```cangjie
let clientTicket = contractTls13CreateClientResumptionTicket(
    encodedNewSessionTicket,
    resumptionMasterSecret,
    "api.example.com",
    "h2",
    0x1301,
    receivedAtUnixMilliseconds
)
let resumed = contractTls13BuildClientHelloFromResumptionTicketX25519(
    clientTicket,
    nowUnixMilliseconds
)
let resumedClientHello = resumed.encodedClientHello
```

服务端验证 ticket、SNI/ALPN/cipher context、ticket age 和 binder，并在成功时原子地消费该条目：

```cangjie
let validated = store.validateAndConsumeClientHello(
    resumedClientHello,
    nowUnixMilliseconds
)
```

`validated.resumptionPsk` 只表示已验证的 PSK 输入。调用方仍必须结合 ClientHello key_share 和完整 transcript 完成 TLS 1.3 PSK+DHE key schedule；返回该对象不等于恢复握手已经完成。

## Rotation、expiry 与错误

- `store.rotate()` 清空所有未消费 ticket 并推进 generation；
- `store.purgeExpired(nowUnixMilliseconds)` 移除过期条目并返回数量；
- 非法参数映射为 `BAD_INPUT`；
- unknown、replayed、rotated、context mismatch、age mismatch 或 binder failure 映射为 `VERIFY_FAILED`；
- 0-RTT ticket 被拒绝。

## 明确边界

- store 是单进程、有界、内存内 owner；调用方必须串行访问同一实例；
- 不声明持久化或跨进程 replay 协调；
- 不支持 HelloRetryRequest 后的 binder transcript continuation；
- 0-RTT 保持关闭；
- ticket/PSK 是敏感材料，日志与诊断输出不得打印其内容。
