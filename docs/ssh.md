# SSH Contract Protocol Facade

SSH 的推荐应用入口现在完整归属 `jinguissl.contract.*`：调用方不需要 deep-import
Core 构造 KEX prelude，也不会从 startup bundle 收到 `jinguissl.live` 类型。

## Prelude

- `contractSshBuildVersionBannerLine(...)`
- `contractSshBuildDefaultKexInitPayload(...)`
- `contractSshBuildKexEcdhInitX25519(...) -> ContractSshX25519ClientInit`
- `contractSshEncodeNewKeys()`

这些函数返回 wire bytes 或 Contract DTO，可直接填入
`ContractSshKexExchangeTranscript` 与 startup request。

## Bridge key adapters

需要保留 Bridge 既有 typed SSH 入口时，可使用
`contractBridgeSshEncode*HostPublicKey(...)`、
`contractBridgeSshSignExchangeHash*(...)` 和对应 handshake adapter。它们接受
Contract-owned RSA/EC key DTO、transcript 与 negotiated-algorithm DTO，使 Bridge
无需再导入 Core key 类型。较新的应用仍优先使用下方 startup bundle，它会把
握手结果与 runtime 包装为 Contract-owned 类型。

## 服务端启动

- `contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request(...)`
- `contractPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(...)`
- `contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(...)`

bundle 中的 `handshake` 是 `ContractSshServerHandshakeResult`，`runtime` 是
`ContractSshServerRuntime`。支持 RSA-SHA2、ECDSA P-256 与 Ed25519 host key 路径。

## 客户端启动与主机验证

`contractPrepareSshClientLibraryStartupX25519Request(...)` 接受
`ContractSshHostVerificationPolicy`。成功后：

```cangjie
let verification = bundle.handshake.requireHostVerification()
let sessionId = bundle.runtime.sessionId()
```

`ContractSshClientHandshakeResult`、`ContractSshHostVerificationResult` 与
`ContractSshClientRuntime` 均为 Contract-owned 类型。

## Caller-owned transport

server/client runtime 暴露：

- `seal(payload, randomPadding)` / `open(encodedPacket)`
- `sessionId()`、`writeSequence`、`readSequence`
- `resetTransportCounters()`

`open(...)` 返回 Contract-owned `ContractSshTransportPacket`。调用方仍负责 socket、
版本行/KEX 报文收发调度、用户认证、SSH channel semantics、超时、rekey policy 与
连接生命周期。

当前证据覆盖 RSA/ECDSA/Ed25519 host key startup、known-host/signature policy、
server→client 包保护 roundtrip、Contract-owned RSA host-signing adapter 与完整
318 项本地回归；不声明外部 OpenSSH
client/server 在线互操作完成。
