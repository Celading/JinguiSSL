# Handshake Interface Guide

## Goal

这份文档回答一个很具体的问题：

- 如果你不是要把 `jinguiSSL` 直接塞进某个现成框架；
- 而是想自己实现 HTTP/TLS 或 SSH 的接口握手层；
- 当前公开仓库里，哪些 contract 是稳定入口，哪些字节和状态应该由你自己的上层持有？

当前推荐稳定入口仍是：

```cangjie
import jinguissl.contract.*
```

## Boundary First

先固定三个边界：

1. `contractTls13BuildHttpClientHelloX25519(...)` 返回的是 `ClientHello` 握手报文，不是 socket-ready 首包。
2. 若你要把 TLS 首包直接写入 socket，必须再调用 `contractTlsEncodePlaintextRecord(...)`。
3. `contractTls13BuildHttpServerFlightX25519Request(...)` 与 `contractTls13VerifyHttpServerFlightX25519WithSessionRequest(...)` 当前公开的是 object-level server flight / verified-session contract，不是“任意抓到一段 socket bytes 就能自动还原”的 attach。
4. SSH 路径当前应直接消费 `jinguissl.contract.*` 的 handshake / runtime facade，而不是等待某条 `stdx.net.tls.TlsServerConfig` attach bridge。
5. SSH runtime 不是终点；若上层继续推进 rekey，应把新的 session-state / `NEWKEYS` 一起带入 `contractPrepareSsh*RuntimeRekeyFromSessionStateRequest(...)`。

这也意味着：

- HTTP client first-flight 是当前已经公开的 handshake 接口面；
- TLS response verify / verified-session 是当前已经公开的 object-level 续航接口面；
- HTTP server attach 仍只停在 `precheck + material preparation + planning`；
- SSH client/server library handshake 是当前已公开的稳定库面。

## A. TLS HTTP Client First Flight

当前最小可公开复用的 TLS 接口握手路径是：

1. 生成 `ClientHello`
2. 把握手报文封装成首条明文 TLS record
3. 将该 record 写入你自己的 socket / transport 层

最小代码形状：

```cangjie
let hello = contractTls13BuildHttpClientHelloX25519(
    "www.example.com",
    alpnProtocols: ["h2", "http/1.1"]
)
let firstRecord = contractTlsEncodePlaintextRecord(
    ContractTlsVersion.Tls12,
    ContractTlsRecordContentType.Handshake,
    hello.encodedClientHello
)
```

你自己的上层应保留：

- `serverName`
- `alpnProtocols`
- `hello.clientPrivateKey`
- `hello.clientPublicKey`
- `hello.encodedClientHello`
- `firstRecord`

其中职责边界是：

- `hello.encodedClientHello`
  - 适合进入 transcript / debug / fixture / hash / replay-cache 等逻辑
- `firstRecord`
  - 适合直接写 socket

当前不要做的事：

- 不要把 `encodedClientHello` 直接当作 wire-ready 首包
- 不要把这条 client first-flight helper 叙述成“公开稳定的 server attach”

现成例子：

- [`examples/ssh-library-consumption-smoke/`](../examples/ssh-library-consumption-smoke/)
- [`examples/handshake-interface-demo/`](../examples/handshake-interface-demo/)

## B. TLS Server Flight Verify And Runtime Continuation

如果你的上层已经能把服务端返回整理成 `ContractTls13HttpServerFlight`，当前公开 contract 已经支持：

1. 校验服务端 flight
2. 产出 `ContractTls13HttpClientVerifiedSession`
3. 把 verified session 转成 record channel / runtime
4. 继续处理 `KeyUpdate` 与 `close_notify`

最小代码形状：

```cangjie
let verifyRequest = ContractTls13HttpVerifyServerFlightX25519Request(
    clientHello,
    serverFlight,
    ContractHttpClientTlsTrustRequest(
        rootPem,
        intermediatesPemBundle: intermediatePem,
        hostname: "www.example.com",
        validationTime: "230101000000Z",
        policy: ContractTlsHttpNegotiationPolicy(
            requireServerName: true,
            allowedServerNames: ["www.example.com"],
            alpnPreference: ["h2", "http/1.1"]
        )
    )
)
let verifiedSession = contractTls13VerifyHttpServerFlightX25519WithSessionRequest(verifyRequest)
let runtime = contractTls13CreateVerifiedSessionChannelSetRequest(
    ContractTls13HttpVerifiedSessionRequest(verifiedSession)
)

let update = contractTls13RotateClientTrafficInVerifiedSessionRequest(
    ContractTls13HttpVerifiedSessionKeyUpdateRequest(
        verifiedSession,
        requestPeerUpdate: true
    )
)
let peerApplied = contractTls13ApplyPeerTrafficUpdateToVerifiedSessionRequest(
    ContractTls13HttpVerifiedSessionPeerKeyUpdateRequest(
        verifiedSession,
        update.encodedKeyUpdate
    )
)
```

你自己的上层应保留：

- `serverFlight.serverHello`
- `serverFlight.encryptedExtensions`
- `serverFlight.certificateHandshake`
- `serverFlight.certificateVerifyHandshake`
- `serverFlight.finishedHandshake`
- `verifiedSession`
- `runtime`
- `encodedKeyUpdate`

这里要特别诚实地区分两个层次：

- 当前已经稳定的是：
  - `ContractTls13HttpServerFlight` 级别的 verify / verified-session / channel
- 当前还没有公开成默认 attach 的是：
  - 从任意 socket 原始字节自动拼回 `ContractTls13HttpServerFlight`
  - 框架侧 server attach / listener attach

换句话说，当前 TLS response-side 的公开 contract 更适合：

- 你自己控制握手 orchestration；
- 或你已经有一层 adapter / bridge，负责把传输字节整理成 `serverFlight` 对象。

但当前不应该叙述成：

- “jinguiSSL 已经公开稳定提供默认 HTTPS server attach”

现成例子：

- [`examples/handshake-interface-demo/`](../examples/handshake-interface-demo/)

## C. HTTP Server Attach Planning

如果你的上层当前只需要把 HTTP server TLS 接到“planning / precheck / material preparation”这一步，
而不是把 listener attach 讲成已冻结公开契约，当前公开 contract 适合这样使用：

1. 校验 server cert / key / ALPN 输入
2. 准备标准化后的 PEM material，交给你自己的上层 glue 持有
3. 读取 provider consumption gate，明确这条路仍然只是 planning-only
4. 对 stable attach 继续 fail closed

最小代码形状：

```cangjie
let request = ContractHttpServerTlsConfigRequest(
    certChainPem,
    privateKeyPem,
    alpnProtocols: ["h2", "http/1.1"],
    requireHttp2Alpn: true
)
let validated = contractValidateHttpServerTlsConfigRequest(request)
let material = contractPrepareHttpServerTlsMaterialRequest(request)
let planningGate = contractRequireProviderConsumptionGate(
    ContractProviderConsumptionPath.HttpServerAttachPlanning
)
let stableAttach = contractTryRequireProviderConsumptionGate(
    ContractProviderConsumptionPath.HttpServerStableAttach
)
```

你自己的上层应保留：

- 原始 certificate/key source
- `validated.normalizedAlpnProtocols`
- `material.certificateChainPemBlocks`
- `material.privateKeyPem`
- `planningGate`
- 你自己的 attach-plan / provider-selection record

这里的边界也要写死：

- 当前公开稳定的是：
  - `contractValidateHttpServerTlsConfig*`
  - `contractPrepareHttpServerTlsMaterial*`
  - `HTTP_SERVER_ATTACH_PLANNING` gate
- 当前仍未公开稳定的是：
  - final listener attach
  - `stdx.net.tls.TlsServerConfig` direct bridge
  - “默认 HTTPS 已切到 jinguissl” 这种叙事

现成例子：

- [`examples/http-server-attach-planning-smoke/`](../examples/http-server-attach-planning-smoke/)

## D. SSH Library Handshake

当前公开仓库里，SSH 的推荐实现形状是：

1. 交换 banner
2. 交换并协商 `KEXINIT`
3. 构造 transcript
4. 由 client 生成 `KEX_ECDH_INIT`
5. 由 server 产出 `KEX_ECDH_REPLY + NEWKEYS`
6. 由 client 完成 host verification 并完成初始握手
7. 将 handshake result 转成 runtime bundle

最小代码形状：

```cangjie
let transcript = contractSshBuildKexExchangeTranscriptFromPrelude(
    clientBanner,
    serverBanner,
    clientKexInit,
    serverKexInit
)
let negotiated = contractSshNegotiateKexInit(clientKexInit, serverKexInit)
let initResult = contractSshBuildKexEcdhInitX25519(clientPrivateKey)

let serverHandshake = contractSshCompleteServerInitialHandshakeX25519Ed25519Request(
    ContractSshServerInitialHandshakeX25519Ed25519Request(
        transcript,
        serverPrivateKey,
        initResult.encodedInit,
        serverHostSeed,
        negotiated,
        contractSshEncodeNewKeys(),
        contractSshEncodeNewKeys()
    )
)

let clientHandshake = contractSshCompleteClientInitialHandshakeX25519Request(
    ContractSshClientInitialHandshakeX25519Request(
        transcript,
        clientPrivateKey,
        initResult.encodedInit,
        serverHandshake.encodedReply,
        negotiated,
        contractSshEncodeNewKeys(),
        contractSshEncodeNewKeys(),
        policy: ContractSshHostVerificationPolicy(
            negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
            expectedHostKeySha256: serverHandshake.hostKeySha256,
            requireKnownHost: true,
            requireHostSignature: true,
            requireVerifiedHost: true
        )
    )
)
```

握手完成后，再转成 runtime：

```cangjie
let serverRuntimeBundle = contractPrepareSshServerRuntimeRequest(
    ContractSshServerRuntimeRequest(serverHandshake)
)
let clientRuntimeBundle = contractPrepareSshClientRuntimeRequest(
    ContractSshClientRuntimeRequest(clientHandshake)
)
```

你自己的上层应保留：

- banner line
- encoded `KEXINIT`
- transcript
- negotiated algorithms
- `encodedInit`
- `encodedReply`
- `hostKeySha256`
- handshake result
- runtime bundle / session snapshot

当前推荐把这些对象分层持有：

- 原始字节
  - 适合日志、录包、协议 transcript
- handshake result
  - 适合把一次握手的结果交给 session / auth / policy 层
- runtime bundle
  - 适合进入真正的 transport data path

现成例子：

- [`examples/handshake-interface-demo/`](../examples/handshake-interface-demo/)

## E. SSH Runtime Rekey Continuation

SSH 路径里，runtime bundle 建好以后，并不意味着上层就可以把 rekey 重新降回“自己拼 transport state”。

当前公开 contract 的推荐续航方式是：

1. 上层继续持有当前 runtime bundle
2. 新一轮 KEX 结束后，把结果整理成 `ContractSshSessionState`
3. 把新的 `NEWKEYS` 和 session-state 一起喂给 request-style rekey facade
4. 用返回的新 runtime bundle 替换旧 runtime

最小代码形状：

```cangjie
let serverRekeyBundle = contractPrepareSshServerRuntimeRekeyFromSessionStateRequest(
    ContractSshServerRuntimeSessionRekeyRequest(
        serverRuntimeBundle.runtime,
        rekeyServerSession.session,
        contractSshEncodeNewKeys(),
        contractSshEncodeNewKeys()
    )
)
let clientRekeyBundle = contractPrepareSshClientRuntimeRekeyFromSessionStateRequest(
    ContractSshClientRuntimeSessionRekeyRequest(
        clientRuntimeBundle.runtime,
        rekeyClientSession,
        contractSshEncodeNewKeys(),
        contractSshEncodeNewKeys(),
        policy: ContractSshHostVerificationPolicy(
            negotiatedHostKeyAlgorithm: negotiated.serverHostKeyAlgorithm,
            expectedHostKeySha256: serverHandshake.hostKeySha256,
            requireKnownHost: true,
            requireHostSignature: true,
            requireVerifiedHost: true
        )
    )
)
```

你自己的上层应保留：

- 当前 runtime bundle
- 新一轮 transcript / `encodedInit` / `encodedReply`
- rekey 后新的 `ContractSshSessionState`
- rekey 使用的 `NEWKEYS`
- 新 runtime bundle

当前不要做的事：

- 不要在 runtime 已建立后，又回到 app/framework 层手工重建 packet protection state
- 不要把新的 `ContractSshSessionState` 丢掉，只保留一段日志或摘要

## Interface Ownership

如果你在自己的框架里对接 `jinguiSSL`，建议按下面的 ownership 切层：

| Layer | What you keep |
|------|------|
| interface / socket layer | outgoing TLS first record、incoming TLS response fragments、SSH packet framing、TLS alert / close_notify record |
| handshake orchestrator | transcript、negotiated algorithms、ephemeral keys、`ContractTls13HttpServerFlight`、host verification policy |
| session / runtime layer | `ContractTls13HttpClientVerifiedSession`、`ContractSsh*RuntimeBundle`、TLS channel state、session cache / exporter state |
| policy / observability | provider gate、fallback decision、错误码、指纹、session id、rekey / key-update trace |

这样做的好处是：

- 不需要深 import `jinguissl.crypto.*`
- 能把 wire bytes 和 contract state 分清
- 后续若 `core / contract / bridge` 继续分层，你的上层不会被内部实现细节绑死

## Common Mistakes

最常见的接错点有这些：

1. 把 `encodedClientHello` 当成可直接发送的 TLS record
2. 把 `ContractTls13HttpServerFlight` 级别的 verify surface 包装成“默认 HTTPS server attach 已稳定”
3. TLS verified session 已经创建出来，却没有把后续 `KeyUpdate` / `close_notify` 继续放在 runtime/channel 层处理
4. SSH client 完成握手后，没有把 `hostKeySha256` 和 verification result 一起进入 session 层
5. runtime 已经创建出来，却还继续靠旧的握手输入重建 transport 状态
6. app/framework 层直接 deep import `jinguissl.crypto.*`

## Example Reference

如果你要最快落地一条“自己实现 handshake 接口层”的最小路径，优先看：

1. [`examples/handshake-interface-demo/`](../examples/handshake-interface-demo/)
2. [`examples/ssh-library-consumption-smoke/`](../examples/ssh-library-consumption-smoke/)
3. [`INTEGRATION_GATE.md`](./INTEGRATION_GATE.md)
4. [`PROVIDER_CONTRACT.md`](./PROVIDER_CONTRACT.md)

## Structured ES256 Verify

如果你的上层已经自己完成了：

- `CBOR` 读取
- `COSE_Key` 解析
- WebAuthn `authenticatorData || clientDataHash` 等 ceremony 语义拼接

但还想把最窄的一段 `ES256 / P-256` 校验交给 `jinguiSSL`，当前可以直接使用一个明确标成 bridge-support 的低层 helper：

```cangjie
import jinguissl.crypto.ecc.*

let outcome = tryEs256P256VerifyStructuredRequest(
    Es256P256StructuredVerifyRequest(
        coseX,
        coseY,
        signedBytes,
        derSignature
    )
)
```

这里的边界要写死：

- 输入必须已经是结构化完成的 `x / y / signedBytes / derSignature`
- helper 内部只负责：
  - `P-256` 公钥点构造
  - `SHA-256`
  - DER ECDSA signature decode
  - verify
- helper 不负责：
  - `CBOR` bytes 解码
  - `COSE_Key` map 语义
  - attestation / assertion ceremony 判断

同时也不要把它讲成稳定 contract 扩容：

- 这条 helper 当前属于 `jinguissl.crypto.ecc.*`
- 它不是 `jinguissl.contract.*` 的稳定公开契约
- 更适合已经持有 parser / ceremony ownership 的 upper layer 用来减少签名校验胶水代码
