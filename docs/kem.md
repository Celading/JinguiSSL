# Traditional KEM Contract API

## 已实现

Contract 提供传统 RSA-KEM 与 P-256 ECDH-KEM 的 byte/DTO facade：

- `contractRsaKemEncapsulate(...)` / `contractRsaKemDecapsulate(...)`
- `contractEcdhKemEncapsulate(...)` / `contractEcdhKemDecapsulate(...)`
- `ContractKemEncapsulation`：`encapsulatedKey` 与 `sharedSecret`

```cangjie
let result = contractRsaKemEncapsulate(
    recipientPublicKey,
    sharedSecretLen: 32,
    info: "context".toArray()
)
let secret = contractRsaKemDecapsulate(
    recipientPrivateKey,
    result.encapsulatedKey,
    sharedSecretLen: 32,
    info: "context".toArray()
)
```

双方必须使用相同的 `sharedSecretLen` 与 `info`。ECDH-KEM 当前由 Core 的 P-256
实现支撑；其他 Contract 曲线传入该入口会被底层约束拒绝。

## ML-KEM 边界

`contractKemProfile()` 的 `available` 仅描述 `algoHint` 中列出的传统算法：
`rsa-kem,p256-ecdh-kem`。探测显式检查默认算法策略中的 RSA-KEM 与 ECDH-KEM；
这不是运行时自检、合规认证或外部设备探测。ML-KEM 和 hybrid PQC 均未实现。
传统 RSA-KEM/ECDH-KEM 不具备后量子安全属性，不能被描述成 ML-KEM/Kyber。

当前证据是本地双方 roundtrip、输入边界与完整 309 项回归；不声明 PQC、外部 KEM
互操作或恒定时间认证。
