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

`contractKemProfile()` 继续用于描述 provider 路由事实，但 JinguiSSL Core 当前没有
ML-KEM 或 hybrid PQC 实现。传统 RSA-KEM/ECDH-KEM 不具备后量子安全属性，也不
能被描述成 ML-KEM/Kyber。

当前证据是本地双方 roundtrip、输入边界与完整 309 项回归；不声明 PQC、外部 KEM
互操作或恒定时间认证。
