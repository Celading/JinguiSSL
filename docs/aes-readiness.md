# AES Contract API 与后端探测

## 应用操作面

`ContractAesMode` 提供 `AesEcb`、`AesCbc` 与 `AesCtr`。CBC/CTR 的 `parameter`
为 16 字节 IV/counter；ECB 不使用该字段。ECB/CBC 可通过 `pkcs7` 显式控制填充。

```cangjie
let ciphertext = contractAesEncrypt(
    ContractAesMode.AesCbc,
    key,
    plaintext,
    parameter: iv,
    pkcs7: true
)
let recovered = contractAesDecrypt(
    ContractAesMode.AesCbc,
    key,
    ciphertext,
    parameter: iv,
    pkcs7: true
)
```

AEAD 使用独立入口：

- `contractAesGcmEncrypt(...) -> ContractAesGcmResult`
- `contractAesGcmDecrypt(...) -> Array<Byte>`

认证标签失败会归一化为 `VERIFY_FAILED`。Contract 不公开 Core context、`into`
缓冲区、AES-NI/ARMv8 native handle 或 benchmark hook。

## 后端探测

- `contractAesListHardwareMountPoints()`
- `contractAesProbeHardware(...)`
- `contractResolveAesEngine(...)`
- `contractAesStartupSelfCheck(...)`
- `contractRequireAesAcceleratedBackend(...)`

`ContractAesEngineKind` 包含 `Auto`、`Software`、`Hardware`；readiness 结果描述
当前宿主代码路径，不构成硬件加速、恒定时间或生产安全认证。

当前证明包括 FIPS 197 AES-128 block vector、GCM roundtrip/篡改拒绝、后端解析
测试与完整 309 项回归。
