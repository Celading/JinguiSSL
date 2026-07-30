# KEM Profile API 参考

## 当前定位

`contractKemProfile()` 当前是 KEM profile placeholder，用于报告可用性、算法提示和
路由信息。它不是 ML-KEM 实现，也不是后量子安全产品接口。

Core 中存在传统 RSA-KEM 与 ECDH-KEM 支撑，但这两类传统构件不具备 ML-KEM 的
后量子安全属性。ML-KEM 已标准化；JinguiSSL 当前的缺口是尚未实现、验证和暴露
ML-KEM，而不是“标准仍未确定”。

### contractKemProfile(): ContractKemProfile

| 字段 | 类型 | 说明 |
|------|------|------|
| `available` | Bool | 当前 profile 是否报告可用 |
| `algoHint` | String | 算法或后续路由提示 |
| `detail` | String | 当前实现边界说明 |

```cangjie
let kem = contractKemProfile()
println("KEM available: ${kem.available}")
println("Hint: ${kem.algoHint}")
```

### contractTryKemProfile(): ContractKemProfileOutcome

非抛出版本，返回 profile 查询结果。

## 不能据此宣称

- 已实现 ML-KEM/Kyber
- 已完成 PQC 互操作
- 当前 TLS/QUIC 已使用混合后量子 key share
- RSA-KEM/ECDH-KEM 等同于量子安全 KEM
