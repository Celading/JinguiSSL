# 国密（SM2/SM3/SM4）API 参考

## SM 能力探测

### contractSmCapability(): ContractSmCapability
报告 SM3 哈希和 SM4 分组密码的可用性。

| 字段 | 类型 | 说明 |
|------|------|------|
| `sm3Available` | Bool | SM3 可用 |
| `sm4Available` | Bool | SM4 可用 |
| `detail` | String | 算法描述 |
| `sm3DigestLen` | Int64 | SM3 摘要长度（32 字节） |
| `sm4BlockLen` | Int64 | SM4 分组长度（16 字节） |
| `sm4KeyLen` | Int64 | SM4 密钥长度（16 字节） |

```cangjie
let sm = contractSmCapability()
println("SM3: ${sm.sm3Available}, SM4: ${sm.sm4Available}")
```

### contractTrySmCapability(): ContractSmCapabilityOutcome
非抛出版本。

### contractRequireSmCapability(): ContractSmCapability
要求 SM3 和 SM4 都可用，不可用时抛出异常。

## SM3 哈希 (GM/T 0004-2012)

SM3 是中国国家密码管理局发布的密码杂凑算法，输出 32 字节摘要。在 JinguiSSL 中通过底层的 `jinguissl_core.crypto.sm3.sm3` 实现。

## SM4 分组密码 (GM/T 0002-2012)

SM4 是中国国家分组密码标准，分组长度 16 字节，密钥长度 16 字节。当前采用 ECB 模式。通过 `jinguissl_core.crypto.sm4` 模块实现。

## 标准与使用边界

SM3 和 SM4 对应公开的 GM/T 算法标准。JinguiSSL Core 提供本地实现，
Contract 当前只通过 capability probe 报告可用性和参数形状。
这不构成商用密码产品检测、监管认证、等保适配结论或完整操作 facade。
