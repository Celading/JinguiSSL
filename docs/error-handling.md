# 错误处理指南

JinguiSSL 使用分层错误模型，兼顾精确性和应用友好度。

## 错误模型

```
ContractException
  ├── code: ContractErrorCode    → 应用层可读的错误分类
  └── message: String            → 人类可读的描述

ContractIgniteCryptoErrorCode    → 保留的下游兼容错误码
  ├── BadEnvelope
  ├── KeyNotFound
  ├── DecryptFailed
  └── CryptoUnavailable
```

## ContractErrorCode 分类

| 枚举值 | toString | 含义 |
|--------|----------|------|
| `BadInput` | `BAD_INPUT` | 输入参数无效（长度、格式、空值） |
| `KeyNotFound` | `KEY_NOT_FOUND` | 密钥/证书未找到 |
| `VerifyFailed` | `VERIFY_FAILED` | 验证失败（证书、签名、pin） |
| `CryptoUnavailable` | `CRYPTO_UNAVAILABLE` | 密码模块不可用 |
| `ComplianceRejected` | `COMPLIANCE_REJECTED` | 合规检查拒绝 |
| `Unsupported` | `UNSUPPORTED` | 不支持的操作/后端/档案 |
| `InternalError` | `INTERNAL_ERROR` | 内部错误 |

## 错误映射

`contractMapToIgniteCryptoErrorCode(code)` 是保留的兼容 API，用于把
contract 错误码映射到较窄的下游错误集合：

| ContractErrorCode | 兼容映射 |
|------------------|-------------|
| `BadInput` | `BadEnvelope` |
| `KeyNotFound` | `KeyNotFound` |
| `VerifyFailed` | `DecryptFailed` |
| `CryptoUnavailable` | `CryptoUnavailable` |
| 其他 | `CryptoUnavailable` |

## 推荐实践

1. **使用 `contractTry*` 变体**：大多数函数都有 `try` 版本，返回 `Outcome` 类型，
   可优雅处理错误而无需 try-catch。

2. **优先检查 `code`**：`igniteCode` 是兼容字段，新代码不应让它取代 Contract 自己的错误语义。

3. **Provider Gate 错误描述**：高风险操作（证书验证、TLS 握手）使用
   `contractDescribeProviderErrorCode` 获取带阶段的错误描述。
