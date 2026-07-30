# SSH 启动捆绑包 API 参考

## 类型

### ContractSshKexExchangeTranscript
KEX 交互记录：`clientBannerLine`, `serverBannerLine`, `clientKexInitPayload`, `serverKexInitPayload`。

### ContractSshNegotiatedAlgorithms
已协商的 SSH 算法：kex、host key、encryption、MAC、compression。

### ContractSshHostVerificationPolicy
主机验证策略：`negotiatedHostKeyAlgorithm`, `expectedHostKeySha256`, `requireKnownHost`, `requireHostSignature`, `requireVerifiedHost`。

## 服务端函数

### contractPrepareSshServerLibraryStartupX25519RsaPkcs8Request(request): ContractSshServerLibraryStartupBundle
准备使用 RSA PKCS#8 主机密钥的 SSH 服务端启动 bundle。

### contractPrepareSshServerLibraryStartupX25519EcdsaPkcs8Request(request): ContractSshServerLibraryStartupBundle
准备使用 ECDSA PKCS#8 主机密钥的服务端启动 bundle。

### contractPrepareSshServerLibraryStartupX25519Ed25519SeedRequest(request): ContractSshServerLibraryStartupBundle
准备使用 Ed25519 种子密钥的服务端启动 bundle。

## 客户端函数

### contractPrepareSshClientLibraryStartupX25519Request(request): ContractSshClientLibraryStartupBundle
准备 X25519 SSH 客户端启动 bundle，包含主机验证策略。

### contractTryPrepareSshServerLibraryStartupX25519RsaPkcs8Request(request): ContractSshServerLibraryStartupOutcome
### contractTryPrepareSshClientLibraryStartupX25519Request(request): ContractSshClientLibraryStartupOutcome
非抛出错误处理变体。

## 错误处理

使用 `profile` 不匹配时抛出 `UNSUPPORTED`。调用方可通过 `contractTry*` 变体显式处理失败。

这些接口整理启动输入、协商结果与主机验证策略，不声明外部 SSH client/server
互操作或完整用户会话实现。
