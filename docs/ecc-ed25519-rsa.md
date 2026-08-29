# ECC / Ed25519 / RSA Contract API

本页描述 `jinguissl.contract.*` 的应用级非国密非对称密码入口。公开面只使用
Contract DTO、枚举和 `Array<Byte>`；`BigNum`、Core key、raw transform 与 native
handle 不属于 Contract API。

## ECC / ECDSA / ECDH

`ContractEcCurve` 支持 `P256`、`P384`、`P521` 与 `Secp256k1`。公钥采用未压缩
SEC1 编码，私钥采用固定曲线宽度的大端字节，ECDSA 签名采用固定宽度 `r || s`。

```cangjie
let alice = contractEcGenerateKeyPair(ContractEcCurve.P256)
let bob = contractEcGenerateKeyPair(ContractEcCurve.P256)
let signature = contractEcdsaSign(
    ContractEcCurve.P256,
    alice.privateKey,
    "message".toArray()
)
let verified = contractEcdsaVerify(alice.publicKey, "message".toArray(), signature)
let sharedA = contractEcdh(ContractEcCurve.P256, alice.privateKey, bob.publicKey)
let sharedB = contractEcdh(ContractEcCurve.P256, bob.privateKey, alice.publicKey)
```

`contractEs256VerifyDer(...)` 为 P-256/SHA-256 的 DER 签名验证入口。Capability
probe (`contractEccCapability`) 仍保留，用于启动期参数与 policy 查询。

`contractEcdsaSignDigest(...)` 与 `contractEcdsaVerifyDigest(...)` 是供 FFI 和协议
adapter 使用的显式预哈希边界：调用方传入与 `ContractSignatureHash` 长度一致的
digest，Contract 不会再次哈希。普通应用消息仍应优先使用 message-level 入口，
避免误把原文当成 digest。

## Ed25519

```cangjie
let keyPair = contractEd25519GenerateKeyPair()
let signature = contractEd25519Sign(keyPair.privateKeySeed, "message".toArray())
let verified = contractEd25519Verify(
    keyPair.publicKey,
    "message".toArray(),
    signature
)
```

种子与公钥均为 32 字节，签名为 64 字节。也可用
`contractEd25519PublicFromSeed(...)` 从已有种子派生公钥。

## RSA

`ContractRsaPublicKey` 和 `ContractRsaPrivateKey` 使用大端字节字段。密钥可通过
`contractRsaGenerateKeyPair(...)` 生成，或由 X.509/key-container facade 导入。

```cangjie
let privateKey = contractX509ParseRsaPrivateKeyPkcs8Pem(pem)
let signature = contractRsaSign(
    privateKey,
    "message".toArray(),
    scheme: ContractRsaSignatureScheme.Pss,
    hashAlgorithm: ContractSignatureHash.Sha256
)
let verified = contractRsaVerify(
    privateKey.publicKey,
    "message".toArray(),
    signature
)
```

支持 message-level RSA-PSS 与 PKCS#1 v1.5 sign/verify。`saltLen = -1` 交由 Core
使用其默认策略；应用需要固定策略时应显式传入。Contract 不公开 raw private
transform、CRT 参数或自定义 padding primitive。PSS 是默认方案；PKCS#1 v1.5
仅用于既有协议/数据兼容。

## 证据与边界

当前证据包括 P-256 message/pre-hashed 签名/篡改/ECDH、本地 RSA
PSS/PKCS#1 v1.5、RSA SSH host-signing adapter、RFC 8032 Ed25519
seed/public-key shape 与完整 318 项回归。它们继承 Core 私钥路径的时序
边界，不构成恒定时间、安全认证、HSM 托管或外部密码栈互操作声明。
