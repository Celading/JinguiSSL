# 国密与国密协议 Contract

JinguiSSL Contract 为应用提供纯仓颉运行时的国密 facade。公开 API 使用
`jinguissl.contract.*` 下的 DTO、固定字节编码和不透明状态对象，不要求应用依赖
Core 的大数、曲线点、证书或 record 类型。

## 能力范围

| 族 | Contract 入口 | 本地证据 |
|:--|:--|:--|
| SM3 | `contractSm3`、`contractHmacSm3`、`contractSm3Kdf` | published vector、长度与边界 |
| SM4 | `contractSm4Encrypt/Decrypt`、`contractSm4AeadEncrypt/Decrypt`、CMAC/CBC-MAC | ECB vector、七种模式、GCM/CCM 篡改拒绝 |
| SM2 | key pair、ZA、sign/verify、encrypt/decrypt、ECDH、双方确认协商 | published vector、roundtrip 与 confirmation |
| GM DRBG | `ContractSm3HashDrbg`、`ContractSm4CtrDrbg` | generate/reseed/uninstantiate 生命周期 |
| SM9 | KGC、用户私钥、签名、身份加密、配对、认证协商 | 双向确认与篡改拒绝 |
| GM X.509 | SPKI、SEC1、PKCS#8、CSR、证书签发/验证、CRL | 容器、身份绑定、链与吊销门禁 |
| RFC 8998 | curveSM2、SM4-GCM/CCM+SM3、Finished、record、CertificateVerify | 两套 cipher suite 的本地双端回放 |
| TLCP/DTLCP | hello、双证书、静态 ECC/ECDHE、record、epoch/replay/fragment/flight | 四套 suite 家族、重放与重组门禁 |

## SM3、SM4 与 SM2

```cangjie
import jinguissl.contract.*

main() {
    let digest = contractSm3("hello gm".toArray())
    let keyPair = contractSm2GenerateKeyPair()
    let identity = "1234567812345678".toArray()
    let signature = contractSm2Sign(keyPair.privateKey, identity, digest)
    println(contractSm2Verify(keyPair.publicKey, identity, digest, signature))

    let key = Array<Byte>(16, repeat: UInt8(1))
    let nonce = Array<Byte>(12, repeat: UInt8(2))
    let sealed = contractSm4AeadEncrypt(Gcm, key, nonce, "payload".toArray())
    let opened = contractSm4AeadDecrypt(Gcm, key, nonce, sealed.ciphertext, sealed.tag)
    println(String.fromUtf8(opened))
}
```

`ContractSm4Mode` 覆盖 ECB、CBC、CTR、CFB128、OFB、XTS 与 HCTR。
GCM/CCM 使用独立 AEAD API，避免把认证标签塞进普通分组模式返回值。XTS/HCTR
要求 32 字节组合密钥，并保持 Core 的输入约束。

SM2 私钥为 32 字节标量，公钥为 65 字节未压缩点，签名为固定 64 字节
`r || s`。这是一条明确的低层密钥材料边界；调用方仍须负责密钥封装、清除、权限和持久化。

## SM9

SM9 facade 分开签名主密钥与加密/协商主密钥。用户私钥 DTO 同时携带对应主公钥，
避免把 Core 曲线点泄到公开面。

```cangjie
let master = contractSm9GenerateEncryptionMasterKeyPair()
let identity = "alice@example.cn".toArray()
let user = contractSm9ExtractEncryptionUserPrivateKey(master.privateKey, identity)
let ciphertext = contractSm9Encrypt(master.publicKey, identity, "secret".toArray())
let plaintext = contractSm9Decrypt(user, identity, ciphertext)
```

`ContractSm9KeyExchangeState` 是不透明且有状态的。每个会话应独占一个实例，完成后不要复用。

## SM2 密钥容器、CSR、证书与 CRL

`contractGmSm2KeyContainers` 从 32 字节私钥生成并交叉约束：

- curveSM2 SubjectPublicKeyInfo DER/PEM；
- RFC 5915 SEC1 DER/PEM；
- 未加密 PKCS#8 DER/PEM。

`contractGmCreateCertificateRequest` 生成并自验 PKCS#10 CSR。
`contractGmCreateSelfSignedCertificate` 与 `contractGmIssueCertificate` 提供最小 SM2-with-SM3
根/叶签发面；`contractGmVerifyCertificateChainPem` 支持 trust anchor、intermediate、keyUsage、
validation time 与可选 CRL。

这些是本地 PKI 构件，不等同浏览器 WebPKI、系统信任库或证书产品认证。

## RFC 8998

推荐从 `contractRfc8998BuildHelloPair` 或分别构建 ClientHello/ServerHello 开始：

```cangjie
let hello = contractRfc8998BuildHelloPair(clientPublic, serverPublic)
let clientSecrets = contractRfc8998DeriveSecrets(
    clientPrivate, serverPublic, hello.transcriptHash, hello.selectedCipherSuite
)
let clientRecord = contractRfc8998CreateClientRecordLayer(clientSecrets)
```

支持注册值：

- `TLS_SM4_GCM_SM3` (`0x00c6`)；
- `TLS_SM4_CCM_SM3` (`0x00c7`)；
- `sm2sig_sm3` (`0x0708`)；
- `curveSM2` (`41`)。

`ContractRfc8998Secrets` 和 `ContractRfc8998RecordLayer` 是有状态、不透明对象，避免应用
手工重建 key schedule。应用仍负责 transport、handshake flight 调度、证书策略与超时。

## TLCP 与 DTLCP

TLCP facade 支持四个 suite：静态 ECC/ECDHE × SM4-CBC/GCM。典型流程为：

1. 构建并协商 TLCP hello；
2. 发送 signing leaf、encryption leaf 与 intermediates；
3. 验证双证书的不同 keyUsage 职责；
4. 运行静态 ECC 或 ECDHE ServerKeyExchange/ClientKeyExchange；
5. 派生不透明 `ContractTlcpSecrets`；
6. 验证 Finished，再创建 client/server record layer。

DTLCP 复用同一 secrets，并额外提供 epoch、64 包 anti-replay window、乱序接收、握手分片
重组和 caller-owned timer 的 flight retransmitter。网络 I/O、MTU 策略、timer 和会话调度仍由
调用方拥有。

## 能力探测

`contractSmCapability()` 保留为轻量启动探测，只证明 SM3/SM4 基线实现可调用。实际操作面
由本页列出的独立 facade 提供；探测成功不替代向量、协议和部署门禁。

## 安全与声明边界

- 当前实现与测试均由仓颉运行时执行；Contract 没有引入本地 FFI 或动态库依赖。
- 私钥算法继承 Core 的时序与内存清理边界。
- 本地 published-vector、双端 roundtrip 和 negative gate 不等同外部实现互操作认证。
- 不声明商用密码产品检测、监管认证、等保结论、完整恒定时间证明或公网协议服务完成。
