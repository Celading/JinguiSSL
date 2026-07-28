# QUIC API 参考

## Salt 常量

- `QUIC_SALT_V1: Array<Byte>` — QUIC v1 初始 salt（20 字节），常量
- `QUIC_SALT_V2: Array<Byte>` — QUIC v2 初始 salt（20 字节），常量

## 初始密钥派生

### contractQuicInitialSecrets(connId: Array<Byte>, isV2: Bool): (Array<Byte>, Array<Byte>)
从 connection ID 派生初始 secret，返回 `(clientSecret, serverSecret)` 元组，各 32 字节。

### contractQuicInitialKeyIv(secret: Array<Byte>, isV2: Bool): (Array<Byte>, Array<Byte>)
从 32 字节 traffic secret 派生密钥与 IV，返回 `(key, iv)` 元组。

### contractQuicInitialHpKey(secret: Array<Byte>, isV2: Bool): Array<Byte>
从 32 字节 traffic secret 派生 Header Protection 密钥（16 字节）。

### contractQuicInitialKeyDerive(connId: Array<Byte>, isV2: Bool): (Array<Byte>, Array<Byte>, Array<Byte>)
一步完成初始密钥派生，返回 `(key, iv, hpKey)` 元组。

## AEAD 加解密

### contractQuicAeadEncrypt(key: Array<Byte>, iv: Array<Byte>, pn: Int64, plaintext: Array<Byte>, aad: Array<Byte>): Array<Byte>
QUIC AEAD 加密（AES-128-GCM 或 ChaCha20-Poly1305，根据 key 长度自动选择）。
返回 `ciphertext || tag`（共 plaintext.size + 16 字节）。

### contractQuicAeadDecrypt(key: Array<Byte>, iv: Array<Byte>, pn: Int64, ciphertextWithTag: Array<Byte>, aad: Array<Byte>): Array<Byte>
QUIC AEAD 解密。`ciphertextWithTag` 为 wire 格式的 `ciphertext || tag`。
解密失败抛出 `Exception`。

## Header Protection

### contractQuicHpAesEncrypt(sample: Array<Byte>, key: Array<Byte>): (Byte, Array<Byte>)
AES-based Header Protection mask（RFC 9001 §5.4.1）。
`sample` 为 16 字节采样数据，`key` 为 16 字节 HP key。
返回 `(firstByteMask, pnMask)` 其中 `pnMask` 为 15 字节。

### contractQuicHpChaChaEncrypt(sample: Array<Byte>, key: Array<Byte>): (Byte, Array<Byte>)
ChaCha20-based Header Protection mask（RFC 9001 §5.4.2）。
`sample` 为 16 字节（前 4 字节 counter LE，后 12 字节 nonce），`key` 为 32 字节。
返回 `(firstByteMask, pnMask)` 其中 `pnMask` 为 4 字节。

## Retry 完整性

### contractQuicRetryIntegrityTag(retryPacket: Array<Byte>, origDestConnId: Array<Byte>, isV2: Bool): Array<Byte>
计算 QUIC Retry Integrity Tag（16 字节）。
`retryPacket` 不含末尾 16 字节 tag，`origDestConnId` 为客户端 Initial 中的 Original Destination Connection ID。

### contractQuicVerifyRetryIntegrity(retryPacketWithTag: Array<Byte>, origDestConnId: Array<Byte>, isV2: Bool): Bool
验证 Retry Integrity Tag。`retryPacketWithTag` 包含末尾 16 字节 tag。
