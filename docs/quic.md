# QUIC API 参考

## 枚举

- `ContractQuicVersion`: `V1`, `V2`
- `ContractQuicHpAlgorithm`: `Aes`, `ChaCha20`

## Salt 常量

### contractQuicInitialSaltV1(): Array<Byte>
QUIC v1 初始 salt（20 字节）。

### contractQuicInitialSaltV2(): Array<Byte>
QUIC v2 初始 salt（20 字节）。

## 初始密钥派生

### contractQuicDeriveInitialSecrets(connId, version): ContractQuicInitialSecrets
从 connection ID 和版本派生初始密钥 secret。

### contractQuicDeriveInitialKeyIv(connId, version): ContractQuicInitialKeyIv
从 connection ID 和版本派生初始密钥与 IV。

### contractQuicDeriveHpKey(connId, version): Array<Byte>
派生 Header Protection 密钥。

### contractQuicOneShotInitialKeyDerivation(connId, version): ContractQuicOneShotInitialKeys
一步完成初始密钥派生（包含 secret、key、IV、HP key）。

## AEAD 加解密

### contractQuicAeadEncrypt(key, iv, plaintext, aad, packetNumber): Array<Byte>
QUIC AEAD 加密（AES-128-GCM 或 ChaCha20-Poly1305）。

### contractQuicAeadDecrypt(key, iv, ciphertext, aad, packetNumber): Array<Byte>
QUIC AEAD 解密。

## Header Protection

### contractQuicApplyHeaderProtection(hpKey, packet, version, hpAlgorithm): Array<Byte>
应用或移除 Header Protection。

### contractQuicRemoveHeaderProtection(hpKey, protectedPacket, version, hpAlgorithm): Array<Byte>
移除 Header Protection。

## Retry 完整性

### contractQuicComputeRetryIntegrityTag(retryPseudoPacket, version): Array<Byte>
计算 QUIC Retry 完整性标签。

### contractQuicVerifyRetryIntegrityTag(retryPseudoPacket, tag, version): Bool
验证 Retry 完整性标签。
