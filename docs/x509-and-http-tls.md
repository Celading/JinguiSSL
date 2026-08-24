# X.509、密钥容器与 HTTP/TLS Contract API

## 通用 X.509 摘要

- `contractX509ParseCertificatePem(...)`
- `contractX509ParseCertificateDer(...)`

两者返回 `ContractX509CertificateSummary`，包含 DER/PEM、serial、subject/issuer
CN、有效期、签名 OID、SAN DNS、EKU、policy OID、key usage 与 basic constraints。
它不是 Core `X509Certificate` 的公开别名。

## 公钥与私钥容器

- `contractX509ExtractRsaPublicKeyPem(...)`
- `contractX509ExtractEcPublicKeyPem(...)`
- `contractX509ParseRsaPrivateKeyPkcs1Pem(...)`
- `contractX509ParseRsaPrivateKeyPkcs8Pem(...)`
- `contractX509ParseEcPrivateKeyPkcs8Pem(...)`

返回值全部为 Contract-owned RSA/EC DTO。解析失败通过稳定
`ContractException` 映射，不向应用暴露 Core exception/type。

## 证书链、pin 与 HTTP/TLS

- `contractVerifyServerCertificatePem(...)`
- `contractVerifyServerCertificateChainPem(...)`
- `contractComputeLeafPinsFromPem(...)`
- `contractValidateHttpServerTlsConfigInput(...)`
- `contractPrepareHttpServerTlsMaterial(...)`
- `contractValidateHttpClientTlsConfigInput(...)`
- `contractPrepareHttpClientTlsTrustMaterial(...)`

这些入口覆盖显式 trust material、hostname/pin policy、证书/私钥匹配和 ALPN
标准化。它们不代表完整 WebPKI、原生系统信任库或浏览器级 HTTPS 已完成。

## 错误码与证据

- `VERIFY_FAILED`：证书验证、pin/hostname、公钥匹配或认证数据失败
- `BAD_INPUT`：编码、字段或参数无效
- `COMPLIANCE_REJECTED`：provider policy 拒绝

通用 parser/container 当前由证书 summary、SAN/policy、RSA PKCS#1/PKCS#8、EC
PKCS#8 和公钥匹配测试覆盖，并参与完整 309 项回归。
