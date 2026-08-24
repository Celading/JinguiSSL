# GM Contract Test Manifest

这份清单公开 C203 国密 Contract 的本地验收面。它描述可重放测试，不把本地结果写成
外部互操作、商密检测或监管认证。

## Test surface

| Test suite | Cases | Covered surface |
|:--|--:|:--|
| `ContractGmPrimitivesTestSuite` | 6 | SM3/HMAC/KDF、SM4 七模式/AEAD/MAC、SM2、GM DRBG |
| `ContractSm9TestSuite` | 3 | 签名/配对、身份加密、认证密钥交换 |
| `ContractGmX509TestSuite` | 3 | SPKI/SEC1/PKCS#8、CSR、签发/链/CRL |
| `ContractRfc8998TestSuite` | 3 | hello、两套 SM4 suite record、SM2 CertificateVerify |
| `ContractTlcpTestSuite` | 5 | 双证书、静态 ECC、ECDHE、DTLCP replay/fragment/flight |

合计 20 个 C203 新增用例。负向门禁覆盖 AEAD/证书/CRL/record 篡改、身份错配、
DTLCP replay、逆向 epoch、未完成重组和 retransmission exhaustion。

## Replay

```bash
cjpm build
cjpm test --filter ContractGmPrimitivesTestSuite
cjpm test --filter ContractSm9TestSuite
cjpm test --filter ContractGmX509TestSuite
cjpm test --filter ContractRfc8998TestSuite
cjpm test --filter ContractTlcpTestSuite
python3 scripts/jinguissl_gm_contract_boundary_gate.py
python3 scripts/jinguissl_gm_contract_boundary_gate_test.py
bash scripts/jinguissl_pre_review.sh <base-ref>
```

最后一条同时运行公开审计、托管依赖图/锁检查、能力清单、完整 `cjpm build/test` 和
standalone application consumer。CI 或 Release 附件中的执行日志才是对应提交的结果凭据；
本清单本身不伪装成动态结果。
