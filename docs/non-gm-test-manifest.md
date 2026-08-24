# Non-GM Contract Test Manifest

- Contract audit base: `6fb9615ca60c742fbc2b3e9898429b7da531019f`
- Core provider: `6ea5d25060412ac0b7f2915b0cc740dcd4f4c132`
- Runtime: Cangjie / CJPM
- Scope: application-level non-GM Core capabilities newly closed in Contract

This manifest records replayable local evidence. It is not an external
certification, constant-time proof, cross-platform certification, or online
interoperability result.

## Replay

```bash
cjpm build
cjpm test
python3 scripts/jinguissl_non_gm_contract_boundary_gate.py
python3 scripts/jinguissl_non_gm_contract_boundary_gate_test.py
bash scripts/jinguissl_pre_review.sh 6fb9615ca60c742fbc2b3e9898429b7da531019f
```

## Focused Evidence

| Surface | Test suite / evidence | Positive path | Negative or boundary path |
| --- | --- | --- | --- |
| AES + CSPRNG | `ContractAesRandomTestSuite` (2) | FIPS 197 AES-128 block vector; GCM roundtrip; 32-byte CSPRNG | GCM tag tamper; zero-size random request |
| ECC / Ed25519 / RSA | `ContractAsymmetricTestSuite` (3) | P-256 ECDSA/ECDH; RFC 8032 seed/public shape; RSA PSS and PKCS#1 v1.5 | message tamper for all signature families |
| Traditional KEM + X.509 | `ContractKemX509GeneralTestSuite` (2) | RSA-KEM/ECDH-KEM roundtrip; certificate summary; RSA/EC containers | curve/provider and parser validation inherited from typed facade/Core tests |
| SSH preferred Contract path | `ContractSshStartupBundleTestSuite` (2) | RSA/ECDSA/Ed25519 host startup; known-host verification; packet seal/open | unsupported profile outcomes; no public Core/live result types |
| Public ownership | non-GM boundary gate + 4 Python regression tests | seven preferred surface files scanned | synthetic Core/live public type leaks rejected |
| Regression | full CJPM suite | 309/309 passed | 0 skipped/error/failed |
| Standalone consumer | `examples/contract-application-smoke` | SHA-256, AES, Ed25519, GM and QUIC through `jinguissl.contract.*` | explicit QUIC invalid-key rejection |

## Honest Limits

- AES context/native-handle APIs, raw RSA/EC operations, BigNum, DER internals,
  SSH wire codecs, live state-machine internals and benchmark hooks remain Core-only.
- RSA-KEM and ECDH-KEM are traditional KEMs; no ML-KEM/hybrid PQC implementation exists.
- Generic non-GM DTLS is not present in Core and is not fabricated in Contract.
- Full-suite and standalone results describe the tested host only.
