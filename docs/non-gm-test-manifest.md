# Non-GM Contract Test Manifest

- Contract audit base: `af361d9f315379bb2d8b59af7d94213c0acf645f`
- Core provider: `cf27ef1807767ebd5155aa32eb467e6dce8ba144`
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
bash scripts/jinguissl_pre_review.sh af361d9f315379bb2d8b59af7d94213c0acf645f
```

## Focused Evidence

| Surface | Test suite / evidence | Positive path | Negative or boundary path |
| --- | --- | --- | --- |
| AES + CSPRNG | `ContractAesRandomTestSuite` (2) | FIPS 197 AES-128 block vector; GCM roundtrip; 32-byte CSPRNG | GCM tag tamper; zero-size random request |
| ECC / Ed25519 / RSA | `ContractAsymmetricTestSuite` (3) | P-256 ECDSA/ECDH; RFC 8032 seed/public shape; RSA PSS and PKCS#1 v1.5 | message tamper for all signature families |
| Traditional KEM + X.509 | `ContractKemX509GeneralTestSuite` (2) | RSA-KEM/ECDH-KEM roundtrip; certificate summary; RSA/EC containers | curve/provider and parser validation inherited from typed facade/Core tests |
| SSH preferred Contract path | `ContractSshStartupBundleTestSuite` (2) | RSA/ECDSA/Ed25519 host startup; known-host verification; packet seal/open | unsupported profile outcomes; no public Core/live result types |
| Public ownership | non-GM boundary gate + 4 Python regression tests | all 39 `src/contract` surface files scanned | synthetic Core/live public type leaks rejected; nine raw key/context/secret helpers sealed internal |
| Session state / opaque resumption | cache suite + secure resumption suite | Contract-owned store/load/remove plus opaque ticket roundtrip | local ticket wire use fails closed; replay, rotation, expiry and invalid input rejected |
| Regression | full CJPM suite | 314/314 passed | 0 skipped/error/failed |
| Standalone consumer | `examples/contract-application-smoke` | SHA-256, owned hash enum/session cache, AES, Ed25519, GM and QUIC through `jinguissl.contract.*` | explicit QUIC invalid-key rejection |

## Honest Limits

- AES context/native-handle APIs, raw RSA/EC operations, BigNum, DER internals,
  raw TLS handshake secrets, SSH wire codecs, live state-machine internals and
  benchmark hooks remain below the stable Contract surface.
- RSA-KEM and ECDH-KEM are traditional KEMs; no ML-KEM/hybrid PQC implementation exists.
- Generic non-GM DTLS is not present in Core and is not fabricated in Contract.
- Full-suite and standalone results describe the tested host only.
