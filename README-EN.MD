# jinguiSSL

`jinguiSSL` is a pure Cangjie SSL/TLS and cryptography library. The current delivery priority is library capability for HTTP / SSH integrations, following a BoringSSL-style capability roadmap while keeping native Cangjie APIs first.

Recommended public integration entry:

```cangjie
import jinguissl.contract.*
```

## Status

- Release line: `0.6.21`
- Maturity: `pre-1.0`
- Package type: `static` Cangjie library
- Public integration surface: `jinguissl.contract.*`
- Current focus: complete the library features required by HTTPS / SSH, not application binaries

The repository currently provides crypto primitives, certificate handling, TLS/SSH facades, and validation helpers. It does not ship an HTTP framework, SSH client suite, or tunnel application.

## Capability Snapshot

- Symmetric crypto: AES-GCM, ChaCha20-Poly1305
- Digest and derivation: SHA-256, SHA-384, HKDF
- Randomness: CSPRNG availability probing and random byte generation
- Asymmetric crypto: RSA, ECDHE (P-256 / P-384), X25519, ECDSA, Ed25519
- X.509: PEM / DER parsing, chain verification, hostname verification, simplified pinning APIs
- TLS: TLS 1.2 / TLS 1.3 handshake foundations, record layer, session ticket / cache, key update, exporter
- SSH: X25519 KEX, host verification, host key fingerprint, and transport-protection-facing contract helpers

## Naming

- Human-facing project name: `jinguiSSL`
- `cjpm` package name: `jinguissl`
- Import root: `jinguissl.*`
- Recommended stable import:

```cangjie
import jinguissl.contract.*
```

External projects should avoid depending deeply on `jinguissl.crypto.*` unless they accept internal API movement during the `0.x` line.

## Public Repository Surface

- Source: `src/`
- Tests: `src/jinguissl/tests/`
- Test vectors and fixtures: `testdata/`
- Public examples: `examples/phase1-demo/` and `examples/handshake-interface-demo/`
- Public docs: `docs/`
- Public packaging helper: `tools/cjpm_bundle_finish.sh`
- Public packaging audit helper: `tools/cjpm_bundle_audit.sh`

The following directories are mainly local collaboration, reference, or experimental areas and are not part of the public release contract:

- `_helper/`
- `bridges/`
- `benchmarks/`

## Build And Validate

```bash
cjpm build
cjpm test
```

Run them serially. Running `cjpm build` and `cjpm test` in parallel can race on the shared `target/` directory and create false failures.

## Packaging Note

On the current Cangjie toolchain, native `cjpm bundle` may still crash during a known SHA256 indexing step after a valid artifact has already been produced. This repository provides a finishing script:

```bash
./tools/cjpm_bundle_finish.sh
./tools/cjpm_bundle_audit.sh
```

The script runs `cjpm bundle`, detects the known post-artifact crash pattern, and generates the final `sha256` plus manifest for a valid `.cjp`.

`tools/cjpm_bundle_audit.sh` then verifies that:

- the `.cjp` archive is readable and contains the core public files
- the `.sha256` file matches the actual artifact
- the bundle manifest is consistent with the artifact, checksum, and known toolchain crash markers

## Documentation

- Index: `docs/README.md`
- API boundary: `docs/API_BOUNDARY.md`
- HTTP / SSH capability matrix: `docs/CAPABILITY_MATRIX.md`
- Provider contract: `docs/PROVIDER_CONTRACT.md`
- SSH facade: `docs/SSH_FACADE.md`
- Integration gate: `docs/INTEGRATION_GATE.md`
- Handshake interface guide: `docs/HANDSHAKE_INTERFACE_GUIDE.md`
- Packaging audit: `docs/PACKAGING_AUDIT.md`

## Versioning

`0.6.21` reflects that the library is well beyond the phase-1 skeleton, but not yet at a 1.0 stability promise. During the `0.x` line, the `contract` facade is intended to stay comparatively stable, while internal `crypto.*` implementation details may keep evolving.

## License

`Apache-2.0`
