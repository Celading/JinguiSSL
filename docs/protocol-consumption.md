# Protocol-library consumption

Depend directly on `jinguissl` and import `jinguissl.contract.*`. The dependency
on Core is transitive. The interfaces below are source additions; do not assume
an older registry archive contains them merely because a checkout has the same version.

| Need | Public interface | Caller retains |
| --- | --- | --- |
| BLAKE2s / keyed MAC | `contractBlake2s`, `ContractBlake2sContext` | Protocol labels, KDF composition and input framing |
| Extended-nonce AEAD | `contractHchacha20`, `contractXchacha20Poly1305Encrypt/Decrypt` | Unique nonces, cookie policy and anti-replay state |
| Reusable AES-GCM | `ContractAesGcmContext.encryptInto/decryptInto` | Distinct exact-sized output buffers and per-key nonce uniqueness |
| SSH byte stream | `contractSshOpenClientPacketStream`, `ContractSshPacketStream` | Version/KEX wire exchange and negotiation, packet counts, host trust, user authentication, channels and rekey scheduling |
| Non-HTTP TLS client | `ContractTls13StreamClient` | Socket, deadlines, ALPN policy and application protocol |
| Non-HTTP TLS server | `ContractTls13StreamServer` | Socket, deadlines, P-256 identity and application protocol |
| Raw QUIC handshake | `ContractTls13ClientEngine` | Encryption-level ordering, CRYPTO reassembly, packets, recovery and congestion |
| DTLS / SRTP secrets | `ContractDtlsIdentity`, `ContractDtlsSession`, `ContractDtlsSrtpSecrets` | Trusted peer fingerprint, UDP scheduling, RTP/SRTP policy and replay state |
| Digest / random / public-key verify | Existing digest, random, ECC and RSA facades | Protocol policy, ceremony/state validation and key trust |

## BLAKE2s and extended nonces

BLAKE2s follows [RFC 7693](https://www.rfc-editor.org/rfc/rfc7693).
`digestLength` (1..32) is part of the hash parameter block; a 16-byte digest is
not a truncated 32-byte digest. Empty key selects unkeyed hashing; protocol
code requiring a MAC must reject an empty key itself. Keys are at most 32 bytes.
The streaming owner is serialized, can be finalized once, and supports idempotent
`destroy()`. The output is an independent byte array.

HChaCha20 and the 24-byte-nonce AEAD follow
[draft-irtf-cfrg-xchacha-03](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03),
not a finalized IETF RFC. AEAD keys/tags are 32/16 bytes. Modified key, nonce,
AAD, ciphertext or tag fails verification. These functions do not implement
WireGuard, entropy generation, replay protection or a compliance certification.

## Reusable AES-GCM

```cangjie
let context = ContractAesGcmContext(key)
try {
    context.encryptInto(nonce, plaintext, ciphertextOut, tagOut, aad: aad)
    context.decryptInto(nonce, ciphertextOut, tagOut, plaintextOut, aad: aad)
} finally { context.destroy() }
```

Output payload length must equal input length. `tagOut` must equal `tagLen`
(4..16); prefer 16 except where a protocol requires another supported length.
Buffers must not overlap inputs, AAD, nonce or each other. No per-packet key
schedule is constructed. Authentication failure clears the destination.
Destroy clears owned mutable schedule arrays and revokes future operations;
managed/scalar copies do not have a physical-erasure guarantee. Use one serialized owner.

## SSH framing and sequence handoff

Prepare `ContractSshClientInitialHandshakeX25519Request` using the existing
Contract KEX/banner helpers. Then call `contractSshOpenClientPacketStream`
with explicit `sentPacketCount` and `receivedPacketCount`. Counts include all
binary messages before protection, including NEWKEYS and ignored messages,
but exclude the version banners. They must not reset at NEWKEYS.

The factory verifies the server signature and requested known-host policy before
installing keys. Supply a trusted fingerprint and `requireKnownHost: true` for
known-host enforcement; a valid signature alone does not establish host trust.
Use `receive(bytes)` for arbitrary fragmentation/coalescing and `seal(payload)`
for outgoing binary payloads. No keys, IVs or unauthenticated packet lengths are
exposed. Framing/authentication failure is terminal. `finishInput()` rejects
truncated EOF; `close()` revokes access. Rekey creates a new verified key state;
this interface does not implement strict-KEX or the SSH login/channel protocol.

## Generic TLS server

`ContractTls13StreamServer(chainPem, ecPkcs8Pem, alpnProtocols: ["mqtt"], requireAlpn: true)`
owns TLS framing, ephemeral exchange, certificate signing, Finished verification
and separate handshake/application record counters. No HTTP ALPN default applies.
An empty ALPN list with `requireAlpn: false` permits no ALPN without inventing a selection.

After every `receive`, drain `takeHandshakeOutput()` and transmit in order.
Only after `established` may application data be written. `established` proves
client Finished, **not client identity authentication**. Receive returns only
authenticated application fragments. Enforce transport deadlines externally.
EOF without close_notify is rejected; close/failure retires the session.

Current server scope: P-256 certificate/key matching, X25519, TLS 1.3 suites
0x1301/02/03. No client certificates, HRR, PSK, early data, tickets, KeyUpdate,
HTTP processing or complete private-key constant-time proof. It releases legacy
record/signer contexts without promising erasure of runtime or BigNum copies.

Tests: `ContractDownstreamSupplyTestSuite`, `ContractSshStreamTestSuite`,
`examples/tls-server-smoke` and `scripts/tls_server_openssl_smoke.py`.
Provider fixture tests and independent-peer tests are different evidence;
neither proves a downstream application has migrated.
