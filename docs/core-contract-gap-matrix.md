# Core → Contract Capability Boundary

This matrix explains which non-GM Core capability belongs in the recommended
application facade and which surface intentionally remains below it.

| Family | Contract status | Boundary |
| --- | --- | --- |
| Digest / HMAC / HKDF | facade closed | Contract-owned `HashAlgorithm` and stable byte facade; raw contexts stay Core-only. |
| ChaCha20 / Poly1305 | already covered | Stream/MAC/AEAD facade; checked/context variants stay Core-only. |
| X25519 | already covered | Keypair/public/agreement facade; raw scalar multiplication stays Core-only. |
| AES | facade closed | ECB/CBC/CTR/GCM bytes; native handles, contexts and `into` paths stay Core-only. |
| ECC / Ed25519 / RSA | facade closed | Contract byte-key DTO and application sign/verify/agreement; BigNum/raw transform stay Core-only. |
| Traditional KEM | facade closed | RSA-KEM and P-256 ECDH-KEM; explicitly not ML-KEM/PQC. |
| General X.509 / key containers | facade closed | Summary and RSA/EC key DTO; raw ASN.1/DER objects stay Core-only. |
| CSPRNG | facade closed | Fail-closed output bytes; entropy backend internals stay Core-only. |
| SSH | facade closed | Contract prelude, handshake summary and opaque packet channel; socket/auth/channel scheduling remain caller-owned. |
| TLS session state | facade closed | Contract-owned version/identity/ticket/cache DTOs and operations; local cached secrets never become self-describing wire tickets. |
| TLS 1.3 opaque resumption | facade closed with limits | Single-process, bounded, single-use protected-ticket owner with SNI/ALPN/cipher/age/binder validation; no 0-RTT, HRR continuation, persistence or cross-process replay coordination. |
| TLS 1.2 / 1.3 handshake runtime | live-by-design / raw facade sealed | Caller-owned transport runtime stays in `jinguissl.live`; nine legacy helpers that exposed Core key/context/secret types are module-internal. Contract keeps only wire-byte helpers that do not export secrets. |
| QUIC | already covered | Packet protection only; no transport or HTTP/3 claim. |
| ML-KEM / hybrid PQC | provider gap | No Core implementation; Contract does not create placeholder operations. |
| Generic non-GM DTLS | need more evidence | No Core implementation; DTLCP remains a distinct GM protocol. |

Completeness is evaluated by application workflow and public type ownership,
not by mirroring every Core symbol. A facade is incomplete when an application
must deep-import Core/live to finish a supported workflow; it is not incomplete
merely because low-level math, wire or performance controls remain internal.
