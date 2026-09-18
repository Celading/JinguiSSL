# Experimental TLCP provider contract v1

Use only `import jinguissl.contract.*`. `examples/tlcp-consumer` has a single direct
JinguiSSL dependency and demonstrates the complete client/server event loop.
The implementation uses Cangjie at runtime, with no native crypto backend.

## Public application surface

- `ContractTlcpIdentity`: matching signing/encryption SM2 keys and certificates,
  owned copies, certificate snapshot and idempotent `destroy()`.
- `ContractTlcpProviderPolicy`: suite allowlist, handshake timeout (1–120000 ms),
  client authentication requirement and explicit unsupported-feature refusals.
- `ContractTlcpSession`: `start`, `receive`, `takeOutput`, `onTimeout`,
  `handshakeComplete`, `peerAuthenticated`, `sealApplicationData`, certificate/suite
  snapshots, `closeNotify`, `endOfInput` and `close`.
- `contractTlcpProviderCapabilities()`, `contractTlcpProviderDescriptor()` and
  `contractTlcpProviderDescriptorSha256()`: versioned availability and exact UTF-8
  descriptor digest. A successful capability probe is not a ready connection.

Construct the session with explicit trusted PEM anchors and validation time.
Clients must set `expectedPeerDnsName`. It checks both peer certificates against
the trust policy. The session copies the identity; destroy caller key buffers and
the original identity after construction when no longer needed. Existing session
copies remain valid until retired/closed.

Call `start(nowMs)`, send drained output records in order, then feed at most 65536
bytes per `receive(bytes, nowMs)` call. Drain output after every event and before
application writes. Tick `onTimeout(nowMs)` even while idle. Use a monotonic clock,
not wall-clock time. Never hand raw record-layer constructors to an HTTP consumer.

`handshakeComplete` requires verified Finished. `peerAuthenticated` additionally
means peer credentials were verified. ECDHE requires dual client credentials;
static ECC permits an unauthenticated client unless the server sets
`requireClientCertificate: true`. Require that policy for mutual authentication.

`closeNotify()` queues the close alert and retires local keys; drain it before
closing the socket. Feed transport EOF through `endOfInput()` to detect truncation.
`close()` aborts locally and is idempotent. The caller owns sockets, scheduling,
timeouts, application protocol selection and connection-pool eviction.

## Refusals and limits

`ContractTlcpProviderRefusal.reason` is a stable provider category. Unsupported
configuration reports `unsupported-alpn`, `unsupported-http2`,
`unsupported-resumption` or `unsupported-certification`. Invalid policy/clock,
timeout, certificate/signature/Finished verification failure, bad record MAC,
truncation and closed-session reuse have distinct reasons. `alertDescription` is
a suggested mapping, not confirmation of transmission. Malformed identity inputs
use `ContractException`; no Core types are required by the public API.

There is no ALPN, HTTP/2, resumption, renegotiation, early data, automatic fallback,
HTTP parser or certification. HTTP/1.1 must be selected explicitly by the caller,
without pretending it was negotiated. Destruction is best-effort for owned byte
buffers, not managed arithmetic temporaries or caller copies. No complete erasure
or constant-time claim is made.

## Proof and replay

The independent counterpart is unmodified official openHiTLS commit
`586d8aa6e8581a23a202d107e0e2af8087c18829`. A test-only adapter uses its public API;
OpenSSL 3 generates independent CA/dual-certificate fixtures. The local macOS arm64
STS 1.1.3 Contract-only consumer passed eight combinations: client/server × suites
`E011/E013/E051/E053`, mutual certificate verification and bidirectional data.
This does not claim hosted CI, external negative tests, DTLCP interoperability,
Ignite integration or production certification.

With matching fixed-source Core and Contract checkouts, build the Core reference
adapter as documented in `docs/guide/tlcp-provider.md`, then:

```sh
(cd examples/tlcp-consumer && cjpm build -j1)
python3 ../core/scripts/tlcp_openhitls_interop.py \
  --binary examples/tlcp-consumer/target/release/bin/main \
  --reference ../core/reference-openhitls/build/tlcp-reference-peer --openssl openssl
```

The example's direct dependency is only JinguiSSL. A review source pin is not a
central-registry publication; do not assume an older registry package contains
these new APIs merely because its package version matches.
