# DTLS 1.2 consumer API

Import only `jinguissl.contract.*`. The standalone `examples/dtls-consumer`
declares only `jinguissl`; Core is a transitive implementation dependency.

1. Import a P-256 PKCS#8 PEM key and matching DER certificate through
   `ContractDtlsIdentity`, or call `generate(commonName, notBefore, notAfter)`.
   Validity strings use the existing X.509 UTC-time representation.
2. Obtain the remote certificate's SHA-256 fingerprint through authenticated
   signaling. Pass 64 hex characters without separators. This API verifies that
   certificate and private-key proof; it does not perform PKIX/hostname validation.
3. Create `ContractDtlsSession(role, identity, fingerprint, endpointBinding)`.
   Bind it to one demultiplexed UDP peer. The binding is a canonical, nonempty
   endpoint identifier of at most 64 bytes, supplied by the transport owner.
4. Call `start(monotonicMs)`, `receive(datagram, monotonicMs)`, and
   `onTimeout(monotonicMs)` from the transport event loop. Call `onTimeout` at
   least every 200 ms while negotiating. Drain `takeOutput()` after every event;
   send each returned array as one UDP datagram, preserving order. Retransmission
   begins at one second and is bounded. `receive` returns application plaintext,
   never handshake secrets. Invalid MACs and replayed application records drop.
5. Only after `authenticated`, call `exportSrtp()`. Its destroyable snapshot
   exposes client/server write keys and salts in **protocol role direction**.
   Getter results are independent caller-owned copies. Destroy the snapshot and
   wipe caller copies when finished. Destroying an identity does not close
   sessions already created from it; closing a session does not wipe snapshots
   already exported to the caller.
6. `sealApplicationData` returns a single DTLS record. Drain pending handshake
   output first and respect the transport MTU. The 16 KiB maximum is a protocol
   limit, not a recommendation for UDP packet size. `closeNotify()` queues an
   authenticated closing alert after pending output and retires session secrets;
   drain it even when `isClosed`. `close()` immediately retires locally.

Supported: DTLS 1.2; X25519 key exchange; P-256 ECDSA SHA-256 identity;
AES-128-GCM records (`0xc02b`); mandatory extended master secret; SRTP profile
7 (`SRTP_AEAD_AES_128_GCM`, 16-byte keys/12-byte salts) and profile 1
(`SRTP_AES128_CM_SHA1_80`, 16-byte keys/14-byte salts). The server requires client
certificate proof; a client sends its proof when the server requests it.

Not included: DTLS 1.3, PSK, resumption, renegotiation, CID, RTP/SRTP packet
processing, replay policy for RTP, SCTP, SDP, ICE or socket scheduling. Those
remain consumer responsibilities. Memory wiping is best-effort in the managed
runtime, not a guarantee that compiler/BigNum temporaries disappear physically.

The example is an ephemeral-secret diagnostic for independent OpenSSL tests,
not a production CLI: it deliberately prints exporter material when requested.
Never send production identities or traffic through that diagnostic.
