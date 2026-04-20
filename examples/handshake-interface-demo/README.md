# Handshake Interface Demo

This example shows the two public handshake-interface shapes that are easiest for integrators to consume today:

- TLS HTTP client first-flight
- TLS server-flight verify followed by verified session / key-update / close-notify runtime handling
- SSH library handshake followed by runtime creation and session-state rekey

It does not open sockets and it does not claim stable HTTP server attach.

## Run

```bash
cjpm run
```

## Output

The program prints:

- TLS `ClientHello` length and the first plaintext TLS record length
- TLS server-flight fragment lengths, verified ALPN / chain result, runtime round-trip, key-update continuation, and `close_notify`
- the X25519 client public key used for the TLS first flight
- SSH banner / KEX algorithm / host key algorithm
- SSH session id and host key fingerprint
- a transport round-trip payload after the SSH runtime bundle is created
- a second transport round-trip payload after SSH session-state rekey updates the runtime bundle

## Notes

- The TLS path intentionally demonstrates that `encodedClientHello` is not wire-ready until you wrap it with `contractTlsEncodePlaintextRecord(...)`.
- The TLS response-side path intentionally stays at `ContractTls13HttpServerFlight` / verified-session / channel-set level; raw response framing still belongs to your adapter.
- The SSH path intentionally keeps all orchestration inside `jinguissl.contract.*` so upper layers do not need to deep import `jinguissl.crypto.*`.
- The SSH rekey path intentionally replaces the runtime bundle from request-style session-state rekey output instead of mutating packet protection state outside the contract layer.
