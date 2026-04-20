# HTTP Client Consumption Smoke

This example is a focused consumer-side smoke for the current published `HTTP_CLIENT_TLS` path.

It intentionally combines four facts in one runnable example:

- the current path is still `provider-candidate`, not default HTTPS
- the preferred stable fallback target remains `stdx-default`
- the wire-ready first flight is `ClientHello -> plaintext TLS record`
- the response-side stable contract stays at `serverFlight -> verifiedSession -> runtime`

It does not open sockets and it does not claim stable HTTP server attach.

## Run

```bash
cjpm run
```

## Output

The program prints:

- the current HTTP client provider gate status, selected entry, release path, and observability tags
- the current provider-candidate smoke profile and readiness facts
- fallback guidance for provider-unavailable, verify-error, and consumed-connection handshake failure paths
- TLS `ClientHello` length, plaintext record length, verified-session result, key-update continuation, and `close_notify`

## Notes

- This example is intentionally narrower than `examples/handshake-interface-demo/`; it is for HTTP client gate/fallback/runtime evidence only.
- `encodedClientHello` is still not wire-ready by itself; the example keeps `contractTlsEncodePlaintextRecord(...)` explicit.
- Verified-session continuation is demonstrated at `jinguissl.contract.*` object/runtime level; raw response framing still belongs to your adapter.
- The example keeps the current public boundary honest: `jinguissl` may be attempted through provider selection here, but it is not being presented as the default HTTPS path.
