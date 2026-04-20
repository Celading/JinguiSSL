# HTTP Server Attach Planning Smoke

This example is a focused consumer-side smoke for the current published `HTTP_SERVER_ATTACH_PLANNING` path.

It intentionally combines four facts in one runnable example:

- the current server-side public path stops at `precheck + material preparation + planning`
- `HTTP_SERVER_ATTACH_PLANNING` is published, but `HTTP_SERVER_STABLE_ATTACH` is still fail-closed
- upper layers may normalize and hold TLS material now, while final listener attach remains outside this repo
- stable fallback guidance still points back to upper-layer `stdx-default` style integration

It does not open listeners and it does not claim stable HTTP server attach.

## Run

```bash
cjpm run
```

## Output

The program prints:

- the current planning gate status, selected entry, attach boundary, and blocked stable-attach result
- validated HTTP server TLS config facts such as chain length, key algorithm, and normalized ALPN
- prepared server material facts such as PEM block count and leaf certificate availability
- deterministic precheck failure outputs for missing `h2` ALPN and certificate/key mismatch

## Notes

- This example is intentionally narrower than `examples/handshake-interface-demo/`; it is for planning-only server attach evidence, not full handshake orchestration.
- The example keeps the current public boundary honest: `jinguissl` may publish planning metadata here, but final listener attach still belongs to upper-layer glue.
- A blocked stable-attach outcome is part of the expected output, not a regression.
