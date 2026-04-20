# SSH Library Consumption Smoke

This example is a focused consumer-side smoke for the current published `SSH_CLIENT_LIBRARY` and `SSH_SERVER_LIBRARY` paths.

It intentionally combines four facts in one runnable example:

- both SSH paths are published as stable `library-contract` surfaces
- the recommended consumer entry remains `jinguissl.contract.*`, not deep `crypto.ssh` imports
- server/client startup bundles can carry handshake, host verification, and runtime state without any `stdx` TLS attach glue
- a known-host fingerprint mismatch should fail closed during client startup instead of silently downgrading

It does not open sockets, and it does not claim built-in `ssh.Client`, daemon, channel, or subsystem orchestration.

## Run

```bash
cjpm run
```

## Output

The program prints:

- the current SSH client/server library gate status, release path, selected entry, and observability tags
- the current SSH startup profile labels for client and server library consumers
- a deterministic server/client startup and runtime smoke, including verified host identity and bidirectional protected payload flow
- a deterministic negative case where a wrong known-host fingerprint fails closed through the client startup outcome

## Notes

- This example is intentionally narrower than `examples/handshake-interface-demo/`; it is for SSH library gate/startup/runtime evidence only.
- The example keeps the current public boundary honest: SSH is a stable direct-library contract here, not an HTTPS/provider attach story.
- Session/channel/subsystem orchestration still belongs to your upper layer or neighboring SSH adapter library.
