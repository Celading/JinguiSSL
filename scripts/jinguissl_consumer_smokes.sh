#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/jinguissl_consumer_dependency_gate.py
for sample in webauthn-crypto-smoke webdav-digest-smoke quic-crypto-smoke protocol-crypto-smoke tls-client-smoke tls-server-smoke dtls-consumer; do
  (
    cd "examples/$sample"
    cjpm build -j1
    if [ "$sample" != tls-client-smoke ] && [ "$sample" != tls-server-smoke ] && [ "$sample" != dtls-consumer ]; then cjpm run; fi
  )
done
