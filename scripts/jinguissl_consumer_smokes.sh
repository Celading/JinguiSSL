#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
python3 scripts/jinguissl_consumer_dependency_gate.py
for sample in webauthn-crypto-smoke webdav-digest-smoke quic-crypto-smoke tls-client-smoke; do
  (
    cd "examples/$sample"
    cjpm build
    if [ "$sample" != tls-client-smoke ]; then cjpm run; fi
  )
done
