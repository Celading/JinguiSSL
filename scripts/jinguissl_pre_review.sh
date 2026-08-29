#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
base_ref="${1:-}"

cd "${root}"

bash scripts/jinguissl_ci_audit.sh public .
bash scripts/jinguissl_ci_audit.sh hosted-graph .
bash scripts/jinguissl_ci_audit.sh dependency-lock .

capability_args=(--check --root .)
if [ -n "${base_ref}" ]; then
  capability_args+=(--base-ref "${base_ref}")
fi
python3 scripts/jinguissl_capability_gate.py "${capability_args[@]}"
python3 scripts/jinguissl_capability_gate_test.py
python3 scripts/jinguissl_gm_contract_boundary_gate.py
python3 scripts/jinguissl_gm_contract_boundary_gate_test.py
python3 scripts/jinguissl_non_gm_contract_boundary_gate.py
python3 scripts/jinguissl_non_gm_contract_boundary_gate_test.py

cjpm build
cjpm test

pushd examples/contract-application-smoke >/dev/null
cjpm build
cjpm run
popd >/dev/null
