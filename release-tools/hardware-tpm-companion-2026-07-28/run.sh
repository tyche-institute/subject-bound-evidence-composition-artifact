#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

if [[ "${1:-}" == "--preflight" ]]; then
  exec python3 hardware_tpm_companion.py \
    --preflight \
    --corpus ../../masters-thesis-radar/research-factory-v4-2026-07-27/labs/composed-transaction-corpus/corpus.json \
    --capsule-sha256-file ../../capsule/tyche-second-host-source-capsule-2026-07-28.sha256 \
    --report preflight/preflight-report.json
fi

exec python3 hardware_tpm_companion.py \
  --corpus ../../masters-thesis-radar/research-factory-v4-2026-07-27/labs/composed-transaction-corpus/corpus.json \
  --capsule-sha256-file ../../capsule/tyche-second-host-source-capsule-2026-07-28.sha256 \
  "$@"
