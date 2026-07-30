#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(dirname "$here")
v4="$root/masters-thesis-radar/research-factory-v4-2026-07-27"
evidence=${1:?usage: run_public_tree_on_runner.sh EVIDENCE_DIRECTORY}
mkdir -p "$evidence"
export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8
export TZ=UTC

python3 "$here/collect_public_environment.py" \
  --phase before-execution \
  --output "$evidence/environment.json"

(
  cd "$v4/labs/policy-version-evidence-replay"
  ./run.sh
) 2>&1 | tee "$evidence/policy-replay.log"

(
  cd "$v4/labs/composed-transaction-corpus"
  ./run.sh
) 2>&1 | tee "$evidence/composed-corpus.log"

(
  cd "$v4/labs/cross-ecosystem-typed-transfer"
  python3 build_transfer.py
  python3 verify_crosswalk_sql.py
  sha256sum -c SHA256SUMS
) 2>&1 | tee "$evidence/typed-transfer.log"

(
  cd "$v4/labs/distributed-revocation-service"
  ./run.sh
) 2>&1 | tee "$evidence/durable-revocation.log"

python3 "$here/assert_public_semantics.py" \
  --v4 "$v4" \
  --output "$evidence/semantic-contract.json"

(
  cd "$v4"
  sha256sum \
    labs/policy-version-evidence-replay/results/summary.json \
    labs/composed-transaction-corpus/results/summary.json \
    labs/cross-ecosystem-typed-transfer/results.json \
    labs/distributed-revocation-service/results.json
) >"$evidence/result-sha256.txt"

printf '%s\n' \
  'Execution boundary: one job VM or local OS instance; no physical-host identity.' \
  >"$evidence/CLAIM-BOUNDARY.txt"

(
  cd "$evidence"
  sha256sum \
    environment.json \
    semantic-contract.json \
    result-sha256.txt \
    CLAIM-BOUNDARY.txt \
    >EVIDENCE-SHA256SUMS
  sha256sum -c EVIDENCE-SHA256SUMS
)
