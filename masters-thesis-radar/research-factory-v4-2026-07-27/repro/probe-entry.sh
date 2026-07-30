#!/usr/bin/env bash
# SECONDARY sensitivity probe driver — NOT part of the pinned reproduction.
#
# Runs only the laboratory that consumes NumPy (composed-transaction-corpus,
# via the SAFE measurement module in the v3 factory) and prints the bootstrap
# lower bounds plus the hash of the two substantive result files, so a change
# in the third decimal of any LCB is visible directly and as a hash break.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8
export TZ=UTC

SRC=/work
DST=/scratch
LABS="$DST/masters-thesis-radar/research-factory-v4-2026-07-27/labs"

cp -a "$SRC"/. "$DST"/
chmod -R u+rwX "$DST"

python - <<'PY'
import numpy
print(f"PROBE-NUMPY {numpy.__version__}")
PY

# The composed verifier needs the authority evaluator's module only, not its
# results, so the single entry point below is sufficient for the measurement
# layer. sha256sum -c inside run.sh is self-referential and is not the check.
bash "$LABS/composed-transaction-corpus/run.sh" >/dev/null

python - "$LABS/composed-transaction-corpus/results/verdicts.jsonl" <<'PY'
import json, sys
seen = {}
for line in open(sys.argv[1], encoding="utf-8"):
    item = json.loads(line)
    m = item["measurement"]
    seen.setdefault(
        m["fixture_id"],
        (m["point_estimate"], m["lcb"], m["threshold"],
         item["layer_results"]["measurement"]),
    )
for fid in sorted(seen):
    point, lcb, thr, res = seen[fid]
    print(f"PROBE-LCB {fid} point={point!r} lcb={lcb!r} "
          f"threshold={thr!r} result={res}")
PY

(
  cd "$LABS/composed-transaction-corpus/results"
  for f in verdicts.jsonl summary.json; do
    printf 'PROBE-HASH %s\n' "$(sha256sum "$f")"
  done
)
