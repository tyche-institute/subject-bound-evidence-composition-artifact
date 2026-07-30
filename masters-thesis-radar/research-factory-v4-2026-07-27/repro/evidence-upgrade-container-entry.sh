#!/usr/bin/env bash
# Re-execute the current composed corpus and the evidence-upgrade laboratories
# inside the pinned offline reproduction image.  The host trees are mounted
# read-only and copied to a writable tmpfs before execution.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8
export TZ=UTC

src=/work
dst=/scratch
v4="$dst/masters-thesis-radar/research-factory-v4-2026-07-27"
zeus="$dst/zeus-followup-2026-07-27"

echo "===== ENVIRONMENT ====="
python -VV
python - <<'PY'
import json, platform, sqlite3, sys
import cryptography, numpy
print(json.dumps({
    "platform": platform.platform(),
    "python": sys.version.replace("\n", " "),
    "sqlite": sqlite3.sqlite_version,
    "numpy": numpy.__version__,
    "cryptography": cryptography.__version__,
}, sort_keys=True))
PY

echo "===== NETWORK ISOLATION ====="
echo "interfaces=$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f ' | sed 's/ $//')"
echo "routes:"
cat /proc/net/route
python - <<'PY'
import errno, socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("1.1.1.1", 443))
except OSError as exc:
    print(
        "outbound_connect=FAILED "
        f"errno={exc.errno} name={errno.errorcode.get(exc.errno, exc.errno)}"
    )
else:
    raise SystemExit("network isolation failed: outbound connect succeeded")
finally:
    s.close()
PY

echo "===== STAGE READ-ONLY INPUTS INTO TMPFS ====="
cp -a "$src"/. "$dst"/
chmod -R u+rwX "$dst"

echo "===== CURRENT 104-TRANSACTION COMPOSITION ====="
bash "$v4/labs/composed-transaction-corpus/run.sh" >/dev/null
python - "$v4/labs/composed-transaction-corpus/results/summary.json" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))
keys = (
    "transactions",
    "allows",
    "denies",
    "baseline_false_allows",
)
result = {key: item[key] for key in keys}
result["binding_gate_counts"] = item["binding_stage"]["binding_gate_counts"]
result["all_five_pass_but_denied"] = item["binding_stage"][
    "cross_layer_denials"
]
print(json.dumps(result, sort_keys=True))
PY

echo "===== NATIVE SIGNED AUTHORITY ADAPTER ====="
native="$zeus/native-signed-authority-adapters"
(
  cd "$native"
  python build_fixtures.py >/dev/null
  python verify_fixtures.py >/dev/null
  python compare_results.py >/dev/null
)
python - "$native/comparison-results.json" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))
keys = (
    "cases",
    "exact_verdict_and_gate",
    "mismatch_count",
    "fixtures_sha256",
    "verifier_sha256",
)
print(json.dumps({key: item[key] for key in keys}, sort_keys=True))
PY

echo "===== SINGLE-FAULT MUTATION CORPUS ====="
single="$zeus/thesis-v4-mutation-tests"
python "$single/evaluate_mutation_corpus.py" >/dev/null
python "$single/compare_mutations.py" >/dev/null
python - "$single/comparison-results.json" <<'PY'
import json, sys
item = json.load(open(sys.argv[1], encoding="utf-8"))
keys = (
    "transactions",
    "single_fault_cases",
    "oracle_exact_verdict_and_gate",
    "oracle_total",
    "js_python_layer_field_agreement",
    "js_python_layer_field_total",
    "mismatch_count",
)
print(json.dumps({key: item[key] for key in keys}, sort_keys=True))
PY

echo "===== MULTI-FAULT MUTATION CORPUS ====="
multi="$zeus/thesis-v4-multifault-tests"
python "$multi/run_python.py" >/dev/null
python - "$multi" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
py = {
    row["transaction_id"]: row
    for row in json.loads((root / "python-results.json").read_text())
}
js = {
    row["transaction_id"]: row
    for row in json.loads((root / "js-results.json").read_text())
}
assert py.keys() == js.keys(), "container/frozen implementation id sets differ"
for transaction_id in py:
    for field in ("verdict", "first_rejecting_gate"):
        assert py[transaction_id][field] == js[transaction_id][field], (
            transaction_id,
            field,
        )
py_layers = {
    row["transaction_id"]: row["layers"]
    for row in json.loads((root / "python-layer-results.json").read_text())
}
js_layers = {
    row["transaction_id"]: row["layers"]
    for row in json.loads((root / "js-layer-results.json").read_text())
}
for transaction_id in py_layers:
    for layer in ("policy", "evidence", "state", "authority", "measurement"):
        for field in ("result", "gate", "rule"):
            assert (
                py_layers[transaction_id][layer][field]
                == js_layers[transaction_id][layer][field]
            ), (transaction_id, layer, field)
print(json.dumps({
    "cases": len(py),
    "container_python_matches_frozen_javascript": len(py),
}, sort_keys=True))
PY

echo "===== PROSPECTIVE SIGNED REVOCATION RACES ====="
revocation="$v4/labs/prospective-revocation-races"
(
  cd "$revocation"
  python build_corpus.py >/dev/null
  python run.py >/dev/null
)
python - "$revocation" <<'PY'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
py = json.loads((root / "python-results.json").read_text())
js = json.loads((root / "js-results.json").read_text())
assert py == js, "container Python rows differ from frozen JavaScript rows"
strict = sum(
    row["verdict"] == row["expected_verdict"]
    and row["first_rejecting_gate"] == row["expected_gate"]
    for row in py
)
print(json.dumps({
    "cases": len(py),
    "strict_exact_verdict_and_gate": strict,
    "container_python_equals_frozen_javascript": len(py),
}, sort_keys=True))
PY

echo "===== REGENERATED HASHES ====="
sha256sum \
  "$v4/labs/composed-transaction-corpus/corpus.json" \
  "$native/fixtures.json" \
  "$single/python-results.json" \
  "$multi/python-results.json" \
  "$revocation/corpus.json" \
  "$revocation/python-results.json"

echo "===== DONE ====="
