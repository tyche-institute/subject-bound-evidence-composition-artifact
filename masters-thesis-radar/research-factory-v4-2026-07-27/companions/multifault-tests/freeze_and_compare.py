#!/usr/bin/env python3
"""Freeze multifault outputs, then compare them to the separate oracle."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SINGLE = HERE.parent / "mutation-tests"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


files = {
    "multifault-packet.json": HERE / "multifault-packet.json",
    "generation-manifest.json": HERE / "generation-manifest.json",
    "run_js.mjs": HERE / "run_js.mjs",
    "run_python.py": HERE / "run_python.py",
    "js-results.json": HERE / "js-results.json",
    "js-layer-results.json": HERE / "js-layer-results.json",
    "python-results.json": HERE / "python-results.json",
    "python-layer-results.json": HERE / "python-layer-results.json",
    "frozen-js-evaluator": SINGLE / "evaluate_mutation_corpus.mjs",
    "frozen-python-evaluator": SINGLE / "evaluate_mutation_corpus.py",
}
for name, path in files.items():
    if not path.is_file():
        raise RuntimeError(f"freeze input missing: {name}")
freeze = {
    "freeze_id": "native-multifault-preoracle-v1",
    "frozen_at": datetime.now(timezone.utc).isoformat(),
    "oracle_read_by_evaluators": False,
    "files": {name: sha256(path) for name, path in files.items()},
}
(HERE / "PREORACLE-FREEZE.json").write_text(
    json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)


def read(name: str) -> Any:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


oracle = {row["transaction_id"]: row for row in read("multifault-oracle.json")}
js = {row["transaction_id"]: row for row in read("js-layer-results.json")}
python = {row["transaction_id"]: row for row in read("python-layer-results.json")}
if set(oracle) != set(js) or set(oracle) != set(python):
    raise RuntimeError("transaction ID sets differ")

mismatches = []
for transaction_id in sorted(oracle):
    expected = oracle[transaction_id]
    observed = {
        "js_verdict": js[transaction_id]["verdict"],
        "js_gate": js[transaction_id]["first_rejecting_gate"],
        "python_verdict": python[transaction_id]["verdict"],
        "python_gate": python[transaction_id]["first_rejecting_gate"],
    }
    if not (
        observed["js_verdict"] == expected["expected_verdict"]
        and observed["python_verdict"] == expected["expected_verdict"]
        and observed["js_gate"] == expected["expected_first_rejecting_gate"]
        and observed["python_gate"] == expected["expected_first_rejecting_gate"]
    ):
        mismatches.append(
            {
                "transaction_id": transaction_id,
                "expected": expected,
                "observed": observed,
            }
        )

layer_total = 0
layer_agreement = 0
for transaction_id in sorted(oracle):
    for layer in ("policy", "evidence", "state", "authority", "measurement"):
        for field in ("result", "gate", "rule"):
            layer_total += 1
            if js[transaction_id]["layers"][layer][field] == python[transaction_id][
                "layers"
            ][layer][field]:
                layer_agreement += 1

result = {
    "corpus_id": "native-multifault-composition-v1",
    "cases": len(oracle),
    "fault_count_min": min(row["fault_count"] for row in oracle.values()),
    "fault_count_max": max(row["fault_count"] for row in oracle.values()),
    "exact_verdict_and_first_gate": len(oracle) - len(mismatches),
    "js_python_layer_field_agreement": layer_agreement,
    "js_python_layer_field_total": layer_total,
    "mismatch_count": len(mismatches),
    "mismatches": mismatches,
    "freeze_sha256": sha256(HERE / "PREORACLE-FREEZE.json"),
    "claim_boundary": (
        "Internal deterministic multi-fault precedence evidence over a designed "
        "corpus, not external ground truth or deployed validity."
    ),
}
(HERE / "comparison-results.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
(HERE / "REPORT.md").write_text(
    f"""# Native multi-fault composition report

- Cases: **{result['cases']}**, with 2–{result['fault_count_max']} simultaneous faults.
- Oracle verdict + first gate: **{result['exact_verdict_and_first_gate']}/{result['cases']}**.
- JS/Python typed layer fields: **{layer_agreement}/{layer_total}**.
- Mismatches: **{len(mismatches)}**.
- Freeze: `{result['freeze_sha256']}`.

The corpus tests cross-layer composition order and two within-layer precedence
cases. It is internal designed-corpus evidence, not external ground truth or
deployed-system validation.
""",
    encoding="utf-8",
)
print(json.dumps(result, indent=2, sort_keys=True))
if mismatches:
    raise SystemExit(1)
