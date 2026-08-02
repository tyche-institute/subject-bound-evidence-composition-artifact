#!/usr/bin/env python3
"""Compare frozen JS/Python results with each other and the mutation oracle."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent


def read(name: str) -> Any:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def sha256(name: str) -> str:
    return hashlib.sha256((HERE / name).read_bytes()).hexdigest()


freeze = read("PREORACLE-FREEZE.json")
for name, expected in freeze["files"].items():
    actual = sha256(name)
    if actual != expected:
        raise RuntimeError(f"post-freeze modification: {name}")

oracle = {row["transaction_id"]: row for row in read("mutation-oracle.json")}
js = {row["transaction_id"]: row for row in read("js-layer-results.json")}
python = {row["transaction_id"]: row for row in read("python-layer-results.json")}

if set(oracle) != set(js) or set(oracle) != set(python):
    raise RuntimeError("transaction ID sets differ")

mismatches: list[dict[str, Any]] = []
for transaction_id in sorted(oracle):
    expected = oracle[transaction_id]
    js_row = js[transaction_id]
    py_row = python[transaction_id]
    fields = {
        "oracle_verdict": expected["expected_verdict"],
        "oracle_gate": expected["expected_first_rejecting_gate"],
        "js_verdict": js_row["verdict"],
        "js_gate": js_row["first_rejecting_gate"],
        "python_verdict": py_row["verdict"],
        "python_gate": py_row["first_rejecting_gate"],
    }
    target_layer = expected["target_layer"]
    target_matches = True
    target_observed: dict[str, Any] = {}
    if target_layer != "all":
        for implementation, row in (("js", js_row), ("python", py_row)):
            target_observed[implementation] = row["layers"][target_layer]
            if row["layers"][target_layer]["rule"] != expected["expected_rule"]:
                target_matches = False
    matches = (
        js_row["verdict"] == expected["expected_verdict"]
        and py_row["verdict"] == expected["expected_verdict"]
        and js_row["first_rejecting_gate"]
        == expected["expected_first_rejecting_gate"]
        and py_row["first_rejecting_gate"]
        == expected["expected_first_rejecting_gate"]
        and js_row["verdict"] == py_row["verdict"]
        and js_row["first_rejecting_gate"] == py_row["first_rejecting_gate"]
        and target_matches
    )
    if not matches:
        mismatches.append(
            {
                "transaction_id": transaction_id,
                "operator": expected["operator"],
                "fields": fields,
                "expected_rule": expected["expected_rule"],
                "target_observed": target_observed,
            }
        )

layer_fields = ("result", "gate", "rule")
layer_cells = 0
layer_agreements = 0
for transaction_id in sorted(oracle):
    for layer in ("policy", "evidence", "state", "authority", "measurement"):
        for field in layer_fields:
            layer_cells += 1
            if js[transaction_id]["layers"][layer][field] == python[transaction_id][
                "layers"
            ][layer][field]:
                layer_agreements += 1

report = {
    "corpus": "thesis-v4-single-fault-mutations-v1",
    "transactions": len(oracle),
    "baseline_cases": sum(row["operator"] == "baseline" for row in oracle.values()),
    "single_fault_cases": sum(
        row["operator"] != "baseline" for row in oracle.values()
    ),
    "oracle_exact_verdict_and_gate": len(oracle) - len(mismatches),
    "oracle_total": len(oracle),
    "js_python_layer_field_agreement": layer_agreements,
    "js_python_layer_field_total": layer_cells,
    "mismatch_count": len(mismatches),
    "mismatches": mismatches,
    "freeze_sha256": sha256("PREORACLE-FREEZE.json"),
    "mutation_packet_sha256": sha256("mutation-packet.json"),
    "oracle_sha256": sha256("mutation-oracle.json"),
    "claim_boundary": (
        "Internal deterministic single-fault property evidence over a designed "
        "corpus; it is not external ground truth or deployed-system validation."
    ),
}
(HERE / "comparison-results.json").write_text(
    json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

status = "PASS" if not mismatches else "FAIL"
markdown = f"""# Thesis-v4 mutation differential report

- Status: **{status}**
- Corpus: 38 deterministic cases = 1 unmodified baseline + 37 isolated faults.
- Oracle verdict + first gate: **{report['oracle_exact_verdict_and_gate']}/{report['oracle_total']}**.
- Independent JS/Python typed layer fields: **{layer_agreements}/{layer_cells}**.
- Mismatches: **{len(mismatches)}**.
- Freeze: `{report['freeze_sha256']}`.
- Mutation packet: `{report['mutation_packet_sha256']}`.
- Oracle: `{report['oracle_sha256']}`.

## Interpretation

The mutation operators cover P1-P5, E1-E2, S1-S3, A0-A19 and M1-M3 with one
fault introduced at a time after selection of a fully passing transaction.
Both implementations were written and run without reading the mutation oracle;
their outputs and source files were hashed in `PREORACLE-FREEZE.json` before
comparison.

This is internal deterministic property evidence over a designed corpus. It
strengthens fault-localisation and implementation-independence evidence, but it
is not external ground truth, standards conformance, or deployed-system
validation.
"""
(HERE / "REPORT.md").write_text(markdown, encoding="utf-8")
print(json.dumps(report, indent=2, sort_keys=True))

if mismatches:
    raise SystemExit(1)
