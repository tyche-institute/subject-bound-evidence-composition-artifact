#!/usr/bin/env python3
"""Compare native verifier outputs to separately generated expectations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def read(name: str):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


expected = {row["case_id"]: row for row in read("expected-results.json")}
actual = {row["case_id"]: row for row in read("actual-results.json")}
if set(expected) != set(actual):
    raise RuntimeError("case ID sets differ")

mismatches = []
for case_id in sorted(expected):
    want = expected[case_id]
    got = actual[case_id]
    if (
        want["expected_verdict"] != got["verdict"]
        or want["expected_gate"] != got["first_rejecting_gate"]
    ):
        mismatches.append({"case_id": case_id, "expected": want, "actual": got})

result = {
    "profile": "tyche-native-signed-authority-fixtures-v0.1",
    "cases": len(expected),
    "exact_verdict_and_gate": len(expected) - len(mismatches),
    "mismatch_count": len(mismatches),
    "mismatches": mismatches,
    "fixtures_sha256": hashlib.sha256((HERE / "fixtures.json").read_bytes()).hexdigest(),
    "verifier_sha256": hashlib.sha256(
        (HERE / "verify_fixtures.py").read_bytes()
    ).hexdigest(),
    "claim_boundary": (
        "Tyche experimental envelope profile with real Ed25519 verification; "
        "not WAVE, JEDI, A2A, DID, or any external standards conformance claim."
    ),
}
(HERE / "comparison-results.json").write_text(
    json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(result, indent=2, sort_keys=True))
if mismatches:
    raise SystemExit(1)
