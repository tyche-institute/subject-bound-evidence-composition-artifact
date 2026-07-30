#!/usr/bin/env python3
"""Compare both revocation-race implementations and summarize ablations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def load(name: str):
    return json.loads((HERE / name).read_text(encoding="utf-8"))


python_rows = {row["case_id"]: row for row in load("python-results.json")}
js_rows = {row["case_id"]: row for row in load("js-results.json")}
if set(python_rows) != set(js_rows):
    raise RuntimeError("implementation case sets differ")

mismatches = []
strict_exact = 0
baseline_false_allows = {
    "appraisal_only": [],
    "commit_fail_open": [],
    "timestamp_only": [],
}
for case_id in sorted(python_rows):
    py = python_rows[case_id]
    js = js_rows[case_id]
    if py != js:
        mismatches.append({"case_id": case_id, "python": py, "javascript": js})
    exact = (
        py["verdict"] == py["expected_verdict"]
        and py["first_rejecting_gate"] == py["expected_gate"]
    )
    strict_exact += exact
    if py["expected_verdict"] == "DENY":
        for name, verdict in py["baselines"].items():
            if verdict == "ALLOW":
                baseline_false_allows[name].append(case_id)

summary = {
    "profile": "tyche-prospective-revocation-races-v1",
    "cases": len(python_rows),
    "strict_exact_verdict_and_gate": strict_exact,
    "python_javascript_exact_rows": len(python_rows) - len(mismatches),
    "mismatch_count": len(mismatches),
    "mismatches": mismatches,
    "baseline_false_allows": baseline_false_allows,
    "corpus_sha256": hashlib.sha256((HERE / "corpus.json").read_bytes()).hexdigest(),
    "claim_boundary": (
        "Internal scheduled-event fixtures with real Ed25519 verification; "
        "not external ground truth, a live concurrency experiment, deployed "
        "validation, or standards conformance."
    ),
}
(HERE / "summary.json").write_text(
    json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)

lines = [
    "# Prospective signed-revocation race result",
    "",
    f"- Strict expected verdict + gate: **{strict_exact}/{len(python_rows)}**.",
    f"- Python/JavaScript exact rows: **{len(python_rows) - len(mismatches)}/{len(python_rows)}**.",
    f"- Mismatches: **{len(mismatches)}**.",
    (
        "- `appraisal_only` false allows: "
        f"**{len(baseline_false_allows['appraisal_only'])}** "
        f"({', '.join(baseline_false_allows['appraisal_only']) or 'none'})."
    ),
    (
        "- `commit_fail_open` false allows: "
        f"**{len(baseline_false_allows['commit_fail_open'])}** "
        f"({', '.join(baseline_false_allows['commit_fail_open']) or 'none'})."
    ),
    (
        "- `timestamp_only` false allows: "
        f"**{len(baseline_false_allows['timestamp_only'])}** "
        f"({', '.join(baseline_false_allows['timestamp_only']) or 'none'})."
    ),
    f"- Corpus SHA-256: `{summary['corpus_sha256']}`.",
    "",
    "These are designed event-sequence coverage counts, not rates.  The lab",
    "uses real Ed25519 verification but an internal experimental credential",
    "and status profile.  It is not a live race, deployed-system validation,",
    "external ground truth, or standards-conformance result.",
]
(HERE / "result-2026-07-27.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
print(json.dumps(summary, indent=2, sort_keys=True))
if mismatches or strict_exact != len(python_rows):
    raise SystemExit(1)
