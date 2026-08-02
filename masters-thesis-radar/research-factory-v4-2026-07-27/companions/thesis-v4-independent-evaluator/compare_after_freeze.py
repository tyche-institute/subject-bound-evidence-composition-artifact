#!/usr/bin/env python3
"""Compare frozen independent results with the locally sealed author labels."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
PACKET = (
    HERE.parent.parent
    / "masters-thesis-radar"
    / "research-factory-v4-2026-07-27"
    / "external-label-packet"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    freeze = json.loads((HERE / "PRECOMPARISON-FREEZE.json").read_text())
    for item in freeze["files"].values():
        path = Path(item["path"])
        if digest(path) != item["sha256"]:
            raise RuntimeError(f"post-freeze drift: {path}")

    sealed_path = PACKET / "sealed-expected-labels.json"
    recorded_seal = (
        (PACKET / "SEALED-EXPECTED-LABELS.sha256")
        .read_text(encoding="utf-8")
        .split()[0]
    )
    if digest(sealed_path) != recorded_seal:
        raise RuntimeError("reference-label seal mismatch")

    answers = {
        item["transaction_id"]: item
        for item in json.loads(
            (HERE / "independent-results-unsealed.json").read_text()
        )
    }
    layer_results = {
        item["transaction_id"]: item
        for item in json.loads(
            (HERE / "independent-layer-results-unsealed.json").read_text()
        )
    }
    sealed = json.loads(sealed_path.read_text(encoding="utf-8"))
    expected = {item["blind_id"]: item["expected"] for item in sealed["labels"]}
    if set(answers) != set(expected) or set(layer_results) != set(expected):
        raise RuntimeError("transaction ID sets differ")

    mismatches: list[dict[str, object]] = []
    verdict_hits = 0
    gate_hits = 0
    layer_hits = 0
    layer_total = 0
    exact_hits = 0
    for transaction_id in sorted(expected):
        observed = answers[transaction_id]
        observed_layers = {
            name: value["result"]
            for name, value in layer_results[transaction_id]["layers"].items()
        }
        reference = expected[transaction_id]
        verdict_ok = observed["verdict"] == reference["verdict"]
        gate_ok = (
            observed["first_rejecting_gate"]
            == reference["first_rejecting_gate"]
        )
        layer_diff = {
            name: {
                "observed": observed_layers[name],
                "reference": reference["layer_results"][name],
            }
            for name in reference["layer_results"]
            if observed_layers[name] != reference["layer_results"][name]
        }
        verdict_hits += verdict_ok
        gate_hits += gate_ok
        layer_hits += 5 - len(layer_diff)
        layer_total += 5
        exact_hits += verdict_ok and gate_ok and not layer_diff
        if not verdict_ok or not gate_ok or layer_diff:
            mismatches.append(
                {
                    "transaction_id": transaction_id,
                    "observed_verdict": observed["verdict"],
                    "reference_verdict": reference["verdict"],
                    "observed_gate": observed["first_rejecting_gate"],
                    "reference_gate": reference["first_rejecting_gate"],
                    "layer_differences": layer_diff,
                }
            )

    report = {
        "claim_boundary": (
            "This is a cross-implementation comparison against sealed "
            "author-written programme-internal labels. It is stronger than "
            "same-code reruns but remains internal designed-corpus evidence, "
            "not external ground truth or deployed-system validity."
        ),
        "precomparison_freeze_sha256": digest(
            HERE / "PRECOMPARISON-FREEZE.json"
        ),
        "sealed_labels_sha256_verified": recorded_seal,
        "transactions": len(expected),
        "verdict_matches": verdict_hits,
        "gate_matches": gate_hits,
        "layer_matches": layer_hits,
        "layer_total": layer_total,
        "fully_exact_transactions": exact_hits,
        "mismatch_count": len(mismatches),
        "mismatches": mismatches,
    }
    (HERE / "comparison-results.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lines = [
        "# Independent thesis-v4 evaluator comparison",
        "",
        "Date: 2026-07-27",
        "",
        report["claim_boundary"],
        "",
        f"- Verdict matches: {verdict_hits}/90.",
        f"- First-gate matches: {gate_hits}/90.",
        f"- Per-layer typed-result matches: {layer_hits}/{layer_total}.",
        f"- Fully exact transactions: {exact_hits}/90.",
        f"- Transactions with any mismatch: {len(mismatches)}.",
        "",
        "The JavaScript implementation used only the labeller-facing packet "
        "before its result was hashed in `PRECOMPARISON-FREEZE.json`. It uses "
        "Node's Ed25519 verifier, an independently written canonical JSON "
        "serializer, authority ladder and bootstrap implementation.",
    ]
    if mismatches:
        lines.extend(["", "## Mismatches", ""])
        for mismatch in mismatches:
            lines.append(
                f"- `{mismatch['transaction_id']}`: "
                f"{mismatch['observed_verdict']}/"
                f"{mismatch['observed_gate']} vs "
                f"{mismatch['reference_verdict']}/"
                f"{mismatch['reference_gate']}; layers "
                f"`{json.dumps(mismatch['layer_differences'], sort_keys=True)}`."
            )
    (HERE / "REPORT.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if not mismatches else 1


if __name__ == "__main__":
    raise SystemExit(main())
