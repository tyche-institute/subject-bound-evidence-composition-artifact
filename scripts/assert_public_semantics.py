#!/usr/bin/env python3
"""Reduce the four public replay lanes to exact architecture-neutral checks."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--v4", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    labs = args.v4 / "labs"

    policy_path = labs / "policy-version-evidence-replay/results/summary.json"
    composed_path = labs / "composed-transaction-corpus/results/summary.json"
    transfer_path = labs / "cross-ecosystem-typed-transfer/results.json"
    revocation_path = labs / "distributed-revocation-service/results.json"
    policy = load(policy_path)
    composed = load(composed_path)
    transfer = load(transfer_path)
    revocation = load(revocation_path)
    revocation_summary = revocation["summary"]
    boundary = revocation_summary["claim_boundary"]

    checks = {
        "policy_vectors_16": policy["vectors"] == 16,
        "policy_exact_16": policy["strict_expected_matches"] == 16,
        "policy_baselines_expose_false_allow": all(
            value > 0 for value in policy["baseline_false_allows"].values()
        ),
        "composed_transactions_104": composed["transactions"] == 104,
        "composed_exact_104": composed["expected_matches"] == 104
        and composed["per_layer_expected_matches"] == 104,
        "composed_subject_match_104": composed["subject_matches"] == 104,
        "composed_binding_denials_8": (
            composed["binding_stage"]["cross_layer_denials"] == 8
        ),
        "composed_all_source_hashes_match": composed[
            "source_hashes_match_corpus"
        ],
        "transfer_source_pins_verified": transfer[
            "all_source_pins_verified"
        ],
        "transfer_codes_total": transfer["all_native_codes_mapped"],
        "transfer_eatf_21": (
            transfer["eatf"]["oracle_and_cross_implementation_matches"] == 21
        ),
        "transfer_transactions_104": (
            transfer["composed_transaction"]["oracle_matches"] == 104
        ),
        "revocation_cases_372": revocation_summary["cases"] == 372,
        "revocation_all_passed": revocation_summary["all_passed"],
        "revocation_atomic_invariant": (
            revocation_summary["atomic_guard_invariant"]
            and revocation_summary["profiles"]["atomic_guard"]["false_allows"]
            == 0
        ),
        "revocation_no_duplicate_effects": (
            revocation_summary["duplicate_effects"] == 0
        ),
        "revocation_fault_recovery_96": (
            revocation_summary["fault_cases"] == 96
            and revocation_summary["fault_recoveries"] == 96
        ),
        "revocation_weak_counterexamples": revocation_summary[
            "weak_counterexamples_observed"
        ],
        "revocation_signatures_372": (
            revocation_summary["signed_responses_verified"] == 372
        ),
        "revocation_boundary_calibrated": (
            "one local OS instance reporting" in boundary
            and "not multi-host" in boundary
            and "physical" not in boundary
        ),
    }
    result_paths = (
        policy_path,
        composed_path,
        transfer_path,
        revocation_path,
    )
    semantic_contract = {
        "contract": "tyche-public-four-lane-semantic-contract-v1",
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "all_passed": all(checks.values()),
        "architecture_neutral_counts": {
            "policy_vectors": policy["vectors"],
            "composed_transactions": composed["transactions"],
            "binding_denials": composed["binding_stage"][
                "cross_layer_denials"
            ],
            "eatf_rows": transfer["eatf"]["cases"],
            "transfer_transaction_rows": transfer["composed_transaction"][
                "cases"
            ],
            "revocation_cases": revocation_summary["cases"],
            "revocation_fault_cases": revocation_summary["fault_cases"],
        },
        "result_hashes": {
            str(path.relative_to(args.v4)): digest(path)
            for path in result_paths
        },
        "rate_boundary": (
            "race-exposure counts are excluded from cross-architecture "
            "equality; exact cases and safety invariants are compared"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(semantic_contract, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(semantic_contract, indent=2, sort_keys=True))
    return 0 if semantic_contract["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
