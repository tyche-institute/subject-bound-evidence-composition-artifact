#!/usr/bin/env python3
"""Compare two executions of the public four-lane replay contract."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--x64", type=Path, required=True)
    parser.add_argument("--arm64", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    x_contract = load(args.x64 / "semantic-contract.json")
    a_contract = load(args.arm64 / "semantic-contract.json")
    x_env = load(args.x64 / "environment.json")
    a_env = load(args.arm64 / "environment.json")
    checks = {
        "x64_contract_passed": x_contract["all_passed"],
        "arm64_contract_passed": a_contract["all_passed"],
        "exact_boolean_contract": x_contract["checks"]
        == a_contract["checks"],
        "exact_architecture_neutral_counts": x_contract[
            "architecture_neutral_counts"
        ]
        == a_contract["architecture_neutral_counts"],
        "same_workflow_source_commit": (
            x_env["workflow"]["checkout_sha"]
            == a_env["workflow"]["checkout_sha"]
            and bool(x_env["workflow"]["checkout_sha"])
        ),
        "reported_architectures_differ": x_env["machine"] != a_env["machine"],
        "x64_reported": x_env["machine"] in {"x86_64", "AMD64"},
        "arm64_reported": a_env["machine"] in {"aarch64", "arm64", "ARM64"},
    }
    result = {
        "comparison": "tyche-public-four-lane-comparison-v1",
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "all_passed": all(checks.values()),
        "source_commit": x_env["workflow"]["checkout_sha"],
        "architecture_neutral_counts": x_contract[
            "architecture_neutral_counts"
        ],
        "x64_environment": x_env,
        "arm64_environment": a_env,
        "claim_boundary": (
            "two GitHub-hosted job VMs reporting different architectures; "
            "no claim of physical-host identity or hardware attestation"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
