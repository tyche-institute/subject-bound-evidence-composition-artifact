#!/usr/bin/env python3
"""Strict and ablated Python evaluators for signed revocation-race fixtures."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.serialization import load_der_public_key


HERE = Path(__file__).resolve().parent


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def verify_signed(item: dict[str, Any], public_key: Any) -> bool:
    unsigned = {key: value for key, value in item.items() if key != "signature_b64"}
    try:
        public_key.verify(
            base64.b64decode(item["signature_b64"]), canonical(unsigned)
        )
    except Exception:
        return False
    return True


def result(case_id: str, verdict: str, gate: str) -> dict[str, str]:
    return {
        "case_id": case_id,
        "verdict": verdict,
        "first_rejecting_gate": gate,
    }


def snapshot_gate(
    item: dict[str, Any] | None,
    *,
    prefix: str,
    credential_id: str,
    decision_time: int,
    max_age: int,
    status_key: Any,
) -> str | None:
    if item is None:
        return f"{prefix}.status.available"
    if not verify_signed(item, status_key):
        return f"{prefix}.status.signature"
    if credential_id not in item.get("states", {}):
        return f"{prefix}.status.binding"
    age = decision_time - item["issued_at"]
    if age < 0 or age > max_age:
        return f"{prefix}.status.freshness"
    if item["states"][credential_id] != "active":
        return f"{prefix}.status.active"
    return None


def evaluate_strict(case: dict[str, Any], credential_key: Any, status_key: Any):
    case_id = case["case_id"]
    credential = case["credential"]
    if not verify_signed(credential, credential_key):
        return result(case_id, "DENY", "credential.signature")
    if not (
        credential["valid_from"] <= case["appraisal_time"] < credential["valid_until"]
        and credential["valid_from"] <= case["commit_time"] < credential["valid_until"]
    ):
        return result(case_id, "DENY", "credential.window")

    credential_id = credential["credential_id"]
    appraisal_gate = snapshot_gate(
        case["appraisal_snapshot"],
        prefix="appraisal",
        credential_id=credential_id,
        decision_time=case["appraisal_time"],
        max_age=case["max_snapshot_age"],
        status_key=status_key,
    )
    if appraisal_gate:
        return result(case_id, "DENY", appraisal_gate)

    commit_gate = snapshot_gate(
        case["commit_snapshot"],
        prefix="commit",
        credential_id=credential_id,
        decision_time=case["commit_time"],
        max_age=case["max_snapshot_age"],
        status_key=status_key,
    )
    if commit_gate:
        return result(case_id, "DENY", commit_gate)
    if (
        case["commit_snapshot"]["sequence"]
        < case["appraisal_snapshot"]["sequence"]
    ):
        return result(case_id, "DENY", "commit.status.monotonic")
    return result(case_id, "ALLOW", "verified")


def appraisal_only(case: dict[str, Any], credential_key: Any, status_key: Any):
    reduced = dict(case)
    reduced["commit_time"] = case["appraisal_time"]
    strict = evaluate_strict(
        reduced
        | {
            "commit_snapshot": case["appraisal_snapshot"],
        },
        credential_key,
        status_key,
    )
    return strict["verdict"]


def commit_fail_open(case: dict[str, Any], credential_key: Any, status_key: Any):
    if case["commit_snapshot"] is not None:
        return evaluate_strict(case, credential_key, status_key)["verdict"]
    fabricated = dict(case)
    fabricated["commit_snapshot"] = case["appraisal_snapshot"]
    fabricated["commit_time"] = case["appraisal_time"]
    return evaluate_strict(fabricated, credential_key, status_key)["verdict"]


def timestamp_only(case: dict[str, Any], credential_key: Any, status_key: Any):
    strict = evaluate_strict(case, credential_key, status_key)
    if strict["first_rejecting_gate"] != "commit.status.monotonic":
        return strict["verdict"]
    return "ALLOW"


packet = json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))
credential_key = load_der_public_key(
    base64.b64decode(packet["public_keys"]["credential_authority_spki_b64"])
)
status_key = load_der_public_key(
    base64.b64decode(packet["public_keys"]["status_authority_spki_b64"])
)

rows = []
for item in packet["cases"]:
    strict = evaluate_strict(item, credential_key, status_key)
    expected = item["expected"]
    rows.append(
        strict
        | {
            "expected_verdict": expected["verdict"],
            "expected_gate": expected["first_rejecting_gate"],
            "baselines": {
                "appraisal_only": appraisal_only(item, credential_key, status_key),
                "commit_fail_open": commit_fail_open(
                    item, credential_key, status_key
                ),
                "timestamp_only": timestamp_only(item, credential_key, status_key),
            },
        }
    )

(HERE / "python-results.json").write_text(
    json.dumps(rows, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps({"implementation": "python", "cases": len(rows)}, sort_keys=True))
