#!/usr/bin/env python3
"""Deterministic verifier for the Protocol-valid, Unauthorized v0 corpus."""

from __future__ import annotations

import copy
import hashlib
import json
import sys

from datetime import datetime
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
RESULTS_DIR = ROOT / "results"

GATE_ORDER = [
    "protocol.schema",
    "authorization.present",
    "native.authorization",
    "native.evidence",
    "edge.subject",
    "seam.tenant",
    "seam.audience",
    "seam.subdelegation",
    "seam.operation",
    "seam.resource",
    "seam.tool",
    "seam.effect",
    "seam.amount_currency",
    "seam.freshness_status",
    "seam.canonicalization",
    "seam.replay",
    "action.commitment",
    "outcome.binding",
]

REQUIRED_PROTOCOL_FIELDS = {
    "schema",
    "schema_valid",
    "signature_valid",
    "message_id",
    "task_id",
    "context_id",
    "extension_uri",
}

ACTION_PROJECTION_FIELDS = (
    "subject",
    "tenant",
    "audience",
    "operation",
    "resource",
    "tool",
    "effect",
    "amount_minor",
    "currency",
)

COMMITMENT_FIELDS = (
    "operation",
    "resource",
    "tool",
    "effect",
    "amount_minor",
    "currency",
)


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def sha256_prefixed(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_json(value)).hexdigest()


def deep_merge(base: Any, patch: Any) -> Any:
    if patch is None:
        return None
    if isinstance(base, dict) and isinstance(patch, dict):
        merged = copy.deepcopy(base)
        for key, value in patch.items():
            merged[key] = deep_merge(merged.get(key), value)
        return merged
    return copy.deepcopy(patch)


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def protocol_valid(case: dict[str, Any]) -> bool:
    protocol = case.get("protocol")
    if not isinstance(protocol, dict):
        return False
    if REQUIRED_PROTOCOL_FIELDS - protocol.keys():
        return False
    if protocol.get("schema_valid") is not True:
        return False
    if protocol.get("signature_valid") is not True:
        return False
    return all(
        isinstance(protocol.get(field), str) and bool(protocol[field])
        for field in ("schema", "message_id", "task_id", "context_id", "extension_uri")
    )


def native_authorization(case: dict[str, Any]) -> str:
    mandate = case.get("mandate")
    if mandate is None:
        return "ABSENT"
    if mandate.get("native_valid") is not True:
        return "INVALID"
    decision_time = parse_time(case["appraisal"]["decision_time"])
    if decision_time < parse_time(mandate["not_before"]):
        return "INVALID"
    if decision_time >= parse_time(mandate["expires_at"]):
        return "INVALID"
    revoked_at = mandate.get("revoked_at")
    if revoked_at is not None and decision_time >= parse_time(revoked_at):
        return "INVALID"
    return "VALID"


def native_evidence(case: dict[str, Any]) -> str:
    evidence = case.get("evidence")
    if not isinstance(evidence, dict):
        return "ABSENT"
    if evidence.get("native_valid") is not True:
        return "INVALID"
    receipt_action = evidence.get("receipt_action")
    if not isinstance(receipt_action, dict):
        return "INVALID"
    if any(field not in receipt_action for field in ACTION_PROJECTION_FIELDS):
        return "INVALID"
    return "VALID"


def projected(source: dict[str, Any], fields: tuple[str, ...]) -> dict[str, Any]:
    return {field: source.get(field) for field in fields}


def first_rejecting_gate(
    case: dict[str, Any], a0: str, e0: str
) -> tuple[str, str]:
    if not protocol_valid(case):
        return "DENY", "protocol.schema"
    mandate = case.get("mandate")
    if mandate is None:
        return "DENY", "authorization.present"
    if a0 != "VALID":
        return "DENY", "native.authorization"
    if e0 != "VALID":
        return "DENY", "native.evidence"

    edge = case["edge"]
    action = case["action"]
    evidence = case["evidence"]
    receipt_action = evidence["receipt_action"]

    if edge["delegator"] != mandate["subject"] or action["subject"] != edge["delegate"]:
        return "DENY", "edge.subject"
    if action["tenant"] != mandate["tenant"]:
        return "DENY", "seam.tenant"
    if action["audience"] != mandate["audience"]:
        return "DENY", "seam.audience"
    if (
        edge["delegate"] != mandate["subject"]
        and edge["delegate"] not in mandate["permitted_subdelegates"]
    ):
        return "DENY", "seam.subdelegation"
    if action["operation"] not in mandate["operations"]:
        return "DENY", "seam.operation"
    if action["resource"] not in mandate["resources"]:
        return "DENY", "seam.resource"
    if action["tool"] not in mandate["tools"]:
        return "DENY", "seam.tool"
    if action["effect"] not in mandate["effects"]:
        return "DENY", "seam.effect"
    if (
        action["currency"] != mandate["currency"]
        or action["amount_minor"] > mandate["max_amount_minor"]
    ):
        return "DENY", "seam.amount_currency"

    executed_at = parse_time(action["executed_at"])
    if executed_at < parse_time(mandate["not_before"]):
        return "DENY", "seam.freshness_status"
    if executed_at >= parse_time(mandate["expires_at"]):
        return "DENY", "seam.freshness_status"
    revoked_at = mandate.get("revoked_at")
    if revoked_at is not None and executed_at >= parse_time(revoked_at):
        return "DENY", "seam.freshness_status"

    if action["canonicalization_profile"] != mandate["canonicalization_profile"]:
        return "DENY", "seam.canonicalization"
    if mandate["prior_uses"] >= mandate["max_uses"]:
        return "DENY", "seam.replay"

    committed = projected(mandate["committed_action"], COMMITMENT_FIELDS)
    actual = projected(action, COMMITMENT_FIELDS)
    if sha256_prefixed(committed) != sha256_prefixed(actual):
        return "DENY", "action.commitment"

    if projected(action, ACTION_PROJECTION_FIELDS) != projected(
        receipt_action, ACTION_PROJECTION_FIELDS
    ):
        return "DENY", "outcome.binding"
    if parse_time(evidence["observed_at"]) < executed_at:
        return "DENY", "outcome.binding"

    return "ALLOW", "verified"


def ordered_gate_trace(verdict: str, rejecting_gate: str) -> dict[str, str]:
    if verdict == "ALLOW":
        return {gate: "PASS" for gate in GATE_ORDER}
    trace: dict[str, str] = {}
    rejected = False
    for gate in GATE_ORDER:
        if rejected:
            trace[gate] = "NOT_EVALUATED"
        elif gate == rejecting_gate:
            trace[gate] = "DENY"
            rejected = True
        else:
            trace[gate] = "PASS"
    return trace


def evaluate(vector: dict[str, Any], base: dict[str, Any]) -> dict[str, Any]:
    case = deep_merge(base, vector["patch"])
    a0 = native_authorization(case)
    e0 = native_evidence(case)
    c1, gate = first_rejecting_gate(case, a0, e0)
    expected = vector["expected"]
    expected_match = (
        a0 == expected["a0"]
        and e0 == expected["e0"]
        and c1 == expected["c1"]
        and gate == expected["gate"]
    )
    first_bad_edge = None if c1 == "ALLOW" else case.get("edge", {}).get("edge_id")
    return {
        "id": vector["id"],
        "description": vector["description"],
        "protocol_valid": protocol_valid(case),
        "a0": a0,
        "e0": e0,
        "c1": c1,
        "first_rejecting_gate": gate,
        "first_bad_edge": first_bad_edge,
        "gate_trace": ordered_gate_trace(c1, gate),
        "expected": expected,
        "expected_match": expected_match,
    }


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    vectors = corpus["vectors"]
    ids = [vector["id"] for vector in vectors]
    if len(ids) != len(set(ids)):
        raise ValueError("vector IDs must be unique")

    results = [evaluate(vector, corpus["base"]) for vector in vectors]
    RESULTS_DIR.mkdir(exist_ok=True)
    verdicts_path = RESULTS_DIR / "verdicts.jsonl"
    verdicts_path.write_text(
        "".join(json.dumps(result, sort_keys=True) + "\n" for result in results),
        encoding="utf-8",
    )

    negatives = [result for result in results if result["c1"] == "DENY"]
    semantic_differentials = [
        result
        for result in negatives
        if result["a0"] == "VALID" and result["e0"] == "VALID"
    ]
    ordered = all(
        all(
            state == "NOT_EVALUATED"
            for gate, state in list(result["gate_trace"].items())[
                list(result["gate_trace"]).index(result["first_rejecting_gate"]) + 1 :
            ]
        )
        for result in negatives
    )
    summary = {
        "profile": corpus["profile"],
        "vectors": len(results),
        "positive": len(results) - len(negatives),
        "negative": len(negatives),
        "protocol_valid": sum(result["protocol_valid"] for result in results),
        "a0_valid_e0_valid_c1_deny": len(semantic_differentials),
        "expected_matches": sum(result["expected_match"] for result in results),
        "negative_gate_rejections": sum(
            bool(result["first_bad_edge"]) for result in negatives
        ),
        "ordered_not_evaluated": ordered,
        "disclaimer": (
            "schema_valid, signature_valid and native_valid are "
            "corpus-supplied experimental flags; this laboratory performs no "
            "cryptographic verification. first_bad_edge copies the single "
            "case edge id and is a gate rejection marker, not edge-level "
            "localization; expected labels are author-written and counts on "
            "a designed corpus are not rates."
        ),
        "corpus_sha256": sha256_prefixed(corpus),
        "verifier_sha256": "sha256:"
        + hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    summary_path = RESULTS_DIR / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    sums_path = RESULTS_DIR / "SHA256SUMS"
    sums_path.write_text(
        f"{hashlib.sha256(verdicts_path.read_bytes()).hexdigest()}  verdicts.jsonl\n"
        f"{hashlib.sha256(summary_path.read_bytes()).hexdigest()}  summary.json\n"
        f"{hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()}  ../corpus.json\n"
        f"{hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}  ../verify_corpus.py\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2, sort_keys=True))
    return int(
        summary["expected_matches"] != summary["vectors"]
        or summary["protocol_valid"] != summary["vectors"]
        or summary["negative_gate_rejections"] != summary["negative"]
        or not summary["ordered_not_evaluated"]
    )


if __name__ == "__main__":
    sys.exit(main())
