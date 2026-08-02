#!/usr/bin/env python3
"""Verify Tyche experimental signed delegation and effect envelopes."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HERE = Path(__file__).resolve().parent


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("signature", None)
    return result


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def verify_signature(
    envelope: dict[str, Any], keys: dict[str, str]
) -> bool:
    issuer = envelope.get("issuer")
    if issuer not in keys or not isinstance(envelope.get("signature"), str):
        return False
    try:
        key = Ed25519PublicKey.from_public_bytes(base64.b64decode(keys[issuer]))
        signature = base64.b64decode(envelope["signature"], validate=True)
        key.verify(signature, canonical(unsigned(envelope)))
        return True
    except Exception:
        return False


def subset(child: Any, parent: Any) -> bool:
    return isinstance(child, list) and isinstance(parent, list) and set(child) <= set(
        parent
    )


def reject(case_id: str, gate: str, detail: str) -> dict[str, str]:
    return {
        "case_id": case_id,
        "verdict": "DENY",
        "first_rejecting_gate": gate,
        "detail": detail,
    }


def evaluate(item: dict[str, Any]) -> dict[str, str]:
    case_id = item["case_id"]
    shared = item["shared"]
    keys = shared["public_keys_ed25519_raw_b64"]
    principal = shared["root_principal"]
    role = shared["root_role"]
    scope = copy.deepcopy(shared["root_scope"])
    parent_digest = shared["root_anchor_digest"]

    for index, edge in enumerate(item["delegations"]):
        if not verify_signature(edge, keys):
            return reject(case_id, "native.edge.signature", f"edge={index}")
        if (
            edge.get("issuer") != principal
            or edge.get("from_role") != role
            or edge.get("parent_digest") != parent_digest
        ):
            return reject(case_id, "native.edge.lineage", f"edge={index}")
        if index > 0 and scope.get("delegable") is not True:
            return reject(case_id, "native.edge.parent_delegable", f"edge={index}")
        if edge.get("to_role") not in shared["allowed_role_transitions"].get(
            role, []
        ):
            return reject(case_id, "native.edge.role_transition", f"edge={index}")
        if edge.get("status") != "active":
            return reject(case_id, "native.edge.status", f"edge={index}")
        if not (
            edge.get("not_before")
            <= shared["effect_time"]
            <= edge.get("expires_at")
        ):
            return reject(case_id, "native.edge.freshness", f"edge={index}")
        for field in (
            "operations",
            "resources",
            "tools",
            "audiences",
            "purposes",
        ):
            if not subset(edge["grant"].get(field), scope.get(field)):
                return reject(
                    case_id, f"native.edge.scope.{field}", f"edge={index}"
                )
        if edge["grant"].get("currency") != scope.get("currency"):
            return reject(case_id, "native.edge.scope.currency", f"edge={index}")
        if edge["grant"].get("amount_max", float("inf")) > scope.get(
            "amount_max", float("-inf")
        ):
            return reject(case_id, "native.edge.scope.amount_max", f"edge={index}")
        parent_digest = digest(edge)
        principal = edge["subject"]
        role = edge["to_role"]
        scope = copy.deepcopy(edge["grant"])

    action = item["action"]
    if action.get("subject") != principal or action.get("role") != role:
        return reject(case_id, "native.action.subject_role", "terminal binding")
    for singular, plural in (
        ("operation", "operations"),
        ("resource", "resources"),
        ("tool", "tools"),
        ("audience", "audiences"),
        ("purpose", "purposes"),
    ):
        if action.get(singular) not in scope.get(plural, []):
            return reject(case_id, f"native.action.{singular}", "terminal scope")
    if (
        action.get("currency") != scope.get("currency")
        or action.get("amount", float("inf")) > scope.get("amount_max", float("-inf"))
    ):
        return reject(case_id, "native.action.amount_currency", "terminal scope")

    receipt = item["receipt"]
    if not verify_signature(receipt, keys):
        return reject(case_id, "native.effect.signature", "receipt")
    if receipt.get("issuer") != principal:
        return reject(case_id, "native.effect.issuer", "terminal principal")
    if receipt.get("authority_chain_digest") != digest(item["delegations"]):
        return reject(case_id, "native.effect.chain_binding", "delegation chain")
    if receipt.get("effect_time") != shared["effect_time"]:
        return reject(case_id, "native.effect.time_binding", "effect time")
    if canonical(receipt.get("action")) != canonical(action):
        return reject(case_id, "native.effect.action_binding", "action")

    return {
        "case_id": case_id,
        "verdict": "ALLOW",
        "first_rejecting_gate": "verified",
        "detail": "all native signed checks passed",
    }


fixtures = json.loads((HERE / "fixtures.json").read_text(encoding="utf-8"))
results = [evaluate(item) for item in fixtures["cases"]]
(HERE / "actual-results.json").write_text(
    json.dumps(results, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(json.dumps(results, indent=2, sort_keys=True))
