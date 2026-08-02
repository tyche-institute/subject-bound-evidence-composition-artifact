#!/usr/bin/env python3
"""Build deterministic Ed25519 delegation/effect fixtures and a separate oracle."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent
EFFECT_TIME = "2026-07-27T10:00:00Z"


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    item = copy.deepcopy(value)
    item.pop("signature", None)
    return item


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical(value)).hexdigest()


def private_key(principal: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(
        f"tyche-native-authority-v0.1::{principal}".encode()
    ).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


def public_raw_b64(principal: str) -> str:
    raw = private_key(principal).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return base64.b64encode(raw).decode("ascii")


def sign(value: dict[str, Any], principal: str) -> dict[str, Any]:
    result = unsigned(value)
    result["signature"] = base64.b64encode(
        private_key(principal).sign(canonical(result))
    ).decode("ascii")
    return result


root_scope = {
    "operations": ["READ"],
    "resources": ["invoice-123"],
    "tools": ["ledger.read"],
    "audiences": ["ledger-service"],
    "purposes": ["audit"],
    "currency": "EUR",
    "amount_max": 1000,
    "delegable": True,
}
shared = {
    "profile": "tyche-native-authority-context-v0.1",
    "root_principal": "principal-anton",
    "root_role": "owner",
    "root_scope": root_scope,
    "root_anchor_digest": "sha256:" + "ab" * 32,
    "effect_time": EFFECT_TIME,
    "allowed_role_transitions": {
        "owner": ["planner"],
        "planner": ["executor"],
        "executor": [],
    },
    "public_keys_ed25519_raw_b64": {
        principal: public_raw_b64(principal)
        for principal in ("principal-anton", "agent-1", "agent-2")
    },
}

d1 = sign(
    {
        "profile": "tyche-native-delegation-v0.1",
        "delegation_id": "delegation-1",
        "issuer": "principal-anton",
        "subject": "agent-1",
        "from_role": "owner",
        "to_role": "planner",
        "grant": copy.deepcopy(root_scope),
        "not_before": "2026-07-27T00:00:00Z",
        "expires_at": "2026-07-28T00:00:00Z",
        "status": "active",
        "parent_digest": shared["root_anchor_digest"],
    },
    "principal-anton",
)
d2 = sign(
    {
        "profile": "tyche-native-delegation-v0.1",
        "delegation_id": "delegation-2",
        "issuer": "agent-1",
        "subject": "agent-2",
        "from_role": "planner",
        "to_role": "executor",
        "grant": {
            **copy.deepcopy(root_scope),
            "amount_max": 500,
            "delegable": False,
        },
        "not_before": "2026-07-27T00:00:00Z",
        "expires_at": "2026-07-28T00:00:00Z",
        "status": "active",
        "parent_digest": digest(d1),
    },
    "agent-1",
)
action = {
    "subject": "agent-2",
    "role": "executor",
    "operation": "READ",
    "resource": "invoice-123",
    "tool": "ledger.read",
    "audience": "ledger-service",
    "purpose": "audit",
    "currency": "EUR",
    "amount": 100,
}


def make_receipt(
    chain: list[dict[str, Any]],
    receipt_action: dict[str, Any] | None = None,
    effect_time: str = EFFECT_TIME,
) -> dict[str, Any]:
    return sign(
        {
            "profile": "tyche-native-effect-v0.1",
            "receipt_id": "effect-1",
            "issuer": "agent-2",
            "effect_time": effect_time,
            "action": copy.deepcopy(receipt_action or action),
            "authority_chain_digest": digest(chain),
        },
        "agent-2",
    )


base = {
    "case_id": "NATIVE-001",
    "shared": shared,
    "delegations": [d1, d2],
    "action": action,
    "receipt": make_receipt([d1, d2]),
}


def corrupt_signature(signature: str) -> str:
    raw = bytearray(base64.b64decode(signature))
    raw[0] ^= 1
    return base64.b64encode(raw).decode("ascii")


cases: list[dict[str, Any]] = []
oracle: list[dict[str, str]] = []


def add(
    operator: str,
    expected_verdict: str,
    expected_gate: str,
    mutate: Any | None = None,
) -> None:
    item = copy.deepcopy(base)
    item["case_id"] = f"NATIVE-{len(cases) + 1:03d}"
    if mutate is not None:
        mutate(item)
    cases.append(item)
    oracle.append(
        {
            "case_id": item["case_id"],
            "operator": operator,
            "expected_verdict": expected_verdict,
            "expected_gate": expected_gate,
        }
    )


add("baseline", "ALLOW", "verified")
add(
    "bad_delegation_signature",
    "DENY",
    "native.edge.signature",
    lambda item: item["delegations"][1].update(
        signature=corrupt_signature(item["delegations"][1]["signature"])
    ),
)
add(
    "bad_effect_signature",
    "DENY",
    "native.effect.signature",
    lambda item: item["receipt"].update(
        signature=corrupt_signature(item["receipt"]["signature"])
    ),
)


def mutate_action_binding(item: dict[str, Any]) -> None:
    changed = copy.deepcopy(item["action"])
    changed["amount"] = 99
    item["receipt"] = make_receipt(item["delegations"], changed)


add(
    "signed_but_different_receipt_action",
    "DENY",
    "native.effect.action_binding",
    mutate_action_binding,
)


def mutate_expired(item: dict[str, Any]) -> None:
    edge = unsigned(item["delegations"][0])
    edge["expires_at"] = "2026-07-26T00:00:00Z"
    item["delegations"][0] = sign(edge, "principal-anton")


add(
    "expired_signed_delegation",
    "DENY",
    "native.edge.freshness",
    mutate_expired,
)


def mutate_lineage(item: dict[str, Any]) -> None:
    edge = unsigned(item["delegations"][1])
    edge["issuer"] = "principal-anton"
    item["delegations"][1] = sign(edge, "principal-anton")


add(
    "valid_signature_wrong_lineage",
    "DENY",
    "native.edge.lineage",
    mutate_lineage,
)


def mutate_scope(item: dict[str, Any]) -> None:
    edge = unsigned(item["delegations"][1])
    edge["grant"]["resources"].append("invoice-999")
    item["delegations"][1] = sign(edge, "agent-1")


add(
    "signed_scope_escalation",
    "DENY",
    "native.edge.scope.resources",
    mutate_scope,
)


def mutate_time_binding(item: dict[str, Any]) -> None:
    item["receipt"] = make_receipt(
        item["delegations"], effect_time="2026-07-27T10:00:01Z"
    )


add(
    "signed_effect_time_mismatch",
    "DENY",
    "native.effect.time_binding",
    mutate_time_binding,
)

(HERE / "fixtures.json").write_text(
    json.dumps(
        {
            "profile": "tyche-native-signed-authority-fixtures-v0.1",
            "case_count": len(cases),
            "cases": cases,
        },
        ensure_ascii=False,
        indent=2,
        sort_keys=True,
    )
    + "\n",
    encoding="utf-8",
)
(HERE / "expected-results.json").write_text(
    json.dumps(oracle, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(
    json.dumps(
        {
            "cases": len(cases),
            "fixture_sha256": hashlib.sha256(
                (HERE / "fixtures.json").read_bytes()
            ).hexdigest(),
            "private_keys_persisted": False,
        },
        indent=2,
        sort_keys=True,
    )
)
