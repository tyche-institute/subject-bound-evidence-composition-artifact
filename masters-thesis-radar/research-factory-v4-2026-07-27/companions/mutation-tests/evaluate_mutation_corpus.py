#!/usr/bin/env python3
"""Independent Python implementation of LABELLING-SPEC.md for mutations.

This evaluator reads only mutation-packet.json. It does not read the mutation
oracle, sealed labels, or research-program evaluator source.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HERE = Path(__file__).resolve().parent


def canonical(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("signature", None)
    return result


def digest_object(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(
        canonical(unsigned(value)).encode("utf-8")
    ).hexdigest()


def valid_signature(
    value: Any, public_key: Ed25519PublicKey
) -> bool:
    if not isinstance(value, dict) or not isinstance(value.get("signature"), str):
        return False
    try:
        signature = base64.b64decode(value["signature"], validate=True)
        if len(signature) != 64:
            return False
        public_key.verify(signature, canonical(unsigned(value)).encode("utf-8"))
        return True
    except Exception:
        return False


def in_window(value: Any, lower: Any, upper: Any) -> bool:
    return (
        isinstance(value, str)
        and isinstance(lower, str)
        and isinstance(upper, str)
        and lower <= value <= upper
    )


def policy_layer(
    policy: Any, shared: dict[str, Any], public_key: Ed25519PublicKey
) -> tuple[str, str | None, str, dict[str, Any] | None]:
    anchor = shared["policy_anchor"]
    decision_time = shared["decision_time"]
    if policy is None:
        return ("MISSING", "policy.missing", "P1", None)
    if not valid_signature(policy, public_key):
        return ("INVALID_SIGNATURE", "policy.signature", "P2", None)
    if policy.get("policy_id") != anchor["required_policy_id"]:
        return ("SUBSTITUTED", "policy.substituted", "P3", None)
    if policy.get("version") != anchor["required_policy_version"] or not in_window(
        decision_time, policy.get("valid_from"), policy.get("valid_until")
    ):
        return ("STALE", "policy.stale", "P4", None)
    if digest_object(policy) != anchor["required_policy_digest"]:
        return ("SUBSTITUTED", "policy.substituted", "P5", None)
    return ("PASS", None, "P1-P5", None)


def evidence_layer(
    evidence: Any, shared: dict[str, Any], public_key: Ed25519PublicKey
) -> tuple[str, str | None, str, dict[str, Any] | None]:
    if not valid_signature(evidence, public_key):
        return ("TAMPERED", "evidence.integrity", "E1", None)
    if evidence.get("nonce") in shared["preseen_nonces"]:
        return ("REPLAY", "evidence.replay", "E2", None)
    return ("PASS", None, "E1-E2", None)


def state_layer(
    state: Any, decision_time: str
) -> tuple[str, str | None, str, dict[str, Any] | None]:
    if not isinstance(state, dict) or state.get("status") != "affirming":
        return ("CONTRAINDICATED", "state.contraindicated", "S1", None)
    if not in_window(decision_time, state.get("issued_at"), state.get("expires_at")):
        return ("STALE", "state.stale", "S2", None)
    if (
        not isinstance(state.get("reference_digest"), str)
        or not state["reference_digest"]
        or state.get("observed_digest") != state["reference_digest"]
    ):
        return ("REFERENCE_MISMATCH", "state.reference", "S3", None)
    return ("PASS", None, "S1-S3", None)


def is_subset(child: Any, parent: Any) -> bool:
    if not isinstance(child, list) or not isinstance(parent, list):
        return False
    parent_values = {canonical(item) for item in parent}
    return all(canonical(item) in parent_values for item in child)


def authority_layer(
    authority: dict[str, Any], shared: dict[str, Any]
) -> tuple[str, str | None, str, dict[str, Any] | None]:
    if authority.get("protocol_valid") is not True:
        return ("DENY", "protocol.valid", "A0", None)

    principal = shared["root_principal"]
    role = shared["root_role"]
    scope = copy.deepcopy(shared["root_scope"])
    for index, edge in enumerate(authority["edges"]):
        if edge.get("delegator") != principal or edge.get("from_role") != role:
            return ("DENY", "edge.lineage", f"A1:{index}", None)
        if edge.get("issuer_signature_valid") is not True:
            return ("DENY", "edge.signature", f"A2:{index}", None)
        if index > 0 and scope.get("delegable") is not True:
            return ("DENY", "edge.parent_delegable", f"A3:{index}", None)
        if edge.get("to_role") not in shared["allowed_role_transitions"].get(
            role, []
        ):
            return ("DENY", "edge.role_transition", f"A4:{index}", None)
        if edge.get("status") != "active":
            return ("DENY", "edge.status", f"A5:{index}", None)
        if not in_window(
            shared["effect_time"], edge.get("not_before"), edge.get("expires_at")
        ):
            return ("DENY", "edge.freshness", f"A6:{index}", None)
        for field in (
            "operations",
            "resources",
            "tools",
            "audiences",
            "purposes",
        ):
            if not is_subset(edge["grant"].get(field), scope.get(field)):
                return (
                    "DENY",
                    f"edge.scope.{field}",
                    f"A7:{index}",
                    None,
                )
        if edge["grant"].get("currency") != scope.get("currency"):
            return ("DENY", "edge.scope.currency", f"A8:{index}", None)
        amount = edge["grant"].get("amount_max")
        if (
            not isinstance(amount, (int, float))
            or isinstance(amount, bool)
            or not isinstance(scope.get("amount_max"), (int, float))
            or amount > scope["amount_max"]
        ):
            return ("DENY", "edge.scope.amount_max", f"A9:{index}", None)
        principal = edge["delegate"]
        role = edge["to_role"]
        scope = copy.deepcopy(edge["grant"])

    action = authority["action"]
    if action.get("subject") != principal or action.get("role") != role:
        return ("DENY", "action.subject_role", "A10", None)
    action_fields = (
        ("operation", "operations", "A11"),
        ("resource", "resources", "A12"),
        ("tool", "tools", "A13"),
        ("audience", "audiences", "A14"),
        ("purpose", "purposes", "A15"),
    )
    for singular, plural, rule in action_fields:
        if action.get(singular) not in scope.get(plural, []):
            return ("DENY", f"action.{singular}", rule, None)
    if (
        action.get("currency") != scope.get("currency")
        or not isinstance(action.get("amount"), (int, float))
        or isinstance(action.get("amount"), bool)
        or action["amount"] > scope["amount_max"]
    ):
        return ("DENY", "action.amount_currency", "A16", None)

    receipt = authority["receipt"]
    if receipt.get("native_evidence_valid") is not True:
        return ("DENY", "effect.native_validity", "A17", None)
    if receipt.get("effect_time") != shared["effect_time"]:
        return ("DENY", "effect.time_binding", "A18", None)
    if canonical(receipt.get("action")) != canonical(action):
        return ("DENY", "effect.action_binding", "A19", None)
    return ("ALLOW", None, "A0-A19", None)


def flatten_mean(rows: list[Any]) -> float:
    return float(np.asarray(rows, dtype=float).mean())


def bootstrap_lcb(
    rows: list[Any], replicates: int, seed: int, alpha: float
) -> float:
    array = np.asarray(rows, dtype=float)
    rng = np.random.default_rng(seed)
    indices = rng.integers(0, len(array), size=(replicates, len(array)))
    replicate_means = array[indices].mean(axis=tuple(range(1, array.ndim + 1)))
    return float(np.quantile(replicate_means, alpha, method="linear"))


def measurement_layer(
    measurement: dict[str, Any],
    shared: dict[str, Any],
    cache: dict[tuple[str, float], dict[str, float]],
) -> tuple[str, str | None, str, dict[str, Any] | None]:
    profile_digest = digest_object(measurement["profile"])
    if profile_digest != measurement["required_profile_digest"]:
        return (
            "PROFILE_MISMATCH",
            "measurement.profile",
            "M1",
            {"profile_digest": profile_digest},
        )
    rows = shared["datasets"].get(measurement["dataset"])
    if not isinstance(rows, list):
        raise RuntimeError(f"missing dataset {measurement['dataset']}")
    key = (measurement["dataset"], measurement["alpha"])
    if key not in cache:
        cache[key] = {
            "point": flatten_mean(rows),
            "lcb": bootstrap_lcb(
                rows,
                shared["bootstrap"]["replicates"],
                shared["bootstrap"]["seed_by_dataset"][measurement["dataset"]],
                measurement["alpha"],
            ),
        }
    values = cache[key]
    if values["point"] < measurement["threshold"]:
        return ("FAIL_POINT", "measurement.point", "M2", values)
    if values["lcb"] < measurement["threshold"]:
        return ("FAIL_LCB", "measurement.confidence", "M3", values)
    return ("PASS", None, "M1-M3", values)


def evaluate(
    transaction: dict[str, Any],
    shared: dict[str, Any],
    public_key: Ed25519PublicKey,
    measurement_cache: dict[tuple[str, float], dict[str, float]],
) -> dict[str, Any]:
    layer_values = {
        "policy": policy_layer(
            transaction["policy"], shared["policy_evidence"], public_key
        ),
        "evidence": evidence_layer(
            transaction["evidence"], shared["policy_evidence"], public_key
        ),
        "state": state_layer(
            transaction["attestation_result"], shared["state"]["decision_time"]
        ),
        "authority": authority_layer(transaction["authority"], shared["authority"]),
        "measurement": measurement_layer(
            transaction["measurement"], shared["measurement"], measurement_cache
        ),
    }
    order = ("policy", "evidence", "state", "authority", "measurement")
    passing = {
        "policy": "PASS",
        "evidence": "PASS",
        "state": "PASS",
        "authority": "ALLOW",
        "measurement": "PASS",
    }
    first = next(
        (name for name in order if layer_values[name][0] != passing[name]), None
    )
    layers = {
        name: {
            "result": layer_values[name][0],
            "gate": layer_values[name][1],
            "rule": layer_values[name][2],
            "diagnostics": layer_values[name][3],
        }
        for name in order
    }
    return {
        "transaction_id": transaction["transaction_id"],
        "verdict": "ALLOW" if first is None else "DENY",
        "first_rejecting_gate": "verified" if first is None else layers[first]["gate"],
        "layers": layers,
    }


packet = json.loads((HERE / "mutation-packet.json").read_text(encoding="utf-8"))
raw_key = base64.b64decode(
    packet["shared_inputs"]["policy_evidence"]["public_key_raw_b64"],
    validate=True,
)
public_key = Ed25519PublicKey.from_public_bytes(raw_key)
measurement_cache: dict[tuple[str, float], dict[str, float]] = {}
evaluations = [
    evaluate(item, packet["shared_inputs"], public_key, measurement_cache)
    for item in packet["transactions"]
]

if len(evaluations) != len(packet["transactions"]):
    raise RuntimeError("evaluation count mismatch")
if len({row["transaction_id"] for row in evaluations}) != len(evaluations):
    raise RuntimeError("transaction IDs are not unique")

answers = [
    {
        "transaction_id": row["transaction_id"],
        "labeller_id": "mutation-python-v1",
        "verdict": row["verdict"],
        "first_rejecting_gate": row["first_rejecting_gate"],
        "confidence": 5,
        "rationale": (
            "All five typed layers pass under LABELLING-SPEC.md v1.0."
            if row["verdict"] == "ALLOW"
            else "The first failing layer in fixed composition order rejects at "
            + row["first_rejecting_gate"]
            + "."
        ),
    }
    for row in evaluations
]

(HERE / "python-results.json").write_text(
    json.dumps(answers, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
)
(HERE / "python-layer-results.json").write_text(
    json.dumps(evaluations, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)

print(
    json.dumps(
        {
            "implementation": "mutation-python-v1",
            "transactions": len(answers),
            "allows": sum(row["verdict"] == "ALLOW" for row in answers),
            "denies": sum(row["verdict"] == "DENY" for row in answers),
            "measurement_diagnostics": {
                f"{dataset}@{alpha}": values
                for (dataset, alpha), values in measurement_cache.items()
            },
        },
        indent=2,
        sort_keys=True,
    )
)
