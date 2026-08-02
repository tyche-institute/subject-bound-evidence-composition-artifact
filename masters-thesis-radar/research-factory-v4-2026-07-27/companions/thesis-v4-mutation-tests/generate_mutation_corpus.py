#!/usr/bin/env python3
"""Build a deterministic single-fault mutation corpus without sealed labels."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any, Callable


HERE = Path(__file__).resolve().parent
VAULT = HERE.parents[1]
PACKET_PATH = (
    VAULT
    / "masters-thesis-radar/research-factory-v4-2026-07-27"
    / "external-label-packet/transactions-for-labelling.json"
)
INDEPENDENT_PATH = (
    HERE.parent
    / "thesis-v4-independent-evaluator/independent-layer-results-unsealed.json"
)


def read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: Any) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


packet = read_json(PACKET_PATH)
independent = read_json(INDEPENDENT_PATH)
transactions = {row["transaction_id"]: row for row in packet["transactions"]}
results = {row["transaction_id"]: row for row in independent}

base_result = next(row for row in independent if row["verdict"] == "ALLOW")
base_id = base_result["transaction_id"]
base = transactions[base_id]

rule_source: dict[str, str] = {}
for row in independent:
    for layer in ("policy", "evidence"):
        rule = row["layers"][layer]["rule"]
        if rule in {"P1", "P2", "P3", "P4", "P5", "E1", "E2"}:
            rule_source.setdefault(rule, row["transaction_id"])

missing = sorted({"P1", "P2", "P3", "P4", "P5", "E1", "E2"} - rule_source.keys())
if missing:
    raise RuntimeError(f"missing source cases for rules: {missing}")

mutations: list[dict[str, Any]] = []
oracle: list[dict[str, Any]] = []
registry: list[dict[str, Any]] = []


def add(
    operator: str,
    expected_gate: str,
    target_layer: str,
    expected_rule: str,
    mutate: Callable[[dict[str, Any]], None] | None = None,
    source_id: str | None = None,
    description: str = "",
) -> None:
    item = copy.deepcopy(base)
    if mutate is not None:
        mutate(item)
    item["transaction_id"] = f"M{len(mutations) + 1:03d}"
    mutations.append(item)
    verdict = "ALLOW" if expected_gate == "verified" else "DENY"
    oracle.append(
        {
            "transaction_id": item["transaction_id"],
            "operator": operator,
            "description": description,
            "base_transaction_id": base_id,
            "source_transaction_id": source_id,
            "expected_verdict": verdict,
            "expected_first_rejecting_gate": expected_gate,
            "target_layer": target_layer,
            "expected_rule": expected_rule,
        }
    )
    registry.append(
        {
            "operator": operator,
            "target_layer": target_layer,
            "expected_first_rejecting_gate": expected_gate,
            "expected_rule": expected_rule,
            "single_fault": operator != "baseline",
            "description": description,
        }
    )


add(
    "baseline",
    "verified",
    "all",
    "all-pass",
    description="Unmodified fully passing transaction selected without sealed labels.",
)

for rule, gate in [
    ("P1", "policy.missing"),
    ("P2", "policy.signature"),
    ("P3", "policy.substituted"),
    ("P4", "policy.stale"),
    ("P5", "policy.substituted"),
]:
    source_id = rule_source[rule]

    def splice_policy(item: dict[str, Any], source_id: str = source_id) -> None:
        item["policy"] = copy.deepcopy(transactions[source_id]["policy"])

    add(
        f"policy_splice_{rule.lower()}",
        gate,
        "policy",
        rule,
        splice_policy,
        source_id,
        f"Replace only policy with an observed {rule} fixture.",
    )

for rule, gate in [("E1", "evidence.integrity"), ("E2", "evidence.replay")]:
    source_id = rule_source[rule]

    def splice_evidence(item: dict[str, Any], source_id: str = source_id) -> None:
        item["evidence"] = copy.deepcopy(transactions[source_id]["evidence"])

    add(
        f"evidence_splice_{rule.lower()}",
        gate,
        "evidence",
        rule,
        splice_evidence,
        source_id,
        f"Replace only evidence with an observed {rule} fixture.",
    )

add(
    "state_status_negative",
    "state.contraindicated",
    "state",
    "S1",
    lambda item: item["attestation_result"].update(status="negative"),
    description="Set attestation status to a non-affirming value.",
)
add(
    "state_issued_after_decision",
    "state.stale",
    "state",
    "S2",
    lambda item: item["attestation_result"].update(
        issued_at="9999-01-01T00:00:00Z"
    ),
    description="Move issued_at beyond the fixed decision time.",
)
add(
    "state_observed_digest_mismatch",
    "state.reference",
    "state",
    "S3",
    lambda item: item["attestation_result"].update(
        observed_digest="sha256:" + "00" * 32
    ),
    description="Change only the observed reference digest.",
)

authority_mutations: list[
    tuple[str, str, str, Callable[[dict[str, Any]], None], str]
] = [
    (
        "authority_protocol_invalid",
        "protocol.valid",
        "A0",
        lambda item: item["authority"].update(protocol_valid=False),
        "Invalidate the protocol-native verification flag.",
    ),
    (
        "authority_lineage_break",
        "edge.lineage",
        "A1:0",
        lambda item: item["authority"]["edges"][0].update(delegator="intruder"),
        "Break the first delegator lineage link.",
    ),
    (
        "authority_issuer_signature_invalid",
        "edge.signature",
        "A2:0",
        lambda item: item["authority"]["edges"][0].update(
            issuer_signature_valid=False
        ),
        "Invalidate the first delegation signature flag.",
    ),
    (
        "authority_parent_not_delegable",
        "edge.parent_delegable",
        "A3:1",
        lambda item: item["authority"]["edges"][0]["grant"].update(
            delegable=False
        ),
        "Remove delegation permission before the second edge.",
    ),
    (
        "authority_role_transition_invalid",
        "edge.role_transition",
        "A4:0",
        lambda item: item["authority"]["edges"][0].update(to_role="invalid-role"),
        "Use a role transition absent from the fixed transition table.",
    ),
    (
        "authority_edge_revoked",
        "edge.status",
        "A5:0",
        lambda item: item["authority"]["edges"][0].update(status="revoked"),
        "Revoke the first delegation edge.",
    ),
    (
        "authority_edge_not_yet_valid",
        "edge.freshness",
        "A6:0",
        lambda item: item["authority"]["edges"][0].update(
            not_before="9999-01-01T00:00:00Z"
        ),
        "Move the first edge validity window after effect time.",
    ),
]

for field in ("operations", "resources", "tools", "audiences", "purposes"):
    authority_mutations.append(
        (
            f"authority_scope_{field}_widened",
            f"edge.scope.{field}",
            "A7:0",
            lambda item, field=field: item["authority"]["edges"][0]["grant"][
                field
            ].append("__out_of_scope__"),
            f"Add one value outside the parent {field} scope.",
        )
    )

authority_mutations.extend(
    [
        (
            "authority_currency_widened",
            "edge.scope.currency",
            "A8:0",
            lambda item: item["authority"]["edges"][0]["grant"].update(
                currency="USD"
            ),
            "Change first-edge currency away from the root currency.",
        ),
        (
            "authority_amount_max_widened",
            "edge.scope.amount_max",
            "A9:0",
            lambda item: item["authority"]["edges"][0]["grant"].update(
                amount_max=packet["shared_inputs"]["authority"]["root_scope"][
                    "amount_max"
                ]
                + 1
            ),
            "Raise first-edge amount_max above the root maximum.",
        ),
        (
            "authority_action_subject_changed",
            "action.subject_role",
            "A10",
            lambda item: item["authority"]["action"].update(subject="intruder"),
            "Change the action subject while preserving the terminal role.",
        ),
    ]
)

for index, field in enumerate(
    ("operation", "resource", "tool", "audience", "purpose"), start=11
):
    authority_mutations.append(
        (
            f"authority_action_{field}_out_of_scope",
            f"action.{field}",
            f"A{index}",
            lambda item, field=field: item["authority"]["action"].update(
                {field: "__out_of_scope__"}
            ),
            f"Set action {field} outside the terminal grant.",
        )
    )

authority_mutations.extend(
    [
        (
            "authority_action_amount_exceeded",
            "action.amount_currency",
            "A16",
            lambda item: item["authority"]["action"].update(
                amount=item["authority"]["edges"][-1]["grant"]["amount_max"] + 1
            ),
            "Raise action amount above the terminal grant.",
        ),
        (
            "authority_native_effect_invalid",
            "effect.native_validity",
            "A17",
            lambda item: item["authority"]["receipt"].update(
                native_evidence_valid=False
            ),
            "Invalidate the native effect evidence flag.",
        ),
        (
            "authority_effect_time_changed",
            "effect.time_binding",
            "A18",
            lambda item: item["authority"]["receipt"].update(
                effect_time="1999-01-01T00:00:00Z"
            ),
            "Change the receipt effect time.",
        ),
        (
            "authority_receipt_action_changed",
            "effect.action_binding",
            "A19",
            lambda item: item["authority"]["receipt"]["action"].update(
                amount=item["authority"]["receipt"]["action"]["amount"] + 1
            ),
            "Change one field in the receipt-bound action.",
        ),
    ]
)

for operator, gate, rule, mutate, description in authority_mutations:
    add(operator, gate, "authority", rule, mutate, description=description)

add(
    "measurement_profile_changed",
    "measurement.profile",
    "measurement",
    "M1",
    lambda item: item["measurement"]["profile"].update(
        profile_id="mutation-profile"
    ),
    description="Change the profile while retaining the required digest.",
)
add(
    "measurement_point_below_threshold",
    "measurement.point",
    "measurement",
    "M2",
    lambda item: item["measurement"].update(dataset="dataset-03", threshold=0.75),
    description="Select the fixed dataset whose point estimate is below 0.75.",
)
add(
    "measurement_lcb_below_threshold",
    "measurement.confidence",
    "measurement",
    "M3",
    lambda item: item["measurement"].update(dataset="dataset-01", threshold=0.75),
    description="Select the fixed dataset whose point passes but LCB fails 0.75.",
)

mutation_packet = {
    "packet": {
        "id": "thesis-v4-single-fault-mutations-v1",
        "generation_method": "deterministic mutations over first independently passing case",
        "sealed_labels_used": False,
        "base_selection": "first ALLOW in frozen independent evaluator output",
    },
    "shared_inputs": packet["shared_inputs"],
    "transactions": mutations,
}

write_json(HERE / "mutation-packet.json", mutation_packet)
write_json(HERE / "mutation-oracle.json", oracle)
write_json(HERE / "mutation-operator-registry.json", registry)

manifest = {
    "corpus_id": "thesis-v4-single-fault-mutations-v1",
    "transaction_count": len(mutations),
    "base_transaction_id": base_id,
    "source_packet": str(PACKET_PATH),
    "source_packet_sha256": sha256(PACKET_PATH),
    "source_independent_results": str(INDEPENDENT_PATH),
    "source_independent_results_sha256": sha256(INDEPENDENT_PATH),
    "sealed_labels_used": False,
    "files": {
        name: sha256(HERE / name)
        for name in (
            "mutation-packet.json",
            "mutation-oracle.json",
            "mutation-operator-registry.json",
        )
    },
}
write_json(HERE / "generation-manifest.json", manifest)

print(
    json.dumps(
        {
            "base_transaction_id": base_id,
            "transaction_count": len(mutations),
            "operator_count": len(registry),
            "rule_sources": rule_source,
            "manifest_sha256": sha256(HERE / "generation-manifest.json"),
        },
        indent=2,
        sort_keys=True,
    )
)
