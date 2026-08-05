#!/usr/bin/env python3
"""Compose deterministic multi-fault cases from the frozen single-fault corpus."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
SINGLE = HERE.parent / "mutation-tests"


def read(name: str) -> Any:
    return json.loads((SINGLE / name).read_text(encoding="utf-8"))


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


packet = read("mutation-packet.json")
oracle = read("mutation-oracle.json")
by_id = {row["transaction_id"]: row for row in packet["transactions"]}
operator_id = {row["operator"]: row["transaction_id"] for row in oracle}
base = by_id[operator_id["baseline"]]

layer_key = {
    "policy": "policy",
    "evidence": "evidence",
    "state": "attestation_result",
    "authority": "authority",
    "measurement": "measurement",
}
operator_layer = {row["operator"]: row["target_layer"] for row in oracle}

specs = [
    (
        "policy-signature-plus-evidence-replay",
        ["policy_splice_p2", "evidence_splice_e2"],
        "policy.signature",
    ),
    (
        "policy-substitution-plus-state-negative",
        ["policy_splice_p5", "state_status_negative"],
        "policy.substituted",
    ),
    (
        "evidence-tamper-plus-state-stale",
        ["evidence_splice_e1", "state_issued_after_decision"],
        "evidence.integrity",
    ),
    (
        "evidence-replay-plus-protocol-invalid",
        ["evidence_splice_e2", "authority_protocol_invalid"],
        "evidence.replay",
    ),
    (
        "state-negative-plus-lineage-break",
        ["state_status_negative", "authority_lineage_break"],
        "state.contraindicated",
    ),
    (
        "state-reference-plus-measurement-point",
        ["state_observed_digest_mismatch", "measurement_point_below_threshold"],
        "state.reference",
    ),
    (
        "protocol-invalid-plus-profile-mismatch",
        ["authority_protocol_invalid", "measurement_profile_changed"],
        "protocol.valid",
    ),
    (
        "effect-invalid-plus-lcb-failure",
        ["authority_native_effect_invalid", "measurement_lcb_below_threshold"],
        "effect.native_validity",
    ),
    (
        "all-layer-faults",
        [
            "policy_splice_p4",
            "evidence_splice_e1",
            "state_status_negative",
            "authority_protocol_invalid",
            "measurement_point_below_threshold",
        ],
        "policy.stale",
    ),
    (
        "four-later-layer-faults",
        [
            "evidence_splice_e2",
            "state_issued_after_decision",
            "authority_edge_revoked",
            "measurement_profile_changed",
        ],
        "evidence.replay",
    ),
]

transactions: list[dict[str, Any]] = []
expectations: list[dict[str, Any]] = []
for index, (case_name, faults, expected_gate) in enumerate(specs, start=1):
    item = copy.deepcopy(base)
    for operator in faults:
        source = by_id[operator_id[operator]]
        layer = operator_layer[operator]
        item[layer_key[layer]] = copy.deepcopy(source[layer_key[layer]])
    item["transaction_id"] = f"MF{index:03d}"
    transactions.append(item)
    expectations.append(
        {
            "transaction_id": item["transaction_id"],
            "case_name": case_name,
            "fault_operators": faults,
            "fault_count": len(faults),
            "expected_verdict": "DENY",
            "expected_first_rejecting_gate": expected_gate,
        }
    )

# Two within-layer precedence cases require field-level composition.
item = copy.deepcopy(by_id[operator_id["authority_issuer_signature_invalid"]])
item["authority"]["edges"][0]["grant"]["resources"].append("__out_of_scope__")
item["transaction_id"] = "MF011"
transactions.append(item)
expectations.append(
    {
        "transaction_id": "MF011",
        "case_name": "authority-signature-plus-scope-escalation",
        "fault_operators": [
            "authority_issuer_signature_invalid",
            "authority_scope_resources_widened",
        ],
        "fault_count": 2,
        "expected_verdict": "DENY",
        "expected_first_rejecting_gate": "edge.signature",
    }
)

item = copy.deepcopy(by_id[operator_id["measurement_profile_changed"]])
item["measurement"]["dataset"] = "dataset-03"
item["measurement"]["threshold"] = 0.75
item["transaction_id"] = "MF012"
transactions.append(item)
expectations.append(
    {
        "transaction_id": "MF012",
        "case_name": "measurement-profile-plus-point-failure",
        "fault_operators": [
            "measurement_profile_changed",
            "measurement_point_below_threshold",
        ],
        "fault_count": 2,
        "expected_verdict": "DENY",
        "expected_first_rejecting_gate": "measurement.profile",
    }
)

multi_packet = {
    "packet": {
        "id": "native-multifault-composition-v1",
        "source": "frozen single-fault mutation corpus",
        "sealed_labels_used": False,
    },
    "shared_inputs": packet["shared_inputs"],
    "transactions": transactions,
}
(HERE / "multifault-packet.json").write_text(
    json.dumps(multi_packet, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
(HERE / "multifault-oracle.json").write_text(
    json.dumps(expectations, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)

manifest = {
    "corpus_id": "native-multifault-composition-v1",
    "case_count": len(transactions),
    "source_packet_sha256": sha256(SINGLE / "mutation-packet.json"),
    "source_oracle_sha256": sha256(SINGLE / "mutation-oracle.json"),
    "sealed_labels_used": False,
    "packet_sha256": sha256(HERE / "multifault-packet.json"),
    "oracle_sha256": sha256(HERE / "multifault-oracle.json"),
}
(HERE / "generation-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(manifest, indent=2, sort_keys=True))
