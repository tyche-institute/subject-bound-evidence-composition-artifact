#!/usr/bin/env python3
"""Build a pinned, loss-audited cross-ecosystem typed-state transfer."""

from __future__ import annotations

import hashlib
import json
import math
from collections import Counter
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
EATF_SOURCE = HERE / "source-eatf-results.json"
TRANSACTION_SOURCE = HERE / "source-transaction-gates.json"
EXPECTED_EATF_SHA256 = (
    "c12196c0364d40ba520f65d62ef87055a28584df99048ea36e7471463da19648"
)
EXPECTED_EATF_COMMIT = "1a6329495e6e1235c388f72d209f23eefa38fe38"
EXPECTED_TRANSACTION_SHA256 = (
    "009e309e9b49e4a099257ed2a4f0ab5f8e7c0b4d6014b6738dc845b3301ef12c"
)

EATF_MAP = {
    None: "pass",
    "ZIP_INVALID_OR_UNSAFE": "representation",
    "REQUIRED_ENTRY_MISSING": "representation",
    "METADATA_INVALID_JSON": "representation",
    "METADATA_NOT_OBJECT": "representation",
    "CANONICAL_FORM_MISMATCH": "representation",
    "HASH_MISMATCH": "cryptographic_integrity",
    "SIGNER_NOT_TRUSTED": "trust_or_authority",
    "RSA_SIGNATURE_INVALID": "cryptographic_integrity",
    "OVERT_INVALID": "subject_binding",
    "OVERT_SIGNATURE_REQUIRED": "cryptographic_integrity",
    "OVERT_SIGNATURE_INVALID": "cryptographic_integrity",
    "PQC_PAIR_INCOMPLETE": "cryptographic_integrity",
    "TSA_MISSING_OR_INVALID": "temporal_freshness",
    "TSA_IMPRINT_MISMATCH": "subject_binding",
    "TSA_CERT_MISSING": "temporal_freshness",
    "TSA_SIGNATURE_INVALID": "temporal_freshness",
}

TRANSACTION_MAP = {
    "verified": "pass",
    "policy.missing": "policy_compatibility",
    "policy.stale": "policy_compatibility",
    "policy.substituted": "policy_compatibility",
    "policy.signature": "cryptographic_integrity",
    "evidence.integrity": "cryptographic_integrity",
    "evidence.replay": "temporal_freshness",
    "state.contraindicated": "runtime_state",
    "state.stale": "temporal_freshness",
    "state.reference": "runtime_state",
    "measurement.confidence": "measurement_confidence",
    "measurement.profile": "measurement_confidence",
    "binding.effect": "subject_binding",
    "binding.resource": "subject_binding",
    "binding.time": "temporal_freshness",
    "binding.measurement_profile": "subject_binding",
    "edge.scope.operations": "trust_or_authority",
    "edge.lineage": "trust_or_authority",
    "edge.role_transition": "trust_or_authority",
    "edge.status": "trust_or_authority",
    "edge.scope.amount_max": "trust_or_authority",
    "edge.parent_delegable": "trust_or_authority",
    "edge.freshness": "temporal_freshness",
    "edge.signature": "cryptographic_integrity",
    "action.resource": "subject_binding",
    "effect.time_binding": "temporal_freshness",
    "effect.action_binding": "subject_binding",
    "effect.native_validity": "cryptographic_integrity",
    "protocol.valid": "representation",
}


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_text(value: Any) -> str:
    return json.dumps(
        value, ensure_ascii=False, indent=2, sort_keys=True
    ) + "\n"


def entropy(counts: Counter[str]) -> float:
    total = sum(counts.values())
    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
        if count
    )


def information_profile(labels: list[str]) -> dict[str, Any]:
    counts = Counter(labels)
    distinct = len(counts)
    total = len(labels)
    majority = max(counts.values())
    return {
        "rejected_cases": total,
        "distinct_native_rejection_states": distinct,
        "pairwise_state_distinctions_erased_by_boolean": (
            distinct * (distinct - 1) // 2
        ),
        "native_state_entropy_bits": entropy(counts),
        "best_native_state_guess_from_reject_only": {
            "correct": majority,
            "total": total,
            "accuracy": majority / total,
        },
    }


def main() -> int:
    observed_eatf_sha = sha(EATF_SOURCE)
    observed_transaction_sha = sha(TRANSACTION_SOURCE)
    if observed_eatf_sha != EXPECTED_EATF_SHA256:
        raise RuntimeError(
            "EATF input drift: expected "
            f"{EXPECTED_EATF_SHA256}, observed {observed_eatf_sha}"
        )
    if observed_transaction_sha != EXPECTED_TRANSACTION_SHA256:
        raise RuntimeError(
            "transaction input drift: expected "
            f"{EXPECTED_TRANSACTION_SHA256}, observed "
            f"{observed_transaction_sha}"
        )
    eatf_snapshot = json.loads(EATF_SOURCE.read_text(encoding="utf-8"))
    transaction_snapshot = json.loads(
        TRANSACTION_SOURCE.read_text(encoding="utf-8")
    )
    if eatf_snapshot["source_commit"] != EXPECTED_EATF_COMMIT:
        raise RuntimeError(
            "EATF commit drift: expected "
            f"{EXPECTED_EATF_COMMIT}, observed "
            f"{eatf_snapshot['source_commit']}"
        )
    if eatf_snapshot["source_sha256"] != (
        eatf_snapshot["expected_source_sha256"]
    ):
        raise RuntimeError("embedded EATF upstream source pin is inconsistent")
    if transaction_snapshot["source_sha256"] != (
        transaction_snapshot["expected_source_sha256"]
    ):
        raise RuntimeError(
            "embedded transaction upstream source pin is inconsistent"
        )

    eatf_rows = eatf_snapshot["rows"]
    transaction_rows = transaction_snapshot["rows"]

    eatf_native = {row["native_first_state"] for row in eatf_rows}
    tx_native = {row["native_first_state"] for row in transaction_rows}
    expected_eatf = {key or "PASS" for key in EATF_MAP}
    if eatf_native != expected_eatf:
        raise RuntimeError(
            f"EATF crosswalk coverage mismatch: {eatf_native ^ expected_eatf}"
        )
    if tx_native != set(TRANSACTION_MAP):
        raise RuntimeError(
            "transaction crosswalk coverage mismatch: "
            f"{tx_native ^ set(TRANSACTION_MAP)}"
        )
    if not all(
        row["typescript_oracle_match"]
        and row["python_oracle_match"]
        and row["cross_implementation_match"]
        and row["typescript_valid"] == row["python_valid"]
        and row["typescript_code"] == row["python_code"]
        and row["typescript_valid"] == row["expected_valid"]
        and row["typescript_code"] == row["expected_code"]
        for row in eatf_rows
    ):
        raise RuntimeError("source EATF differential result is not exact")
    if not all(row["oracle_match"] for row in transaction_rows):
        raise RuntimeError("source transaction result is not exact")

    eatf_rejections = [
        row["native_first_state"] for row in eatf_rows if not row["valid"]
    ]
    tx_rejections = [
        row["native_first_state"]
        for row in transaction_rows
        if not row["valid"]
    ]
    eatf_info = information_profile(eatf_rejections)
    tx_info = information_profile(tx_rejections)
    shared_eatf = {row["shared_class"] for row in eatf_rows} - {"pass"}
    shared_tx = {
        row["shared_class"] for row in transaction_rows
    } - {"pass"}
    overlap = shared_eatf & shared_tx

    source_eatf = eatf_snapshot
    source_tx = transaction_snapshot
    crosswalk = {
        "status": "analytic crosswalk; not a standards mapping",
        "classes": [
            "representation",
            "cryptographic_integrity",
            "trust_or_authority",
            "temporal_freshness",
            "subject_binding",
            "policy_compatibility",
            "measurement_confidence",
            "runtime_state",
        ],
        "eatf": {"PASS" if key is None else key: value for key, value in EATF_MAP.items()},
        "composed_transaction": TRANSACTION_MAP,
    }
    output = {
        "lab": "cross-ecosystem-typed-transfer",
        "eatf": {
            "cases": len(eatf_rows),
            "oracle_and_cross_implementation_matches": sum(
                row["typescript_oracle_match"]
                and row["python_oracle_match"]
                and row["cross_implementation_match"]
                for row in eatf_rows
            ),
            **eatf_info,
        },
        "composed_transaction": {
            "cases": len(transaction_rows),
            "oracle_matches": sum(
                row["oracle_match"] for row in transaction_rows
            ),
            **tx_info,
        },
        "shared_ontology": {
            "eatf_classes": sorted(shared_eatf),
            "transaction_classes": sorted(shared_tx),
            "overlap": sorted(overlap),
            "overlap_count": len(overlap),
            "union_count": len(shared_eatf | shared_tx),
        },
        "boolean_scalarization": {
            "native_pairwise_rejection_distinctions_erased": (
                eatf_info[
                    "pairwise_state_distinctions_erased_by_boolean"
                ]
                + tx_info[
                    "pairwise_state_distinctions_erased_by_boolean"
                ]
            ),
            "interpretation": (
                "count of within-ecosystem pairs of distinct native "
                "rejection labels mapped to the same Boolean REJECT value"
            ),
        },
        "all_native_codes_mapped": True,
        "all_source_pins_verified": True,
        "claim_boundary": (
            "representational transfer over two first-party executable "
            "corpora; not semantic equivalence, interoperability, or "
            "external replication"
        ),
    }

    files = {
        "source-eatf-results.json": source_eatf,
        "source-transaction-gates.json": source_tx,
        "crosswalk.json": crosswalk,
        "results.json": output,
    }
    for name, value in files.items():
        (HERE / name).write_text(json_text(value), encoding="utf-8")
    (HERE / "SUMMARY.md").write_text(
        "# Cross-ecosystem typed-state transfer\n\n"
        f"- EATF: **{len(eatf_rows)}/21** exact oracle and "
        "cross-implementation rows; **"
        f"{eatf_info['distinct_native_rejection_states']}** native "
        "rejection states.\n"
        f"- Composed transactions: **{len(transaction_rows)}/104** exact "
        "oracle rows; **"
        f"{tx_info['distinct_native_rejection_states']}** native rejection "
        "gates.\n"
        f"- Shared coarse classes: **{len(overlap)}/"
        f"{len(shared_eatf | shared_tx)}** in both corpora.\n"
        "- Pairwise native distinctions erased by Boolean scalarization: "
        f"**{output['boolean_scalarization']['native_pairwise_rejection_distinctions_erased']}**.\n"
        "- Boundary: analytic crosswalk; no semantic-equivalence or "
        "interoperability claim.\n",
        encoding="utf-8",
    )
    manifest_names = (
        "README.md",
        "NOTICE.source",
        "build_transfer.py",
        "verify_crosswalk_sql.py",
        "source-eatf-results.json",
        "source-transaction-gates.json",
        "crosswalk.json",
        "results.json",
        "SUMMARY.md",
    )
    (HERE / "SHA256SUMS").write_text(
        "".join(
            f"{sha(HERE / name)}  {name}\n" for name in manifest_names
        ),
        encoding="utf-8",
    )
    print(json_text(output), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
