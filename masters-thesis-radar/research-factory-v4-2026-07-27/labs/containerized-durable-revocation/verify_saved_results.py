#!/usr/bin/env python3
"""Independently verify saved containerized revocation evidence."""

from __future__ import annotations

import base64
import json
import sys
from pathlib import Path
from typing import Any, Iterable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from container_service import canonical


HERE = Path(__file__).resolve().parent
DEFAULT_RESULTS = HERE / "results" / "results.json"


def signed_rows(packet: dict[str, Any]) -> Iterable[dict[str, Any]]:
    yield from packet["service_health"]
    for case in packet["cases"]:
        yield from case["trace"]


def verify_signature(row: dict[str, Any], key: Ed25519PublicKey) -> bool:
    evidence = row["signed_evidence"]
    key.verify(
        base64.b64decode(evidence["signature_b64"], validate=True),
        canonical(evidence["payload"]),
    )
    return evidence["payload"] == {
        key: value
        for key, value in row.items()
        if key
        not in {
            "signature_verified",
            "signed_evidence",
        }
    }


def main() -> int:
    path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RESULTS
    packet = json.loads(path.read_text(encoding="utf-8"))
    key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(packet["status_public_key_raw_b64"], validate=True)
    )
    signatures = [verify_signature(row, key) for row in signed_rows(packet)]
    cases = packet["cases"]
    snapshot = packet["database_snapshot"]
    atomic = [row for row in cases if row["profile"] == "atomic_guard"]
    weak = [
        row for row in cases if row["profile"] == "prior_read_unguarded"
    ]
    faults = [row for row in cases if row["category"] == "fault_recovery"]
    drop_after = [
        row for row in faults if row["fault"] == "drop_after_forward"
    ]
    effect_keys = [row["idempotency_key"] for row in snapshot["effects"]]
    decision_keys = [row["idempotency_key"] for row in snapshot["decisions"]]
    event_ids = [row["event_id"] for row in snapshot["events"]]
    recomputed = {
        "all_persisted_signatures_verify": all(signatures),
        "atomic_guard_zero_false_allows": not any(
            row["accepted"] and not row["oracle_accept_at_effect"]
            for row in atomic
        ),
        "weak_scheduled_counterexample_exists": any(
            row["category"] == "scheduled"
            and row["accepted"]
            and not row["oracle_accept_at_effect"]
            for row in weak
        ),
        "fault_transport_failures_observed": all(
            row["transport_failure_observed"] for row in faults
        ),
        "drop_after_decisions_replayed": all(
            row["recovery"]["idempotent_replay"] for row in drop_after
        ),
        "cross_instance_recovery_exact": all(
            row["recovery"]["served_by_instance"] == "effect-b"
            for row in faults
        )
        and all(
            row["recovery"]["original_instance"] == "effect-a"
            for row in drop_after
        ),
        "effect_keys_unique": len(effect_keys) == len(set(effect_keys)),
        "decision_keys_unique": len(decision_keys) == len(set(decision_keys)),
        "event_ids_contiguous": event_ids
        == list(range(1, len(event_ids) + 1)),
        "sqlite_integrity_recorded_ok": snapshot["integrity_check"] == "ok",
        "service_containers_distinct": len(
            {
                row["container_hostname"]
                for row in packet["service_health"]
            }
        )
        == 3,
        "runner_distinct_from_services": (
            packet["environment"]["runner_container_hostname"]
            not in {
                row["container_hostname"]
                for row in packet["service_health"]
            }
        ),
        "saved_assertions_all_true": all(packet["assertions"].values()),
        "saved_summary_consistent": packet["summary"]["cases"] == len(cases)
        and packet["summary"]["effects"] == len(snapshot["effects"])
        and packet["summary"]["decisions"] == len(snapshot["decisions"])
        and packet["summary"]["events"] == len(snapshot["events"]),
        "claim_boundary_is_same_host": "same physical" in packet["claim_boundary"]
        and "not multi-host" in packet["claim_boundary"],
    }
    output = {
        "lab": packet["lab"],
        "cases": len(cases),
        "persisted_signed_responses": len(signatures),
        "checks": recomputed,
        "checks_passed": sum(recomputed.values()),
        "checks_total": len(recomputed),
        "all_passed": all(recomputed.values()),
    }
    print(json.dumps(output, indent=2, sort_keys=True))
    return 0 if output["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
