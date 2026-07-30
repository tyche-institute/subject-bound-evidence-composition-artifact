#!/usr/bin/env python3
"""Reverify result invariants and durable-log consistency."""

from __future__ import annotations

import base64
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent


def main() -> int:
    output = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    summary = output["summary"]
    events = output["durable_events"]
    effects = output["durable_effects"]
    cases = output["cases"]
    indices = [row["event_id"] for row in events]
    contiguous = indices == list(range(1, len(indices) + 1))
    effect_keys = [row["idempotency_key"] for row in effects]
    unique_effects = len(effect_keys) == len(set(effect_keys))
    event_ids = {row["event_id"] for row in events}
    effects_reference_events = all(
        row["event_id"] in event_ids for row in effects
    )
    exact = (
        contiguous
        and unique_effects
        and effects_reference_events
        and summary["cases"] == len(cases)
        and summary["durable_events"] == len(events)
        and summary["durable_effects"] == len(effects)
        and summary["signed_responses_verified"] == len(cases)
        and summary["fault_recoveries"] == summary["fault_cases"]
        and summary["duplicate_effects"] == 0
        and summary["atomic_guard_invariant"]
        and summary["weak_counterexamples_observed"]
        and summary["all_passed"]
    )
    result = {
        "contiguous_linearization_indices": contiguous,
        "unique_idempotency_keys": unique_effects,
        "effects_reference_events": effects_reference_events,
        "stored_summary_consistent": exact,
        "public_key_bytes": len(
            base64.b64decode(
                output["environment"]["public_key_raw_b64"], validate=True
            )
        ),
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if exact else 1


if __name__ == "__main__":
    raise SystemExit(main())
