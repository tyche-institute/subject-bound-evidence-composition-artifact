#!/usr/bin/env python3
"""Tests for state_adapter.appraise_state.

Deterministic, dependency-free (plain asserts, no pytest), no wall-clock,
no randomness, no network. Exit code 0 iff every check passes.

These tests exercise a structural appraisal of corpus-supplied
attestation-result objects. They involve no cryptographic verification,
no TPM, no Veraison, and are not remote attestation tests. Expected
values are author-written; agreement measures the specification, not any
deployed system.

Coverage:
- all four outcomes (PASS, CONTRAINDICATED, STALE, REFERENCE_MISMATCH);
- both window boundaries (decision_time == issued_at, == expires_at);
- precedence (contraindicated+stale -> CONTRAINDICATED,
  stale+mismatch -> STALE, triple fault -> CONTRAINDICATED);
- fail-closed extensions (unknown status, missing expires_at,
  missing reference digest);
- details completeness;
- every fixture in state-fixtures.json matches its expected label;
- determinism (two appraisals of the same input are identical).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from state_adapter import APPRAISAL_METHOD, appraise_state

ROOT = Path(__file__).resolve().parent
FIXTURES_PATH = ROOT / "state-fixtures.json"

# Fixed constants — no wall-clock anywhere in this file.
DECISION_TIME = "2026-07-25T21:30:00Z"
REF = "sha256:c1ff2499c12c61315bc784a6475864dcc882682232af29e1a87a96746d0633cd"
OTHER = "sha256:96657a329a4aa6323d70f58a3a0d8920af4cfe04dd48be7b2b10c45014743ccb"


def base(**overrides: Any) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "profile": "state-fixtures-v1",
        "status": "affirming",
        "reference_digest": REF,
        "observed_digest": REF,
        "issued_at": "2026-07-25T21:00:00Z",
        "expires_at": "2026-07-25T22:00:00Z",
    }
    obj.update(overrides)
    return obj


CHECKS: list[tuple[str, dict[str, Any], str, str, str]] = [
    # (name, attestation_result, decision_time, expected_result, expected_gate)
    ("pass_fresh_match", base(), DECISION_TIME, "PASS", "state.verified"),
    (
        "contraindicated",
        base(status="contraindicated"),
        DECISION_TIME,
        "CONTRAINDICATED",
        "state.contraindicated",
    ),
    (
        "stale_match",
        base(issued_at="2026-07-25T20:00:00Z", expires_at="2026-07-25T21:15:00Z"),
        DECISION_TIME,
        "STALE",
        "state.stale",
    ),
    (
        "fresh_mismatch",
        base(observed_digest=OTHER),
        DECISION_TIME,
        "REFERENCE_MISMATCH",
        "state.reference",
    ),
    # Boundary times: both window bounds are inclusive.
    (
        "boundary_decision_equals_issued",
        base(issued_at=DECISION_TIME),
        DECISION_TIME,
        "PASS",
        "state.verified",
    ),
    (
        "boundary_decision_equals_expires",
        base(expires_at=DECISION_TIME),
        DECISION_TIME,
        "PASS",
        "state.verified",
    ),
    # One second outside each bound.
    (
        "just_before_issued",
        base(issued_at="2026-07-25T21:30:01Z"),
        DECISION_TIME,
        "STALE",
        "state.stale",
    ),
    (
        "just_after_expires",
        base(expires_at="2026-07-25T21:29:59Z"),
        DECISION_TIME,
        "STALE",
        "state.stale",
    ),
    # Precedence: rule 1 before rule 2, rule 2 before rule 3, rule 1 over all.
    (
        "precedence_contraindicated_and_stale",
        base(status="contraindicated", expires_at="2026-07-25T21:15:00Z"),
        DECISION_TIME,
        "CONTRAINDICATED",
        "state.contraindicated",
    ),
    (
        "precedence_stale_and_mismatch",
        base(expires_at="2026-07-25T21:15:00Z", observed_digest=OTHER),
        DECISION_TIME,
        "STALE",
        "state.stale",
    ),
    (
        "precedence_triple_fault",
        base(
            status="contraindicated",
            expires_at="2026-07-25T21:15:00Z",
            observed_digest=OTHER,
        ),
        DECISION_TIME,
        "CONTRAINDICATED",
        "state.contraindicated",
    ),
    # Fail-closed extensions.
    (
        "fail_closed_unknown_status",
        base(status="indeterminate"),
        DECISION_TIME,
        "CONTRAINDICATED",
        "state.contraindicated",
    ),
    (
        "fail_closed_missing_status",
        {k: v for k, v in base().items() if k != "status"},
        DECISION_TIME,
        "CONTRAINDICATED",
        "state.contraindicated",
    ),
    (
        "fail_closed_missing_expires_at",
        {k: v for k, v in base().items() if k != "expires_at"},
        DECISION_TIME,
        "STALE",
        "state.stale",
    ),
    (
        "fail_closed_missing_reference_digest",
        {k: v for k, v in base().items() if k != "reference_digest"},
        DECISION_TIME,
        "REFERENCE_MISMATCH",
        "state.reference",
    ),
    (
        "fail_closed_both_digests_missing",
        {
            k: v
            for k, v in base().items()
            if k not in ("reference_digest", "observed_digest")
        },
        DECISION_TIME,
        "REFERENCE_MISMATCH",
        "state.reference",
    ),
]

DETAIL_KEYS = {
    "profile",
    "status",
    "issued_at",
    "expires_at",
    "reference_digest",
    "observed_digest",
    "decision_time",
    "status_affirming",
    "within_window",
    "digest_match",
    "appraisal_method",
}


def main() -> int:
    failures = 0
    passed = 0

    for name, obj, decision_time, want_result, want_gate in CHECKS:
        result, gate, details = appraise_state(obj, decision_time)
        ok = result == want_result and gate == want_gate
        # details must carry every inspected field and the disclaimer.
        ok = ok and set(details) == DETAIL_KEYS
        ok = ok and details["decision_time"] == decision_time
        ok = ok and details["appraisal_method"] == APPRAISAL_METHOD
        # determinism: a second appraisal of the same input is identical.
        ok = ok and appraise_state(obj, decision_time) == (result, gate, details)
        status_word = "ok" if ok else "FAIL"
        print(
            f"{status_word:4s} {name}: "
            f"got ({result}, {gate}) want ({want_result}, {want_gate})"
        )
        if ok:
            passed += 1
        else:
            failures += 1

    # Every fixture in state-fixtures.json must match its expected label
    # under the file's own fixed decision_time.
    fixtures_doc = json.loads(FIXTURES_PATH.read_text(encoding="utf-8"))
    fixture_decision_time = fixtures_doc["decision_time"]
    assert fixture_decision_time == DECISION_TIME
    required_names = {
        "affirming-fresh-match",
        "contraindicated",
        "stale-match",
        "fresh-mismatch",
        "stale-mismatch",
        "boundary-fresh",
    }
    fixture_names = set(fixtures_doc["fixtures"])
    missing = required_names - fixture_names
    if missing:
        print(f"FAIL fixtures file missing required names: {sorted(missing)}")
        failures += 1
    for name in sorted(fixtures_doc["fixtures"]):
        fixture = fixtures_doc["fixtures"][name]
        result, gate, _ = appraise_state(
            fixture["attestation_result"], fixture_decision_time
        )
        want = fixture["expected"]
        ok = result == want["result"] and gate == want["gate"]
        status_word = "ok" if ok else "FAIL"
        print(
            f"{status_word:4s} fixture {name}: "
            f"got ({result}, {gate}) "
            f"want ({want['result']}, {want['gate']})"
        )
        if ok:
            passed += 1
        else:
            failures += 1

    print(
        json.dumps(
            {
                "checks_passed": passed,
                "checks_failed": failures,
                "fixtures_file": FIXTURES_PATH.name,
                "fixtures_count": len(fixtures_doc["fixtures"]),
                "decision_time": DECISION_TIME,
                "disclaimer": (
                    "structural appraisal tests over author-designed "
                    "fixtures; no cryptographic verification, no TPM, no "
                    "Veraison, not remote attestation; author-written "
                    "expected labels, not external ground truth"
                ),
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
