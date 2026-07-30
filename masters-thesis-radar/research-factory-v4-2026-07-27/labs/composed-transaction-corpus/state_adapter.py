#!/usr/bin/env python3
"""Structural appraisal of a supplied attestation-result object.

HONESTY CEILING — read before citing this module anywhere.

This is a structural appraisal of a supplied attestation-result object:
a deterministic field comparison over a JSON dictionary that the corpus
itself provides. It performs no cryptographic verification, involves no
TPM, no Veraison, and is not remote attestation. No signature is checked,
no evidence is collected from any device, and no appraisal policy is
negotiated with any verifier service. The digests compared here are
strings supplied by the corpus, not measurements taken from a running
system. Nothing this module returns may be described as attestation,
verification of a runtime, or evidence about any deployed system.

What it replaces: in the previous corpus version the runtime-state
predicate was a corpus string literal
(``"PASS" if transaction["runtime_state"] == "affirming" else
"CONTRAINDICATED"``). This module upgrades that literal to an evaluated
appraisal over an attestation-result object with a freshness window and a
reference-digest comparison — review finding E2 / C-13. The upgrade is
from *declared* to *structurally evaluated*; it is NOT an upgrade to
cryptographic or remote attestation.

Input object (``attestation_result``), all values corpus-supplied:

- ``profile``          — identifier of the appraisal profile (opaque here)
- ``status``           — ``"affirming"`` or ``"contraindicated"``
- ``reference_digest`` — expected runtime measurement, ``sha256:<hex>`` string
- ``observed_digest``  — reported runtime measurement, ``sha256:<hex>`` string
- ``issued_at``        — ISO-8601 UTC string (``YYYY-MM-DDTHH:MM:SSZ``)
- ``expires_at``       — ISO-8601 UTC string

Timestamps are compared lexicographically, exactly as elsewhere in this
codebase (see ``policy-version-evidence-replay/run.py``: the policy
window check ``valid_from <= decision_time <= valid_until``). This is
sound only because all timestamps share the fixed-width UTC ``Z`` form.
Both window boundaries are INCLUSIVE.

Deterministic appraisal order (first failing rule wins; later rules are
not consulted):

1. status gate      — ``status`` is ``"contraindicated"``
                      -> ``("CONTRAINDICATED", "state.contraindicated")``.
                      Fail-closed: any value other than ``"affirming"``
                      (including a missing or unrecognised status) also
                      fires this rule.
2. freshness gate   — ``not (issued_at <= decision_time <= expires_at)``
                      -> ``("STALE", "state.stale")``.
                      Fail-closed on the upper bound: a missing
                      ``expires_at`` reads as ``""`` and always fails.
3. reference gate   — ``observed_digest != reference_digest``
                      -> ``("REFERENCE_MISMATCH", "state.reference")``.
                      Fail-closed: a missing or empty ``reference_digest``
                      also fires this rule (two absent digests are never
                      treated as a match).
4. otherwise        -> ``("PASS", "state.verified")``.
                      "verified" here means "structurally appraised
                      against corpus-supplied values", nothing more.

Consequence of the order: a contraindicated-and-stale object appraises as
``CONTRAINDICATED``; a stale-and-mismatched object appraises as ``STALE``.

The third tuple element ``details`` carries every inspected field plus
the derived booleans, so that any downstream results JSON discloses what
was — and was not — examined. ``details["appraisal_method"]`` embeds the
non-claim in machine-readable form.

Deterministic by construction: no wall-clock, no randomness, no I/O, no
network. ``decision_time`` is always an explicit argument.
"""

from __future__ import annotations

from typing import Any

# Machine-readable non-claim, propagated into every details dict so that
# downstream verdicts.jsonl / summary.json carry the disclaimer, not only
# this docstring.
APPRAISAL_METHOD = (
    "structural field comparison of a corpus-supplied attestation-result "
    "object; no cryptographic verification, no TPM, no Veraison, not "
    "remote attestation"
)

# Typed vocabulary of this layer, in appraisal order.
STATE_RESULTS = ("CONTRAINDICATED", "STALE", "REFERENCE_MISMATCH", "PASS")
STATE_GATES = (
    "state.contraindicated",
    "state.stale",
    "state.reference",
    "state.verified",
)


def appraise_state(
    attestation_result: dict[str, Any],
    decision_time: str,
) -> tuple[str, str, dict[str, Any]]:
    """Appraise one attestation-result object at a fixed decision time.

    Returns ``(result, gate, details)`` following the codebase-wide
    evaluator convention (compare ``evaluate_policy`` /
    ``evaluate_evidence`` in ``policy-version-evidence-replay/run.py``).
    The appraisal order and its fail-closed extensions are documented in
    the module docstring; rule numbers below refer to it.
    """
    status = attestation_result.get("status")
    issued_at = attestation_result.get("issued_at", "")
    expires_at = attestation_result.get("expires_at", "")
    reference_digest = attestation_result.get("reference_digest")
    observed_digest = attestation_result.get("observed_digest")

    status_affirming = status == "affirming"
    within_window = issued_at <= decision_time <= expires_at
    digest_match = bool(reference_digest) and observed_digest == reference_digest

    details: dict[str, Any] = {
        "profile": attestation_result.get("profile"),
        "status": status,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "reference_digest": reference_digest,
        "observed_digest": observed_digest,
        "decision_time": decision_time,
        "status_affirming": status_affirming,
        "within_window": within_window,
        "digest_match": digest_match,
        "appraisal_method": APPRAISAL_METHOD,
    }

    if not status_affirming:  # rule 1 (fail-closed on unknown status)
        return "CONTRAINDICATED", "state.contraindicated", details
    if not within_window:  # rule 2
        return "STALE", "state.stale", details
    if not digest_match:  # rule 3 (fail-closed on missing reference)
        return "REFERENCE_MISMATCH", "state.reference", details
    return "PASS", "state.verified", details  # rule 4
