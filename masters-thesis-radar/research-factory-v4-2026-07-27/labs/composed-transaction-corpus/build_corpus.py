#!/usr/bin/env python3
"""Build the frozen composed transaction corpus v3.

Spans policy, evidence, runtime-state, authority and measurement layers,
plus the cross-layer binding stage.

v2 (2026-07-27) rebuild against review blockers:

- B1: the expected-label composition ladder now lives ONLY in
  composition_rule.py, imported here and by verify_transactions.py.
  Composition-level agreement is therefore analytic by construction and is
  declared as such (label_provenance in the corpus and in every summary).
- B2: transactions carry attestation_result objects (patterns from
  state-fixtures.json) instead of a bare runtime_state string; the state
  layer is structurally appraised by state_adapter.py, not declared.
- B3: a cross_layer_joins family removes every zero off-diagonal cell of
  the 5x5 pairwise co-failure matrix.

v3 (2026-07-27) rebuild against blocker B5 — the composition seam:

- The composed verifier ALLOWED the article's own section-1 counterexample
  (a correctly signed evidence receipt describing a WRITE effect under a
  delegation path that permits only READ). The v2 cross_layer_joins family
  was not a join: each transaction was a 4-tuple of independent fixture
  identifiers with two independent faults set at once, and compose() took
  six scalar strings with no cross-layer argument, so a denial produced by
  the join was architecturally unrepresentable.
- v3 adds the explicit binding stage (composition_rule.bind) and the
  cross_layer_binding family: transactions in which every one of the five
  artefact verifiers passes locally and the composed verdict is DENY.
  Each mismatch case is paired with an all-valid lookalike control that
  must be ALLOWED, so universal refusal cannot masquerade as correctness.
- required_effect and required_measurement_profile, written into the signed
  policy by the policy laboratory since v1 and read by no evaluator
  anywhere, are now load-bearing: they are the policy-owned half of
  canonical_action.
- canonical_action and observed_effect, advertised by section 4 of the
  article and previously absent from the artifact, are now real transaction
  fields, built by composition_rule.subjects_of and consumed by bind().

Two constructions are OWNED BY THIS LABORATORY and are not upstream data:

- evidence_variants: additional evidence objects signed with the policy
  laboratory's own test key (imported, not transcribed) that vary effect,
  resource or issued_at while remaining correctly signed with a fresh
  nonce. They are appraised by the UNMODIFIED policy-laboratory
  evaluate_evidence, which passes them, exactly as the defect report says
  it does.
- measurement_variants: two measurement fixtures in the SAFE fixture schema
  that differ only in profile identity, both appraised by the UNMODIFIED
  v3 SAFE evaluator, both of which it passes. They exist because varying
  the policy is impossible (any edit to a signed policy changes its digest
  and the policy layer then reports SUBSTITUTED) and because the shipped
  profile-mismatch fixture already fails its own layer.

Neither sibling laboratory is modified: their evaluators are imported and
executed as shipped.

Sources: the v4 upgraded policy (16 vectors) and delegation (16 cases)
laboratories, the v4 state fixtures, and the UNCHANGED v3 SAFE measurement
laboratory (read-only, pinned by SHA-256; it was not part of the v4
upgrade).

All expected labels are author-written programme-internal expectations.
Deterministic: fixed decision times, no wall-clock, no randomness.
"""

from __future__ import annotations

import copy
import hashlib
import importlib.util
import itertools
import json
import os
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

sys.dont_write_bytecode = True

import composition_rule


ROOT = Path(__file__).resolve().parent
FACTORY = ROOT.parents[1]
V3_FACTORY = ROOT.parents[2] / "research-factory-v3-2026-07-25"
POLICY_DIR = FACTORY / "labs" / "policy-version-evidence-replay"
SAFE_DIR = V3_FACTORY / "labs" / "safe-metric-metamorphics"
AUTHORITY_DIR = FACTORY / "labs" / "protocol-valid-unauthorized"
STATE_FIXTURES_PATH = ROOT / "state-fixtures.json"
CORPUS_PATH = ROOT / "corpus.json"

NEW_POLICY_VECTOR_IDS = (
    "PSR_version_only_good",
    "PSR_freshness_only_good",
    "PSR_digest_only_good",
    "PSR_policy_sig_invalid_good",
)
NEW_DELEGATION_CASE_IDS = (
    "D1_protocol_invalid",
    "D2_signature_invalid_second_edge",
    "D1_receipt_native_invalid",
    "D1_receipt_effect_time_outside_window",
)

# ---------------------------------------------------------------------------
# Evidence objects owned by this laboratory (B5).
#
# Each is a correctly signed tyche-signed-effect-v1 object with a fresh
# nonce, so the UNMODIFIED evidence evaluator returns PASS on all of them.
# They differ from the policy laboratory's own evidence only in the subject
# fields the binding stage reads. Columns: id, effect, resource, issued_at.
# ---------------------------------------------------------------------------
EVIDENCE_VARIANTS: tuple[tuple[str, str, str, str], ...] = (
    ("EVB_read_invoice123", "ledger.read", "invoice-123", "2026-07-25T21:29:30Z"),
    ("EVB_write_invoice123", "ledger.write", "invoice-123", "2026-07-25T21:29:30Z"),
    ("EVB_write_invoice999", "ledger.write", "invoice-999", "2026-07-25T21:29:30Z"),
    ("EVB_export_invoice123", "ledger.export", "invoice-123", "2026-07-25T21:29:30Z"),
    ("EVB_read_invoice999", "ledger.read", "invoice-999", "2026-07-25T21:29:30Z"),
    ("EVB_read_after_window", "ledger.read", "invoice-123", "2026-07-26T00:00:01Z"),
    ("EVB_read_before_window", "ledger.read", "invoice-123", "2026-07-24T23:59:59Z"),
    ("EVB_read_window_lower", "ledger.read", "invoice-123", "2026-07-25T00:00:00Z"),
    ("EVB_read_window_upper", "ledger.read", "invoice-123", "2026-07-26T00:00:00Z"),
)

# Measurement fixtures owned by this laboratory (B5): identical in dataset,
# alpha and threshold, differing only in profile identity. Columns:
# id, SAFE profile key, expected local result.
MEASUREMENT_VARIANTS: tuple[tuple[str, str, str], ...] = (
    ("measurement_binding_main_profile", "main", "PASS"),
    ("measurement_binding_alt_profile", "altered", "PASS"),
)

# ---------------------------------------------------------------------------
# cross_layer_joins family (B3), fully enumerated so the engineering intent
# is reviewable. Columns: id, policy_vector, state_fixture, authority_case,
# measurement_fixture. Blocks:
#   (a) all 10 unordered layer pairs x 2 distinct instantiations = 20;
#   (b) 4 triples + 1 quadruple + 1 all-five = 6;
#   (c) 4 matched all-valid lookalike positives (so universal refusal cannot
#       masquerade as correctness).
# ---------------------------------------------------------------------------
CROSS_LAYER_JOINS = (
    # (a) pairwise two-fault joins — every pair twice within this family.
    ("XLJ_PE_stale_tampered", "PSR_stale_tampered", "affirming-fresh-match", "P2_exact_two_hop", "measurement_supported"),
    ("XLJ_PE_substituted_replayed", "PSR_substituted_replayed", "affirming-fresh-match", "P1_exact_one_hop", "measurement_supported"),
    ("XLJ_PS_stale_policy_reference_mismatch", "PSR_stale_good", "fresh-mismatch", "P2_exact_two_hop", "measurement_supported"),
    ("XLJ_PS_digest_only_contraindicated", "PSR_digest_only_good", "contraindicated", "P1_exact_one_hop", "measurement_supported"),
    ("XLJ_PA_substituted_scope_amplification", "PSR_substituted_good", "affirming-fresh-match", "D2_scope_amplification_at_second_edge", "measurement_supported"),
    ("XLJ_PA_sig_invalid_protocol_invalid", "PSR_policy_sig_invalid_good", "affirming-fresh-match", "D1_protocol_invalid", "measurement_supported"),
    ("XLJ_PM_version_only_unsupported", "PSR_version_only_good", "affirming-fresh-match", "P2_exact_two_hop", "measurement_unsupported"),
    ("XLJ_PM_freshness_only_profile_mismatch", "PSR_freshness_only_good", "affirming-fresh-match", "P4_exact_four_hop", "measurement_profile_mismatch"),
    ("XLJ_ES_tampered_stale_state", "PSR_correct_tampered", "stale-match", "P2_exact_two_hop", "measurement_supported"),
    ("XLJ_ES_replayed_reference_mismatch", "PSR_correct_replayed", "fresh-mismatch", "P1_exact_one_hop", "measurement_supported"),
    ("XLJ_EA_replayed_revoked_edge", "PSR_correct_replayed", "affirming-fresh-match", "D4_revoked_third_edge", "measurement_supported"),
    ("XLJ_EA_tampered_edge_signature", "PSR_correct_tampered", "affirming-fresh-match", "D2_signature_invalid_second_edge", "measurement_supported"),
    ("XLJ_EM_tampered_unsupported", "PSR_correct_tampered", "affirming-fresh-match", "P2_exact_two_hop", "measurement_unsupported"),
    ("XLJ_EM_replayed_point_only", "PSR_correct_replayed", "affirming-fresh-match", "P4_exact_four_hop", "measurement_point_only"),
    ("XLJ_SA_contraindicated_role_transition", "PSR_correct_good", "contraindicated", "D1_wrong_role_transition", "measurement_supported"),
    ("XLJ_SA_stale_state_receipt_invalid", "PSR_correct_good", "stale-mismatch", "D1_receipt_native_invalid", "measurement_supported"),
    ("XLJ_SM_stale_state_point_only", "PSR_correct_good", "stale-match", "P2_exact_two_hop", "measurement_point_only"),
    ("XLJ_SM_reference_mismatch_profile_mismatch", "PSR_correct_good", "fresh-mismatch", "P1_exact_one_hop", "measurement_profile_mismatch"),
    ("XLJ_AM_lineage_break_profile_mismatch", "PSR_correct_good", "affirming-fresh-match", "D2_lineage_break_at_second_edge", "measurement_profile_mismatch"),
    ("XLJ_AM_effect_time_unsupported", "PSR_correct_good", "affirming-fresh-match", "D1_receipt_effect_time_outside_window", "measurement_unsupported"),
    # (b) higher-order joins.
    ("XLJ_TRIPLE_policy_evidence_authority", "PSR_stale_tampered", "affirming-fresh-match", "D4_action_outside_terminal_scope", "measurement_supported"),
    ("XLJ_TRIPLE_policy_state_measurement", "PSR_missing_good", "stale-match", "P2_exact_two_hop", "measurement_unsupported"),
    ("XLJ_TRIPLE_evidence_state_authority", "PSR_correct_tampered", "contraindicated", "D2_first_edge_expired", "measurement_supported"),
    ("XLJ_TRIPLE_state_authority_measurement", "PSR_correct_good", "fresh-mismatch", "D4_multi_fault_returns_earliest_edge", "measurement_point_only"),
    ("XLJ_QUAD_policy_evidence_state_authority", "PSR_substituted_replayed", "contraindicated", "D2_parent_forbids_second_delegation", "measurement_supported"),
    ("XLJ_QUINT_all_layers_fail", "PSR_missing_replayed", "contraindicated-stale-mismatch", "D1_wrong_role_transition", "measurement_unsupported"),
    # (c) matched all-valid lookalike positives.
    ("XLJ_LOOKALIKE_one_hop", "PSR_correct_good", "affirming-fresh-match", "P1_exact_one_hop", "measurement_supported"),
    ("XLJ_LOOKALIKE_two_hop_boundary_fresh", "PSR_correct_good", "boundary-fresh", "P2_exact_two_hop", "measurement_supported"),
    ("XLJ_LOOKALIKE_four_hop_boundary_expiry", "PSR_correct_good", "boundary-expiry", "P4_exact_four_hop", "measurement_supported"),
    ("XLJ_LOOKALIKE_four_hop", "PSR_correct_good", "affirming-fresh-match", "P4_exact_four_hop", "measurement_supported"),
)

# ---------------------------------------------------------------------------
# cross_layer_binding family (B5).
#
# EVERY transaction below is built so that all five artefact verifiers pass
# locally: correct signed policy, correctly signed evidence with a fresh
# nonce, affirming and fresh attestation result, an ALLOW delegation path,
# and a measurement fixture its own evaluator passes. The only thing that
# can differ is subject agreement across artefacts. Mismatch cases are
# therefore denials that no five-layer conjunction can produce; each is
# paired with a control that differs only in the varied subject field.
#
# Columns: id, evidence_variant, authority_case, measurement_fixture,
#          expected binding result (author-written), rationale.
# ---------------------------------------------------------------------------
CROSS_LAYER_BINDING: tuple[tuple[str, str, str, str, str, str], ...] = (
    (
        "XLB_effect_write_two_hop",
        "EVB_write_invoice123",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "EFFECT_MISMATCH",
        "correctly signed receipt describes a WRITE effect; policy requires "
        "ledger.read and the terminal grant carries only ledger.read",
    ),
    (
        "XLB_effect_write_other_resource_two_hop",
        "EVB_write_invoice999",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "EFFECT_MISMATCH",
        "the article's section-1 counterexample verbatim: WRITE effect on "
        "invoice-999 under a path that permits only READ on invoice-123; "
        "the effect rule fires before the resource rule",
    ),
    (
        "XLB_effect_export_four_hop",
        "EVB_export_invoice123",
        "P4_exact_four_hop",
        "measurement_binding_main_profile",
        "EFFECT_MISMATCH",
        "same seam at four hops: the seam is not a property of path length",
    ),
    (
        "XLB_resource_other_two_hop",
        "EVB_read_invoice999",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "RESOURCE_MISMATCH",
        "permitted operation on an unauthorised resource",
    ),
    (
        "XLB_resource_other_one_hop",
        "EVB_read_invoice999",
        "P1_exact_one_hop",
        "measurement_binding_main_profile",
        "RESOURCE_MISMATCH",
        "same seam at one hop",
    ),
    (
        "XLB_issued_after_window_two_hop",
        "EVB_read_after_window",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "TIME_MISMATCH",
        "effect reported one second after the whole delegation path expired",
    ),
    (
        "XLB_issued_before_window_two_hop",
        "EVB_read_before_window",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "TIME_MISMATCH",
        "effect reported one second before the path became valid",
    ),
    (
        "XLB_measurement_profile_two_hop",
        "EVB_read_invoice123",
        "P2_exact_two_hop",
        "measurement_binding_alt_profile",
        "PROFILE_MISMATCH",
        "the appraisal that passed its own gates was computed under a "
        "profile the active policy does not require",
    ),
    # Matched all-valid lookalike controls — every one must be ALLOWED.
    (
        "XLB_CONTROL_read_two_hop",
        "EVB_read_invoice123",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for the effect and resource cases: identical construction, "
        "agreeing subjects",
    ),
    (
        "XLB_CONTROL_read_one_hop",
        "EVB_read_invoice123",
        "P1_exact_one_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for XLB_resource_other_one_hop",
    ),
    (
        "XLB_CONTROL_read_four_hop",
        "EVB_read_invoice123",
        "P4_exact_four_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for XLB_effect_export_four_hop",
    ),
    (
        "XLB_CONTROL_window_lower_two_hop",
        "EVB_read_window_lower",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for the time cases at the inclusive lower boundary",
    ),
    (
        "XLB_CONTROL_window_upper_two_hop",
        "EVB_read_window_upper",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for the time cases at the inclusive upper boundary",
    ),
    (
        "XLB_CONTROL_main_profile_two_hop",
        "EVB_read_invoice123",
        "P2_exact_two_hop",
        "measurement_binding_main_profile",
        "PASS",
        "control for XLB_measurement_profile_two_hop: the same locally "
        "defined fixture construction under the required profile",
    ),
)


def load_module(
    name: str, path: Path, prepend: Path | None = None
) -> ModuleType:
    if prepend is not None and str(prepend) not in sys.path:
        sys.path.insert(0, str(prepend))
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def expected_for(
    policy_vector: dict[str, Any],
    state_fixture: dict[str, Any],
    authority_case: dict[str, Any],
    measurement_fixture: dict[str, Any],
    subjects: dict[str, Any],
) -> dict[str, Any]:
    """Expected composed tuple from per-layer author-written expectations.

    The composition itself is composition_rule.compose — the same function
    the verifier applies to re-executed layer results (label_provenance).
    """
    return composition_rule.compose(
        policy_vector["expected"]["policy_result"],
        policy_vector["expected"]["evidence_result"],
        state_fixture["expected"]["result"],
        authority_case["expected"]["verdict"],
        authority_case["expected"]["gate"],
        measurement_fixture["expected"],
        subjects,
    )


def make_transaction(
    transaction_id: str,
    family: str,
    policy_vector: dict[str, Any],
    state_fixture_id: str,
    state_fixture: dict[str, Any],
    authority_case: dict[str, Any],
    expanded_authority_case: dict[str, Any],
    measurement_fixture: dict[str, Any],
    measurement_fixture_source: str,
    evidence_variant_id: str | None,
    evidence_object: dict[str, Any],
    expected_evidence_result: str | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Assemble one decision transaction.

    ``expected_evidence_result`` overrides the policy vector's own
    author-written evidence expectation when the transaction substitutes a
    laboratory-owned evidence object for the vector's evidence.
    """
    subjects = composition_rule.subjects_of(
        policy_vector["policy"],
        expanded_authority_case,
        evidence_object,
        measurement_fixture,
    )
    vector_for_expectation = policy_vector
    if expected_evidence_result is not None:
        vector_for_expectation = copy.deepcopy(policy_vector)
        vector_for_expectation["expected"]["evidence_result"] = (
            expected_evidence_result
        )
    transaction = {
        "id": transaction_id,
        "family": family,
        "policy_vector_id": policy_vector["id"],
        "state_fixture_id": state_fixture_id,
        "attestation_result": copy.deepcopy(
            state_fixture["attestation_result"]
        ),
        "authority_case_id": authority_case["id"],
        "measurement_fixture_id": measurement_fixture["id"],
        "measurement_fixture_source": measurement_fixture_source,
        "evidence_variant_id": evidence_variant_id,
        "canonical_action": subjects["canonical_action"],
        "observed_effect": subjects["observed_effect"],
        "expected": expected_for(
            vector_for_expectation,
            state_fixture,
            authority_case,
            measurement_fixture,
            subjects,
        ),
    }
    if note is not None:
        transaction["note"] = note
    return transaction


def check_design_constraints(transactions: list[dict[str, Any]]) -> None:
    """Corpus-engineering gates (B3/B4/B5). All deterministic assertions."""
    layers = composition_rule.EVALUATION_ORDER
    co: dict[str, dict[str, int]] = {
        a: {b: 0 for b in layers} for a in layers
    }
    for transaction in transactions:
        failed = transaction["expected"]["failed_layers"]
        for a in failed:
            for b in failed:
                co[a][b] += 1
    off_diagonal = [
        co[a][b] for a in layers for b in layers if a != b
    ]
    assert min(off_diagonal) >= 1, "zero off-diagonal co-failure cell"

    measurement_usage: dict[str, int] = {}
    state_outcomes: dict[str, int] = {}
    policy_usage: dict[str, int] = {}
    authority_usage: dict[str, int] = {}
    for transaction in transactions:
        measurement_usage[transaction["measurement_fixture_id"]] = (
            measurement_usage.get(transaction["measurement_fixture_id"], 0) + 1
        )
        state_outcomes[transaction["expected"]["layer_results"]["state"]] = (
            state_outcomes.get(
                transaction["expected"]["layer_results"]["state"], 0
            )
            + 1
        )
        policy_usage[transaction["policy_vector_id"]] = (
            policy_usage.get(transaction["policy_vector_id"], 0) + 1
        )
        authority_usage[transaction["authority_case_id"]] = (
            authority_usage.get(transaction["authority_case_id"], 0) + 1
        )
    for fixture_id in (
        "measurement_supported",
        "measurement_point_only",
        "measurement_unsupported",
        "measurement_profile_mismatch",
    ):
        assert measurement_usage.get(fixture_id, 0) >= 2, fixture_id
    for outcome in ("CONTRAINDICATED", "STALE", "REFERENCE_MISMATCH"):
        assert state_outcomes.get(outcome, 0) >= 1, outcome
    for vector_id in NEW_POLICY_VECTOR_IDS:
        assert policy_usage.get(vector_id, 0) >= 1, vector_id
    for case_id in NEW_DELEGATION_CASE_IDS:
        assert authority_usage.get(case_id, 0) >= 1, case_id
    lookalike_allows = sum(
        transaction["family"] == "cross_layer_joins"
        and transaction["expected"]["verdict"] == "ALLOW"
        for transaction in transactions
    )
    assert lookalike_allows >= 3, "need >=3 all-valid lookalike positives"

    # B5 gates.
    binding_family = [
        transaction
        for transaction in transactions
        if transaction["family"] == "cross_layer_binding"
    ]
    binding_only_denies = [
        transaction
        for transaction in transactions
        if transaction["expected"]["verdict"] == "DENY"
        and not transaction["expected"]["failed_layers"]
    ]
    assert binding_only_denies, "no cross-layer denial is expressible"
    for transaction in binding_only_denies:
        # A cross-layer denial must be one where every artefact verifier
        # passed; anything else would be a relabelled single-layer failure.
        assert transaction["expected"]["binding_result"] != "PASS"
        assert transaction["expected"]["first_rejecting_gate"].startswith(
            "binding."
        )
    observed_binding_outcomes = {
        transaction["expected"]["binding_result"]
        for transaction in binding_family
    }
    for outcome in (
        "EFFECT_MISMATCH",
        "RESOURCE_MISMATCH",
        "TIME_MISMATCH",
        "PROFILE_MISMATCH",
        "PASS",
    ):
        assert outcome in observed_binding_outcomes, outcome
    binding_controls = [
        transaction
        for transaction in binding_family
        if transaction["expected"]["verdict"] == "ALLOW"
    ]
    assert len(binding_controls) >= 4, "need >=4 matched binding controls"
    assert 90 <= len(transactions) <= 120, len(transactions)


def main() -> int:
    policy_path = POLICY_DIR / "corpus.json"
    safe_path = SAFE_DIR / "corpus.json"
    authority_path = AUTHORITY_DIR / "delegation-paths.json"
    policy = json.loads(policy_path.read_text(encoding="utf-8"))
    safe = json.loads(safe_path.read_text(encoding="utf-8"))
    authority = json.loads(authority_path.read_text(encoding="utf-8"))
    state_fixtures_doc = json.loads(
        STATE_FIXTURES_PATH.read_text(encoding="utf-8")
    )
    state_fixtures = state_fixtures_doc["fixtures"]
    state_decision_time = state_fixtures_doc["decision_time"]
    # Shared fixed constant with the policy laboratory (documented in
    # state-fixtures.json); assert so drift cannot pass silently.
    assert state_decision_time == policy["decision_time"], (
        state_decision_time,
        policy["decision_time"],
    )

    # The authority and SAFE modules are imported, never transcribed: the
    # expanded delegation cases and the profile digest function are the
    # sibling laboratories' own code, executed as shipped.
    authority_module = load_module(
        "typed_authority_paths", AUTHORITY_DIR / "verify_delegation_paths.py"
    )
    safe_module = load_module(
        "safe_metric_metamorphics_run", SAFE_DIR / "run.py", prepend=SAFE_DIR
    )
    policy_builder = load_module(
        "policy_version_evidence_replay_build", POLICY_DIR / "build_corpus.py"
    )

    policy_by_id = {item["id"]: item for item in policy["vectors"]}
    measurement_by_id = {
        item["id"]: item for item in safe["measurement_fixtures"]
    }
    authority_by_id = {item["id"]: item for item in authority["cases"]}

    # Expanded delegation cases: build_case + the case's own mutations, i.e.
    # exactly the object the authority evaluator appraises. canonical_action
    # reads its terminal grant and edge windows from here.
    expanded_by_id: dict[str, dict[str, Any]] = {}
    for vector in authority["cases"]:
        case = authority_module.build_case(
            authority["base"], vector["hops"], authority["effect_time"]
        )
        for mutation in vector["mutations"]:
            authority_module.apply_mutation(
                case, mutation["path"], mutation["value"]
            )
        expanded_by_id[vector["id"]] = case

    # --- laboratory-owned measurement variants ------------------------------
    # The digest function is the SAFE laboratory's own; assert it reproduces
    # the shipped anchor before using it, so a silent upstream change cannot
    # slip past.
    assert (
        safe_module.digest(safe["profiles"]["main"])
        == measurement_by_id["measurement_supported"]["required_profile_digest"]
    )
    reference_fixture = measurement_by_id["measurement_supported"]
    measurement_variants: dict[str, dict[str, Any]] = {}
    for variant_id, profile_key, expected_result in MEASUREMENT_VARIANTS:
        profile = copy.deepcopy(safe["profiles"][profile_key])
        measurement_variants[variant_id] = {
            "id": variant_id,
            "dataset": reference_fixture["dataset"],
            "alpha": reference_fixture["alpha"],
            "threshold": reference_fixture["threshold"],
            "profile": profile,
            # Self-consistent anchor: the fixture's own profile digest, so
            # the SAFE evaluator's profile gate passes and only the
            # cross-layer binding stage can object to the profile identity.
            "required_profile_digest": safe_module.digest(profile),
            "expected": expected_result,
            "owned_by": "composed-transaction-corpus",
            "note": (
                "laboratory-owned fixture in the SAFE fixture schema, "
                "appraised by the unmodified v3 SAFE evaluator; it differs "
                "from measurement_supported only in profile identity"
            ),
        }
    all_measurement_by_id = {**measurement_by_id, **measurement_variants}

    # --- laboratory-owned evidence variants ---------------------------------
    # Signed with the policy laboratory's own test key and its own
    # sign_object function (imported, not transcribed). Nonces are fresh, so
    # the unmodified evidence evaluator returns PASS on every one of them.
    private_key = policy_builder.Ed25519PrivateKey.from_private_bytes(
        policy_builder.SEED
    )
    preseen_nonces = set(policy["preseen_nonces"])
    evidence_variants: dict[str, dict[str, Any]] = {}
    for variant_id, effect, resource, issued_at in EVIDENCE_VARIANTS:
        transaction_id = f"xlb-{variant_id}"
        nonce = f"nonce-binding-{variant_id}"
        assert nonce not in preseen_nonces, nonce
        payload = {
            "profile": "tyche-signed-effect-v1",
            "issuer": "tyche-test-evidence-producer",
            "transaction_id": transaction_id,
            "effect": effect,
            "resource": resource,
            "issued_at": issued_at,
            "nonce": nonce,
            "payload_digest": "sha256:"
            + hashlib.sha256(
                f"{transaction_id}|{effect}|{resource}".encode()
            ).hexdigest(),
        }
        evidence_variants[variant_id] = policy_builder.sign_object(
            private_key, payload
        )

    transactions: list[dict[str, Any]] = []

    def vector_evidence(policy_vector: dict[str, Any]) -> dict[str, Any]:
        return policy_vector["evidence"]

    # Family 1 — policy/evidence/measurement factorial (unchanged design):
    # the ORIGINAL 12 policy x evidence vectors only (gate-isolation vectors
    # are exercised in cross_layer_joins), x 3 measurement outcomes = 36.
    original_vectors = [
        vector for vector in policy["vectors"] if "isolated_gate" not in vector
    ]
    assert len(original_vectors) == 12, len(original_vectors)
    for policy_vector in original_vectors:
        for measurement_id in (
            "measurement_supported",
            "measurement_point_only",
            "measurement_profile_mismatch",
        ):
            measurement = measurement_by_id[measurement_id]
            transactions.append(
                make_transaction(
                    f"F_{policy_vector['policy_state']}_{policy_vector['evidence_state']}_{measurement_id.removeprefix('measurement_')}",
                    "policy_evidence_measurement_factorial",
                    policy_vector,
                    "affirming-fresh-match",
                    state_fixtures["affirming-fresh-match"],
                    authority_by_id["P2_exact_two_hop"],
                    expanded_by_id["P2_exact_two_hop"],
                    measurement,
                    "safe-v3-corpus",
                    None,
                    vector_evidence(policy_vector),
                )
            )

    # Family 2 — all 2^3 combinations for state, authority and measurement
    # under a correct policy and good evidence. State pass/fail uses the
    # affirming-fresh-match / contraindicated adapter objects.
    correct_good = policy_by_id["PSR_correct_good"]
    for state_pass, authority_pass, measurement_pass in itertools.product(
        (True, False), repeat=3
    ):
        state_fixture_id = (
            "affirming-fresh-match" if state_pass else "contraindicated"
        )
        authority_case_id = (
            "P2_exact_two_hop"
            if authority_pass
            else "D2_scope_amplification_at_second_edge"
        )
        authority_case = authority_by_id[authority_case_id]
        measurement = measurement_by_id[
            "measurement_supported"
            if measurement_pass
            else "measurement_point_only"
        ]
        bits = "".join(
            "1" if value else "0"
            for value in (state_pass, authority_pass, measurement_pass)
        )
        transactions.append(
            make_transaction(
                f"CUBE_{bits}",
                "state_authority_measurement_cube",
                correct_good,
                state_fixture_id,
                state_fixtures[state_fixture_id],
                authority_case,
                expanded_by_id[authority_case_id],
                measurement,
                "safe-v3-corpus",
                None,
                vector_evidence(correct_good),
            )
        )

    # Family 3 — re-evaluate ALL 16 typed delegation cases (v4 corpus,
    # including the four cases that close previously dead gates) inside the
    # same all-other-layers-valid transaction wrapper.
    for authority_case in authority["cases"]:
        transactions.append(
            make_transaction(
                f"PATH_{authority_case['id']}",
                "authority_path_reuse",
                correct_good,
                "affirming-fresh-match",
                state_fixtures["affirming-fresh-match"],
                authority_case,
                expanded_by_id[authority_case["id"]],
                measurement_by_id["measurement_supported"],
                "safe-v3-corpus",
                None,
                vector_evidence(correct_good),
            )
        )

    # Family 4 — cross_layer_joins (B3).
    for (
        transaction_id,
        policy_vector_id,
        state_fixture_id,
        authority_case_id,
        measurement_fixture_id,
    ) in CROSS_LAYER_JOINS:
        transactions.append(
            make_transaction(
                transaction_id,
                "cross_layer_joins",
                policy_by_id[policy_vector_id],
                state_fixture_id,
                state_fixtures[state_fixture_id],
                authority_by_id[authority_case_id],
                expanded_by_id[authority_case_id],
                measurement_by_id[measurement_fixture_id],
                "safe-v3-corpus",
                None,
                vector_evidence(policy_by_id[policy_vector_id]),
            )
        )

    # Family 5 — cross_layer_binding (B5). Every layer passes locally; only
    # subject agreement varies.
    for (
        transaction_id,
        evidence_variant_id,
        authority_case_id,
        measurement_fixture_id,
        expected_binding,
        rationale,
    ) in CROSS_LAYER_BINDING:
        transaction = make_transaction(
            transaction_id,
            "cross_layer_binding",
            correct_good,
            "affirming-fresh-match",
            state_fixtures["affirming-fresh-match"],
            authority_by_id[authority_case_id],
            expanded_by_id[authority_case_id],
            all_measurement_by_id[measurement_fixture_id],
            (
                "composed-lab-binding-variant"
                if measurement_fixture_id in measurement_variants
                else "safe-v3-corpus"
            ),
            evidence_variant_id,
            evidence_variants[evidence_variant_id],
            expected_evidence_result="PASS",
            note=rationale,
        )
        # Author-written per-case binding expectation, asserted against the
        # rule's own output so the two cannot drift apart silently.
        assert (
            transaction["expected"]["binding_result"] == expected_binding
        ), (transaction_id, transaction["expected"]["binding_result"])
        # The defining property of this family.
        assert not transaction["expected"]["failed_layers"], transaction_id
        transactions.append(transaction)

    assert len({t["id"] for t in transactions}) == len(transactions)
    check_design_constraints(transactions)

    family_counts: dict[str, int] = {}
    for transaction in transactions:
        family_counts[transaction["family"]] = (
            family_counts.get(transaction["family"], 0) + 1
        )

    corpus = {
        "profile": "tyche-evidence-carrying-decision-transaction-v3",
        "evaluation_order": list(composition_rule.EVALUATION_ORDER),
        "binding_stage": {
            "position": (
                "after the five artefact layers; consulted by the "
                "first-rejecting-gate ladder only when all five have passed"
            ),
            "results": list(composition_rule.BINDING_RESULTS),
            "gates": dict(composition_rule.BINDING_GATES),
            "canonical_action_fields": list(
                composition_rule.CANONICAL_ACTION_FIELDS
            ),
            "observed_effect_fields": list(
                composition_rule.OBSERVED_EFFECT_FIELDS
            ),
            "method": composition_rule.BINDING_METHOD,
        },
        "state_decision_time": state_decision_time,
        "source_artifacts": {
            "policy_corpus": {
                "path": os.path.relpath(policy_path, ROOT),
                "sha256": sha256_file(policy_path),
            },
            "safe_corpus": {
                "path": os.path.relpath(safe_path, ROOT),
                "sha256": sha256_file(safe_path),
                "note": (
                    "unchanged v3 SAFE measurement laboratory, consumed "
                    "read-only; it was not part of the v4 upgrade"
                ),
            },
            "authority_corpus": {
                "path": os.path.relpath(authority_path, ROOT),
                "sha256": sha256_file(authority_path),
            },
            "state_fixtures": {
                "path": os.path.relpath(STATE_FIXTURES_PATH, ROOT),
                "sha256": sha256_file(STATE_FIXTURES_PATH),
            },
        },
        "evidence_variants": evidence_variants,
        "evidence_variants_note": (
            "Evidence objects owned by this laboratory and signed with the "
            "policy laboratory's own test key and sign_object function "
            "(imported, not transcribed). Every one carries a fresh nonce "
            "and a valid signature, so the UNMODIFIED evidence evaluator "
            "returns PASS on all of them; they differ only in the subject "
            "fields the binding stage reads."
        ),
        "measurement_variants": measurement_variants,
        "measurement_variants_note": (
            "Measurement fixtures owned by this laboratory in the SAFE "
            "fixture schema, appraised by the UNMODIFIED v3 SAFE evaluator, "
            "which passes both. They differ from each other only in profile "
            "identity. They exist because the signed policy cannot be varied "
            "without changing its digest (the policy layer would then report "
            "SUBSTITUTED) and because the shipped profile-mismatch fixture "
            "already fails its own layer."
        ),
        "families": family_counts,
        "label_provenance": composition_rule.LABEL_PROVENANCE,
        "transactions": transactions,
        "claim_ceiling": {
            "synthetic_or_hybrid": True,
            "external_labels": False,
            "production_interoperability": False,
        },
        "disclaimers": [
            "All expected labels are author-written programme-internal "
            "expectations; agreement measures reproduction of those "
            "expectations, not external ground truth.",
            "Counts on this designed corpus are corpus-coverage statistics; "
            "they are not rates and do not estimate prevalence in any "
            "deployed system.",
            "attestation_result objects are corpus fixtures appraised "
            "structurally by state_adapter.py; this is not cryptographic "
            "attestation of any runtime.",
            "issuer_signature_valid, native_evidence_valid and "
            "protocol_valid in the authority corpus are corpus-supplied "
            "experimental flags; the authority laboratory performs no "
            "cryptographic verification.",
            "The binding stage is a deterministic string-agreement and "
            "interval-containment condition over subject fields read out of "
            "corpus-supplied artefacts; it verifies no signature and takes "
            "no measurement.",
            "canonical_action and observed_effect are derived from the "
            "artefacts by composition_rule.subjects_of; the verifier "
            "re-derives them and checks field equality, but they are "
            "corpus-supplied strings throughout.",
        ],
    }
    CORPUS_PATH.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"transactions={len(transactions)}")
    print(
        "families="
        + json.dumps(family_counts, sort_keys=True, separators=(",", ":"))
    )
    binding_counts: dict[str, int] = {}
    for transaction in transactions:
        key = transaction["expected"]["binding_result"]
        binding_counts[key] = binding_counts.get(key, 0) + 1
    print(
        "binding_outcomes="
        + json.dumps(binding_counts, sort_keys=True, separators=(",", ":"))
    )
    print(
        "cross_layer_denies="
        + str(
            sum(
                transaction["expected"]["verdict"] == "DENY"
                and not transaction["expected"]["failed_layers"]
                for transaction in transactions
            )
        )
    )
    print(f"corpus_sha256={sha256_file(CORPUS_PATH)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
