#!/usr/bin/env python3
"""CRITICAL ACCEPTANCE TEST — the article's section-1 counterexample.

Section 1 of the article claims:

    "an evidence receipt can correctly describe a WRITE effect when the
     valid delegation path permits only READ"

Until the binding stage existed, the shipped composed verifier ALLOWED
exactly that transaction. This test constructs it from first principles —
it does not read corpus.json, so it cannot be satisfied by a corpus entry
that happens to carry the right label — and asserts that the composed
verdict is now DENY at the binding gate, with every one of the five
artefact verifiers passing.

Construction:

- policy: the UNMODIFIED PSR_correct_good policy object from the policy
  laboratory's own corpus, whose required_effect is "ledger.read";
- evidence: a freshly signed tyche-signed-effect-v1 object with
  effect "ledger.write", resource "invoice-999" and a nonce that is not in
  preseen_nonces, signed with the policy laboratory's own test key via its
  own sign_object function;
- state: the affirming-fresh-match attestation result at the fixed
  decision time;
- authority: P2_exact_two_hop, an ALLOW path whose terminal grant carries
  tools ["ledger.read"] and resources ["invoice-123"];
- measurement: measurement_supported, which its own evaluator passes.

The matched lookalike differs in exactly one respect: effect "ledger.read"
on resource "invoice-123". It must be ALLOWED.

Deterministic, dependency-free (plain asserts, no pytest), fixed decision
times, no wall-clock, no randomness, no network. Exit code 0 iff every
check passes.

If the counterexample is still ALLOWED this test FAILS and says so plainly.
The correct response to that is to fix the implementation, never to adjust
this test.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

sys.dont_write_bytecode = True

import composition_rule
import state_adapter


ROOT = Path(__file__).resolve().parent
FACTORY = ROOT.parents[1]
V3_FACTORY = ROOT.parents[2] / "research-factory-v3-2026-07-25"
POLICY_DIR = FACTORY / "labs" / "policy-version-evidence-replay"
SAFE_DIR = V3_FACTORY / "labs" / "safe-metric-metamorphics"
AUTHORITY_DIR = FACTORY / "labs" / "protocol-valid-unauthorized"
STATE_FIXTURES_PATH = ROOT / "state-fixtures.json"

# Fixed constants — no wall-clock anywhere in this file.
ISSUED_AT = "2026-07-25T21:29:30Z"
AUTHORITY_CASE_ID = "P2_exact_two_hop"
MEASUREMENT_FIXTURE_ID = "measurement_supported"
STATE_FIXTURE_ID = "affirming-fresh-match"
POLICY_VECTOR_ID = "PSR_correct_good"


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


def main() -> int:
    policy_module = load_module(
        "acceptance_policy_run", POLICY_DIR / "run.py"
    )
    policy_builder = load_module(
        "acceptance_policy_build", POLICY_DIR / "build_corpus.py"
    )
    safe_module = load_module(
        "acceptance_safe_run", SAFE_DIR / "run.py", prepend=SAFE_DIR
    )
    authority_module = load_module(
        "acceptance_authority", AUTHORITY_DIR / "verify_delegation_paths.py"
    )

    policy_corpus = json.loads(
        (POLICY_DIR / "corpus.json").read_text(encoding="utf-8")
    )
    safe_corpus = json.loads(
        (SAFE_DIR / "corpus.json").read_text(encoding="utf-8")
    )
    authority_corpus = json.loads(
        (AUTHORITY_DIR / "delegation-paths.json").read_text(encoding="utf-8")
    )
    state_fixtures = json.loads(
        STATE_FIXTURES_PATH.read_text(encoding="utf-8")
    )

    decision_time = policy_corpus["decision_time"]
    state_decision_time = state_fixtures["decision_time"]
    assert decision_time == state_decision_time

    vector = next(
        item
        for item in policy_corpus["vectors"]
        if item["id"] == POLICY_VECTOR_ID
    )
    policy_object = vector["policy"]
    assert policy_object["required_effect"] == "ledger.read", (
        "the counterexample presupposes a policy that requires ledger.read"
    )

    authority_vector = next(
        item
        for item in authority_corpus["cases"]
        if item["id"] == AUTHORITY_CASE_ID
    )
    assert authority_vector["expected"]["verdict"] == "ALLOW"
    measurement_fixture = next(
        item
        for item in safe_corpus["measurement_fixtures"]
        if item["id"] == MEASUREMENT_FIXTURE_ID
    )
    attestation_result = state_fixtures["fixtures"][STATE_FIXTURE_ID][
        "attestation_result"
    ]

    private_key = policy_builder.Ed25519PrivateKey.from_private_bytes(
        policy_builder.SEED
    )
    public_key = policy_module.Ed25519PublicKey.from_public_bytes(
        policy_module.base64.b64decode(policy_corpus["public_key_raw_b64"])
    )
    preseen_nonces = set(policy_corpus["preseen_nonces"])

    def signed_evidence(effect: str, resource: str, label: str) -> dict[str, Any]:
        transaction_id = f"acceptance-{label}"
        nonce = f"nonce-acceptance-{label}"
        assert nonce not in preseen_nonces, "the nonce must be fresh"
        payload = {
            "profile": "tyche-signed-effect-v1",
            "issuer": "tyche-test-evidence-producer",
            "transaction_id": transaction_id,
            "effect": effect,
            "resource": resource,
            "issued_at": ISSUED_AT,
            "nonce": nonce,
            "payload_digest": "sha256:"
            + hashlib.sha256(
                f"{transaction_id}|{effect}|{resource}".encode()
            ).hexdigest(),
        }
        return policy_builder.sign_object(private_key, payload)

    def compose_transaction(evidence_object: dict[str, Any]) -> dict[str, Any]:
        policy_result, _, _ = policy_module.evaluate_policy(
            public_key,
            policy_object,
            policy_corpus["policy_anchor"],
            decision_time,
        )
        evidence_result, _, _ = policy_module.evaluate_evidence(
            public_key, evidence_object, preseen_nonces
        )
        state_result, _, _ = state_adapter.appraise_state(
            attestation_result, state_decision_time
        )
        case = authority_module.build_case(
            authority_corpus["base"],
            authority_vector["hops"],
            authority_corpus["effect_time"],
        )
        for mutation in authority_vector["mutations"]:
            authority_module.apply_mutation(
                case, mutation["path"], mutation["value"]
            )
        verdict, gate, _, _, _ = authority_module.evaluate(
            case, authority_corpus["base"], authority_corpus["effect_time"]
        )
        measurement_result = safe_module.evaluate_measurement_fixture(
            measurement_fixture, safe_corpus
        )
        subjects = composition_rule.subjects_of(
            policy_object, case, evidence_object, measurement_fixture
        )
        composed = composition_rule.compose(
            policy_result,
            evidence_result,
            state_result,
            verdict,
            gate,
            measurement_result["result"],
            subjects,
        )
        composed["subjects"] = subjects
        composed["evidence_result_from_shipped_evaluator"] = evidence_result
        return composed

    failures: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        if condition:
            print(f"  ok   {name}")
        else:
            failures.append(f"{name}{(' — ' + detail) if detail else ''}")
            print(f"  FAIL {name}{(' — ' + detail) if detail else ''}")

    print("=" * 72)
    print("ACCEPTANCE TEST: article section-1 counterexample")
    print("  'an evidence receipt can correctly describe a WRITE effect")
    print("   when the valid delegation path permits only READ'")
    print("=" * 72)

    counterexample_evidence = signed_evidence(
        "ledger.write", "invoice-999", "write-invoice999"
    )
    counterexample = compose_transaction(counterexample_evidence)

    lookalike_evidence = signed_evidence(
        "ledger.read", "invoice-123", "read-invoice123"
    )
    lookalike = compose_transaction(lookalike_evidence)

    print()
    print("COUNTEREXAMPLE  effect=ledger.write  resource=invoice-999")
    print(
        "  policy required_effect             : "
        + str(counterexample["subjects"]["canonical_action"]["effect"])
    )
    print(
        "  terminal granted tools             : "
        + json.dumps(
            counterexample["subjects"]["canonical_action"]["granted_tools"]
        )
    )
    print(
        "  terminal granted resources         : "
        + json.dumps(
            counterexample["subjects"]["canonical_action"][
                "granted_resources"
            ]
        )
    )
    print(
        "  shipped evidence evaluator says    : "
        + counterexample["evidence_result_from_shipped_evaluator"]
    )
    print(
        "  layer results                      : "
        + json.dumps(counterexample["layer_results"], sort_keys=True)
    )
    print(
        "  failed layers                      : "
        + json.dumps(counterexample["failed_layers"])
    )
    print("  binding result                     : "
          + counterexample["binding_result"])
    print("  VERDICT                            : "
          + counterexample["verdict"])
    print("  first rejecting gate               : "
          + counterexample["first_rejecting_gate"])

    print()
    print("LOOKALIKE       effect=ledger.read   resource=invoice-123")
    print(
        "  layer results                      : "
        + json.dumps(lookalike["layer_results"], sort_keys=True)
    )
    print("  binding result                     : "
          + lookalike["binding_result"])
    print("  VERDICT                            : " + lookalike["verdict"])
    print("  first rejecting gate               : "
          + lookalike["first_rejecting_gate"])

    print()
    print("CHECKS")
    check(
        "shipped evidence evaluator still passes the WRITE receipt",
        counterexample["evidence_result_from_shipped_evaluator"] == "PASS",
        "the defect's root cause is unchanged: evaluate_evidence checks "
        "only signature and nonce. The fix is at the join, not in the layer",
    )
    check(
        "all five artefact verifiers pass on the counterexample",
        counterexample["failed_layers"] == [],
        json.dumps(counterexample["failed_layers"]),
    )
    check(
        "counterexample binding result is EFFECT_MISMATCH",
        counterexample["binding_result"] == "EFFECT_MISMATCH",
        counterexample["binding_result"],
    )
    check(
        "counterexample composed verdict is DENY",
        counterexample["verdict"] == "DENY",
        counterexample["verdict"],
    )
    check(
        "counterexample first rejecting gate is binding.effect",
        counterexample["first_rejecting_gate"] == "binding.effect",
        counterexample["first_rejecting_gate"],
    )
    check(
        "lookalike binding result is PASS",
        lookalike["binding_result"] == "PASS",
        lookalike["binding_result"],
    )
    check(
        "lookalike composed verdict is ALLOW",
        lookalike["verdict"] == "ALLOW",
        lookalike["verdict"],
    )
    check(
        "lookalike first rejecting gate is verified",
        lookalike["first_rejecting_gate"] == "verified",
        lookalike["first_rejecting_gate"],
    )
    check(
        "the two transactions differ ONLY in the observed subject",
        counterexample["layer_results"] == lookalike["layer_results"],
        "layer results must be identical for the pair to be a matched "
        "control",
    )
    check(
        "determinism: recomposing the counterexample is identical",
        compose_transaction(counterexample_evidence) == counterexample,
    )

    print()
    if failures:
        print("=" * 72)
        print("ACCEPTANCE TEST FAILED.")
        if counterexample["verdict"] == "ALLOW":
            print(
                "The article's section-1 counterexample is STILL ALLOWED by "
                "the composed verifier. The implementation has failed: the "
                "composition thesis remains asserted rather than "
                "implemented. Fix the implementation — do not adjust this "
                "test."
            )
        for failure in failures:
            print(f"  - {failure}")
        print("=" * 72)
        return 1

    print("=" * 72)
    print(
        "ACCEPTANCE TEST PASSED: the counterexample the article names is "
        "denied at the binding gate with every component verifier passing, "
        "and its matched lookalike is allowed."
    )
    print("=" * 72)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
