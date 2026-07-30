#!/usr/bin/env python3
"""Compose policy, evidence, state, authority, measurement and binding (v3).

The verifier re-executes the three source evaluators (policy, measurement,
authority) per transaction via importlib, appraises the embedded
attestation_result object with state_adapter.appraise_state, re-derives the
two subject records (canonical_action, observed_effect) from the same
artefacts, and composes everything through the SINGLE shared composition
rule module (composition_rule.py) that build_corpus.py also imports.

Why the policy laboratory's evaluate_policy / evaluate_evidence /
baseline_verdicts are called directly instead of its evaluate_vector
wrapper: transactions in the cross_layer_binding family substitute a
laboratory-owned evidence object for the policy vector's own evidence, so
the two appraisals must be addressable separately. These are the upstream
functions themselves — nothing about the policy or evidence appraisal is
reimplemented here.

Consequence (B1, declared in every summary): composition-level agreement
with the expected labels is analytic; the substantive check is per-layer
agreement plus subject-record agreement. Labels are not externally
independent.

B5: a transaction with an empty failed_layers list and a DENY verdict is a
CROSS-LAYER denial — every artefact verifier passed and the join refused.
Those transactions are counted separately (binding_stage in summary.json)
because they are the only ones that could not exist before the binding
stage was implemented.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import platform
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
CORPUS_PATH = ROOT / "corpus.json"
STATE_FIXTURES_PATH = ROOT / "state-fixtures.json"
RESULTS = ROOT / "results"

BASELINE_NAMES = (
    "artifact_validity_only",
    "point_only_measurement",
    "four_of_five_majority",
    "effect_resource_binding",
    "effect_resource_time_binding",
    "effect_resource_profile_binding",
)

DISCLAIMERS = [
    "All expected labels are author-written programme-internal "
    "expectations; agreement measures reproduction of those expectations, "
    "not external ground truth.",
    "All counts (including baseline false allows and the co-failure "
    "matrix) are counts on a designed corpus; they are not rates and do "
    "not estimate prevalence in any deployed system.",
    "The state layer is a structural appraisal of corpus-supplied "
    "attestation-result objects (state_adapter.py); it is not "
    "cryptographic attestation of any runtime.",
    "The authority layer consumes corpus-supplied experimental flags "
    "(issuer_signature_valid, native_evidence_valid, protocol_valid); it "
    "performs no cryptographic verification.",
    "The binding stage is a deterministic string-agreement and "
    "interval-containment condition over subject fields read out of "
    "corpus-supplied artefacts; it verifies no signature, takes no "
    "measurement and is not attestation of any runtime.",
    "The SQL oracle in results-sql-oracle recomposes layer results and "
    "subject strings produced by this evaluator; it is a second "
    "composition code path, not independent validation.",
]


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


def build_authority_case(
    authority_module: ModuleType,
    authority_corpus: dict[str, Any],
    vector: dict[str, Any],
) -> dict[str, Any]:
    case = authority_module.build_case(
        authority_corpus["base"],
        vector["hops"],
        authority_corpus["effect_time"],
    )
    for mutation in vector["mutations"]:
        authority_module.apply_mutation(
            case, mutation["path"], mutation["value"]
        )
    return case


def evaluate_authority(
    authority_module: ModuleType,
    authority_corpus: dict[str, Any],
    case: dict[str, Any],
) -> dict[str, Any]:
    verdict, gate, bad_id, bad_index, trace = authority_module.evaluate(
        case, authority_corpus["base"], authority_corpus["effect_time"]
    )
    return {
        "verdict": verdict,
        "gate": gate,
        "first_bad_edge_id": bad_id,
        "first_bad_edge_index": bad_index,
        "trace": trace,
    }


def main() -> int:
    policy_module = load_module(
        "policy_version_evidence_replay_run", POLICY_DIR / "run.py"
    )
    safe_module = load_module(
        "safe_metric_metamorphics_run",
        SAFE_DIR / "run.py",
        prepend=SAFE_DIR,
    )
    authority_module = load_module(
        "typed_authority_paths", AUTHORITY_DIR / "verify_delegation_paths.py"
    )

    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    policy_corpus = json.loads(
        (POLICY_DIR / "corpus.json").read_text(encoding="utf-8")
    )
    safe_corpus = json.loads(
        (SAFE_DIR / "corpus.json").read_text(encoding="utf-8")
    )
    authority_corpus = json.loads(
        (AUTHORITY_DIR / "delegation-paths.json").read_text(encoding="utf-8")
    )
    policy_by_id = {item["id"]: item for item in policy_corpus["vectors"]}
    measurement_by_id = {
        item["id"]: item for item in safe_corpus["measurement_fixtures"]
    }
    measurement_by_id.update(corpus["measurement_variants"])
    authority_by_id = {
        item["id"]: item for item in authority_corpus["cases"]
    }
    evidence_variants = corpus["evidence_variants"]
    state_decision_time = corpus["state_decision_time"]

    public_key = policy_module.Ed25519PublicKey.from_public_bytes(
        policy_module.base64.b64decode(policy_corpus["public_key_raw_b64"])
    )
    preseen_nonces = set(policy_corpus["preseen_nonces"])

    results = []
    for transaction in corpus["transactions"]:
        vector = policy_by_id[transaction["policy_vector_id"]]
        evidence_object = (
            evidence_variants[transaction["evidence_variant_id"]]
            if transaction["evidence_variant_id"] is not None
            else vector["evidence"]
        )
        measurement_fixture = measurement_by_id[
            transaction["measurement_fixture_id"]
        ]

        policy_result, policy_gate, policy_details = (
            policy_module.evaluate_policy(
                public_key,
                vector["policy"],
                policy_corpus["policy_anchor"],
                policy_corpus["decision_time"],
            )
        )
        evidence_result, evidence_gate, evidence_details = (
            policy_module.evaluate_evidence(
                public_key, evidence_object, preseen_nonces
            )
        )
        policy_baselines = policy_module.baseline_verdicts(
            public_key, vector["policy"], evidence_result
        )
        measurement_result = safe_module.evaluate_measurement_fixture(
            measurement_fixture, safe_corpus
        )
        authority_case = build_authority_case(
            authority_module,
            authority_corpus,
            authority_by_id[transaction["authority_case_id"]],
        )
        authority_result = evaluate_authority(
            authority_module, authority_corpus, authority_case
        )
        state_result, state_gate, state_details = state_adapter.appraise_state(
            transaction["attestation_result"], state_decision_time
        )

        # Subject records re-derived from the same artefacts the five
        # evaluators just consumed, then checked against the stored record
        # fields. This is what makes canonical_action / observed_effect real
        # transaction fields rather than decoration.
        subjects = composition_rule.subjects_of(
            vector["policy"],
            authority_case,
            evidence_object,
            measurement_fixture,
        )
        subject_match = (
            subjects["canonical_action"] == transaction["canonical_action"]
            and subjects["observed_effect"] == transaction["observed_effect"]
        )
        binding = composition_rule.bind(subjects)

        composed = composition_rule.compose(
            policy_result,
            evidence_result,
            state_result,
            authority_result["verdict"],
            authority_result["gate"],
            measurement_result["result"],
            subjects,
        )
        layer_results = composed["layer_results"]
        failed_layers = composed["failed_layers"]
        verdict = composed["verdict"]
        gate = composed["first_rejecting_gate"]

        presence_only = policy_baselines["presence_only"]
        artifact_validity_only = (
            "ALLOW" if presence_only == "ALLOW" else "DENY"
        )
        # The point-only ablation replaces ONLY the measurement criterion;
        # it keeps the binding stage, so its historical counts are not
        # silently redefined by the arrival of that stage.
        point_only = (
            "ALLOW"
            if (
                policy_result == "PASS"
                and evidence_result == "PASS"
                and state_result == "PASS"
                and authority_result["verdict"] == "ALLOW"
                and measurement_result["point_only_result"] == "PASS"
                and binding["result"] == "PASS"
            )
            else "DENY"
        )
        passed_layer_count = sum(
            composition_rule.layer_passes(layer, layer_results[layer])
            for layer in composition_rule.EVALUATION_ORDER
        )
        # A compensating majority over the five artefact verifiers. It has
        # no binding stage by construction — that is the thing being ablated.
        majority = "ALLOW" if passed_layer_count >= 4 else "DENY"
        all_local_layers_pass = passed_layer_count == len(
            composition_rule.EVALUATION_ORDER
        )
        binding_details = binding["details"]
        effect_resource_match = (
            binding_details["effect_matches_policy"]
            and binding_details["effect_within_granted_tools"]
            and binding_details["resource_matches_canonical"]
            and binding_details["resource_within_granted_resources"]
        )
        # Plausible partial joins: each is subject-aware, but deliberately
        # omits at least one coordinate required by the proposed rule.
        effect_resource_binding = (
            "ALLOW"
            if all_local_layers_pass and effect_resource_match
            else "DENY"
        )
        effect_resource_time_binding = (
            "ALLOW"
            if (
                all_local_layers_pass
                and effect_resource_match
                and binding_details["issued_at_within_authorised_window"]
            )
            else "DENY"
        )
        effect_resource_profile_binding = (
            "ALLOW"
            if (
                all_local_layers_pass
                and effect_resource_match
                and binding_details["measurement_profile_matches_policy"]
            )
            else "DENY"
        )

        expected = transaction["expected"]
        expected_match = composed == expected
        per_layer_expected_match = (
            layer_results == expected["layer_results"]
        )
        results.append(
            {
                "id": transaction["id"],
                "family": transaction["family"],
                "verdict": verdict,
                "first_rejecting_gate": gate,
                "failed_layers": failed_layers,
                "layer_results": layer_results,
                "cross_layer_denial": (
                    verdict == "DENY" and not failed_layers
                ),
                "policy_evidence": {
                    "policy_gate": policy_details,
                    "evidence_gate": evidence_details,
                    "policy_first_gate": policy_gate,
                    "evidence_first_gate": evidence_gate,
                    "evidence_variant_id": transaction["evidence_variant_id"],
                },
                "state": {
                    "fixture_id": transaction["state_fixture_id"],
                    "gate": state_gate,
                    "details": state_details,
                },
                "authority": {
                    "case_id": transaction["authority_case_id"],
                    "gate": authority_result["gate"],
                    "first_bad_edge_id": authority_result["first_bad_edge_id"],
                    "first_bad_edge_index": authority_result[
                        "first_bad_edge_index"
                    ],
                },
                "measurement": {
                    "fixture_id": transaction["measurement_fixture_id"],
                    "fixture_source": transaction[
                        "measurement_fixture_source"
                    ],
                    "point_estimate": measurement_result["point_estimate"],
                    "lcb": measurement_result["lcb"],
                    "threshold": measurement_result["threshold"],
                    "profile_digest": measurement_result["profile_digest"],
                },
                "binding": {
                    "result": binding["result"],
                    "gate": binding["gate"],
                    "canonical_action": subjects["canonical_action"],
                    "observed_effect": subjects["observed_effect"],
                    "details": binding["details"],
                    "subject_match": subject_match,
                },
                "baselines": {
                    "artifact_validity_only": artifact_validity_only,
                    "point_only_measurement": point_only,
                    "four_of_five_majority": majority,
                    "effect_resource_binding": effect_resource_binding,
                    "effect_resource_time_binding": (
                        effect_resource_time_binding
                    ),
                    "effect_resource_profile_binding": (
                        effect_resource_profile_binding
                    ),
                },
                "expected": expected,
                "expected_match": expected_match,
                "per_layer_expected_match": per_layer_expected_match,
            }
        )

    layers = composition_rule.EVALUATION_ORDER
    families = sorted(corpus["families"])

    co_failure_matrix = {
        a: {
            b: sum(
                a in item["failed_layers"] and b in item["failed_layers"]
                for item in results
            )
            for b in layers
        }
        for a in layers
    }
    off_diagonal = [
        co_failure_matrix[a][b] for a in layers for b in layers if a != b
    ]
    min_offdiagonal = min(off_diagonal)

    failure_set_distribution: dict[str, int] = {}
    for item in results:
        key = "+".join(item["failed_layers"]) if item["failed_layers"] else "none"
        failure_set_distribution[key] = (
            failure_set_distribution.get(key, 0) + 1
        )
    distinct_nonempty_failure_sets = sum(
        key != "none" for key in failure_set_distribution
    )

    def usage(field: str) -> dict[str, int]:
        table: dict[str, int] = {}
        for transaction in corpus["transactions"]:
            value = transaction[field]
            # evidence_variant_id is null on every transaction that uses the
            # policy vector's own evidence object; name that bucket rather
            # than emitting a null JSON key.
            key = "(policy vector evidence)" if value is None else value
            table[key] = table.get(key, 0) + 1
        return table

    state_result_counts: dict[str, int] = {}
    for item in results:
        value = item["layer_results"]["state"]
        state_result_counts[value] = state_result_counts.get(value, 0) + 1

    binding_result_counts: dict[str, int] = {}
    for item in results:
        value = item["binding"]["result"]
        binding_result_counts[value] = binding_result_counts.get(value, 0) + 1

    cross_layer_denial_ids = sorted(
        item["id"] for item in results if item["cross_layer_denial"]
    )
    four_of_five_false_allow_ids = sorted(
        item["id"]
        for item in results
        if item["baselines"]["four_of_five_majority"] == "ALLOW"
        and item["expected"]["verdict"] == "DENY"
    )
    single_fault_deny_ids = sorted(
        item["id"]
        for item in results
        if item["expected"]["verdict"] == "DENY"
        and len(item["failed_layers"]) == 1
    )
    single_fault_layer_distribution: dict[str, int] = {}
    for item in results:
        if (
            item["expected"]["verdict"] == "DENY"
            and len(item["failed_layers"]) == 1
        ):
            layer = item["failed_layers"][0]
            single_fault_layer_distribution[layer] = (
                single_fault_layer_distribution.get(layer, 0) + 1
            )
    refined_identity_ids = sorted(
        set(single_fault_deny_ids) | set(cross_layer_denial_ids)
    )

    summary = {
        "profile": corpus["profile"],
        "transactions": len(results),
        "expected_matches": sum(item["expected_match"] for item in results),
        "per_layer_expected_matches": sum(
            item["per_layer_expected_match"] for item in results
        ),
        "subject_matches": sum(
            item["binding"]["subject_match"] for item in results
        ),
        "allows": sum(item["verdict"] == "ALLOW" for item in results),
        "denies": sum(item["verdict"] == "DENY" for item in results),
        "family_counts": {
            family: sum(item["family"] == family for item in results)
            for family in families
        },
        "family_verdicts": {
            family: {
                "allows": sum(
                    item["family"] == family and item["verdict"] == "ALLOW"
                    for item in results
                ),
                "denies": sum(
                    item["family"] == family and item["verdict"] == "DENY"
                    for item in results
                ),
            }
            for family in families
        },
        "failed_layer_occurrences": {
            layer: sum(layer in item["failed_layers"] for item in results)
            for layer in layers
        },
        "co_failure_matrix": co_failure_matrix,
        "co_failure_min_offdiagonal": min_offdiagonal,
        "co_failure_no_zero_offdiagonal": min_offdiagonal > 0,
        "failure_set_distribution": failure_set_distribution,
        "distinct_nonempty_failure_sets": distinct_nonempty_failure_sets,
        "binding_stage": {
            "binding_result_counts": binding_result_counts,
            "binding_result_counts_by_family": {
                family: {
                    value: sum(
                        item["family"] == family
                        and item["binding"]["result"] == value
                        for item in results
                    )
                    for value in sorted(
                        {item["binding"]["result"] for item in results}
                    )
                }
                for family in families
            },
            "cross_layer_denials": len(cross_layer_denial_ids),
            "cross_layer_denial_ids": cross_layer_denial_ids,
            "cross_layer_denials_by_family": {
                family: sum(
                    item["family"] == family and item["cross_layer_denial"]
                    for item in results
                )
                for family in families
            },
            "binding_gate_counts": {
                gate: sum(
                    item["first_rejecting_gate"] == gate for item in results
                )
                for gate in sorted(
                    set(composition_rule.BINDING_GATES.values())
                )
            },
            "definition": (
                "a cross-layer denial is a transaction whose five artefact "
                "verifiers all passed and whose composed verdict is DENY; "
                "before the binding stage existed no such transaction could "
                "be represented, so this count was structurally zero"
            ),
            "method": composition_rule.BINDING_METHOD,
        },
        "coverage": {
            "authority_case_usage": usage("authority_case_id"),
            "measurement_fixture_usage": usage("measurement_fixture_id"),
            "state_fixture_usage": usage("state_fixture_id"),
            "evidence_variant_usage": usage("evidence_variant_id"),
            "state_result_counts": state_result_counts,
        },
        "baseline_false_allows": {
            name: sum(
                item["baselines"][name] == "ALLOW"
                and item["expected"]["verdict"] == "DENY"
                for item in results
            )
            for name in BASELINE_NAMES
        },
        "baseline_false_allows_by_family": {
            family: {
                name: sum(
                    item["family"] == family
                    and item["baselines"][name] == "ALLOW"
                    and item["expected"]["verdict"] == "DENY"
                    for item in results
                )
                for name in BASELINE_NAMES
            }
            for family in families
        },
        "baseline_expected_matches": {
            name: sum(
                item["baselines"][name] == item["expected"]["verdict"]
                for item in results
            )
            for name in BASELINE_NAMES
        },
        "baseline_note": (
            "baselines are experimental ablations defined by the authors; "
            "they are not representations of named external products. The "
            "point-only ablation replaces only the measurement criterion "
            "and keeps the binding stage; the four-of-five majority is an "
            "ablation OF the binding stage as well, since it votes over the "
            "five artefact verifiers only. The three partial-binding "
            "baselines require all five local verifiers and effect/resource "
            "agreement, then add either neither, time, or measurement-profile "
            "agreement; each therefore omits at least one implemented "
            "binding dimension"
        ),
        "analytic_identities": {
            "four_of_five_equals_single_fault_denies": {
                "holds": (
                    four_of_five_false_allow_ids == single_fault_deny_ids
                ),
                "set_equality_on_ids": (
                    four_of_five_false_allow_ids == single_fault_deny_ids
                ),
                "four_of_five_false_allow_count": len(
                    four_of_five_false_allow_ids
                ),
                "single_fault_deny_count": len(single_fault_deny_ids),
                "single_fault_layer_distribution": (
                    single_fault_layer_distribution
                ),
                "note": (
                    "In corpus v2 this identity held. It does NOT hold in "
                    "v3, and the reason is the point of the v3 rebuild: a "
                    "four-of-five majority allows a transaction iff at most "
                    "one of the five artefact verifiers fails, so once "
                    "cross-layer denials exist (zero failing verifiers, "
                    "DENY verdict) the majority's false allows are the "
                    "single-fault denies UNION the cross-layer denials. The "
                    "counts measure how many such transactions the corpus "
                    "contains, not a property of any deployed system"
                ),
            },
            "four_of_five_equals_single_fault_or_cross_layer": {
                "holds": (
                    four_of_five_false_allow_ids == refined_identity_ids
                ),
                "four_of_five_false_allow_count": len(
                    four_of_five_false_allow_ids
                ),
                "single_fault_deny_count": len(single_fault_deny_ids),
                "cross_layer_denial_count": len(cross_layer_denial_ids),
                "note": (
                    "the refined identity that replaces the v2 one, "
                    "verified as set equality on transaction identifiers"
                ),
            },
        },
        "label_provenance": composition_rule.LABEL_PROVENANCE,
        "disclaimers": DISCLAIMERS,
        "corpus_sha256": sha256_file(CORPUS_PATH),
        "runner_sha256": sha256_file(Path(__file__)),
        "composition_rule_sha256": sha256_file(ROOT / "composition_rule.py"),
        "state_adapter_sha256": sha256_file(ROOT / "state_adapter.py"),
        "source_hashes_match_corpus": all(
            sha256_file((ROOT / item["path"]).resolve()) == item["sha256"]
            for item in corpus["source_artifacts"].values()
        ),
    }
    metadata = {
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": safe_module.np.__version__,
        "cryptography": policy_module.cryptography.__version__,
        "network_used": False,
        "network_used_note": (
            "declared property of the entry points, not an enforced "
            "sandbox measurement"
        ),
        "evaluation_order": corpus["evaluation_order"],
        "binding_stage_position": corpus["binding_stage"]["position"],
        "state_decision_time": state_decision_time,
    }

    RESULTS.mkdir(exist_ok=True)
    verdicts_path = RESULTS / "verdicts.jsonl"
    summary_path = RESULTS / "summary.json"
    metadata_path = RESULTS / "run-metadata.json"
    verdicts_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (RESULTS / "SHA256SUMS").write_text(
        "\n".join(
            [
                f"{sha256_file(verdicts_path)}  verdicts.jsonl",
                f"{sha256_file(summary_path)}  summary.json",
                f"{sha256_file(metadata_path)}  run-metadata.json",
                f"{sha256_file(CORPUS_PATH)}  ../corpus.json",
                f"{sha256_file(Path(__file__))}  ../verify_transactions.py",
                f"{sha256_file(ROOT / 'build_corpus.py')}  ../build_corpus.py",
                f"{sha256_file(ROOT / 'composition_rule.py')}  ../composition_rule.py",
                f"{sha256_file(ROOT / 'state_adapter.py')}  ../state_adapter.py",
                f"{sha256_file(ROOT / 'test_state_adapter.py')}  ../test_state_adapter.py",
                f"{sha256_file(ROOT / 'test_cross_layer_binding.py')}  ../test_cross_layer_binding.py",
                f"{sha256_file(STATE_FIXTURES_PATH)}  ../state-fixtures.json",
                f"{sha256_file(POLICY_DIR / 'run.py')}  ../../policy-version-evidence-replay/run.py",
                f"{sha256_file(POLICY_DIR / 'build_corpus.py')}  ../../policy-version-evidence-replay/build_corpus.py",
                f"{sha256_file(AUTHORITY_DIR / 'verify_delegation_paths.py')}  ../../protocol-valid-unauthorized/verify_delegation_paths.py",
                f"{sha256_file(SAFE_DIR / 'run.py')}  ../../../../research-factory-v3-2026-07-25/labs/safe-metric-metamorphics/run.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if (
        summary["expected_matches"] == len(results)
        and summary["per_layer_expected_matches"] == len(results)
        and summary["subject_matches"] == len(results)
        and summary["source_hashes_match_corpus"]
        and summary["co_failure_no_zero_offdiagonal"]
        and summary["binding_stage"]["cross_layer_denials"] > 0
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
