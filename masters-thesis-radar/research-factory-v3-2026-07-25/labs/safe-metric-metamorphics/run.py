#!/usr/bin/env python3
"""Execute formula, profile, TOPSIS, bootstrap and passport metamorphics."""

from __future__ import annotations

import copy
import hashlib
import itertools
import json
import platform
import sys
from pathlib import Path
from typing import Any

import numpy as np

import reference_impl as reference
import vector_impl as vectorized


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
RESULTS = ROOT / "results"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def close(left: float, right: float, tolerance: float = 1e-12) -> bool:
    return abs(left - right) <= tolerance


def bootstrap_distribution(
    samples: np.ndarray, replicates: int, seed: int, joint: bool
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    count = len(samples)
    output = np.empty(replicates)
    for index in range(replicates):
        if joint:
            rows = rng.integers(0, count, count)
            output[index] = np.mean(samples[rows])
        else:
            means = [
                np.mean(samples[rng.integers(0, count, count), column])
                for column in range(samples.shape[1])
            ]
            output[index] = float(np.mean(means))
    return output


def evaluate_measurement_fixture(
    fixture: dict[str, Any], corpus: dict[str, Any]
) -> dict[str, Any]:
    supplied_profile_digest = digest(fixture["profile"])
    samples = np.asarray(corpus["datasets"][fixture["dataset"]], dtype=float)
    point = float(np.mean(samples))
    bootstrap = bootstrap_distribution(
        samples,
        corpus["bootstrap"]["replicates"],
        corpus["bootstrap"]["seed_by_dataset"][fixture["dataset"]],
        joint=True,
    )
    lcb = float(np.quantile(bootstrap, fixture["alpha"]))
    if supplied_profile_digest != fixture["required_profile_digest"]:
        result = "PROFILE_MISMATCH"
        gate = "measurement.profile"
    elif point < fixture["threshold"]:
        result = "FAIL_POINT"
        gate = "measurement.point"
    elif lcb < fixture["threshold"]:
        result = "FAIL_LCB"
        gate = "measurement.confidence"
    else:
        result = "PASS"
        gate = "measurement.verified"
    point_only_verdict = (
        "PASS" if point >= fixture["threshold"] else "FAIL_POINT"
    )
    return {
        "id": fixture["id"],
        "dataset": fixture["dataset"],
        "sample_count": len(samples),
        "profile_digest": supplied_profile_digest,
        "required_profile_digest": fixture["required_profile_digest"],
        "point_estimate": point,
        "lcb": lcb,
        "threshold": fixture["threshold"],
        "alpha": fixture["alpha"],
        "result": result,
        "gate": gate,
        "point_only_result": point_only_verdict,
        "expected": fixture["expected"],
        "expected_match": result == fixture["expected"],
    }


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    vectors = corpus["base_vectors"]
    a, b, c = vectors["RGA"], vectors["RGE"], vectors["RGR"]

    ref_values = {
        "arithmetic": reference.arithmetic_tensor(a, b, c),
        "geometric": reference.geometric_tensor(a, b, c),
        "rms": reference.rms_tensor(a, b, c),
    }
    vector_values = {
        "arithmetic": vectorized.arithmetic_tensor(a, b, c),
        "geometric": vectorized.geometric_tensor(a, b, c),
        "rms": vectorized.rms_tensor(a, b, c),
    }
    checks: list[dict[str, Any]] = []

    for name in ("arithmetic", "geometric", "rms"):
        checks.append(
            {
                "id": f"two_implementations_{name}",
                "pass": close(ref_values[name], vector_values[name]),
                "observed": [ref_values[name], vector_values[name]],
            }
        )
    checks.extend(
        [
            {
                "id": "arithmetic_factorization",
                "pass": close(
                    ref_values["arithmetic"],
                    reference.arithmetic_factorized(a, b, c),
                ),
                "observed": [
                    ref_values["arithmetic"],
                    reference.arithmetic_factorized(a, b, c),
                ],
            },
            {
                "id": "geometric_factorization",
                "pass": close(
                    ref_values["geometric"],
                    reference.geometric_factorized(a, b, c),
                ),
                "observed": [
                    ref_values["geometric"],
                    reference.geometric_factorized(a, b, c),
                ],
            },
            {
                "id": "geometric_le_arithmetic_le_rms",
                "pass": (
                    ref_values["geometric"]
                    <= ref_values["arithmetic"]
                    <= ref_values["rms"]
                ),
                "observed": ref_values,
            },
        ]
    )

    permuted_values = []
    for permutation in itertools.permutations((a, b, c)):
        permuted_values.append(reference.arithmetic_tensor(*permutation))
    checks.append(
        {
            "id": "axis_permutation_invariance",
            "pass": all(close(value, ref_values["arithmetic"]) for value in permuted_values),
            "observed": permuted_values,
        }
    )
    reordered = reference.arithmetic_tensor(
        list(reversed(a)), [b[2], b[0], b[3], b[1]], [c[1], c[3], c[0], c[2]]
    )
    checks.append(
        {
            "id": "within_axis_order_invariance",
            "pass": close(reordered, ref_values["arithmetic"]),
            "observed": [ref_values["arithmetic"], reordered],
        }
    )
    diagonal = reference.diagonal(a, b, c, "geometric")
    checks.append(
        {
            "id": "tensor_diagonal_non_equivalence_fixture",
            "pass": not close(diagonal, ref_values["geometric"], tolerance=1e-8),
            "observed": {
                "geometric_tensor": ref_values["geometric"],
                "geometric_diagonal": diagonal,
            },
        }
    )

    main_profile = corpus["profiles"]["main"]
    main_digest = digest(main_profile)
    profile_results = []
    for mutation in corpus["profile_mutations"]:
        changed = copy.deepcopy(main_profile)
        changed[mutation["field"]] = mutation["value"]
        changed_digest = digest(changed)
        profile_results.append(
            {
                "field": mutation["field"],
                "base_digest": main_digest,
                "changed_digest": changed_digest,
                "digest_changed": changed_digest != main_digest,
            }
        )
    checks.append(
        {
            "id": "profile_digest_sensitivity",
            "pass": all(item["digest_changed"] for item in profile_results),
            "observed": profile_results,
        }
    )

    topsis = corpus["topsis"]
    base = topsis["base_alternatives"]
    augmented = base + [topsis["added_alternative"]]
    dynamic_base_ref = reference.topsis_dynamic(base, topsis["weights"])
    dynamic_aug_ref = reference.topsis_dynamic(augmented, topsis["weights"])
    fixed_base_ref = reference.topsis_fixed(base, topsis["weights"])
    fixed_aug_ref = reference.topsis_fixed(augmented, topsis["weights"])
    dynamic_base_vec = vectorized.topsis_dynamic(base, topsis["weights"])
    dynamic_aug_vec = vectorized.topsis_dynamic(augmented, topsis["weights"])
    fixed_base_vec = vectorized.topsis_fixed(base, topsis["weights"])
    fixed_aug_vec = vectorized.topsis_fixed(augmented, topsis["weights"])

    dynamic_base_order = reference.ranking(dynamic_base_ref)
    dynamic_aug_original_order = [
        index
        for index in reference.ranking(dynamic_aug_ref)
        if index < len(base)
    ]
    fixed_base_order = reference.ranking(fixed_base_ref)
    fixed_aug_original_order = [
        index for index in reference.ranking(fixed_aug_ref) if index < len(base)
    ]
    topsis_result = {
        "dynamic_base_scores": dynamic_base_ref,
        "dynamic_augmented_scores": dynamic_aug_ref,
        "dynamic_base_order": dynamic_base_order,
        "dynamic_augmented_original_order": dynamic_aug_original_order,
        "dynamic_rank_reversal": dynamic_base_order != dynamic_aug_original_order,
        "fixed_base_scores": fixed_base_ref,
        "fixed_augmented_scores": fixed_aug_ref,
        "fixed_base_order": fixed_base_order,
        "fixed_augmented_original_order": fixed_aug_original_order,
        "fixed_rank_invariant": fixed_base_order == fixed_aug_original_order,
        "two_implementation_agreement": all(
            np.allclose(left, right, atol=1e-12, rtol=0.0)
            for left, right in (
                (dynamic_base_ref, dynamic_base_vec),
                (dynamic_aug_ref, dynamic_aug_vec),
                (fixed_base_ref, fixed_base_vec),
                (fixed_aug_ref, fixed_aug_vec),
            )
        ),
    }
    checks.extend(
        [
            {
                "id": "topsis_two_implementation_agreement",
                "pass": topsis_result["two_implementation_agreement"],
                "observed": topsis_result,
            },
            {
                "id": "dynamic_topsis_rank_reversal_fixture",
                "pass": topsis_result["dynamic_rank_reversal"],
                "observed": topsis_result,
            },
            {
                "id": "fixed_topsis_rank_invariance",
                "pass": topsis_result["fixed_rank_invariant"],
                "observed": topsis_result,
            },
        ]
    )

    measurement_results = [
        evaluate_measurement_fixture(fixture, corpus)
        for fixture in corpus["measurement_fixtures"]
    ]
    point_only = next(
        item for item in corpus["measurement_fixtures"] if item["id"] == "measurement_point_only"
    )
    point_samples = np.asarray(
        corpus["datasets"][point_only["dataset"]], dtype=float
    )
    bootstrap_settings = corpus["bootstrap"]
    joint = bootstrap_distribution(
        point_samples,
        bootstrap_settings["replicates"],
        bootstrap_settings["seed_by_dataset"][point_only["dataset"]],
        joint=True,
    )
    independent = bootstrap_distribution(
        point_samples,
        bootstrap_settings["replicates"],
        bootstrap_settings["seed_by_dataset"][point_only["dataset"]],
        joint=False,
    )
    overlap_threshold = bootstrap_settings["overlap_boundary_threshold"]
    overlap_result = {
        "fixture": point_only["dataset"],
        "threshold": overlap_threshold,
        "joint_lcb": float(np.quantile(joint, point_only["alpha"])),
        "independence_assumed_lcb": float(
            np.quantile(independent, point_only["alpha"])
        ),
    }
    overlap_result["decision_differs"] = (
        overlap_result["joint_lcb"] < overlap_threshold
        <= overlap_result["independence_assumed_lcb"]
    )
    checks.extend(
        [
            {
                "id": "measurement_fixture_expectations",
                "pass": all(item["expected_match"] for item in measurement_results),
                "observed": measurement_results,
            },
            {
                "id": "sampling_overlap_boundary_fixture",
                "pass": overlap_result["decision_differs"],
                "observed": overlap_result,
            },
        ]
    )

    summary = {
        "profile": corpus["profile"],
        "checks": len(checks),
        "checks_passed": sum(item["pass"] for item in checks),
        "checks_failed": sum(not item["pass"] for item in checks),
        "formula_values": ref_values,
        "profile_digest_mutations": len(profile_results),
        "profile_digest_changes": sum(
            item["digest_changed"] for item in profile_results
        ),
        "dynamic_topsis_rank_reversal": topsis_result["dynamic_rank_reversal"],
        "fixed_topsis_rank_invariant": topsis_result["fixed_rank_invariant"],
        "measurement_fixtures": len(measurement_results),
        "measurement_fixture_matches": sum(
            item["expected_match"] for item in measurement_results
        ),
        "point_only_false_allows": sum(
            item["point_only_result"] == "PASS" and item["result"] != "PASS"
            for item in measurement_results
        ),
        "overlap_decision_differs": overlap_result["decision_differs"],
        "corpus_sha256": sha256_file(CORPUS_PATH),
        "reference_impl_sha256": sha256_file(ROOT / "reference_impl.py"),
        "vector_impl_sha256": sha256_file(ROOT / "vector_impl.py"),
        "runner_sha256": sha256_file(Path(__file__)),
    }
    metadata = {
        "python": sys.version,
        "platform": platform.platform(),
        "numpy": np.__version__,
        "network_used": False,
        "bootstrap_replicates": bootstrap_settings["replicates"],
    }

    RESULTS.mkdir(exist_ok=True)
    checks_path = RESULTS / "checks.jsonl"
    measurements_path = RESULTS / "measurement-fixtures.json"
    topsis_path = RESULTS / "topsis-result.json"
    overlap_path = RESULTS / "overlap-result.json"
    summary_path = RESULTS / "summary.json"
    metadata_path = RESULTS / "run-metadata.json"
    checks_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in checks),
        encoding="utf-8",
    )
    measurements_path.write_text(
        json.dumps(measurement_results, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    topsis_path.write_text(
        json.dumps(topsis_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    overlap_path.write_text(
        json.dumps(overlap_result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checksum_entries = [
        checks_path,
        measurements_path,
        topsis_path,
        overlap_path,
        summary_path,
        metadata_path,
    ]
    (RESULTS / "SHA256SUMS").write_text(
        "\n".join(
            f"{sha256_file(path)}  {path.name}" for path in checksum_entries
        )
        + "\n"
        + "\n".join(
            [
                f"{sha256_file(CORPUS_PATH)}  ../corpus.json",
                f"{sha256_file(Path(__file__))}  ../run.py",
                f"{sha256_file(ROOT / 'build_corpus.py')}  ../build_corpus.py",
                f"{sha256_file(ROOT / 'reference_impl.py')}  ../reference_impl.py",
                f"{sha256_file(ROOT / 'vector_impl.py')}  ../vector_impl.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["checks_failed"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
