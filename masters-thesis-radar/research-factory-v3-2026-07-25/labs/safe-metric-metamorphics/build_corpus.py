#!/usr/bin/env python3
"""Build deterministic SAFE metric, bootstrap and TOPSIS fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def sample_matrix(
    rng: np.random.Generator,
    means: list[float],
    standard_deviation: float,
    count: int,
) -> list[list[float]]:
    covariance = np.full(
        (3, 3), 0.4 * standard_deviation * standard_deviation
    )
    np.fill_diagonal(covariance, standard_deviation * standard_deviation)
    values = rng.multivariate_normal(means, covariance, count)
    return np.clip(values, 0.01, 0.99).tolist()


def main() -> int:
    main_profile = {
        "profile_id": "safe-profile-main-v1",
        "metric_family": "Giudici-Kolesnikov-SAFE-derived-test-profile",
        "severity_grid": [0.0, 0.25, 0.5, 0.75, 1.0],
        "zero_anchor": 0.0,
        "perturbation_family": "feature-removal-ordered-v1",
        "aggregation": "arithmetic-tensor",
        "topsis_reference": "fixed-0-1",
        "sampling_overlap": "shared",
    }
    altered_profile = {
        **main_profile,
        "profile_id": "safe-profile-altered-v1",
        "severity_grid": [0.0, 0.5, 1.0],
    }

    rng = np.random.default_rng(20260725)
    datasets = {
        "supported": sample_matrix(rng, [0.84, 0.82, 0.80], 0.055, 30),
        "point_only": sample_matrix(rng, [0.77, 0.76, 0.75], 0.10, 18),
        "unsupported": sample_matrix(rng, [0.69, 0.70, 0.68], 0.06, 30),
    }
    measurement_fixtures = [
        {
            "id": "measurement_supported",
            "dataset": "supported",
            "profile": main_profile,
            "required_profile_digest": digest(main_profile),
            "threshold": 0.75,
            "alpha": 0.05,
            "expected": "PASS",
        },
        {
            "id": "measurement_point_only",
            "dataset": "point_only",
            "profile": main_profile,
            "required_profile_digest": digest(main_profile),
            "threshold": 0.75,
            "alpha": 0.05,
            "expected": "FAIL_LCB",
        },
        {
            "id": "measurement_unsupported",
            "dataset": "unsupported",
            "profile": main_profile,
            "required_profile_digest": digest(main_profile),
            "threshold": 0.75,
            "alpha": 0.05,
            "expected": "FAIL_POINT",
        },
        {
            "id": "measurement_profile_mismatch",
            "dataset": "supported",
            "profile": altered_profile,
            "required_profile_digest": digest(main_profile),
            "threshold": 0.75,
            "alpha": 0.05,
            "expected": "PROFILE_MISMATCH",
        },
    ]

    corpus = {
        "profile": "tyche-safe-metric-metamorphics-v1",
        "base_vectors": {
            "RGA": [0.74, 0.79, 0.83, 0.88],
            "RGE": [0.62, 0.71, 0.80, 0.86],
            "RGR": [0.68, 0.73, 0.77, 0.82],
        },
        "profiles": {
            "main": main_profile,
            "altered": altered_profile,
        },
        "profile_mutations": [
            {"field": "severity_grid", "value": [0.0, 0.5, 1.0]},
            {"field": "zero_anchor", "value": 0.1},
            {"field": "perturbation_family", "value": "random-removal-v1"},
            {"field": "aggregation", "value": "geometric-tensor"},
            {"field": "topsis_reference", "value": "dynamic-observed"},
            {"field": "sampling_overlap", "value": "unknown"},
        ],
        "topsis": {
            "weights": [1.0 / 3.0, 1.0 / 3.0, 1.0 / 3.0],
            "base_alternatives": [
                [0.91523876, 0.67678372, 0.42182445],
                [0.74434274, 0.38129969, 0.32989705],
                [0.51577418, 0.35107988, 0.50560654],
            ],
            "added_alternative": [0.20146128, 0.48101048, 0.80093428],
            "expected_dynamic_reversal": True,
            "expected_fixed_invariance": True,
        },
        "datasets": datasets,
        "measurement_fixtures": measurement_fixtures,
        "bootstrap": {
            "replicates": 5000,
            "seed_by_dataset": {
                "supported": 101,
                "point_only": 102,
                "unsupported": 103,
            },
            "overlap_boundary_threshold": 0.737,
            "overlap_fixture": "point_only",
        },
        "generation": {
            "numpy_seed": 20260725,
            "synthetic_boundary_fixtures": True,
            "source_metric_values_are_not_claimed_as_pavia_empirical_results": True,
        },
    }
    CORPUS_PATH.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote={CORPUS_PATH}")
    print(f"corpus_sha256={hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
