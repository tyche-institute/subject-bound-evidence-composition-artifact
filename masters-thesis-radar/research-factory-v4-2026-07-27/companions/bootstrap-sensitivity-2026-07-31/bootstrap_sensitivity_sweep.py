#!/usr/bin/env python3
"""Seed/replicate sensitivity sweep for the SAFE measurement bootstrap.

Reads the frozen SAFE corpus read-only and recomputes the one-sided
percentile lower confidence bound for every measurement fixture dataset
under five seeds x three replicate counts, using the exact bootstrap
implementation of the frozen laboratory (plain percentile, joint row
resampling, numpy default_rng). Also recomputes the sampling-overlap
boundary comparison (joint vs independent column resampling) on the
overlap fixture dataset.

The frozen laboratory's published values (seeds 101/102/103, 5,000
replicates) are not modified; this sweep is a companion sensitivity
analysis addressing the stated limitation that no seed or
replicate-count sensitivity sweep had been run.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import numpy as np

CORPUS = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "../../masters-thesis-radar/research-factory-v3-2026-07-25/"
    "labs/safe-metric-metamorphics/corpus.json"
)
OUTPUT = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("sweep-results.json")

SEEDS = [11, 23, 47, 101, 977]
REPLICATES = [2000, 5000, 10000]
ALPHA = 0.05


def bootstrap_distribution(
    samples: np.ndarray, replicates: int, seed: int, joint: bool
) -> np.ndarray:
    # Byte-for-byte the frozen laboratory's implementation (run.py).
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


def main() -> None:
    corpus = json.loads(CORPUS.read_text())
    datasets = {
        name: np.asarray(rows, dtype=float)
        for name, rows in corpus["datasets"].items()
    }
    frozen_seeds = corpus["bootstrap"]["seed_by_dataset"]
    overlap_threshold = corpus["bootstrap"]["overlap_boundary_threshold"]
    overlap_dataset = corpus["bootstrap"]["overlap_fixture"]

    results: dict[str, object] = {
        "sweep": {
            "seeds": SEEDS,
            "replicate_counts": REPLICATES,
            "alpha": ALPHA,
            "method": "plain percentile, joint row resampling",
            "frozen_reference": {
                "seed_by_dataset": frozen_seeds,
                "replicates": corpus["bootstrap"]["replicates"],
            },
        },
        "fixtures": [],
        "overlap_boundary": [],
    }

    for fixture in corpus["measurement_fixtures"]:
        name = fixture["dataset"]
        samples = datasets[name]
        threshold = fixture["threshold"]
        point = float(np.mean(samples))
        rows = []
        for seed in SEEDS:
            for replicates in REPLICATES:
                lcb = float(
                    np.quantile(
                        bootstrap_distribution(samples, replicates, seed, True),
                        ALPHA,
                    )
                )
                rows.append(
                    {
                        "seed": seed,
                        "replicates": replicates,
                        "lcb": lcb,
                        "lcb_below_threshold": lcb < threshold,
                    }
                )
        lcbs = [row["lcb"] for row in rows]
        confidence_outcome_stable = len(
            {row["lcb_below_threshold"] for row in rows}
        ) == 1
        results["fixtures"].append(
            {
                "id": fixture["id"],
                "dataset": name,
                "n": int(samples.shape[0]),
                "threshold": threshold,
                "point_estimate": point,
                "grid_points": len(rows),
                "lcb_min": min(lcbs),
                "lcb_max": max(lcbs),
                "lcb_spread": max(lcbs) - min(lcbs),
                "confidence_outcome_stable": confidence_outcome_stable,
                "rows": rows,
            }
        )

    samples = datasets[overlap_dataset]
    for seed in SEEDS:
        for replicates in REPLICATES:
            joint = float(
                np.quantile(
                    bootstrap_distribution(samples, replicates, seed, True),
                    ALPHA,
                )
            )
            independent = float(
                np.quantile(
                    bootstrap_distribution(samples, replicates, seed, False),
                    ALPHA,
                )
            )
            results["overlap_boundary"].append(
                {
                    "seed": seed,
                    "replicates": replicates,
                    "joint_lcb": joint,
                    "independent_lcb": independent,
                    "threshold": overlap_threshold,
                    "decision_flips_at_threshold": (joint < overlap_threshold)
                    != (independent < overlap_threshold),
                }
            )

    flips = [row["decision_flips_at_threshold"] for row in results["overlap_boundary"]]
    results["overlap_summary"] = {
        "grid_points": len(flips),
        "flip_count": sum(flips),
        "joint_lcb_min": min(r["joint_lcb"] for r in results["overlap_boundary"]),
        "joint_lcb_max": max(r["joint_lcb"] for r in results["overlap_boundary"]),
        "independent_lcb_min": min(
            r["independent_lcb"] for r in results["overlap_boundary"]
        ),
        "independent_lcb_max": max(
            r["independent_lcb"] for r in results["overlap_boundary"]
        ),
    }

    OUTPUT.write_text(json.dumps(results, indent=1, sort_keys=True) + "\n")
    for fx in results["fixtures"]:
        print(
            f"{fx['id']}: n={fx['n']} point={fx['point_estimate']:.6f} "
            f"LCB [{fx['lcb_min']:.6f}, {fx['lcb_max']:.6f}] "
            f"spread={fx['lcb_spread']:.6f} "
            f"stable={fx['confidence_outcome_stable']}"
        )
    ov = results["overlap_summary"]
    print(
        f"overlap: joint [{ov['joint_lcb_min']:.6f}, {ov['joint_lcb_max']:.6f}] "
        f"independent [{ov['independent_lcb_min']:.6f}, "
        f"{ov['independent_lcb_max']:.6f}] flips {ov['flip_count']}/{ov['grid_points']}"
    )


if __name__ == "__main__":
    main()
