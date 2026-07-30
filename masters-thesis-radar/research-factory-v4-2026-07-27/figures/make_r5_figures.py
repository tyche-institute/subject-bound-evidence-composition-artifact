#!/usr/bin/env python3
"""Generate the r5 evidence-class upgrade figure from saved results."""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ["SOURCE_DATE_EPOCH"] = "1785110400"

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt


HERE = Path(__file__).resolve().parent
FACTORY = HERE.parent
NATIVE = (
    FACTORY
    / "labs"
    / "native-state-transaction-overlay"
    / "results"
    / "summary.json"
)
DURABLE = (
    FACTORY / "labs" / "distributed-revocation-service" / "results.json"
)

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 7.5,
        "text.color": "black",
        "axes.edgecolor": "black",
        "axes.labelcolor": "black",
        "xtick.color": "black",
        "ytick.color": "black",
        "figure.facecolor": "white",
        "axes.facecolor": "white",
        "savefig.facecolor": "white",
        "savefig.edgecolor": "white",
        "pdf.fonttype": 42,
        "svg.fonttype": "none",
        "svg.hashsalt": "tyche-r5-figures-2026-07-28",
        "hatch.color": "black",
        "hatch.linewidth": 0.65,
        "lines.solid_joinstyle": "miter",
        "patch.force_edgecolor": True,
    }
)


def label_bars(axis: plt.Axes, bars, values: list[int], offset: float) -> None:
    for bar, value in zip(bars, values):
        axis.text(
            value + offset,
            bar.get_y() + bar.get_height() / 2,
            str(value),
            va="center",
            ha="left",
            fontsize=7.5,
        )


def build() -> dict[str, object]:
    native = json.loads(NATIVE.read_text(encoding="utf-8"))
    durable = json.loads(DURABLE.read_text(encoding="utf-8"))["summary"]

    assert native["all_passed"]
    assert native["source_vectors"] == 104
    assert native["native_oracle_matches"] == 104
    assert native["mutation_cases"] == 64
    assert native["mutation_rejections"] == 64
    assert native["composed_exact_matches"] == 104
    assert native["distinct_ak_public_keys"] == 8
    assert native["unique_challenges"] == 104
    assert durable["all_passed"]
    assert durable["cases"] == 372
    assert durable["fault_cases"] == durable["fault_recoveries"] == 96
    assert durable["duplicate_effects"] == 0
    assert durable["profiles"]["atomic_guard"]["false_allows"] == 0

    fig, axes = plt.subplots(
        1,
        3,
        figsize=(5.917, 3.25),
        gridspec_kw={"wspace": 0.58},
    )

    class_labels = ["PASS", "contra.", "stale", "ref. mismatch"]
    class_values = [
        native["state_class_counts"]["PASS"],
        native["state_class_counts"]["CONTRAINDICATED"],
        native["state_class_counts"]["STALE"],
        native["state_class_counts"]["REFERENCE_MISMATCH"],
    ]
    bars = axes[0].barh(
        range(4),
        class_values,
        height=0.55,
        color="white",
        edgecolor="black",
        linewidth=0.8,
    )
    for bar, hatch in zip(bars, ["", "////", "..", "xx"]):
        bar.set_hatch(hatch)
    label_bars(axes[0], bars, class_values, 1.2)
    axes[0].set_yticks(range(4))
    axes[0].set_yticklabels(class_labels)
    axes[0].invert_yaxis()
    axes[0].set_xlim(0, 100)
    axes[0].set_xticks([0, 50, 100])
    axes[0].set_xlabel("transactions")
    axes[0].set_title("(a) Native state classes", loc="left", fontsize=8.5)

    check_labels = ["state oracle", "mutations", "recomposition"]
    check_values = [
        native["native_oracle_matches"],
        native["mutation_rejections"],
        native["composed_exact_matches"],
    ]
    check_totals = [
        native["source_vectors"],
        native["mutation_cases"],
        native["composed_cases"],
    ]
    check_pct = [
        100 * value / total
        for value, total in zip(check_values, check_totals)
    ]
    bars = axes[1].barh(
        range(3),
        check_pct,
        height=0.52,
        color="white",
        edgecolor="black",
        linewidth=0.8,
        hatch="////",
    )
    for bar, value, total in zip(bars, check_values, check_totals):
        axes[1].text(
            50,
            bar.get_y() + bar.get_height() / 2,
            f"{value}/{total}",
            va="center",
            ha="center",
            fontsize=7.5,
        )
    axes[1].set_yticks(range(3))
    axes[1].set_yticklabels(check_labels)
    axes[1].invert_yaxis()
    axes[1].set_xlim(0, 100)
    axes[1].set_xticks([0, 50, 100])
    axes[1].set_xlabel("checks passed (%)")
    axes[1].set_title("(b) Overlay invariants", loc="left", fontsize=8.5)

    profile_keys = ["atomic_guard", "double_read", "single_read", "ttl_cache"]
    profile_labels = ["atomic", "double read", "single read", "TTL cache"]
    false_allows = [
        durable["profiles"][key]["false_allows"] for key in profile_keys
    ]
    assert false_allows == [0, 61, 66, 63]
    bars = axes[2].barh(
        range(4),
        false_allows,
        height=0.55,
        color="white",
        edgecolor="black",
        linewidth=0.8,
    )
    for bar, hatch in zip(bars, ["", "..", "xx", "////"]):
        bar.set_hatch(hatch)
    label_bars(axes[2], bars, false_allows, 1.2)
    axes[2].set_yticks(range(4))
    axes[2].set_yticklabels(profile_labels)
    axes[2].invert_yaxis()
    axes[2].set_xlim(0, 75)
    axes[2].set_xticks([0, 25, 50, 75])
    axes[2].set_xlabel("false allows / 93 cases")
    axes[2].set_title("(c) Durable revocation", loc="left", fontsize=8.5)

    for axis in axes:
        axis.spines[["top", "right", "left"]].set_visible(False)
        axis.tick_params(axis="y", length=0)
        axis.grid(axis="x", color="black", linewidth=0.35, linestyle=":")
        axis.set_axisbelow(True)

    fig.text(
        0.5,
        0.012,
        "96/96 fault recoveries; 0 duplicate effects. Software TPM + same-host "
        "loopback/SQLite; coverage, not rates.",
        ha="center",
        va="bottom",
        fontsize=7.0,
    )
    fig.subplots_adjust(left=0.14, right=0.98, bottom=0.25, top=0.89)

    stem = HERE / "figL-evidence-class-upgrades"
    metadata = {
        "Title": "r5 native-state and durable-revocation evidence upgrades",
        "Author": "Internal research draft",
        "Subject": "Designed-corpus evidence; not a population estimate",
        "Creator": "make_r5_figures.py",
        "CreationDate": None,
        "ModDate": None,
    }
    fig.savefig(
        stem.with_suffix(".png"),
        dpi=300,
        metadata={"Software": "make_r5_figures.py"},
    )
    fig.savefig(stem.with_suffix(".pdf"), metadata=metadata)
    fig.savefig(
        stem.with_suffix(".svg"),
        metadata={"Title": stem.name, "Date": "2026-07-28T00:00:00Z"},
    )
    plt.close(fig)

    return {
        "figure": stem.name,
        "native_state_classes": class_values,
        "overlay_checks": [
            f"{value}/{total}"
            for value, total in zip(check_values, check_totals)
        ],
        "revocation_false_allows": false_allows,
        "fault_recoveries": durable["fault_recoveries"],
        "duplicate_effects": durable["duplicate_effects"],
    }


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
