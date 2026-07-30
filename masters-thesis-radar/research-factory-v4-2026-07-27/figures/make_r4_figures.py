#!/usr/bin/env python3
"""Generate the r4 evidence figures from hashed laboratory results."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path

os.environ["SOURCE_DATE_EPOCH"] = "1785015000"

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch


HERE = Path(__file__).resolve().parent
FACTORY = HERE.parent
LIVE = FACTORY / "labs" / "live-revocation-service" / "results.json"
TRANSFER = (
    FACTORY / "labs" / "cross-ecosystem-typed-transfer" / "results.json"
)
COMPOSED = (
    FACTORY / "labs" / "composed-transaction-corpus" / "results" / "summary.json"
)

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 8,
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
        "svg.hashsalt": "tyche-r4-figures-2026-07-27",
        "hatch.color": "black",
        "hatch.linewidth": 0.7,
        "lines.solid_joinstyle": "miter",
        "patch.force_edgecolor": True,
    }
)


def save(fig: plt.Figure, stem: str) -> None:
    metadata = {
        "Title": stem,
        "Author": "Internal research draft",
        "Subject": "Designed-corpus evidence; not a population estimate",
        "Creator": "make_r4_figures.py",
        "CreationDate": None,
        "ModDate": None,
    }
    fig.savefig(
        HERE / f"{stem}.png",
        dpi=300,
        bbox_inches="tight",
        pad_inches=0.04,
        metadata={"Software": "make_r4_figures.py"},
    )
    fig.savefig(
        HERE / f"{stem}.pdf",
        bbox_inches="tight",
        pad_inches=0.04,
        metadata=metadata,
    )
    fig.savefig(
        HERE / f"{stem}.svg",
        bbox_inches="tight",
        pad_inches=0.04,
        metadata={"Title": stem},
    )
    plt.close(fig)


def live_figure(data: dict) -> None:
    profiles = [
        ("atomic_guard", "atomic guard", ""),
        ("double_read", "double read", ".."),
        ("single_read", "single read", "xx"),
        ("ttl_cache", "TTL cache", "////"),
    ]
    values = [data["profiles"][key]["false_allows"] for key, _, _ in profiles]
    assert values[0] == 0
    assert all(value > 0 for value in values[1:])
    assert all(
        data["profiles"][key]["false_denies"] == 0 for key, _, _ in profiles
    )
    assert data["cases"] == 276
    per_profile = data["profiles"]["atomic_guard"]["cases"]
    assert per_profile == 69

    fig, ax = plt.subplots(figsize=(5.49, 2.55))
    y = range(len(profiles))
    bars = ax.barh(
        y,
        values,
        height=0.55,
        color="white",
        edgecolor="black",
        linewidth=0.9,
    )
    for bar, (_, _, hatch), value in zip(bars, profiles, values):
        bar.set_hatch(hatch)
        ax.text(
            value + 0.7,
            bar.get_y() + bar.get_height() / 2,
            str(value),
            va="center",
            ha="left",
            fontsize=8,
        )
    ax.set_yticks(list(y))
    ax.set_yticklabels([label for _, label, _ in profiles])
    ax.invert_yaxis()
    ax.set_xlabel(f"false allows in {per_profile} cases per profile")
    ax.set_xlim(0, max(values) + 5)
    ax.set_xticks([0, 10, 20, 30, 40])
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="y", length=0)
    ax.grid(axis="x", color="black", linewidth=0.35, linestyle=":")
    ax.set_axisbelow(True)
    ax.text(
        0,
        -0.62,
        f"All {data['cases']} traces / {data['signed_responses']} responses: "
        "signatures verified; false denies: 0",
        ha="left",
        va="bottom",
        fontsize=8,
    )
    fig.tight_layout()
    save(fig, "figI-live-revocation-service")


def transfer_figure(data: dict) -> None:
    ecosystems = ["EATF", "transactions"]
    native = [
        data["eatf"]["distinct_native_rejection_states"],
        data["composed_transaction"]["distinct_native_rejection_states"],
    ]
    erased = [
        data["eatf"]["pairwise_state_distinctions_erased_by_boolean"],
        data["composed_transaction"][
            "pairwise_state_distinctions_erased_by_boolean"
        ],
    ]
    assert native == [16, 28]
    assert erased == [120, 378]
    assert (
        data["boolean_scalarization"][
            "native_pairwise_rejection_distinctions_erased"
        ]
        == 498
    )

    fig, (left, right) = plt.subplots(
        1,
        2,
        figsize=(5.61, 3.2),
        gridspec_kw={"wspace": 0.48},
    )
    positions = [0, 1]
    width = 0.34
    native_bars = left.bar(
        [value - width / 2 for value in positions],
        native,
        width=width,
        color="white",
        edgecolor="black",
        hatch="////",
        linewidth=0.9,
        label="native typed states",
    )
    boolean_bars = left.bar(
        [value + width / 2 for value in positions],
        [1, 1],
        width=width,
        color="white",
        edgecolor="black",
        hatch="..",
        linewidth=0.9,
        label="Boolean REJECT",
    )
    for bar in [*native_bars, *boolean_bars]:
        left.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.8,
            str(round(bar.get_height())),
            ha="center",
            va="bottom",
            fontsize=8,
        )
    left.set_xticks(positions)
    left.set_xticklabels(ecosystems)
    left.set_ylabel("distinct rejection states")
    left.set_ylim(0, 37)
    left.set_title("(a) State vocabulary retained", loc="left", fontsize=9)
    left.spines[["top", "right"]].set_visible(False)
    left.legend(
        frameon=False,
        fontsize=7,
        loc="upper left",
        handles=[
            Patch(
                facecolor="white",
                edgecolor="black",
                hatch="////",
                label="native typed states",
            ),
            Patch(
                facecolor="white",
                edgecolor="black",
                hatch="..",
                label="Boolean REJECT",
            ),
        ],
    )

    erased_bars = right.bar(
        positions,
        erased,
        width=0.55,
        color="white",
        edgecolor="black",
        linewidth=0.9,
    )
    for bar, hatch, value in zip(erased_bars, ["xx", "////"], erased):
        bar.set_hatch(hatch)
        right.text(
            bar.get_x() + bar.get_width() / 2,
            value + 10,
            str(value),
            ha="center",
            va="bottom",
            fontsize=8,
        )
    right.set_xticks(positions)
    right.set_xticklabels(ecosystems)
    right.set_ylabel("pairwise distinctions erased")
    right.set_ylim(0, 430)
    right.set_title("(b) Loss under scalarization", loc="left", fontsize=9)
    right.spines[["top", "right"]].set_visible(False)
    right.text(
        0.5,
        405,
        "total = 498",
        ha="center",
        va="top",
        fontsize=8,
    )
    fig.subplots_adjust(left=0.12, right=0.98, bottom=0.19, top=0.86, wspace=0.5)
    save(fig, "figJ-typed-state-transfer")


def binding_ablation_figure(data: dict) -> None:
    totals = data["baseline_false_allows"]
    profiles = [
        (
            "effect_resource_binding",
            "effect + resource\n(omit time + profile)",
            "////",
        ),
        (
            "effect_resource_profile_binding",
            "+ profile\n(omit time)",
            "..",
        ),
        (
            "effect_resource_time_binding",
            "+ time\n(omit profile)",
            "xx",
        ),
        (
            "strict",
            "full implemented binding\n(omit neither)",
            "",
        ),
    ]
    values = [
        totals["effect_resource_binding"],
        totals["effect_resource_profile_binding"],
        totals["effect_resource_time_binding"],
        0,
    ]
    assert values == [3, 2, 1, 0]
    assert data["binding_stage"]["cross_layer_denials"] == 8

    fig, ax = plt.subplots(figsize=(5.49, 2.65))
    positions = list(range(len(profiles)))
    bars = ax.bar(
        positions,
        values,
        width=0.58,
        color="white",
        edgecolor="black",
        linewidth=0.9,
    )
    for bar, (_, _, hatch), value in zip(bars, profiles, values):
        bar.set_hatch(hatch)
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + 0.10,
            str(value),
            ha="center",
            va="bottom",
            fontsize=9,
        )
    ax.set_xticks(positions)
    ax.set_xticklabels([label for _, label, _ in profiles], fontsize=7)
    ax.set_ylabel("false allows")
    ax.set_ylim(0, 3.55)
    ax.set_yticks([0, 1, 2, 3])
    ax.spines[["top", "right"]].set_visible(False)
    ax.grid(axis="y", color="black", linewidth=0.35, linestyle=":")
    ax.set_axisbelow(True)
    ax.text(
        0.0,
        -0.36,
        "All profiles require all five local verifiers and effect/resource "
        "agreement; counts are on 14 designed binding cases.",
        transform=ax.transAxes,
        ha="left",
        va="top",
        fontsize=7,
    )
    fig.subplots_adjust(left=0.11, right=0.98, bottom=0.31, top=0.96)
    save(fig, "figK-partial-binding-ablation")


def main() -> int:
    live = json.loads(LIVE.read_text(encoding="utf-8"))
    transfer = json.loads(TRANSFER.read_text(encoding="utf-8"))
    composed = json.loads(COMPOSED.read_text(encoding="utf-8"))
    live_figure(live)
    transfer_figure(transfer)
    binding_ablation_figure(composed)
    names = [
        "make_r4_figures.py",
        "figI-live-revocation-service.png",
        "figI-live-revocation-service.pdf",
        "figI-live-revocation-service.svg",
        "figJ-typed-state-transfer.png",
        "figJ-typed-state-transfer.pdf",
        "figJ-typed-state-transfer.svg",
        "figK-partial-binding-ablation.png",
        "figK-partial-binding-ablation.pdf",
        "figK-partial-binding-ablation.svg",
    ]
    (HERE / "SHA256SUMS-r4").write_text(
        "".join(
            f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  "
            f"{name}\n"
            for name in names
        ),
        encoding="utf-8",
    )
    print("generated figI, figJ, and figK from hashed laboratory results")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
