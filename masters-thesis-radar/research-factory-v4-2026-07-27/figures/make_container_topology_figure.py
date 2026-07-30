#!/usr/bin/env python3
"""Generate the containerized durable-revocation topology/result figure."""

from __future__ import annotations

import json
import os
from pathlib import Path

os.environ["SOURCE_DATE_EPOCH"] = "1785110400"

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, Rectangle


HERE = Path(__file__).resolve().parent
RESULT = (
    HERE.parent
    / "labs"
    / "containerized-durable-revocation"
    / "results"
    / "results.json"
)

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 7.3,
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
        "svg.hashsalt": "tyche-container-topology-2026-07-28",
        "hatch.color": "black",
        "hatch.linewidth": 0.65,
        "patch.force_edgecolor": True,
    }
)


def box(axis: plt.Axes, xy, width, height, label, hatch="") -> None:
    patch = Rectangle(
        xy,
        width,
        height,
        facecolor="white",
        edgecolor="black",
        linewidth=0.8,
        hatch=hatch,
        joinstyle="miter",
    )
    axis.add_patch(patch)
    axis.text(
        xy[0] + width / 2,
        xy[1] + height / 2,
        label,
        ha="center",
        va="center",
        fontsize=7.0,
    )


def arrow(
    axis: plt.Axes,
    start,
    end,
    style="-|>",
    dashed=False,
    connectionstyle="arc3",
) -> None:
    axis.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle=style,
            mutation_scale=7,
            linewidth=0.7,
            color="black",
            linestyle="--" if dashed else "-",
            connectionstyle=connectionstyle,
        )
    )


def build() -> dict[str, object]:
    packet = json.loads(RESULT.read_text(encoding="utf-8"))
    summary = packet["summary"]
    assertions = packet["assertions"]
    assert summary == {
        "all_passed": True,
        "assertions_passed": 14,
        "assertions_total": 14,
        "atomic_cases": 69,
        "atomic_false_allows": 0,
        "cases": 135,
        "decisions": 135,
        "effects": 95,
        "events": 537,
        "fault_cases": 4,
        "weak_cases": 66,
        "weak_false_allows": 36,
    }
    assert all(assertions.values())

    fig = plt.figure(figsize=(5.978, 3.35))
    grid = fig.add_gridspec(1, 2, width_ratios=[1.20, 0.80], wspace=0.48)
    topology = fig.add_subplot(grid[0, 0])
    results = fig.add_subplot(grid[0, 1])

    topology.set_xlim(0, 1)
    topology.set_ylim(0, 1)
    topology.axis("off")
    topology.set_title(
        "(a) Executed topology and shared boundary", loc="left", fontsize=8.5
    )
    host = Rectangle(
        (0.02, 0.14),
        0.96,
        0.77,
        facecolor="white",
        edgecolor="black",
        linewidth=0.9,
        linestyle="--",
        joinstyle="miter",
    )
    topology.add_patch(host)
    topology.text(
        0.04,
        0.895,
        "same physical x86_64 host · shared bridge",
        ha="left",
        va="top",
        fontsize=7.0,
    )

    box(topology, (0.07, 0.57), 0.22, 0.13, "runner\ncontainer", "..")
    box(topology, (0.39, 0.57), 0.22, 0.13, "fault-proxy\ncontainer", "xx")
    box(topology, (0.70, 0.71), 0.22, 0.13, "effect-a\ncontainer", "////")
    box(topology, (0.70, 0.45), 0.22, 0.13, "effect-b\ncontainer", "////")
    box(topology, (0.07, 0.23), 0.22, 0.13, "status-a\ncontainer", "\\\\\\\\")
    box(topology, (0.39, 0.18), 0.35, 0.13, "shared SQLite WAL\nnamed volume", "")

    arrow(topology, (0.29, 0.635), (0.39, 0.635))
    arrow(topology, (0.61, 0.66), (0.70, 0.765))
    arrow(topology, (0.29, 0.58), (0.34, 0.43), style="-", dashed=True)
    arrow(topology, (0.34, 0.43), (0.65, 0.43), style="-", dashed=True)
    arrow(topology, (0.65, 0.43), (0.70, 0.515), dashed=True)
    topology.text(
        0.52,
        0.40,
        "direct retry",
        ha="center",
        va="center",
        fontsize=7.0,
    )
    arrow(topology, (0.18, 0.57), (0.18, 0.36))
    arrow(topology, (0.18, 0.23), (0.39, 0.245))
    arrow(topology, (0.81, 0.71), (0.66, 0.31))
    arrow(topology, (0.81, 0.45), (0.66, 0.31))

    topology.text(
        0.50,
        0.06,
        "request loss before forward · response loss after commit\n"
        "retry through effect-b · same datastore trust domain",
        ha="center",
        va="center",
        fontsize=7.0,
    )

    categories = [
        "atomic FA",
        "duplicate decisions",
        "duplicate effects",
        "weak-profile FA",
    ]
    values = [0, 0, 0, summary["weak_false_allows"]]
    bars = results.barh(
        range(4),
        values,
        height=0.52,
        facecolor="white",
        edgecolor="black",
        linewidth=0.8,
    )
    for bar, hatch in zip(bars, ["", "..", "xx", "////"]):
        bar.set_hatch(hatch)
    for index, (bar, value) in enumerate(zip(bars, values)):
        label = (
            "0/69"
            if index == 0
            else "0"
            if index in (1, 2)
            else f"{value}/66"
        )
        results.text(
            max(value, 0) + 0.8,
            bar.get_y() + bar.get_height() / 2,
            label,
            ha="left",
            va="center",
            fontsize=7.2,
        )
    results.set_yticks(range(4))
    results.set_yticklabels(categories)
    results.invert_yaxis()
    results.set_xlim(0, 42)
    results.set_xticks([0, 10, 20, 30, 40])
    results.set_xlabel("observed cases")
    results.set_title("(b) Saved categorical outcomes", loc="left", fontsize=8.5)
    results.spines[["top", "right", "left"]].set_visible(False)
    results.tick_params(axis="y", length=0)
    results.grid(axis="x", color="black", linewidth=0.35, linestyle=":")
    results.set_axisbelow(True)
    results.text(
        0.0,
        -0.18,
        "4/4 recovery via effect-b\n"
        "540/540 signatures\n"
        "14/14 + 15/15 checks",
        transform=results.transAxes,
        ha="left",
        va="top",
        fontsize=7.0,
    )

    fig.text(
        0.5,
        0.025,
        "Executed instance separation; one physical host and shared SQLite "
        "remain explicit ceilings.",
        ha="center",
        va="bottom",
        fontsize=7.0,
    )
    fig.subplots_adjust(left=0.04, right=0.985, bottom=0.33, top=0.89)

    stem = HERE / "figM-containerized-revocation-boundaries"
    metadata = {
        "Title": "Containerized durable-revocation boundaries and outcomes",
        "Author": "Internal research draft",
        "Subject": "Same-host designed experiment; not a population estimate",
        "Creator": "make_container_topology_figure.py",
        "CreationDate": None,
        "ModDate": None,
    }
    fig.savefig(
        stem.with_suffix(".png"),
        dpi=300,
        metadata={"Software": "make_container_topology_figure.py"},
    )
    fig.savefig(stem.with_suffix(".pdf"), metadata=metadata)
    fig.savefig(
        stem.with_suffix(".svg"),
        metadata={"Title": stem.name, "Date": "2026-07-28T00:00:00Z"},
    )
    plt.close(fig)
    return {
        "figure": stem.name,
        "cases": summary["cases"],
        "atomic_false_allows": summary["atomic_false_allows"],
        "weak_false_allows": summary["weak_false_allows"],
        "fault_cases": summary["fault_cases"],
        "signed_responses": 540,
        "same_physical_host": True,
        "all_passed": True,
    }


if __name__ == "__main__":
    print(json.dumps(build(), indent=2, sort_keys=True))
