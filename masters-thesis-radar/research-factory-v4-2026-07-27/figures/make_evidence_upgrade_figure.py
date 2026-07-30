#!/usr/bin/env python3
"""Generate the monochrome revocation-race figure from laboratory results."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

os.environ["SOURCE_DATE_EPOCH"] = "1785015000"

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt


HERE = Path(__file__).resolve().parent
LAB = HERE.parent / "labs" / "prospective-revocation-races"
packet = json.loads((LAB / "corpus.json").read_text(encoding="utf-8"))
summary = json.loads((LAB / "summary.json").read_text(encoding="utf-8"))

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
        "pdf.fonttype": 42,
        "svg.fonttype": "none",
        "svg.hashsalt": "tyche-evidence-upgrade-2026-07-27",
        "hatch.color": "black",
        "hatch.linewidth": 0.65,
    }
)

selected = {item["case_id"]: item for item in packet["cases"]}
rows = [
    ("RR-002", "revoked before appraisal", 95),
    ("RR-003", "revoked between appraisal and commit", 105),
    ("RR-004", "revoked at commit", 110),
    ("RR-005", "revoked after commit", 111),
]

fig, (timeline, bars) = plt.subplots(
    2,
    1,
    figsize=(6.0, 5.15),
    gridspec_kw={"height_ratios": [2.2, 1.35], "hspace": 0.72},
)

for y, (case_id, label, revocation_time) in enumerate(rows[::-1]):
    item = selected[case_id]
    timeline.hlines(y, 92, 113, color="black", linewidth=0.8)
    timeline.plot(
        item["appraisal_time"],
        y,
        marker="o",
        markerfacecolor="white",
        markeredgecolor="black",
        markersize=5,
    )
    timeline.plot(
        item["commit_time"],
        y,
        marker="s",
        markerfacecolor="white",
        markeredgecolor="black",
        markersize=5,
    )
    timeline.plot(
        revocation_time,
        y,
        marker="x",
        color="black",
        markersize=6,
        markeredgewidth=1.2,
    )
    verdict = item["expected"]["verdict"]
    gate = item["expected"]["first_rejecting_gate"]
    timeline.text(
        112.2,
        y,
        f"{verdict} · {gate}",
        va="center",
        ha="left",
        fontsize=7.1,
    )

timeline.axvline(100, color="black", linewidth=0.6, linestyle=":")
timeline.axvline(110, color="black", linewidth=0.6, linestyle="--")
timeline.set_xlim(92, 130)
timeline.set_ylim(-0.65, len(rows) - 0.35)
timeline.set_yticks(range(len(rows)))
timeline.set_yticklabels([label for _, label, _ in rows[::-1]], fontsize=7.1)
timeline.set_xticks([95, 100, 105, 110])
timeline.set_xlabel("fixed event time")
timeline.set_title(
    "(a) Boundary placement determines the strict gate",
    loc="left",
    fontsize=9,
    pad=28,
)
timeline.spines[["top", "right", "left"]].set_visible(False)
timeline.tick_params(axis="y", length=0)
timeline.legend(
    handles=[
        plt.Line2D(
            [],
            [],
            marker="o",
            markerfacecolor="white",
            markeredgecolor="black",
            linestyle="none",
            label="appraisal",
        ),
        plt.Line2D(
            [],
            [],
            marker="s",
            markerfacecolor="white",
            markeredgecolor="black",
            linestyle="none",
            label="commit",
        ),
        plt.Line2D(
            [],
            [],
            marker="x",
            color="black",
            linestyle="none",
            label="revocation",
        ),
    ],
    frameon=False,
    loc="lower left",
    bbox_to_anchor=(0, 1.015),
    ncol=3,
    fontsize=7.1,
    handletextpad=0.35,
    columnspacing=0.75,
)

names = ["strict", "timestamp-only", "commit fail-open", "appraisal-only"]
values = [
    0,
    len(summary["baseline_false_allows"]["timestamp_only"]),
    len(summary["baseline_false_allows"]["commit_fail_open"]),
    len(summary["baseline_false_allows"]["appraisal_only"]),
]
hatches = ["", "..", "xx", "////"]
bars_drawn = bars.barh(
    range(len(names)),
    values,
    color="white",
    edgecolor="black",
    linewidth=0.8,
)
for patch, hatch in zip(bars_drawn, hatches):
    patch.set_hatch(hatch)
for y, value in enumerate(values):
    bars.text(value + 0.15, y, str(value), va="center", ha="left", fontsize=8)
bars.set_yticks(range(len(names)))
bars.set_yticklabels(names, fontsize=7.3)
bars.set_xlim(0, 8)
bars.set_xticks(range(0, 9, 2))
bars.set_xlabel("false allows in 13 designed cases")
bars.set_title(
    "(b) Commit checks remove ablation errors", loc="left", fontsize=9, pad=8
)
bars.spines[["top", "right", "left"]].set_visible(False)
bars.tick_params(axis="y", length=0)
bars.grid(axis="x", color="black", alpha=0.16, linewidth=0.45)
bars.set_axisbelow(True)
fig.text(
    0.98,
    0.018,
    "Designed event-sequence coverage; not a deployed-system rate.",
    ha="right",
    va="bottom",
    fontsize=7.1,
)

fig.subplots_adjust(left=0.34, right=0.98, bottom=0.12, top=0.90)
stem = HERE / "figH-revocation-races"
metadata = {
    "Title": "Prospective signed-revocation race fixtures",
    "Author": "Tyche internal research artifact",
    "Subject": "Designed event-sequence coverage; not deployment rates",
    "Creator": "make_evidence_upgrade_figure.py",
    "CreationDate": datetime(2026, 7, 25, 21, 30, tzinfo=timezone.utc),
    "ModDate": datetime(2026, 7, 25, 21, 30, tzinfo=timezone.utc),
}
fig.savefig(stem.with_suffix(".pdf"), metadata=metadata)
fig.savefig(stem.with_suffix(".png"), dpi=300, metadata={"Software": "Tyche"})
fig.savefig(stem.with_suffix(".svg"), metadata={"Date": "2026-07-25T21:30:00Z"})
plt.close(fig)

print(
    json.dumps(
        {
            "figure": stem.name,
            "strict_false_allows": 0,
            "baseline_false_allows": {
                key: len(value)
                for key, value in summary["baseline_false_allows"].items()
            },
        },
        sort_keys=True,
    )
)
