#!/usr/bin/env python3
"""Render the r7 execution-domain and TPM-evidence matrix."""

from __future__ import annotations

import os
from pathlib import Path


os.environ.setdefault("SOURCE_DATE_EPOCH", "1785373200")
os.environ.setdefault("MPLCONFIGDIR", "/tmp/tyche-mpl-r7")

import matplotlib as mpl

mpl.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Rectangle


HERE = Path(__file__).resolve().parent

mpl.rcParams.update(
    {
        "font.family": "DejaVu Sans",
        "font.size": 8.2,
        "axes.titlesize": 10,
        "figure.facecolor": "white",
        "savefig.facecolor": "white",
        "savefig.edgecolor": "white",
        "svg.hashsalt": "tyche-r8-identified-vm-evidence",
    }
)

rows = [
    (
        "Local x86-64\nsoftware TPM",
        ["16", "104", "104", "372", "832/832", "512/512"],
        "8 fresh swtpm roots; one physical host",
    ),
    (
        "Hosted x86-64\njob VM",
        ["16", "104", "104", "372", "—", "—"],
        "four-lane contract 20/20; reported architecture; physical host unknown",
    ),
    (
        "Hosted ARM64\njob VM",
        ["16", "104", "104", "372", "—", "—"],
        "four-lane contract 20/20; reported architecture; physical host unknown",
    ),
    (
        "identified VM (host-A)\nHyper-V x86-64",
        ["16", "104", "104", "372", "104/104", "64/64"],
        "four-lane contract 20/20; identified VM/OS; Microsoft vTPM",
    ),
]

columns = [
    "Policy\nReplay",
    "Composed\nCorpus",
    "Typed\nTransfer",
    "Durable\nRevocation",
    "TPM quote\nverification",
    "TPM mutation\nrejection",
]

fig, ax = plt.subplots(figsize=(10.8, 4.3))
ax.set_xlim(-2.35, len(columns) + 0.05)
ax.set_ylim(-1.05, len(rows) + 0.75)
ax.axis("off")

header_color = "#22324a"
line_color = "#8c98a8"
fill_strong = "#d8eadf"
fill_neutral = "#edf1f5"
fill_absent = "#f6f7f8"
text_color = "#17212b"
accent = "#2f6f4e"

for index, label in enumerate(columns):
    ax.text(
        index + 0.5,
        len(rows) + 0.38,
        label,
        ha="center",
        va="center",
        color=header_color,
        fontweight="bold",
    )

for row_index, (name, values, boundary) in enumerate(rows):
    y = len(rows) - 1 - row_index
    ax.text(
        -2.25,
        y + 0.53,
        name,
        ha="left",
        va="center",
        color=text_color,
        fontweight="bold" if row_index == len(rows) - 1 else "normal",
    )
    for column_index, value in enumerate(values):
        if value == "—":
            color = fill_absent
        elif row_index == len(rows) - 1 and column_index >= 4:
            color = fill_strong
        else:
            color = fill_neutral
        ax.add_patch(
            Rectangle(
                (column_index + 0.03, y + 0.08),
                0.94,
                0.9,
                facecolor=color,
                edgecolor=line_color,
                linewidth=0.8,
            )
        )
        ax.text(
            column_index + 0.5,
            y + 0.53,
            value,
            ha="center",
            va="center",
            color=accent if color == fill_strong else text_color,
            fontweight="bold" if color == fill_strong else "normal",
        )
    ax.text(
        -2.25,
        y + 0.09,
        boundary,
        ha="left",
        va="bottom",
        color="#4e5c6b",
        fontsize=6.8,
    )

ax.plot([-2.3, len(columns)], [len(rows) + 0.02] * 2, color=header_color, lw=1.0)
ax.text(
    -2.25,
    -0.55,
    "Counts are deterministic contract checks, not deployed-system rates. "
    "vTPM evidence is not hardware-rooted attestation.",
    ha="left",
    va="center",
    color=text_color,
    fontsize=7.2,
)

fig.tight_layout(pad=0.5)
stem = HERE / "figN-execution-domain-evidence-matrix"
metadata = {
    "Title": "Execution-domain and TPM-evidence matrix",
    "Author": "Anton Sokolov",
    "Creator": "Tyche r7 figure generator",
    "CreationDate": None,
    "ModDate": None,
}
fig.savefig(stem.with_suffix(".pdf"), bbox_inches="tight", metadata=metadata)
fig.savefig(
    stem.with_suffix(".png"),
    dpi=300,
    bbox_inches="tight",
    metadata={"Software": "Tyche r7 figure generator"},
)
fig.savefig(
    stem.with_suffix(".svg"),
    bbox_inches="tight",
    metadata={"Date": "2026-07-30T09:00:00Z"},
)
