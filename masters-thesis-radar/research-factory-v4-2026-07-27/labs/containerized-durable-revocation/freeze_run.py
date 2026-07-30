#!/usr/bin/env python3
"""Freeze source and result hashes after a successful run."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results" / "results.json"
SUMMARY = HERE / "SUMMARY.md"
MANIFEST = HERE / "SHA256SUMS"


def main() -> int:
    packet = json.loads(RESULTS.read_text(encoding="utf-8"))
    summary = packet["summary"]
    SUMMARY.write_text(
        "# Containerized durable-revocation result\n\n"
        f"- Cases: **{summary['cases']}**\n"
        f"- Atomic / weak: **{summary['atomic_cases']} / "
        f"{summary['weak_cases']}**\n"
        f"- Fault-recovery cases: **{summary['fault_cases']}**\n"
        f"- Atomic / weak false allows: "
        f"**{summary['atomic_false_allows']} / "
        f"{summary['weak_false_allows']}**\n"
        f"- Durable decisions / effects / events: "
        f"**{summary['decisions']} / {summary['effects']} / "
        f"{summary['events']}**\n"
        f"- Executable assertions: "
        f"**{summary['assertions_passed']}/{summary['assertions_total']}**\n"
        "- Boundary: same physical host and Docker kernel; separate "
        "containers and internal bridge, not multi-host evidence.\n",
        encoding="utf-8",
    )
    names = (
        "README.md",
        "compose.yaml",
        "container_service.py",
        "fault_proxy.py",
        "run_matrix.py",
        "verify_saved_results.py",
        "freeze_run.py",
        "run.sh",
        "results/results.json",
        "results/compose-config.yaml",
        "results/compose-images.txt",
        "SUMMARY.md",
    )
    MANIFEST.write_text(
        "".join(
            f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  "
            f"{name}\n"
            for name in names
        ),
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
