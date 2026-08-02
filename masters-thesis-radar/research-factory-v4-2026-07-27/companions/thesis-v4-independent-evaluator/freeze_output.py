#!/usr/bin/env python3
"""Freeze independent evaluator inputs and outputs before comparison."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
PACKET = (
    HERE.parent.parent
    / "masters-thesis-radar"
    / "research-factory-v4-2026-07-27"
    / "external-label-packet"
)
OUTPUT = HERE / "PRECOMPARISON-FREEZE.json"
FILES = {
    "labelling_spec": PACKET / "LABELLING-SPEC.md",
    "transactions_packet": PACKET / "transactions-for-labelling.json",
    "response_schema": PACKET / "RESPONSE-SCHEMA.json",
    "implementation": HERE / "evaluate.mjs",
    "independent_answers": HERE / "independent-results-unsealed.json",
    "independent_layer_results": HERE / "independent-layer-results-unsealed.json",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if OUTPUT.exists():
        raise FileExistsError("refusing to overwrite pre-comparison freeze")
    manifest = {
        "frozen_at_utc": datetime.now(timezone.utc).isoformat(),
        "implementation": "independent-js-v1",
        "claim_boundary": (
            "The implementation consumed only the labeller-facing packet. "
            "No research-program evaluator, result file, or reference label "
            "was used before this freeze."
        ),
        "files": {
            name: {
                "path": str(path),
                "sha256": digest(path),
                "bytes": path.stat().st_size,
            }
            for name, path in FILES.items()
        },
    }
    OUTPUT.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
