#!/usr/bin/env python3
"""Freeze evaluator inputs, sources, and outputs before oracle comparison."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
FILES = (
    "mutation-packet.json",
    "generation-manifest.json",
    "evaluate_mutation_corpus.mjs",
    "evaluate_mutation_corpus.py",
    "js-results.json",
    "js-layer-results.json",
    "python-results.json",
    "python-layer-results.json",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


for name in FILES:
    if not (HERE / name).is_file():
        raise RuntimeError(f"required freeze input missing: {name}")

freeze = {
    "freeze_id": "thesis-v4-mutations-pre-oracle-comparison-v1",
    "frozen_at": datetime.now(timezone.utc).isoformat(),
    "oracle_read_by_evaluators": False,
    "files": {name: sha256(HERE / name) for name in FILES},
}
(HERE / "PREORACLE-FREEZE.json").write_text(
    json.dumps(freeze, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(freeze, indent=2, sort_keys=True))
