#!/usr/bin/env python3
"""Hash the reproducible native-signed adapter source and evidence outputs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path


HERE = Path(__file__).resolve().parent
FILES = (
    "README.md",
    "profile.schema.json",
    "build_fixtures.py",
    "verify_fixtures.py",
    "compare_results.py",
    "fixtures.json",
    "expected-results.json",
    "actual-results.json",
    "comparison-results.json",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


manifest = {
    "artifact_id": "tyche-native-signed-authority-fixtures-v0.1",
    "created_at": datetime.now(timezone.utc).isoformat(),
    "private_keys_persisted": False,
    "files": {name: sha256(HERE / name) for name in FILES},
}
(HERE / "artifact-manifest.json").write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
print(json.dumps(manifest, indent=2, sort_keys=True))
