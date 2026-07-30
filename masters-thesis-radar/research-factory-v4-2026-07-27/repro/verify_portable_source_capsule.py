#!/usr/bin/env python3
"""Verify capsule paths, embedded hashes, and sidecar digest without extraction."""

from __future__ import annotations

import hashlib
import json
import tarfile
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
ARCHIVE = HERE / "tyche-second-host-source-capsule-2026-07-28.tar.gz"
SIDECAR = HERE / "tyche-second-host-source-capsule-2026-07-28.sha256"


def main() -> int:
    expected_archive = SIDECAR.read_text(encoding="utf-8").split()[0]
    observed_archive = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    with tarfile.open(ARCHIVE, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        safe = all(
            not PurePosixPath(name).is_absolute()
            and ".." not in PurePosixPath(name).parts
            for name in names
        )
        duplicate_free = len(names) == len(set(names))
        manifest_member = archive.extractfile("CAPSULE-MANIFEST.json")
        if manifest_member is None:
            raise RuntimeError("manifest missing")
        manifest = json.loads(manifest_member.read())
        exact = True
        for name, expected in manifest["files"].items():
            handle = archive.extractfile(name)
            if handle is None:
                exact = False
                continue
            value = handle.read()
            exact &= len(value) == expected["bytes"]
            exact &= hashlib.sha256(value).hexdigest() == expected["sha256"]
        expected_names = set(manifest["files"]) | {"CAPSULE-MANIFEST.json"}
        exact_names = set(names) == expected_names
    result = {
        "archive_sha256_match": observed_archive == expected_archive,
        "safe_relative_paths": safe,
        "duplicate_free": duplicate_free,
        "member_hashes_match": exact,
        "exact_member_set": exact_names,
        "members": len(names),
        "second_host_run_claimed": manifest["second_physical_host_run"],
        "second_architecture_run_claimed": manifest["second_architecture_run"],
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if all(
        (
            result["archive_sha256_match"],
            safe,
            duplicate_free,
            exact,
            exact_names,
            not result["second_host_run_claimed"],
            not result["second_architecture_run_claimed"],
        )
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
