#!/usr/bin/env python3
"""Verify, safely extract, and execute the frozen capsule in a clean directory."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath


HERE = Path(__file__).resolve().parent
ARCHIVE = HERE / "tyche-second-host-source-capsule-2026-07-28.tar.gz"
SIDECAR = HERE / "tyche-second-host-source-capsule-2026-07-28.sha256"
LOG = HERE / "CAPSULE-CLEAN-REPLAY-2026-07-28.log"
RESULT = HERE / "CAPSULE-CLEAN-REPLAY-2026-07-28.json"


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def main() -> int:
    expected_archive = SIDECAR.read_text(encoding="utf-8").split()[0]
    observed_archive = sha256(ARCHIVE)
    if observed_archive != expected_archive:
        raise RuntimeError("archive digest does not match sidecar")

    started = datetime.now(timezone.utc)
    with tempfile.TemporaryDirectory(prefix="tyche-capsule-clean-replay-") as name:
        extraction_root = Path(name)
        with tarfile.open(ARCHIVE, "r:gz") as capsule:
            members = capsule.getmembers()
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or ".." in path.parts
                    or not member.isfile()
                    or member.issym()
                    or member.islnk()
                ):
                    raise RuntimeError(
                        f"unsafe or non-regular archive member: {member.name}"
                    )
            capsule.extractall(extraction_root, filter="data")

        runner = extraction_root / "run.sh"
        runner_sha256 = sha256(runner)
        completed = subprocess.run(
            [str(runner)],
            cwd=extraction_root,
            text=True,
            capture_output=True,
            check=False,
            timeout=1800,
            env={
                **os.environ,
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC",
            },
        )

    ended = datetime.now(timezone.utc)
    log_text = "\n".join(
        [
            "TYCHE CLEAN CAPSULE REPLAY",
            f"archive={ARCHIVE.name}",
            f"archive_sha256={observed_archive}",
            f"members={len(members)}",
            f"runner_sha256={runner_sha256}",
            f"started_utc={started.isoformat()}",
            f"ended_utc={ended.isoformat()}",
            f"command=./run.sh",
            f"exit_code={completed.returncode}",
            "",
            "----- STDOUT -----",
            completed.stdout.rstrip(),
            "",
            "----- STDERR -----",
            completed.stderr.rstrip(),
            "",
        ]
    )
    LOG.write_text(log_text, encoding="utf-8")
    all_passed = (
        completed.returncode == 0
        and "SECOND-HOST CAPSULE RUN: PASS on this environment"
        in completed.stdout
    )
    result = {
        "archive": ARCHIVE.name,
        "archive_sha256": observed_archive,
        "archive_sha256_match": True,
        "members": len(members),
        "runner_sha256": runner_sha256,
        "command": "./run.sh",
        "exit_code": completed.returncode,
        "pass_sentinel_observed": (
            "SECOND-HOST CAPSULE RUN: PASS on this environment"
            in completed.stdout
        ),
        "all_passed": all_passed,
        "clean_temporary_extraction": True,
        "same_physical_host": True,
        "second_physical_host": False,
        "second_architecture_claimed": False,
        "environment": {
            "hostname": platform.node(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
        },
        "started_utc": started.isoformat(),
        "ended_utc": ended.isoformat(),
        "log": LOG.name,
        "log_sha256": sha256(LOG),
    }
    RESULT.write_text(
        json.dumps(result, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if all_passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
