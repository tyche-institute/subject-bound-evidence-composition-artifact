#!/usr/bin/env python3
"""Record a privacy-minimized execution environment for a runner."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sqlite3
import ssl
import subprocess
import sys
from pathlib import Path


def command(*args: str) -> str:
    return subprocess.run(
        args,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    ).stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", required=True)
    args = parser.parse_args()
    try:
        import cryptography

        cryptography_version = cryptography.__version__
    except ImportError:
        cryptography_version = None
    try:
        import numpy

        numpy_version = numpy.__version__
    except ImportError:
        numpy_version = None
    record = {
        "phase": args.phase,
        "machine": platform.machine(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "python": sys.version.replace("\n", " "),
        "python_implementation": platform.python_implementation(),
        "sqlite": sqlite3.sqlite_version,
        "openssl": ssl.OPENSSL_VERSION,
        "numpy": numpy_version,
        "cryptography": cryptography_version,
        "cpu_count": os.cpu_count(),
        "runner": {
            "arch": os.environ.get("RUNNER_ARCH"),
            "os": os.environ.get("RUNNER_OS"),
            "environment": os.environ.get("RUNNER_ENVIRONMENT"),
            "image_os": os.environ.get("ImageOS"),
            "image_version": os.environ.get("ImageVersion"),
        },
        "workflow": {
            "repository": os.environ.get("GITHUB_REPOSITORY"),
            "sha": os.environ.get("GITHUB_SHA"),
            "checkout_sha": command("git", "rev-parse", "HEAD"),
            "run_id": os.environ.get("GITHUB_RUN_ID"),
            "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
            "workflow_ref": os.environ.get("GITHUB_WORKFLOW_REF"),
        },
        "tool_versions": {
            "uname": command("uname", "-a"),
            "git": command("git", "--version"),
            "node": command("node", "--version"),
        },
        "privacy_note": (
            "hostname, network addresses, machine-id, account names, and "
            "environment variables outside the allowlist are not recorded"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
