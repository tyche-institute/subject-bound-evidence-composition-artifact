#!/usr/bin/env python3
"""Build a deterministic, dependency-pinned second-host source capsule."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
from pathlib import Path
from typing import Iterable


HERE = Path(__file__).resolve().parent
V4 = HERE.parent
RADAR = V4.parent
VAULT = RADAR.parent
V3_SAFE = RADAR / "research-factory-v3-2026-07-25" / "labs" / (
    "safe-metric-metamorphics"
)
BOUNDARY = VAULT / "a2a-boundary-seal" / "results" / "extension-enabled"
ARCHIVE = HERE / "tyche-second-host-source-capsule-2026-07-28.tar.gz"
ARCHIVE_SHA = HERE / "tyche-second-host-source-capsule-2026-07-28.sha256"
CLEAN_REPLAY_FILES = {
    "CAPSULE-CLEAN-REPLAY-2026-07-28.json",
    "CAPSULE-CLEAN-REPLAY-2026-07-28.log",
    "PANEL-SYNTHESIS.md",
}
EPOCH = 1785110400

RUNNER = """#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
export PYTHONDONTWRITEBYTECODE=1 PYTHONHASHSEED=0 LC_ALL=C.UTF-8 TZ=UTC
python3 -m venv "$ROOT/.venv"
"$ROOT/.venv/bin/pip" install --no-index \
  --find-links="$ROOT/wheelhouse-linux-amd64-cp312" \
  -r "$ROOT/workspace/masters-thesis-radar/research-factory-v4-2026-07-27/repro/requirements.txt"
PY="$ROOT/.venv/bin/python"
V4="$ROOT/workspace/masters-thesis-radar/research-factory-v4-2026-07-27"
printf 'host=%s\\n' "$(hostname)"
uname -a
"$PY" -VV
"$PY" - <<'PY'
import cryptography, numpy, platform, sqlite3
print("machine", platform.machine())
print("numpy", numpy.__version__)
print("cryptography", cryptography.__version__)
print("sqlite", sqlite3.sqlite_version)
PY
(
  cd "$V4/labs/policy-version-evidence-replay"
  bash ./run.sh >/dev/null
)
(
  cd "$V4/labs/composed-transaction-corpus"
  bash ./run.sh >/dev/null
)
if command -v javac >/dev/null 2>&1; then
  (
    cd "$V4/labs/formal-composition-modelcheck"
    bash ./run.sh >/dev/null
    sha256sum -c SHA256SUMS
  )
else
  echo "SKIP standalone finite Java check: javac unavailable"
fi
(
  cd "$V4/labs/cross-ecosystem-typed-transfer"
  "$PY" build_transfer.py >/dev/null
  "$PY" verify_crosswalk_sql.py >/dev/null
  sha256sum -c SHA256SUMS
)
(
  cd "$V4/labs/distributed-revocation-service"
  "$PY" run_experiment.py >/dev/null
  "$PY" verify_saved_results.py
  sha256sum -c SHA256SUMS
)
(
  cd "$V4/labs/containerized-durable-revocation"
  "$PY" verify_saved_results.py
  sha256sum -c SHA256SUMS
)
if command -v tpm2_checkquote >/dev/null 2>&1; then
  (
    cd "$V4/labs/native-state-transaction-overlay"
    "$PY" verify_overlay.py >/dev/null
    (cd results && sha256sum -c SHA256SUMS)
    if command -v javac >/dev/null 2>&1; then
      (cd independent-java && bash ./run.sh >/dev/null)
    else
      echo "SKIP independent compiled native verifier: javac unavailable"
    fi
  )
else
  echo "SKIP fresh native-state verification: tpm2_checkquote unavailable"
fi
echo "SECOND-HOST CAPSULE RUN: PASS on this environment"
"""

README = """# Tyche second-host execution capsule

Status: source-complete candidate, locally integrity-tested; **not yet run on
a second physical host or architecture**.

The archive vendors the V4 laboratories, the exact sibling SAFE laboratory and
boundary-seal snapshots required by their relative paths, the reproduction
scripts, and an offline CPython 3.12 linux/amd64 wheelhouse. `run.sh` rebuilds
the deterministic core, reruns the process-isolated revocation experiment, and
reverifies the saved containerized-revocation and native TPM evidence. When
OpenJDK is present it also reruns the finite model check and compiled native
verifier; when `tpm2_checkquote` is absent, the native path is explicitly
skipped rather than silently treated as a pass.

The wheelhouse is deliberately labelled linux/amd64. An ARM64 run must create
an independently hash-recorded ARM64 wheelhouse from the same pinned
requirements; pretending x86 wheels are architecture-neutral would defeat the
experiment. The sources themselves are portable Python.

Required host tools: Bash, CPython 3.12 with `venv`, coreutils, SQLite, and
optionally `swtpm`/tpm2-tools 5.x for fresh TPM generation.

Acceptance evidence from an external operator must preserve:

- the archive SHA-256 and `CAPSULE-MANIFEST.json`;
- `uname -a`, machine architecture, Python/dependency versions;
- complete `run.sh` stdout/stderr and exit code;
- regenerated semantic-result hashes;
- operator, physical-machine, and execution-time attestation.

This capsule is preparation for the external gate, not the external result.
"""


def files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if path in {ARCHIVE, ARCHIVE_SHA}:
            continue
        if path.name in CLEAN_REPLAY_FILES:
            continue
        # Editorial model-review outputs are deliberately outside the
        # execution capsule. Their runner/protocol remain inspectable source,
        # while excluding results prevents a review of the final manuscript
        # from changing the archive that the manuscript itself identifies.
        if (
            "hermes-referee-panel" in path.parts
            and "results" in path.parts
        ):
            continue
        if "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        yield path


def add_tree(
    entries: dict[str, bytes], source: Path, archive_prefix: str
) -> None:
    for path in files(source):
        relative = path.relative_to(source).as_posix()
        entries[f"{archive_prefix}/{relative}"] = path.read_bytes()


def main() -> int:
    required = (V4 / "labs", V3_SAFE, BOUNDARY)
    for path in required:
        if not path.is_dir():
            raise RuntimeError(f"missing capsule input: {path}")
    entries: dict[str, bytes] = {
        "README.md": README.encode("utf-8"),
        "run.sh": RUNNER.encode("utf-8"),
    }
    add_tree(
        entries,
        V4 / "labs",
        "workspace/masters-thesis-radar/research-factory-v4-2026-07-27/labs",
    )
    add_tree(
        entries,
        HERE,
        "workspace/masters-thesis-radar/research-factory-v4-2026-07-27/repro",
    )
    add_tree(
        entries,
        V3_SAFE,
        "workspace/masters-thesis-radar/research-factory-v3-2026-07-25/"
        "labs/safe-metric-metamorphics",
    )
    add_tree(
        entries,
        BOUNDARY,
        "workspace/a2a-boundary-seal/results/extension-enabled",
    )
    with tempfile.TemporaryDirectory(prefix="tyche-wheelhouse-") as name:
        wheelhouse = Path(name) / "wheelhouse"
        subprocess.run(
            [
                "python3",
                str(HERE / "collect-wheels.py"),
                "--requirements",
                str(HERE / "requirements.txt"),
                "--cache",
                str(Path.home() / ".cache" / "pip" / "http-v2"),
                "--out",
                str(wheelhouse),
            ],
            check=True,
        )
        add_tree(entries, wheelhouse, "wheelhouse-linux-amd64-cp312")

    manifest = {
        "capsule": "tyche-second-host-source-capsule-2026-07-28",
        "created_epoch": EPOCH,
        "status": "prepared-not-externally-run",
        "source_complete": True,
        "offline_wheelhouse": "linux/amd64 CPython 3.12 only",
        "second_physical_host_run": False,
        "second_architecture_run": False,
        "files": {
            name: {
                "sha256": hashlib.sha256(value).hexdigest(),
                "bytes": len(value),
            }
            for name, value in sorted(entries.items())
        },
    }
    entries["CAPSULE-MANIFEST.json"] = (
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n"
    ).encode("utf-8")

    with ARCHIVE.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=EPOCH
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for name, value in sorted(entries.items()):
                    info = tarfile.TarInfo(name)
                    info.size = len(value)
                    info.mtime = EPOCH
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if name == "run.sh" else 0o644
                    archive.addfile(info, io.BytesIO(value))
    digest = hashlib.sha256(ARCHIVE.read_bytes()).hexdigest()
    ARCHIVE_SHA.write_text(f"{digest}  {ARCHIVE.name}\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "archive": str(ARCHIVE),
                "sha256": digest,
                "members": len(entries),
                "bytes": ARCHIVE.stat().st_size,
                "status": manifest["status"],
            },
            indent=2,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
