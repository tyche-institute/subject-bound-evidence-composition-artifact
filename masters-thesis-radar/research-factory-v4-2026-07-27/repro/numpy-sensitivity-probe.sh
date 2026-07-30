#!/usr/bin/env bash
# SECONDARY sensitivity probe — NOT part of the pinned reproduction.
#
#   ./numpy-sensitivity-probe.sh 2.5.1 2.4.6
#
# For each NumPy version given, builds an otherwise-identical image and runs
# the composed-transaction-corpus entry point with --network=none, printing
# the SAFE bootstrap lower bounds. Answers the question the pinned
# reproduction structurally cannot: does the PCG64-derived percentile move
# when the NumPy build changes?
#
# Every version must already be present in the local pip HTTP cache; nothing
# is downloaded.
set -euo pipefail

REPRO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKET=$(dirname "$REPRO_DIR")
RADAR=$(dirname "$PACKET")
VAULT=$(dirname "$RADAR")
V3="$RADAR/research-factory-v3-2026-07-25"
BSEAL="$VAULT/a2a-boundary-seal/results/extension-enabled"
PIP_CACHE=${PIP_CACHE:-$HOME/.cache/pip/http-v2}
CTX_ROOT=${CTX_ROOT:-${TMPDIR:-/tmp}/tyche-v4-probe-ctx}

[ "$#" -ge 1 ] || { echo "usage: $0 <numpy-version> [<numpy-version> ...]" >&2; exit 1; }

for version in "$@"; do
  ctx="$CTX_ROOT/$version"
  image="tyche-v4-probe-numpy-$version:2026-07-27"
  rm -rf "$ctx"; mkdir -p "$ctx"
  {
    echo "numpy==$version"
    grep -E '^(cryptography|cffi|pycparser)==' "$REPRO_DIR/requirements.txt"
  } > "$ctx/requirements.txt"
  cp "$REPRO_DIR/probe-entry.sh" "$ctx/probe-entry.sh"
  python3 "$REPRO_DIR/collect-wheels.py" \
    --requirements "$ctx/requirements.txt" --cache "$PIP_CACHE" \
    --out "$ctx/wheelhouse" >/dev/null

  docker build --network=none --pull=false -q \
    -f "$REPRO_DIR/Dockerfile.numpy-probe" -t "$image" "$ctx" >/dev/null

  echo "===== PROBE numpy==$version ====="
  docker run --rm --network=none --read-only \
    --tmpfs /scratch:rw,exec,size=256m --tmpfs /tmp:rw,size=32m \
    -v "$PACKET":/work/masters-thesis-radar/research-factory-v4-2026-07-27:ro \
    -v "$V3":/work/masters-thesis-radar/research-factory-v3-2026-07-25:ro \
    -v "$BSEAL":/work/a2a-boundary-seal/results/extension-enabled:ro \
    "$image"
done
