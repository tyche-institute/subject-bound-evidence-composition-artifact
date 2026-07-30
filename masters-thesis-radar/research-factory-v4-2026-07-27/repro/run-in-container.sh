#!/usr/bin/env bash
# Build the reproduction image and run the three V4 laboratory entry points
# inside it, with the packet mounted read-only and no network namespace.
#
# Review experiment E4 (cross-host closure); closes review finding C-25 by
# replacing the self-asserted `network_used: false` with an enforced property.
#
# Usage:
#   ./run-in-container.sh                 # build + run, print hashes
#   IMAGE=foo:bar ./run-in-container.sh   # override image tag
set -euo pipefail

REPRO_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PACKET=$(dirname "$REPRO_DIR")                        # research-factory-v4-2026-07-27
RADAR=$(dirname "$PACKET")                            # masters-thesis-radar
VAULT=$(dirname "$RADAR")                             # vault root
V3="$RADAR/research-factory-v3-2026-07-25"
BSEAL="$VAULT/a2a-boundary-seal/results/extension-enabled"

IMAGE=${IMAGE:-tyche-v4-repro:2026-07-27}
BUILD_CTX=${BUILD_CTX:-${TMPDIR:-/tmp}/tyche-v4-repro-ctx}
PIP_CACHE=${PIP_CACHE:-$HOME/.cache/pip/http-v2}

# The packet's own entry points reach outside the packet directory:
#   labs/composed-transaction-corpus/*      -> ../../../research-factory-v3-2026-07-25/
#                                              labs/safe-metric-metamorphics (SAFE module + corpus)
#   labs/protocol-valid-unauthorized/adapters -> <vault>/a2a-boundary-seal/results/extension-enabled
# Both are mounted read-only at the exact relative positions the code resolves.
for required in "$PACKET" "$V3/labs/safe-metric-metamorphics" "$BSEAL"; do
  [ -d "$required" ] || { echo "missing required input tree: $required" >&2; exit 1; }
done

echo "== staging offline wheelhouse =="
rm -rf "$BUILD_CTX"
mkdir -p "$BUILD_CTX"
cp "$REPRO_DIR/requirements.txt" "$BUILD_CTX/requirements.txt"
cp "$REPRO_DIR/container-entry.sh" "$BUILD_CTX/container-entry.sh"
python3 "$REPRO_DIR/collect-wheels.py" \
  --requirements "$REPRO_DIR/requirements.txt" \
  --cache "$PIP_CACHE" \
  --out "$BUILD_CTX/wheelhouse"

echo "== docker build (--network=none) =="
docker build --network=none --pull=false \
  -f "$REPRO_DIR/Dockerfile" -t "$IMAGE" "$BUILD_CTX"

echo "== image identity =="
docker image inspect "$IMAGE" --format 'image_id={{.Id}}'
docker image inspect python:3.12-slim \
  --format 'base_repo_digest={{range .RepoDigests}}{{.}}{{end}}'

echo "== docker run (--network=none, packet read-only at /work) =="
docker run --rm \
  --network=none \
  --read-only \
  --tmpfs /scratch:rw,exec,size=256m \
  --tmpfs /tmp:rw,size=32m \
  -v "$PACKET":/work/masters-thesis-radar/research-factory-v4-2026-07-27:ro \
  -v "$V3":/work/masters-thesis-radar/research-factory-v3-2026-07-25:ro \
  -v "$BSEAL":/work/a2a-boundary-seal/results/extension-enabled:ro \
  "$IMAGE"
