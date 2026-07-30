#!/usr/bin/env bash
set -euo pipefail

lab=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
project=tyche-container-revocation-v1
export TYCHE_RUNTIME_IMAGE=${TYCHE_RUNTIME_IMAGE:-tyche-v4-repro@sha256:e9d09e11129b6b53734d780c21fa90d1d92cf7e5f508357704c5fd34e319a173}

cleanup() {
  docker compose --project-name "$project" --file "$lab/compose.yaml" \
    down --volumes --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

mkdir -p "$lab/results"
docker image inspect "$TYCHE_RUNTIME_IMAGE" >/dev/null
cleanup
docker compose --project-name "$project" --file "$lab/compose.yaml" \
  config | sed "s#${lab}#<LAB>#g" >"$lab/results/compose-config.yaml"
docker compose --project-name "$project" --file "$lab/compose.yaml" \
  config --images >"$lab/results/compose-images.txt"
docker compose --project-name "$project" --file "$lab/compose.yaml" \
  up --abort-on-container-exit --exit-code-from runner
python3 "$lab/verify_saved_results.py" "$lab/results/results.json"
python3 "$lab/freeze_run.py"
(cd "$lab" && sha256sum -c SHA256SUMS)
