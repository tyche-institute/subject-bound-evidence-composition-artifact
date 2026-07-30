#!/usr/bin/env bash
# Run the evidence upgrades in the already-built, digest-pinned offline image.
set -euo pipefail

repro_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
packet=$(dirname "$repro_dir")
radar=$(dirname "$packet")
vault=$(dirname "$radar")
v3="$radar/research-factory-v3-2026-07-25"
zeus="$vault/zeus-followup-2026-07-27"
a2a="$vault/a2a-boundary-seal/results/extension-enabled"
image=${IMAGE:-tyche-v4-repro:2026-07-27}
log="$repro_dir/EVIDENCE-UPGRADE-CONTAINER-RUN-2026-07-27.log"

for required in "$packet" "$v3" "$zeus" "$a2a"; do
  [ -d "$required" ] || {
    echo "missing required input tree: $required" >&2
    exit 1
  }
done

docker image inspect "$image" >/dev/null

docker run --rm \
  --network=none \
  --read-only \
  --tmpfs /scratch:rw,exec,size=512m \
  --tmpfs /tmp:rw,size=32m \
  -v "$packet":/work/masters-thesis-radar/research-factory-v4-2026-07-27:ro \
  -v "$v3":/work/masters-thesis-radar/research-factory-v3-2026-07-25:ro \
  -v "$zeus":/work/zeus-followup-2026-07-27:ro \
  -v "$a2a":/work/a2a-boundary-seal/results/extension-enabled:ro \
  -v "$repro_dir/evidence-upgrade-container-entry.sh":/opt/repro/evidence-upgrade-container-entry.sh:ro \
  --entrypoint /bin/bash \
  "$image" /opt/repro/evidence-upgrade-container-entry.sh \
  | tee "$log"

sha256sum "$log"
