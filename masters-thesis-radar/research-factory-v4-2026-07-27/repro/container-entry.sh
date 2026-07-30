#!/usr/bin/env bash
# In-container driver for the V4 laboratory entry points.
#
# /work holds the packet, bind-mounted read-only. Nothing is written there:
# the tree is copied to /scratch (a tmpfs) and every entry point runs against
# that copy, so the container cannot mutate the host packet even if a
# laboratory tried to.
set -euo pipefail

export PYTHONDONTWRITEBYTECODE=1
export PYTHONHASHSEED=0
export LC_ALL=C.UTF-8
export TZ=UTC

SRC=/work
DST=/scratch
V4_REL=masters-thesis-radar/research-factory-v4-2026-07-27
LABS="$DST/$V4_REL/labs"

echo "===== ENVIRONMENT ====="
python -VV
python - <<'PY'
import platform, sqlite3, sys
import numpy, cryptography
print("platform:", platform.platform())
print("numpy:", numpy.__version__)
print("cryptography:", cryptography.__version__)
print("sqlite3:", sqlite3.sqlite_version)
print("sys.version:", sys.version.replace("\n", " "))
PY

echo "===== NETWORK MEASUREMENT (C-25) ====="
echo "interfaces in this network namespace:"
ls -1 /sys/class/net
echo "routes:"
cat /proc/net/route
python - <<'PY'
import socket, errno
# Literal IPv4, no DNS. Under `docker run --network=none` the namespace has no
# route and no non-loopback interface, so the kernel fails this call locally;
# no packet can leave the machine. This is the measurement that replaces the
# self-asserted `network_used: false` key.
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(1.0)
try:
    s.connect(("1.1.1.1", 443))
except OSError as exc:
    name = errno.errorcode.get(exc.errno, str(exc.errno))
    print(f"outbound TCP connect: FAILED errno={exc.errno} ({name}) {exc.strerror}")
else:
    print("outbound TCP connect: SUCCEEDED -- isolation NOT enforced")
    raise SystemExit(2)
finally:
    s.close()
PY

echo "===== STAGE READ-ONLY PACKET INTO WRITABLE SCRATCH ====="
mkdir -p "$DST"
cp -a "$SRC"/. "$DST"/
chmod -R u+rwX "$DST"
echo "staged: $(find "$DST" -type f | wc -l) files"

echo "===== ENTRY POINT 1/3: labs/protocol-valid-unauthorized ====="
(
  cd "$LABS/protocol-valid-unauthorized"
  python verify_corpus.py
  python adapters/boundary_seal_adapter.py
  python verify_delegation_paths.py
  python run_sql_oracle.py
) >/dev/null

echo "===== ENTRY POINT 2/3: labs/policy-version-evidence-replay/run.sh ====="
bash "$LABS/policy-version-evidence-replay/run.sh" >/dev/null

echo "===== ENTRY POINT 3/3: labs/composed-transaction-corpus/run.sh ====="
bash "$LABS/composed-transaction-corpus/run.sh" >/dev/null

echo "===== RESULT FILE HASHES ====="
(
  cd "$LABS"
  find . -path '*/results*/*' -type f | LC_ALL=C sort | while read -r f; do
    printf 'CONTAINER-HASH %s\n' "$(sha256sum "$f" | sed 's#  \./#  #')"
  done
)

echo "===== REGENERATED INPUT ARTIFACT HASHES ====="
(
  cd "$LABS"
  for f in composed-transaction-corpus/corpus.json \
           policy-version-evidence-replay/corpus.json \
           protocol-valid-unauthorized/corpus.json \
           protocol-valid-unauthorized/delegation-paths.json; do
    printf 'CONTAINER-HASH %s\n' "$(sha256sum "$f")"
  done
)

echo "===== MEASUREMENT LCB VALUES (SAFE bootstrap) ====="
python - "$LABS/composed-transaction-corpus/results/verdicts.jsonl" <<'PY'
import json, sys
seen = {}
for line in open(sys.argv[1], encoding="utf-8"):
    item = json.loads(line)
    m = item["measurement"]
    seen.setdefault(
        m["fixture_id"],
        (m["point_estimate"], m["lcb"], m["threshold"],
         item["layer_results"]["measurement"]),
    )
for fid in sorted(seen):
    point, lcb, thr, res = seen[fid]
    print(f"CONTAINER-LCB {fid} point={point!r} lcb={lcb!r} "
          f"threshold={thr!r} result={res}")
PY

echo "===== DONE ====="
