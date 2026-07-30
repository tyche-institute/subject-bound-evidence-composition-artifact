#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1
python3 generate_vectors.py
python3 verify_overlay.py
(
  cd results
  sha256sum -c SHA256SUMS
)
(
  cd independent-java
  ./run.sh
)
