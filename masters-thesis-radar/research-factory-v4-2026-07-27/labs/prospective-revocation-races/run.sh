#!/usr/bin/env bash
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

python3 build_corpus.py
python3 run.py
node run.mjs
python3 compare.py

sha256sum \
  README.md \
  build_corpus.py \
  run.py \
  run.mjs \
  compare.py \
  run.sh \
  corpus.json \
  python-results.json \
  js-results.json \
  summary.json \
  result-2026-07-27.md \
  > SHA256SUMS

sha256sum -c SHA256SUMS
