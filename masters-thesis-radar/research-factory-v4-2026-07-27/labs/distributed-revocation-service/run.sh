#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONDONTWRITEBYTECODE=1
python3 run_experiment.py
python3 verify_saved_results.py
sha256sum -c SHA256SUMS
