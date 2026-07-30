#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

# Never write bytecode caches — the SAFE measurement laboratory is imported
# read-only from the frozen v3 factory tree.
export PYTHONDONTWRITEBYTECODE=1

python test_state_adapter.py
python build_corpus.py
python test_cross_layer_binding.py
python verify_transactions.py
python run_sql_oracle.py

(cd results && sha256sum -c SHA256SUMS)
(cd results-sql-oracle && sha256sum -c SHA256SUMS)
