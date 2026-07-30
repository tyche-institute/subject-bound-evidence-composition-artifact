#!/usr/bin/env bash
set -euo pipefail

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$script_dir"

python build_corpus.py
python run.py
python run_sql_oracle.py

(cd results && sha256sum -c SHA256SUMS)
(cd results-sql-oracle && sha256sum -c SHA256SUMS)
