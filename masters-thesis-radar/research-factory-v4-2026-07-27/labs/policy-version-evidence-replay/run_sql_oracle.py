#!/usr/bin/env python3
"""Recompose verified layer results through a second, relational code path.

This oracle consumes the per-layer typed results already produced by the
Python evaluator and re-derives only the conjunction and the
first-rejecting-gate label. It is NOT independent validation: it touches no
signature and re-evaluates no layer semantics (review item C-01)."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "results" / "verdicts.jsonl"
SQL_PATH = ROOT / "oracle.sql"
RESULTS = ROOT / "results-sql-oracle"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    rows = [
        json.loads(line)
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    database = sqlite3.connect(":memory:")
    database.execute(
        """
        CREATE TABLE replay_inputs (
          id TEXT PRIMARY KEY,
          policy_result TEXT NOT NULL,
          evidence_result TEXT NOT NULL
        )
        """
    )
    database.executemany(
        "INSERT INTO replay_inputs VALUES (?, ?, ?)",
        [(row["id"], row["policy_result"], row["evidence_result"]) for row in rows],
    )
    oracle = {
        row[0]: {"verdict": row[1], "gate": row[2]}
        for row in database.execute(SQL_PATH.read_text(encoding="utf-8"))
    }
    results = []
    for row in rows:
        observed = oracle[row["id"]]
        results.append(
            {
                "id": row["id"],
                "oracle_verdict": observed["verdict"],
                "oracle_gate": observed["gate"],
                "python_verdict": row["verdict"],
                "python_gate": row["first_rejecting_gate"],
                "implementation_match": (
                    observed["verdict"] == row["verdict"]
                    and observed["gate"] == row["first_rejecting_gate"]
                ),
            }
        )
    oracle_gate_counts: dict[str, int] = {}
    for item in results:
        gate = item["oracle_gate"]
        oracle_gate_counts[gate] = oracle_gate_counts.get(gate, 0) + 1
    summary = {
        "profile": "tyche-policy-version-evidence-replay-sql-oracle-v2",
        "vectors": len(results),
        "implementation_matches": sum(
            item["implementation_match"] for item in results
        ),
        "oracle_gate_counts": oracle_gate_counts,
        "source_verdicts_sha256": sha256_file(SOURCE),
        "sql_sha256": sha256_file(SQL_PATH),
        "runner_sha256": sha256_file(Path(__file__)),
        "disclaimers": [
            "This oracle recomposes per-layer typed results already "
            "produced by the Python evaluator; agreement validates only "
            "the conjunction and the first-rejecting-gate labelling, not "
            "signatures, layer semantics, or the author-written expected "
            "labels. It is NOT independent validation.",
            "All expected labels in the source corpus are author-written.",
        ],
    }
    RESULTS.mkdir(exist_ok=True)
    verdicts_path = RESULTS / "verdicts.jsonl"
    summary_path = RESULTS / "summary.json"
    verdicts_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (RESULTS / "SHA256SUMS").write_text(
        "\n".join(
            [
                f"{sha256_file(verdicts_path)}  verdicts.jsonl",
                f"{sha256_file(summary_path)}  summary.json",
                f"{sha256_file(SOURCE)}  ../results/verdicts.jsonl",
                f"{sha256_file(SQL_PATH)}  ../oracle.sql",
                f"{sha256_file(Path(__file__))}  ../run_sql_oracle.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["implementation_matches"] == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
