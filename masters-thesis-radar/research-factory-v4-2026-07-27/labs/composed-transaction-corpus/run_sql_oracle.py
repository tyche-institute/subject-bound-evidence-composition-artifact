#!/usr/bin/env python3
"""SQL re-composition oracle for the composed transaction outputs (v3).

NOT independent validation: this runner reads results/verdicts.jsonl — the
per-layer typed results and the two subject records already produced by the
Python evaluator — and oracle.sql re-derives the typed binding outcome, the
conjunction and the first-rejecting-gate label from those columns. It
touches no signature, no bootstrap replicate, no delegation edge and no
attestation object.

What changed in v3: the oracle no longer receives the binding outcome as an
input. It receives the SUBJECT STRINGS (canonical_action / observed_effect)
and re-derives EFFECT_MISMATCH / RESOURCE_MISMATCH / TIME_MISMATCH /
PROFILE_MISMATCH / PASS itself, so a divergence between the SQL and Python
binding rules is detectable. That is a transcription check between two
same-author implementations, not an independent source of truth.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "results" / "verdicts.jsonl"
SQL_PATH = ROOT / "oracle.sql"
RESULTS = ROOT / "results-sql-oracle"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def delimited(values: Any) -> str:
    """Pipe-delimited set literal for SQL membership tests.

    ``["ledger.read"]`` -> ``"|ledger.read|"``; the empty set -> ``"|"``,
    which no ``'|' || x || '|'`` probe can match, reproducing Python's
    ``x in []`` being false.
    """
    items = list(values or [])
    return "|" + "|".join(items) + "|" if items else "|"


def main() -> int:
    rows = [
        json.loads(line)
        for line in SOURCE.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    database = sqlite3.connect(":memory:")
    database.execute(
        """
        CREATE TABLE transaction_inputs (
          id TEXT PRIMARY KEY,
          policy_result TEXT NOT NULL,
          evidence_result TEXT NOT NULL,
          state_result TEXT NOT NULL,
          authority_result TEXT NOT NULL,
          authority_gate TEXT NOT NULL,
          measurement_result TEXT NOT NULL,
          canonical_effect TEXT,
          canonical_resource TEXT,
          canonical_operation TEXT,
          canonical_granted_tools TEXT,
          canonical_granted_resources TEXT,
          canonical_authorised_from TEXT,
          canonical_authorised_until TEXT,
          canonical_measurement_profile TEXT,
          observed_effect TEXT,
          observed_resource TEXT,
          observed_issued_at TEXT,
          observed_measurement_profile TEXT
        )
        """
    )
    database.executemany(
        "INSERT INTO transaction_inputs VALUES ("
        + ", ".join(["?"] * 19)
        + ")",
        [
            (
                row["id"],
                row["layer_results"]["policy"],
                row["layer_results"]["evidence"],
                row["layer_results"]["state"],
                row["layer_results"]["authority"],
                row["authority"]["gate"],
                row["layer_results"]["measurement"],
                row["binding"]["canonical_action"]["effect"],
                row["binding"]["canonical_action"]["resource"],
                row["binding"]["canonical_action"]["operation"],
                delimited(row["binding"]["canonical_action"]["granted_tools"]),
                delimited(
                    row["binding"]["canonical_action"]["granted_resources"]
                ),
                row["binding"]["canonical_action"]["authorised_from"],
                row["binding"]["canonical_action"]["authorised_until"],
                row["binding"]["canonical_action"]["measurement_profile"],
                row["binding"]["observed_effect"]["effect"],
                row["binding"]["observed_effect"]["resource"],
                row["binding"]["observed_effect"]["issued_at"],
                row["binding"]["observed_effect"]["measurement_profile"],
            )
            for row in rows
        ],
    )
    oracle = {
        row[0]: {"verdict": row[1], "gate": row[2], "binding": row[3]}
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
                "oracle_binding_result": observed["binding"],
                "python_verdict": row["verdict"],
                "python_gate": row["first_rejecting_gate"],
                "python_binding_result": row["binding"]["result"],
                "expected_verdict": row["expected"]["verdict"],
                "expected_gate": row["expected"]["first_rejecting_gate"],
                "expected_binding_result": row["expected"]["binding_result"],
                "implementation_match": (
                    observed["verdict"] == row["verdict"]
                    and observed["gate"] == row["first_rejecting_gate"]
                    and observed["binding"] == row["binding"]["result"]
                ),
                "expected_match": (
                    observed["verdict"] == row["expected"]["verdict"]
                    and observed["gate"]
                    == row["expected"]["first_rejecting_gate"]
                    and observed["binding"]
                    == row["expected"]["binding_result"]
                ),
            }
        )
    oracle_gate_counts: dict[str, int] = {}
    oracle_binding_counts: dict[str, int] = {}
    for item in results:
        oracle_gate_counts[item["oracle_gate"]] = (
            oracle_gate_counts.get(item["oracle_gate"], 0) + 1
        )
        oracle_binding_counts[item["oracle_binding_result"]] = (
            oracle_binding_counts.get(item["oracle_binding_result"], 0) + 1
        )
    summary = {
        "profile": "tyche-evidence-carrying-decision-sql-oracle-v3",
        "transactions": len(results),
        "implementation_matches": sum(
            item["implementation_match"] for item in results
        ),
        "expected_matches": sum(item["expected_match"] for item in results),
        "binding_result_matches": sum(
            item["oracle_binding_result"] == item["python_binding_result"]
            for item in results
        ),
        "oracle_gate_counts": oracle_gate_counts,
        "oracle_binding_result_counts": oracle_binding_counts,
        "disclaimers": [
            "This oracle recomposes per-layer typed results and subject "
            "records produced by the Python evaluator; it is a second "
            "composition code path, not independent validation. It verifies "
            "no signature, no bootstrap replicate, no delegation edge and "
            "no attestation object.",
            "The binding outcome IS re-derived here rather than echoed, so "
            "SQL/Python divergence in the binding rules is detectable; the "
            "subject strings it compares still come from the Python "
            "evaluator, so this is a transcription check between two "
            "same-author implementations.",
            "Expected labels are author-written programme-internal "
            "expectations generated by build_corpus.py with the same "
            "composition rule module the Python verifier imports; "
            "agreement is not external ground truth.",
        ],
        "source_verdicts_sha256": sha256_file(SOURCE),
        "sql_sha256": sha256_file(SQL_PATH),
        "runner_sha256": sha256_file(Path(__file__)),
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
    return 0 if (
        summary["implementation_matches"] == len(results)
        and summary["expected_matches"] == len(results)
        and summary["binding_result_matches"] == len(results)
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
