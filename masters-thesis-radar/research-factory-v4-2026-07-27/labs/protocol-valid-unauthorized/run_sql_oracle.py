#!/usr/bin/env python3
"""Independent SQLite/relational oracle for expanded delegation-path cases."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
EXPANDED_PATH = ROOT / "results-delegation-paths" / "expanded-cases.json"
PYTHON_VERDICTS_PATH = ROOT / "results-delegation-paths" / "verdicts.jsonl"
SQL_PATH = ROOT / "oracle_delegation_paths.sql"
RESULTS_DIR = ROOT / "results-sql-oracle"
VERDICTS_PATH = RESULTS_DIR / "verdicts.jsonl"
SUMMARY_PATH = RESULTS_DIR / "summary.json"
CHECKSUMS_PATH = RESULTS_DIR / "SHA256SUMS"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def create_schema(db: sqlite3.Connection) -> None:
    db.executescript(
        """
        CREATE TABLE cases(
          case_id TEXT PRIMARY KEY, ordinal INTEGER, hops INTEGER,
          effect_time TEXT, protocol_valid INTEGER,
          root_principal TEXT, root_role TEXT,
          root_operations TEXT, root_resources TEXT, root_tools TEXT,
          root_audiences TEXT, root_purposes TEXT,
          root_amount_max REAL, root_currency TEXT,
          expected_verdict TEXT, expected_gate TEXT,
          expected_stage_id TEXT, expected_stage_index INTEGER
        );
        CREATE TABLE role_transitions(from_role TEXT, to_role TEXT);
        CREATE TABLE edges(
          case_id TEXT, edge_index INTEGER, edge_id TEXT,
          delegator TEXT, delegate TEXT, from_role TEXT, to_role TEXT,
          issuer_signature_valid INTEGER, status TEXT,
          not_before TEXT, expires_at TEXT,
          grant_operations TEXT, grant_resources TEXT, grant_tools TEXT,
          grant_audiences TEXT, grant_purposes TEXT,
          grant_amount_max REAL, grant_currency TEXT,
          grant_delegable INTEGER,
          PRIMARY KEY(case_id, edge_index)
        );
        CREATE TABLE actions(
          case_id TEXT PRIMARY KEY, subject TEXT, role TEXT,
          operation TEXT, resource TEXT, tool TEXT, audience TEXT,
          purpose TEXT, amount REAL, currency TEXT, action_json TEXT
        );
        CREATE TABLE receipts(
          case_id TEXT PRIMARY KEY, native_evidence_valid INTEGER,
          effect_time TEXT, action_json TEXT
        );
        """
    )


def load_data(db: sqlite3.Connection, expanded: dict[str, Any]) -> None:
    base = expanded["base"]
    for from_role, to_roles in base["allowed_role_transitions"].items():
        db.executemany(
            "INSERT INTO role_transitions VALUES (?, ?)",
            [(from_role, to_role) for to_role in to_roles],
        )

    scope = base["scope"]
    for ordinal, item in enumerate(expanded["cases"]):
        case = item["case"]
        expected = item["expected"]
        db.execute(
            "INSERT INTO cases VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                item["id"], ordinal, item["hops"], expanded["effect_time"],
                int(case["protocol_valid"]), base["root_principal"],
                base["root_role"], compact(scope["operations"]),
                compact(scope["resources"]), compact(scope["tools"]),
                compact(scope["audiences"]), compact(scope["purposes"]),
                scope["amount_max"], scope["currency"], expected["verdict"],
                expected["gate"], expected["first_bad_edge_id"],
                expected["first_bad_edge_index"],
            ),
        )
        for index, edge in enumerate(case["edges"]):
            grant = edge["grant"]
            db.execute(
                "INSERT INTO edges VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    item["id"], index, edge["edge_id"], edge["delegator"],
                    edge["delegate"], edge["from_role"], edge["to_role"],
                    int(edge["issuer_signature_valid"]), edge["status"],
                    edge["not_before"], edge["expires_at"],
                    compact(grant["operations"]), compact(grant["resources"]),
                    compact(grant["tools"]), compact(grant["audiences"]),
                    compact(grant["purposes"]), grant["amount_max"],
                    grant["currency"], int(grant["delegable"]),
                ),
            )
        action = case["action"]
        db.execute(
            "INSERT INTO actions VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (
                item["id"], action["subject"], action["role"],
                action["operation"], action["resource"], action["tool"],
                action["audience"], action["purpose"], action["amount"],
                action["currency"], compact(action),
            ),
        )
        receipt = case["receipt"]
        db.execute(
            "INSERT INTO receipts VALUES (?,?,?,?)",
            (
                item["id"], int(receipt["native_evidence_valid"]),
                receipt["effect_time"], compact(receipt["action"]),
            ),
        )


def main() -> int:
    expanded = json.loads(EXPANDED_PATH.read_text(encoding="utf-8"))
    python_results = {
        item["id"]: item
        for item in (
            json.loads(line)
            for line in PYTHON_VERDICTS_PATH.read_text(encoding="utf-8").splitlines()
        )
    }
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    create_schema(db)
    load_data(db, expanded)
    rows = db.execute(SQL_PATH.read_text(encoding="utf-8")).fetchall()

    results = []
    for row in rows:
        expected = next(
            item["expected"] for item in expanded["cases"] if item["id"] == row["case_id"]
        )
        expected_match = (
            row["verdict"] == expected["verdict"]
            and row["gate"] == expected["gate"]
            and row["stage_id"] == expected["first_bad_edge_id"]
            and row["stage_index"] == expected["first_bad_edge_index"]
        )
        python_result = python_results[row["case_id"]]
        implementation_match = (
            row["verdict"] == python_result["verdict"]
            and row["gate"] == python_result["first_rejecting_gate"]
            and row["stage_id"] == python_result["first_bad_edge_id"]
            and row["stage_index"] == python_result["first_bad_edge_index"]
        )
        results.append(
            {
                "id": row["case_id"],
                "verdict": row["verdict"],
                "first_rejecting_gate": row["gate"],
                "first_bad_edge_id": row["stage_id"],
                "first_bad_edge_index": row["stage_index"],
                "expected_match": expected_match,
                "python_implementation_match": implementation_match,
            }
        )

    summary = {
        "profile": "tyche-delegation-path-sql-oracle-v0",
        "cases": len(results),
        "expected_matches": sum(item["expected_match"] for item in results),
        "python_implementation_matches": sum(
            item["python_implementation_match"] for item in results
        ),
        "disclaimer": (
            "issuer_signature_valid, native_evidence_valid and protocol_valid "
            "are corpus-supplied experimental flags; neither implementation "
            "performs any cryptographic verification."
        ),
        "independence_note": (
            "the relational oracle re-derives verdicts from the raw case "
            "objects in expanded-cases.json, not from the Python evaluator's "
            "verdict stream; case expansion (build_case plus mutations) and "
            "the expected labels are shared with the Python entry point, so "
            "agreement is implementation diversity over verdict derivation, "
            "not independent validation of the labels."
        ),
        "expanded_cases_sha256": sha256_file(EXPANDED_PATH),
        "sql_sha256": sha256_file(SQL_PATH),
        "runner_sha256": sha256_file(Path(__file__)),
    }
    RESULTS_DIR.mkdir(exist_ok=True)
    VERDICTS_PATH.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    SUMMARY_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    CHECKSUMS_PATH.write_text(
        "\n".join(
            [
                f"{sha256_file(VERDICTS_PATH)}  verdicts.jsonl",
                f"{sha256_file(SUMMARY_PATH)}  summary.json",
                f"{sha256_file(EXPANDED_PATH)}  ../results-delegation-paths/expanded-cases.json",
                f"{sha256_file(SQL_PATH)}  ../oracle_delegation_paths.sql",
                f"{sha256_file(Path(__file__))}  ../run_sql_oracle.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if (
        summary["expected_matches"] == summary["cases"]
        and summary["python_implementation_matches"] == summary["cases"]
    ) else 1


if __name__ == "__main__":
    raise SystemExit(main())
