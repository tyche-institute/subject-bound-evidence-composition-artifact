#!/usr/bin/env python3
"""Independent SQLite execution and mutation-sensitivity audit of crosswalk."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent


def load(name: str) -> Any:
    return json.loads((HERE / name).read_text(encoding="utf-8"))


def evaluate(
    connection: sqlite3.Connection,
    ecosystem: str,
    rows: list[dict[str, Any]],
    mapping: dict[str, str],
) -> list[dict[str, Any]]:
    connection.execute("DELETE FROM native_rows")
    connection.execute("DELETE FROM mapping")
    connection.executemany(
        "INSERT INTO native_rows VALUES(?,?,?)",
        [
            (row["id"], row["native_first_state"], row["shared_class"])
            for row in rows
        ],
    )
    connection.executemany(
        "INSERT INTO mapping VALUES(?,?,?)",
        [(ecosystem, native, shared) for native, shared in mapping.items()],
    )
    return [
        {
            "id": row[0],
            "native_first_state": row[1],
            "expected_shared_class": row[2],
            "sql_shared_class": row[3],
            "exact_match": row[2] == row[3],
        }
        for row in connection.execute(
            """
            SELECT n.id,n.native_state,n.expected_shared_class,m.shared_class
            FROM native_rows n
            LEFT JOIN mapping m
              ON m.ecosystem=? AND m.native_state=n.native_state
            ORDER BY n.id
            """,
            (ecosystem,),
        )
    ]


def main() -> int:
    crosswalk = load("crosswalk.json")
    sources = {
        "eatf": load("source-eatf-results.json")["rows"],
        "composed_transaction": load("source-transaction-gates.json")["rows"],
    }
    mappings = {
        "eatf": crosswalk["eatf"],
        "composed_transaction": crosswalk["composed_transaction"],
    }
    connection = sqlite3.connect(":memory:")
    connection.executescript(
        """
        CREATE TABLE native_rows(
          id TEXT PRIMARY KEY,
          native_state TEXT NOT NULL,
          expected_shared_class TEXT NOT NULL
        );
        CREATE TABLE mapping(
          ecosystem TEXT NOT NULL,
          native_state TEXT NOT NULL,
          shared_class TEXT NOT NULL,
          PRIMARY KEY(ecosystem,native_state)
        );
        """
    )
    baseline: dict[str, list[dict[str, Any]]] = {}
    mutation_rows: list[dict[str, Any]] = []
    classes = sorted(set(crosswalk["classes"]) | {"pass"})
    for ecosystem, rows in sources.items():
        baseline[ecosystem] = evaluate(
            connection, ecosystem, rows, mappings[ecosystem]
        )
        for native_state, original in sorted(mappings[ecosystem].items()):
            replacement = next(
                candidate for candidate in classes if candidate != original
            )
            changed = dict(mappings[ecosystem])
            changed[native_state] = replacement
            changed_rows = evaluate(connection, ecosystem, rows, changed)
            affected = [
                row["id"] for row in changed_rows if not row["exact_match"]
            ]
            omitted = dict(mappings[ecosystem])
            del omitted[native_state]
            omitted_rows = evaluate(connection, ecosystem, rows, omitted)
            unmapped = [
                row["id"]
                for row in omitted_rows
                if row["sql_shared_class"] is None
            ]
            mutation_rows.append(
                {
                    "ecosystem": ecosystem,
                    "native_state": native_state,
                    "original_class": original,
                    "replacement_class": replacement,
                    "class_mutation_detected": bool(affected),
                    "class_mutation_affected_rows": affected,
                    "leave_one_out_detected": bool(unmapped),
                    "leave_one_out_unmapped_rows": unmapped,
                }
            )
    result = {
        "lab": "crosswalk-independent-sql-audit",
        "engine": f"SQLite {sqlite3.sqlite_version}",
        "baseline_rows": sum(len(rows) for rows in baseline.values()),
        "baseline_exact_matches": sum(
            row["exact_match"]
            for rows in baseline.values()
            for row in rows
        ),
        "mapping_entries": len(mutation_rows),
        "class_mutations_detected": sum(
            row["class_mutation_detected"] for row in mutation_rows
        ),
        "leave_one_out_gaps_detected": sum(
            row["leave_one_out_detected"] for row in mutation_rows
        ),
        "all_passed": (
            all(
                row["exact_match"]
                for rows in baseline.values()
                for row in rows
            )
            and all(
                row["class_mutation_detected"]
                and row["leave_one_out_detected"]
                for row in mutation_rows
            )
        ),
        "claim_boundary": (
            "independent relational execution and sensitivity audit of an "
            "author-defined analytic mapping; not external semantic "
            "validation or interoperability"
        ),
        "baseline": baseline,
        "mutations": mutation_rows,
    }
    (HERE / "independent-sql-results.json").write_text(
        json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest_names = (
        "README.md",
        "NOTICE.source",
        "build_transfer.py",
        "verify_crosswalk_sql.py",
        "source-eatf-results.json",
        "source-transaction-gates.json",
        "crosswalk.json",
        "results.json",
        "independent-sql-results.json",
        "SUMMARY.md",
    )
    (HERE / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  "
            f"{name}\n"
            for name in manifest_names
        ),
        encoding="utf-8",
    )
    print(
        json.dumps(
            {
                key: value
                for key, value in result.items()
                if key not in {"baseline", "mutations"}
            },
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
    )
    return 0 if result["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
