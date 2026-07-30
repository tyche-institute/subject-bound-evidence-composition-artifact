#!/usr/bin/env python3
"""Verify saved native vectors, mutations, and composed-decision parity."""

from __future__ import annotations

import collections
import hashlib
import importlib.util
import json
from pathlib import Path
from typing import Any

import native_state_adapter as native


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results"
OVERLAY = HERE / "native-state-overlay.json"
POLICY_PATH = HERE / "appraisal-policy.json"
COMPOSED = HERE.parent / "composed-transaction-corpus"
SOURCE_RESULTS = COMPOSED / "results" / "verdicts.jsonl"
MUTATIONS = (
    "quote_message_flip",
    "signature_flip",
    "pcr_blob_flip",
    "challenge_replay",
    "transaction_substitution",
    "corpus_hash_substitution",
    "measurement_substitution",
    "window_substitution",
)


def load_composition() -> Any:
    spec = importlib.util.spec_from_file_location(
        "native_overlay_composition", COMPOSED / "composition_rule.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load composition rule")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def main() -> int:
    RESULTS.mkdir(exist_ok=True)
    overlay = json.loads(OVERLAY.read_text(encoding="utf-8"))
    policy = json.loads(POLICY_PATH.read_text(encoding="utf-8"))
    vectors = overlay["vectors"]
    by_id = {
        item["envelope"]["transaction_id"]: item for item in vectors
    }

    verdict_rows: list[dict[str, Any]] = []
    for evidence in vectors:
        result = native.appraise(evidence, policy)
        verdict_rows.append(
            {
                "transaction_id": evidence["envelope"]["transaction_id"],
                "root_id": evidence["root_id"],
                "ak_algorithm": evidence["ak_algorithm"],
                "expected_state_class": evidence["expected_state_class"],
                "observed_state_class": result["result"],
                "oracle_match": (
                    result["result"] == evidence["expected_state_class"]
                ),
                "appraisal": result,
            }
        )
    write_jsonl(RESULTS / "verdicts.jsonl", verdict_rows)

    representatives: dict[str, dict[str, Any]] = {}
    for evidence in vectors:
        representatives.setdefault(evidence["root_id"], evidence)
    ordered = sorted(vectors, key=lambda x: x["envelope"]["transaction_id"])
    mutation_rows: list[dict[str, Any]] = []
    for root_offset, (root_id, evidence) in enumerate(
        sorted(representatives.items())
    ):
        alternate = ordered[(root_offset + 37) % len(ordered)]
        if alternate["envelope"]["transaction_id"] == evidence["envelope"][
            "transaction_id"
        ]:
            alternate = ordered[(root_offset + 38) % len(ordered)]
        for mutation in MUTATIONS:
            candidate = native.mutate_evidence(
                evidence, mutation, alternate
            )
            result = native.appraise(candidate, policy)
            mutation_rows.append(
                {
                    "root_id": root_id,
                    "source_transaction_id": evidence["envelope"][
                        "transaction_id"
                    ],
                    "mutation": mutation,
                    "expected_state_class": "CRYPTOGRAPHIC_FAILURE",
                    "observed_state_class": result["result"],
                    "rejected_as_expected": (
                        result["result"] == "CRYPTOGRAPHIC_FAILURE"
                    ),
                    "appraisal": result,
                }
            )
    write_jsonl(RESULTS / "mutation-verdicts.jsonl", mutation_rows)

    source_rows = [
        json.loads(line)
        for line in SOURCE_RESULTS.read_text(encoding="utf-8").splitlines()
        if line
    ]
    composition = load_composition()
    composed_rows: list[dict[str, Any]] = []
    native_by_id = {
        row["transaction_id"]: row["observed_state_class"]
        for row in verdict_rows
    }
    for source in source_rows:
        subjects = {
            "canonical_action": source["binding"]["canonical_action"],
            "observed_effect": source["binding"]["observed_effect"],
        }
        recomposed = composition.compose(
            source["layer_results"]["policy"],
            source["layer_results"]["evidence"],
            native_by_id[source["id"]],
            source["layer_results"]["authority"],
            source["authority"]["gate"],
            source["layer_results"]["measurement"],
            subjects,
        )
        composed_rows.append(
            {
                "transaction_id": source["id"],
                "native_state_class": native_by_id[source["id"]],
                "recomposed": recomposed,
                "source_expected": source["expected"],
                "exact_match": recomposed == source["expected"],
            }
        )
    write_jsonl(RESULTS / "composed-verdicts.jsonl", composed_rows)

    class_counts = collections.Counter(
        row["observed_state_class"] for row in verdict_rows
    )
    ak_hashes = {
        root["ak_pub_sha256"] for root in overlay["roots"]
    }
    quote_hashes = {
        hashlib.sha256(
            __import__("base64").b64decode(item["quote_msg_b64"])
        ).hexdigest()
        for item in vectors
    }
    summary = {
        "lab": "native-state-transaction-overlay",
        "source_vectors": len(vectors),
        "fresh_roots": len(overlay["roots"]),
        "distinct_ak_public_keys": len(ak_hashes),
        "rsa_roots": sum(
            root["algorithm"] == "rsa" for root in overlay["roots"]
        ),
        "ecc_roots": sum(
            root["algorithm"] == "ecc" for root in overlay["roots"]
        ),
        "distinct_quote_messages": len(quote_hashes),
        "unique_challenges": len(
            {
                item["envelope"]["challenge"]
                for item in vectors
            }
        ),
        "state_class_counts": dict(sorted(class_counts.items())),
        "native_oracle_matches": sum(
            row["oracle_match"] for row in verdict_rows
        ),
        "mutation_cases": len(mutation_rows),
        "mutation_rejections": sum(
            row["rejected_as_expected"] for row in mutation_rows
        ),
        "composed_cases": len(composed_rows),
        "composed_exact_matches": sum(
            row["exact_match"] for row in composed_rows
        ),
        "all_passed": (
            len(vectors) == 104
            and len(overlay["roots"]) == 8
            and len(ak_hashes) == 8
            and len(quote_hashes) == 104
            and len(
                {item["envelope"]["challenge"] for item in vectors}
            )
            == 104
            and all(row["oracle_match"] for row in verdict_rows)
            and len(mutation_rows) == 64
            and all(
                row["rejected_as_expected"] for row in mutation_rows
            )
            and len(composed_rows) == 104
            and all(row["exact_match"] for row in composed_rows)
        ),
        "claim_boundary": overlay["claim_boundary"],
    }
    (RESULTS / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    (HERE / "SUMMARY.md").write_text(
        "# Native state overlay results\n\n"
        f"- Native state oracle matches: "
        f"**{summary['native_oracle_matches']}/104**\n"
        f"- State classes: **{summary['state_class_counts']}**\n"
        f"- Fresh roots / distinct AKs: "
        f"**{summary['fresh_roots']}/{summary['distinct_ak_public_keys']}** "
        f"(RSA {summary['rsa_roots']}, ECC {summary['ecc_roots']})\n"
        f"- Unique quote messages / challenges: "
        f"**{summary['distinct_quote_messages']}/"
        f"{summary['unique_challenges']}**\n"
        f"- Predeclared mutation rejections: "
        f"**{summary['mutation_rejections']}/{summary['mutation_cases']}**\n"
        f"- Exact recomposed decisions: "
        f"**{summary['composed_exact_matches']}/"
        f"{summary['composed_cases']}**\n"
        f"- Overall: **{'PASS' if summary['all_passed'] else 'FAIL'}**\n\n"
        f"Boundary: {summary['claim_boundary']}.\n",
        encoding="utf-8",
    )
    manifest_files = (
        HERE / "README.md",
        HERE / "native_state_adapter.py",
        HERE / "generate_vectors.py",
        HERE / "verify_overlay.py",
        HERE / "appraisal-policy.json",
        HERE / "native-state-overlay.json",
        HERE / "SUMMARY.md",
        RESULTS / "run-metadata.json",
        RESULTS / "verdicts.jsonl",
        RESULTS / "mutation-verdicts.jsonl",
        RESULTS / "composed-verdicts.jsonl",
        RESULTS / "summary.json",
    )
    (RESULTS / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"{path.relative_to(RESULTS)}\n"
            if path.is_relative_to(RESULTS)
            else f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
            f"../{path.relative_to(HERE)}\n"
            for path in manifest_files
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
