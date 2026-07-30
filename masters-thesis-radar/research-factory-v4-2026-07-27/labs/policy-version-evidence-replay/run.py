#!/usr/bin/env python3
"""Verify the signed policy/evidence corpus and compare fail-open baselines.

v2 (2026-07-27): the corpus adds four gate-isolation vectors (review items
C-16/E5), so the version, freshness, digest and policy-signature gates are
each exercised in isolation. All expected labels are author-written."""

from __future__ import annotations

import base64
import hashlib
import json
import platform
import sys
from pathlib import Path
from typing import Any

import cryptography
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
RESULTS = ROOT / "results"
VERDICTS_PATH = RESULTS / "verdicts.jsonl"
SUMMARY_PATH = RESULTS / "summary.json"
METADATA_PATH = RESULTS / "run-metadata.json"
CHECKSUMS_PATH = RESULTS / "SHA256SUMS"


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def unsigned(value: dict[str, Any]) -> dict[str, Any]:
    return {key: item for key, item in value.items() if key != "signature"}


def object_digest(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(unsigned(value))).hexdigest()


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signature_valid(public_key: Ed25519PublicKey, value: dict[str, Any]) -> bool:
    try:
        public_key.verify(
            base64.b64decode(value["signature"]),
            canonical_bytes(unsigned(value)),
        )
        return True
    except (InvalidSignature, KeyError, ValueError):
        return False


def evaluate_policy(
    public_key: Ed25519PublicKey,
    policy: dict[str, Any] | None,
    anchor: dict[str, Any],
    decision_time: str,
) -> tuple[str, str, dict[str, Any]]:
    if policy is None:
        return "MISSING", "policy.missing", {"present": False}
    sig_ok = signature_valid(public_key, policy)
    details = {
        "present": True,
        "signature_valid": sig_ok,
        "policy_id": policy.get("policy_id"),
        "version": policy.get("version"),
        "digest": object_digest(policy),
    }
    if not sig_ok:
        return "INVALID_SIGNATURE", "policy.signature", details
    if policy.get("policy_id") != anchor["required_policy_id"]:
        return "SUBSTITUTED", "policy.substituted", details
    if (
        policy.get("version") != anchor["required_policy_version"]
        or not (
            policy.get("valid_from", "") <= decision_time <= policy.get("valid_until", "")
        )
    ):
        return "STALE", "policy.stale", details
    if object_digest(policy) != anchor["required_policy_digest"]:
        return "SUBSTITUTED", "policy.substituted", details
    return "PASS", "policy.verified", details


def evaluate_evidence(
    public_key: Ed25519PublicKey,
    evidence: dict[str, Any],
    preseen_nonces: set[str],
) -> tuple[str, str, dict[str, Any]]:
    sig_ok = signature_valid(public_key, evidence)
    details = {
        "signature_valid": sig_ok,
        "nonce": evidence.get("nonce"),
        "effect": evidence.get("effect"),
        "digest": object_digest(evidence),
    }
    if not sig_ok:
        return "TAMPERED", "evidence.integrity", details
    if evidence.get("nonce") in preseen_nonces:
        return "REPLAY", "evidence.replay", details
    return "PASS", "evidence.verified", details


def baseline_verdicts(
    public_key: Ed25519PublicKey,
    policy: dict[str, Any] | None,
    evidence_result: str,
) -> dict[str, str]:
    policy_present_and_signed = (
        policy is not None and signature_valid(public_key, policy)
    )
    evidence_pass = evidence_result == "PASS"
    return {
        "presence_only": (
            "ALLOW" if policy_present_and_signed and evidence_pass else "DENY"
        ),
        "fail_open": (
            "ALLOW"
            if (policy is None or policy_present_and_signed) and evidence_pass
            else "DENY"
        ),
    }


def evaluate_vector(
    vector: dict[str, Any],
    corpus: dict[str, Any],
) -> dict[str, Any]:
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(corpus["public_key_raw_b64"])
    )
    policy_result, policy_gate, policy_details = evaluate_policy(
        public_key,
        vector["policy"],
        corpus["policy_anchor"],
        corpus["decision_time"],
    )
    evidence_result, evidence_gate, evidence_details = evaluate_evidence(
        public_key,
        vector["evidence"],
        set(corpus["preseen_nonces"]),
    )
    verdict = (
        "ALLOW"
        if policy_result == "PASS" and evidence_result == "PASS"
        else "DENY"
    )
    first_gate = (
        "verified"
        if verdict == "ALLOW"
        else policy_gate if policy_result != "PASS" else evidence_gate
    )
    baselines = baseline_verdicts(
        public_key, vector["policy"], evidence_result
    )
    expected = vector["expected"]
    expected_match = (
        policy_result == expected["policy_result"]
        and evidence_result == expected["evidence_result"]
        and verdict == expected["verdict"]
        and first_gate == expected["first_rejecting_gate"]
    )
    return {
        "id": vector["id"],
        "declared_policy_state": vector["policy_state"],
        "declared_evidence_state": vector["evidence_state"],
        "isolated_gate": vector.get("isolated_gate"),
        "policy_result": policy_result,
        "evidence_result": evidence_result,
        "verdict": verdict,
        "first_rejecting_gate": first_gate,
        "policy_details": policy_details,
        "evidence_details": evidence_details,
        "baselines": baselines,
        "expected": expected,
        "expected_match": expected_match,
    }


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    results = [evaluate_vector(vector, corpus) for vector in corpus["vectors"]]
    strict_expected_matches = sum(item["expected_match"] for item in results)
    baseline_false_allows = {
        name: sum(
            item["baselines"][name] == "ALLOW"
            and item["expected"]["verdict"] == "DENY"
            for item in results
        )
        for name in ("presence_only", "fail_open")
    }
    baseline_expected_matches = {
        name: sum(
            item["baselines"][name] == item["expected"]["verdict"]
            for item in results
        )
        for name in ("presence_only", "fail_open")
    }
    gate_isolation_ids = [
        vector["id"] for vector in corpus["vectors"] if "isolated_gate" in vector
    ]
    summary = {
        "profile": corpus["profile"],
        "vectors": len(results),
        "families": {
            "factorial_4x3": len(results) - len(gate_isolation_ids),
            "gate_isolation": len(gate_isolation_ids),
        },
        "gate_isolation_ids": gate_isolation_ids,
        "strict_expected_matches": strict_expected_matches,
        "strict_allows": sum(item["verdict"] == "ALLOW" for item in results),
        "strict_denies": sum(item["verdict"] == "DENY" for item in results),
        "policy_result_counts": {
            state: sum(item["policy_result"] == state for item in results)
            for state in (
                "PASS",
                "MISSING",
                "STALE",
                "SUBSTITUTED",
                "INVALID_SIGNATURE",
            )
        },
        "evidence_result_counts": {
            state: sum(item["evidence_result"] == state for item in results)
            for state in ("PASS", "TAMPERED", "REPLAY")
        },
        "baseline_expected_matches": baseline_expected_matches,
        "baseline_false_allows": baseline_false_allows,
        "corpus_sha256": sha256_file(CORPUS_PATH),
        "runner_sha256": sha256_file(Path(__file__)),
        "disclaimers": [
            "All expected labels are author-written programme-internal "
            "expectations; agreement measures reproduction of those "
            "expectations, not external ground truth.",
            "False-allow counts are counts on a designed corpus; they are "
            "not rates and do not estimate prevalence in any deployed "
            "system.",
            "Structural appraisal of signed test objects is not "
            "cryptographic attestation of any runtime.",
            "The SQL oracle in results-sql-oracle recomposes layer results "
            "produced by this evaluator; it is a second composition code "
            "path, not independent validation.",
        ],
    }
    metadata = {
        "python": sys.version,
        "platform": platform.platform(),
        "cryptography": cryptography.__version__,
        "argv": sys.argv,
        "network_used": False,
    }

    RESULTS.mkdir(exist_ok=True)
    VERDICTS_PATH.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in results),
        encoding="utf-8",
    )
    SUMMARY_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    METADATA_PATH.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    CHECKSUMS_PATH.write_text(
        "\n".join(
            [
                f"{sha256_file(VERDICTS_PATH)}  verdicts.jsonl",
                f"{sha256_file(SUMMARY_PATH)}  summary.json",
                f"{sha256_file(METADATA_PATH)}  run-metadata.json",
                f"{sha256_file(CORPUS_PATH)}  ../corpus.json",
                f"{sha256_file(Path(__file__))}  ../run.py",
                f"{sha256_file(ROOT / 'build_corpus.py')}  ../build_corpus.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if strict_expected_matches == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
