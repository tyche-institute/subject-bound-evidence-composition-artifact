#!/usr/bin/env python3
"""Build a deterministic signed policy/evidence replay corpus.

v2 (2026-07-27): 4x3 factorial (12 vectors, unchanged from v1) plus four
gate-isolation vectors added per review items C-16 / E5, each carrying GOOD
evidence and failing exactly one strict-verifier policy gate:
version-only, freshness-only, digest-only, invalid-policy-signature.
All expected labels are author-written."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "corpus.json"
DECISION_TIME = "2026-07-25T21:30:00Z"
# The key-derivation string deliberately keeps the v1 lab name so that the
# twelve original factorial vectors remain byte-identical to the v1 corpus.
SEED = hashlib.sha256(b"tyche-policy-state-replay-test-key-v1").digest()


def canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def digest_object(value: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def sign_object(private_key: Ed25519PrivateKey, payload: dict[str, Any]) -> dict[str, Any]:
    signed = json.loads(json.dumps(payload))
    signed["signature"] = base64.b64encode(
        private_key.sign(canonical_bytes(payload))
    ).decode("ascii")
    return signed


def policy_payload(state: str) -> dict[str, Any] | None:
    common = {
        "profile": "tyche-policy-snapshot-v1",
        "issuer": "tyche-test-policy-authority",
        "valid_from": "2026-07-25T00:00:00Z",
        "evidence_profile": "tyche-signed-effect-v1",
        "required_effect": "ledger.read",
        "required_measurement_profile": "safe-profile-main-v1",
    }
    if state == "missing":
        return None
    if state == "correct":
        return {
            **common,
            "policy_id": "policy-main",
            "version": 2,
            "valid_until": "2026-07-26T00:00:00Z",
        }
    if state == "stale":
        return {
            **common,
            "policy_id": "policy-main",
            "version": 1,
            "valid_until": "2026-07-25T20:00:00Z",
        }
    if state == "substituted":
        return {
            **common,
            "policy_id": "policy-other",
            "version": 2,
            "valid_until": "2026-07-26T00:00:00Z",
            "required_effect": "ledger.export",
        }
    raise ValueError(state)


def isolation_policy_payload(kind: str) -> dict[str, Any]:
    """Signed-policy payloads that each fail exactly one strict-verifier gate.

    Every payload starts from the correct policy and changes one field:
    - version_only:   version 1 (wrong), validity interval ACTIVE;
    - freshness_only: version 2 (right), validity interval EXPIRED;
    - digest_only:    identity, version and interval all match the anchor,
      one semantic field differs, so only the digest comparison can reject.
    """
    base = policy_payload("correct")
    assert base is not None
    if kind == "version_only":
        return {**base, "version": 1}
    if kind == "freshness_only":
        return {**base, "valid_until": "2026-07-25T20:00:00Z"}
    if kind == "digest_only":
        return {**base, "required_measurement_profile": "safe-profile-alt-v1"}
    raise ValueError(kind)


# (kind, expected_policy_result, expected_first_rejecting_gate, isolated_gate)
GATE_ISOLATION: list[tuple[str, str, str, str]] = [
    ("version_only", "STALE", "policy.stale", "policy.version"),
    ("freshness_only", "STALE", "policy.stale", "policy.freshness"),
    ("digest_only", "SUBSTITUTED", "policy.substituted", "policy.digest"),
    ("policy_sig_invalid", "INVALID_SIGNATURE", "policy.signature", "policy.signature"),
]


def evidence_payload(policy_state: str, evidence_state: str) -> dict[str, Any]:
    nonce = (
        f"nonce-preseen-{policy_state}"
        if evidence_state == "replayed"
        else f"nonce-{policy_state}-{evidence_state}"
    )
    return {
        "profile": "tyche-signed-effect-v1",
        "issuer": "tyche-test-evidence-producer",
        "transaction_id": f"psr-{policy_state}-{evidence_state}",
        "effect": "ledger.read",
        "resource": "invoice-123",
        "issued_at": "2026-07-25T21:29:30Z",
        "nonce": nonce,
        "payload_digest": "sha256:"
        + hashlib.sha256(
            f"psr-{policy_state}-{evidence_state}|ledger.read|invoice-123".encode()
        ).hexdigest(),
    }


def main() -> int:
    private_key = Ed25519PrivateKey.from_private_bytes(SEED)
    public_key = private_key.public_key()
    public_raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    correct_unsigned = policy_payload("correct")
    assert correct_unsigned is not None
    correct_digest = digest_object(correct_unsigned)

    signed_policies: dict[str, dict[str, Any] | None] = {}
    for state in ("correct", "missing", "stale", "substituted"):
        payload = policy_payload(state)
        signed_policies[state] = (
            None if payload is None else sign_object(private_key, payload)
        )

    vectors: list[dict[str, Any]] = []
    for policy_state in ("correct", "missing", "stale", "substituted"):
        for evidence_state in ("good", "tampered", "replayed"):
            unsigned_evidence = evidence_payload(policy_state, evidence_state)
            evidence = sign_object(private_key, unsigned_evidence)
            if evidence_state == "tampered":
                evidence["effect"] = "ledger.export"

            expected_policy = {
                "correct": "PASS",
                "missing": "MISSING",
                "stale": "STALE",
                "substituted": "SUBSTITUTED",
            }[policy_state]
            expected_evidence = {
                "good": "PASS",
                "tampered": "TAMPERED",
                "replayed": "REPLAY",
            }[evidence_state]
            expected_final = (
                "ALLOW"
                if expected_policy == "PASS" and expected_evidence == "PASS"
                else "DENY"
            )
            expected_first_gate = (
                "verified"
                if expected_final == "ALLOW"
                else (
                    {
                        "MISSING": "policy.missing",
                        "STALE": "policy.stale",
                        "SUBSTITUTED": "policy.substituted",
                    }[expected_policy]
                    if expected_policy != "PASS"
                    else {
                        "TAMPERED": "evidence.integrity",
                        "REPLAY": "evidence.replay",
                    }[expected_evidence]
                )
            )
            vectors.append(
                {
                    "id": f"PSR_{policy_state}_{evidence_state}",
                    "policy_state": policy_state,
                    "evidence_state": evidence_state,
                    "policy": signed_policies[policy_state],
                    "evidence": evidence,
                    "expected": {
                        "policy_result": expected_policy,
                        "evidence_result": expected_evidence,
                        "verdict": expected_final,
                        "first_rejecting_gate": expected_first_gate,
                    },
                }
            )

    for kind, expected_policy, expected_gate, isolated_gate in GATE_ISOLATION:
        if kind == "policy_sig_invalid":
            # The correct policy object, tampered AFTER signing: the stored
            # signature covers the original bytes, so verification must fail.
            policy_obj = sign_object(private_key, correct_unsigned)
            policy_obj["required_effect"] = "ledger.write"
        else:
            policy_obj = sign_object(private_key, isolation_policy_payload(kind))
        evidence = sign_object(private_key, evidence_payload(kind, "good"))
        vectors.append(
            {
                "id": f"PSR_{kind}_good",
                "policy_state": kind,
                "evidence_state": "good",
                "isolated_gate": isolated_gate,
                "policy": policy_obj,
                "evidence": evidence,
                "expected": {
                    "policy_result": expected_policy,
                    "evidence_result": "PASS",
                    "verdict": "DENY",
                    "first_rejecting_gate": expected_gate,
                },
            }
        )

    corpus = {
        "profile": "tyche-policy-version-evidence-replay-v2",
        "decision_time": DECISION_TIME,
        "public_key_raw_b64": base64.b64encode(public_raw).decode("ascii"),
        "policy_anchor": {
            "required_policy_id": "policy-main",
            "required_policy_version": 2,
            "required_policy_digest": correct_digest,
        },
        "preseen_nonces": [
            f"nonce-preseen-{state}"
            for state in ("correct", "missing", "stale", "substituted")
        ],
        "vectors": vectors,
        "external_labels": False,
        "label_provenance": (
            "All expected labels are author-written programme-internal "
            "expectations, not external ground truth."
        ),
        "generation": {
            "key_derivation": "sha256('tyche-policy-state-replay-test-key-v1')",
            "key_derivation_note": (
                "v1 derivation string retained so the 12 factorial vectors "
                "remain byte-identical to the v1 corpus"
            ),
            "test_key_only": True,
            "policy_states": ["correct", "missing", "stale", "substituted"],
            "evidence_states": ["good", "tampered", "replayed"],
            "gate_isolation_vectors": [
                f"PSR_{kind}_good" for kind, _, _, _ in GATE_ISOLATION
            ],
            "gate_isolation_note": (
                "Added in v2 per review items C-16/E5: each vector carries "
                "good evidence and fails exactly one policy gate (version, "
                "freshness, digest, signature), closing the fused-STALE and "
                "dead digest/INVALID_SIGNATURE branches of the v1 corpus."
            ),
        },
    }
    CORPUS_PATH.write_text(
        json.dumps(corpus, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(f"wrote={CORPUS_PATH}")
    print(f"vectors={len(vectors)}")
    print(f"corpus_sha256={hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
