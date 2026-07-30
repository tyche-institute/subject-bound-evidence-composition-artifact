#!/usr/bin/env python3
"""Build deterministic signed fixtures for appraisal-to-commit revocation races."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


HERE = Path(__file__).resolve().parent


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def key(label: str) -> Ed25519PrivateKey:
    seed = hashlib.sha256(f"tyche-revocation-races-v1|{label}".encode()).digest()
    return Ed25519PrivateKey.from_private_bytes(seed)


AUTHORITY_KEY = key("credential-authority")
STATUS_KEY = key("status-authority")


def public_spki_b64(private_key: Ed25519PrivateKey) -> str:
    der = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode("ascii")


def sign(unsigned: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    item = copy.deepcopy(unsigned)
    signature = private_key.sign(canonical(item))
    item["signature_b64"] = base64.b64encode(signature).decode("ascii")
    return item


def credential(
    credential_id: str = "cred-primary",
    *,
    valid_from: int = 0,
    valid_until: int = 1_000,
) -> dict[str, Any]:
    return sign(
        {
            "profile": "tyche-signed-authority-credential-v0.2",
            "credential_id": credential_id,
            "issuer": "authority-root",
            "subject": "agent-alpha",
            "scope": {
                "operation": "ledger.read",
                "resource": "invoice-123",
            },
            "valid_from": valid_from,
            "valid_until": valid_until,
        },
        AUTHORITY_KEY,
    )


def snapshot(
    sequence: int,
    issued_at: int,
    states: dict[str, str],
) -> dict[str, Any]:
    return sign(
        {
            "profile": "tyche-signed-status-snapshot-v0.2",
            "issuer": "status-authority",
            "sequence": sequence,
            "issued_at": issued_at,
            "states": states,
        },
        STATUS_KEY,
    )


def tamper_signature(item: dict[str, Any]) -> dict[str, Any]:
    changed = copy.deepcopy(item)
    raw = bytearray(base64.b64decode(changed["signature_b64"]))
    raw[0] ^= 1
    changed["signature_b64"] = base64.b64encode(raw).decode("ascii")
    return changed


def case(
    case_id: str,
    description: str,
    *,
    authority_credential: dict[str, Any] | None = None,
    appraisal_time: int = 100,
    commit_time: int = 110,
    appraisal_snapshot: dict[str, Any] | None,
    commit_snapshot: dict[str, Any] | None,
    expected_verdict: str,
    expected_gate: str,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "description": description,
        "credential": authority_credential or credential(),
        "appraisal_time": appraisal_time,
        "commit_time": commit_time,
        "max_snapshot_age": 30,
        "appraisal_snapshot": appraisal_snapshot,
        "commit_snapshot": commit_snapshot,
        "expected": {
            "verdict": expected_verdict,
            "first_rejecting_gate": expected_gate,
        },
    }


active_10_95 = snapshot(10, 95, {"cred-primary": "active"})
active_11_108 = snapshot(11, 108, {"cred-primary": "active"})

cases = [
    case(
        "RR-001",
        "credential remains active through commit",
        appraisal_snapshot=active_10_95,
        commit_snapshot=active_11_108,
        expected_verdict="ALLOW",
        expected_gate="verified",
    ),
    case(
        "RR-002",
        "credential revoked before appraisal",
        appraisal_snapshot=snapshot(10, 95, {"cred-primary": "revoked"}),
        commit_snapshot=snapshot(11, 108, {"cred-primary": "revoked"}),
        expected_verdict="DENY",
        expected_gate="appraisal.status.active",
    ),
    case(
        "RR-003",
        "revocation occurs between appraisal and commit",
        appraisal_snapshot=active_10_95,
        commit_snapshot=snapshot(11, 105, {"cred-primary": "revoked"}),
        expected_verdict="DENY",
        expected_gate="commit.status.active",
    ),
    case(
        "RR-004",
        "revocation becomes effective exactly at commit",
        appraisal_snapshot=active_10_95,
        commit_snapshot=snapshot(11, 110, {"cred-primary": "revoked"}),
        expected_verdict="DENY",
        expected_gate="commit.status.active",
    ),
    case(
        "RR-005",
        "revocation occurs after the committed effect",
        appraisal_snapshot=active_10_95,
        commit_snapshot=active_11_108,
        expected_verdict="ALLOW",
        expected_gate="verified",
    )
    | {
        "post_commit_snapshot": snapshot(
            12, 111, {"cred-primary": "revoked"}
        )
    },
    case(
        "RR-006",
        "appraisal receives a correctly signed but stale snapshot",
        appraisal_snapshot=snapshot(10, 60, {"cred-primary": "active"}),
        commit_snapshot=active_11_108,
        expected_verdict="DENY",
        expected_gate="appraisal.status.freshness",
    ),
    case(
        "RR-007",
        "commit receives a correctly signed but stale snapshot",
        appraisal_snapshot=active_10_95,
        commit_snapshot=snapshot(11, 70, {"cred-primary": "active"}),
        expected_verdict="DENY",
        expected_gate="commit.status.freshness",
    ),
    case(
        "RR-008",
        "commit replays a lower status sequence with a newer timestamp",
        appraisal_snapshot=snapshot(20, 95, {"cred-primary": "active"}),
        commit_snapshot=snapshot(19, 108, {"cred-primary": "active"}),
        expected_verdict="DENY",
        expected_gate="commit.status.monotonic",
    ),
    case(
        "RR-009",
        "status snapshots are valid but omit the presented credential id",
        appraisal_snapshot=snapshot(10, 95, {"cred-other": "active"}),
        commit_snapshot=snapshot(11, 108, {"cred-other": "active"}),
        expected_verdict="DENY",
        expected_gate="appraisal.status.binding",
    ),
    case(
        "RR-010",
        "commit-time status service is unavailable",
        appraisal_snapshot=active_10_95,
        commit_snapshot=None,
        expected_verdict="DENY",
        expected_gate="commit.status.available",
    ),
    case(
        "RR-011",
        "new credential is active while predecessor remains revoked",
        authority_credential=credential("cred-reissued"),
        appraisal_snapshot=snapshot(
            30,
            95,
            {"cred-primary": "revoked", "cred-reissued": "active"},
        ),
        commit_snapshot=snapshot(
            31,
            108,
            {"cred-primary": "revoked", "cred-reissued": "active"},
        ),
        expected_verdict="ALLOW",
        expected_gate="verified",
    ),
    case(
        "RR-012",
        "credential validity ends at the commit instant",
        authority_credential=credential(valid_until=110),
        appraisal_snapshot=active_10_95,
        commit_snapshot=active_11_108,
        expected_verdict="DENY",
        expected_gate="credential.window",
    ),
    case(
        "RR-013",
        "commit snapshot signature is corrupted",
        appraisal_snapshot=active_10_95,
        commit_snapshot=tamper_signature(active_11_108),
        expected_verdict="DENY",
        expected_gate="commit.status.signature",
    ),
]

document = {
    "profile": "tyche-prospective-revocation-races-v1",
    "claim_boundary": (
        "Internal designed scheduled-event evidence with real Ed25519 "
        "verification; not a live race, external label, deployed-system "
        "validation, or standards-conformance result."
    ),
    "semantics": {
        "credential_window": "valid_from <= t < valid_until at appraisal and commit",
        "snapshot_freshness": "0 <= decision_time - issued_at <= max_snapshot_age",
        "sequence_rule": "commit.sequence >= appraisal.sequence",
        "revocation_boundary": "revoked at issued_at, inclusive",
    },
    "public_keys": {
        "credential_authority_spki_b64": public_spki_b64(AUTHORITY_KEY),
        "status_authority_spki_b64": public_spki_b64(STATUS_KEY),
    },
    "cases": cases,
}

out = HERE / "corpus.json"
out.write_text(
    json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
    encoding="utf-8",
)
print(
    json.dumps(
        {
            "cases": len(cases),
            "corpus_sha256": hashlib.sha256(out.read_bytes()).hexdigest(),
            "private_keys_persisted": False,
        },
        indent=2,
        sort_keys=True,
    )
)
