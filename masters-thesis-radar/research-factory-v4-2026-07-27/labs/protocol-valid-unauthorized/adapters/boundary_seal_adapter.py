#!/usr/bin/env python3
"""Join a recorded A2A boundary-seal result to an experimental mandate."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import sys

from datetime import datetime
from pathlib import Path
from typing import Any


ADAPTER_DIR = Path(__file__).resolve().parent
LAB_DIR = ADAPTER_DIR.parent
WORKSPACE_ROOT = ADAPTER_DIR.parents[4]
BOUNDARY_ROOT = WORKSPACE_ROOT / "a2a-boundary-seal"
SEND_MESSAGE_PATH = (
    BOUNDARY_ROOT / "results" / "extension-enabled" / "send-message.json"
)
AGENT_CARD_PATH = (
    BOUNDARY_ROOT / "results" / "extension-enabled" / "agent-card.json"
)
CASES_PATH = ADAPTER_DIR / "boundary-seal-cases.json"
RESULTS_DIR = LAB_DIR / "results-boundary-adapter"

def rel_to_results(path: Path) -> str:
    """Path relative to the results dir, so SHA256SUMS stays relocatable."""
    return Path(os.path.relpath(path, RESULTS_DIR)).as_posix()


EXTENSION_URI = "https://tyche.institute/a2a/extensions/boundary-seal/v1"
CAPSULE_URI_KEY = f"{EXTENSION_URI}/capsule-uri"
CAPSULE_SHA256_KEY = f"{EXTENSION_URI}/capsule-sha256"


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def parse_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def extract_recorded_evidence() -> tuple[str, dict[str, Any], list[str]]:
    errors: list[str] = []
    response = json.loads(SEND_MESSAGE_PATH.read_text(encoding="utf-8"))
    agent_card = json.loads(AGENT_CARD_PATH.read_text(encoding="utf-8"))
    task = response["result"]["task"]
    status = task["status"]
    status_message = status["message"]
    artifact = task["artifacts"][0]
    raw_part = artifact["parts"][0]
    capsule_bytes = base64.b64decode(raw_part["raw"], validate=True)
    capsule = json.loads(capsule_bytes)

    recomputed_capsule_digest = (
        "sha256:" + hashlib.sha256(canonical_json(capsule)).hexdigest()
    )
    cited_artifact_digest = artifact["metadata"][CAPSULE_SHA256_KEY]
    cited_status_digest = status_message["metadata"][CAPSULE_SHA256_KEY]
    if recomputed_capsule_digest != cited_artifact_digest:
        errors.append("capsule digest != artifact metadata")
    if recomputed_capsule_digest != cited_status_digest:
        errors.append("capsule digest != status-message metadata")
    if artifact["extensions"] != [EXTENSION_URI]:
        errors.append("unexpected artifact extension")
    if capsule["task_id"] != task["id"]:
        errors.append("capsule task_id mismatch")
    if capsule["context_id"] != task["contextId"]:
        errors.append("capsule context_id mismatch")
    if capsule["originating_message_id"] != task["history"][0]["messageId"]:
        errors.append("capsule originating_message_id mismatch")
    if capsule["terminal_state"] != status["state"]:
        errors.append("capsule terminal_state mismatch")

    output_text = status_message["parts"][0]["text"].encode("utf-8")
    effect_sha256 = hashlib.sha256(output_text).hexdigest()
    if capsule["effect"]["sha256"] != effect_sha256:
        errors.append("capsule effect digest mismatch")

    normalized = {
        "agent_name": agent_card["name"],
        "provider_organization": agent_card["provider"]["organization"],
        "task_id": task["id"],
        "context_id": task["contextId"],
        "originating_message_id": task["history"][0]["messageId"],
        "terminal_state": status["state"],
        "effect_sha256": effect_sha256,
        "observed_at": status["timestamp"],
        "capsule_sha256": recomputed_capsule_digest,
    }
    return ("VALID" if not errors else "INVALID"), normalized, errors


def native_authorization(mandate: dict[str, Any] | None) -> str:
    if mandate is None:
        return "ABSENT"
    return "VALID" if mandate.get("native_valid") is True else "INVALID"


def compose(
    mandate: dict[str, Any] | None,
    evidence_verdict: str,
    evidence: dict[str, Any],
) -> tuple[str, str]:
    if mandate is None:
        return "DENY", "authorization.present"
    if native_authorization(mandate) != "VALID":
        return "DENY", "native.authorization"
    if evidence_verdict != "VALID":
        return "DENY", "native.evidence"
    if (
        mandate["agent_name"] != evidence["agent_name"]
        or mandate["provider_organization"] != evidence["provider_organization"]
    ):
        return "DENY", "seam.agent"
    if mandate["task_id"] != evidence["task_id"]:
        return "DENY", "seam.task"
    if mandate["context_id"] != evidence["context_id"]:
        return "DENY", "seam.context"
    if mandate["originating_message_id"] != evidence["originating_message_id"]:
        return "DENY", "seam.origin"
    if mandate["terminal_state"] != evidence["terminal_state"]:
        return "DENY", "seam.terminal_state"
    if mandate["effect_sha256"] != evidence["effect_sha256"]:
        return "DENY", "seam.effect"
    observed_at = parse_time(evidence["observed_at"])
    if observed_at < parse_time(mandate["not_before"]):
        return "DENY", "seam.freshness"
    if observed_at >= parse_time(mandate["expires_at"]):
        return "DENY", "seam.freshness"
    return "ALLOW", "verified"


def main() -> int:
    config = json.loads(CASES_PATH.read_text(encoding="utf-8"))
    evidence_verdict, evidence, native_errors = extract_recorded_evidence()
    results = []
    for case in config["cases"]:
        mandate = (
            None
            if case["patch"] is None
            else {**copy.deepcopy(config["base_mandate"]), **case["patch"]}
        )
        a0 = native_authorization(mandate)
        c1, gate = compose(mandate, evidence_verdict, evidence)
        expected = case["expected"]
        matched = (
            a0 == expected["a0"]
            and evidence_verdict == expected["e0"]
            and c1 == expected["c1"]
            and gate == expected["gate"]
        )
        results.append(
            {
                "id": case["id"],
                "a0": a0,
                "e0": evidence_verdict,
                "c1": c1,
                "gate": gate,
                "expected": expected,
                "expected_match": matched,
            }
        )

    summary = {
        "profile": config["profile"],
        "source_send_message": rel_to_results(SEND_MESSAGE_PATH),
        "source_agent_card": rel_to_results(AGENT_CARD_PATH),
        "native_evidence_errors": native_errors,
        "cases": len(results),
        "expected_matches": sum(result["expected_match"] for result in results),
        "a0_valid_e0_valid_c1_deny": sum(
            result["a0"] == "VALID"
            and result["e0"] == "VALID"
            and result["c1"] == "DENY"
            for result in results
        ),
        "send_message_sha256": hashlib.sha256(
            SEND_MESSAGE_PATH.read_bytes()
        ).hexdigest(),
        "agent_card_sha256": hashlib.sha256(AGENT_CARD_PATH.read_bytes()).hexdigest(),
        "cases_sha256": hashlib.sha256(CASES_PATH.read_bytes()).hexdigest(),
        "adapter_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    RESULTS_DIR.mkdir(exist_ok=True)
    verdicts_path = RESULTS_DIR / "verdicts.jsonl"
    verdicts_path.write_text(
        "".join(json.dumps(result, sort_keys=True) + "\n" for result in results),
        encoding="utf-8",
    )
    summary_path = RESULTS_DIR / "summary.json"
    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (RESULTS_DIR / "SHA256SUMS").write_text(
        f"{hashlib.sha256(verdicts_path.read_bytes()).hexdigest()}  verdicts.jsonl\n"
        f"{hashlib.sha256(summary_path.read_bytes()).hexdigest()}  summary.json\n"
        f"{summary['send_message_sha256']}  {rel_to_results(SEND_MESSAGE_PATH)}\n"
        f"{summary['agent_card_sha256']}  {rel_to_results(AGENT_CARD_PATH)}\n"
        f"{summary['cases_sha256']}  ../adapters/boundary-seal-cases.json\n"
        f"{summary['adapter_sha256']}  ../adapters/boundary_seal_adapter.py\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return int(
        bool(native_errors)
        or summary["expected_matches"] != summary["cases"]
    )


if __name__ == "__main__":
    sys.exit(main())
