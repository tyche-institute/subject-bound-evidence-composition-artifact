#!/usr/bin/env python3
"""Exercise a native TPM quote gate over a frozen software-TPM vector."""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
VECTOR = HERE / "frozen-vector.json"
CASES = HERE / "cases.json"
RESULTS = HERE / "results.json"
SUMMARY = HERE / "SUMMARY.md"
MANIFEST = HERE / "SHA256SUMS"
EXPECTED_CASES_SHA256 = (
    "17b1bc8a5139e641d22a9a7c71992917ee6560ab3125849717741f2b2d09e758"
)


def derive(vector: dict[str, Any]) -> tuple[str, str, str]:
    outcome = vector["outcome_digest"]
    if not outcome.startswith("sha256:"):
        raise ValueError("outcome digest lacks sha256 prefix")
    outcome_hex = outcome.split(":", 1)[1]
    if len(outcome_hex) != 64:
        raise ValueError("outcome digest is not 32 bytes")
    bytes.fromhex(outcome_hex)
    transcript = (
        "tyche.aep.qual.v1"
        f"|capsule={vector['capsule_id']}"
        f"|outcome=sha256:{outcome_hex}"
        f"|nonce={vector['verifier_challenge']}"
    )
    qual = hashlib.sha256(transcript.encode("utf-8")).hexdigest()
    pcr = hashlib.sha256(bytes(32) + bytes.fromhex(outcome_hex)).hexdigest()
    return qual, pcr, transcript


def flip(value: bytes, offset: int = -1) -> bytes:
    mutated = bytearray(value)
    mutated[offset] ^= 0x01
    return bytes(mutated)


def appraise(vector: dict[str, Any], mutation: str) -> dict[str, Any]:
    qual, derived_pcr, transcript = derive(vector)
    qualifying_option_hex = qual.encode("utf-8").hex()
    if derived_pcr != vector["pcr_value"]:
        return {
            "accepted": False,
            "gate": "MEASUREMENT_BINDING",
            "native_rc": None,
            "derived_qualifying_data": qual,
            "qualifying_data_preimage": transcript,
            "tpm2_checkquote_q_hex": qualifying_option_hex,
            "derived_pcr": derived_pcr,
        }

    blobs = {
        "ak.pub": base64.b64decode(vector["ak_pub_b64"], validate=True),
        "quote.msg": base64.b64decode(
            vector["quote_msg_b64"], validate=True
        ),
        "quote.sig": base64.b64decode(
            vector["quote_sig_b64"], validate=True
        ),
        "pcr.bin": base64.b64decode(
            "".join(vector["pcr_bin_b64_chunks"]), validate=True
        ),
    }
    if mutation == "quote-message":
        blobs["quote.msg"] = flip(blobs["quote.msg"])
    elif mutation == "quote-signature":
        blobs["quote.sig"] = flip(blobs["quote.sig"])

    with tempfile.TemporaryDirectory(prefix="tyche-native-attest-") as name:
        temporary = Path(name)
        for filename, value in blobs.items():
            (temporary / filename).write_bytes(value)
        command = [
            shutil.which("tpm2_checkquote") or "tpm2_checkquote",
            "-u",
            str(temporary / "ak.pub"),
            "-m",
            str(temporary / "quote.msg"),
            "-s",
            str(temporary / "quote.sig"),
            "-q",
            qualifying_option_hex,
            "-g",
            "sha256",
            "-f",
            str(temporary / "pcr.bin"),
        ]
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
        )
    return {
        "accepted": completed.returncode == 0,
        "gate": (
            "PASS"
            if completed.returncode == 0
            else "NATIVE_ATTESTATION_REJECTED"
        ),
        "native_rc": completed.returncode,
        "derived_qualifying_data": qual,
        "qualifying_data_preimage": transcript,
        "tpm2_checkquote_q_hex": qualifying_option_hex,
        "derived_pcr": derived_pcr,
        "native_stdout_sha256": hashlib.sha256(
            completed.stdout.encode("utf-8")
        ).hexdigest(),
        "native_stderr_sha256": hashlib.sha256(
            completed.stderr.encode("utf-8")
        ).hexdigest(),
    }


def load_cases(source: dict[str, Any]) -> list[dict[str, Any]]:
    observed = hashlib.sha256(CASES.read_bytes()).hexdigest()
    if observed != EXPECTED_CASES_SHA256:
        raise RuntimeError(
            f"case/oracle drift: expected {EXPECTED_CASES_SHA256}, "
            f"observed {observed}"
        )
    specification = json.loads(CASES.read_text(encoding="utf-8"))
    scenarios: list[dict[str, Any]] = []
    for item in specification["cases"]:
        vector = copy.deepcopy(source)
        change = item["change"]
        if change is not None:
            vector[change["field"]] = change["value"]
        scenarios.append({**item, "vector": vector})
    return scenarios


def main() -> int:
    if shutil.which("tpm2_checkquote") is None:
        raise SystemExit("tpm2_checkquote is required")
    source = json.loads(VECTOR.read_text(encoding="utf-8"))
    source_qual, source_pcr, _ = derive(source)
    if source_qual != source["qualifying_data"]:
        raise RuntimeError("frozen qualifying-data fixture mismatch")
    if source_pcr != source["pcr_value"]:
        raise RuntimeError("frozen PCR fixture mismatch")

    rows: list[dict[str, Any]] = []
    for scenario in load_cases(source):
        result = appraise(scenario["vector"], scenario["mutation"])
        row = {
            key: value
            for key, value in scenario.items()
            if key not in {"vector", "mutation", "change"}
        }
        row.update(result)
        row["oracle_match"] = (
            row["accepted"] == row["expected_accept"]
            and row["gate"] == row["expected_gate"]
        )
        rows.append(row)

    exact = sum(row["oracle_match"] for row in rows)
    rejected_negatives = sum(
        not row["accepted"] for row in rows if not row["expected_accept"]
    )
    native_rejections = sum(
        row["gate"] == "NATIVE_ATTESTATION_REJECTED" for row in rows
    )
    binding_rejections = sum(
        row["gate"] == "MEASUREMENT_BINDING" for row in rows
    )
    output = {
        "lab": "native-runtime-attestation",
        "source_commit": source["source"]["commit"],
        "source_kind": source["source"]["claim_boundary"],
        "runtime": {
            "tpm2_checkquote": shutil.which("tpm2_checkquote"),
            "tool_version": subprocess.run(
                ["tpm2_checkquote", "--version"],
                check=False,
                capture_output=True,
                text=True,
            ).stdout.strip(),
        },
        "cases": len(rows),
        "exact_oracle_matches": exact,
        "negative_cases_rejected": rejected_negatives,
        "native_negative_rejections": native_rejections,
        "binding_precheck_rejections": binding_rejections,
        "case_oracle_sha256": EXPECTED_CASES_SHA256,
        "all_passed": exact == len(rows) and rejected_negatives == 6,
        "claim_boundary": (
            "native offline appraisal of one frozen software-TPM vector; "
            "not hardware-rooted and not an independent-host replication"
        ),
        "results": rows,
    }
    RESULTS.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    SUMMARY.write_text(
        "# Native runtime-attestation results\n\n"
        f"- Cases: **{len(rows)}**\n"
        f"- Exact predeclared-oracle matches: **{exact}/{len(rows)}**\n"
        f"- Targeted negatives rejected: **{rejected_negatives}/6**\n"
        f"- Native TPM rejections: **{native_rejections}/4**; binding "
        f"precheck rejections: **{binding_rejections}/2**\n"
        f"- Native verifier: **{output['runtime']['tool_version']}**\n"
        "- Boundary: frozen software-TPM vector; no hardware or independent-"
        "host claim.\n",
        encoding="utf-8",
    )
    manifest_names = (
        "README.md",
        "LICENSE.source",
        "frozen-vector.json",
        "cases.json",
        "verify_runtime_attestation.py",
        "results.json",
        "SUMMARY.md",
    )
    MANIFEST.write_text(
        "".join(
            f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  "
            f"{name}\n"
            for name in manifest_names
        ),
        encoding="utf-8",
    )
    print(json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if output["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
