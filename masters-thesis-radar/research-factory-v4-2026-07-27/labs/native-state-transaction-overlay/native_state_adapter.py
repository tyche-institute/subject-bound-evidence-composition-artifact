#!/usr/bin/env python3
"""Native offline appraisal for the transaction-bound TPM state overlay."""

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


DOMAIN = "tyche.state.qual.v1"
PCR_INDEX = 16


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def capsule_id(
    source_corpus_sha256: str,
    transaction_id: str,
    canonical_action: dict[str, Any],
    observed_effect: dict[str, Any],
) -> str:
    return sha256_hex(
        canonical(
            {
                "source_corpus_sha256": source_corpus_sha256,
                "transaction_id": transaction_id,
                "canonical_action": canonical_action,
                "observed_effect": observed_effect,
            }
        )
    )


def derived_measurement(transaction_id: str, source_digest: str) -> str:
    """Domain-separate repeated corpus fixture digests by transaction."""
    return "sha256:" + sha256_hex(
        canonical(
            {
                "domain": "tyche.state.measurement.v1",
                "transaction_id": transaction_id,
                "source_digest": source_digest,
            }
        )
    )


def expected_pcr(measurement: str) -> str:
    prefix, digest = measurement.split(":", 1)
    if prefix != "sha256" or len(digest) != 64:
        raise ValueError("measurement must be sha256:<64 lowercase hex>")
    return sha256_hex(bytes(32) + bytes.fromhex(digest))


def transcript(envelope: dict[str, Any]) -> str:
    return (
        f"{DOMAIN}"
        f"|corpus={envelope['source_corpus_sha256']}"
        f"|transaction={envelope['transaction_id']}"
        f"|capsule={envelope['capsule_id']}"
        f"|measurement={envelope['observed_measurement']}"
        f"|issued={envelope['issued_at']}"
        f"|expires={envelope['expires_at']}"
        f"|challenge={envelope['challenge']}"
    )


def qualifying_digest(envelope: dict[str, Any]) -> str:
    return sha256_hex(transcript(envelope).encode("utf-8"))


def q_option_hex(envelope: dict[str, Any]) -> str:
    # The profile binds the lowercase hexadecimal digest as 64 UTF-8 bytes.
    return qualifying_digest(envelope).encode("ascii").hex()


def flip_b64(value: str, offset: int = -1) -> str:
    raw = bytearray(base64.b64decode(value, validate=True))
    raw[offset] ^= 0x01
    return base64.b64encode(bytes(raw)).decode("ascii")


def mutate_evidence(
    evidence: dict[str, Any],
    mutation: str,
    alternate: dict[str, Any],
) -> dict[str, Any]:
    candidate = copy.deepcopy(evidence)
    envelope = candidate["envelope"]
    if mutation == "quote_message_flip":
        candidate["quote_msg_b64"] = flip_b64(candidate["quote_msg_b64"])
    elif mutation == "signature_flip":
        candidate["quote_sig_b64"] = flip_b64(candidate["quote_sig_b64"])
    elif mutation == "pcr_blob_flip":
        raw = bytearray(
            base64.b64decode(candidate["pcr_bin_b64"], validate=True)
        )
        needle = bytes.fromhex(
            expected_pcr(envelope["observed_measurement"])
        )
        offset = raw.find(needle)
        if offset < 0:
            raise ValueError("quoted PCR value not found in PCR blob")
        raw[offset] ^= 0x01
        candidate["pcr_bin_b64"] = base64.b64encode(bytes(raw)).decode(
            "ascii"
        )
    elif mutation == "challenge_replay":
        envelope["challenge"] = alternate["envelope"]["challenge"]
    elif mutation == "transaction_substitution":
        envelope["transaction_id"] = alternate["envelope"]["transaction_id"]
    elif mutation == "corpus_hash_substitution":
        envelope["source_corpus_sha256"] = "0" * 64
    elif mutation == "measurement_substitution":
        envelope["observed_measurement"] = (
            alternate["envelope"]["observed_measurement"]
        )
    elif mutation == "window_substitution":
        envelope["expires_at"] = "2099-01-01T00:00:00Z"
    else:
        raise ValueError(f"unknown mutation: {mutation}")
    return candidate


def appraise(
    evidence: dict[str, Any],
    policy: dict[str, Any],
) -> dict[str, Any]:
    envelope = evidence["envelope"]
    transaction_id = envelope.get("transaction_id")
    reasons: list[str] = []

    if envelope.get("source_corpus_sha256") != policy["source_corpus_sha256"]:
        reasons.append("source_corpus_binding")
    expected_challenge = policy["expected_challenges"].get(transaction_id)
    if expected_challenge != envelope.get("challenge"):
        reasons.append("challenge_binding")
    expected_capsule = policy["capsule_ids"].get(transaction_id)
    if expected_capsule != envelope.get("capsule_id"):
        reasons.append("transaction_subject_binding")

    native_rc: int | None = None
    native_stdout = ""
    native_stderr = ""
    pcr_match = False
    try:
        blobs = {
            "ak.pub": base64.b64decode(
                evidence["ak_pub_b64"], validate=True
            ),
            "quote.msg": base64.b64decode(
                evidence["quote_msg_b64"], validate=True
            ),
            "quote.sig": base64.b64decode(
                evidence["quote_sig_b64"], validate=True
            ),
            "pcr.bin": base64.b64decode(
                evidence["pcr_bin_b64"], validate=True
            ),
        }
        with tempfile.TemporaryDirectory(prefix="tyche-state-check-") as name:
            directory = Path(name)
            for filename, value in blobs.items():
                (directory / filename).write_bytes(value)
            completed = subprocess.run(
                [
                    shutil.which("tpm2_checkquote") or "tpm2_checkquote",
                    "-u",
                    str(directory / "ak.pub"),
                    "-m",
                    str(directory / "quote.msg"),
                    "-s",
                    str(directory / "quote.sig"),
                    "-q",
                    q_option_hex(envelope),
                    "-g",
                    "sha256",
                    "-f",
                    str(directory / "pcr.bin"),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=20,
            )
        native_rc = completed.returncode
        native_stdout = completed.stdout
        native_stderr = completed.stderr
        expected = expected_pcr(envelope["observed_measurement"])
        pcr_match = expected.lower() in native_stdout.lower()
        if native_rc != 0:
            reasons.append("native_quote")
        if not pcr_match:
            reasons.append("pcr_measurement_binding")
    except (KeyError, ValueError, TypeError, subprocess.TimeoutExpired) as exc:
        reasons.append(f"malformed_native_evidence:{type(exc).__name__}")

    if reasons:
        result = "CRYPTOGRAPHIC_FAILURE"
        gate = "state.native_evidence"
    elif envelope["observed_measurement"] in policy["denied_measurements"]:
        result = "CONTRAINDICATED"
        gate = "state.contraindicated"
    elif not (
        envelope["issued_at"]
        <= policy["decision_time"]
        <= envelope["expires_at"]
    ):
        result = "STALE"
        gate = "state.stale"
    elif (
        envelope["observed_measurement"]
        != policy["reference_measurements"][transaction_id]
    ):
        result = "REFERENCE_MISMATCH"
        gate = "state.reference"
    else:
        result = "PASS"
        gate = "state.verified"

    return {
        "result": result,
        "gate": gate,
        "native_rc": native_rc,
        "pcr_match": pcr_match,
        "failures": reasons,
        "native_stdout_sha256": sha256_hex(native_stdout.encode("utf-8")),
        "native_stderr_sha256": sha256_hex(native_stderr.encode("utf-8")),
        "qualifying_data": qualifying_digest(envelope),
        "qualifying_data_preimage": transcript(envelope),
    }
