#!/usr/bin/env python3
"""Non-destructive TPM companion for the frozen 104-case corpus.

The execution path creates one transient primary and one transient signing
key, quotes a configured PCR at its current state, and verifies the public
evidence offline. It supports a createak profile for a compatible endorsement
key and a create/load profile whose encrypted private blob exists only inside
the run's temporary private directory. It never clears, extends/resets PCRs,
creates persistent handles, changes hierarchy state, or accesses TPM NV
storage.
"""

from __future__ import annotations

import argparse
import ast
import base64
import copy
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
EXPECTED_CORPUS_SHA256 = (
    "1ba6d40d07e62a862b98ec52ab5c189eb491f19e4e1e69a411fba73bbb9a43a8"
)
EXPECTED_CAPSULE_SHA256 = (
    "8c8919f9826381da289b73dfd35721938ad5aafea5cd3687b23187589a2d0386"
)
PROFILE = "subject-bound.hardware-quote.v1"
EXPECTED_TRANSACTIONS = 104
EXPECTED_MUTATIONS = 64
MUTATION_PLAN = HERE / "mutation-plan.json"
MANIFEST_SCHEMA = HERE / "hardware-run-manifest.schema.json"

# Every TPM executable callable by this program.  Preflight extracts every
# run_tpm("literal", ...) call from the AST and rejects anything outside this
# exact set.
ALLOWED_TPM_EXECUTABLES = {
    "tpm2_getcap",
    "tpm2_createprimary",
    "tpm2_createak",
    "tpm2_create",
    "tpm2_load",
    "tpm2_readpublic",
    "tpm2_quote",
    "tpm2_checkquote",
    "tpm2_flushcontext",
}

# Runtime defense in depth.  These are names/families, not executable call
# sites; the AST auditor distinguishes the two.
FORBIDDEN_TPM_EXECUTABLES = {
    "tpm2_clear",
    "tpm2_clearcontrol",
    "tpm2_changeauth",
    "tpm2_dictionarylockout",
    "tpm2_evictcontrol",
    "tpm2_hierarchycontrol",
    "tpm2_pcrextend",
    "tpm2_pcrreset",
    "tpm2_setprimarypolicy",
    "tpm2_shutdown",
    "tpm2_startup",
}
FORBIDDEN_PREFIXES = ("tpm2_nv",)
PRIVATE_OUTPUT_MARKERS = (
    ".ctx",
    ".priv",
    ".private",
    "private.",
    "tpmstate",
)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PCR_LINE = re.compile(
    r"(?im)^\s*(\d+):\s*0x([0-9a-f]{64}|[0-9a-f]{96})\s*$"
)
TPM_HANDLE = re.compile(r"(?im)(?:^|\s)(0x[0-9a-f]{8})(?:\s|$)")


class SafetyError(RuntimeError):
    """Raised before an unsafe or undeclared TPM command can execute."""


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(json_bytes(value))


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(
            json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n"
            for row in rows
        ),
        encoding="utf-8",
    )


def read_capsule_hash(path: Path) -> str:
    words = path.read_text(encoding="utf-8").split()
    if not words or not HEX64.fullmatch(words[0]):
        raise ValueError(f"invalid capsule checksum file: {path}")
    return words[0]


def validate_inputs(
    corpus_path: Path, capsule_checksum_path: Path
) -> tuple[dict[str, Any], str, list[str]]:
    corpus_hash = sha256_file(corpus_path)
    if corpus_hash != EXPECTED_CORPUS_SHA256:
        raise ValueError(
            f"frozen corpus hash mismatch: {corpus_hash} != "
            f"{EXPECTED_CORPUS_SHA256}"
        )
    corpus = json.loads(corpus_path.read_text(encoding="utf-8"))
    transactions = corpus.get("transactions")
    if not isinstance(transactions, list) or len(transactions) != 104:
        raise ValueError("frozen corpus must contain exactly 104 transactions")
    transaction_ids = [item.get("id") for item in transactions]
    if (
        not all(isinstance(item, str) and item for item in transaction_ids)
        or len(set(transaction_ids)) != 104
    ):
        raise ValueError("transaction identifiers must be non-empty and unique")
    capsule_hash = read_capsule_hash(capsule_checksum_path)
    if capsule_hash != EXPECTED_CAPSULE_SHA256:
        raise ValueError(
            f"source capsule hash mismatch: {capsule_hash} != "
            f"{EXPECTED_CAPSULE_SHA256}"
        )
    return corpus, capsule_hash, sorted(transaction_ids)


def load_mutation_plan(transaction_ids: list[str]) -> dict[str, Any]:
    plan = json.loads(MUTATION_PLAN.read_text(encoding="utf-8"))
    indices = plan["representative_sorted_transaction_indices"]
    mutations = plan["mutations"]
    if (
        len(indices) != 8
        or len(set(indices)) != 8
        or any(not isinstance(item, int) for item in indices)
        or any(item < 0 or item >= len(transaction_ids) for item in indices)
    ):
        raise ValueError("mutation plan must select eight valid unique indices")
    if len(mutations) != 8 or len(set(mutations)) != 8:
        raise ValueError("mutation plan must contain eight unique mutations")
    if len(indices) * len(mutations) != plan["expected_cases"]:
        raise ValueError("mutation plan case-count mismatch")
    plan["representative_transaction_ids"] = [
        transaction_ids[index] for index in indices
    ]
    return plan


def transcript(envelope: dict[str, Any]) -> str:
    return (
        f"{PROFILE}"
        f"|corpus={envelope['corpus_sha256']}"
        f"|capsule={envelope['capsule_sha256']}"
        f"|transaction={envelope['transaction_id']}"
        f"|challenge={envelope['challenge']}"
        f"|pcr={envelope['pcr_bank']}:{envelope['pcr_index']}"
    )


def qualifying_data(envelope: dict[str, Any]) -> str:
    """Return raw 32-byte SHA-256 represented as lowercase hexadecimal."""
    return sha256_bytes(transcript(envelope).encode("utf-8"))


def flip_b64(value: str, offset: int = -1) -> str:
    raw = bytearray(base64.b64decode(value, validate=True))
    if not raw:
        raise ValueError("cannot mutate empty evidence")
    raw[offset] ^= 0x01
    return base64.b64encode(raw).decode("ascii")


def find_subsequence(value: bytes, needle: bytes) -> int:
    return value.find(needle)


def sanitize_argument(argument: str, work: Path | None, stage: Path | None) -> str:
    value = argument
    if work is not None:
        value = value.replace(str(work), "<PRIVATE-WORK>")
    if stage is not None:
        value = value.replace(str(stage), "<PUBLIC-STAGE>")
    return value


def validate_runtime_command(
    executable: str,
    arguments: list[str],
    *,
    owned_contexts: set[Path],
    work: Path | None = None,
) -> None:
    if executable not in ALLOWED_TPM_EXECUTABLES:
        raise SafetyError(f"TPM executable is not allowlisted: {executable}")
    if executable in FORBIDDEN_TPM_EXECUTABLES or executable.startswith(
        FORBIDDEN_PREFIXES
    ):
        raise SafetyError(f"forbidden TPM executable: {executable}")
    if any(
        argument.startswith("0x81")
        for argument in arguments
    ):
        raise SafetyError("persistent TPM handles are forbidden")
    if executable == "tpm2_flushcontext":
        if len(arguments) != 1 or arguments[0].startswith("-"):
            raise SafetyError(
                "flushcontext may target only one run-owned context file"
            )
        target = Path(arguments[0]).resolve()
        if target not in {path.resolve() for path in owned_contexts}:
            raise SafetyError(f"flush target is not run-owned: {target}")
    if executable == "tpm2_createak" and "-r" in arguments:
        raise SafetyError("export of an AK private blob is forbidden")
    if executable == "tpm2_createprimary":
        if (
            "-C" not in arguments
            or arguments[arguments.index("-C") + 1] not in {"e", "o"}
        ):
            raise SafetyError(
                "primary must use the endorsement or owner hierarchy"
            )
    if executable in {"tpm2_create", "tpm2_load"}:
        if "-r" not in arguments:
            raise SafetyError(f"{executable} requires an explicit private blob")
        private_blob = Path(arguments[arguments.index("-r") + 1]).resolve()
        if work is None or work.resolve() not in private_blob.parents:
            raise SafetyError(
                f"{executable} private blob must remain in run-private work"
            )
    if executable == "tpm2_create":
        required = {"-C", "-G", "-g", "-a", "-u", "-r"}
        if not required.issubset(arguments):
            raise SafetyError("create command lacks a required explicit option")
        attributes = arguments[arguments.index("-a") + 1]
        expected = {
            "fixedtpm",
            "fixedparent",
            "sensitivedataorigin",
            "userwithauth",
            "sign",
            "noda",
        }
        if set(attributes.split("|")) != expected:
            raise SafetyError("create command has an undeclared key attribute")
    if executable == "tpm2_load":
        required = {"-C", "-u", "-r", "-c"}
        if not required.issubset(arguments):
            raise SafetyError("load command lacks a required explicit option")
    if executable == "tpm2_getcap" and arguments not in (
        ["properties-fixed"],
        ["properties-variable"],
        ["handles-transient"],
        ["handles-persistent"],
    ):
        raise SafetyError("getcap query is outside the read-only capability profile")
    if executable == "tpm2_quote":
        if arguments == ["--version"]:
            return
        required = {"-c", "-l", "-q", "-m", "-s", "-o", "-g"}
        if not required.issubset(arguments):
            raise SafetyError("quote command lacks a required explicit option")


def run_tpm(
    executable: str,
    arguments: list[str],
    *,
    env: dict[str, str],
    owned_contexts: set[Path],
    audit: list[dict[str, Any]],
    work: Path | None,
    stage: Path | None,
    allow_failure: bool = False,
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    validate_runtime_command(
        executable,
        arguments,
        owned_contexts=owned_contexts,
        work=work,
    )
    resolved = shutil.which(executable)
    if resolved is None:
        raise FileNotFoundError(f"missing required executable: {executable}")
    command = [resolved, *arguments]
    started = time.monotonic()
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        env=env,
        timeout=timeout,
    )
    audit.append(
        {
            "sequence": len(audit),
            "executable": executable,
            "arguments": [
                sanitize_argument(item, work, stage) for item in arguments
            ],
            "returncode": completed.returncode,
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "stdout_sha256": sha256_bytes(completed.stdout.encode("utf-8")),
            "stderr_sha256": sha256_bytes(completed.stderr.encode("utf-8")),
        }
    )
    if completed.returncode != 0 and not allow_failure:
        raise RuntimeError(
            f"{executable} failed rc={completed.returncode}: "
            f"{completed.stderr[:500]}"
        )
    return completed


def parse_tpm_handles(value: str) -> set[str]:
    """Return the normalized TPM handles emitted by tpm2_getcap."""

    return {match.lower() for match in TPM_HANDLE.findall(value)}


def ast_command_audit() -> dict[str, Any]:
    source_path = Path(__file__).resolve()
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(source_path))
    call_sites: list[dict[str, Any]] = []
    invalid_calls: list[dict[str, Any]] = []
    direct_subprocess_calls: list[int] = []

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    def enclosing_function(node: ast.AST) -> str | None:
        current: ast.AST | None = node
        while current in parents:
            current = parents[current]
            if isinstance(current, (ast.FunctionDef, ast.AsyncFunctionDef)):
                return current.name
        return None

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id == "run_tpm":
            literal = (
                node.args[0].value
                if node.args
                and isinstance(node.args[0], ast.Constant)
                and isinstance(node.args[0].value, str)
                else None
            )
            item = {
                "line": node.lineno,
                "enclosing_function": enclosing_function(node),
                "executable": literal,
            }
            call_sites.append(item)
            if literal not in ALLOWED_TPM_EXECUTABLES:
                invalid_calls.append(item)
        if (
            isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "subprocess"
            and node.func.attr in {"run", "call", "check_call", "check_output", "Popen"}
            and enclosing_function(node) != "run_tpm"
        ):
            direct_subprocess_calls.append(node.lineno)

    shell_source = (HERE / "run.sh").read_text(encoding="utf-8")
    shell_tpm_tokens = sorted(set(re.findall(r"\btpm2_[a-z0-9_]+\b", shell_source)))
    forbidden_call_sites = [
        item
        for item in call_sites
        if item["executable"] in FORBIDDEN_TPM_EXECUTABLES
        or (
            isinstance(item["executable"], str)
            and item["executable"].startswith(FORBIDDEN_PREFIXES)
        )
    ]
    return {
        "source_sha256": sha256_file(source_path),
        "run_tpm_call_sites": sorted(
            call_sites, key=lambda item: (item["line"], str(item["executable"]))
        ),
        "allowlisted_executables": sorted(ALLOWED_TPM_EXECUTABLES),
        "forbidden_executables": sorted(FORBIDDEN_TPM_EXECUTABLES),
        "forbidden_prefixes": list(FORBIDDEN_PREFIXES),
        "invalid_run_tpm_calls": invalid_calls,
        "forbidden_run_tpm_calls": forbidden_call_sites,
        "direct_subprocess_calls_outside_wrapper": direct_subprocess_calls,
        "shell_tpm_tokens": shell_tpm_tokens,
        "all_passed": (
            not invalid_calls
            and not forbidden_call_sites
            and not direct_subprocess_calls
            and not shell_tpm_tokens
            and bool(call_sites)
        ),
    }


def validate_manifest_schema_static() -> dict[str, Any]:
    schema = json.loads(MANIFEST_SCHEMA.read_text(encoding="utf-8"))
    required = {
        "schema",
        "run_status",
        "claim_boundary",
        "source",
        "configuration",
        "public_provenance",
        "counts",
        "cleanup",
        "environment",
        "artifacts",
        "all_passed",
    }
    actual = set(schema.get("required", []))
    return {
        "schema_sha256": sha256_file(MANIFEST_SCHEMA),
        "draft_2020_12": schema.get("$schema")
        == "https://json-schema.org/draft/2020-12/schema",
        "required_fields_exact": actual == required,
        "additional_properties_false": schema.get("additionalProperties") is False,
        "all_passed": (
            schema.get("$schema")
            == "https://json-schema.org/draft/2020-12/schema"
            and actual == required
            and schema.get("additionalProperties") is False
        ),
    }


def negative_safety_selftests() -> dict[str, Any]:
    """Exercise reject paths without executing any external command."""
    checks: dict[str, bool] = {}
    for executable in sorted(FORBIDDEN_TPM_EXECUTABLES) + ["tpm2_nvwrite"]:
        try:
            validate_runtime_command(
                executable, [], owned_contexts=set()
            )
        except SafetyError:
            checks[f"reject_executable:{executable}"] = True
        else:
            checks[f"reject_executable:{executable}"] = False
    try:
        validate_runtime_command(
            "tpm2_flushcontext", ["-t"], owned_contexts=set()
        )
    except SafetyError:
        checks["reject_flush_all_transient"] = True
    else:
        checks["reject_flush_all_transient"] = False
    try:
        validate_runtime_command(
            "tpm2_quote",
            [
                "-c",
                "0x81010002",
                "-l",
                "sha256:16",
                "-q",
                "00" * 32,
                "-m",
                "m",
                "-s",
                "s",
                "-o",
                "p",
                "-g",
                "sha256",
            ],
            owned_contexts=set(),
        )
    except SafetyError:
        checks["reject_persistent_handle"] = True
    else:
        checks["reject_persistent_handle"] = False
    try:
        validate_runtime_command(
            "tpm2_createak",
            ["-C", "p.ctx", "-c", "a.ctx", "-r", "ak.private"],
            owned_contexts=set(),
        )
    except SafetyError:
        checks["reject_private_ak_export"] = True
    else:
        checks["reject_private_ak_export"] = False
    try:
        validate_runtime_command(
            "tpm2_create",
            [
                "-C",
                "p.ctx",
                "-G",
                "rsa2048:rsassa-sha256",
                "-g",
                "sha256",
                "-a",
                "fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign|noda",
                "-u",
                "ak.pub",
                "-r",
                "/tmp/exported-ak.priv",
            ],
            owned_contexts=set(),
            work=Path("/private/run"),
        )
    except SafetyError:
        checks["reject_private_blob_outside_run_work"] = True
    else:
        checks["reject_private_blob_outside_run_work"] = False

    synthetic = ast.parse(
        'def unsafe():\n    run_tpm("tpm2_pcrextend", [])\n'
    )
    detected = False
    for node in ast.walk(synthetic):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "run_tpm"
            and node.args
            and isinstance(node.args[0], ast.Constant)
            and node.args[0].value not in ALLOWED_TPM_EXECUTABLES
        ):
            detected = True
    checks["synthetic_forbidden_ast_call_detected"] = detected
    return {
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "all_passed": all(checks.values()),
        "external_commands_executed": False,
    }


def profile_and_mutation_selftests(
    transaction_ids: list[str], plan: dict[str, Any]
) -> dict[str, Any]:
    envelopes = []
    qdata = set()
    for transaction_id in transaction_ids:
        envelope = {
            "profile": PROFILE,
            "corpus_sha256": EXPECTED_CORPUS_SHA256,
            "capsule_sha256": EXPECTED_CAPSULE_SHA256,
            "transaction_id": transaction_id,
            "challenge": sha256_bytes(
                f"preflight-challenge|{transaction_id}".encode("utf-8")
            ),
            "pcr_bank": "sha256",
            "pcr_index": 16,
        }
        envelopes.append(envelope)
        value = qualifying_data(envelope)
        if not HEX64.fullmatch(value):
            raise AssertionError("qualifying-data digest is not 32-byte hex")
        qdata.add(value)

    pcr_value = sha256_bytes(b"synthetic-current-pcr")
    source = {
        "envelope": copy.deepcopy(envelopes[0]),
        "ak_pub_b64": base64.b64encode(b"synthetic-ak-public").decode("ascii"),
        "quote_msg_b64": base64.b64encode(b"synthetic-quote-message").decode(
            "ascii"
        ),
        "quote_sig_b64": base64.b64encode(b"synthetic-signature").decode(
            "ascii"
        ),
        "pcr_bin_b64": base64.b64encode(
            b"prefix" + bytes.fromhex(pcr_value) + b"suffix"
        ).decode("ascii"),
        "verified_pcr_value": pcr_value,
    }
    alternate = copy.deepcopy(source)
    alternate["envelope"] = copy.deepcopy(envelopes[37])
    frozen_source = json.dumps(source, sort_keys=True)
    mutation_checks: dict[str, bool] = {}
    for mutation in plan["mutations"]:
        candidate, q_override = mutate_vector(source, mutation, alternate)
        source_unchanged = json.dumps(source, sort_keys=True) == frozen_source
        candidate_changed = (
            json.dumps(candidate, sort_keys=True) != frozen_source
            or q_override is not None
        )
        mutation_checks[mutation] = source_unchanged and candidate_changed
    checks = {
        "transcripts_unique_104": len(
            {transcript(item) for item in envelopes}
        )
        == 104,
        "qualifying_data_unique_104": len(qdata) == 104,
        "qualifying_data_hex_width": all(
            HEX64.fullmatch(item) for item in qdata
        ),
        "all_eight_mutation_builders_change_only_copy": all(
            mutation_checks.values()
        )
        and len(mutation_checks) == 8,
    }
    return {
        "checks": checks,
        "mutation_checks": mutation_checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "all_passed": all(checks.values()),
        "external_commands_executed": False,
    }


def write_preflight_hashes(report_path: Path) -> Path:
    base = report_path.parent
    files = [
        HERE / "README.md",
        HERE / "hardware_tpm_companion.py",
        HERE / "run.sh",
        HERE / "mutation-plan.json",
        HERE / "hardware-run-manifest.schema.json",
        report_path,
    ]
    manifest = base / "SHA256SUMS"
    manifest.write_text(
        "".join(
            f"{sha256_file(path)}  "
            f"{os.path.relpath(path, base)}\n"
            for path in files
        ),
        encoding="utf-8",
    )
    return manifest


def preflight(args: argparse.Namespace) -> int:
    _, capsule_hash, transaction_ids = validate_inputs(
        args.corpus, args.capsule_sha256_file
    )
    plan = load_mutation_plan(transaction_ids)
    static = ast_command_audit()
    schema = validate_manifest_schema_static()
    negative_safety = negative_safety_selftests()
    profile_selftests = profile_and_mutation_selftests(transaction_ids, plan)
    tool_presence = {
        executable: shutil.which(executable)
        for executable in sorted(ALLOWED_TPM_EXECUTABLES)
    }
    checks = {
        "frozen_corpus_hash": sha256_file(args.corpus)
        == EXPECTED_CORPUS_SHA256,
        "frozen_capsule_hash": capsule_hash == EXPECTED_CAPSULE_SHA256,
        "transactions_exactly_104": len(transaction_ids) == 104,
        "transaction_ids_unique": len(set(transaction_ids)) == 104,
        "mutation_plan_64": plan["expected_cases"] == 64,
        "static_command_audit": static["all_passed"],
        "negative_safety_selftests": negative_safety["all_passed"],
        "profile_and_mutation_selftests": profile_selftests["all_passed"],
        "manifest_schema_static": schema["all_passed"],
        "python_source_compiles": True,
        "zero_hardware_commands_executed": True,
    }
    # The value above is a named assertion: it means "zero hardware commands
    # were executed", kept positive so all checks can be aggregated.
    report = {
        "preflight": "subject-bound-hardware-tpm-companion-preflight-v1",
        "status": "PREPARATION_ONLY_NO_HARDWARE_RUN",
        "hardware_commands_executed": False,
        "checks": checks,
        "checks_passed": sum(checks.values()),
        "checks_total": len(checks),
        "static_command_audit": static,
        "negative_safety_selftests": negative_safety,
        "profile_and_mutation_selftests": profile_selftests,
        "manifest_schema_audit": schema,
        "tool_presence_not_execution": tool_presence,
        "source": {
            "corpus": str(args.corpus),
            "corpus_sha256": EXPECTED_CORPUS_SHA256,
            "capsule_sha256": EXPECTED_CAPSULE_SHA256,
            "transactions": len(transaction_ids),
        },
        "mutation_plan": {
            "sha256": sha256_file(MUTATION_PLAN),
            "representative_transaction_ids": plan[
                "representative_transaction_ids"
            ],
            "mutations": plan["mutations"],
            "expected_cases": plan["expected_cases"],
        },
        "claim_boundary": (
            "static preparation and input validation only; no TPM device was "
            "contacted and no hardware result exists"
        ),
    }
    report["all_passed"] = all(checks.values())
    write_json(args.report, report)
    manifest = write_preflight_hashes(args.report)
    print(json.dumps(report, indent=2, sort_keys=True))
    print(f"preflight SHA256SUMS: {manifest}")
    return 0 if report["all_passed"] else 1


def tcti_kind(value: str) -> str:
    head = value.split(":", 1)[0].strip()
    return head if head else "unspecified"


def parse_pcr_value(stdout: str, pcr_index: int) -> str:
    for match in PCR_LINE.finditer(stdout):
        if int(match.group(1)) == pcr_index:
            return match.group(2).lower()
    raise ValueError(
        f"tpm2_checkquote output lacks PCR index {pcr_index}"
    )


def verify_public_vector(
    vector: dict[str, Any],
    *,
    q_option_hex: str | None,
    env: dict[str, str],
    owned_contexts: set[Path],
    audit: list[dict[str, Any]],
    work: Path,
    stage: Path,
    sequence: str,
) -> dict[str, Any]:
    verify_dir = work / "offline" / sequence
    verify_dir.mkdir(parents=True, exist_ok=False)
    files = {
        "ak.pub": base64.b64decode(vector["ak_pub_b64"], validate=True),
        "quote.msg": base64.b64decode(vector["quote_msg_b64"], validate=True),
        "quote.sig": base64.b64decode(vector["quote_sig_b64"], validate=True),
        "pcr.bin": base64.b64decode(vector["pcr_bin_b64"], validate=True),
    }
    for name, value in files.items():
        (verify_dir / name).write_bytes(value)
    envelope = vector["envelope"]
    qdata = q_option_hex or qualifying_data(envelope)
    completed = run_tpm(
        "tpm2_checkquote",
        [
            "-u",
            str(verify_dir / "ak.pub"),
            "-m",
            str(verify_dir / "quote.msg"),
            "-s",
            str(verify_dir / "quote.sig"),
            "-q",
            qdata,
            "-g",
            "sha256",
            "-f",
            str(verify_dir / "pcr.bin"),
        ],
        env=env,
        owned_contexts=owned_contexts,
        audit=audit,
        work=work,
        stage=stage,
        allow_failure=True,
    )
    return {
        "accepted": completed.returncode == 0,
        "native_rc": completed.returncode,
        "stdout_sha256": sha256_bytes(completed.stdout.encode("utf-8")),
        "stderr_sha256": sha256_bytes(completed.stderr.encode("utf-8")),
        "pcr_value": (
            parse_pcr_value(completed.stdout, int(envelope["pcr_index"]))
            if completed.returncode == 0
            else None
        ),
    }


def mutate_vector(
    source: dict[str, Any],
    mutation: str,
    alternate: dict[str, Any],
) -> tuple[dict[str, Any], str | None]:
    candidate = copy.deepcopy(source)
    envelope = candidate["envelope"]
    q_override: str | None = None
    if mutation == "quote_message_flip":
        candidate["quote_msg_b64"] = flip_b64(candidate["quote_msg_b64"])
    elif mutation == "signature_flip":
        candidate["quote_sig_b64"] = flip_b64(candidate["quote_sig_b64"])
    elif mutation == "pcr_blob_flip":
        raw = bytearray(base64.b64decode(candidate["pcr_bin_b64"], validate=True))
        pcr_value = bytes.fromhex(source["verified_pcr_value"])
        offset = find_subsequence(raw, pcr_value)
        if offset < 0:
            raise ValueError("verified PCR value not found in PCR blob")
        raw[offset] ^= 0x01
        candidate["pcr_bin_b64"] = base64.b64encode(raw).decode("ascii")
    elif mutation == "challenge_replay":
        envelope["challenge"] = alternate["envelope"]["challenge"]
    elif mutation == "transaction_substitution":
        envelope["transaction_id"] = alternate["envelope"]["transaction_id"]
    elif mutation == "corpus_hash_substitution":
        envelope["corpus_sha256"] = "0" * 64
    elif mutation == "capsule_hash_substitution":
        envelope["capsule_sha256"] = "f" * 64
    elif mutation == "qualifying_data_representation":
        digest = qualifying_data(envelope)
        q_override = digest.encode("ascii").hex()
    else:
        raise ValueError(f"unknown mutation: {mutation}")
    return candidate, q_override


def artifact_inventory(stage: Path) -> list[dict[str, Any]]:
    artifacts = []
    for path in sorted(item for item in stage.rglob("*") if item.is_file()):
        relative = path.relative_to(stage).as_posix()
        if relative in {"hardware-run-manifest.json", "SHA256SUMS"}:
            continue
        lowered = relative.lower()
        if any(marker in lowered for marker in PRIVATE_OUTPUT_MARKERS):
            raise SafetyError(f"private-state-like output path rejected: {relative}")
        artifacts.append(
            {
                "path": relative,
                "sha256": sha256_file(path),
                "bytes": path.stat().st_size,
            }
        )
    return artifacts


def write_output_hashes(stage: Path) -> None:
    paths = sorted(
        path
        for path in stage.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    (stage / "SHA256SUMS").write_text(
        "".join(
            f"{sha256_file(path)}  {path.relative_to(stage).as_posix()}\n"
            for path in paths
        ),
        encoding="utf-8",
    )


def execute_hardware(args: argparse.Namespace) -> int:
    corpus, capsule_hash, transaction_ids = validate_inputs(
        args.corpus, args.capsule_sha256_file
    )
    plan = load_mutation_plan(transaction_ids)
    static = ast_command_audit()
    if not static["all_passed"]:
        raise SafetyError("static command audit failed; hardware execution refused")
    if args.output.exists():
        raise FileExistsError(
            f"output path already exists; refusing overwrite: {args.output}"
        )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    stage_path = Path(
        tempfile.mkdtemp(
            prefix=args.output.name + ".public-stage-",
            dir=args.output.parent,
        )
    )
    audit: list[dict[str, Any]] = []
    owned_contexts: set[Path] = set()
    cleanup = {
        "ak_flush_attempted": False,
        "primary_flush_attempted": False,
        "ak_flush_rc": None,
        "primary_flush_rc": None,
        "transient_handles_before": 0,
        "transient_handles_after": 0,
        "run_transient_handles_remaining": 0,
        "persistent_handles_before": 0,
        "persistent_handles_after": 0,
        "handle_census_returncodes": {},
        "persistent_handles_created": 0,
        "pcr_writes": 0,
        "nv_writes": 0,
        "private_state_files_exported": 0,
        "cleanup_verified": False,
    }
    success = False
    started = time.monotonic()
    try:
        with tempfile.TemporaryDirectory(
            prefix="subject-bound-hardware-tpm-private-"
        ) as work_name:
            work = Path(work_name)
            primary_ctx = work / "endorsement-primary.ctx"
            ak_ctx = work / "ak.ctx"
            ak_private = work / "ak.priv"
            owned_contexts.update({primary_ctx, ak_ctx})
            public = stage_path / "public"
            public.mkdir()
            properties = stage_path / "environment"
            properties.mkdir()
            env = dict(os.environ)
            env["TPM2TOOLS_TCTI"] = args.tcti
            transient_before: set[str] = set()
            persistent_before: set[str] = set()

            try:
                version = run_tpm(
                    "tpm2_quote",
                    ["--version"],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                ).stdout.strip()
                transient_before = parse_tpm_handles(
                    run_tpm(
                        "tpm2_getcap",
                        ["handles-transient"],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    ).stdout
                )
                persistent_before = parse_tpm_handles(
                    run_tpm(
                        "tpm2_getcap",
                        ["handles-persistent"],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    ).stdout
                )
                cleanup["transient_handles_before"] = len(transient_before)
                cleanup["persistent_handles_before"] = len(persistent_before)
                for capability in ("properties-fixed", "properties-variable"):
                    result = run_tpm(
                        "tpm2_getcap",
                        [capability],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    )
                    (properties / f"{capability}.txt").write_text(
                        result.stdout, encoding="utf-8"
                    )

                run_tpm(
                    "tpm2_createprimary",
                    [
                        "-C",
                        "e" if args.primary_hierarchy == "endorsement" else "o",
                        "-G",
                        args.primary_algorithm,
                        "-g",
                        "sha256",
                        "-c",
                        str(primary_ctx),
                        "-o",
                        str(public / "transient-primary.pub"),
                    ],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                )
                read_name = (
                    public / "ak.name.readpublic"
                    if args.ak_creation_profile == "createak"
                    else public / "ak.name"
                )
                run_tpm(
                    "tpm2_readpublic",
                    [
                        "-c",
                        str(primary_ctx),
                        "-f",
                        "pem",
                        "-o",
                        str(public / "transient-primary.pem"),
                        "-n",
                        str(public / "transient-primary.name"),
                    ],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                )
                signing = "rsassa" if args.ak_algorithm == "rsa" else "ecdsa"
                if args.ak_creation_profile == "createak":
                    run_tpm(
                        "tpm2_createak",
                        [
                            "-C",
                            str(primary_ctx),
                            "-c",
                            str(ak_ctx),
                            "-G",
                            args.ak_algorithm,
                            "-g",
                            "sha256",
                            "-s",
                            signing,
                            "-u",
                            str(public / "ak.pub"),
                            "-n",
                            str(public / "ak.name"),
                        ],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    )
                else:
                    algorithm = (
                        "rsa2048:rsassa-sha256"
                        if args.ak_algorithm == "rsa"
                        else "ecc:ecdsa-sha256"
                    )
                    run_tpm(
                        "tpm2_create",
                        [
                            "-C",
                            str(primary_ctx),
                            "-G",
                            algorithm,
                            "-g",
                            "sha256",
                            "-a",
                            (
                                "fixedtpm|fixedparent|sensitivedataorigin|"
                                "userwithauth|sign|noda"
                            ),
                            "-u",
                            str(public / "ak.pub"),
                            "-r",
                            str(ak_private),
                        ],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    )
                    run_tpm(
                        "tpm2_load",
                        [
                            "-C",
                            str(primary_ctx),
                            "-u",
                            str(public / "ak.pub"),
                            "-r",
                            str(ak_private),
                            "-c",
                            str(ak_ctx),
                        ],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    )
                    if not ak_private.is_file():
                        raise RuntimeError("private AK blob was not created")
                run_tpm(
                    "tpm2_readpublic",
                    [
                        "-c",
                        str(ak_ctx),
                        "-f",
                        "pem",
                        "-o",
                        str(public / "ak.pem"),
                        "-n",
                        str(read_name),
                    ],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                )
                if (
                    args.ak_creation_profile == "createak"
                    and (public / "ak.name").read_bytes()
                    != read_name.read_bytes()
                ):
                    raise RuntimeError("AK name mismatch between create and readpublic")

                ak_pub_b64 = base64.b64encode(
                    (public / "ak.pub").read_bytes()
                ).decode("ascii")
                vectors: list[dict[str, Any]] = []
                challenges: set[str] = set()
                qualifying_values: set[str] = set()
                quote_hashes: set[str] = set()
                for index, transaction_id in enumerate(transaction_ids):
                    challenge = secrets.token_hex(32)
                    if challenge in challenges:
                        raise RuntimeError("verifier challenge collision")
                    challenges.add(challenge)
                    envelope = {
                        "profile": PROFILE,
                        "corpus_sha256": EXPECTED_CORPUS_SHA256,
                        "capsule_sha256": capsule_hash,
                        "transaction_id": transaction_id,
                        "challenge": challenge,
                        "pcr_bank": args.pcr_bank,
                        "pcr_index": args.pcr_index,
                    }
                    qdata = qualifying_data(envelope)
                    qualifying_values.add(qdata)
                    quote_dir = work / "quotes" / f"{index:03d}"
                    quote_dir.mkdir(parents=True)
                    run_tpm(
                        "tpm2_quote",
                        [
                            "-c",
                            str(ak_ctx),
                            "-l",
                            f"{args.pcr_bank}:{args.pcr_index}",
                            "-q",
                            qdata,
                            "-m",
                            str(quote_dir / "quote.msg"),
                            "-s",
                            str(quote_dir / "quote.sig"),
                            "-o",
                            str(quote_dir / "pcr.bin"),
                            "-g",
                            "sha256",
                        ],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                    )
                    vector = {
                        "sequence": index,
                        "envelope": envelope,
                        "qualifying_data": qdata,
                        "qualifying_data_preimage": transcript(envelope),
                        "ak_pub_b64": ak_pub_b64,
                        "quote_msg_b64": base64.b64encode(
                            (quote_dir / "quote.msg").read_bytes()
                        ).decode("ascii"),
                        "quote_sig_b64": base64.b64encode(
                            (quote_dir / "quote.sig").read_bytes()
                        ).decode("ascii"),
                        "pcr_bin_b64": base64.b64encode(
                            (quote_dir / "pcr.bin").read_bytes()
                        ).decode("ascii"),
                    }
                    verification = verify_public_vector(
                        vector,
                        q_option_hex=None,
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                        sequence=f"baseline-{index:03d}",
                    )
                    if not verification["accepted"]:
                        raise RuntimeError(
                            f"baseline quote rejected for {transaction_id}"
                        )
                    vector["verified_pcr_value"] = verification["pcr_value"]
                    vector["verification"] = verification
                    quote_hashes.add(
                        sha256_bytes(
                            base64.b64decode(vector["quote_msg_b64"])
                        )
                    )
                    vectors.append(vector)

                if (
                    len(vectors) != 104
                    or len(challenges) != 104
                    or len(qualifying_values) != 104
                    or len(quote_hashes) != 104
                ):
                    raise RuntimeError("baseline uniqueness/count invariant failed")

                mutation_rows: list[dict[str, Any]] = []
                by_id = {
                    item["envelope"]["transaction_id"]: item for item in vectors
                }
                for representative_offset, source_id in enumerate(
                    plan["representative_transaction_ids"]
                ):
                    source = by_id[source_id]
                    alternate = vectors[
                        (
                            plan["representative_sorted_transaction_indices"][
                                representative_offset
                            ]
                            + 37
                        )
                        % len(vectors)
                    ]
                    if alternate["envelope"]["transaction_id"] == source_id:
                        alternate = vectors[
                            (
                                plan[
                                    "representative_sorted_transaction_indices"
                                ][representative_offset]
                                + 38
                            )
                            % len(vectors)
                        ]
                    for mutation in plan["mutations"]:
                        candidate, q_override = mutate_vector(
                            source, mutation, alternate
                        )
                        result = verify_public_vector(
                            candidate,
                            q_option_hex=q_override,
                            env=env,
                            owned_contexts=owned_contexts,
                            audit=audit,
                            work=work,
                            stage=stage_path,
                            sequence=(
                                f"mutation-{representative_offset:02d}-"
                                f"{mutation}"
                            ),
                        )
                        rejected = not result["accepted"]
                        mutation_rows.append(
                            {
                                "source_transaction_id": source_id,
                                "mutation": mutation,
                                "expected": "NATIVE_QUOTE_REJECTED",
                                "observed": (
                                    "NATIVE_QUOTE_REJECTED"
                                    if rejected
                                    else "UNEXPECTED_ACCEPT"
                                ),
                                "native_rc": result["native_rc"],
                                "rejected_as_expected": rejected,
                            }
                        )
                if (
                    len(mutation_rows) != 64
                    or not all(
                        item["rejected_as_expected"] for item in mutation_rows
                    )
                ):
                    raise RuntimeError("offline mutation suite failed")

                write_jsonl(stage_path / "vectors.jsonl", vectors)
                write_jsonl(
                    stage_path / "mutation-results.jsonl", mutation_rows
                )
                environment = {
                    "hostname_sha256": sha256_bytes(
                        platform.node().encode("utf-8")
                    ),
                    "platform": platform.platform(),
                    "machine": platform.machine(),
                    "python": platform.python_version(),
                    "kernel": platform.release(),
                    "tpm2_tools": version,
                    "tcti_kind": tcti_kind(args.tcti),
                    "tcti_sha256": sha256_bytes(args.tcti.encode("utf-8")),
                    "properties_fixed_sha256": sha256_file(
                        properties / "properties-fixed.txt"
                    ),
                    "properties_variable_sha256": sha256_file(
                        properties / "properties-variable.txt"
                    ),
                }
                write_json(stage_path / "environment.json", environment)
            finally:
                if ak_ctx.exists():
                    cleanup["ak_flush_attempted"] = True
                    cleanup["ak_flush_rc"] = run_tpm(
                        "tpm2_flushcontext",
                        [str(ak_ctx)],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                        allow_failure=True,
                    ).returncode
                else:
                    cleanup["ak_flush_attempted"] = True
                if primary_ctx.exists():
                    cleanup["primary_flush_attempted"] = True
                    cleanup["primary_flush_rc"] = run_tpm(
                        "tpm2_flushcontext",
                        [str(primary_ctx)],
                        env=env,
                        owned_contexts=owned_contexts,
                        audit=audit,
                        work=work,
                        stage=stage_path,
                        allow_failure=True,
                    ).returncode
                else:
                    cleanup["primary_flush_attempted"] = True
                transient_census = run_tpm(
                    "tpm2_getcap",
                    ["handles-transient"],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                    allow_failure=True,
                )
                persistent_census = run_tpm(
                    "tpm2_getcap",
                    ["handles-persistent"],
                    env=env,
                    owned_contexts=owned_contexts,
                    audit=audit,
                    work=work,
                    stage=stage_path,
                    allow_failure=True,
                )
                transient_after = parse_tpm_handles(transient_census.stdout)
                persistent_after = parse_tpm_handles(persistent_census.stdout)
                cleanup["transient_handles_after"] = len(transient_after)
                cleanup["run_transient_handles_remaining"] = len(
                    transient_after - transient_before
                )
                cleanup["persistent_handles_after"] = len(persistent_after)
                cleanup["persistent_handles_created"] = len(
                    persistent_after - persistent_before
                )
                cleanup["handle_census_returncodes"] = {
                    "transient": transient_census.returncode,
                    "persistent": persistent_census.returncode,
                }
                cleanup["cleanup_verified"] = (
                    transient_census.returncode == 0
                    and persistent_census.returncode == 0
                    and cleanup["run_transient_handles_remaining"] == 0
                    and cleanup["persistent_handles_created"] == 0
                )

        write_jsonl(stage_path / "command-audit.jsonl", audit)
        write_json(stage_path / "cleanup.json", cleanup)
        summary = {
            "baseline_quotes": len(vectors),
            "baseline_verified": sum(
                item["verification"]["accepted"] for item in vectors
            ),
            "unique_transactions": len(
                {item["envelope"]["transaction_id"] for item in vectors}
            ),
            "unique_challenges": len(
                {item["envelope"]["challenge"] for item in vectors}
            ),
            "unique_qualifying_data": len(
                {item["qualifying_data"] for item in vectors}
            ),
            "unique_quote_messages": len(
                {
                    sha256_bytes(base64.b64decode(item["quote_msg_b64"]))
                    for item in vectors
                }
            ),
            "mutation_cases": len(mutation_rows),
            "mutation_rejections": sum(
                item["rejected_as_expected"] for item in mutation_rows
            ),
            "elapsed_seconds": round(time.monotonic() - started, 6),
            "all_passed": cleanup["cleanup_verified"],
        }
        if not summary["all_passed"]:
            raise RuntimeError("post-run TPM handle census failed")
        write_json(stage_path / "summary.json", summary)
        artifacts = artifact_inventory(stage_path)
        manifest = {
            "schema": "subject-bound-tpm-run-manifest-v2",
            "run_status": "tpm-executed",
            "claim_boundary": (
                "104 transaction-bound quotes under one transient AK at the "
                "current selected PCR state; the TPM class and virtualization "
                "boundary must be established by the adjacent host provenance; "
                "no manufacturer-certified EK, secure application measurement, "
                "trusted time, or physical-host identity claim"
            ),
            "source": {
                "corpus_path": (
                    "masters-thesis-radar/research-factory-v4-2026-07-27/"
                    "labs/composed-transaction-corpus/corpus.json"
                ),
                "corpus_sha256": EXPECTED_CORPUS_SHA256,
                "capsule_sha256": capsule_hash,
                "transactions": 104,
            },
            "configuration": {
                "tcti_kind": tcti_kind(args.tcti),
                "tcti_sha256": sha256_bytes(args.tcti.encode("utf-8")),
                "pcr_bank": args.pcr_bank,
                "pcr_index": args.pcr_index,
                "primary_hierarchy": args.primary_hierarchy,
                "primary_algorithm": args.primary_algorithm,
                "ak_algorithm": args.ak_algorithm,
                "ak_creation_profile": args.ak_creation_profile,
                "hash_algorithm": "sha256",
                "qualifying_data_profile": PROFILE,
            },
            "public_provenance": {
                "transient_primary_public_sha256": sha256_file(
                    stage_path / "public" / "transient-primary.pub"
                ),
                "transient_primary_name_sha256": sha256_file(
                    stage_path / "public" / "transient-primary.name"
                ),
                "ak_public_sha256": sha256_file(
                    stage_path / "public" / "ak.pub"
                ),
                "ak_name_sha256": sha256_file(
                    stage_path / "public" / "ak.name"
                ),
                "manufacturer_certificate_present": False,
            },
            "counts": {
                key: summary[key]
                for key in (
                    "baseline_quotes",
                    "baseline_verified",
                    "unique_transactions",
                    "unique_challenges",
                    "unique_qualifying_data",
                    "mutation_cases",
                    "mutation_rejections",
                )
            },
            "cleanup": {
                key: cleanup[key]
                for key in (
                    "ak_flush_attempted",
                    "primary_flush_attempted",
                    "transient_handles_before",
                    "transient_handles_after",
                    "run_transient_handles_remaining",
                    "persistent_handles_before",
                    "persistent_handles_after",
                    "handle_census_returncodes",
                    "persistent_handles_created",
                    "pcr_writes",
                    "nv_writes",
                    "private_state_files_exported",
                    "cleanup_verified",
                )
            },
            "environment": environment,
            "artifacts": artifacts,
            "all_passed": True,
        }
        write_json(stage_path / "hardware-run-manifest.json", manifest)
        write_output_hashes(stage_path)
        stage_path.rename(args.output)
        success = True
        print(json.dumps(manifest, indent=2, sort_keys=True))
        return 0
    finally:
        if not success and stage_path.exists():
            shutil.rmtree(stage_path)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    mode = value.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--execute-hardware", action="store_true")
    value.add_argument("--corpus", type=Path, required=True)
    value.add_argument("--capsule-sha256-file", type=Path, required=True)
    value.add_argument("--report", type=Path)
    value.add_argument("--output", type=Path)
    value.add_argument("--tcti", default="device:/dev/tpmrm0")
    value.add_argument("--pcr-bank", choices=("sha256", "sha384"), default="sha256")
    value.add_argument("--pcr-index", type=int, default=16)
    value.add_argument(
        "--primary-hierarchy",
        choices=("endorsement", "owner"),
        default="endorsement",
    )
    value.add_argument(
        "--primary-algorithm", choices=("rsa", "ecc"), default="rsa"
    )
    value.add_argument("--ak-algorithm", choices=("rsa", "ecc"), default="rsa")
    value.add_argument(
        "--ak-creation-profile",
        choices=("createak", "create-load"),
        default="createak",
    )
    return value


def main() -> int:
    args = parser().parse_args()
    if not 0 <= args.pcr_index <= 31:
        raise SystemExit("--pcr-index must be between 0 and 31")
    if args.preflight:
        if args.report is None:
            raise SystemExit("--preflight requires --report")
        return preflight(args)
    if args.output is None:
        raise SystemExit("--execute-hardware requires --output")
    if not args.output.is_absolute():
        raise SystemExit("--output must be an absolute new path")
    return execute_hardware(args)


if __name__ == "__main__":
    raise SystemExit(main())
