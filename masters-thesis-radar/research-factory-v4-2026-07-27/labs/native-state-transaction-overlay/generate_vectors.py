#!/usr/bin/env python3
"""Generate 104 transaction-bound quotes under eight fresh swtpm roots."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import socket
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

import native_state_adapter as native


HERE = Path(__file__).resolve().parent
COMPOSED = HERE.parent / "composed-transaction-corpus"
CORPUS_PATH = COMPOSED / "corpus.json"
OVERLAY = HERE / "native-state-overlay.json"
POLICY_PATH = HERE / "appraisal-policy.json"
RUN_METADATA = HERE / "results" / "run-metadata.json"
EXPECTED_CORPUS_SHA256 = (
    "1ba6d40d07e62a862b98ec52ab5c189eb491f19e4e1e69a411fba73bbb9a43a8"
)
ROOTS = 8


def load_structural_adapter() -> Any:
    spec = importlib.util.spec_from_file_location(
        "source_state_adapter", COMPOSED / "state_adapter.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load source state adapter")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def free_pair() -> tuple[int, int]:
    for _ in range(100):
        first = socket.socket()
        second = socket.socket()
        try:
            first.bind(("127.0.0.1", 0))
            port = first.getsockname()[1]
            control = port + 1
            if control <= 65535:
                second.bind(("127.0.0.1", control))
                # tcti-swtpm derives the control port as server port + 1.
                return port, control
        except OSError:
            continue
        finally:
            first.close()
            second.close()
    raise RuntimeError("cannot allocate swtpm ports")


def checked(
    command: list[str],
    env: dict[str, str],
    cwd: Path,
    allow_failure: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
        capture_output=True,
        timeout=30,
    )
    if completed.returncode != 0 and not allow_failure:
        raise RuntimeError(
            f"{' '.join(command)} failed rc={completed.returncode}: "
            f"{completed.stderr.decode('utf-8', 'replace')[:500]}"
        )
    return completed


def b64(path: Path) -> str:
    return base64.b64encode(path.read_bytes()).decode("ascii")


def build_policy(
    corpus: dict[str, Any],
    structural: Any,
) -> tuple[dict[str, Any], dict[str, str]]:
    source_classes: dict[str, str] = {}
    references: dict[str, str] = {}
    denied: list[str] = []
    challenges: dict[str, str] = {}
    capsules: dict[str, str] = {}
    for transaction in corpus["transactions"]:
        transaction_id = transaction["id"]
        source_result = structural.appraise_state(
            transaction["attestation_result"], corpus["state_decision_time"]
        )[0]
        source_classes[transaction_id] = source_result
        state = transaction["attestation_result"]
        observed = native.derived_measurement(
            transaction_id, state["observed_digest"]
        )
        reference = native.derived_measurement(
            transaction_id, state["reference_digest"]
        )
        references[transaction_id] = reference
        if source_result == "CONTRAINDICATED":
            denied.append(observed)
        challenges[transaction_id] = hashlib.sha256(
            (
                "tyche.state.challenge.v1|"
                + EXPECTED_CORPUS_SHA256
                + "|"
                + transaction_id
            ).encode("utf-8")
        ).hexdigest()
        capsules[transaction_id] = native.capsule_id(
            EXPECTED_CORPUS_SHA256,
            transaction_id,
            transaction["canonical_action"],
            transaction["observed_effect"],
        )
    policy = {
        "profile": native.DOMAIN,
        "source_corpus_sha256": EXPECTED_CORPUS_SHA256,
        "decision_time": corpus["state_decision_time"],
        "reference_measurements": references,
        "denied_measurements": sorted(denied),
        "expected_challenges": challenges,
        "capsule_ids": capsules,
        "appraisal_order": [
            "CRYPTOGRAPHIC_FAILURE",
            "CONTRAINDICATED",
            "STALE",
            "REFERENCE_MISMATCH",
            "PASS",
        ],
        "oracle_boundary": (
            "policy was derived from the author-designed source corpus; "
            "source classes are evaluation oracles, not external labels"
        ),
    }
    return policy, source_classes


def start_root(
    directory: Path, algorithm: str
) -> tuple[subprocess.Popen[bytes], dict[str, str]]:
    port, control = free_pair()
    process = subprocess.Popen(
        [
            "swtpm",
            "socket",
            "--tpmstate",
            f"dir={directory}",
            "--ctrl",
            f"type=tcp,port={control}",
            "--server",
            f"type=tcp,port={port}",
            "--tpm2",
            "--flags",
            "not-need-init,startup-clear",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    env = dict(os.environ)
    env["TPM2TOOLS_TCTI"] = f"swtpm:host=127.0.0.1,port={port}"
    time.sleep(0.6)
    checked(["tpm2_startup", "-c"], env, directory, allow_failure=True)
    checked(
        ["tpm2_createek", "-G", algorithm, "-c", "ek.ctx"],
        env,
        directory,
    )
    checked(["tpm2_flushcontext", "-t"], env, directory, allow_failure=True)
    signature = "rsassa" if algorithm == "rsa" else "ecdsa"
    checked(
        [
            "tpm2_createak",
            "-C",
            "ek.ctx",
            "-c",
            "ak.ctx",
            "-u",
            "ak.pub",
            "-G",
            algorithm,
            "-g",
            "sha256",
            "-s",
            signature,
        ],
        env,
        directory,
    )
    checked(
        ["tpm2_evictcontrol", "-c", "ak.ctx", "0x81010002"],
        env,
        directory,
    )
    checked(["tpm2_flushcontext", "-t"], env, directory, allow_failure=True)
    return process, env


def main() -> int:
    for executable in (
        "swtpm",
        "tpm2_startup",
        "tpm2_createek",
        "tpm2_createak",
        "tpm2_evictcontrol",
        "tpm2_pcrreset",
        "tpm2_pcrextend",
        "tpm2_quote",
        "tpm2_checkquote",
    ):
        if shutil.which(executable) is None:
            raise SystemExit(f"missing required executable: {executable}")
    observed_hash = hashlib.sha256(CORPUS_PATH.read_bytes()).hexdigest()
    if observed_hash != EXPECTED_CORPUS_SHA256:
        raise RuntimeError(
            f"source corpus drift: {observed_hash} != "
            f"{EXPECTED_CORPUS_SHA256}"
        )
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    structural = load_structural_adapter()
    policy, source_classes = build_policy(corpus, structural)
    POLICY_PATH.write_text(
        json.dumps(policy, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    groups: list[list[dict[str, Any]]] = [[] for _ in range(ROOTS)]
    for index, transaction in enumerate(corpus["transactions"]):
        groups[index % ROOTS].append(transaction)

    vectors: list[dict[str, Any]] = []
    roots: list[dict[str, Any]] = []
    started = time.monotonic()
    for root_index, transactions in enumerate(groups):
        algorithm = "rsa" if root_index < 4 else "ecc"
        with tempfile.TemporaryDirectory(
            prefix=f"tyche-state-root-{root_index:02d}-"
        ) as name:
            directory = Path(name)
            process, env = start_root(directory, algorithm)
            try:
                ak_pub = (directory / "ak.pub").read_bytes()
                root_id = f"root-{root_index:02d}-{algorithm}"
                roots.append(
                    {
                        "root_id": root_id,
                        "algorithm": algorithm,
                        "ak_pub_sha256": hashlib.sha256(ak_pub).hexdigest(),
                        "transactions": len(transactions),
                    }
                )
                for transaction in transactions:
                    transaction_id = transaction["id"]
                    state = transaction["attestation_result"]
                    observed_measurement = native.derived_measurement(
                        transaction_id, state["observed_digest"]
                    )
                    envelope = {
                        "profile": native.DOMAIN,
                        "source_corpus_sha256": EXPECTED_CORPUS_SHA256,
                        "transaction_id": transaction_id,
                        "capsule_id": policy["capsule_ids"][transaction_id],
                        "observed_measurement": observed_measurement,
                        "issued_at": state["issued_at"],
                        "expires_at": state["expires_at"],
                        "challenge": policy["expected_challenges"][
                            transaction_id
                        ],
                        "pcr_index": native.PCR_INDEX,
                    }
                    checked(
                        ["tpm2_pcrreset", str(native.PCR_INDEX)],
                        env,
                        directory,
                    )
                    digest = observed_measurement.split(":", 1)[1]
                    checked(
                        [
                            "tpm2_pcrextend",
                            f"{native.PCR_INDEX}:sha256={digest}",
                        ],
                        env,
                        directory,
                    )
                    checked(
                        [
                            "tpm2_quote",
                            "-c",
                            "0x81010002",
                            "-l",
                            f"sha256:{native.PCR_INDEX}",
                            "-q",
                            native.q_option_hex(envelope),
                            "-m",
                            "quote.msg",
                            "-s",
                            "quote.sig",
                            "-o",
                            "pcr.bin",
                            "-g",
                            "sha256",
                        ],
                        env,
                        directory,
                    )
                    checked(
                        ["tpm2_flushcontext", "-t"],
                        env,
                        directory,
                        allow_failure=True,
                    )
                    vectors.append(
                        {
                            "root_id": root_id,
                            "ak_algorithm": algorithm,
                            "expected_state_class": source_classes[
                                transaction_id
                            ],
                            "envelope": envelope,
                            "ak_pub_b64": base64.b64encode(ak_pub).decode(
                                "ascii"
                            ),
                            "quote_msg_b64": b64(directory / "quote.msg"),
                            "quote_sig_b64": b64(directory / "quote.sig"),
                            "pcr_bin_b64": b64(directory / "pcr.bin"),
                        }
                    )
            finally:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)

    output = {
        "lab": "native-state-transaction-overlay",
        "profile": native.DOMAIN,
        "source_corpus_sha256": EXPECTED_CORPUS_SHA256,
        "claim_boundary": (
            "104 transaction-bound native TPM2 quotes from eight fresh "
            "software-TPM roots on one x86_64 host; not hardware-rooted, "
            "remote-runtime, or independent-host evidence"
        ),
        "roots": roots,
        "vectors": sorted(
            vectors, key=lambda item: item["envelope"]["transaction_id"]
        ),
    }
    OVERLAY.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    RUN_METADATA.parent.mkdir(exist_ok=True)
    metadata = {
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "host": platform.node(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "swtpm": subprocess.run(
            ["swtpm", "--version"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.splitlines()[0],
        "tpm2_tools": subprocess.run(
            ["tpm2_startup", "--version"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip(),
        "roots": ROOTS,
        "vectors": len(vectors),
    }
    RUN_METADATA.write_text(
        json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(metadata, ensure_ascii=False, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
