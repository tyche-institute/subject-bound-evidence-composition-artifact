#!/usr/bin/env python3
"""Orchestrate process-isolated durable revocation races."""

from __future__ import annotations

import base64
import collections
import hashlib
import json
import multiprocessing as mp
import os
import platform
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from services import KEY_SEED, canonical


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results.json"
SUMMARY = HERE / "SUMMARY.md"
MANIFEST = HERE / "SHA256SUMS"
PROFILES = ("atomic_guard", "double_read", "single_read", "ttl_cache")
PLACEMENTS = (
    "before_appraisal",
    "between_appraisal_and_commit",
    "after_cache_expiry",
    "after_final_read",
    "after_commit",
)
SIMULTANEOUS_TRIALS = 64
LOSS_TRIALS = 16
RESTART_TRIALS = 8
TTL_NS = 8_000_000
EXPIRY_SLEEP = 0.012


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


class Client:
    def __init__(self, base_url: str, public_key: Any) -> None:
        self.base_url = base_url
        self.public_key = public_key

    def request(
        self,
        method: str,
        path: str,
        credential_id: str | None = None,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        query: dict[str, str] = {}
        if credential_id is not None:
            query["credential_id"] = credential_id
        if idempotency_key is not None:
            query["idempotency_key"] = idempotency_key
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(
            url, method=method, data=b"" if method == "POST" else None
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            signed = json.loads(response.read())
        signature = base64.b64decode(signed.pop("signature"), validate=True)
        self.public_key.verify(signature, canonical(signed))
        value = dict(signed)
        value["signature_verified"] = True
        return value

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health")

    def initialize(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/initialize", credential_id)

    def status(self, credential_id: str) -> dict[str, Any]:
        return self.request("GET", "/status", credential_id)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/revoke", credential_id)

    def commit(
        self, credential_id: str, idempotency_key: str, guarded: bool
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/guarded-commit" if guarded else "/unguarded-commit",
            credential_id,
            idempotency_key,
        )

    def fire_and_abort(
        self, credential_id: str, idempotency_key: str, guarded: bool
    ) -> None:
        path = "/guarded-commit" if guarded else "/unguarded-commit"
        query = urllib.parse.urlencode(
            {
                "credential_id": credential_id,
                "idempotency_key": idempotency_key,
            }
        )
        host, port_text = self.base_url.removeprefix("http://").split(":")
        request = (
            f"POST {path}?{query} HTTP/1.1\r\n"
            f"Host: {host}:{port_text}\r\n"
            "Content-Length: 0\r\n"
            "Connection: close\r\n\r\n"
        ).encode("ascii")
        with socket.create_connection((host, int(port_text)), timeout=5) as sock:
            sock.sendall(request)
            sock.shutdown(socket.SHUT_RDWR)


def wait_healthy(client: Client) -> dict[str, Any]:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        try:
            return client.health()
        except Exception:
            time.sleep(0.03)
    raise RuntimeError(f"service did not become healthy: {client.base_url}")


def start_service(
    service: str,
    database: Path,
    port: int,
    public_key: Any,
) -> tuple[subprocess.Popen[bytes], Client, dict[str, Any]]:
    process = subprocess.Popen(
        [
            sys.executable,
            str(HERE / "services.py"),
            "--service",
            service,
            "--database",
            str(database),
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    client = Client(f"http://127.0.0.1:{port}", public_key)
    health = wait_healthy(client)
    return process, client, health


def worker(
    start: mp.Event,
    queue: mp.Queue,
    operation: str,
    base_url: str,
    credential_id: str,
    idempotency_key: str,
    guarded: bool,
) -> None:
    public_key = Ed25519PrivateKey.from_private_bytes(
        KEY_SEED
    ).public_key()
    client = Client(base_url, public_key)
    start.wait()
    if operation == "revoke":
        result = client.revoke(credential_id)
    else:
        result = client.commit(credential_id, idempotency_key, guarded)
    queue.put((operation, result))


def effect_count(database: Path, idempotency_key: str) -> int:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with sqlite3.connect(database, timeout=5) as connection:
            count = connection.execute(
                "SELECT COUNT(*) FROM effects WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()[0]
        if count:
            return int(count)
        time.sleep(0.01)
    return 0


def finalize(
    case_id: str,
    profile: str,
    placement: str,
    trace: list[dict[str, Any]],
    effect: dict[str, Any] | None,
    fault: str,
    duplicate_effects: int,
    recovery: bool,
) -> dict[str, Any]:
    accepted = bool(effect and effect["effect_committed"])
    oracle_accept = bool(effect and effect["status"] == "active")
    if effect is None:
        last_status = next(
            (
                row["status"]
                for row in reversed(trace)
                if row.get("status") is not None
            ),
            "revoked",
        )
        oracle_accept = last_status == "active"
    return {
        "case_id": case_id,
        "profile": profile,
        "placement": placement,
        "fault": fault,
        "accepted": accepted,
        "oracle_accept_at_effect": oracle_accept,
        "false_allow": accepted and not oracle_accept,
        "false_deny": (not accepted) and oracle_accept,
        "duplicate_effects": duplicate_effects,
        "recovery_succeeded": recovery,
        "all_signatures_verified": all(
            row.get("signature_verified", False) for row in trace
        ),
        "trace": trace,
    }


def execute_case(
    profile: str,
    placement: str,
    serial: int,
    status_client: Client,
    effect_client: Client,
    database: Path,
    fault: str = "none",
    restart_effect: Callable[[], Client] | None = None,
) -> tuple[dict[str, Any], Client]:
    case_id = f"{profile}-{placement}-{serial:03d}"
    idempotency_key = hashlib.sha256(
        ("tyche.effect.v1|" + case_id).encode("utf-8")
    ).hexdigest()
    trace = [status_client.initialize(case_id)]
    if placement == "before_appraisal":
        trace.append(status_client.revoke(case_id))
    appraisal = status_client.status(case_id)
    trace.append(appraisal)
    if appraisal["status"] == "revoked":
        return (
            finalize(
                case_id,
                profile,
                placement,
                trace,
                None,
                fault,
                0,
                True,
            ),
            effect_client,
        )
    stored_ns = time.monotonic_ns()
    if placement == "between_appraisal_and_commit":
        trace.append(status_client.revoke(case_id))
    if placement == "after_cache_expiry":
        time.sleep(EXPIRY_SLEEP)
        trace.append(status_client.revoke(case_id))
    if profile == "double_read":
        final_read = status_client.status(case_id)
        trace.append(final_read)
        if final_read["status"] == "revoked":
            return (
                finalize(
                    case_id,
                    profile,
                    placement,
                    trace,
                    None,
                    fault,
                    0,
                    True,
                ),
                effect_client,
            )
    if profile == "ttl_cache" and time.monotonic_ns() - stored_ns >= TTL_NS:
        refreshed = status_client.status(case_id)
        trace.append(refreshed)
        if refreshed["status"] == "revoked":
            return (
                finalize(
                    case_id,
                    profile,
                    placement,
                    trace,
                    None,
                    fault,
                    0,
                    True,
                ),
                effect_client,
            )
    if placement == "after_final_read":
        trace.append(status_client.revoke(case_id))
    guarded = profile == "atomic_guard"

    if placement == "simultaneous":
        start = mp.Event()
        queue: mp.Queue = mp.Queue()
        contenders = [
            mp.Process(
                target=worker,
                args=(
                    start,
                    queue,
                    "revoke",
                    status_client.base_url,
                    case_id,
                    idempotency_key,
                    guarded,
                ),
            ),
            mp.Process(
                target=worker,
                args=(
                    start,
                    queue,
                    "commit",
                    effect_client.base_url,
                    case_id,
                    idempotency_key,
                    guarded,
                ),
            ),
        ]
        for contender in contenders:
            contender.start()
        start.set()
        outputs = dict(queue.get(timeout=15) for _ in contenders)
        for contender in contenders:
            contender.join(timeout=15)
            if contender.exitcode != 0:
                raise RuntimeError("contender process failed")
        trace.extend([outputs["revoke"], outputs["commit"]])
        effect = outputs["commit"]
    elif fault in ("response_loss_retry", "restart_after_commit"):
        effect_client.fire_and_abort(case_id, idempotency_key, guarded)
        if effect_count(database, idempotency_key) != 1:
            raise RuntimeError("effect did not durably commit before retry")
        if fault == "restart_after_commit":
            if restart_effect is None:
                raise RuntimeError("restart callback missing")
            effect_client = restart_effect()
        effect = effect_client.commit(case_id, idempotency_key, guarded)
        trace.append(effect)
    else:
        effect = effect_client.commit(case_id, idempotency_key, guarded)
        trace.append(effect)
    if placement == "after_commit":
        trace.append(status_client.revoke(case_id))

    with sqlite3.connect(database) as connection:
        durable_effects = connection.execute(
            "SELECT COUNT(*) FROM effects WHERE idempotency_key=?",
            (idempotency_key,),
        ).fetchone()[0]
    duplicates = max(0, int(durable_effects) - int(bool(effect["effect_committed"])))
    recovery = (
        fault == "none"
        or (
            effect.get("idempotent_replay") is True
            and durable_effects == 1
        )
    )
    return (
        finalize(
            case_id,
            profile,
            placement,
            trace,
            effect,
            fault,
            duplicates,
            recovery,
        ),
        effect_client,
    )


def main() -> int:
    mp.set_start_method("fork")
    key = Ed25519PrivateKey.from_private_bytes(KEY_SEED)
    public_key = key.public_key()
    public_raw = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)
    cases: list[dict[str, Any]] = []
    service_instances: list[dict[str, Any]] = []
    with tempfile.TemporaryDirectory(
        prefix="tyche-durable-revocation-"
    ) as name:
        database = Path(name) / "linearization.sqlite3"
        status_port, effect_port = free_port(), free_port()
        status_process, status_client, status_health = start_service(
            "status", database, status_port, public_key
        )
        effect_process, effect_client, effect_health = start_service(
            "effect", database, effect_port, public_key
        )
        service_instances.extend([status_health, effect_health])

        def restart_effect() -> Client:
            nonlocal effect_process, effect_client, effect_port
            effect_process.terminate()
            effect_process.wait(timeout=10)
            effect_port = free_port()
            effect_process, effect_client, health = start_service(
                "effect", database, effect_port, public_key
            )
            service_instances.append(health)
            return effect_client

        try:
            for profile in PROFILES:
                for index, placement in enumerate(PLACEMENTS):
                    case, effect_client = execute_case(
                        profile,
                        placement,
                        index,
                        status_client,
                        effect_client,
                        database,
                    )
                    cases.append(case)
                for serial in range(SIMULTANEOUS_TRIALS):
                    case, effect_client = execute_case(
                        profile,
                        "simultaneous",
                        serial,
                        status_client,
                        effect_client,
                        database,
                    )
                    cases.append(case)
                for serial in range(LOSS_TRIALS):
                    case, effect_client = execute_case(
                        profile,
                        "active_commit",
                        serial,
                        status_client,
                        effect_client,
                        database,
                        fault="response_loss_retry",
                    )
                    cases.append(case)
                for serial in range(RESTART_TRIALS):
                    case, effect_client = execute_case(
                        profile,
                        "active_commit",
                        100 + serial,
                        status_client,
                        effect_client,
                        database,
                        fault="restart_after_commit",
                        restart_effect=restart_effect,
                    )
                    cases.append(case)
            with sqlite3.connect(database) as connection:
                connection.row_factory = sqlite3.Row
                event_rows = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM events ORDER BY event_id"
                    )
                ]
                effect_rows = [
                    dict(row)
                    for row in connection.execute(
                        "SELECT * FROM effects ORDER BY idempotency_key"
                    )
                ]
        finally:
            for process in (status_process, effect_process):
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=10)

    by_profile: dict[str, Any] = {}
    for profile in PROFILES:
        rows = [row for row in cases if row["profile"] == profile]
        by_profile[profile] = {
            "cases": len(rows),
            "false_allows": sum(row["false_allow"] for row in rows),
            "false_denies": sum(row["false_deny"] for row in rows),
            "duplicate_effects": sum(row["duplicate_effects"] for row in rows),
        }
    fault_rows = [
        row for row in cases if row["fault"] != "none"
    ]
    summary = {
        "lab": "distributed-revocation-service",
        "cases": len(cases),
        "profiles": by_profile,
        "durable_events": len(event_rows),
        "durable_effects": len(effect_rows),
        "signed_responses_verified": sum(
            row["all_signatures_verified"] for row in cases
        ),
        "fault_cases": len(fault_rows),
        "fault_recoveries": sum(
            row["recovery_succeeded"] for row in fault_rows
        ),
        "duplicate_effects": sum(
            row["duplicate_effects"] for row in cases
        ),
        "service_instances": len(service_instances),
        "distinct_service_pids": len(
            {item["pid"] for item in service_instances}
        ),
        "runner_pid": os.getpid(),
        "atomic_guard_invariant": (
            by_profile["atomic_guard"]["false_allows"] == 0
            and by_profile["atomic_guard"]["false_denies"] == 0
            and by_profile["atomic_guard"]["duplicate_effects"] == 0
        ),
        "weak_counterexamples_observed": all(
            by_profile[profile]["false_allows"] > 0
            for profile in ("double_read", "single_read", "ttl_cache")
        ),
        "all_passed": False,
        "claim_boundary": (
            f"one local OS instance reporting {platform.machine()}; separate "
            "status/effect services and client contender processes over "
            "loopback TCP with durable SQLite linearization, signed "
            "responses, disconnect/retry and service restart; not "
            "multi-host or deployment evidence"
        ),
    }
    summary["all_passed"] = (
        summary["atomic_guard_invariant"]
        and summary["weak_counterexamples_observed"]
        and summary["signed_responses_verified"] == len(cases)
        and summary["fault_recoveries"] == len(fault_rows)
        and summary["duplicate_effects"] == 0
        and summary["distinct_service_pids"] >= 2
    )
    output = {
        "summary": summary,
        "environment": {
            "host": platform.node(),
            "platform": platform.platform(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "public_key_raw_b64": base64.b64encode(public_raw).decode("ascii"),
            "service_instances": service_instances,
        },
        "cases": cases,
        "durable_events": event_rows,
        "durable_effects": effect_rows,
    }
    RESULTS.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    SUMMARY.write_text(
        "# Process-isolated revocation results\n\n"
        f"- Cases: **{summary['cases']}**\n"
        f"- Profile outcomes: **{summary['profiles']}**\n"
        f"- Durable events/effects: **{summary['durable_events']}/"
        f"{summary['durable_effects']}**\n"
        f"- Disconnect/restart recoveries: **{summary['fault_recoveries']}/"
        f"{summary['fault_cases']}**\n"
        f"- Duplicate effects: **{summary['duplicate_effects']}**\n"
        f"- Distinct service PIDs: **{summary['distinct_service_pids']}**\n"
        f"- Atomic-guard invariant: "
        f"**{'PASS' if summary['atomic_guard_invariant'] else 'FAIL'}**\n"
        f"- Overall: **{'PASS' if summary['all_passed'] else 'FAIL'}**\n\n"
        f"Boundary: {summary['claim_boundary']}.\n",
        encoding="utf-8",
    )
    files = (
        "README.md",
        "services.py",
        "run_experiment.py",
        "run.sh",
        "results.json",
        "SUMMARY.md",
    )
    MANIFEST.write_text(
        "".join(
            f"{hashlib.sha256((HERE / name).read_bytes()).hexdigest()}  "
            f"{name}\n"
            for name in files
        ),
        encoding="utf-8",
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
