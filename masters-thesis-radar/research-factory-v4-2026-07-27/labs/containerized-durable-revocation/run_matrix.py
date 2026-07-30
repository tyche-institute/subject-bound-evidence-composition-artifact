#!/usr/bin/env python3
"""Run exact same-host multi-container revocation assertions."""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import os
import platform
import socket
import sqlite3
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from container_service import KEY_SEED, canonical, public_key_b64


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self.public_key = Ed25519PrivateKey.from_private_bytes(
            KEY_SEED
        ).public_key()

    def request(
        self,
        method: str,
        path: str,
        *,
        credential_id: str | None = None,
        idempotency_key: str | None = None,
        fault: str | None = None,
        delay_ms: int = 0,
    ) -> dict[str, Any]:
        query: dict[str, str] = {}
        if credential_id is not None:
            query["credential_id"] = credential_id
        if idempotency_key is not None:
            query["idempotency_key"] = idempotency_key
        if fault is not None:
            query["tyche_fault"] = fault
        if delay_ms:
            query["tyche_delay_ms"] = str(delay_ms)
        url = self.base_url + path
        if query:
            url += "?" + urllib.parse.urlencode(query)
        request = urllib.request.Request(
            url,
            method=method,
            data=b"" if method == "POST" else None,
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            signed = json.loads(response.read())
        signature_b64 = signed.pop("signature")
        signature = base64.b64decode(signature_b64, validate=True)
        self.public_key.verify(signature, canonical(signed))
        value = dict(signed)
        value["signature_verified"] = True
        value["signed_evidence"] = {
            "payload": signed,
            "signature_b64": signature_b64,
        }
        return value

    def health(self) -> dict[str, Any]:
        return self.request("GET", "/health")

    def initialize(self, credential_id: str) -> dict[str, Any]:
        return self.request(
            "POST", "/initialize", credential_id=credential_id
        )

    def status(self, credential_id: str) -> dict[str, Any]:
        return self.request("GET", "/status", credential_id=credential_id)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/revoke", credential_id=credential_id)

    def commit(
        self,
        credential_id: str,
        idempotency_key: str,
        *,
        guarded: bool,
        fault: str | None = None,
        delay_ms: int = 0,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            "/guarded-commit" if guarded else "/unguarded-commit",
            credential_id=credential_id,
            idempotency_key=idempotency_key,
            fault=fault,
            delay_ms=delay_ms,
        )


def wait_healthy(client: Client, expected: str) -> dict[str, Any]:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            result = client.health()
            if result.get("instance_id") == expected:
                return result
        except Exception:
            time.sleep(0.05)
    raise RuntimeError(f"service did not become healthy: {expected}")


def case_row(
    case_id: str,
    profile: str,
    category: str,
    trace: list[dict[str, Any]],
    effect: dict[str, Any] | None,
    *,
    fault: str = "none",
    transport_failure_observed: bool = False,
    recovery: dict[str, Any] | None = None,
) -> dict[str, Any]:
    accepted = bool(effect and effect["effect_committed"])
    oracle_accept = bool(effect and effect["status"] == "active")
    return {
        "case_id": case_id,
        "profile": profile,
        "category": category,
        "fault": fault,
        "accepted": accepted,
        "oracle_accept_at_effect": oracle_accept,
        "false_allow": accepted and not oracle_accept,
        "false_deny": (not accepted) and oracle_accept,
        "transport_failure_observed": transport_failure_observed,
        "recovery": recovery,
        "all_observed_signatures_verified": all(
            row.get("signature_verified", False) for row in trace
        ),
        "trace": trace,
    }


def idempotency(case_id: str) -> str:
    import hashlib

    return hashlib.sha256(
        ("tyche.container.effect.v1|" + case_id).encode("utf-8")
    ).hexdigest()


def scheduled_cases(
    status: Client,
    effect_a: Client,
    effect_b: Client,
    proxy: Client,
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []

    case_id = "scheduled-atomic-active"
    trace = [status.initialize(case_id), status.status(case_id)]
    effect = effect_a.commit(case_id, idempotency(case_id), guarded=True)
    trace.append(effect)
    rows.append(case_row(case_id, "atomic_guard", "scheduled", trace, effect))

    case_id = "scheduled-atomic-revoked"
    trace = [status.initialize(case_id), status.status(case_id)]
    trace.append(status.revoke(case_id))
    effect = effect_a.commit(case_id, idempotency(case_id), guarded=True)
    trace.append(effect)
    rows.append(case_row(case_id, "atomic_guard", "scheduled", trace, effect))

    case_id = "scheduled-prior-read-revoked"
    trace = [status.initialize(case_id), status.status(case_id)]
    trace.append(status.revoke(case_id))
    effect = effect_a.commit(case_id, idempotency(case_id), guarded=False)
    trace.append(effect)
    rows.append(
        case_row(case_id, "prior_read_unguarded", "scheduled", trace, effect)
    )

    case_id = "fault-drop-before-forward"
    key = idempotency(case_id)
    trace = [status.initialize(case_id), status.status(case_id)]
    failed = False
    try:
        proxy.commit(
            case_id,
            key,
            guarded=True,
            fault="drop_before_forward",
        )
    except Exception:
        failed = True
    recovery = effect_b.commit(case_id, key, guarded=True)
    trace.append(recovery)
    rows.append(
        case_row(
            case_id,
            "atomic_guard",
            "fault_recovery",
            trace,
            recovery,
            fault="drop_before_forward",
            transport_failure_observed=failed,
            recovery={
                "served_by_instance": recovery["served_by_instance"],
                "original_instance": recovery["original_instance"],
                "idempotent_replay": recovery["idempotent_replay"],
            },
        )
    )

    case_id = "fault-drop-after-commit-cross-instance"
    key = idempotency(case_id)
    trace = [status.initialize(case_id), status.status(case_id)]
    failed = False
    try:
        proxy.commit(
            case_id,
            key,
            guarded=True,
            fault="drop_after_forward",
        )
    except Exception:
        failed = True
    recovery = effect_b.commit(case_id, key, guarded=True)
    trace.append(recovery)
    rows.append(
        case_row(
            case_id,
            "atomic_guard",
            "fault_recovery",
            trace,
            recovery,
            fault="drop_after_forward",
            transport_failure_observed=failed,
            recovery={
                "served_by_instance": recovery["served_by_instance"],
                "original_instance": recovery["original_instance"],
                "idempotent_replay": recovery["idempotent_replay"],
            },
        )
    )

    case_id = "fault-denied-decision-cross-instance"
    key = idempotency(case_id)
    trace = [status.initialize(case_id), status.status(case_id)]
    trace.append(status.revoke(case_id))
    failed = False
    try:
        proxy.commit(
            case_id,
            key,
            guarded=True,
            fault="drop_after_forward",
        )
    except Exception:
        failed = True
    recovery = effect_b.commit(case_id, key, guarded=True)
    trace.append(recovery)
    rows.append(
        case_row(
            case_id,
            "atomic_guard",
            "fault_recovery",
            trace,
            recovery,
            fault="drop_after_forward",
            transport_failure_observed=failed,
            recovery={
                "served_by_instance": recovery["served_by_instance"],
                "original_instance": recovery["original_instance"],
                "idempotent_replay": recovery["idempotent_replay"],
            },
        )
    )

    case_id = "fault-unguarded-after-revoke"
    key = idempotency(case_id)
    trace = [status.initialize(case_id), status.status(case_id)]
    trace.append(status.revoke(case_id))
    failed = False
    try:
        proxy.commit(
            case_id,
            key,
            guarded=False,
            fault="drop_after_forward",
        )
    except Exception:
        failed = True
    recovery = effect_b.commit(case_id, key, guarded=False)
    trace.append(recovery)
    rows.append(
        case_row(
            case_id,
            "prior_read_unguarded",
            "fault_recovery",
            trace,
            recovery,
            fault="drop_after_forward",
            transport_failure_observed=failed,
            recovery={
                "served_by_instance": recovery["served_by_instance"],
                "original_instance": recovery["original_instance"],
                "idempotent_replay": recovery["idempotent_replay"],
            },
        )
    )
    return rows


def concurrent_cases(
    status: Client,
    effect: Client,
    *,
    guarded: bool,
    trials: int,
) -> list[dict[str, Any]]:
    profile = "atomic_guard" if guarded else "prior_read_unguarded"
    rows: list[dict[str, Any]] = []
    for serial in range(trials):
        case_id = f"race-{profile}-{serial:03d}"
        trace = [status.initialize(case_id), status.status(case_id)]
        barrier = threading.Barrier(3)

        def revoke() -> dict[str, Any]:
            barrier.wait()
            return status.revoke(case_id)

        def commit() -> dict[str, Any]:
            barrier.wait()
            return effect.commit(
                case_id,
                idempotency(case_id),
                guarded=guarded,
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            revoke_future = pool.submit(revoke)
            commit_future = pool.submit(commit)
            barrier.wait()
            revoked = revoke_future.result(timeout=30)
            committed = commit_future.result(timeout=30)
        trace.extend(
            sorted(
                (revoked, committed),
                key=lambda item: item["linearization_index"],
            )
        )
        rows.append(
            case_row(
                case_id,
                profile,
                "same_release",
                trace,
                committed,
            )
        )
    return rows


def database_snapshot(database: Path) -> dict[str, Any]:
    connection = sqlite3.connect(
        f"file:{database}?mode=ro", uri=True, timeout=30
    )
    connection.row_factory = sqlite3.Row
    integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
    events = [
        dict(row)
        for row in connection.execute("SELECT * FROM events ORDER BY event_id")
    ]
    decisions = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM decisions ORDER BY idempotency_key"
        )
    ]
    effects = [
        dict(row)
        for row in connection.execute(
            "SELECT * FROM effects ORDER BY idempotency_key"
        )
    ]
    connection.close()
    return {
        "integrity_check": integrity,
        "events": events,
        "decisions": decisions,
        "effects": effects,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--status-url", required=True)
    parser.add_argument("--effect-a-url", required=True)
    parser.add_argument("--effect-b-url", required=True)
    parser.add_argument("--proxy-url", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=64)
    args = parser.parse_args()

    status = Client(args.status_url)
    effect_a = Client(args.effect_a_url)
    effect_b = Client(args.effect_b_url)
    proxy = Client(args.proxy_url)
    health = [
        wait_healthy(status, "status-a"),
        wait_healthy(effect_a, "effect-a"),
        wait_healthy(effect_b, "effect-b"),
    ]

    rows = scheduled_cases(status, effect_a, effect_b, proxy)
    rows.extend(
        concurrent_cases(
            status, effect_a, guarded=True, trials=args.trials
        )
    )
    rows.extend(
        concurrent_cases(
            status, effect_a, guarded=False, trials=args.trials
        )
    )
    snapshot = database_snapshot(args.database)

    atomic = [row for row in rows if row["profile"] == "atomic_guard"]
    weak = [
        row for row in rows if row["profile"] == "prior_read_unguarded"
    ]
    fault = [row for row in rows if row["category"] == "fault_recovery"]
    cross_instance = [
        row
        for row in fault
        if row["fault"] == "drop_after_forward"
    ]
    hostnames = {
        item["container_hostname"] for item in health
    } | {socket.gethostname()}
    event_ids = [row["event_id"] for row in snapshot["events"]]
    assertions = {
        "all_observed_signatures_verified": all(
            row["all_observed_signatures_verified"] for row in rows
        )
        and all(item["signature_verified"] for item in health),
        "atomic_guard_zero_false_allows": not any(
            row["false_allow"] for row in atomic
        ),
        "weak_profile_has_scheduled_false_allow": any(
            row["false_allow"] and row["category"] == "scheduled"
            for row in weak
        ),
        "all_faults_raise_transport_failure": all(
            row["transport_failure_observed"] for row in fault
        ),
        "drop_after_forward_replays_original_decision": all(
            row["recovery"]["idempotent_replay"] for row in cross_instance
        ),
        "cross_instance_recovery_served_by_effect_b": all(
            row["recovery"]["served_by_instance"] == "effect-b"
            for row in fault
        ),
        "drop_after_forward_originated_at_effect_a": all(
            row["recovery"]["original_instance"] == "effect-a"
            for row in cross_instance
        ),
        "drop_before_forward_originated_at_effect_b": next(
            row
            for row in fault
            if row["fault"] == "drop_before_forward"
        )["recovery"]["original_instance"]
        == "effect-b",
        "no_duplicate_decisions": len(snapshot["decisions"])
        == len({row["idempotency_key"] for row in snapshot["decisions"]}),
        "no_duplicate_effects": len(snapshot["effects"])
        == len({row["idempotency_key"] for row in snapshot["effects"]}),
        "sqlite_integrity_ok": snapshot["integrity_check"] == "ok",
        "event_sequence_contiguous": event_ids
        == list(range(1, len(event_ids) + 1)),
        "four_distinct_container_hostnames": len(hostnames) == 4,
        "three_distinct_signed_service_hostnames": len(
            {item["container_hostname"] for item in health}
        )
        == 3,
    }
    summary = {
        "cases": len(rows),
        "atomic_cases": len(atomic),
        "weak_cases": len(weak),
        "fault_cases": len(fault),
        "atomic_false_allows": sum(row["false_allow"] for row in atomic),
        "weak_false_allows": sum(row["false_allow"] for row in weak),
        "effects": len(snapshot["effects"]),
        "decisions": len(snapshot["decisions"]),
        "events": len(snapshot["events"]),
        "assertions_passed": sum(assertions.values()),
        "assertions_total": len(assertions),
        "all_passed": all(assertions.values()),
    }
    output = {
        "lab": "containerized-durable-revocation",
        "profile": "tyche-containerized-durable-revocation-v1",
        "topology": {
            "network": "Docker internal bridge",
            "services": [
                "status-a",
                "effect-a",
                "effect-b",
                "fault-proxy",
                "runner",
            ],
            "durable_store": "SQLite WAL named volume",
            "linearization": "BEGIN IMMEDIATE transaction and event_id",
        },
        "environment": {
            "runner_container_hostname": socket.gethostname(),
            "machine": platform.machine(),
            "platform": platform.platform(),
            "python": platform.python_version(),
            "sqlite": sqlite3.sqlite_version,
            "network_interfaces": sorted(
                path.name for path in Path("/sys/class/net").iterdir()
            ),
            "runtime_image": os.environ.get("TYCHE_RUNTIME_IMAGE", "unknown"),
        },
        "status_public_key_raw_b64": public_key_b64(),
        "service_health": health,
        "cases": rows,
        "database_snapshot": snapshot,
        "assertions": assertions,
        "summary": summary,
        "claim_boundary": (
            "same physical x86_64 host; separate status, two effect, proxy, "
            "and runner containers over an internal Docker bridge with a "
            "shared durable SQLite linearization store; signed responses, "
            "lost-response injection, idempotent cross-instance recovery, "
            "and concurrent races; not multi-host, consensus, "
            "independent-clock, deployment, Internet-scale, or performance "
            "evidence"
        ),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
