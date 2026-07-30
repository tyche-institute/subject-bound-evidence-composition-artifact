#!/usr/bin/env python3
"""Run signed revocation races against a concurrent local HTTP service."""

from __future__ import annotations

import base64
import hashlib
import json
import statistics
import threading
import time
import urllib.parse
import urllib.request
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


HERE = Path(__file__).resolve().parent
RESULTS = HERE / "results.json"
SUMMARY = HERE / "SUMMARY.md"
MANIFEST = HERE / "SHA256SUMS"
SIMULTANEOUS_TRIALS = 64
TTL_CACHE_NS = 50_000_000
TTL_EXPIRY_DELAY_S = 0.075
KEY_SEED = hashlib.sha256(b"tyche-live-revocation-service-v1").digest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


class RevocationState:
    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self.private_key = private_key
        self.lock = threading.Lock()
        self.credentials: dict[str, dict[str, Any]] = {}
        self.index = 0
        self.events: list[dict[str, Any]] = []

    def initialize(self, credential_id: str) -> None:
        with self.lock:
            self.credentials[credential_id] = {
                "status": "active",
                "sequence": 1,
            }

    def signed(self, payload: dict[str, Any]) -> dict[str, Any]:
        signed = dict(payload)
        signed["signature"] = base64.b64encode(
            self.private_key.sign(canonical(payload))
        ).decode("ascii")
        return signed

    def event(
        self,
        operation: str,
        credential_id: str,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.index += 1
        row = {
            "linearization_index": self.index,
            "server_monotonic_ns": time.monotonic_ns(),
            "operation": operation,
            "credential_id": credential_id,
            "status": self.credentials[credential_id]["status"],
            "sequence": self.credentials[credential_id]["sequence"],
        }
        if extra:
            row.update(extra)
        self.events.append(row)
        return row

    def read(self, credential_id: str) -> dict[str, Any]:
        with self.lock:
            event = self.event("status_read", credential_id)
            return self.signed(event)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        with self.lock:
            item = self.credentials[credential_id]
            if item["status"] != "revoked":
                item["status"] = "revoked"
                item["sequence"] += 1
            event = self.event("revoke", credential_id)
            return self.signed(event)

    def guarded_commit(self, credential_id: str) -> dict[str, Any]:
        with self.lock:
            allowed = self.credentials[credential_id]["status"] == "active"
            event = self.event(
                "guarded_commit",
                credential_id,
                {"effect_committed": allowed},
            )
            return self.signed(event)

    def unguarded_commit(self, credential_id: str) -> dict[str, Any]:
        with self.lock:
            event = self.event(
                "unguarded_commit",
                credential_id,
                {"effect_committed": True},
            )
            return self.signed(event)


class Handler(BaseHTTPRequestHandler):
    server_version = "TycheRevocationLab/1.0"

    @property
    def state(self) -> RevocationState:
        return self.server.state  # type: ignore[attr-defined]

    def log_message(self, format: str, *args: Any) -> None:
        return

    def send_json(self, value: dict[str, Any], status: int = 200) -> None:
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def credential(self) -> str:
        query = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        return query["credential_id"][0]

    def do_GET(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        if path != "/status":
            self.send_json({"error": "not_found"}, 404)
            return
        self.send_json(self.state.read(self.credential()))

    def do_POST(self) -> None:
        path = urllib.parse.urlparse(self.path).path
        credential_id = self.credential()
        if path == "/revoke":
            result = self.state.revoke(credential_id)
        elif path == "/guarded-commit":
            result = self.state.guarded_commit(credential_id)
        elif path == "/unguarded-commit":
            result = self.state.unguarded_commit(credential_id)
        else:
            self.send_json({"error": "not_found"}, 404)
            return
        self.send_json(result)


class Client:
    def __init__(self, base_url: str, public_key: Ed25519PublicKey) -> None:
        self.base_url = base_url
        self.public_key = public_key

    def request(self, method: str, path: str, credential_id: str) -> dict[str, Any]:
        url = (
            self.base_url
            + path
            + "?"
            + urllib.parse.urlencode({"credential_id": credential_id})
        )
        request = urllib.request.Request(url, method=method, data=b"")
        started = time.monotonic_ns()
        with urllib.request.urlopen(request, timeout=5) as response:
            value = json.loads(response.read())
        ended = time.monotonic_ns()
        signature_b64 = value.pop("signature")
        signature = base64.b64decode(signature_b64, validate=True)
        self.public_key.verify(signature, canonical(value))
        signed_payload = dict(value)
        value["signature_verified"] = True
        value["signature_b64"] = signature_b64
        value["signed_payload"] = signed_payload
        value["round_trip_ns"] = ended - started
        return value

    def status(self, credential_id: str) -> dict[str, Any]:
        return self.request("GET", "/status", credential_id)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/revoke", credential_id)

    def guarded_commit(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/guarded-commit", credential_id)

    def unguarded_commit(self, credential_id: str) -> dict[str, Any]:
        return self.request("POST", "/unguarded-commit", credential_id)


def execute_case(
    state: RevocationState,
    client: Client,
    profile: str,
    placement: str,
    serial: int,
) -> dict[str, Any]:
    credential_id = f"cred-{profile}-{placement}-{serial:03d}"
    state.initialize(credential_id)
    trace: list[dict[str, Any]] = []

    def get_status() -> dict[str, Any]:
        row = client.status(credential_id)
        trace.append(row)
        return row

    def revoke() -> dict[str, Any]:
        row = client.revoke(credential_id)
        trace.append(row)
        return row

    if placement == "before_appraisal":
        revoke()
    appraisal = get_status()
    cached = dict(appraisal)
    cache_stored_ns = time.monotonic_ns()
    decision_context: dict[str, Any] = {
        "cache_ttl_ns": TTL_CACHE_NS if profile == "ttl_cache" else None,
        "cache_age_at_decision_ns": None,
        "cache_hit": None,
        "cache_refresh": False,
    }

    if appraisal["status"] == "revoked":
        return finalize(
            profile,
            placement,
            credential_id,
            trace,
            accepted=False,
            effect=None,
            decision_context=decision_context,
        )

    final_read: dict[str, Any] | None = None
    if placement == "between_appraisal_and_commit":
        revoke()
    if placement == "after_cache_expiry":
        time.sleep(TTL_EXPIRY_DELAY_S)
        revoke()
    if profile == "double_read":
        final_read = get_status()
        if final_read["status"] == "revoked":
            return finalize(
                profile,
                placement,
                credential_id,
                trace,
                accepted=False,
                effect=None,
                decision_context=decision_context,
            )
    if profile == "ttl_cache":
        cache_age = time.monotonic_ns() - cache_stored_ns
        decision_context["cache_age_at_decision_ns"] = cache_age
        decision_context["cache_hit"] = cache_age < TTL_CACHE_NS
        if not decision_context["cache_hit"]:
            decision_context["cache_refresh"] = True
            final_read = get_status()
            cached = dict(final_read)
            if final_read["status"] == "revoked":
                return finalize(
                    profile,
                    placement,
                    credential_id,
                    trace,
                    accepted=False,
                    effect=None,
                    decision_context=decision_context,
                )
    if placement == "after_final_read":
        revoke()

    if profile == "atomic_guard":
        commit_call = client.guarded_commit
    else:
        commit_call = client.unguarded_commit
        if profile == "single_read":
            assert appraisal["status"] == "active"
        elif profile == "ttl_cache":
            assert cached["status"] == "active"
        elif profile == "double_read":
            assert final_read is not None and final_read["status"] == "active"
        else:
            raise ValueError(profile)

    if placement == "simultaneous":
        barrier = threading.Barrier(3)
        outputs: dict[str, dict[str, Any]] = {}

        def run_revoke() -> None:
            barrier.wait()
            outputs["revoke"] = client.revoke(credential_id)

        def run_commit() -> None:
            barrier.wait()
            outputs["commit"] = commit_call(credential_id)

        revoke_thread = threading.Thread(target=run_revoke)
        commit_thread = threading.Thread(target=run_commit)
        revoke_thread.start()
        commit_thread.start()
        barrier.wait()
        revoke_thread.join()
        commit_thread.join()
        trace.extend([outputs["revoke"], outputs["commit"]])
        effect = outputs["commit"]
        accepted = bool(effect["effect_committed"])
    else:
        effect = commit_call(credential_id)
        trace.append(effect)
        accepted = bool(effect["effect_committed"])
        if placement == "after_commit":
            revoke()

    return finalize(
        profile,
        placement,
        credential_id,
        trace,
        accepted=accepted,
        effect=effect,
        decision_context=decision_context,
    )


def finalize(
    profile: str,
    placement: str,
    credential_id: str,
    trace: list[dict[str, Any]],
    accepted: bool,
    effect: dict[str, Any] | None,
    decision_context: dict[str, Any],
) -> dict[str, Any]:
    all_signed = all(row["signature_verified"] for row in trace)
    if effect is None:
        current_status = trace[-1]["status"]
        oracle_accept = current_status == "active"
    else:
        oracle_accept = effect["status"] == "active"
    false_allow = accepted and not oracle_accept
    false_deny = not accepted and oracle_accept
    return {
        "case_id": credential_id,
        "profile": profile,
        "placement": placement,
        "accepted": accepted,
        "oracle_accept_at_effect": oracle_accept,
        "false_allow": false_allow,
        "false_deny": false_deny,
        "all_signatures_verified": all_signed,
        "decision_context": decision_context,
        "event_order": [
            {
                "operation": row["operation"],
                "linearization_index": row["linearization_index"],
                "status": row["status"],
                "sequence": row["sequence"],
            }
            for row in sorted(
                trace, key=lambda item: item["linearization_index"]
            )
        ],
        "signed_responses": [
            {
                "payload": row["signed_payload"],
                "signature_b64": row["signature_b64"],
            }
            for row in sorted(
                trace, key=lambda item: item["linearization_index"]
            )
        ],
        "round_trip_ns": [row["round_trip_ns"] for row in trace],
    }


def percentile(values: list[int], fraction: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def main() -> int:
    private_key = Ed25519PrivateKey.from_private_bytes(KEY_SEED)
    state = RevocationState(private_key)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.state = state  # type: ignore[attr-defined]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    client = Client(
        f"http://{host}:{port}",
        private_key.public_key(),
    )

    profiles = ("atomic_guard", "double_read", "single_read", "ttl_cache")
    deterministic = (
        "before_appraisal",
        "between_appraisal_and_commit",
        "after_cache_expiry",
        "after_final_read",
        "after_commit",
    )
    rows: list[dict[str, Any]] = []
    try:
        for profile in profiles:
            for serial, placement in enumerate(deterministic):
                rows.append(
                    execute_case(state, client, profile, placement, serial)
                )
            for serial in range(SIMULTANEOUS_TRIALS):
                rows.append(
                    execute_case(
                        state,
                        client,
                        profile,
                        "simultaneous",
                        serial,
                    )
                )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)

    profile_summary: dict[str, dict[str, Any]] = {}
    for profile in profiles:
        selected = [row for row in rows if row["profile"] == profile]
        profile_summary[profile] = {
            "cases": len(selected),
            "false_allows": sum(row["false_allow"] for row in selected),
            "false_denies": sum(row["false_deny"] for row in selected),
            "signature_failures": sum(
                not row["all_signatures_verified"] for row in selected
            ),
            "placement_counts": dict(
                Counter(row["placement"] for row in selected)
            ),
            "cache_hits": sum(
                row["decision_context"]["cache_hit"] is True
                for row in selected
            ),
            "cache_refreshes": sum(
                row["decision_context"]["cache_refresh"] for row in selected
            ),
        }

    latencies = [
        latency for row in rows for latency in row["round_trip_ns"]
    ]
    signed_response_count = sum(
        len(row["signed_responses"]) for row in rows
    )
    output = {
        "lab": "live-revocation-service",
        "transport": "concurrent HTTP over 127.0.0.1 ephemeral TCP port",
        "status_signature": "Ed25519 deterministic test key",
        "status_public_key_raw_b64": base64.b64encode(
            private_key.public_key().public_bytes(
                Encoding.Raw, PublicFormat.Raw
            )
        ).decode("ascii"),
        "profiles": profile_summary,
        "cases": len(rows),
        "simultaneous_trials_per_profile": SIMULTANEOUS_TRIALS,
        "ttl_cache_ns": TTL_CACHE_NS,
        "ttl_expiry_delay_s": TTL_EXPIRY_DELAY_S,
        "all_status_signatures_verified": all(
            row["all_signatures_verified"] for row in rows
        ),
        "signed_responses": signed_response_count,
        "atomic_guard_zero_safety_errors": (
            profile_summary["atomic_guard"]["false_allows"] == 0
            and profile_summary["atomic_guard"]["false_denies"] == 0
        ),
        "incomplete_profiles_expose_false_allow": all(
            profile_summary[profile]["false_allows"] > 0
            for profile in ("double_read", "single_read", "ttl_cache")
        ),
        "ttl_profile_is_behaviorally_distinct": (
            next(
                row
                for row in rows
                if row["profile"] == "ttl_cache"
                and row["placement"] == "after_cache_expiry"
            )["decision_context"]["cache_refresh"]
            and not next(
                row
                for row in rows
                if row["profile"] == "ttl_cache"
                and row["placement"] == "after_cache_expiry"
            )["false_allow"]
            and next(
                row
                for row in rows
                if row["profile"] == "single_read"
                and row["placement"] == "after_cache_expiry"
            )["false_allow"]
            and profile_summary["ttl_cache"]["cache_hits"] > 0
        ),
        "http_round_trip_ns": {
            "median": round(statistics.median(latencies)),
            "p95": percentile(latencies, 0.95),
            "maximum": max(latencies),
            "descriptive_only": True,
        },
        "claim_boundary": (
            "live local concurrency and signed status responses; not a "
            "multi-host, Internet-scale, conformance, or performance claim"
        ),
        "results": rows,
    }
    output["all_passed"] = (
        output["all_status_signatures_verified"]
        and output["atomic_guard_zero_safety_errors"]
        and output["incomplete_profiles_expose_false_allow"]
        and output["ttl_profile_is_behaviorally_distinct"]
    )
    RESULTS.write_text(
        json.dumps(output, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    SUMMARY.write_text(
        "# Live revocation-service race results\n\n"
        f"- Executed cases: **{len(rows)}**\n"
        f"- Same-barrier trials: **{SIMULTANEOUS_TRIALS} per profile**\n"
        f"- TTL cache: **{TTL_CACHE_NS / 1_000_000:.0f} ms**; forced-expiry "
        f"delay: **{TTL_EXPIRY_DELAY_S * 1000:.0f} ms**\n"
        f"- Signed traces verified: **{sum(row['all_signatures_verified'] for row in rows)}/{len(rows)}**\n"
        f"- Persisted signed responses: **{signed_response_count}**\n"
        "- Safety errors (false allow / false deny):\n"
        + "".join(
            f"  - `{profile}`: "
            f"**{profile_summary[profile]['false_allows']} / "
            f"{profile_summary[profile]['false_denies']}**\n"
            for profile in profiles
        )
        + "- Boundary: live local HTTP concurrency; not multi-host or a "
        "performance claim.\n",
        encoding="utf-8",
    )
    manifest_names = (
        "README.md",
        "run_live_races.py",
        "verify_saved_results.py",
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
