#!/usr/bin/env python3
"""Separate durable status/effect HTTP services for revocation experiments."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sqlite3
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


KEY_SEED = hashlib.sha256(
    b"tyche-distributed-revocation-service-v1"
).digest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEY_SEED)


class Store:
    def __init__(self, path: Path) -> None:
        self.path = path

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize_schema(self) -> None:
        with self.connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode=WAL;
                CREATE TABLE IF NOT EXISTS credentials (
                    credential_id TEXT PRIMARY KEY,
                    status TEXT NOT NULL,
                    sequence INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS events (
                    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    credential_id TEXT NOT NULL,
                    service TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    status_at_linearization TEXT NOT NULL,
                    sequence INTEGER NOT NULL,
                    effect_committed INTEGER,
                    idempotency_key TEXT,
                    process_id INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS effects (
                    idempotency_key TEXT PRIMARY KEY,
                    credential_id TEXT NOT NULL,
                    event_id INTEGER NOT NULL REFERENCES events(event_id)
                );
                """
            )

    @staticmethod
    def event_payload(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "linearization_index": row["event_id"],
            "credential_id": row["credential_id"],
            "service": row["service"],
            "operation": row["operation"],
            "status": row["status_at_linearization"],
            "sequence": row["sequence"],
            "effect_committed": (
                None
                if row["effect_committed"] is None
                else bool(row["effect_committed"])
            ),
            "idempotency_key": row["idempotency_key"],
            "service_process_id": row["process_id"],
        }

    def _credential(
        self, connection: sqlite3.Connection, credential_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM credentials WHERE credential_id=?",
            (credential_id,),
        ).fetchone()
        if row is None:
            raise KeyError(credential_id)
        return row

    def initialize(self, credential_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO credentials(credential_id,status,sequence)
                VALUES(?, 'active', 1)
                """,
                (credential_id,),
            )
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,operation,status_at_linearization,
                    sequence,effect_committed,idempotency_key,process_id
                ) VALUES(?, 'status', 'initialize', 'active', 1, NULL, NULL, ?)
                RETURNING *
                """,
                (credential_id, os.getpid()),
            ).fetchone()
            connection.commit()
            return self.event_payload(row)

    def status(self, credential_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._credential(connection, credential_id)
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,operation,status_at_linearization,
                    sequence,effect_committed,idempotency_key,process_id
                ) VALUES(?, 'status', 'status_read', ?, ?, NULL, NULL, ?)
                RETURNING *
                """,
                (
                    credential_id,
                    item["status"],
                    item["sequence"],
                    os.getpid(),
                ),
            ).fetchone()
            connection.commit()
            return self.event_payload(row)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self._credential(connection, credential_id)
            sequence = item["sequence"]
            if item["status"] != "revoked":
                sequence += 1
                connection.execute(
                    """
                    UPDATE credentials SET status='revoked', sequence=?
                    WHERE credential_id=?
                    """,
                    (sequence, credential_id),
                )
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,operation,status_at_linearization,
                    sequence,effect_committed,idempotency_key,process_id
                ) VALUES(?, 'status', 'revoke', 'revoked', ?, NULL, NULL, ?)
                RETURNING *
                """,
                (credential_id, sequence, os.getpid()),
            ).fetchone()
            connection.commit()
            return self.event_payload(row)

    def commit(
        self,
        credential_id: str,
        idempotency_key: str,
        guarded: bool,
    ) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute(
                """
                SELECT e.* FROM effects x
                JOIN events e ON e.event_id=x.event_id
                WHERE x.idempotency_key=?
                """,
                (idempotency_key,),
            ).fetchone()
            if prior is not None:
                connection.commit()
                payload = self.event_payload(prior)
                payload["idempotent_replay"] = True
                payload["replay_service_process_id"] = os.getpid()
                return payload
            item = self._credential(connection, credential_id)
            committed = (item["status"] == "active") if guarded else True
            operation = "guarded_commit" if guarded else "unguarded_commit"
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,operation,status_at_linearization,
                    sequence,effect_committed,idempotency_key,process_id
                ) VALUES(?, 'effect', ?, ?, ?, ?, ?, ?)
                RETURNING *
                """,
                (
                    credential_id,
                    operation,
                    item["status"],
                    item["sequence"],
                    int(committed),
                    idempotency_key,
                    os.getpid(),
                ),
            ).fetchone()
            if committed:
                connection.execute(
                    """
                    INSERT INTO effects(idempotency_key,credential_id,event_id)
                    VALUES(?,?,?)
                    """,
                    (idempotency_key, credential_id, row["event_id"]),
                )
            connection.commit()
            payload = self.event_payload(row)
            payload["idempotent_replay"] = False
            return payload


class ReusableServer(ThreadingHTTPServer):
    allow_reuse_address = True
    daemon_threads = True


def handler_for(service: str, store: Store) -> type[BaseHTTPRequestHandler]:
    key = private_key()

    class Handler(BaseHTTPRequestHandler):
        server_version = "TycheDurableRevocation/2.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def send_value(self, payload: dict[str, Any], status: int = 200) -> None:
            signed = dict(payload)
            signed["signature"] = base64.b64encode(
                key.sign(canonical(payload))
            ).decode("ascii")
            body = canonical(signed)
            try:
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # Expected in the drop-after-request fault: the durable
                # transaction remains the oracle even when delivery fails.
                return

        def query(self) -> dict[str, list[str]]:
            return urllib.parse.parse_qs(
                urllib.parse.urlparse(self.path).query
            )

        def do_GET(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            if path == "/health":
                self.send_value(
                    {"service": service, "healthy": True, "pid": os.getpid()}
                )
                return
            if service != "status" or path != "/status":
                self.send_value({"error": "not_found"}, 404)
                return
            try:
                self.send_value(store.status(self.query()["credential_id"][0]))
            except KeyError:
                self.send_value({"error": "unknown_credential"}, 404)

        def do_POST(self) -> None:
            path = urllib.parse.urlparse(self.path).path
            query = self.query()
            try:
                credential_id = query["credential_id"][0]
                if service == "status" and path == "/initialize":
                    value = store.initialize(credential_id)
                elif service == "status" and path == "/revoke":
                    value = store.revoke(credential_id)
                elif service == "effect" and path in (
                    "/guarded-commit",
                    "/unguarded-commit",
                ):
                    value = store.commit(
                        credential_id,
                        query["idempotency_key"][0],
                        guarded=path == "/guarded-commit",
                    )
                else:
                    self.send_value({"error": "not_found"}, 404)
                    return
                self.send_value(value)
            except KeyError:
                self.send_value({"error": "bad_request"}, 400)
            except sqlite3.IntegrityError:
                self.send_value({"error": "already_initialized"}, 409)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", choices=("status", "effect"), required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()
    store = Store(args.database)
    store.initialize_schema()
    server = ReusableServer(
        ("127.0.0.1", args.port), handler_for(args.service, store)
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
