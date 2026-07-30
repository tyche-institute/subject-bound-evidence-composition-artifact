#!/usr/bin/env python3
"""Signed status/effect services backed by one durable SQLite event store."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import socket
import sqlite3
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


KEY_SEED = hashlib.sha256(
    b"tyche-containerized-durable-revocation-v1"
).digest()


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def signing_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(KEY_SEED)


def public_key_b64() -> str:
    return base64.b64encode(
        signing_key()
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode("ascii")


class Store:
    def __init__(self, path: Path, instance_id: str) -> None:
        self.path = path
        self.instance_id = instance_id

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def initialize_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for attempt in range(100):
            try:
                with self.connect() as connection:
                    connection.executescript(
                        """
                        PRAGMA journal_mode=WAL;
                        PRAGMA synchronous=FULL;
                        CREATE TABLE IF NOT EXISTS credentials (
                            credential_id TEXT PRIMARY KEY,
                            status TEXT NOT NULL,
                            sequence INTEGER NOT NULL
                        );
                        CREATE TABLE IF NOT EXISTS events (
                            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                            credential_id TEXT NOT NULL,
                            service TEXT NOT NULL,
                            instance_id TEXT NOT NULL,
                            operation TEXT NOT NULL,
                            status_at_linearization TEXT NOT NULL,
                            sequence INTEGER NOT NULL,
                            effect_committed INTEGER,
                            idempotency_key TEXT
                        );
                        CREATE TABLE IF NOT EXISTS decisions (
                            idempotency_key TEXT PRIMARY KEY,
                            credential_id TEXT NOT NULL,
                            event_id INTEGER NOT NULL REFERENCES events(event_id)
                        );
                        CREATE TABLE IF NOT EXISTS effects (
                            idempotency_key TEXT PRIMARY KEY,
                            credential_id TEXT NOT NULL,
                            event_id INTEGER NOT NULL REFERENCES events(event_id)
                        );
                        """
                    )
                return
            except sqlite3.OperationalError as error:
                if "locked" not in str(error).lower() or attempt == 99:
                    raise
                time.sleep(0.02)

    @staticmethod
    def event_payload(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "linearization_index": row["event_id"],
            "credential_id": row["credential_id"],
            "service": row["service"],
            "original_instance": row["instance_id"],
            "operation": row["operation"],
            "status": row["status_at_linearization"],
            "sequence": row["sequence"],
            "effect_committed": (
                None
                if row["effect_committed"] is None
                else bool(row["effect_committed"])
            ),
            "idempotency_key": row["idempotency_key"],
        }

    @staticmethod
    def credential(
        connection: sqlite3.Connection, credential_id: str
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
                    credential_id,service,instance_id,operation,
                    status_at_linearization,sequence,effect_committed,
                    idempotency_key
                ) VALUES(?, 'status', ?, 'initialize', 'active', 1, NULL, NULL)
                RETURNING *
                """,
                (credential_id, self.instance_id),
            ).fetchone()
            connection.commit()
        return self.event_payload(row)

    def status(self, credential_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self.credential(connection, credential_id)
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,instance_id,operation,
                    status_at_linearization,sequence,effect_committed,
                    idempotency_key
                ) VALUES(?, 'status', ?, 'status_read', ?, ?, NULL, NULL)
                RETURNING *
                """,
                (
                    credential_id,
                    self.instance_id,
                    item["status"],
                    item["sequence"],
                ),
            ).fetchone()
            connection.commit()
        return self.event_payload(row)

    def revoke(self, credential_id: str) -> dict[str, Any]:
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            item = self.credential(connection, credential_id)
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
                    credential_id,service,instance_id,operation,
                    status_at_linearization,sequence,effect_committed,
                    idempotency_key
                ) VALUES(?, 'status', ?, 'revoke', 'revoked', ?, NULL, NULL)
                RETURNING *
                """,
                (credential_id, self.instance_id, sequence),
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
                SELECT e.* FROM decisions d
                JOIN events e ON e.event_id=d.event_id
                WHERE d.idempotency_key=?
                """,
                (idempotency_key,),
            ).fetchone()
            if prior is not None:
                connection.commit()
                payload = self.event_payload(prior)
                payload["idempotent_replay"] = True
                payload["served_by_instance"] = self.instance_id
                return payload

            item = self.credential(connection, credential_id)
            committed = (item["status"] == "active") if guarded else True
            row = connection.execute(
                """
                INSERT INTO events(
                    credential_id,service,instance_id,operation,
                    status_at_linearization,sequence,effect_committed,
                    idempotency_key
                ) VALUES(?, 'effect', ?, ?, ?, ?, ?, ?)
                RETURNING *
                """,
                (
                    credential_id,
                    self.instance_id,
                    "guarded_commit" if guarded else "unguarded_commit",
                    item["status"],
                    item["sequence"],
                    int(committed),
                    idempotency_key,
                ),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO decisions(idempotency_key,credential_id,event_id)
                VALUES(?,?,?)
                """,
                (idempotency_key, credential_id, row["event_id"]),
            )
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
        payload["served_by_instance"] = self.instance_id
        return payload


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def handler(
    service: str, instance_id: str, store: Store
) -> type[BaseHTTPRequestHandler]:
    key = signing_key()
    hostname = socket.gethostname()

    class Handler(BaseHTTPRequestHandler):
        server_version = "TycheContainerRevocation/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def send_signed(
            self, payload: dict[str, Any], status_code: int = 200
        ) -> None:
            signed = dict(payload)
            signed["signature"] = base64.b64encode(
                key.sign(canonical(payload))
            ).decode("ascii")
            body = canonical(signed)
            try:
                self.send_response(status_code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                return

        def parsed(self) -> tuple[str, dict[str, list[str]]]:
            parsed = urllib.parse.urlparse(self.path)
            return parsed.path, urllib.parse.parse_qs(parsed.query)

        def do_GET(self) -> None:
            path, query = self.parsed()
            if path == "/health":
                self.send_signed(
                    {
                        "healthy": True,
                        "service": service,
                        "instance_id": instance_id,
                        "container_hostname": hostname,
                        "process_id": os.getpid(),
                        "public_key_raw_b64": public_key_b64(),
                        "sqlite": sqlite3.sqlite_version,
                    }
                )
                return
            if service != "status" or path != "/status":
                self.send_signed({"error": "not_found"}, 404)
                return
            try:
                self.send_signed(store.status(query["credential_id"][0]))
            except KeyError:
                self.send_signed({"error": "unknown_credential"}, 404)

        def do_POST(self) -> None:
            path, query = self.parsed()
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
                    self.send_signed({"error": "not_found"}, 404)
                    return
                self.send_signed(value)
            except (KeyError, IndexError):
                self.send_signed({"error": "bad_request"}, 400)
            except sqlite3.IntegrityError:
                self.send_signed({"error": "already_initialized"}, 409)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service", choices=("status", "effect"), required=True)
    parser.add_argument("--instance-id", required=True)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args()

    store = Store(args.database, args.instance_id)
    store.initialize_schema()
    server = Server(
        (args.bind, args.port),
        handler(args.service, args.instance_id, store),
    )
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
