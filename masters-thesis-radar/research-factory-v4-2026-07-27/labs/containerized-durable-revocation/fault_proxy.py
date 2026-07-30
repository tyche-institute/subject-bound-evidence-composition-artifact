#!/usr/bin/env python3
"""Deterministic HTTP fault proxy for effect-service requests."""

from __future__ import annotations

import argparse
import json
import socket
import time
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def handler(upstream: str) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "TycheDeterministicFaultProxy/1.0"

        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            self.forward("GET")

        def do_POST(self) -> None:
            self.forward("POST")

        def disconnect(self) -> None:
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        def forward(self, method: str) -> None:
            parsed = urllib.parse.urlparse(self.path)
            query = urllib.parse.parse_qs(parsed.query)
            fault = query.pop("tyche_fault", ["none"])[0]
            delay_ms = int(query.pop("tyche_delay_ms", ["0"])[0])
            if fault == "drop_before_forward":
                self.disconnect()
                return
            if delay_ms:
                time.sleep(delay_ms / 1000)
            target = upstream + parsed.path
            encoded = urllib.parse.urlencode(
                [(key, item) for key, values in query.items() for item in values]
            )
            if encoded:
                target += "?" + encoded
            request = urllib.request.Request(
                target,
                method=method,
                data=b"" if method == "POST" else None,
            )
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    body = response.read()
                    status = response.status
                    content_type = response.headers.get(
                        "Content-Type", "application/json"
                    )
            except Exception as error:
                body = json.dumps(
                    {"proxy_error": type(error).__name__},
                    sort_keys=True,
                ).encode("utf-8")
                status = 502
                content_type = "application/json"
            if fault == "drop_after_forward":
                self.disconnect()
                return
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8090)
    args = parser.parse_args()
    Server((args.bind, args.port), handler(args.upstream)).serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
