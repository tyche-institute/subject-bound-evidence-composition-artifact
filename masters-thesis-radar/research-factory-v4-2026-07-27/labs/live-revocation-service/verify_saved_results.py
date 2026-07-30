#!/usr/bin/env python3
"""Reverify persisted signatures and safety labels without running the server."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


HERE = Path(__file__).resolve().parent


def canonical(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def main() -> int:
    result = json.loads((HERE / "results.json").read_text(encoding="utf-8"))
    public_key = Ed25519PublicKey.from_public_bytes(
        base64.b64decode(
            result["status_public_key_raw_b64"], validate=True
        )
    )
    response_count = 0
    label_matches = 0
    for row in result["results"]:
        for signed in row["signed_responses"]:
            public_key.verify(
                base64.b64decode(signed["signature_b64"], validate=True),
                canonical(signed["payload"]),
            )
            response_count += 1
        effect = next(
            (
                event
                for event in row["event_order"]
                if event["operation"] in {"guarded_commit", "unguarded_commit"}
            ),
            None,
        )
        if effect is None:
            oracle_accept = row["event_order"][-1]["status"] == "active"
        else:
            oracle_accept = effect["status"] == "active"
        expected_false_allow = row["accepted"] and not oracle_accept
        expected_false_deny = not row["accepted"] and oracle_accept
        if (
            row["oracle_accept_at_effect"] == oracle_accept
            and row["false_allow"] == expected_false_allow
            and row["false_deny"] == expected_false_deny
        ):
            label_matches += 1

    assert response_count == result["signed_responses"]
    assert label_matches == result["cases"]
    print(
        json.dumps(
            {
                "persisted_signatures_verified": response_count,
                "safety_labels_recomputed": label_matches,
                "all_passed": True,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
