#!/usr/bin/env python3
"""Evaluate typed 1/2/4-hop delegation paths and localize the first invalid stage."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent
CORPUS_PATH = ROOT / "delegation-paths.json"
RESULTS_DIR = ROOT / "results-delegation-paths"
VERDICTS_PATH = RESULTS_DIR / "verdicts.jsonl"
SUMMARY_PATH = RESULTS_DIR / "summary.json"
EXPANDED_PATH = RESULTS_DIR / "expanded-cases.json"
CHECKSUMS_PATH = RESULTS_DIR / "SHA256SUMS"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_case(base: dict[str, Any], hops: int, effect_time: str) -> dict[str, Any]:
    roles = base["role_path"][:hops]
    edges: list[dict[str, Any]] = []
    delegator = base["root_principal"]
    from_role = base["root_role"]
    for index, to_role in enumerate(roles):
        delegate = f"agent-{index + 1}"
        edges.append(
            {
                "edge_id": f"edge-{index}",
                "delegator": delegator,
                "delegate": delegate,
                "from_role": from_role,
                "to_role": to_role,
                "issuer_signature_valid": True,
                "status": "active",
                "not_before": "2026-07-25T00:00:00Z",
                "expires_at": "2026-07-26T00:00:00Z",
                "grant": copy.deepcopy(base["scope"]),
            }
        )
        delegator = delegate
        from_role = to_role

    action = copy.deepcopy(base["action"])
    action.update({"subject": delegator, "role": from_role})
    receipt = {
        "native_evidence_valid": True,
        "effect_time": effect_time,
        "action": copy.deepcopy(action),
    }
    return {
        "protocol_valid": True,
        "edges": edges,
        "action": action,
        "receipt": receipt,
    }


def apply_mutation(case: dict[str, Any], path: str, value: Any) -> None:
    parts = path.split(".")
    cursor: Any = case
    for part in parts[:-1]:
        cursor = cursor[int(part)] if isinstance(cursor, list) else cursor[part]
    final = parts[-1]
    if isinstance(cursor, list):
        cursor[int(final)] = value
    else:
        cursor[final] = value


def deny(
    gate: str, stage_id: str, stage_index: int, stages: list[dict[str, Any]]
) -> tuple[str, str, str, int, list[dict[str, Any]]]:
    for stage in stages:
        if stage["index"] < stage_index:
            stage["state"] = "PASS"
        elif stage["index"] == stage_index:
            stage["state"] = "DENY"
            stage["gate"] = gate
        else:
            stage["state"] = "NOT_EVALUATED"
    return "DENY", gate, stage_id, stage_index, stages


def evaluate(
    case: dict[str, Any],
    base: dict[str, Any],
    effect_time: str,
) -> tuple[str, str, str | None, int | None, list[dict[str, Any]]]:
    edges = case["edges"]
    stages = [
        {"id": edge["edge_id"], "index": index, "kind": "delegation_edge"}
        for index, edge in enumerate(edges)
    ]
    stages.extend(
        [
            {"id": "action", "index": len(edges), "kind": "action"},
            {"id": "effect", "index": len(edges) + 1, "kind": "effect"},
        ]
    )

    if not case["protocol_valid"]:
        return deny("protocol.valid", "edge-0", 0, stages)

    parent_principal = base["root_principal"]
    parent_role = base["root_role"]
    parent_scope = copy.deepcopy(base["scope"])

    for index, edge in enumerate(edges):
        edge_id = edge["edge_id"]
        if edge["delegator"] != parent_principal or edge["from_role"] != parent_role:
            return deny("edge.lineage", edge_id, index, stages)
        if not edge["issuer_signature_valid"]:
            return deny("edge.signature", edge_id, index, stages)
        if index > 0 and not parent_scope["delegable"]:
            return deny("edge.parent_delegable", edge_id, index, stages)
        allowed_roles = base["allowed_role_transitions"].get(parent_role, [])
        if edge["to_role"] not in allowed_roles:
            return deny("edge.role_transition", edge_id, index, stages)
        if edge["status"] != "active":
            return deny("edge.status", edge_id, index, stages)
        if not (edge["not_before"] <= effect_time <= edge["expires_at"]):
            return deny("edge.freshness", edge_id, index, stages)

        grant = edge["grant"]
        for field in ("operations", "resources", "tools", "audiences", "purposes"):
            if not set(grant[field]).issubset(parent_scope[field]):
                return deny(f"edge.scope.{field}", edge_id, index, stages)
        if grant["currency"] != parent_scope["currency"]:
            return deny("edge.scope.currency", edge_id, index, stages)
        if grant["amount_max"] > parent_scope["amount_max"]:
            return deny("edge.scope.amount_max", edge_id, index, stages)

        parent_principal = edge["delegate"]
        parent_role = edge["to_role"]
        parent_scope = copy.deepcopy(grant)

    action = case["action"]
    action_index = len(edges)
    if action["subject"] != parent_principal or action["role"] != parent_role:
        return deny("action.subject_role", "action", action_index, stages)
    scalar_scope = {
        "operation": "operations",
        "resource": "resources",
        "tool": "tools",
        "audience": "audiences",
        "purpose": "purposes",
    }
    for action_field, scope_field in scalar_scope.items():
        if action[action_field] not in parent_scope[scope_field]:
            return deny(f"action.{action_field}", "action", action_index, stages)
    if (
        action["currency"] != parent_scope["currency"]
        or action["amount"] > parent_scope["amount_max"]
    ):
        return deny("action.amount_currency", "action", action_index, stages)

    receipt = case["receipt"]
    effect_index = len(edges) + 1
    if not receipt["native_evidence_valid"]:
        return deny("effect.native_validity", "effect", effect_index, stages)
    if receipt["effect_time"] != effect_time:
        return deny("effect.time_binding", "effect", effect_index, stages)
    if receipt["action"] != action:
        return deny("effect.action_binding", "effect", effect_index, stages)

    for stage in stages:
        stage["state"] = "PASS"
    return "ALLOW", "verified", None, None, stages


def main() -> int:
    corpus = json.loads(CORPUS_PATH.read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    expanded_cases: list[dict[str, Any]] = []
    for vector in corpus["cases"]:
        case = build_case(corpus["base"], vector["hops"], corpus["effect_time"])
        for mutation in vector["mutations"]:
            apply_mutation(case, mutation["path"], mutation["value"])
        expanded_cases.append(
            {
                "id": vector["id"],
                "hops": vector["hops"],
                "case": case,
                "expected": vector["expected"],
            }
        )
        verdict, gate, bad_id, bad_index, trace = evaluate(
            case, corpus["base"], corpus["effect_time"]
        )
        expected = vector["expected"]
        expected_match = (
            verdict == expected["verdict"]
            and gate == expected["gate"]
            and bad_id == expected["first_bad_edge_id"]
            and bad_index == expected["first_bad_edge_index"]
        )
        trace_order_valid = all(
            stage["state"] == ("PASS" if bad_index is None or stage["index"] < bad_index
                              else "DENY" if stage["index"] == bad_index
                              else "NOT_EVALUATED")
            for stage in trace
        )
        results.append(
            {
                "id": vector["id"],
                "hops": vector["hops"],
                "protocol_flag_true": case["protocol_valid"],
                "native_object_flags_true": all(
                    edge["issuer_signature_valid"] for edge in case["edges"]
                )
                and case["receipt"]["native_evidence_valid"],
                "verdict": verdict,
                "first_rejecting_gate": gate,
                "first_bad_edge_id": bad_id,
                "first_bad_edge_index": bad_index,
                "expected": expected,
                "expected_match": expected_match,
                "trace_order_valid": trace_order_valid,
                "trace": trace,
            }
        )

    negatives = [result for result in results if result["verdict"] == "DENY"]
    # Edge-level localization is counted by the rejecting gate, not by the
    # stage id: the protocol.valid denial pins its stage to "edge-0" by
    # convention, but it is a case-level gate, not an edge appraisal.
    edge_negatives = [
        result
        for result in negatives
        if result["first_rejecting_gate"].startswith("edge.")
    ]
    summary = {
        "profile": corpus["profile"],
        "cases": len(results),
        "positive": sum(result["verdict"] == "ALLOW" for result in results),
        "negative": len(negatives),
        "protocol_flags_true": sum(result["protocol_flag_true"] for result in results),
        "native_object_flags_true": sum(
            result["native_object_flags_true"] for result in results
        ),
        "expected_matches": sum(result["expected_match"] for result in results),
        "first_invalid_stage_matches": sum(
            result["expected_match"] for result in negatives
        ),
        "delegation_edge_matches": sum(
            result["expected_match"] for result in edge_negatives
        ),
        "delegation_edge_cases": len(edge_negatives),
        "trace_order_matches": sum(result["trace_order_valid"] for result in results),
        "hop_lengths": sorted({result["hops"] for result in results}),
        "disclaimer": (
            "issuer_signature_valid, native_evidence_valid and protocol_valid "
            "are corpus-supplied experimental flags; this laboratory performs "
            "no cryptographic verification."
        ),
        "labels_note": (
            "expected labels are author-written within the same research "
            "programme; agreement counts on a designed corpus are coverage "
            "checks, not rates."
        ),
        "corpus_sha256": sha256_file(CORPUS_PATH),
        "verifier_sha256": sha256_file(Path(__file__)),
    }

    RESULTS_DIR.mkdir(exist_ok=True)
    EXPANDED_PATH.write_text(
        json.dumps(
            {
                "profile": corpus["profile"],
                "effect_time": corpus["effect_time"],
                "base": corpus["base"],
                "cases": expanded_cases,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    VERDICTS_PATH.write_text(
        "".join(json.dumps(result, sort_keys=True) + "\n" for result in results),
        encoding="utf-8",
    )
    SUMMARY_PATH.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    CHECKSUMS_PATH.write_text(
        "\n".join(
            [
                f"{sha256_file(VERDICTS_PATH)}  verdicts.jsonl",
                f"{sha256_file(SUMMARY_PATH)}  summary.json",
                f"{sha256_file(EXPANDED_PATH)}  expanded-cases.json",
                f"{sha256_file(CORPUS_PATH)}  ../delegation-paths.json",
                f"{sha256_file(Path(__file__))}  ../verify_delegation_paths.py",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0 if summary["expected_matches"] == summary["cases"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
