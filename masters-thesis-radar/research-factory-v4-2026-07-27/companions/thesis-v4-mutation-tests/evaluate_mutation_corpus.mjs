#!/usr/bin/env node
/*
 * Independent JavaScript implementation of LABELLING-SPEC.md v1.0.
 *
 * Inputs are limited to the labeller-facing specification packet. This file
 * imports no research-program evaluator code and contains no reference labels.
 */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packetPath = path.join(here, "mutation-packet.json");
const outputPath = path.join(here, "js-results.json");
const layerPath = path.join(here, "js-layer-results.json");

function canonical(value, profileFloatConvention = false, parentKey = "") {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("non-finite JSON number");
    if (
      profileFloatConvention &&
      Number.isInteger(value) &&
      (parentKey === "severity_grid" || parentKey === "zero_anchor")
    ) {
      return `${value}.0`;
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    return `[${value
      .map((item) => canonical(item, profileFloatConvention, parentKey))
      .join(",")}]`;
  }
  const keys = Object.keys(value).sort();
  return `{${keys
    .map(
      (key) =>
        `${JSON.stringify(key)}:${canonical(
          value[key],
          profileFloatConvention,
          key,
        )}`,
    )
    .join(",")}}`;
}

function unsigned(object) {
  const copy = structuredClone(object);
  delete copy.signature;
  return copy;
}

function digestObject(object, profileFloatConvention = false) {
  return `sha256:${crypto
    .createHash("sha256")
    .update(canonical(unsigned(object), profileFloatConvention), "utf8")
    .digest("hex")}`;
}

function publicKeyFromRaw(base64) {
  const raw = Buffer.from(base64, "base64");
  if (raw.length !== 32) throw new Error(`Ed25519 key length ${raw.length}`);
  const spkiPrefix = Buffer.from("302a300506032b6570032100", "hex");
  return crypto.createPublicKey({
    key: Buffer.concat([spkiPrefix, raw]),
    format: "der",
    type: "spki",
  });
}

function validSignature(object, publicKey) {
  if (
    object === null ||
    typeof object !== "object" ||
    typeof object.signature !== "string"
  ) {
    return false;
  }
  let signature;
  try {
    signature = Buffer.from(object.signature, "base64");
  } catch {
    return false;
  }
  if (signature.length !== 64) return false;
  try {
    return crypto.verify(
      null,
      Buffer.from(canonical(unsigned(object)), "utf8"),
      publicKey,
      signature,
    );
  } catch {
    return false;
  }
}

function inInclusiveWindow(value, lower, upper) {
  return (
    typeof value === "string" &&
    typeof lower === "string" &&
    typeof upper === "string" &&
    lower <= value &&
    value <= upper
  );
}

function policyLayer(policy, shared, publicKey) {
  const anchor = shared.policy_anchor;
  const decisionTime = shared.decision_time;
  if (policy === null) return ["MISSING", "policy.missing", "P1"];
  if (!validSignature(policy, publicKey)) {
    return ["INVALID_SIGNATURE", "policy.signature", "P2"];
  }
  if (policy.policy_id !== anchor.required_policy_id) {
    return ["SUBSTITUTED", "policy.substituted", "P3"];
  }
  if (
    policy.version !== anchor.required_policy_version ||
    !inInclusiveWindow(decisionTime, policy.valid_from, policy.valid_until)
  ) {
    return ["STALE", "policy.stale", "P4"];
  }
  if (digestObject(policy) !== anchor.required_policy_digest) {
    return ["SUBSTITUTED", "policy.substituted", "P5"];
  }
  return ["PASS", null, "P1-P5"];
}

function evidenceLayer(evidence, shared, publicKey) {
  if (!validSignature(evidence, publicKey)) {
    return ["TAMPERED", "evidence.integrity", "E1"];
  }
  if (shared.preseen_nonces.includes(evidence.nonce)) {
    return ["REPLAY", "evidence.replay", "E2"];
  }
  return ["PASS", null, "E1-E2"];
}

function stateLayer(state, decisionTime) {
  if (state?.status !== "affirming") {
    return ["CONTRAINDICATED", "state.contraindicated", "S1"];
  }
  if (
    !inInclusiveWindow(decisionTime, state.issued_at, state.expires_at)
  ) {
    return ["STALE", "state.stale", "S2"];
  }
  if (
    typeof state.reference_digest !== "string" ||
    state.reference_digest.length === 0 ||
    state.observed_digest !== state.reference_digest
  ) {
    return ["REFERENCE_MISMATCH", "state.reference", "S3"];
  }
  return ["PASS", null, "S1-S3"];
}

function isSubset(child, parent) {
  if (!Array.isArray(child) || !Array.isArray(parent)) return false;
  const parentSet = new Set(parent.map((item) => canonical(item)));
  return child.every((item) => parentSet.has(canonical(item)));
}

function authorityLayer(authority, shared) {
  if (authority.protocol_valid !== true) {
    return ["DENY", "protocol.valid", "A0"];
  }
  let principal = shared.root_principal;
  let role = shared.root_role;
  let scope = structuredClone(shared.root_scope);
  for (let index = 0; index < authority.edges.length; index += 1) {
    const edge = authority.edges[index];
    if (edge.delegator !== principal || edge.from_role !== role) {
      return ["DENY", "edge.lineage", `A1:${index}`];
    }
    if (edge.issuer_signature_valid !== true) {
      return ["DENY", "edge.signature", `A2:${index}`];
    }
    if (index > 0 && scope.delegable !== true) {
      return ["DENY", "edge.parent_delegable", `A3:${index}`];
    }
    const transitions = shared.allowed_role_transitions[role] ?? [];
    if (!transitions.includes(edge.to_role)) {
      return ["DENY", "edge.role_transition", `A4:${index}`];
    }
    if (edge.status !== "active") {
      return ["DENY", "edge.status", `A5:${index}`];
    }
    if (
      !inInclusiveWindow(
        shared.effect_time,
        edge.not_before,
        edge.expires_at,
      )
    ) {
      return ["DENY", "edge.freshness", `A6:${index}`];
    }
    for (const field of [
      "operations",
      "resources",
      "tools",
      "audiences",
      "purposes",
    ]) {
      if (!isSubset(edge.grant[field], scope[field])) {
        return ["DENY", `edge.scope.${field}`, `A7:${index}`];
      }
    }
    if (edge.grant.currency !== scope.currency) {
      return ["DENY", "edge.scope.currency", `A8:${index}`];
    }
    if (
      typeof edge.grant.amount_max !== "number" ||
      typeof scope.amount_max !== "number" ||
      edge.grant.amount_max > scope.amount_max
    ) {
      return ["DENY", "edge.scope.amount_max", `A9:${index}`];
    }
    principal = edge.delegate;
    role = edge.to_role;
    scope = structuredClone(edge.grant);
  }

  const action = authority.action;
  if (action.subject !== principal || action.role !== role) {
    return ["DENY", "action.subject_role", "A10"];
  }
  for (const [field, gate] of [
    ["operation", "action.operation"],
    ["resource", "action.resource"],
    ["tool", "action.tool"],
    ["audience", "action.audience"],
    ["purpose", "action.purpose"],
  ]) {
    const plural = `${field}s`;
    if (!Array.isArray(scope[plural]) || !scope[plural].includes(action[field])) {
      return ["DENY", gate, `A${11 + ["operation", "resource", "tool", "audience", "purpose"].indexOf(field)}`];
    }
  }
  if (
    action.currency !== scope.currency ||
    typeof action.amount !== "number" ||
    action.amount > scope.amount_max
  ) {
    return ["DENY", "action.amount_currency", "A16"];
  }
  const receipt = authority.receipt;
  if (receipt.native_evidence_valid !== true) {
    return ["DENY", "effect.native_validity", "A17"];
  }
  if (receipt.effect_time !== shared.effect_time) {
    return ["DENY", "effect.time_binding", "A18"];
  }
  if (canonical(receipt.action) !== canonical(action)) {
    return ["DENY", "effect.action_binding", "A19"];
  }
  return ["ALLOW", null, "A0-A19"];
}

function flattenMean(rows) {
  let total = 0;
  let count = 0;
  for (const row of rows) {
    if (Array.isArray(row)) {
      for (const value of row) {
        total += value;
        count += 1;
      }
    } else {
      total += row;
      count += 1;
    }
  }
  return total / count;
}

function xorshift32(seed) {
  let state = seed >>> 0;
  return () => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) / 4294967296;
  };
}

function quantileLinear(sorted, alpha) {
  const position = (sorted.length - 1) * alpha;
  const lower = Math.floor(position);
  const upper = Math.ceil(position);
  if (lower === upper) return sorted[lower];
  const fraction = position - lower;
  return sorted[lower] * (1 - fraction) + sorted[upper] * fraction;
}

function bootstrapLcb(rows, replicates, seed, alpha) {
  const rng = xorshift32(seed);
  const n = rows.length;
  const means = [];
  for (let replicate = 0; replicate < replicates; replicate += 1) {
    const sampled = [];
    for (let index = 0; index < n; index += 1) {
      sampled.push(rows[Math.floor(rng() * n)]);
    }
    means.push(flattenMean(sampled));
  }
  means.sort((left, right) => left - right);
  return quantileLinear(means, alpha);
}

function measurementLayer(measurement, shared, cache) {
  const profileDigest = digestObject(measurement.profile, true);
  if (profileDigest !== measurement.required_profile_digest) {
    return ["PROFILE_MISMATCH", "measurement.profile", "M1", {
      profile_digest: profileDigest,
    }];
  }
  const rows = shared.datasets[measurement.dataset];
  if (!Array.isArray(rows)) {
    throw new Error(`missing dataset ${measurement.dataset}`);
  }
  if (!cache.has(measurement.dataset)) {
    const point = flattenMean(rows);
    const lcb = bootstrapLcb(
      rows,
      shared.bootstrap.replicates,
      shared.bootstrap.seed_by_dataset[measurement.dataset],
      measurement.alpha,
    );
    cache.set(measurement.dataset, { point, lcb });
  }
  const values = cache.get(measurement.dataset);
  if (values.point < measurement.threshold) {
    return ["FAIL_POINT", "measurement.point", "M2", values];
  }
  if (values.lcb < measurement.threshold) {
    return ["FAIL_LCB", "measurement.confidence", "M3", values];
  }
  return ["PASS", null, "M1-M3", values];
}

function evaluate(transaction, shared, publicKey, measurementCache) {
  const layers = {
    policy: policyLayer(
      transaction.policy,
      shared.policy_evidence,
      publicKey,
    ),
    evidence: evidenceLayer(
      transaction.evidence,
      shared.policy_evidence,
      publicKey,
    ),
    state: stateLayer(
      transaction.attestation_result,
      shared.state.decision_time,
    ),
    authority: authorityLayer(transaction.authority, shared.authority),
    measurement: measurementLayer(
      transaction.measurement,
      shared.measurement,
      measurementCache,
    ),
  };
  const order = ["policy", "evidence", "state", "authority", "measurement"];
  const passing = {
    policy: "PASS",
    evidence: "PASS",
    state: "PASS",
    authority: "ALLOW",
    measurement: "PASS",
  };
  const first = order.find((name) => layers[name][0] !== passing[name]);
  return {
    transaction_id: transaction.transaction_id,
    verdict: first === undefined ? "ALLOW" : "DENY",
    first_rejecting_gate:
      first === undefined ? "verified" : layers[first][1],
    layers: Object.fromEntries(
      order.map((name) => [
        name,
        {
          result: layers[name][0],
          gate: layers[name][1],
          rule: layers[name][2],
          diagnostics: layers[name][3] ?? null,
        },
      ]),
    ),
  };
}

const packet = JSON.parse(fs.readFileSync(packetPath, "utf8"));
const publicKey = publicKeyFromRaw(
  packet.shared_inputs.policy_evidence.public_key_raw_b64,
);
const measurementCache = new Map();
const evaluations = packet.transactions.map((transaction) =>
  evaluate(transaction, packet.shared_inputs, publicKey, measurementCache),
);
if (evaluations.length !== packet.transactions.length) {
  throw new Error(
    `expected ${packet.transactions.length} transactions, got ${evaluations.length}`,
  );
}
if (
  new Set(evaluations.map((item) => item.transaction_id)).size !==
  evaluations.length
) {
  throw new Error("transaction IDs are not unique");
}

const answers = evaluations.map((item) => ({
  transaction_id: item.transaction_id,
  labeller_id: "mutation-js-v1",
  verdict: item.verdict,
  first_rejecting_gate: item.first_rejecting_gate,
  confidence: 5,
  rationale:
    item.verdict === "ALLOW"
      ? "All five typed layers pass under LABELLING-SPEC.md v1.0."
      : `The first failing layer in fixed composition order rejects at ${item.first_rejecting_gate}.`,
}));

fs.writeFileSync(outputPath, `${JSON.stringify(answers, null, 2)}\n`);
fs.writeFileSync(layerPath, `${JSON.stringify(evaluations, null, 2)}\n`);

const summary = {
  implementation: "mutation-js-v1",
  transactions: answers.length,
  allows: answers.filter((item) => item.verdict === "ALLOW").length,
  denies: answers.filter((item) => item.verdict === "DENY").length,
  gate_counts: Object.fromEntries(
    [...new Set(answers.map((item) => item.first_rejecting_gate))]
      .sort()
      .map((gate) => [
        gate,
        answers.filter((item) => item.first_rejecting_gate === gate).length,
      ]),
  ),
  measurement_diagnostics: Object.fromEntries(measurementCache),
};
process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
