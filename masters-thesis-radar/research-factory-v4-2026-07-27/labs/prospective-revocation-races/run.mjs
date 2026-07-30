#!/usr/bin/env node
/* Independent Node evaluator for the Tyche signed revocation-race profile. */

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const packet = JSON.parse(fs.readFileSync(path.join(here, "corpus.json"), "utf8"));

function canonical(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`)
    .join(",")}}`;
}

function keyFromSpki(encoded) {
  return crypto.createPublicKey({
    key: Buffer.from(encoded, "base64"),
    format: "der",
    type: "spki",
  });
}

const credentialKey = keyFromSpki(
  packet.public_keys.credential_authority_spki_b64,
);
const statusKey = keyFromSpki(packet.public_keys.status_authority_spki_b64);

function verifySigned(item, publicKey) {
  const unsigned = Object.fromEntries(
    Object.entries(item).filter(([key]) => key !== "signature_b64"),
  );
  return crypto.verify(
    null,
    Buffer.from(canonical(unsigned), "utf8"),
    publicKey,
    Buffer.from(item.signature_b64, "base64"),
  );
}

function outcome(caseId, verdict, gate) {
  return { case_id: caseId, verdict, first_rejecting_gate: gate };
}

function snapshotGate(item, prefix, credentialId, decisionTime, maxAge) {
  if (item === null) return `${prefix}.status.available`;
  if (!verifySigned(item, statusKey)) return `${prefix}.status.signature`;
  if (!(credentialId in item.states)) return `${prefix}.status.binding`;
  const age = decisionTime - item.issued_at;
  if (age < 0 || age > maxAge) return `${prefix}.status.freshness`;
  if (item.states[credentialId] !== "active") return `${prefix}.status.active`;
  return null;
}

function evaluateStrict(item) {
  const credential = item.credential;
  if (!verifySigned(credential, credentialKey)) {
    return outcome(item.case_id, "DENY", "credential.signature");
  }
  if (
    !(
      credential.valid_from <= item.appraisal_time &&
      item.appraisal_time < credential.valid_until &&
      credential.valid_from <= item.commit_time &&
      item.commit_time < credential.valid_until
    )
  ) {
    return outcome(item.case_id, "DENY", "credential.window");
  }
  const credentialId = credential.credential_id;
  const appraisalGate = snapshotGate(
    item.appraisal_snapshot,
    "appraisal",
    credentialId,
    item.appraisal_time,
    item.max_snapshot_age,
  );
  if (appraisalGate) return outcome(item.case_id, "DENY", appraisalGate);
  const commitGate = snapshotGate(
    item.commit_snapshot,
    "commit",
    credentialId,
    item.commit_time,
    item.max_snapshot_age,
  );
  if (commitGate) return outcome(item.case_id, "DENY", commitGate);
  if (item.commit_snapshot.sequence < item.appraisal_snapshot.sequence) {
    return outcome(item.case_id, "DENY", "commit.status.monotonic");
  }
  return outcome(item.case_id, "ALLOW", "verified");
}

function appraisalOnly(item) {
  const reduced = {
    ...item,
    commit_time: item.appraisal_time,
    commit_snapshot: item.appraisal_snapshot,
  };
  return evaluateStrict(reduced).verdict;
}

function commitFailOpen(item) {
  if (item.commit_snapshot !== null) return evaluateStrict(item).verdict;
  const fabricated = {
    ...item,
    commit_time: item.appraisal_time,
    commit_snapshot: item.appraisal_snapshot,
  };
  return evaluateStrict(fabricated).verdict;
}

function timestampOnly(item) {
  const strict = evaluateStrict(item);
  return strict.first_rejecting_gate === "commit.status.monotonic"
    ? "ALLOW"
    : strict.verdict;
}

const rows = packet.cases.map((item) => ({
  ...evaluateStrict(item),
  expected_verdict: item.expected.verdict,
  expected_gate: item.expected.first_rejecting_gate,
  baselines: {
    appraisal_only: appraisalOnly(item),
    commit_fail_open: commitFailOpen(item),
    timestamp_only: timestampOnly(item),
  },
}));

fs.writeFileSync(
  path.join(here, "js-results.json"),
  `${JSON.stringify(rows, null, 2)}\n`,
);
process.stdout.write(`${JSON.stringify({ implementation: "node", cases: rows.length })}\n`);
