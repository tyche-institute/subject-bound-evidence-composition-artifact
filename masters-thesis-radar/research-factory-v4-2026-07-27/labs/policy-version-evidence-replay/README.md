# Policy-Version × Evidence Replay v2

Status: executable signed-object experiment
Date: 2026-07-27 (v2 of the lab formerly named "Policy–State Replay", v1
dated 2026-07-25 in `research-factory-v3-2026-07-25/labs/policy-state-replay`)

## Why the lab was renamed

Review finding **C-04** (claim audit, 2026-07-27): "state" in the v1 lab name
denoted the *policy/evidence state* (`MISSING`/`STALE`/`SUBSTITUTED`), while
the predicate `S` in the composed decision rule denotes *runtime* state — two
different referents sharing one word in the same paper. The lab is now named
**Policy-Version × Evidence Replay** and the word "state" is reserved for the
runtime predicate. Profile string renamed accordingly:
`tyche-policy-state-replay-v1` → `tyche-policy-version-evidence-replay-v2`
(SQL oracle: `…-sql-oracle-v1` → `…-sql-oracle-v2`).

## What changed vs v3, and why

Review findings **C-16** (claim audit) and Referee A (§4 of the full
independent review), implemented as plan item **E5**, identified three
coverage defects in the v1 corpus:

1. the single `stale` vector carried *both* a wrong version (1) *and* an
   expired validity interval, so the version and freshness gates were fused
   and neither was ever isolated;
2. the digest gate in `run.py` was only reachable when identity, version and
   window all pass, which no vector achieved with a differing digest — it was
   **dead code** in that corpus;
3. no vector carried a tampered policy, so policy `INVALID_SIGNATURE` was
   never produced, and the `INVALID_SIGNATURE` branch of `oracle.sql` was
   also dead.

v2 adds **four gate-isolation vectors**, each carrying GOOD evidence and
failing exactly one strict-verifier policy gate:

| id | construction | policy result | first rejecting gate |
| --- | --- | --- | --- |
| `PSR_version_only_good` | correct policy, version 1, ACTIVE interval | `STALE` | `policy.stale` (version alone) |
| `PSR_freshness_only_good` | correct policy, version 2, EXPIRED interval | `STALE` | `policy.stale` (time alone) |
| `PSR_digest_only_good` | correct id/version/interval, one semantic field changed (`required_measurement_profile`), properly signed | `SUBSTITUTED` | `policy.substituted` (digest comparison) |
| `PSR_policy_sig_invalid_good` | correct policy object tampered AFTER signing | `INVALID_SIGNATURE` | `policy.signature` |

For `PSR_digest_only_good` the previously dead digest branch was verified to
fire two ways: (i) the recorded `policy_details` show signature valid,
`policy_id` correct and version correct, so no earlier gate can have
produced `SUBSTITUTED`; (ii) a counterfactual run with the anchor digest set
to this policy's own digest returns `PASS`, proving the digest comparison is
the only rejecting gate. A line-level trace confirmed the digest-comparison
and its `SUBSTITUTED` return in `run.py` execute for this vector.

The **original 12 factorial vectors are unchanged** — same ids, same
content, verified identical (canonical-JSON comparison, 12/12) against the
v3 corpus, including anchor, pre-seen nonces, decision time and public key.
The test-key derivation string deliberately retains the v1 name so those
vectors stay byte-identical.

Corpus hashes:

- v1 corpus SHA-256: `082f60e9655b031bd008525f53740cd74c5b136855f45afe41a2d9a7244c0ca1`
- v2 corpus SHA-256: `8d1925bfe0459dc9f42e554cf63d01adbe801b6c628ff61908bde5f9d9dd45da`

## Question

Does the exact policy version/freshness/digest/signature condition change the
reproducible appraisal of otherwise identical classes of evidence?

The frozen corpus is a 4×3 factorial plus four gate isolations:

```text
policy   ∈ {correct, missing, stale, substituted}      × evidence ∈ {good, tampered, replayed}
plus     {version_only, freshness_only, digest_only, policy_sig_invalid} × {good}
```

This is a standalone Tyche experiment motivated by the recorded Veraison
freshness run. It is **not** a new Veraison execution and does not attribute
fail-open behaviour to Veraison. The previously recorded missing/stale-policy
failures were in Tyche provisioning/harness state.

## Mechanism

- policies and evidence are signed with a deterministic Ed25519 test key;
- a tampered artifact changes a field after signing (evidence in the
  factorial family; the policy itself in `PSR_policy_sig_invalid_good`);
- a replayed artifact has a valid signature but a pre-seen nonce;
- the strict verifier checks policy signature, identity, version, validity
  window and exact digest — and, as of v2, **every one of those gates is
  exercised in isolation by at least one vector**;
- two deliberately weaker baselines check presence only or fail open.

The key is public test material and must not be used outside the corpus.

## Run

```bash
./run.sh
```

`results/` contains the cryptographic and composition verdicts (16 vectors:
strict 16/16 expected matches, 1 allow, 15 denies; presence-only baseline 5
false allows, fail-open baseline 6 false allows).
`results-sql-oracle/` recomposes the verified layer states through a second,
relational code path (16/16 agreement, `policy.signature` branch now live).
The SQL oracle consumes the per-layer results produced by the Python
evaluator; it does not reimplement Ed25519 and is **not independent
validation**.

`result-2026-07-25.md` records the v1 (12-vector) run and is retained as a
historical record; its numbers describe the v1 corpus only.

## Claim ceiling

All expected labels — for the original 12 vectors and the 4 new ones — are
**author-written** programme-internal expectations, not external ground
truth. The experiment can establish a counterexample to treating policy as
ambient, unversioned configuration in this test profile. It cannot
establish:

- a defect in Veraison;
- production prevalence (false-allow counts are counts on a designed
  corpus, not rates);
- sufficiency of the proposed policy passport;
- interoperability or legal validity;
- security against key compromise;
- external independence of expected labels;
- cryptographic attestation of any runtime (structural appraisal of signed
  test objects is not attestation);
- independent validation via the SQL oracle (it recomposes
  Python-produced layer results).

These disclaimers are also embedded in `results/summary.json` and
`results-sql-oracle/summary.json`.
