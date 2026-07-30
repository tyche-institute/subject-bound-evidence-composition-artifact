# Research factory v4 — empirical flagship r5

**Status: internal preprint and executable benchmark. Submission decision:
NO-GO.** No submission, upload, deposit, DOI, public release, editor contact,
email, or repository push is authorized or has occurred.

## Primary outputs

- `preprint-03-valid-artifacts-accountable-decisions-r5-2026-07-28.md`
- `preprint-03-valid-artifacts-accountable-decisions-r5-2026-07-28.pdf`
- `jair-prototype-2026-07-27/main.pdf`
- `jair-prototype-2026-07-27/JAIR-submission-answers-r5-2026-07-28.md`
- `intellectual-neighbours-r4-2026-07-27.md`
- `referee-report-r5-jair-2026-07-28.md`
- `submission-readiness.md`
- `release-capsule-r5-2026-07-28.md`
- `five-of-five-closure-matrix-2026-07-28.md`
- `external-five-of-five-dispatch-index-2026-07-28.md`
- `release-preparation-2026-07-28/`

The r1--r4 files are retained as historical revisions, not current claims.
The final local Hermes editorial panel parsed 3/3 model responses against the
frozen r5 digest; its synthesis is
`labs/hermes-referee-panel/PANEL-SYNTHESIS.md`. It is not external review.

## Scientific spine

The paper tests one proposition:

> Valid local artifacts do not compose into a subject-bound delegated-AI
> decision unless their subject projections are explicitly bound and
> revocable authority remains valid at effect commit.

Three core laboratories share a frozen transaction vocabulary:

1. policy-version/evidence replay tests exact policy applicability, signature,
   tamper, substitution, and replay semantics;
2. SAFE metric metamorphics tests aggregation geometry, severity,
   perturbation, bootstrap uncertainty, overlap, TOPSIS reference sets, and
   poisoning;
3. the 104-transaction corpus joins policy, evidence, runtime state,
   authority, measurement, and cross-artifact binding; an overlay replaces
   the source structural state appraisal with native TPM2 evidence for every
   transaction.

Companion laboratories stress native authority, single- and multi-fault
mutation, scheduled revocation, corpus-wide TPM appraisal, and concurrent
revocation through separate durable services. A transfer lab maps both the
104-case corpus and a pinned public EATF verifier result without discarding
native rejection codes, then challenges every mapping entry through SQLite.

## Executed results

| Lane | Result | Claim ceiling |
| --- | --- | --- |
| Policy replay | 16/16 typed outcomes | Designed signed-object fixtures |
| SAFE metamorphics | 9 implementation identities + 6 informative relations | Frozen internal laboratory |
| Composed corpus | 104 cases; 15 allow, 89 deny; 8 all-local-pass binding denials | Coverage, not deployed rates |
| Weak ablations | 2 / 31 / 48 false allows | Designed-corpus diagnostics |
| Partial subject joins | 3 / 2 / 1 false allows; full implemented join 0 | Effect/resource/time/profile only; schema remains partial |
| Standalone finite model check | 2/2 Boolean-composer cases; 16/16 binding states; 6/6 one-read and 4/4 two-read schedules | Exhaustive only for the declared finite models |
| Native signed authority | 8/8 exact verdict/first gate | Tyche profile, not external conformance |
| Single-fault mutation | 38/38 oracle pairs; 570/570 typed fields | Internal operators/oracle |
| Multi-fault mutation | 12/12 oracle pairs; 180/180 typed fields | Internal precedence fixtures |
| Scheduled revocation | 13/13 exact Python/JavaScript rows | Scheduled, not concurrent |
| Native runtime appraisal | 7/7; four native TPM negatives plus two binding-precheck negatives rejected | One frozen `swtpm` vector |
| Live revocation service | 276 signed traces and 890 persisted signed responses; atomic guard 0 false allow/deny | Local safety, not distributed performance |
| Native state overlay | 104/104 state classes; 64/64 mutation rejects; 104/104 recompositions; independent compiled Java path 19/19 assertions; 8 distinct RSA/ECC AKs | Two implementations, but software TPM and one x86_64 host |
| Durable revocation services | 372 cases; 1,478 events; 96/96 fault recoveries; 0 duplicates; atomic guard 0/0 | Separate processes, but one host and centralized SQLite |
| Containerized durable revocation | 5 containers; 135 decisions; 540 signed responses; 4/4 fault recoveries; atomic false allows 0; duplicate decisions/effects 0 | Separate instances and bridge, but one physical host and shared SQLite volume |
| Typed EATF transfer | 21/21 first-party two-language rows + 104/104 transaction rows; SQL 125/125 and all 46 mutation/omission challenges; sealed blind 46-task semantic-validation kit | Analytic author-defined crosswalk; semantic kit undispatched |
| Neutral labelling packet | 104/104 tuples preserved; no known mnemonic leak; frozen analysis pipeline self-test PASS | Undispatched, no external labels |
| Portable source capsule | 210/210 members verified; clean temporary extraction PASS with hash-bound JSON and full log | Prepared only; same x86_64 host, no second-host/architecture run |
| Offline rerun | PASS with empty route and outbound `ENETUNREACH` | Different userland, same physical host |

## Figures

`figures/` contains thirteen deterministic monochrome-compatible figures in
PDF, PNG, and SVG. Figures I, J, and K report the live revocation,
typed-state transfer and partial-binding ablation; Figures L and M report the
r5 evidence-class upgrades and container trust boundaries. Verify
`SHA256SUMS`, `SHA256SUMS-r4`, and `SHA256SUMS-r5` from inside
that directory.

## Entry points

```bash
# Core laboratories
labs/policy-version-evidence-replay/run.sh
labs/composed-transaction-corpus/run.sh
labs/prospective-revocation-races/run.sh
labs/formal-composition-modelcheck/run.sh

# r4/r5 laboratories
python3 labs/native-runtime-attestation/verify_runtime_attestation.py
labs/native-state-transaction-overlay/run.sh
python3 labs/live-revocation-service/run_live_races.py
labs/distributed-revocation-service/run.sh
labs/containerized-durable-revocation/run.sh
python3 labs/cross-ecosystem-typed-transfer/build_transfer.py
python3 labs/cross-ecosystem-typed-transfer/verify_crosswalk_sql.py
python3 external-label-packet-neutral-104/build_neutral_packet.py
python3 external-label-packet-neutral-104/analyze_responses.py --self-test
python3 release-preparation-2026-07-28/crosswalk-semantic-validation/validate_semantic_response.py --self-test
python3 repro/verify_portable_source_capsule.py
python3 repro/run_clean_capsule_replay.py

# Figures
(cd figures && python3 make_r4_figures.py)
(cd figures && python3 make_r5_figures.py)
(cd figures && python3 make_container_topology_figure.py)

# Local-model editorial red team (not external review)
(cd labs/hermes-referee-panel && python3 run_panel.py)

# JAIR prototype
(cd jair-prototype-2026-07-27 && ./build.sh)

# Deterministic internal PDF
./build_internal_pdf.sh

# Root integrity manifest
python3 make_manifest.py
python3 make_manifest.py --check
```

The native-authority and mutation sources also consume the sibling
`../../zeus-followup-2026-07-27/` tree. The SAFE laboratory remains frozen in
`../research-factory-v3-2026-07-25/`. The cross-ecosystem transfer consumes
field-minimized local snapshots, verifies their hashes before parsing, and
retains the frozen upstream source hashes and EATF commit as provenance.

## Open gates

- no external labelling or adjudication has occurred;
- no genuinely independent physical-host replay exists;
- the native TPM roots are software-backed and all live services are
  same-host loopback;
- release metadata, SBOM, RO-Crate, rights inventory, hostile-replay protocol
  and licence proposals are prepared, but no immutable public artifact, DOI,
  or author-approved licence exists;
- authorship, affiliations, declarations, and release decision are pending;
- active blind-work governance prevents public release.

Read `submission-readiness.md` before any dissemination action.
