# r5 release capsule — internal candidate plan

Status: **PREPARED LOCALLY, NOT AUTHORIZED, NOT LICENSED, NOT PUBLIC**

No submission, upload, DOI, repository push, public preprint, or external
dispatch is performed by this plan.

## Candidate evidence set

- r5 Markdown, internal PDF, JAIR LaTeX source, and JAIR PDF;
- all twelve figure sources and rendered forms;
- Policy-State Replay, SAFE Metric Metamorphics, and the frozen
  State–Authority–Measurement transaction corpus;
- the 104-transaction native state overlay, eight software-TPM roots, 64
  mutations, saved verdicts, Python verifier, independent compiled Java
  verifier, and checksum manifests;
- the dependency-free finite Java model checker and exhaustive bounded results;
- the 372-case process-isolated durable revocation lab, durable event/effect
  results, signatures, stored-result verifier, and checksum manifest;
- the five-container 135-case durable revocation replay, two effect instances,
  fault proxy, 540 signed responses and a separate saved-result verifier;
- the typed-transfer builder plus separate SQLite audit and all
  wrong-class/omission mutations;
- the neutral 104-case annotator archive, separately held coordinator archive,
  response validator, and author-label-blind agreement pipeline;
- the sealed 46-task blind semantic-crosswalk kit and its coordinator-side
  response validator;
- the no-grant release-preparation packet: rights inventory, proposed licence
  split, draft CFF/CodeMeta/Zenodo metadata, SBOM, RO-Crate and hostile-replay
  protocol;
- the locally validated, undispatched x64/ARM64 hosted-runner workflow and
  semantic comparison contract;
- the portable second-host source capsule:
  `repro/tyche-second-host-source-capsule-2026-07-28.tar.gz`,
  SHA-256
  `8c8919f9826381da289b73dfd35721938ad5aafea5cd3687b23187589a2d0386`;
- environment records, exact manifests, build commands, and claim-boundary
  documents.

The portable archive has 210 members, is 22.1 MB, embeds exact V4, V3 SAFE,
and boundary-seal sources, and includes an offline CPython 3.12 Linux/amd64
wheelhouse. It passes member/path/hash validation. A clean temporary extraction
on `redacted-local-host` reran `run.sh` with exit code 0; the archive hash, runner
hash, environment, sentinel, timestamps and outcome are frozen in
`repro/CAPSULE-CLEAN-REPLAY-2026-07-28.json`, with full stdout/stderr in the
companion log. This is **same-host capsule preparation**, not a second-host
result.

## Required additions before release

1. Confirm real authors, order, affiliations, ORCIDs, CRediT roles, funding,
   conflicts, acknowledgements, and AI-assistance disclosure.
2. Decide and approve compatible source, data, figure, manuscript, and
   third-party licences; add the umbrella licence files and notices.
3. Reconcile the active blind-work/publication hold.
4. Complete or explicitly remove any submission claim requiring external
   human labels.
5. Execute the exact archive on another physical host/architecture with a
   different operator, save its signed host record and outputs, and compare
   them under the declared deterministic/nondeterministic policy.
6. Replace the prepared metadata placeholders with confirmed authors,
   licences, repository and version identifiers; regenerate the SBOM and
   RO-Crate over the exact final release tree.
7. Build a sanitized release tree and regenerate one final manifest from that
   tree, not from the mutable working directory.
8. After authorization, deposit the versioned artifacts and preprint under
   immutable identifiers; then commission independent hostile replay from the
   deposited archive.

## Architecture note

The bundled wheelhouse is Linux/amd64. A second-host `aarch64` run must use an
equally pinned architecture-specific wheelhouse and record its hashes; silently
falling back to the network would not satisfy the clean-replay claim.

## Acceptance test

```text
verify archive and every nested manifest
→ clean-extract on the independent host
→ execute deterministic core, finite model, SAFE, SQL, native-state, and durable-revocation checks
→ regenerate the twelve figures and both PDFs
→ compare deterministic outputs byte-for-byte
→ check declared invariants for scheduling-dependent experiments
→ reproduce from the immutable licensed public archive
```

Release readiness is false until every external and governance step above is
recorded as an event with exact artifacts and hashes.
