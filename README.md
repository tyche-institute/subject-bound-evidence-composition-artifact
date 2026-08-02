# Subject-Bound Evidence Composition for Delegated AI Actions

This repository is the executable public artifact for Anton Sokolov's
empirical study of typed policy, evidence, runtime-state, authority,
measurement, subject-binding, and commit-time revocation.

## Current state

Version `0.2.0-rc4` is a **blind-preserving, sanitized public artifact
release**.
The public artifact repository is
<https://github.com/tyche-institute/subject-bound-evidence-composition-artifact>;
blind study coordination and expected-label material are excluded from it.
The release carries the exact 44-page PDF submitted to JAIR on 2026-08-01
(SHA-256 `8336906cc984c578e9d6fcd160dc45a1b92ad0329e9c666e7cffffa316de73da`)
and can obtain fresh x86-64 and ARM64 hosted-runner evidence without
publishing sealed expected labels before independent human studies. No DOI
has been minted; the Git tag, release archive digest, and Software Heritage
snapshot are the current content anchors.

The submitted PDF's claim that the earlier `v0.2.0-rc2` release already
contained all manuscript code and evidence was too broad: four companion
trees and a bootstrap-sensitivity companion were made public only after
submission. The exact PDF is preserved unchanged; see
`SUBMISSION-ARTIFACT-CORRECTION-2026-08-02.md`. This release also commits the
downloaded evidence from public replay run 30767663171 so that it does not
depend only on workflow-artifact retention.

The private hosted-evidence workflow uses the exact frozen r5 source package
and its SAFE Metric Metamorphics dependency carried in:

`capsule/tyche-second-host-source-capsule-2026-07-28.tar.gz`

Its declared SHA-256 is verified before any member is extracted. The
extraction helper rejects absolute paths, path traversal, links, devices,
duplicates, member-set drift, size drift, and hash drift.

## Hosted cross-architecture replay

The manually dispatched workflow `.github/workflows/second-host-matrix.yml`
runs four core laboratories on fresh GitHub-hosted Ubuntu VMs:

- x86-64 (`ubuntu-24.04`);
- ARM64 (`ubuntu-24.04-arm`).

It compares exact categorical assertions and architecture-neutral counts.
It deliberately does not claim physical-machine identity or hardware-rooted
attestation.

Two independently dispatched matrices have now passed. The preferred
Node-24-action run reports `aarch64` and `x86_64`, passes both 20/20 semantic
contracts, and passes all 11 cross-architecture comparison checks. Downloaded
logs, environment records, result hashes, and complete evidence manifests are
preserved under `evidence/hosted-x64-arm64-2026-07-28/`.

An additional run on the configured `zeus2` target identifies a distinct
Ubuntu 24.04 x86-64 Hyper-V VM/OS with a Microsoft vTPM. It passes the
four-lane 20/20 contract, verifies 104/104 live transaction-bound TPM2 quotes,
rejects 64/64 predeclared quote mutations, and leaves no new transient or
persistent TPM handle. Its evidence and explicit non-hardware claim boundary
are under `evidence/zeus2-vtpm-2026-07-30/`.

The r8 evidence manuscript and reproducibility/readiness records are under
`preprint/`. The JAIR-formatted submitted PDF is 44 US-letter pages; it
suppresses production-only Associate Editor, volume, article, and DOI
placeholders rather than fabricating publication metadata. The Markdown and
build-audit status lines remain the frozen pre-submission record; the PDF
digest above identifies the submitted bytes.

The sanitized public release does not advertise or depend on that private
capsule. It carries the four executable lanes directly, together with
`.github/workflows/public-four-lane-replay.yml` and
`scripts/run_public_tree_on_runner.sh`. Thus an extracted public archive can
replay its included lanes without any blind/private file.

## Release tools

The versioned tools under `release-tools/` add:

- a commit-pinned x86-64/ARM64 replay builder;
- a quote-only TPM companion with fail-closed safety preflight, explicit
  hardware/firmware/vTPM provenance boundaries, and post-run handle census;
- blind semantic-study validation, kappa stop rules, and adjudication;
- a deterministic public sanitizer driven by an exact path manifest.

Preparation tools do not count as external observations. In particular, no
hardware-TPM result or human semantic result exists until an eligible operator
or participant returns a sealed output.

## Evidence boundaries

- The corpora are designed synthetic fixtures, not deployed-system samples.
- Expected labels are author-written unless an external result says otherwise.
- GitHub-hosted runs are independent VM executions, not witnessed physical
  hosts.
- Software-TPM and Microsoft-vTPM vectors are not hardware-rooted evidence.
- The human-labelling and semantic-mapping packets remain blind until their
  preregistered response seals are complete.

## Licensing

Original code and schemas are released under Apache-2.0. Original prose,
figures, corpora, and generated research data are released under CC-BY-4.0.
Files carrying an adjacent upstream licence or notice remain under those
terms. See `LICENSE.md` and the per-component notices.

The working repository remains private while this separate public repository
is built from the explicit sanitized allowlist. The sanitizer excludes blind
study coordination and expected-label material. Public visibility is not
itself a licence grant for any material marked `HOLD` or `NOASSERTION`.

## Citation

Use `CITATION.cff`. A DOI field will be added only after a DOI-bearing deposit
exists; the Git tag, Git commit, deterministic archive hash, and Software
Heritage snapshot identifier provide the current content anchors.
