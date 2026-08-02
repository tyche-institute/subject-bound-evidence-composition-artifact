# Public four-lane replay evidence: GitHub Actions run 30767663171

Source release: `v0.2.0-rc3`

Source commit: `e172ea951e8e031b787f5b895436e76edde53bd6`

Workflow run: <https://github.com/tyche-institute/subject-bound-evidence-composition-artifact/actions/runs/30767663171>

The run executed the public four-lane tree on GitHub-hosted x86-64 and ARM64
jobs. Both semantic contracts passed, and the cross-architecture comparison
passed 8/8 declared checks. `SHA256SUMS` fixes every file in this directory;
each architecture directory also carries its own `EVIDENCE-SHA256SUMS`.

These files are committed so that the evidence does not depend only on the
finite retention period of a GitHub Actions artifact.

## Claim boundary

This is evidence of fresh executions by two GitHub-managed job VMs reporting
different architectures. It is not evidence of an identified second physical
host, a human outside operator, organizational independence, or hardware-rooted
attestation. The historic environment files include an ephemeral runner
nodename in `uname -a`; see `PRIVACY-METADATA-CORRECTION-2026-08-02.md`.
