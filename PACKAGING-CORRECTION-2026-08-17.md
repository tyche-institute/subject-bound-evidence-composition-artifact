# Packaging correction, 2026-08-17

Two packaging defects, found by an independent replication campaign (a fresh clone of this
repository at `c3a1db8425542fb40b967d810a5d871b70cbb9ce`, every laboratory re-run against its
shipped results). **No result byte changes.** Both fixes are packaging-only; the replication
itself found zero semantic divergence — 41 of 50 recomputed counterpart files byte-identical,
the remainder differing only in environment-provenance strings or by-design fresh key material.

## 1. `verify_overlay.py` crashed when run directly on the shipped vectors

`masters-thesis-radar/research-factory-v4-2026-07-27/labs/native-state-transaction-overlay/verify_overlay.py`
ended by writing a checksum manifest that included `results/run-metadata.json`. That file is
written by `generate_vectors.py` and is deliberately absent from the shipped `results/`
directory (environment provenance is scrubbed from the deposit), so running the verifier
directly on the shipped vectors — the natural first thing a reviewer does — raised
`FileNotFoundError` after all four result files had already verified byte-identical.
`run.sh` masked the defect by regenerating vectors first.

**Fix:** the manifest now includes `run-metadata.json` only when it exists. Verification
behaviour is otherwise unchanged; re-run on the shipped vectors completes with
`all_passed: true`, 104/104 exact recomposed decisions and 64/64 mutation rejections, and the
four shipped result files remain byte-identical.

## 2. A nested manifest pointed at a staging path that was never shipped

`evidence/host-A-vtpm-2026-07-30/tpm-final-preflight/SHA256SUMS` referenced five files under
`../../extracted/subject-bound-evidence-composition-public-2026-07-28/release-tools/…` — a
packaging-time staging directory that does not exist in this repository. All five files ship at
`release-tools/hardware-tpm-companion-2026-07-28/` with **exactly the recorded hashes**, so no
content was ever missing; the manifest paths were stale.

**Fix:** the five entries now point at `../../../release-tools/hardware-tpm-companion-2026-07-28/…`.
`sha256sum -c` in that directory now passes 6/6.

## Scope

Files changed: the two named above, plus this note and the two corresponding lines of the
top-level `SHA256SUMS`. Nothing under any `results/` directory changed. No corpus, no verdict,
no summary, no evidence file was touched.
