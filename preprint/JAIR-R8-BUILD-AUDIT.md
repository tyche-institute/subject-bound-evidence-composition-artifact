# JAIR r8 build and submission-metadata audit

Date: 2026-07-31
Status: **SUBMITTED to JAIR 2026-08-01, submission ID 23967** (see SUBMISSION-RECORD-JAIR-2026-08-01.md); build PASS

## Build

- format: JAIR 2025+ `jair` class, `manuscript,screen,review`;
- page size: US Letter;
- pages: **44** (window 40–44 inclusive);
- deterministic build controls: `SOURCE_DATE_EPOCH=1785110400`,
  `FORCE_SOURCE_DATE=1`, `TZ=UTC`, `LC_ALL=C.UTF-8`;
- two complete consecutive `latexmk -gg` builds: byte-identical
  (`build-r8-final-1.log`, `build-r8-final-2.log`);
- overfull boxes: zero; undefined references/citations: zero;
- figures: 8 retained (A, E, G, H, J, L, M, N); B, C, D, F, I, K removed —
  each duplicated an adjacent table or prose count (referee rows 18/19);
- figN regenerated with the disclosed host label
  "identified VM (host-A)" (deterministic salt updated);
- refcheck: 18/18 DOIs clean (Crossref + Retraction Watch), including the
  seven new prior-art references [38]–[44];
- AI-tell grep: PASS (combined limiting-register density 1.7/1k,
  threshold 2.5; no named-string hits);
- fix-all round (Anton, 31.07): Generative-AI disclosure scope broadened
  to the actual workflow (unit testing, drafting and editing assistance,
  reference verification, reproducibility checks) per AGENT.md §5.5's
  broaden-to-match rule; bootstrap seed/replicate sensitivity sweep
  executed and archived (companions/bootstrap-sensitivity-2026-07-31,
  outcome stable 15/15 grid points, LCB spread <= 0.0017); measurement
  gate precedence stated (profile -> point -> LCB); performance
  characterization explicitly scoped out; PCR/AK expanded at first use;
- pre-submission readability round (Anton, 31.07): all seven remaining
  figures verified page-by-page after a caption-trim regression had left
  five of them (A, E, G, H, M) rendering as raw caption text — restored;
  figN converted to an in-text execution-domain table whose local-TPM cells
  now carry artifact-grounded counts (104/104, 64/64 — the figure's
  832/832 and 512/512 matched no artifact and were dropped); pandoc table
  column widths retuned per table (build_body.py retune_table) and every
  table visually checked; the post-\maketitle submission-note block
  removed (self-contradictory in a submitted copy);
- revision-history phrase scan over extracted PDF text: clean
  ("previous revision", "this revision", "previous draft", "formerly",
  "predecessor", "rN showed/added/fixed" — zero hits);
- Declarations block present (unnumbered, after Conclusion): funding,
  competing interests, locked Generative-AI assistance paragraph, data
  availability. ⚠ The disclosure's locked scope wording ("for unit
  testing") is the global Tyche canon; scope-accuracy confirmation before
  any submission is Anton's gate (AGENT.md §5.5).

## Publication metadata

The review PDF suppresses the production-only JAIR reference strip and uses
the neutral footer `Submitted manuscript, July 2026.` It contains no
invented Associate Editor, volume, article number, DOI, or publication
date. The structured abstract was rewritten to ~430 words with a
plain-language thesis; the reproducibility checklist is retained.

## SHA-256

```text
preprint-03-valid-artifacts-accountable-decisions-r8-2026-07-31.md
  df45cb11d0a357edf62465c6532c0b17ef9a71197623b0db82f268708fef610d
main.tex
  daaf1acf3b8508ab5ab3fece1a1fd276d41cac29411541aa8e045c49bef2f4f6
body.tex
  e433d7c54ce489688fe04a79cd2767000683e73e20a10c65c8ada4eeafc5dc22
references.bib
  50ddd3c3e93ea7e7f5583181572b999aae7024747cbfea2f616849ddd27f53fa
submission-candidate PDF
  8336906cc984c578e9d6fcd160dc45a1b92ad0329e9c666e7cffffa316de73da
```

## Evidence corrections landed in r8 (from REFEREE-R7-FULL-2026-07-31.md)

1. The native signed authority adapter, both mutation laboratories, and
   their input evaluator are now committed in the source repository under
   `masters-thesis-radar/research-factory-v4-2026-07-27/companions/`
   (commit `614d08e`); all five manuscript-pinned digests re-derive.
2. §6.4/§9 durable-revocation realization synced to the archived
   `labs/distributed-revocation-service/results.json`
   (`367f9575…9358`): false allows 63/67/66, durable effects 301,
   events 1,478, recoveries 96/96, duplicates 0.
3. Reference [33] cites the published title *EATF Agent Evidence Package
   Toolkit* with the v0.3.0 Zenodo DOI `10.5281/zenodo.21618887` and the
   pinned result commit; the prose canon remains "Action Evidence
   Package" with an explicit continuity sentence in §3.7. No published
   DOI metadata was altered.
4. Abstract no longer claims severity-direction or reference-set-poisoning
   metamorphic relations; the SAFE claims match the implemented checks.
5. Theorem scope precondition (nonempty single linear delegation path),
   the definition of a compensating rule, the expository status of the
   decision clock κ(x), and the honest description of the Java model
   checker's atomic branch are stated in §4.
6. Threat-model subsection added (§2); prior-art family (confused deputy,
   OAuth RFC 8707/9396/9449, SAML/VC/SPIFFE, OPA/Rego) and the
   "single policy engine" concession added (§3.2).
7. Codename hygiene: `host-A` appears only as the disclosed artifact host
   label (§9 first use, figN caption/label); `redacted-local-host` removed;
   §9 companion paths use the committed repository locations.
8. "six scalar strings", "eight companion laboratories", §5.6-vs-§9
   mutation-class naming, and the §7.1 passport field list corrected.

## Evidence boundary

Unchanged from r7 in substance: executable results over author-defined
synthetic fixtures; no deployed-system rates, physical-host identity,
hardware root, human-label agreement, external semantic consensus, or
interoperability claims. The §9 statement now also discloses that the
public `v0.2.0-rc2` release bundles an earlier preprint copy: the release
anchors code, corpora, and generated evidence (unchanged in range), and a
release recut at the r8 commit is planned as a separate, explicitly
authorized step (NOT executed).

## Continuous integration

- prior anchors: run 30526978734 (matrix at `d605e8d`, PASS) and run
  30529092409 (matrix at `62d5df8`, PASS — exact r7 HEAD);
- r8 branch `agent/r8-jair-referee-compression`, commit `dfaa963`
  (companions + r8 manuscript included): run
  <https://github.com/tyche-institute/subject-bound-evidence-composition/actions/runs/30604379229>
  — public-replay-x64 PASS, public-replay-arm64 PASS,
  compare-public-x64-arm64 PASS;
- final-commit CI (`0f12589`, includes the fix-all round): run
  <https://github.com/tyche-institute/subject-bound-evidence-composition/actions/runs/30605757664>
  — all three jobs PASS;
- staged (unpublished) v0.2.0-rc3 recut: archive `edfeb010…93aa8`, two
  byte-identical builds, validation all_passed, fail-closed 11/11,
  extracted-archive four-lane replay 20/20 (see
  RELEASE-STAGING-RC3-2026-07-31.md);
- local clean-clone validation at `dfaa963`: four-lane semantic
  contract 20/20 PASS (16 policy vectors, 104 composed transactions, 8
  binding denials, 21 EATF rows, 104 transfer rows, 372 revocation cases,
  96 fault cases); committed companion trees execute from the clone
  (native adapter 8/8, mutation corpus 38 transactions, multi-fault
  mismatch count 0).
