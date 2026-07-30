# Figure pack — research-factory-v4 r5 (2026-07-28)

The current manuscript references thirteen figures, `figA` through `figM`.
Every figure ships as PDF, PNG, and SVG.

- `make_r1_figures.py` produces the canonical `figA`--`figG` set.
- `make_evidence_upgrade_figure.py` produces `figH`.
- `make_r4_figures.py` produces `figI`--`figK`.
- `make_r5_figures.py` produces `figL` from the saved native-state and durable
  revocation results.
- `make_container_topology_figure.py` produces `figM` from the saved
  five-container durable-revocation result.

`figH`--`figM` extend rather than rename the canonical set. Their counts are
designed-case coverage, not prevalence or performance estimates.

```bash
cd figures
python3 make_r1_figures.py
python3 make_evidence_upgrade_figure.py
python3 make_r4_figures.py
python3 make_r5_figures.py
python3 make_container_topology_figure.py
```

The generators assert their plotted values against saved JSON. They pin
`SOURCE_DATE_EPOCH`, SVG hash salts, PNG software tags, and PDF metadata and
contain no randomness or wall-clock content.

## Global claim ceiling

This applies to every figure below, and each figure also carries the relevant
part of it as an in-figure footnote.

- Every expected label is an author-written, programme-internal expectation.
  Agreement measures reproduction of those expectations, not external ground
  truth.
- Every count is a count on a designed corpus. It is **coverage**, not a
  rate, and it does not estimate prevalence or behaviour in any deployed
  system.
- The source corpus state layer is a **structural appraisal** of
  corpus-supplied attestation-result objects (`state_adapter.py`). The r5
  native overlay separately replaces all 104 source state outcomes with TPM2
  quote appraisal and recomposes the decisions. Its roots are software TPMs
  on one host, so neither path establishes deployed-runtime attestation.
- The authority layer consumes corpus-supplied experimental flags
  (`issuer_signature_valid`, `native_evidence_valid`, `protocol_valid`). It
  performs **no** cryptographic verification.
- The binding stage is deterministic **string agreement and interval
  containment** over subject fields read out of corpus-supplied artefacts. It
  verifies no signature, takes no measurement and is not attestation of any
  runtime. It is not a sixth artefact verifier: it ranges over fields the
  five verifiers already read.
- The SQL oracles recompose per-layer typed results that the Python
  evaluator produced. They are a second composition code path, **not**
  independent validation. **One exception, and it is a real one:** the
  *delegation-path* oracle
  (`labs/protocol-valid-unauthorized/oracle_delegation_paths.sql`,
  `run_sql_oracle.py`) does **not** consume the Python evaluator's verdict
  stream. It re-derives verdicts from the raw case objects in
  `results-delegation-paths/expanded-cases.json`, so its agreement is
  implementation diversity over *verdict derivation*, not recomposition. It
  is still not independent validation: case expansion and the expected labels
  are shared with the Python entry point, and both implementations read the
  same corpus-supplied validity flags. The deposited
  `results-sql-oracle/summary.json` states this in its
  `independence_note`, and this figure pack must not contradict it.
  - Composed corpus: the composed SQL oracle *does* re-derive the binding
    outcome rather than echo it (`binding_result_matches` in its summary), so
    a Python/SQL divergence in the binding rules would be detectable; the
    subject strings it compares still come from the Python evaluator, so that
    remains a transcription check between two same-author implementations.
- The ablation profiles are author-defined experimental profiles. They are
  **not** representations of any named external product.

## House style

Strict black on white. Encoding is carried by hatch pattern, marker shape and
line style only — no colour hue and no grey fill anywhere, so every figure
survives monochrome print and any colour-vision deficiency. No legend key is
distinguished by fill alone. No rounded corners: every rectangle is drawn
with a mitre join, and line joins are mitred too.

## Legibility contract

Effective on-page size is `font_pt * (6.1 in * embed_width_fraction /
figure_width_in)`, where 6.1 in is the manuscript's A4 text block and the
width fraction is the `{ width=NN% }` key in the manuscript. Each figure's
width in inches is set to exactly `6.1 * fraction`, so the scale factor is
1.000 and effective size equals nominal size. The generator asserts every
declared text element at ≥ 7 pt, and asserts that no text artist crosses the
canvas edge.

| Figure | embed | width (in) | height (in) | scale | smallest element | eff. pt |
| --- | ---: | ---: | ---: | ---: | --- | ---: |
| figA | 97% | 5.917 | 7.276 | 1.000 | footnote 7.0 pt | 7.00 |
| figB | 88% | 5.368 | 4.908 | 1.000 | footnote 7.0 pt | 7.00 |
| figC | 90% | 5.490 | 4.017 | 1.000 | fixture *n* 7.0 pt | 7.00 |
| figD | 97% | 5.917 | 3.718 | 1.000 | value label 7.0 pt | 7.00 |
| figE | 72% | 4.392 | 5.013 | 1.000 | footnote 7.0 pt | 7.00 |
| figF | 95% | 5.795 | 3.765 | 1.000 | footnote 7.0 pt | 7.00 |
| figG | 97% | 5.917 | 5.803 | 1.000 | row identifier 7.0 pt | 7.00 |
| figL | 97% | 5.917 | 3.250 | 1.000 | footnote 7.0 pt | 7.00 |
| figM | 98% | 5.978 | 3.350 | 1.000 | footnote 7.0 pt | 7.00 |

Every figure's smallest declared element is exactly 7.0 pt and every scale
factor is exactly 1.000, so the smallest on-page type in the pack is 7.0 pt.
figA and figG are tall; both still fit inside an A4 text block (≈ 9.7 in
high) at their declared embed widths.

---

## figA — `figA-composition-five-predicates.{png,pdf,svg}`

**Data source.** `labs/composed-transaction-corpus/results/summary.json`
(`failed_layer_occurrences`, `transactions`, `binding_stage`), recomputed
from `results/verdicts.jsonl` and asserted equal;
`labs/protocol-valid-unauthorized/results-delegation-paths/summary.json`
(`cases`, `hop_lengths`) and `.../results/summary.json` (`protocol_valid`,
`vectors`) for the authority and protocol annotations.

**What it shows.** The typed non-compensable decision rule
`ALLOW iff P ∧ E ∧ S ∧ A ∧ M ∧ B`. Each predicate box names the mechanism
that establishes it in this artifact packet — Ed25519 signature verification
(policy, evidence), structural attestation-object appraisal (state), a
flag-gated typed delegation-path evaluator (authority), profile digest plus
bootstrap lower confidence bound (measurement) — and how often its failure is
exercised across the 104 frozen transactions (39 / 36 / 17 / 30 / 39).

The sixth box is the binding stage `B`. It is drawn with a **dashed** edge,
and the footnote gives the key ("solid boxes are the five artefact verifiers;
the dashed box is the join condition over their subjects"), because `B` is
not a layer: it has no column in the co-failure matrix and never appears in
`failed_layers`. Its box names exactly what establishes it — deterministic
string agreement and interval containment over the required effect and
required measurement profile (signed policy), effect, resource and
`issued_at` (signed evidence), the terminal narrowed grant and the
intersection of the per-edge validity windows (delegation path), and the
profile identifier (measurement fixture) — and states that it verifies no
signature, takes no measurement and is not attestation of any runtime. It is
annotated with the 8 transactions whose verdict it decided rather than with a
failure-exercise count. The rule box states the fixed evaluation order that
`first_rejecting_gate` follows, `policy → evidence → state → authority →
measurement → binding`, and says that `B` is consulted only when all five
artefact verifiers pass.

**Claim ceiling.** The counts describe the composition of a designed corpus
with author-written labels; they are not rates. Two of the five predicates
are established structurally or by corpus-supplied flags, not
cryptographically, and the binding stage compares corpus-supplied subject
strings; the figure says all of this on its face. Evaluating all layers
to preserve a typed failure set is not a claim that later failures did not
exist. Nothing in the figure is baked in: every count, the hop lengths, the
case count and the protocol-gate ratio are read from the result JSON at build
time.

## figB — `figB-policy-version-evidence-replay.{png,pdf,svg}`

**Data source.** `labs/policy-version-evidence-replay/results/verdicts.jsonl`,
cross-checked against `results/summary.json` (vector count, strict allows and
denies, expected matches, baseline false allows) and
`results-sql-oracle/summary.json` (implementation matches, gate histogram).

**What it shows.** Strict typed verdicts for all 16 vectors: the 4 × 3
policy × evidence factorial with each cell's `first_rejecting_gate`, plus the
four gate-isolation vectors that each fail exactly one strict policy gate.
Strict allows exactly one vector (correct policy, good evidence). The □ mark
identifies the strict denies that a weaker ablation profile falsely allows —
signed-policy presence 5 of 15, missing-policy fail-open 6.

**Claim ceiling.** 16/16 agreement is reproduction of a frozen specification
on designed vectors with author-written labels, not detection performance on
any external workload. The 16/16 relational agreement is a second composition
code path, not independent validation: the oracle re-derives only the
conjunction and the gate label, and reimplements no signature check.

## figC — `figC-measurement-fixtures.{png,pdf,svg}`

**Data source.** `labs/composed-transaction-corpus/results/verdicts.jsonl`
(point estimate, lower confidence bound, threshold, profile digest and typed
result per fixture) and `results/summary.json`
(`coverage.measurement_fixture_usage`). Sample sizes *n* come from the frozen
v3 SAFE laboratory,
`../../research-factory-v3-2026-07-25/labs/safe-metric-metamorphics/results/measurement-fixtures.json`,
which the V4 corpus embeds by id and hash; the generator asserts that the two
sources agree on every point estimate, bound, threshold, profile digest and
typed result. The generator partitions the corpus's measurement fixtures by
`fixture_source` and plots only the four SAFE-sourced fixtures; the two
laboratory-owned profile variants used by the cross-layer binding family
(`measurement_binding_main_profile`, `measurement_binding_alt_profile`) are
asserted to be exactly the non-SAFE population and are not plotted as SAFE
measurements.

**What it shows.** All four confidence-aware SAFE measurement fixtures: point
estimate (filled circle), one-sided 5% bootstrap lower confidence bound (open
square), the 0.75 threshold (dashed), the typed result, the sample size, and
how many of the 104 transactions use each fixture (51 / 19 / 5 / 15). The
altered-profile fixture has scores identical to the supported fixture, so its
denial is driven by the profile digest alone.

**Coverage, stated on the face of the figure.** 51 + 19 + 5 + 15 = 90 of the
104 transactions. The figure says so, and says that the remaining 14 use the
two laboratory-owned profile variants, which are scored identically to the
supported fixture and passed by the unmodified SAFE evaluator and therefore
are not SAFE boundary cases. The generator asserts the arithmetic
(`plotted_usage + laboratory-owned usage == transactions`) rather than
letting the reader assume the four plotted fixtures exhaust the corpus.

**Claim ceiling.** These are designed boundary cases with author-chosen
thresholds. The values are not measurements of any deployed model, and the
*n* = 18 fixture sits where percentile-bootstrap bias is not negligible. The
figure demonstrates that the typed distinctions exist; it says nothing about
their frequency in any real measurement.

## figD — `figD-topsis-reference-sets.{png,pdf,svg}`

**Data source.**
`../../research-factory-v3-2026-07-25/labs/safe-metric-metamorphics/results/topsis-result.json`.
There is no V4 TOPSIS laboratory: the SAFE laboratory is frozen from the
previous packet and consumed read-only in this revision. Every ordering claim
in the figure is recomputed from the raw score vectors and asserted against
the stored order fields.

**What it shows.** TOPSIS closeness for alternatives A, B and C under the
dynamic observed reference (left) and the fixed 0–1 reference (right), before
and after adding alternative D. Under the dynamic reference the base order
A > C > B becomes A > B > C. Under the fixed reference the base order is
already A > B > C and does not change.

**Claim ceiling.** A constructed reproduction of a known reference-set /
normalisation sensitivity of TOPSIS. The fixture reproduces the phenomenon
inside this evidence profile; it does not discover it. The two schemes
disagree on the base ranking, so **neither is a control for the other**: the
fixed scheme is a different ranking function that happens to be stable here,
not a scheme that retained the dynamic scheme's original order.

## figE — `figE-cofailure-matrix.{png,pdf,svg}`

**Data source.** `labs/composed-transaction-corpus/results/summary.json`
(`co_failure_matrix`, `co_failure_min_offdiagonal`), recomputed cell by cell
from `results/verdicts.jsonl` and asserted equal, with symmetry and the
diagonal-equals-`failed_layer_occurrences` identity also asserted.

**What it shows.** The full 5 × 5 pairwise co-failure matrix over the 104
transactions. The diagonal (bold) is the number of transactions in which that
layer failed; each off-diagonal cell is the number in which both layers
failed. Every one of the 20 off-diagonal cells is at least 5 — the
predecessor corpus was block-diagonal with four zero cells joining authority
or state with policy or evidence, so the seam this article names was
previously untested.

**What it does not cover, stated in the footnote.** The matrix ranges over
the five artefact verifiers only. The 8 cross-layer denials have an empty
failed-layer set, so they appear in **no** cell of it: the matrix accounts
for 81 of the 89 denies. The generator asserts that count rather than leaving
it implicit.

**Claim ceiling.** These are counts on a designed corpus. The corpus was
engineered so that no off-diagonal cell is zero, so cell magnitudes reflect
corpus construction and nothing more; they are not failure prevalence
anywhere. State failures are structural-appraisal outcomes of corpus-supplied
attestation objects, not attestation verdicts of any runtime.

## figF — `figF-stratified-false-allows.{png,pdf,svg}`

**Data source.** `labs/composed-transaction-corpus/results/summary.json`
(`baseline_false_allows_by_family`, `baseline_false_allows`, `family_counts`,
`family_verdicts`, `analytic_identities`), every bar recomputed from
`results/verdicts.jsonl` and asserted equal, with the column totals and the
family sizes and deny counts also asserted.

**What it shows.** False allows relative to the strict rule for three
ablation profiles, stratified over all five corpus families and never
aggregate-only. The stratification is the point: the four-of-five majority
false-allows 13 of 13 authority-reuse denies, 0 of 26 cross-layer-join denies
(every join deny carries at least two failed layers) and 8 of 8 cross-layer
binding denies (those carry *zero* failed layers, so a majority over the five
artefact verifiers cannot represent them at all); the artifact-validity
profile false-allows every deny whose faults lie outside policy presence and
evidence integrity.

**Claim ceiling.** Proof by construction plus corpus coverage, on 104
transactions with 89 strict denies. The four-of-five column is governed by an
analytic identity, not a measurement. The v2 identity — its false allows
*are* the single-fault denies — no longer holds and is asserted false by the
generator; the refined identity that replaces it is that its false allows are
the single-fault denies **union** the cross-layer denials (31 = 23 + 8,
verified as set equality on transaction identifiers). That column therefore
measures how many single-fault and cross-layer transactions the corpus
contains and nothing else. No bar is a rate or an estimate of behaviour in
any deployed system.

## figG — `figG-cross-layer-denials.{png,pdf,svg}`

**Referenced from** §6.3 *Integrated transaction results* of
`preprint-03-valid-artifacts-accountable-decisions-r2-2026-07-27.md`, at
`{ width=97% }`, immediately after the paragraph that enumerates the eight
`XLB_*` identifiers. That is the only manuscript edit this figure lane made.

**New in this revision.** It exists because the binding stage created a
transaction class that could not previously be represented, and that class is
the article's headline: a denial with **zero** failing artefact verifiers. No
other figure in the pack can show it — figE's matrix is indexed by failed
layers and figF's majority column collapses it into a bar.

**Data source.** `labs/composed-transaction-corpus/results/verdicts.jsonl`,
the whole `cross_layer_binding` family (14 transactions): per-transaction
`layer_results`, `failed_layers`, `binding.details.canonical_action`,
`binding.details.observed_effect`, `binding.result`, `binding.gate`,
`verdict` and `expected`. Cross-checked against `results/summary.json`
(`binding_stage.cross_layer_denial_ids`, `binding_stage.cross_layer_denials`,
`binding_stage.cross_layer_denials_by_family`,
`binding_stage.binding_result_counts_by_family`, `family_counts`).

**What it shows.** The 8 transactions in which all five artefact verifiers
return `policy PASS`, `evidence PASS`, `state PASS`, `authority ALLOW`,
`measurement PASS`, the failed-layer set is empty, and the composition still
denies — each with the subject pair that disagrees, read out of its own
binding record, and the typed binding result that fired
(`EFFECT_MISMATCH` ×3, `RESOURCE_MISMATCH` ×2, `TIME_MISMATCH` ×2,
`PROFILE_MISMATCH` ×1). Beneath them, the 6 matched lookalike controls of the
same family, built the same way with agreeing subjects, all 6 ALLOW.

The controls are the load-bearing half of the figure. Without them the eight
denials would be consistent with a verifier that refuses everything; with
them, the figure shows that the two groups differ only in the observed
subject.

**Verification.** The generator asserts, per transaction and not in
aggregate: all five layer results equal the passing tuple; `failed_layers`
is empty; the verdict-stream binding result equals the expected label's;
`binding.subject_match` is true (the verifier re-derived the subject records
rather than echoing stored ones); for each denial, the deciding boolean in
`binding.details` is false and the value printed on the row is the value in
the record; for each control, `missing_subject_fields` is empty. The eight
denial identifiers are asserted equal to the deposited
`cross_layer_denial_ids`.

**Claim ceiling.** The binding stage verifies no signature, takes no
measurement, contacts no attestation service and is not attestation of any
runtime; the figure says this in its footnote. These are 8 denials on a
designed corpus with author-written expected labels — coverage, not a rate,
and not an estimate of how often subject disagreement arises in any deployed
system. The transactions were *constructed* so that their five verifiers
pass, so the figure demonstrates that the class is representable and caught;
it does not discover the class in the wild.

---

## figH — `figH-revocation-races.{png,pdf,svg}`

Generated by `make_evidence_upgrade_figure.py` from the 13 scheduled signed
revocation sequences. It juxtaposes boundary placement with false allows of
the three incomplete scheduled profiles. It is not the live-service result.

## figI — `figI-live-revocation-service.{png,pdf,svg}`

Generated by `make_r4_figures.py` from
`labs/live-revocation-service/results.json`. It plots false allows for all four
69-case profiles and asserts 276/276 signature-verifying traces, zero false
denies, and zero safety errors for `atomic_guard`. Exact incomplete-profile
bars belong to one scheduler realization; they are coverage counts, not rates.

## figJ — `figJ-typed-state-transfer.{png,pdf,svg}`

Generated by `make_r4_figures.py` from
`labs/cross-ecosystem-typed-transfer/results.json`. Panel (a) compares the
native rejection vocabularies with one Boolean state. Panel (b) shows the
120 and 378 pairwise distinctions erased within the two corpora, total 498.
The values quantify analytic label loss, not empirical error.

## figK — `figK-partial-binding-ablation.{png,pdf,svg}`

Generated by `make_r4_figures.py` from the composed-corpus
`results/summary.json`. It compares three subject-aware partial joins with the
full implemented binding schema. All four profiles require the five local
verifiers and effect/resource agreement; the partial profiles omit time,
profile, or both. The 3/2/1/0 bars are counts on the 14 designed binding cases,
not rates or product measurements.

## figL — `figL-evidence-class-upgrades.{png,pdf,svg}`

Generated by `make_r5_figures.py` from
`labs/native-state-transaction-overlay/results/summary.json` and
`labs/distributed-revocation-service/results.json`. Panel (a) reports the
87/9/4/4 native state-class distribution. Panel (b) shows 104/104 state-oracle
agreement, 64/64 mutation rejection, and 104/104 recomposition. Panel (c)
shows 0/61/66/63 false allows across the atomic, double-read, single-read, and
TTL-cache profiles and annotates 96/96 fault recovery with zero duplicate
effects. The generator asserts every value. Software TPMs, same-host loopback,
and centralized SQLite remain explicit ceilings.

## figM — `figM-containerized-revocation-boundaries.{png,pdf,svg}`

Generated by `make_container_topology_figure.py` from
`labs/containerized-durable-revocation/results/results.json`. Panel (a)
places the runner, status service, fault proxy and two effect instances inside
the same dashed physical-host boundary and makes the shared SQLite WAL trust
domain visible. The solid request reaches effect-a through the proxy; the
dashed recovery route goes directly from the runner to effect-b. Panel (b)
reports 0/69 atomic false allows, zero duplicate
decision/effect keys, 36/66 intentionally exposed prior-read false allows,
4/4 cross-instance recoveries, 540/540 verified signatures, and both assertion
sets. The figure establishes container/process/network-instance separation,
not multi-host or distributed-datastore evidence.

## Superseded v3 material — removed from this packet

The `figures/archive-v3/` directory that previously sat here has been
**moved out of the packet** to

```
../figures-archive-v3-superseded-2026-07-27/
```

(a sibling of `research-factory-v4-2026-07-27/`, outside every path the
submission packet enumerates). It held the superseded v3 renders
(`fig1`–`fig10`), the v3 generators (`make_figures.py`,
`make_empirical_figures.py`) and a stale `.dot` source.

**Why moved rather than renamed.** Renaming was the other option and it is
the weaker one:

1. The internal codenames are not only in filenames
   (`fig5-flagship-…`, `fig9-flagship-…`, `fig10-flagship-…`,
   `fig4-a0-…`). They are **rendered into the artefacts themselves** — the
   text layer of `fig5-flagship-composition.svg/.pdf/.png` and
   `fig4-a0-evidence-ladder.svg/.pdf/.png` carries them. Renaming files would
   leave the codenames inside the deliverables.
2. Removing them from the rendered content would mean re-running the v3
   generators against superseded v3 data, i.e. manufacturing *new* superseded
   artefacts inside a submission packet. That is worse than not shipping
   them.
3. The v3 SVGs also embed wall-clock timestamps
   (`2026-07-25T22:52:57.564250`), which contradicts this pack's determinism
   claim for anyone who hashes the tree.
4. Nothing in the packet consumes them. They were provenance only.

The material is preserved in full at the new path; nothing was deleted.

**Consequence for the manifest.** `artifact-manifest.md` still lists 13
`figures/archive-v3/*` entries and the pre-rebuild figure hashes. It is a
generated file (`make_manifest.py`) and must be regenerated once the
manuscript lane has settled; it was deliberately **not** regenerated here,
because a mid-flight run would freeze hashes of files another lane is still
editing.

## Checksums

`SHA256SUMS` covers `figA`--`figH`, their generators, and this README.
Verify from this directory:

```bash
sha256sum -c SHA256SUMS
```

`SHA256SUMS-r4` separately covers `make_r4_figures.py` and the nine
`figI`/`figJ`/`figK` files:

```bash
sha256sum -c SHA256SUMS-r4
```

`SHA256SUMS-r5` covers the r5/closure generators and all figL/figM files.
