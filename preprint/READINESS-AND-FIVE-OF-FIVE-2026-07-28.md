# Evidence maturity and exact five-of-five gates

Date: 2026-07-28
Status: executable readiness record; future actions never count as evidence

## Scoring rule

| Score | Evidence required |
| ---: | --- |
| 0 | absent or contradicted |
| 1 | research idea or specification only |
| 2 | executable, sealed preparation exists; required observation is absent |
| 3 | internally executed, frozen, and hash-addressed |
| 4 | corroborated by a materially different implementation, architecture, host class, operator, or evidence source |
| 5 | sufficient public evidence for the scoped claim, bound to an immutable licensed artifact and independently reproduced under a hostile protocol |

`PASS` means that the evidence required for the displayed score is present.
`FAIL` means that the next claimed score cannot be awarded. A decimal is a
readiness estimate inside the last fully passed integer level; it is never a
substitute for the next level's required observation.

## Current scores

| Direction | Score | Current result | Exact blocker to 5 |
| --- | ---: | --- | --- |
| Scientific article overall | **4.7/5** | **PASS at level 4**: one formal spine, 104-case flagship, implementation-diverse checks, process/fault experiments, repeated x86_64/ARM64 execution, explicit ceilings | final public claim/evidence freeze, two substantive outside reviews, DOI-bound hostile reproduction |
| Native state | **4.1/5** | **PASS at level 4**: 104 software-TPM transactions, eight RSA/ECC roots, 64 mutations, Python/Java parity | hardware TPM, independent operator, public raw evidence and hostile mutation |
| Durable revocation | **4.5/5** | **PASS at level 4**: 372 process cases, five-container replay, 96 fault recoveries, identical architecture-neutral assertions on x86_64/ARM64, and a corrected one-OS-instance claim boundary | separate physical failure domains or narrower final claim, outside operator, DOI replay |
| Typed crosswalk | **3.7/5** | **PASS at level 3**: 125 executable rows, independent SQL path, exhaustive class/omission mutation tests, sealed 46-task kit | two returned blind mappings, adjudication, third-party adapter, public deidentified record |
| External labels | **2.0/5** | **PASS at level 2 / FAIL at level 3**: neutral 104-case kit and preregistered analysis exist; ethics and recruitment inquiries sent | two complete independent responses, sealed before analysis; kappa and adjudication; releasable deidentified record |
| Four-lane hosted VM and architecture | **4.9/5** | **PASS at level 4**: two sealed-capsule repetitions plus a direct public-tree PR-head matrix on job VMs reporting x86_64 and ARM64; 20/20 assertions per architecture and exact cross-architecture comparison | outside operator plus hostile mutation against immutable public bytes; no whole-package claim |
| Known second physical host | **2.0/5** | **PASS at level 2 / FAIL at level 3**: capsule and protocol exist | a witnessed outside physical host result with sealed environment provenance |
| Public licensed artifact | **3.8/5** | **PASS at level 3**: author/ORCID/affiliation resolved; Apache-2.0/CC-BY-4.0 grant; exact-path sanitizer; repeated and clean-clone byte identity; archive self-replay; 11/11 fail-closed negative gates | public visibility, immutable tag/deposit, DOI digest identity, outside hostile replay |
| Submission package | **4.2/5** | **PASS at level 4 / NO-GO for submission**: deterministic 50-page JAIR r6 package, authorship metadata, blind-safe release sequence, and reproducible licensed release candidate | close or explicitly narrow every remaining external gate; final artifact DOI; outside technical/editorial review |

## Completed in this closure cycle

1. Created a dedicated blind-preserving repository and recorded authorship,
   ORCID, affiliation, licence scope, CFF, CodeMeta, and upstream exceptions.
2. Verified the exact capsule, applied the declared hash-recorded portability
   overlay, and executed the four-lane replay contract twice on separate
   GitHub-hosted job VMs reporting x86_64 and ARM64.
3. Preserved complete logs, environment records, nested hashes, and
   cross-architecture comparisons.
4. Sent an ethics/applicability inquiry and availability requests for human
   labelling and semantic mapping. No response is counted until returned and
   sealed.
5. Built and independently rechecked a conservative public sanitizer outside
   the frozen r5 tree. It accepts only the exact clean Git commit and a sorted
   307-path allowlist, preserves explicit licences/notices, contains a direct
   four-lane replay instead of depending on the private capsule, reproduces
   byte-for-byte from a clean clone, self-replays 20/20 from its extracted
   archive, and passes 11/11 fail-closed negative gates.
6. Built a quote-only hardware-TPM companion: 11/11 preflight checks, 16/16
   forbidden-operation rejections, 104 unique challenge profiles, and a
   64-case offline mutation plan. No TPM device was contacted.
7. Built and independently rechecked the semantic-study execution package:
   46/46 response validation, preregistered kappa stop, independent
   adjudication, zero-final-`NO_FIT` and zero-taxonomy-defect gates, with
   positive and negative self-tests passing and the author mapping unopened.

## Ordered external closure

The order is mandatory because premature publication can expose expected
labels:

1. receive ethics/privacy applicability guidance;
2. dispatch blind kits only under the approved consent/data route;
3. seal both label responses and both semantic mappings;
4. execute preregistered analyses and preserve raw disagreements;
5. run hardware TPM and known-second-physical-host protocols;
6. build and audit the sanitized public archive;
7. mint an immutable DOI from those exact bytes;
8. give only the DOI bytes and hostile protocol to a fresh outside operator;
9. integrate public results and run the final JAIR referee.

## Binary five-of-five assertions

```text
article:
  substantive_outside_reviews >= 2
  unresolved_major_referee_findings == 0
  all_headline_claims_trace_to_public_evidence == true

native_state:
  hardware_tpm == true
  outside_operator == true
  baseline_parity == 104/104
  declared_mutations_rejected == 64/64
  operator_hostile_mutations_rejected == all

durable_revocation:
  atomic_false_allow == 0
  atomic_false_deny == 0
  duplicate_effects == 0
  injected_ambiguous_outcomes_resolved == all
  architectures >= 2
  outside_operator == true

typed_crosswalk:
  blind_complete_mappings >= 2
  author_mapping_opened_after_response_seals == true
  adjudicated_totality == 46/46
  wrong_class_detection == 46/46
  omission_detection == 46/46

external_labels:
  complete_independent_responses == 2
  verdict_kappa >= 0.60
  first_gate_exact_match >= 0.80
  raw_responses_hash_sealed == true
  adjudication_trace_preserved == true

artifact_and_replay:
  approved_licence_files_present == true
  third_party_holds == 0
  immutable_public_release == true
  doi_resolves_to_identical_digest == true
  outside_hostile_replay == PASS

submission:
  placeholder_fields == 0
  unresolved_checklist_no_or_partial == 0
  final_pdf_hash_recorded == true
  final_artifact_doi_recorded == true
  submission_verdict == GO
```

## Verdict

**INTERNAL SCIENTIFIC PASS / HOSTED CROSS-ARCHITECTURE PASS / SUBMISSION
NO-GO.**

The remaining failures are real-world observations, not missing prose or
local computation. They must not be replaced by synthetic labels, LLM
judgements, containers described as physical hosts, or a mutable private URL
described as an immutable public artifact.
