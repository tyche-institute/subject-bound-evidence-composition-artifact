# Evidence closure matrix — route to honest 5/5

Date: 2026-07-28  
Status: living execution record; no score is awarded for a future action

## Scale

| Score | Required evidence state |
| ---: | --- |
| 0 | absent or contradicted |
| 1 | idea, plan, or specification only |
| 2 | executable preparation exists, but the required external run is absent |
| 3 | internally executed, asserted, frozen, and hash-addressed |
| 4 | corroborated by a genuinely different implementation, operator, host, or evidence source |
| 5 | immutable licensed public artifact plus independent hostile reproduction sufficient for the scoped claim |

Preparation is never counted as observation. A local model is never counted
as a human labeller. A container is never counted as a second physical host.
A public URL is never counted as a licence, immutable release, DOI, or hostile
reproduction.

## Current evidence after the local closure sprint

These are provisional evidence-maturity estimates to be re-run by an
independent referee after the active laboratories and manuscript are frozen.

| Direction | Provisional score | What now earns the score | Why it is not 5 |
| --- | ---: | --- | --- |
| Scientific article overall | 4.4 | one formal spine; 104-case flagship; implementation-diverse finite check and native verifier; process/fault experiments; explicit ceilings | no immutable public release or outside hostile reproduction |
| Native state | 4.1 | 104 TPM2 vectors, eight RSA/ECC AKs, 64 mutations, 104 recompositions, separate compiled Java verifier with 19 assertions | software TPM, shared frozen packet, same operator and x86_64 host |
| Durable revocation | 4.0 | 372-case process lab plus five-container/two-effect-instance/fault-proxy replay; 540 reverified signatures; 15/15 saved-result checks | same operator, one physical host and centralized SQLite trust domain |
| Typed crosswalk | 3.6 | total 125-row transfer, separate SQL execution, exhaustive mutation/omission tests, sealed blind 46-task semantic kit | author-defined ontology; no returned independent semantic mappings |
| External labels | 2.0 | neutral 104-case kit, separated archives, validator, bootstrap, confusion matrices and kill gate | zero human responses |
| Second physical host | 2.0 | 210-member capsule passes a hash-bound clean same-host replay; x64/ARM64 external-run contracts are prepared | no outside machine/operator result exists |
| Public licensed artifact | 2.0 | rights inventory, proposed split, CFF, CodeMeta, Zenodo template, SBOM, RO-Crate and hostile replay protocol | no rightsholder licence grant, public immutable release, DOI or outside replay |
| Submission package | 3.4 | JAIR-formatted deterministic PDF, answers, checklist architecture, internal referee and release governance | authorship/declarations and all external evidence/release gates remain open |

## Exact 5/5 acceptance gates

### A. Scientific article overall

Required evidence:

1. freeze the claim/evidence/ceiling table against one immutable release;
2. obtain at least two substantive reviews from people not involved in
   corpus construction, with responses and changes recorded;
3. obtain one independent hostile reproduction from the public release;
4. re-run a blinded referee against the final PDF and artifact;
5. show that every headline claim has either public evidence or an explicit
   limitation in the abstract, results, and conclusion.

Pass assertion:

```text
all_headline_claims_trace_to_public_artifact == true
independent_hostile_replays >= 1
unresolved_major_referee_findings == 0
```

### B. Native state

Required evidence:

1. run the frozen packet on a machine with a hardware TPM 2.0;
2. record TPM manufacturer/firmware, EK/AK provenance appropriate to the
   claim, OS, architecture, clock source, and command versions;
3. regenerate fresh challenges and quotes without using the software-TPM
   roots;
4. run both Python and compiled Java paths;
5. have an outside operator introduce at least the eight declared mutations
   plus one operator-chosen hostile substitution;
6. publish raw quotes, non-secret public material, transcripts, results and
   manifests under approved licences.

Pass assertion:

```text
hardware_tpm == true
outside_operator == true
baseline_parity == 104/104
declared_mutations_rejected == 64/64
operator_hostile_mutations_rejected == all
public_replay_manifest_verified == true
```

Failure handling: a hardware or cross-implementation disagreement is a
first-class result; freeze it, localize the first divergent gate, and narrow
the claim rather than deleting the run.

### C. Durable revocation

Required evidence:

1. place status, effect and datastore failure domains on genuinely separate
   hosts or managed services;
2. run x86_64 and ARM64 jobs from the frozen release;
3. inject response loss, process death, host loss, delay, duplication and
   network partition;
4. retain an idempotency and linearization trace that lets an outside checker
   decide false allow, false deny and duplicate effect without trusting the
   service summary;
5. repeat with a non-SQLite transaction mechanism or clearly scope the claim
   to centralized serializable storage;
6. obtain an outside hostile run from the immutable public artifact.

Pass assertion:

```text
atomic_false_allow == 0
atomic_false_deny == 0
duplicate_effects == 0
all_injected_ambiguous_outcomes_resolved == true
architectures >= 2
outside_operator == true
```

### D. Typed crosswalk

Required evidence:

1. dispatch the sealed 46-task kit to at least two domain-qualified
   annotators who have not seen the author mapping;
2. seal each returned mapping before opening the author mapping;
3. publish agreement, disagreements, rationales and adjudication rules;
4. implement at least one mapping or adapter by a third party;
5. rerun totality, wrong-class and omission tests against the adjudicated
   mapping;
6. narrow or rename classes wherever semantic disagreement survives.

Pass assertion:

```text
independent_complete_mappings >= 2
author_mapping_opened_after_response_seals == true
adjudicated_totality == 46/46
wrong_class_detection == 46/46
omission_detection == 46/46
public_deidentified_record == true
```

The result may validate transfer of typed failure structure. It must not be
renamed protocol interoperability without actual protocol interaction.

### E. External labels

Required evidence:

1. confirm ethics/privacy applicability and compensation/data-handling terms;
2. recruit two independent labellers who receive only the three-file neutral
   annotator kit;
3. freeze both 104-row responses before comparison;
4. execute the preregistered 10,000-replicate analysis;
5. stop or revise if verdict kappa is below 0.60;
6. adjudicate disagreements without overwriting raw responses;
7. obtain permission to release deidentified labels and the analysis record;
8. have another operator reproduce the analysis from the public artifact.

Pass assertion:

```text
complete_independent_responses == 2
verdict_kappa >= 0.60
raw_responses_hash_sealed == true
adjudication_trace_preserved == true
public_analysis_hostile_replay == PASS
```

### F. Second physical host and architecture

Required evidence:

1. one outside x86_64 host and one outside ARM64 host run the exact release;
2. each operator starts from a clean account or machine, records environment
   provenance, verifies the outer digest before extraction, and uses no
   unrecorded local source tree;
3. each signs the result manifest and records every deviation;
4. at least one run is intentionally hostile: remove a payload, alter a
   result, change a policy anchor, and confirm that the acceptance gate fails;
5. publish logs and manifests next to the immutable release.

Hosted VMs can close the architecture and independent-environment gates, but
must not be described as proof of a particular physical machine unless the
provider exposes evidence that supports that statement.

Pass assertion:

```text
outside_x86_64_replay == PASS
outside_arm64_replay == PASS
hostile_tamper_detection == PASS
signed_public_run_manifests == 2
```

### G. Public licensed artifact

Required evidence:

1. confirm authors, rightsholders, CRediT, affiliations and declarations;
2. approve the exact licence split; proposed identifiers alone are no grant;
3. resolve or exclude every third-party redistribution HOLD;
4. run secret, personal-data and deanonymization scans on the exact release
   tree;
5. create the dedicated repository, protected version tag and immutable
   release;
6. attach SBOM, RO-Crate, source capsule, checksums and provenance
   attestations;
7. deposit the identical release in a DOI-minting repository;
8. obtain and publish an outside hostile replay against the DOI bytes.

Pass assertion:

```text
approved_licence_files_present == true
third_party_holds == 0
immutable_release == true
doi_resolves_to_identical_digest == true
artifact_attestation_verified == true
outside_hostile_replay == PASS
```

### H. Submission package

Required evidence:

1. close A–G or explicitly reduce every claim whose evidence gate remains
   below 5;
2. confirm title, author order, affiliations, ORCIDs, CRediT, funding,
   conflicts, acknowledgements and AI-assistance statement;
3. verify the current JAIR format, submission questions, checklist, reference
   metadata, preprint policy and publication economics;
4. run deterministic PDF builds and a clean-source artifact replay;
5. obtain a final independent technical and editorial review;
6. record the editor-facing novelty statement and why the systems experiments
   answer a general AI research question.

Pass assertion:

```text
placeholder_fields == 0
unresolved_checklist_no_or_partial == 0
unresolved_major_referee_findings == 0
final_pdf_hash_recorded == true
final_artifact_doi_recorded == true
submission_verdict == GO
```

## External-action queue

The following actions cannot be replaced by more local computation:

| Priority | Action | Reserved decision |
| ---: | --- | --- |
| 1 | approve author/rightsholder metadata and exact licence scope | authors/rightsholders |
| 2 | approve a dedicated public repository and DOI release sequence | responsible author |
| 3 | approve human recruitment, ethics/privacy record and dispatch | responsible author |
| 4 | select independent x86_64, ARM64 and hardware-TPM operators | responsible author |
| 5 | approve public disclosure/deanonymization timing | responsible author |

Until those decisions and outside events occur, the honest deliverable is a
high-maturity internal flagship plus release candidate—not eight fabricated
5/5 scores.
