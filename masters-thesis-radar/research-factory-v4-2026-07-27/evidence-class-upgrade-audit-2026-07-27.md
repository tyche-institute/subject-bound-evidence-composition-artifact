# Evidence-class upgrade audit — r4

Manuscript: *Subject-Bound Evidence Composition for Delegated AI Actions*  
Audit date: 2026-07-27  
Decision: **STRONG INTERNAL CLOSURE — NOT SUBMISSION READY**

“Closed” below always means closed for a named bounded laboratory, not for the
whole evidence class.

| Evidence-class change | Laboratory status | Executed evidence | Remaining ceiling |
| --- | --- | --- | --- |
| External labels | **PACKET CLOSED; RESULT OPEN** | Neutral 104-case derivative, packet-specific Ed25519 re-signing, known-token audit clean, 104/104 typed tuples preserved, response schema and sealed labels | Undispatched; no external labels, adjudication, agreement, or correctness evidence |
| Native signed authority | **CLOSED for Tyche profile** | 8/8 exact verdict/first gate under real Ed25519 verification | Not WAVE/JEDI/OAuth/DID/A2A conformance; no external issuer or lifecycle |
| Isolated second host | **CROSS-ENVIRONMENT CLOSED; PHYSICAL HOST OPEN** | Offline digest-pinned container, read-only inputs/root, empty route, outbound `ENETUNREACH` | Same host, kernel, CPU, and compiled wheel lineage |
| Mutation-generated transactions | **CLOSED internally** | 38/38 single-fault oracle pairs, 570/570 typed fields; 12/12 multi-fault pairs, 180/180 fields | Same programme, designed mutations and expectations |
| Prospective revocation | **SCHEDULED AND LOCAL-LIVE CLOSED** | 13/13 signed scheduled rows; 276 signed concurrent HTTP traces retaining 890 signed responses; atomic guard 0 false allow/deny | One process/loopback; no multi-host, partition, clock-skew, propagation, or performance claim |
| Native runtime attestation | **CLOSED for one frozen vector** | Actual `tpm2_checkquote`; 7/7 hash-pinned author cases; four native TPM rejects plus two binding-precheck rejects | `swtpm`, one public frozen quote; no hardware diversity or deployed workload |
| Typed cross-ecosystem transfer | **CLOSED analytically** | 21/21 EATF rows preserve two first-party TypeScript/Python native results; 104/104 transaction rows preserve first gates; total crosswalk | No implementation independence, semantic equivalence, interoperability, or external replication |
| Decision clock | **CLOSED for the model** | Explicit appraisal/commit clock plus server-side linearization indices; bounded atomic-safety proposition | Not an externally standardized clock or distributed-clock experiment |

## Exact r4 records

- Neutral labelling packet:
  `external-label-packet-neutral-104/`; transaction hash
  `fe56e226687cf38f31c6c692efd75245ac2a9ea6f474135f082883668b3da5e9`.
- Native runtime result:
  `labs/native-runtime-attestation/results.json`; hash
  `70b73cd540434a192d64ed11e1c446a1857747326712fd87419f17e8777937b6`.
- Live race result:
  `labs/live-revocation-service/results.json`; hash
  `f61af5b5be7fb2ba300dcd6cfe4ea3fadeacc137fac74843402dc6e465fc1dfa`.
- Typed transfer result:
  `labs/cross-ecosystem-typed-transfer/results.json`; hash
  `7bb3896fdf324405917e2ff7d76d76dd22de2bf43240e7a17f4b63a8006e0c90`.

## What changed relative to r3

The r3 review asked either to execute native runtime appraisal and a live
revocation service or narrow the claims. r4 does both: it executes bounded
companions and keeps the broader hardware/deployment claims excluded.

The leaking 90-case labelling packet is superseded for future use by a
label-isomorphic 104-case packet. The original packet remains frozen as a
negative provenance result; it is neither deleted nor retrospectively
described as blind.

The EATF transfer does not collapse verifier states into a universal
eight-class truth. It retains all native codes and uses the crosswalk only for
comparison. Collapsing each corpus to Boolean `REJECT` would erase 120 EATF
and 378 transaction-state pairs, 498 total.

## Verdict

The accurate evidence statement is now:

> Native Ed25519 authority fixtures, deterministic mutations, signed scheduled
> revocation, one native software-TPM appraisal, one local concurrent
> revocation service, typed EATF transfer, and offline cross-userland replay
> have been executed. A neutral external-labelling packet is sealed but
> undispatched. External adjudication, independent physical-host reproduction,
> hardware/deployed diversity, and an immutable licensed public release remain
> open. The work is a strong internal empirical flagship, not yet a
> submission-ready claim about deployed systems.
