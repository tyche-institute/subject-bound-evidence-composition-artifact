# Intellectual-neighbour map — r4

Date: 2026-07-27

This map separates the paper's actual claim from adjacent literatures. It is a
novelty-control instrument, not a claim of exhaustive systematic review.

| Neighbour | What it establishes | What remains distinct here |
| --- | --- | --- |
| Verification of agent-based artifact systems | data-aware artifact lifecycles can be model checked in multi-agent systems | the present theorem concerns information lost when a decision composer sees only local verdicts rather than protected-subject projections |
| Cooperative monitoring of multi-agent plans | distributed observations can diagnose expected-effect failures under partial observability | the present decision is pre-commit authorization applicability, not post-hoc plan-trajectory diagnosis |
| Norm monitoring in multi-agent systems | norms can be monitored selectively under resource constraints | local monitors may all accept artifacts whose protected subjects do not compose |
| Data-driven norm revision | observed outcomes can trigger revision of conditional norms | a decision can fail before revision because policy version, authority, state, measurement, and effect do not bind to one transaction |
| Negative-side-effect avoidance | incomplete system knowledge creates unsafe side effects | strong but inapplicable evidence can create a false green even when no individual verifier is wrong |
| Runtime attestation | a signed quote can bind measurements to a challenge and PCR state | a valid quote is neither action authority nor proof that the authorised effect was committed |
| Credential/status verification | signatures and status can validate authority objects | appraisal-time validity is insufficient if status and effect are not atomically committed |
| Concurrency/linearizability | concurrent operations can be reasoned about through a legal sequential history | the paper instantiates this at the authorization boundary and records status at effect linearization |
| Multi-criteria scoring | several dimensions can be aggregated into a rank or score | critical evidence gates must remain non-compensable; reference-set choice and uncertainty are first-class provenance |
| Metamorphic testing | relations can test programs without a full point oracle | the SAFE lane specifies domain-facing metamorphics for aggregation, severity, perturbation, uncertainty, and reference-set poisoning |
| Reproducible benchmarks | frozen corpora enable repeatable comparisons | the decision record preserves native state, first decisive gate, subject, policy/verifier identity, and commit evidence across ecosystems |

## Central novelty claim

The paper's unit of analysis is not an artifact and not a verifier. It is an
authorization transaction whose accepted evidence objects must share a
protected subject and whose revocable authority must remain valid at the
effect's linearization point. Local validity is therefore necessary but not
sufficient; composition requires explicit typed binding and a non-compensable
decision rule. Formally, a matched and a subject-mismatched transaction can
have the same all-one vector of local verdicts. Any deterministic composer
whose only input is that vector must return the same decision for both and
therefore cannot both allow the matched case and deny the mismatched case.

## Negative-space claims

The paper does **not** claim:

- that the designed corpus estimates deployment prevalence;
- that a Tyche Ed25519 profile is standards interoperability;
- that one frozen `swtpm` vector establishes hardware diversity;
- that a loopback service measures distributed-system performance;
- that the eight-class crosswalk proves semantic equivalence;
- that an undispatched labelling packet provides external validation.

## Citation anchors

- Francesco Belardinelli, Alessio Lomuscio, and Fabio Patrizi. “Verification
  of Agent-Based Artifact Systems.” *JAIR* 51 (2014).
  <https://doi.org/10.1613/JAIR.4424>
- Ivano Micalizio and Pietro Torasso. “Cooperative Monitoring to Diagnose
  Multiagent Plans.” *JAIR* 51 (2014).
  <https://doi.org/10.1613/JAIR.4339>
- Rodrigo Criado. “Resource-bounded Norm Monitoring in Multi-agent Systems.”
  *JAIR* 62 (2018), 153–192. <https://doi.org/10.1613/jair.1.11206>
- Davide Dell'Anna et al. “Data-Driven Revision of Conditional Norms in
  Multi-Agent Systems.” *JAIR* 75 (2022), 1549–1593.
  <https://doi.org/10.1613/jair.1.13683>
- Shashank Saisubramanian et al. “Avoiding Negative Side Effects due to
  Incomplete Knowledge of AI Systems.” *JAIR* 74 (2022), 143–177.
  <https://doi.org/10.1613/jair.1.13581>
- Maurice Herlihy and Jeannette Wing. “Linearizability: A Correctness Condition
  for Concurrent Objects.” *ACM TOPLAS* 12(3), 1990.
  <https://doi.org/10.1145/78969.78972>
- Trusted Computing Group. *TPM 2.0 Library Specification*.
  <https://trustedcomputinggroup.org/resource/tpm-library-specification/>
