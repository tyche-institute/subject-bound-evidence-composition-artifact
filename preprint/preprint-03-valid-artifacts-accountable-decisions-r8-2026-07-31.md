---
title: "Subject-Bound Evidence Composition for Delegated AI Actions"
subtitle: "Executable Indistinguishability Witnesses and Commit-Time Revocation"
author: "Anton Sokolov — Tyche Institute, Tallinn, Estonia — ORCID 0000-0003-2452-7096"
date: "2026-07-31"
status: "JAIR submission candidate (r8); no journal submission has been sent"
---

## Abstract

Delegated AI workflows can contain individually valid policy documents,
signed evidence, runtime-state results, authorization paths, measurement
scores, and effect receipts and still provide no end-to-end basis for the one
action they are meant to authorize. We show constructively that this failure
class is representable, localizable, and repairable at the composition
boundary. The study evaluates a typed, non-compensable decision rule
$\operatorname{Allow}(x)=P\land E\land S\land A\land M\land B$ over five
artifact predicates — exact policy state, evidence integrity/freshness,
runtime state, authority-to-effect validity, and measurement support — plus an
explicit cross-artifact binding stage $B$ over the implemented effect,
resource, report-time, and measurement-profile coordinates.

A frozen 104-transaction corpus contains eight witnesses in which all five
component verifiers pass and the composition still denies at a named binding
gate, each paired with a matched all-valid lookalike that is allowed. The
motivating case — a correctly signed receipt reporting a WRITE effect where
the valid delegation path grants only READ — is denied at `binding.effect`.
Against the strict rule, point-only measurement, four-of-five majority, and
artifact-validity ablations produce 2, 31, and 48 false allows on the designed
corpus; the majority count decomposes exactly into 23 single-fault denials
plus the 8 cross-layer denials. Partial subject bindings that omit time or
profile coordinates leave 1--3 false allows. A SAFE-metric metamorphic suite
separates aggregation, measurement-profile identity, reference-set choice, and
bootstrap-confidence semantics that a scalar score omits.

Companion laboratories strengthen the evidence classes at the rule's two
runtime boundaries. Native appraisal re-derives every state decision from 104
transaction-bound TPM2 (Trusted Platform Module) quotes under eight fresh
software-TPM roots, rejecting 64/64 predeclared mutations, and an identified
virtual-machine host exposing a Microsoft vTPM independently verifies 104/104
live quotes and rejects 64/64 mutations. A process-isolated revocation
laboratory with a durable transactional log executes 372 cases: the atomic
status-and-effect guard has zero safety errors and zero duplicate effects,
all 96 disconnect/retry and kill/restart cases recover without duplicates,
and every read-based profile exposes stored counterexamples. A typed
crosswalk transfers a public two-language artifact-verifier result while
preserving all native rejection codes (21/21 rows; a separate SQLite path
reproduces 125/125 rows and detects 46/46 mutation and 46/46 omission
changes). Two hosted repetitions reproduce the sealed four-lane contract on
x86_64 and ARM64 job VMs.

All counts are coverage on author-designed synthetic fixtures, not
deployed-system rates, and composition-level expected labels are analytic by
construction; the supported claim is an executable benchmark and systems
result — local Boolean validity cannot substitute for typed composition over
the implemented subject coordinates, and revocation status and effect require
one commit boundary — not production validity, hardware-rooted attestation,
or interoperability.

**Keywords:** delegated AI; autonomous agents; norm monitoring;
authorization; policy provenance; measurement uncertainty; SAFE AI; evidence
composition; cross-layer binding; runtime attestation; revocation;
reproducibility.

## 1. Introduction

An agent may present a valid identity and execute a schema-valid tool call.
Its machine may report an affirming attestation result. The action receipt
may be correctly signed and internally well formed while reporting a claimed
effect. A
model-quality score may exceed a policy threshold. These statements do not
entail that the specific effect was both authorized and supported by an
applicable measurement.

The gap is compositional, and it is a classical one: component certificates
do not compose into a system certificate without explicit discharge of the
assumptions each certificate rests on [29]. Each verifier here answers a
scoped question:

- a policy verifier identifies which appraisal rule was active;
- an evidence verifier checks integrity and freshness;
- a state verifier consumes a typed appraisal result; the frozen source
  fixtures encode it structurally, and the native overlay re-derives it from
  transaction-bound TPM2 evidence;
- an authority verifier checks whether a delegation path covers an action,
  with a terminal effect check against the receipt inside its own case file;
- a measurement verifier checks profile applicability and inferential
  support.

Effect is not a sixth artifact with a sixth verifier. It is a subject that
several artifacts describe at once, and no single verifier can see all the
descriptions. The policy artifact carries the required effect and the
required measurement profile; the evidence artifact carries the effect,
resource, and issue time actually reported; the authority artifact carries
the terminal narrowed scope and the interval in which the whole delegation
path is valid; the measurement artifact carries the profile the appraisal was
actually run under. A predicate over all four has no local home. The
component interfaces cannot force a mismatch between the canonical action
and the receipt's reported effect to surface as an authority or evidence
failure: neither layer can see both sides of the comparison.

Local validity may coexist with global denial. For example, a signed but
superseded policy can be authentic; a replayed receipt can retain a valid
signature; a point estimate can exceed a threshold while its lower
confidence bound does not; and an evidence receipt can validly report a WRITE
effect when the valid delegation path permits only READ.

That last case is the worked example, evaluated in both directions. Under a
composition of the five scalar layer verdicts alone, the verifier **allows**
it: a correctly Ed25519-signed evidence object with
effect `ledger.write` on resource `invoice-999` and an unseen nonce,
evaluated under a policy whose required effect is `ledger.read` against an
`ALLOW` delegation path whose terminal grant carries only `ledger.read` on
`invoice-123`, returned policy `PASS`, evidence `PASS`, state `PASS`,
authority `ALLOW`, measurement `PASS`, verdict `ALLOW`, and first rejecting
gate `verified`. With the explicit binding stage, the same transaction
returns binding result `EFFECT_MISMATCH`, verdict `DENY`,
and first rejecting gate `binding.effect` — with all five component
verifiers still passing, and with a matched lookalike that differs only in
the reported subject fields still allowed at gate `verified`. A standalone
acceptance test builds both transactions from first principles rather than
reading the frozen corpus, so the result cannot be satisfied by a corpus
entry carrying a convenient label (Sections 4, 5.4, and 6.3).

This article evaluates the following decision rule:

$$
\operatorname{Allow}(x)=
P(x)\land E(x)\land S(x)\land A(x)\land M(x)\land B(x),
$$

where $P$ is exact policy applicability, $E$ is evidence
integrity/freshness, $S$ is runtime state, $A$ is authority-to-effect
validity, $M$ is measurement support, and $B$ is the implemented partial
binding. The rule is non-compensable: five passing predicates cannot offset
one failed predicate. $B$ is not a sixth artifact verifier and introduces no
sixth artifact. It is a well-formedness condition on the conjunction over
effect, resource, report time, and measurement profile fields extracted from
the policy, evidence, authority, and measurement artifacts. The current $B$
does not bind a state/workload subject or the other omitted coordinates listed
in Section 4.1. The conjunction is commutative; the *evaluation* order is
fixed separately and places $B$ last (Section 4).

The contribution is deliberately artifact-first. Theorem 1 frames the
problem as an information limitation and is proved in one line; the advance
this article claims is the executable instantiation — a typed
decision-transaction model, a frozen counterexample corpus with matched
lookalike controls, ablation identities, native state evidence, an atomic
revocation boundary, and cross-implementation, cross-architecture replays —
for the runtime accountability layer that delegated-agent deployments
currently lack. In AI terms, the object is the seam that norm monitoring
[30] and multi-agent plan diagnosis [37] study at the level of norms and
plans, approached here at the level of the evidence one delegated action
carries.

The work has three objectives:

1. establish the semantic limit of local validity and make its remedy
   executable, using explicit policy and measurement semantics, re-executed
   typed layer evaluators, a cross-layer binding stage, and matched
   indistinguishability witnesses;
2. test the two runtime boundaries abstracted by the main corpus: native
   appraisal of a frozen attestation vector and atomic revocation-status
   checking with effect commit; and
3. test whether the typed first-decisive-state representation transfers to a
   separately built artifact verifier while preserving its native diagnostic
   codes.

The result is an executable artifact study, not a claim of production
readiness or population-level safety improvement.

## 2. Research Questions and Claim Boundaries

### RQ1: When is local validity insufficient?

Can individually passing policy, evidence, state, authority, and measurement
verifiers be locally indistinguishable between a transaction matched on the
implemented coordinates and one mismatched on a required coordinate that must
be denied? Within this question we
test exact policy state, SAFE measurement semantics, typed composition,
partial-binding ablations, named-gate localization, and the number of
constructed all-local-pass denials in the frozen corpus.

### RQ2: Where must runtime authority become atomic?

Does native offline appraisal preserve all 104 transaction state classes while
rejecting targeted quote, PCR, freshness, and subject-binding mutations, and,
in process-isolated signed-status races with durable retry and restart, does a
linearizable status-and-effect guard avoid the false allows and duplicate
effects exposed by incomplete protocols?

### RQ3: What survives transfer across verifier ecosystems?

Can a separately constructed two-language artifact-verification experiment be
represented in the same first-decisive-state form without discarding native
rejection codes, and how much diagnostic distinction would a Boolean
valid/invalid projection erase?

### Threat model and adversary assumptions

The laboratories model an adversary who can present, substitute, replay,
tamper with, or withhold individual artifacts: policies (missing, stale,
substituted, re-signed after tampering), evidence objects (tampered
payloads, replayed nonces, mismatched subject fields), attestation-result
objects and TPM2 quote material (mutated messages, signatures, Platform
Configuration Register (PCR) blobs, challenges, bindings), delegation paths (broken lineage, expired edges,
amplified scope), measurement fixtures (substituted profiles), and
revocation timing (races between status reads, revocation, and effect
commit). The adversary cannot break Ed25519 signatures, corrupt the shared
composition-rule module, or alter frozen corpora without changing recorded
hashes. Key compromise, side channels, denial of service, and supply-chain
attacks on the toolchain are out of scope. The corpus instantiates this
adversary by construction; no claim is made about attacker prevalence in
deployed systems.

### Claim ceiling

The study may report exact observations from frozen artifacts. It does not
claim:

- prevalence in deployed agent systems;
- a defect in Veraison, A2A, MCP, RATS, SCITT, SAFE AI, or TOPSIS;
- ownership of the SAFE integration functions of Giudici and Kolesnikov;
- invention of authenticated or transitive delegation;
- externally independent labels;
- production interoperability or legal compliance;
- sufficiency of the proposed passport fields for every environment.

Three additional boundaries apply:

- external independence of the expected labels: all labels are
  author-written within this research programme, and the composition-level
  labels are generated by the same shared composition-rule module the
  composed verifier imports, so agreement at the composition level is
  analytic (Section 6.3);
- cryptographic attestation in the **source corpus**: its original state
  predicate is a structural appraisal of a corpus-supplied
  attestation-result object, with no TPM, no Veraison, and no verification of
  any runtime. A separate 104-transaction companion supplies
  transaction-bound TPM2 evidence for every state decision and recomposes
  the complete tuples, but remains software-TPM evidence on one host rather
  than attestation of a deployed workload;
- real-world false-allow rates: every false-allow count in this article is
  a count on a designed corpus, a corpus-coverage statistic, and must not
  be read as an estimate of prevalence anywhere.

A separate boundary applies to the binding stage. It is a deterministic
string-agreement and interval-containment condition over subject fields read
out of corpus-supplied artifacts. It
verifies no signature, takes no measurement, contacts no attestation service,
and does not upgrade any corpus-supplied flag into a cryptographic fact. The
denials it produces are denials on a designed corpus, and the claim it
supports is representability and localization, not detection performance.

The companion experiments introduce three further ceilings:

- the seven-case native companion is one frozen `swtpm` vector; the
  104-transaction companion uses eight fresh software-TPM
  roots, but neither experiment supplies a hardware root, live attested
  workload, manufacturer endorsement, or independent-host evidence;
- the 276-case service is one-process loopback; the durable service
  separates status, effect, and contender processes with durable
  linearization and recovery, and a five-container extension adds two
  interchangeable effect instances plus a deterministic fault proxy. Both
  remain on one physical host with centralized SQLite linearization rather
  than multi-host, Internet-scale, consensus, or performance evidence;
- cross-ecosystem transfer means that an explicit analytic crosswalk preserves
  native first-failure codes from two executable corpora; it does not mean
  semantic equivalence, protocol interoperability, or independent
  validation.

## 3. Related Work and the Remaining Composition Seam

### 3.1 Measurement integration

Kolesnikov's master's thesis proposes an integrated S.A.F.E.-AI compliance
score built from accuracy, explainability, and robustness vectors, denoted
RGA, RGE, and RGR, and studies arithmetic, geometric, root-mean-square, and
TOPSIS integration [1]. Giudici and Kolesnikov develop this integrated SAFE
measurement line in a journal article and working paper [2, 3]. Babaei and
Giudici provide a statistical SAFE AI package [4].

We do not propose a replacement metric. We test whether an evidence identity
distinguishes aggregation, profile, reference-set, dependence, and
confidence semantics that a scalar score alone omits.

### 3.2 Delegation and authorization

South et al. argue that AI agents require authenticated and auditable
delegation, including agent-specific credentials and robust scope
translation [5]. WAVE already provides signed authorization graphs,
transitive scoped delegation, revocation, and independently verifiable
authorization proofs [6]. JEDI provides restricted key delegation across
scope and time [7]. We note that these two systems share several authors
from one research group, so they are related lines of work rather than two
independent bounds on novelty; either alone suffices to bound any claim
about delegation primitives.

A second adjacent family binds tokens and assertions to their intended
subject or audience inside one credential system. The confused-deputy
problem [38] names the underlying failure; OAuth 2.0 mitigates it with
resource indicators [39], rich authorization requests [40], and
sender-constrained tokens [41], and SAML audience restriction, XACML
condition machinery [28], W3C Verifiable Credentials [42], and SPIFFE
workload identities [43] each bind an assertion to a scope, condition, or
workload. General-purpose policy engines such as Open Policy Agent evaluate
one policy over an assembled request context [44]. These mechanisms
constrain one artifact or centralize one decision; none of them composes
five independently verified artifact families while preserving each native
typed verdict and a first-decisive-gate localization. A single policy
engine evaluating the full request context could encode the binding
predicate $B$ — but it would then *be* the composer this article studies,
and it would still need the typed inputs, the subject projections, and the
witness corpus evaluated here. The contribution is the typed interface and
the executable evidence, not a claim that no engine could host the rule.

The remaining experimental seam is the join from a valid authorization path
to the canonical action and effect described by evidence. Our authority
layer asks whether the terminal action remains entailed after delegation,
freshness, status, scope, and binding checks — but it asks that question
only of the objects inside its own case file. The join across artifacts
belongs to the composition and is implemented there (Sections 4 and 5.4).

### 3.3 Policy versioning and change impact

The policy-state subquestion of RQ1 has prior art in policy analysis. Margrave verifies access-control
policies and computes the semantic impact of policy changes [27], and XACML
3.0 carries an explicit `Version` attribute on policies and policy sets
[28]. Those tools answer what a policy means and how an edit changes it. Our subquestion
asks a narrower operational question: whether the decision procedure binds
each decision to the exact policy identity, version, validity window, and
digest that were active at decision time, so that an authentic but
superseded or substituted policy cannot silently govern an appraisal.
Versioning metadata existing in a policy language does not by itself make
the verifier check it; the replay corpus tests the checking.

### 3.4 Agent benchmarks

TeamBench evaluates coordination under operating-system-enforced role
separation [8]. AgentRedBench includes underspecified-authorization attacks
over SaaS integrations [9]. ToolPrivacyBench evaluates field-to-tool
authorization for private information [10]. TraceSafe localizes mutated
safety failures in tool trajectories [11]. Heartbeat-Bound Hierarchical
Credentials evaluates bounded hierarchical revocation [12]. Li benchmarks
authenticated account-level actions that leave the user's assigned task, in
a high-performance-computing setting [13].

These works preclude broad claims such as the first unauthorized-action,
role-isolation, trajectory-localization, or cascading-revocation benchmark.
Our narrower object is typed composition: separately appraised artifacts
that become invalid only when exact policy, evidence, state, delegation,
measurement, and effect relations are joined.

### 3.5 Attestation and transparent evidence

Remote ATtestation procedureS (RATS) separates Evidence, Verifier
appraisal policy, reference values, and Attestation Results [14]. Supply Chain Integrity, Transparency, and Trust (SCITT) distinguishes
signed statements, transparency registration, receipts, and later audit
[15]. A2A and MCP
define agent interaction and tool-facing authorization contexts [16, 17].
NIST's software and AI agent identity initiative identifies authorization,
auditing, and non-repudiation as active infrastructure problems [18].

These mechanisms motivate typed boundaries. An attestation result is not an
action grant; a transparency receipt is not proof of measurement adequacy;
and an authenticated tool call is not necessarily within a delegated task.
The composition question, what discharges the assumptions between such
certificates, is the modular-certification problem in an agent setting
[29].

### 3.6 Closest JAIR neighbours: artifacts, diagnosis, and norms

Belardinelli, Lomuscio, and Patrizi formalize artifact-centric multi-agent
systems with data/lifecycle semantics and temporal-epistemic model checking
[36]. Micalizio and Torasso diagnose expected-effect failures in distributed,
partially observable multi-agent plans, including dependent failures [37].
Criado treats norm monitoring as a resource-allocation problem under
incomplete observations and proves properties of a resource-bounded monitor
[30]. These are closer technical neighbours than credential syntax.

Our narrower object is a single authorization transaction at one decision
boundary. We neither model-check an artifact lifecycle, diagnose a plan
trajectory, nor choose which norms to observe. We show that a composer seeing
only local Boolean verdicts cannot distinguish matched from mismatched
transactions, then retain typed projections, the first decisive gate, and
commit-time status. The distinction is summarized explicitly:

| Work | Decision object | Partial observation | Cross-artifact identity | Commit-time status | Main guarantee/evaluation |
| --- | --- | --- | --- | --- | --- |
| Belardinelli et al. [36] | artifact-centric MAS lifecycle | agent knowledge | relational artifact data | temporal lifecycle | finite abstractions and model checking |
| Micalizio and Torasso [37] | multi-agent plan execution | distributed action observations | dependencies between action failures | asynchronous trajectory | diagnosis of primary/secondary failures |
| Criado [30] | monitored norm set | resource-bounded observations | norm/event applicability | monitor execution | monitor properties and simulations |
| this work | one delegated authorization transaction | local typed verifier outputs | explicit partial subject projections | atomic status/effect boundary | local-verdict theorem plus executable witnesses |

Dell'Anna et al. revise conditional norms from execution traces [31], while
Saisubramanian et al. mitigate side effects caused by incomplete open-world
models [32]. They remain relevant conceptual neighbours, but are not claimed
as the closest technical precedents.

### 3.7 Typed verifier states and concurrent commit

The public first-party EATF (Agent Trust Framework) toolkit supplies a
two-language Action Evidence Package (AEP) verification example with an
author-defined decision-path oracle and native first-failure codes in
TypeScript and Python [33]. The toolkit is published under the historical
expansion "Agent Evidence Package"; this article uses the framework's
current canonical expansion, "Action Evidence Package", for the same object
model, and cites the published artifact under its own recorded title. We use
that result only to test representational transfer: its codes remain native
and are crosswalked to a coarse shared ontology for analysis.

For revocation, the relevant systems property is linearizability: concurrent
operations should appear in a single order consistent with their real-time
precedence [34]. A status read followed by a separate effect is not an atomic
operation, even when the read is fresh and signed. Our live-race laboratory
therefore compares read-based profiles with a status-and-effect guard whose
check and commit share one server-side linearization point. Native state
appraisal uses the TPM 2.0 quote-verification interface but only over a frozen
software-TPM vector [35].

## 4. Decision-Transaction Model

The implemented record makes the cross-artifact subjects explicit through
`canonical_action` and `observed_effect`. Both fields are written by the
corpus builder, re-derived by the verifier through the shared
`composition_rule.subjects_of` extractor, and read by the binding stage. This
checks serialization and plumbing, not independent subject extraction. The
record is:

```text
DecisionTransaction {
  id                          -- stable transaction identifier
  family                      -- one of the five corpus families
  policy_vector_id            -- selects the signed policy and its evidence
  evidence_variant_id         -- optional evidence override, else null
  measurement_fixture_id      -- selects the measurement fixture
  measurement_fixture_source  -- provenance of that fixture
  state_fixture_id            -- names the attestation-result fixture
  attestation_result {        -- the embedded appraisal input
    status, issued_at, expires_at,
    observed_digest, reference_digest, profile }
  authority_case_id           -- selects the typed delegation-path case
  canonical_action {          -- the action the artifacts jointly authorize
    effect, resource, operation,
    granted_tools, granted_resources,
    authorised_from, authorised_until,
    measurement_profile }
  observed_effect {           -- the effect as reported and appraised
    effect, resource, issued_at, measurement_profile }
  expected {                  -- the author-written expected label
    verdict, first_rejecting_gate, failed_layers,
    layer_results, binding_result, binding_gate }
  note                        -- optional prose, on the binding family only
}
```

Neither subject record is a new artifact, and neither introduces a sixth
verifier. Every field is read out of an artifact that one of the five
verifiers already inspects:

- `canonical_action.effect` and `canonical_action.measurement_profile` are
  the signed policy object's `required_effect` and
  `required_measurement_profile`;
- `canonical_action.resource` and `.operation` are the delegation case's
  terminal action;
- `canonical_action.granted_tools` and `.granted_resources` are the terminal
  narrowed scope, that is the grant carried by the last delegation edge,
  which the authority verifier has already certified to be a subset of every
  parent scope whenever it returns `ALLOW`;
- `canonical_action.authorised_from` and `.authorised_until` are the
  intersection of the per-edge validity windows, the interval in which the
  whole path is valid;
- `observed_effect.effect`, `.resource`, and `.issued_at` are fields of the
  signed evidence object whose signature the evidence layer verifies;
- `observed_effect.measurement_profile` is the profile identifier of the
  fixture the measurement layer actually appraised.

The corpus builder stores both records; the verifier re-derives them from the
re-executed inputs and asserts field equality, reported as `subject_matches`
in the shipped summary, so these are checked record fields rather than
decoration. They remain corpus-supplied strings throughout, and comparing
them is not attestation of anything.

Every layer returns a typed result rather than one undifferentiated Boolean,
and so does the binding stage:

```text
policy      in {PASS, MISSING, STALE, SUBSTITUTED, INVALID_SIGNATURE}
evidence    in {PASS, TAMPERED, REPLAY}
state       in {PASS, CONTRAINDICATED, STALE, REFERENCE_MISMATCH}
authority   in {ALLOW, DENY(gate, edge_id, edge_index)}
measurement in {PASS, FAIL_POINT, FAIL_LCB, PROFILE_MISMATCH}
binding     in {PASS, EFFECT_MISMATCH, RESOURCE_MISMATCH,
               TIME_MISMATCH, PROFILE_MISMATCH, UNDETERMINED}
```

The evaluation order is fixed, and the binding stage is last:

```text
policy -> evidence -> state -> authority -> measurement -> binding
```

All five layers are appraised to preserve a typed failure set. The
`first_rejecting_gate` follows the fixed order and supports deterministic
localization. It is not a claim that later failures did not exist.

Two properties of the binding stage belong here because they are properties
of the record; the rule itself is given in Section 5.4. First,
`failed_layers` deliberately remains a list over the five artifact layers
only. The binding stage never appears in it and has no row or column in the
co-failure matrix, so a transaction whose `failed_layers` is empty and whose
`verdict` is `DENY` is exactly a cross-layer denial. Second, the binding
function is pure over the two subject records and is evaluated for every
transaction regardless of the layer results, while the gate ladder consults
its outcome only after all five layers have passed. This is not fail-open: a
transaction with a failed layer is already a `DENY`, and the earlier gate is
the honest localization. When a required subject field is absent — for
example when a `MISSING` policy supplies no `required_effect` — the binding
result is `UNDETERMINED`, which never counts as a pass.

### 4.1 The formal spine: local-verdict indistinguishability

Let $a_P,a_E,a_S,a_A,a_M$ be the five artifacts and let
$V_i(a_i)\in\{0,1\}$ be their local acceptance predicates. Each accepted
artifact also exposes a partial subject projection $\pi_i(a_i)$: effect,
resource, interval, measurement profile, or some subset. Define

$$
L(x)=\bigwedge_{i\in\{P,E,S,A,M\}}V_i(a_i)
$$

and let $B(x)$ be the conjunction of the cross-artifact equality,
membership, and interval constraints in Section 5.4. The strict decision is
$C(x)=L(x)\land B(x)$. A Boolean-only composer observes
$v(x)=(V_P,V_E,V_S,V_A,V_M)$ but not the projections.

The implemented $B$ is deliberately a **partial protected-subject schema**:
it binds the policy-required effect and measurement profile to the signed
reported effect, the authority action/scope resource, and the report
`issued_at` to the authority interval. It does not yet bind principal,
request identifier, full action parameters/digest, state workload identity,
measured model/dataset identity, actual external effect time, or commit
receipt. The theorem applies when a required global relation is not observable
through $v(x)$ and a matched/mismatched pair exists; it does not automatically
establish every omitted field. The executable 104-case result establishes only
the four implemented relations. We use “subject-bound” below only in that
bounded sense. The implemented model additionally assumes a nonempty,
single, linear delegation path: the terminal-grant projection reads the
final edge of one path, no zero-hop fixture exists, and branching or
concurrent delegation graphs are out of scope.

**Theorem 1 (local-verdict indistinguishability).** Suppose there are a
matched transaction $x^+$ and a mismatched transaction $x^-$ such that

$$
v(x^+)=v(x^-)=(1,1,1,1,1),\qquad B(x^+)=1,\quad B(x^-)=0.
$$

Every deterministic composer $f$ whose only input is $v(x)$ returns the same
decision for $x^+$ and $x^-$. Consequently, it cannot both allow the matched
transaction and deny the mismatched transaction.

*Proof.* Equality of the observed vectors gives
$f(v(x^+))=f(v(x^-))$. The required decisions differ, so either the matched
transaction is falsely denied or the mismatched transaction is falsely
allowed. $\square$

This is an information limitation, not a defect specific to majority voting.
The corpus provides eight $x^-$ witnesses and six matched $x^+$ controls,
including a locally valid signed report for `ledger.write` paired with a
locally valid terminal grant for `ledger.read`. Their existence is
constructed evidence under the partial subject schema defined below, not a
deployment-frequency estimate.

**Corollary 1 (strict refinement).** $C(x)\Rightarrow L(x)$, and the
refinement is proper whenever a witness $x^-$ from Theorem 1 exists. This
follows directly from $C=L\land B$.

**Proposition 2 (failure of compensating composition).** Call a rule
*compensating* if it is a monotone function of a subset of the predicates
that can accept while at least one required predicate is false — for
example, any $k$-of-$n$ threshold with $k<n$, or any rule that omits a
predicate entirely. For any critical predicate $q$ omitted or outvoted by
such a rule, a transaction with $q(x)=0$ and all counted predicates equal
to one is accepted by that rule and denied by $C$. On this corpus the four-of-five false-allow count is an
algebraic identity:

$$
N_{\mathrm{FA,majority}}=
N_{\mathrm{single\ local\ failure}}+
N_{\mathrm{all\ local\ pass,\ binding\ fail}}=23+8=31.
$$

The 2 and 48 counts of the other weak ablations, and the 3/2/1 counts of the
partial subject joins, depend on which fixtures the corpus contains; they are
implementation observations on the frozen corpus, not algebraic properties
and not rate estimates.

### 4.2 Decision clock and the revocation linearization point

A decision transaction has more than one relevant time. We make that explicit
with a decision clock

$$
\kappa(x)=(t_P,t_E,t_S,t_A,t_M,t_B,t_C),
$$

where the first six components are the policy, evidence, state, authority,
measurement, and binding appraisal instants and $t_C$ is the effect-commit
instant. The clock is expository notation: no shipped artifact computes
$\kappa(x)$, and the live laboratories order events by the server-side
linearization index $\ell$ alone. Each artifact contributes its own
validity interval or freshness constraint. A revocation event has an effective instant $t_R$. Wall clocks,
however, are insufficient to order concurrent requests reliably, so the live
laboratory records a server-side linearization index $\ell$ for every status
read, revocation, guarded commit, and unguarded effect.

**Proposition 3 (atomic revocation safety under the laboratory model).** If a
revocation operation and a guarded effect commit are linearizable operations
on the same credential state, and the guarded commit writes the effect only
when that state is active at its linearization point, then every committed
effect was active at commit. A separate status read cannot provide this
guarantee: the admissible order

$$
\ell_{\mathrm{read}} < \ell_{\mathrm{revoke}} <
\ell_{\mathrm{effect}}
$$

returns an authentic active status and still commits after revocation.

*Argument.* The guarded operation holds the state lock across check and
commit, so either it linearizes before revocation and commits while active,
or revocation linearizes first and it denies. The three-operation schedule
above is a counterexample for every profile whose check and effect have
different linearization points. This is a property of the experimental
service semantics, not a universal deployment theorem.

A dependency-free Java model checker separately exhausts the bounded models
used by Theorem 1, Corollary 1, and Proposition 3. It imports no Python
adapter, corpus builder, SQL oracle, expected-label module, or saved verdict
stream. It enumerates both possible outputs of a Boolean-only composer on the
shared all-pass vector; all 16 agreement states over effect, resource, time,
and measurement profile; all six orders of one read, revoke, and commit; and
all four topologically valid two-read schedules. This is
implementation-diverse finite enumeration, not a proof of arbitrary programs
or distributed systems. For the revocation schedules, the checker's
atomic-guard oracle encodes the guarded semantics by construction, so that
branch documents the incomplete profiles' time-of-check-to-time-of-use
(TOCTOU) witnesses rather than independently establishing atomicity; the
atomicity evidence is the live, process-isolated, and containerized
laboratories of Sections 5.6 and 6.4.

### 4.3 What a Boolean verdict destroys

Let a typed verifier expose $K$ distinct rejection states. The scalar map
$s(r)=\text{REJECT}$ for every rejecting $r$ is non-injective and erases all
$K(K-1)/2$ pairwise distinctions among them. This count is independent of
case frequency; entropy and best-guess accuracy additionally depend on the
fixture mix. In the transfer laboratory EATF has 16 native rejection states
and the composed corpus has 28, so Boolean scalarization erases
$16(15)/2+28(27)/2=498$ within-corpus pairwise distinctions. The
analytic crosswalk retains every native code and adds a coarse comparison
class; it does not replace the code.

![The composition rule. Each of the five predicate nodes is annotated
with the mechanism that establishes it in this artifact packet and with how often that layer fails across the 104
frozen transactions; the binding stage is not a layer and is annotated with
the number of transactions whose verdict it decided. Counts describe corpus
composition, not any deployed system; the state mechanism is structural
appraisal, and the binding stage compares corpus-supplied subject strings
(Section 2 ceiling).](figures/figA-composition-five-predicates.png){ width=97% }

## 5. Methods

The study design is summarized before the laboratory details so that each
question has one primary artifact, observation, and claim ceiling.

| RQ | Primary artifacts | Oracle or invariant | Primary observation | Ceiling |
| --- | --- | --- | --- | --- |
| RQ1: local-validity limit | 16 policy/evidence vectors; SAFE metamorphics; 104 composed transactions including 14 binding cases | typed precedence, metamorphic relations, re-executed layer evaluators, matched local-verdict witnesses | policy and measurement gate sensitivity; eight all-local-pass denials; false allows of weak and partial-binding ablations | constructed data; shared-rule composition labels are analytic |
| RQ2: runtime atomicity | 104 TPM-bound state vectors + 64 mutations; 372 durable service cases | native TPM verification and frozen state oracle; transactional linearization and idempotency | 104/104 state classes, 64/64 mutation rejects, 104/104 recompositions; safety, recovery, and duplicate-effect invariants | eight software-TPM roots and separate services, but one x86_64 physical host |
| RQ3: typed transfer | 21 EATF rows + 104 transaction rows | native codes preserved by total crosswalk; separate SQL execution and mapping mutation | code coverage, crosswalk sensitivity, and scalarization loss | author-defined analytic mapping; no external semantic validation or interoperability |

### 5.1 Policy-Version × Evidence Replay

The name **Policy-Version × Evidence Replay** reserves "state" for the
runtime predicate $S$ and distinguishes it from policy and evidence
conditions such as missing, stale, substituted, tampered, and replayed.

We generated a deterministic 16-vector corpus: the full factorial

$$
\{\text{correct, missing, stale, substituted}\}
\times
\{\text{good, tampered, replayed}\},
$$

plus four gate-isolation vectors, each carrying good
evidence and failing exactly one strict policy gate:

- **version-only:** correct policy, version 1, active interval;
- **freshness-only:** correct policy, version 2, expired interval;
- **digest-only:** correct identity, version, and interval, one semantic
  field changed and re-signed, so only the digest comparison rejects;
- **invalid policy signature:** the policy object tampered after signing.

The four isolation vectors separate the version and freshness gates, make
the digest branch reachable, and exercise policy `INVALID_SIGNATURE`.
Each strict gate (signature, identity, version, time, digest) is therefore
exercised in isolation by at least one vector.

Policies and evidence are signed with a deterministic Ed25519 test key. The
key is public corpus material. The factorial vectors instantiate:

- **correct policy:** expected identity, version 2, active interval, and
  exact unsigned-object digest;
- **missing policy:** no policy object;
- **stale policy:** valid signature, version 1, and an expired interval;
- **substituted policy:** valid signature but a different policy identity
  and required effect;
- **good evidence:** valid signed effect with an unseen nonce;
- **tampered evidence:** effect changed after signing;
- **replayed evidence:** valid signature with a pre-seen nonce.

We compare the strict verifier with two experimental ablations:

1. signed-policy presence only;
2. missing-policy fail-open plus signed-policy presence.

A second, relational re-composition code path recomposes the verified
policy and evidence layer states in SQL. It consumes the per-layer typed
results emitted by the Python evaluator and re-derives only the conjunction
and the first-rejecting-gate label; it does not reimplement Ed25519 and is
not independent validation.

The experiment is motivated by a recorded Veraison freshness run
in which Veraison correctly rejected a replay while the intended policy was
active; the missing-policy and stale-policy fail-open cases occurred in this
programme's own provisioning harness, not in Veraison. That record is an
internal companion artifact; a public deposit is pending.

### 5.2 SAFE Metric Metamorphics

This laboratory consumes a frozen corpus read-only.

For positive vectors $a$, $b$, and $c$, we evaluated tensor means of:

$$
M_A(x,y,z)=\frac{x+y+z}{3},
$$

$$
M_G(x,y,z)=(xyz)^{1/3},
$$

$$
M_R(x,y,z)=
\sqrt{\frac{x^2+y^2+z^2}{3}}.
$$

The arithmetic and geometric tensor means have the factorized identities:

$$
V_A=\frac{\bar a+\bar b+\bar c}{3},
$$

$$
V_G=
\overline{a^{1/3}}\,
\overline{b^{1/3}}\,
\overline{c^{1/3}}.
$$

The suite uses a pure-Python loop implementation and a NumPy tensor
transliteration of the same specification. Agreement between them excludes
vectorisation and floating-point error, not specification error. The method
is metamorphic testing [25, 26]: each check states a relation that must
hold between outputs rather than an oracle for one output. The fifteen
checks divide into nine implementation identities (two-implementation
agreement for the three integration operators and for TOPSIS, the
arithmetic and geometric factorizations, the ordering
$V_G\leq V_A\leq V_R$, and axis and within-axis permutation invariance) and
six informative checks (tensor-versus-aligned-diagonal non-equivalence,
profile-digest sensitivity under six semantic mutations, dynamic-reference
TOPSIS rank behaviour, fixed-reference TOPSIS rank behaviour,
measurement-fixture typing over four fixtures, and the sampling-overlap
boundary fixture).

The synthetic confidence fixtures use shared three-column samples. For each
fixture we compute a point estimate and a one-sided bootstrap lower bound
$LCB_{1-\alpha}(C)$. The strict measurement rule requires:

$$
\text{profile digest matches}
\land
\widehat C\geq\tau
\land
LCB_{1-\alpha}(C)\geq\tau.
$$

The bootstrap is fully disclosed here because the boundary decision depends
on it: the lower bound is the plain percentile method, 5,000 deterministic
replicates, NumPy PCG64 generators seeded per dataset at 101, 102, and 103,
with the resampling unit being the row of the shared sample. The fixture
sample sizes are n = 30 (supported), n = 18 (point-only boundary), n = 30
(unsupported), and n = 30 (altered profile, which reuses the supported
dataset). No bias-corrected or accelerated (BCa) interval was computed — a
limitation, and the percentile method's small-sample bias at n = 18 is
exactly where the boundary fixture sits. A companion sensitivity sweep
over five seeds and 2,000/5,000/10,000 replicates, using the same
percentile bootstrap, leaves every fixture's confidence outcome unchanged
at all 15 grid points (per-fixture lower-bound spread at most 0.0017) and
preserves the overlap fixture's joint-versus-independent decision flip at
15/15 grid points; the archived sweep is part of the artifact. The
evaluator applies its gates in a fixed first-fail order symmetric with the
binding ladder of Section 5.4: profile digest, then point threshold, then
lower confidence bound. Bootstrap validity is also dependence-sensitive
[22, 23, 24], which motivates the overlap fixture below. The fixtures were
designed to test boundary behavior and are not measurements of a deployed
model.

The TOPSIS fixture contains alternatives A, B, and C plus one added
alternative. Dynamic observed-reference TOPSIS recomputes normalization,
ideal, and anti-ideal points from the current set. The fixed-reference
variant uses a declared normalized 0--1 reference.

### 5.3 Authority-to-effect evaluator

The authority layer reuses the typed delegation-path suite from the
protocol-valid-but-unauthorized laboratory of this packet. It constructs
1/2/4-hop paths and evaluates:

- lineage and role transitions;
- issuer-signature flags;
- permitted subdelegation;
- monotone scope;
- status and freshness;
- terminal action coverage;
- effect time and action binding.

The suite contains 16 typed cases. Four isolate
`protocol.valid`, `edge.signature`, `effect.native_validity`, and
`effect.time_binding`, making each branch reachable in both the Python
evaluator and the relational oracle.

Three of them — `D1_protocol_invalid`, `D2_signature_invalid_second_edge`,
and `D1_receipt_native_invalid` — flip the corpus-supplied Boolean the gate
under test reads. That is *branch coverage* in two implementations at once,
not verification of the property the branch names: no signature is checked
and no protocol run is validated. What it rules out is a branch that is
unreachable, and therefore silently untested, in both implementations.
Only `D1_receipt_effect_time_outside_window` exercises a computed
comparison, moving the receipt's effect time outside the delegation window.

The suite reports 16/16 expected typed tuples, 13/13 first-invalid-stage
matches on the negative cases, and 8/8 delegation-edge ID and index matches
under an edge-gate definition that counts only cases rejected by an `edge.*`
gate. The same laboratory also retains a 20-vector semantic corpus (20/20)
and a seven-case hybrid adapter over recorded A2A evidence (7/7).

The cryptographic component of this layer is stipulated, not computed: the
fields `issuer_signature_valid`, `native_evidence_valid`, and
`protocol_valid` are corpus-supplied experimental flags, and no
cryptography executes anywhere in the authority laboratory. The result
schema uses explicit coverage names such as `native_object_flags_true`, and
the disclaimer is embedded in the result JSON, not only here.

The delegation-path suite agrees 16/16 with an independent relational SQL
implementation. We keep the word "independent" for this oracle alone, and
it differs in kind from the composition-level SQL of Sections 5.1 and 5.4:
it is a 233-line relational re-derivation that starts from the raw case
objects, normalises edges, scopes, and receipts into tables, computes a
violation set, and ranks violations with a window function, a set-then-rank
formulation confronting the Python evaluator's imperative short-circuit.
The case expansion and expected labels remain shared with the Python entry
point, so even this agreement is implementation diversity over verdict
derivation, not independent validation of the labels.

### 5.4 Composed frozen corpus

The composed corpus contains 104 transactions:

| Family | Transactions | Purpose |
| --- | ---: | --- |
| policy/evidence/measurement factorial | 36 | cross the 12 signed replay vectors with three measurement outcomes |
| state--authority--measurement cube | 8 | enumerate all binary pass/fail combinations of those three layers |
| authority path reuse | 16 | re-execute all 16 typed 1/2/4-hop cases with other layers valid |
| cross-layer joins | 30 | 10 layer pairs × 2 two-fault joins, 4 triples, 1 quadruple, 1 all-five failure, and 4 matched all-valid lookalike positives |
| cross-layer binding | 14 | 8 transactions in which all five layers pass and the subject records disagree, each paired with a matched all-valid lookalike (6 distinct controls) |

The cross-layer-joins and cross-layer-binding families do two different jobs
that must not be conflated under the word "join".

The cross-layer-joins family populates the co-failure structure. It fills
every off-diagonal cell of the 5 × 5
co-failure matrix, with a corpus-wide minimum off-diagonal count of 5, and
its four matched all-valid lookalike positives ensure that universal refusal
cannot masquerade as correctness. A populated co-failure cell is a
co-occurrence of two independently caused layer failures in one transaction.
It is not a join in the relational sense, and it does not test whether the
layers are describing the same action.

The cross-layer-binding family tests agreement over the
implemented effect, resource, report-time, and measurement-profile
coordinates; it does not test the omitted state/workload, principal, model, or
commit-receipt coordinates. Each of its 8 denials is a transaction in which
every one of the five component verifiers returns a pass and the composition
denies because one implemented coordinate disagrees; each is paired with a
matched all-valid lookalike that is allowed, so the denials are not universal
refusal. Its evidence objects are owned by this laboratory and signed with
the policy laboratory's own test key and signing function, imported rather
than transcribed; every one carries a fresh nonce and a valid signature, so
the unmodified evidence evaluator returns `PASS` on all of them and they
differ only in the subject fields the binding stage reads. Its two extra
measurement fixtures are likewise owned by this laboratory, in the SAFE
fixture schema, appraised by the unmodified SAFE evaluator, which passes
both; they differ from each other only in profile identity, and they exist
because the signed policy cannot be varied without changing its digest, which
would make the policy layer report `SUBSTITUTED`. Each transaction's
`measurement_fixture_source` records which population its fixture came from.
All these constraints are enforced as deterministic assertions at corpus
build time and re-checked by the verifier's exit gate.

The binding stage itself is a single pure function over the two subject
records, applied in a fixed rule order, first failing rule winning:

```text
0. any required subject field absent            -> UNDETERMINED
1. signed reported effect differs from the policy-required effect,
   or is not in the terminal granted tools      -> EFFECT_MISMATCH
2. reported resource differs from the canonical action resource,
   or is not in the terminal granted resources  -> RESOURCE_MISMATCH
3. issued_at outside the authorised window      -> TIME_MISMATCH
4. measurement profile differs from the
   policy-required profile                      -> PROFILE_MISMATCH
5. otherwise                                    -> PASS
```

Each non-`PASS` outcome maps to the correspondingly named gate in the
`binding.*` namespace. Timestamps are compared lexicographically, which is
sound only because every timestamp in this artifact is fixed-width UTC `Z`
form; both window boundaries are inclusive, matching the state adapter and
the policy validity window. The time test is containment and never equality.
The three decision-relevant time constants in the artifact — the
policy and state decision time 2026-07-25T21:30:00Z, the authority effect
time 2026-07-25T20:00:00Z, and the evidence issue time 2026-07-25T21:29:30Z
— are unrelated. The main corpus therefore cannot instantiate the decision
clock of Section 4.2 from those constants. The live companion does instantiate
its critical order with server-side linearization indices.

The stage is placed in the composition rather than inside a layer because a
predicate over four artifacts has no local home. Putting it inside the
evidence evaluator would make the evidence column of the co-failure matrix
partly a copy of the policy column, and could not express the resource, time,
or profile mismatches at all; putting it inside the authority evaluator would
be cross-layer analysis wearing a single-layer costume and would make the
composition rule vacuous. Only the join can see all four subjects, so only
the join can reject on their disagreement.

A standalone acceptance test rebuilds the Section 1 counterexample and its
lookalike from first principles and does not read the frozen corpus, so the
result cannot be satisfied by a corpus entry carrying a convenient label. It
asserts, and prints, that the shipped evidence evaluator still returns `PASS`
on the WRITE receipt — the root cause is unchanged, and the fix is at the
join and not in the layer — that all five artifact verifiers pass, that the
binding result is `EFFECT_MISMATCH`, that the verdict is `DENY` at gate
`binding.effect`, and that the lookalike is `ALLOW` at gate `verified`.

Two provenance properties are central and are declared inside the corpus
and every generated summary. First, the conjunction, binding stage, and
first-rejecting-gate ladder are centralized in one shared composition-rule
module imported by both the corpus builder and verifier. Consequently,
composition-level expected labels are
generated by the same composition rule the verifier imports, so agreement at
that level is analytic. Per-layer agreement is the non-analytic execution
check; subject-record agreement is a same-function round trip. Second,
transactions embed
`attestation_result` objects, and the verifier calls a state adapter at the
fixed decision time
2026-07-25T21:30:00Z (asserted equal to the policy corpus decision time)
rather than comparing a corpus string. The adapter is a structural
appraisal of the supplied object: a status gate, an inclusive freshness
window, and a reference-digest comparison, in a fixed order, emitting
`PASS`, `CONTRAINDICATED`, `STALE`, or `REFERENCE_MISMATCH`, and failing
closed on missing fields. It performs no cryptographic verification,
involves no TPM and no Veraison, and is not remote attestation; the
disclaimer travels inside the result records. A 24-case adapter self-test
runs as the first gate of the laboratory's entry point.

Corpus construction records the SHA-256 of each source corpus. The composed
verifier verifies those hashes and re-executes the three source evaluators
per transaction through `importlib`; it does not copy stored verdicts. The
SAFE source corpus is consumed read-only from its frozen source.

### 5.5 Ablations

We compare the strict composition with:

- **artifact validity / policy presence:** signed-policy presence and
  evidence integrity, ignoring policy identity, state, authority,
  measurement, and binding;
- **point-only measurement:** strict policy, evidence, state, authority, and
  binding, but $\widehat C\geq\tau$ without confidence or profile
  enforcement;
- **four-of-five majority:** allow when any four of the five artifact layers
  pass;
- **effect/resource binding:** require all five local verifiers plus effect
  and resource agreement, but omit time and measurement-profile agreement;
- **effect/resource + time:** add authorized-window containment, but omit
  measurement-profile agreement; and
- **effect/resource + profile:** add measurement-profile agreement, but omit
  authorized-window containment.

The two compensating ablations differ in what they remove. The point-only
profile replaces exactly one
thing, the measurement criterion, and retains the binding stage; that is what
makes it an ablation of one thing, and it is why the binding function is
evaluated for every transaction rather than only when the layers pass. The
four-of-five majority is by construction also an ablation *of the binding
stage*: it votes over the five artifact verifiers, and a stage that is not
one of them cannot appear in the vote.

These are intentionally incomplete experimental profiles, not
representations of named products. The latter three are credible
subject-aware schema ablations rather than local-validity strawmen: each
checks a useful subset of the join and omits a different coordinate. Their
false-allow counts are reported in Section 6.3, together with the analytic
identity that governs the majority profile, because the aggregate counts are
functions of corpus design.

### 5.6 Companion evidence-class upgrades

The main 104-transaction corpus treats its supplied experimental
authority-validity flags as controlled factorial inputs. Nine companion
laboratories change evidence class without silently reinterpreting that
corpus; a tenth, the standalone finite model check, accompanies the formal
apparatus (Section 4.2).

**Native signed authority/effect adapter.** Eight deterministic fixtures use
real Ed25519 verification for every delegation edge and the effect receipt.
The verifier checks parent digest, principal and role lineage, permission,
status, freshness, scope attenuation, terminal action scope, receipt issuer,
chain digest, effect time, and action binding. One fixture passes; seven
isolate a bad edge signature, bad receipt signature, signed action mismatch,
expired edge, signed wrong lineage, signed scope amplification, and signed
effect-time mismatch. The builder uses deterministic test-key seeds and
persists public keys only. This is a Tyche experimental profile, not
conformance with WAVE, JEDI, OAuth, DID, or another external credential
format.

**Mutation-generated transactions.** Starting from one independently passing
transaction, a deterministic builder applies 37 single faults, one at a time
(one baseline plus 37 generated cases, the 38 frozen pairs),
across policy rules P1--P5, evidence rules E1--E2, state rules S1--S3,
authority rules A0--A19, and measurement rules M1--M3. The transaction packet,
both evaluator sources, and both unsealed outputs were hashed before comparison
with the author-written mutation oracle. A second packet composes 12 cases
with two to five simultaneous faults, including two within-layer precedence
cases. The freeze establishes ordering, not label truth: generator, oracle,
and labels remain programme-internal.

**Prospective signed-revocation races.** Thirteen scheduled event sequences
place signed status snapshots before appraisal, between appraisal and
commit, at the commit instant, and after commit, adding stale, replayed,
substituted, unavailable, re-issued, out-of-window, and bad-signature
status cases. The strict rule verifies signed credential and status
objects, uses the half-open credential window
`valid_from <= t < valid_until`, requires fresh status at appraisal and
commit with a non-decreasing signed sequence number, and treats revocation
at the commit instant as effective. Independent Python and Node
implementations evaluate the frozen packet; three ablations omit commit
rechecking, fail open on missing commit status, or ignore sequence
monotonicity.

**Native runtime-attestation appraisal.** The lab embeds the public frozen
Tyche `aep-pcr16-vector` at commit
`2d22013987e1e98f8f9132832c9db2b967035945`, including its RSA attestation
public key, `TPMS_ATTEST`, TPM signature, and PCR-values blob. The verifier
recomputes

```text
PCR16 = SHA256(0x00*32 || outcome_digest_bytes)
preimage = "tyche.aep.qual.v1|capsule=" || capsule_hex
           || "|outcome=sha256:" || outcome_hex
           || "|nonce=" || challenge_hex
qual_hex = HEX(SHA256(ASCII(preimage)))
checkquote_q = HEX(ASCII(qual_hex))
```

and invokes `tpm2_checkquote` with the last value, matching the frozen
vector's ASCII-hex convention. One affirming case and six author-written
cases, hash-pinned before the recorded invocation, cover outcome substitution,
fresh-challenge replay, capsule substitution, declared-PCR substitution,
quote-message tampering, and quote-signature tampering. The source vector was
produced by `swtpm`; no hardware endorsement or live workload is inferred.

**Live concurrent revocation service.** A `ThreadingHTTPServer` on an
ephemeral loopback port linearizes signed status reads, revocations,
guarded commits, and unguarded effects under one lock, assigning each
operation an increasing index; every status-bearing response is
Ed25519-signed and client-verified. Four profiles are crossed with five
revocation placements plus 64 same-barrier revocation/commit trials each.
`atomic_guard` checks status and commits the effect within one locked
operation; `double_read`, `single_read`, and `ttl_cache` make an unguarded
effect after a fresh, appraisal-time, or cached status (the 50 ms cache
with a forced 75 ms expiry deterministically separates `ttl_cache` from
`single_read`). A false allow is defined by the service record itself: the
client accepted and the credential status at the effect's linearization
point was revoked.

**Native state transaction overlay.** The retained structural objects define
the frozen source oracle, but no `status` field enters the native adapter. For
each transaction, a subject-derived capsule identifier binds the source-corpus
hash, transaction identifier, canonical action, and observed effect. PCR 16
binds a transaction-specific runtime measurement, while qualifying data binds
the capsule, measurement, signed validity interval, and unique 32-byte
challenge. Eight freshly initialized `swtpm` roots issue 104 quotes: four RSA
and four ECC attestation keys (AKs), thirteen transactions per root. After
`tpm2_checkquote`, PCR, challenge, and subject checks, a frozen appraisal
policy applies contraindication, signed-window, and reference-measurement
rules in the same precedence as the source state vocabulary. The verifier
then re-runs the shared composition rule with only the state result replaced.
One representative vector per root receives eight predeclared mutations:
quote message, signature, PCR blob, challenge, transaction identifier, source
corpus hash, measurement, and signed window.

An independent compiled verifier reprocesses the same frozen native packet in
OpenJDK 21. It imports and executes none of the Python adapter, structural
corpus, corpus builder, expected-label module, or saved mutation generator.
It implements its own strict JSON parser, canonical transcript, SHA-256 and
PCR derivations, appraisal precedence, and mutation construction, then invokes
`tpm2_checkquote` directly. `jdeps` reports only `java.base`. The comparison
therefore tests implementation diversity against the frozen packet, while
remaining author-operated, same-host, and dependent on the same packet and
TPM2 command-line verifier.

**Process-isolated durable revocation service.** Status and effect run as
separate OS processes with separate TCP listeners. They coordinate through a
SQLite append-only event log; every status read, revocation, and effect
receives a durable linearization index and a signed response. The guarded
effect checks status and inserts an idempotency-keyed effect in one
`BEGIN IMMEDIATE` transaction. Simultaneous revoker and committer contenders
run in separate client processes. In addition to the five scheduled
placements and 64 same-release trials per profile, the runner disconnects
after commit request but before response consumption, retries, and in a
second fault class kills and restarts the effect service before retry.
The primary safety oracle is the status stored in the effect transaction;
the effect table supplies the duplicate-effect oracle. The experiment remains
same-host and uses SQLite as a centralized linearization mechanism.

**Containerized durable-revocation replay.** A pinned offline image runs a
status service, two interchangeable effect-service instances, a
deterministic response-fault proxy, and the runner as five read-only
containers over an internal bridge, with a named-volume SQLite
write-ahead-log store as the centralized linearization mechanism. The proxy
injects request loss before forwarding and response loss after durable
commit; recovery retries through the second effect instance and replays
both allowed and denied idempotency keys. A separate saved-result verifier
rechecks every signature, reconstructs the false-allow predicate from
stored effect-time state, and checks unique decision/effect keys,
contiguous event identifiers, database integrity, and distinct signed
service hostnames. Container separation changes process, filesystem,
network-namespace, and service-instance boundaries — not the physical
host, kernel, datastore trust domain, or operator.

**Cross-ecosystem typed transfer.** A pinned, field-minimized snapshot of
the public EATF decision-path result supplies 21 rows (two accepts, 19
rejects covering 16 native rejection codes, exact TypeScript/Python
agreement). Every native code and first gate from the 104 transactions
must appear in an explicit total crosswalk to eight coarse analytic
classes; the builder exits non-zero on an unmapped code or a source-oracle
mismatch. Native codes remain the primary result. A separate SQLite
implementation consumes the frozen JSON mapping and performs a
leave-one-out plus wrong-class mutation for every entry, testing
execution-path agreement, totality, and sensitivity — not the semantic
correctness of the ontology.

A separate blind semantic-validation kit converts the 46 native states into
opaque mapping tasks with nine class definitions, a `NO_FIT` option, and a
response schema, excluding the author mapping (hash-sealed outside the
archive) and all result fields. A coordinator validator, preregistered
unweighted-kappa analysis with a 0.60 stop rule, and fail-closed checks for
duplicates, low agreement, residual `NO_FIT`, and unresolved
`taxonomy-defect` are frozen before any dispatch; its self-tests pass with
`author_mapping_opened=false`. The kit remains undispatched and therefore
supplies no independent semantic evidence.

The human-labelling experiment is deliberately separate. Its neutral packet
is a label-isomorphic 104-case transformation of the composed corpus: the
builder replaces mnemonic identifiers with opaque aliases, re-signs policy
and evidence objects under a packet-specific deterministic Ed25519 key,
preserves invalid signatures and replay membership, and re-evaluates every
typed tuple (104/104 preserved; the known-token audit reports no remaining
mnemonic match). The response schema, sealed author labels, adjudication
protocol, and a pre-registered analysis program (verdict kappa with a fixed
10,000-replicate paired bootstrap, an uncollapsed gate confusion matrix,
and the 0.60 stop gate enforced without opening author labels) are
prepared; the packet is undispatched, and no external label, adjudicated
result, or agreement statistic exists.

## 6. Results

### 6.1 Policy state changed the appraisal surface

The strict verifier matched 16/16 expected tuples and allowed only the
correct-policy/good-evidence cell. The signed-policy presence profile
matched 11/16 with five false allows: good evidence under stale,
substituted, version-only, freshness-only, and digest-only policies. The
missing-policy fail-open profile matched 10/16 and additionally falsely
allowed good evidence with no policy, six false allows in total. Both
baselines still validate signatures, so the tampered-policy vector is
denied by all three profiles. The SQL re-composition matched the Python
verdict and rejecting gate 16/16, including execution of the
`policy.signature` branch.

| Profile | Expected matches | False allows |
| --- | ---: | ---: |
| strict identity/version/digest | 16/16 | 0 |
| signed-policy presence only | 11/16 | 5 |
| missing-policy fail-open | 10/16 | 6 |

All counts are counts on this designed corpus, and the 16/16 needs the same
analytic/substantive split that Section 6.3 applies to the composed layer.
The typed per-layer results are hand-written from each declared vector
condition, and recovering that condition from the signed bytes is what the
verifier must do, so per-layer agreement is the substantive check. The
expected `verdict` and `first_rejecting_gate`, by contrast, are
machine-generated by a two-layer precedence ladder that `run.py`
re-implements when it composes; agreement on those two fields is agreement
between two transcriptions of one small function — weaker than the composed
laboratory, where a single shared module makes the corresponding agreement
outright analytic, and stronger than nothing, because two transcriptions
can in principle disagree. It is not evidence that the precedence order is
correct.

### 6.2 Metamorphic and confidence results

All 15 SAFE checks passed: the nine implementation identities passed as
required (they cannot fail absent a coding defect), and the six informative
checks also passed. The integrated frozen values were:

| Operator | Tensor volume |
| --- | ---: |
| geometric | 0.7665940656 |
| arithmetic | 0.7691666667 |
| RMS | 0.7716991533 |

The harness accepts two-implementation agreement at a threshold of
$10^{-12}$; the observed gaps were smaller: exactly 0.0 for the three
integration values and at most $1.1\times10^{-16}$ (one unit in the last
place) across the TOPSIS closeness scores. Six of six profile mutations
changed the profile digest; these six mutations do not establish that the
profile field set is complete.

The confidence fixtures produced:

| Fixture | Point | 5% bootstrap LCB | Threshold | Result |
| --- | ---: | ---: | ---: | --- |
| supported (n = 30) | 0.825377 | 0.811554 | 0.75 | PASS |
| point-only boundary (n = 18) | 0.764537 | 0.732088 | 0.75 | FAIL_LCB |
| unsupported (n = 30) | 0.682263 | 0.665874 | 0.75 | FAIL_POINT |
| altered profile (n = 30) | 0.825377 | 0.811554 | 0.75 | PROFILE_MISMATCH |

A point-only gate falsely allowed two fixtures, and the two false allows
are different phenomena: one confidence-gate false allow (the boundary
fixture, whose point estimate clears the threshold while its lower bound
does not) and one profile-gate false allow (the altered-profile fixture,
which the point-only gate admits because it never checks the profile
digest).

In the overlap boundary fixture the threshold 0.737 was chosen by
construction to sit between the two computed bounds: joint resampling of
the shared columns produced LCB 0.732088 while incorrectly resampling them
as independent produced 0.740781, so the decision changes at that
threshold. This is a designed counterexample demonstrating existence, not a
finding about any data-generating process; the dependence-sensitivity of
bootstrap intervals is established statistics [22, 23, 24].

Dynamic-reference TOPSIS changed the relative order of the original three
alternatives from A > C > B to A > B > C after the fourth alternative was
added. Under the fixed 0--1 reference the base ordering was already
A > B > C and was unchanged by the addition; the two reference schemes
therefore disagree on the base ranking as well as on its stability, and the
fixed scheme is not a control for the reversal but a different ranking
function that is stable in this fixture. Rank reversal under reference-set
change is a known property of TOPSIS and of normalisation-based
multi-criteria methods generally [19, 20, 21]; the fixture reproduces the
phenomenon inside this evidence profile, it does not discover it.

### 6.3 Integrated transaction results

The composed verifier reproduced all 104 expected typed tuples. That
sentence requires its provenance statement before any interpretation:
composition-level expected labels are generated by the corpus builder using
the same shared composition-rule module the verifier imports, so agreement
on the conjunction, the binding outcome, and the gate label is analytic, a
property of one function applied twice. The non-analytic execution content of
the 104/104 is the per-layer agreement: the re-executed policy, evidence, and
measurement evaluators, the delegation-path
evaluator, and the state adapter each reproducing the per-layer expectation
carried by their source corpora. The subject-record agreement, also 104/104,
is the stored `canonical_action` and `observed_effect` records agreeing field
by field with the records re-derived from the artifacts at verification time,
but both paths call `composition_rule.subjects_of`. It therefore checks
serialization/plumbing and ensures the binding stage reads source fields
rather than a stored verdict; it does not independently validate subject
extraction.

| Metric | Result |
| --- | ---: |
| exact expected tuples (composition level, analytic) | 104/104 |
| per-layer expected agreement (substantive) | 104/104 |
| subject-record agreement, same-function round trip (plumbing) | 104/104 |
| allows | 15 |
| denies | 89 |
| **cross-layer denials: all five verifiers pass, composition denies** | **8** |
| relational re-composition agreement | 104/104 |
| relational binding-outcome agreement (re-derived, not echoed) | 104/104 |
| source-corpus hash closure | PASS |

The cross-layer-denial row is the article's strongest single number, and it
is structural: a composition rule that consumes only the five scalar layer
results has no cross-layer argument, so a transaction of this class cannot
even be represented, let alone denied. The corpus populates the class. The
8 transactions are:

```text
XLB_effect_write_two_hop
XLB_effect_write_other_resource_two_hop
XLB_effect_export_four_hop
XLB_resource_other_one_hop
XLB_resource_other_two_hop
XLB_issued_before_window_two_hop
XLB_issued_after_window_two_hop
XLB_measurement_profile_two_hop
```

Each carries `failed_layers == []` and verdict `DENY`. The second,
`XLB_effect_write_other_resource_two_hop`, is the
counterexample this article opens with, verbatim: a WRITE effect on
`invoice-999` under a path that permits only READ on `invoice-123`. Its
sibling `XLB_effect_write_two_hop` isolates the effect alone, on the
authorized resource, and `XLB_effect_export_four_hop` reproduces the same
seam at four hops, so the result is not a property of path length.

![The cross-layer denial class: the 8 transactions in which every
artifact verifier passes — policy PASS,
evidence PASS, state PASS, authority ALLOW, measurement PASS, empty
failed-layer set — and the composition still denies, each with the
disagreeing subject pair and the typed binding result that fired; beneath
them, the 6 matched lookalike controls of the same family, all allowed,
without which the denials would be consistent with a verifier that refuses
everything. Coverage counts on a designed corpus (Section 2
ceiling).](figures/figG-cross-layer-denials.png){ width=97% }

The relational re-composition rows are a second code path, not independent
validation: the SQL oracle consumes the per-layer typed results and the
subject strings emitted by the Python evaluator and re-derives the
conjunction, the binding outcome, and the first-rejecting-gate label. Because
it re-derives the binding rules rather than echoing them, a divergence
between the two implementations of those rules would be detectable; the
subject strings it compares still come from the Python evaluator, so this
remains a transcription check between two same-author implementations. It
verifies no signature, no bootstrap replicate, no delegation edge, and no
attestation object.

The ablations produced, in aggregate and per family:

| Profile | Expected matches | False allows |
| --- | ---: | ---: |
| strict typed composition | 104/104 | 0 |
| point-only measurement | 102/104 | 2 |
| four-of-five majority | 73/104 | 31 |
| artifact validity / policy presence | 56/104 | 48 |
| effect/resource partial binding | 101/104 | 3 |
| effect/resource + profile | 102/104 | 2 |
| effect/resource + time | 103/104 | 1 |

Here `A` and `D` are strict allows and denies; `FA` is a false allow relative
to strict composition.

| Family | n | A | D | point FA | 4/5 FA | validity FA |
| ------------------------------------- | ----: | -----: | ------: | ------------: | --------------: | -------------------: |
| policy/evidence/measurement factorial | 36 | 1 | 35 | 1 | 7 | 8 |
| state--authority--measurement cube | 8 | 1 | 7 | 1 | 3 | 7 |
| authority path reuse | 16 | 3 | 13 | 0 | 13 | 13 |
| cross-layer joins | 30 | 4 | 26 | 0 | 0 | 12 |
| cross-layer binding | 14 | 6 | 8 | 0 | 8 | 8 |
| **total** | **104** | **15** | **89** | **2** | **31** | **48** |

All three partial-binding errors occur in the 14-case cross-layer-binding
family, where their omitted coordinates can be isolated:

| Partial subject join | False-allowed mismatch class | False allows |
| --- | --- | ---: |
| effect/resource only | two time + one profile | 3 |
| effect/resource + profile | two time | 2 |
| effect/resource + time | one profile | 1 |
| full implemented effect/resource/time/profile binding | none | 0 |

This ladder is the more demanding comparison: every row already requires all
five local verifiers and some subject agreement. It shows the marginal
coverage supplied by the implemented time and profile coordinates on the
designed witnesses; it does not establish that these are the only coordinates
a deployed transaction must bind.

On the 90-transaction base subset, the artifact-validity and four-of-five
ablations yield 40 and 23 false allows. The point-only ablation yields 2
because the binding stage catches `F_correct_good_profile_mismatch` as
`binding.measurement_profile`. The measurement evaluator's point-only result
ignores the profile gate, while the binding stage rejects the
profile-substituted appraisal. This follows from the ablation definition in
Section 5.5: the point-only profile replaces the measurement criterion and
keeps the binding stage.


A four-of-five majority allows a transaction if and only if at most one of
the five artifact verifiers fails. Once denials with *zero* failing verifiers
exist, its false allows are the single-fault denies **union** the cross-layer
denials, 31 = 23 + 8, verified as exact set equality on transaction
identifiers. The single-fault layer distribution is authority 14,
policy 3, measurement 3, evidence 2, state 1. All 8 cross-layer denials are
majority false allows because a vote over the five artifact verifiers cannot
represent them at all — there is nothing for it to vote against.

The artifact-validity profile inspects only policy presence and evidence
integrity, so it necessarily false-allows every transaction whose faults lie
entirely in state, authority, measurement, or the binding: that is 13 of 13
authority-reuse denies, 7 of 7 cube denies, and 8 of 8 cross-layer binding
denies. The correct reading of the whole comparison is a proof by
construction, that a compensating or incomplete rule cannot preserve a
non-compensable specification, together with a corpus-coverage statistic; it
is not a measurement of external systems.

Layer failures and co-failures are disclosed in full, and are reported
separately from cross-layer binding because they are separate properties.
Failed-layer occurrences across the 89 denies are policy 39, evidence 36,
state 17, authority 30, measurement 39; state remains the least-exercised
layer, and we say so rather than leaving the reader to notice. Every
off-diagonal cell of the co-failure matrix is at least 5, and 22 of the 31
possible non-empty failure subsets occur. The
cross-layer-binding family contributes nothing to any of these numbers, by
construction: its 8 denials have no failed layer at all.

The matrix reports co-failure rather than cross-artifact binding. A populated
off-diagonal cell means two layers failed in the same
transaction for independent reasons; it is co-occurrence, and it says nothing
about whether the two layers were describing the same action. Co-failure
coverage and cross-layer binding are two different properties with two
different counts: the minimum off-diagonal co-failure cell is 5, and the
number of cross-layer denials is 8. Neither number substitutes for the other,
and only the second tests the seam.

![Pairwise co-failure matrix over the 104 transactions, on a designed
corpus engineered so that no
off-diagonal cell is zero; cell magnitudes reflect corpus construction, not
failure prevalence. Co-occurrence of two layer failures is not a join; the
binding stage is not a layer and has no cell
here.](figures/figE-cofailure-matrix.png){ width=72% }

The typed binding vocabulary is exercised as follows. Because the binding
function is pure over the subject records, it is computed for every
transaction, and corpus-wide it returns `PASS` 50, `EFFECT_MISMATCH` 28,
`PROFILE_MISMATCH` 9, `RESOURCE_MISMATCH` 3, `TIME_MISMATCH` 3, and
`UNDETERMINED` 11. Only a subset of those outcomes is *decisive*, that is,
reached by the gate ladder because all five layers passed, and only those may
be quoted as binding failures: `binding.effect` 3, `binding.resource` 2,
`binding.time` 2, `binding.measurement_profile` 1, `binding.undetermined` 0.
The larger corpus-wide counts are dominated by transactions whose policy is
substituted or whose evidence is tampered — those deny earlier, and the
binding outcome is never consulted — and all 11 `UNDETERMINED` transactions
carry a `MISSING` policy, which fires `policy.missing` first, so that branch
is live in the vocabulary but never decisive here. The shipped summary keeps
the two counts in separate fields so that the larger cannot be quoted as if
it meant the smaller.

Coverage concentration is reported rather than hidden: one authority case
(the exact two-hop positive path) backs 59 of the 104 transactions, and all
16 delegation cases appear. Six measurement fixtures appear: the four frozen
SAFE fixtures, including the unsupported fixture, exercised five times, which
makes the `FAIL_POINT` composition branch live, plus the two profile variants
this laboratory owns for the binding family, which the unmodified SAFE
evaluator passes and which differ from each other only in profile identity.
The state layer has three failure outcomes plus a pass, and all four states
occur: `CONTRAINDICATED` 9, `STALE` 4, and `REFERENCE_MISMATCH` 4, against
87 `PASS`. Per-case usage tables are in the result summary.

### 6.4 Companion evidence-class results

The companion laboratories return the following exact designed-fixture
results:

| Evidence-class change | Executed result | Interpretation ceiling |
| --- | ---: | --- |
| native signed authority/effect adapter | 8/8 verdict + first gate | real Ed25519 over a Tyche test profile; internal labels, no external-protocol conformance |
| single-fault mutations | 38/38 oracle pairs; 570/570 Python/JS typed fields | 1 baseline + 37 generated faults; frozen-before-comparison, but internally designed |
| multi-fault mutations | 12/12 oracle pairs; 180/180 Python/JS typed fields | 2--5 simultaneous faults; internally designed precedence cases |
| prospective signed revocation | 13/13 oracle pairs; 13/13 exact Python/Node rows | scheduled sequences, not a live concurrent status service |
| native runtime-attestation gate | 7/7 verdict-and-gate cases; four native + two binding negatives rejected | `tpm2_checkquote` over one frozen `swtpm` vector; no hardware or live workload |
| identified vTPM VM companion | four-lane contract 20/20; 104/104 live TPM2 quotes; 64/64 native mutation rejects; no new transient or persistent handle | distinct Hyper-V VM/OS and Microsoft vTPM; no physical-host identity, manufacturer-certified EK, or hardware-root claim |
| live revocation service | 276 traces, 890 persisted signed responses; atomic guard 0/0 safety errors | loopback HTTP and one process; safety result, not performance or multi-host evidence |
| native state transaction overlay | 104/104 source classes and gates in Python and compiled Java; 64/64 mutation rejects and parity; 104/104 exact recompositions; Java 19/19 assertions; 8 distinct RSA/ECC AKs | cross-implementation native TPM2 evidence for the full corpus, but software TPM, shared packet, and one physical host |
| process-isolated durable revocation | 372 cases; 1,478 durable events; 96/96 fault recoveries; 0 duplicates; atomic guard 0/0 | separate services/processes with restart and retry, but loopback and centralized SQLite on one host |
| containerized durable revocation | five containers; 135 decisions, 537 events, 95 effects; 540 signed responses; 4/4 fault recoveries; atomic false allows 0; duplicate decisions/effects 0; verifier 15/15 | two effect instances and deterministic proxy, but one physical host and shared SQLite volume |
| typed EATF transfer | 21/21 native-code rows plus 104/104 transaction rows mapped; SQL 125/125; 46/46 wrong-class and 46/46 omission detections; sealed blind 46-task semantic kit | analytic author-defined crosswalk; semantic kit undispatched; establishes no interoperability |
| standalone finite model check | both Boolean outputs; 16/16 binding states; 6/6 one-read and 4/4 two-read schedules; zero atomic-oracle mismatches | implementation-diverse exhaustive check of declared finite models only |
| isolated container re-execution | PASS for the 104-case corpus and companion evidence upgrades through scheduled revocation | different userland and interpreter; same host, kernel, CPU, and compiled NumPy/OpenSSL wheels |
| optional external-label extension | **not executed and not counted** | neutral 104-case packet and blind analysis pipeline prepared; no claim of human agreement is made |

The revocation strict profile has no false allow against its 13
author-written expectations. The appraisal-only ablation false-allows seven
cases: revocation between appraisal and commit, revocation at commit, stale
commit status, lower-sequence replay, unavailable commit status, credential
expiry at commit, and a corrupted commit-status signature. Commit fail-open
false-allows the unavailable-status case; timestamp-only false-allows the
lower-sequence replay. These values are intentionally case identifiers and
coverage counts, not estimates of how frequently a deployed revocation
service races.

![Four temporal boundary placements in the signed revocation fixtures,
with false allows of three incomplete profiles.
Revocation at the commit instant is effective under the strict profile;
revocation after commit is not retroactive. Coverage counts over 13
designed sequences.](figures/figH-revocation-races.png){ width=97% }

The native runtime-attestation gate allows the unmodified vector and matches
all seven hash-pinned author-written verdict-and-gate cases. Two negatives —
substituted outcome and altered declared PCR — stop at the explicit
measurement-binding precheck before the native verifier is called.
Fresh-challenge replay, capsule substitution, quote-message tampering, and
quote-signature tampering produce non-zero `tpm2_checkquote` returns. This
supplies a native verifier call in a bounded companion experiment; it does not upgrade
the structural state objects inside the 104 transactions by itself.

The native state overlay supplies that missing corpus-wide upgrade. All 104
quotes pass their cryptographic, PCR, qualifying-data, challenge, and subject
checks before policy appraisal. The native results exactly reproduce 87
`PASS`, 9 `CONTRAINDICATED`, 4 `STALE`, and 4 `REFERENCE_MISMATCH` classes,
104/104. All eight AK public-key fingerprints, all 104 quote messages, and all
104 challenges are distinct. The 64 altered vectors fail at the native
evidence gate, and substituting the native state classes into the original
four other layer results yields 104/104 exact composed tuples. This closes the
structural-main-state and one-vector limitations **within the designed
benchmark**. It does not attest a deployed workload: all roots are fresh
software TPMs on the same x86_64 host, the reference policy is author-written,
and no manufacturer endorsement or trusted external clock exists.

The independent compiled verifier matches the baseline state class and first
gate on 104/104 vectors, rejects all 64/64 independently reconstructed
mutations with exact state/gate parity, verifies 104/104 root-to-AK pins, and
passes 19/19 predeclared assertions. The implementation source imports only
`java.base`; its frozen results are bound to the exact overlay and primary
verdict hashes. This removes a single-language/single-parser ceiling, not the
shared-fixture, same-operator, software-root, or same-host ceilings.

The live service executes 69 cases per profile, including 64 same-barrier
trials. Every one of the 276 result traces verifies its service responses;
all 890 exact payload/signature pairs and the raw public key are persisted,
and the saved-result checker reverifies them. The atomic guard has 0 false
allows and 0 false denies. In this run the double-read, single-read, and
TTL-cache profiles have 31, 39, and 31 false allows and no false denies. The
forced-expiry case refreshes and denies under `ttl_cache` but false-allows
under `single_read`, proving that the implementations are behaviorally
distinct. The exact three incomplete-profile counts depend
on operating-system scheduling in the same-barrier trials and are descriptive
observations, not fixed expectations. Their deterministic
revoke-after-final-read cases and Proposition 3 establish the existence of the
TOCTOU schedule independently of those counts.

The process-isolated extension executes 93 cases per profile, 372 total,
through separate status and effect service PIDs and separate contender
processes. The durable log of the archived run contains 1,478 events and 301 effects.
A case is one scheduled contender sequence against one credential; a
recovery is a disconnected or killed-and-restarted commit whose retry
returns the original idempotent effect. All 372 case traces verify their
signed responses. Across 96 response-loss/retry and kill/restart cases, 96
recover the original idempotent effect and none creates a duplicate. The
atomic guard again has 0 false allows and 0 false denies; double-read,
single-read, and TTL-cache expose 63, 67, and 66 false allows in that
scheduling realization, with no false denies. Those three totals are
not rates. The stronger observation is categorical: the atomic invariant and
zero-duplicate invariant survive process separation, durable recovery, and
ambiguous client outcomes, while every incomplete profile still has a stored
counterexample.

The five-container extension records 135 decisions, 537 events, and 95
effects across 69 atomic and 66 prior-read cases. All 540 persisted signed
responses reverify. Four injected transport-fault cases recover through the
second effect instance; allowed and denied retries replay the original
idempotent decision, and no duplicate decision or effect key appears. The
atomic profile has zero false allows; the intentionally incomplete prior-read
profile exposes 36 in this scheduling realization, including its fixed
scheduled witness. Fourteen in-run assertions and 15 separate saved-result
checks pass. These counts add cross-instance and network-fault evidence on one
host; they are not distributed-system or rate estimates.

![The executed five-container durable-revocation topology and saved
outcomes. Panel (a): runner, deterministic fault proxy, status service,
and two effect instances inside one dashed physical-host boundary, with the initial
request through the proxy to effect-a, the direct retry to effect-b, and
the shared SQLite trust domain. Panel (b): zero atomic false allows, zero
duplicate decision/effect keys, 36 designed prior-read counterexamples, 4/4
recoveries through the second instance, 540/540 signature verifications.
The physical host and datastore remain deliberately visible
ceilings.](figures/figM-containerized-revocation-boundaries.png){ width=98% }

The standalone Java checker accepts all of its finite assertions. For the
shared all-pass local vector, each of the two possible Boolean-composer
outputs makes at least one error across the matched/mismatched pair. The
binding enumeration visits 16/16 agreement states: a Boolean-only rule admits
all 15 mismatches; effect/resource binding admits 3; adding profile or time
admits 1 in each branch; full effect/resource/time/profile binding admits 0.
The revocation enumeration visits all six one-read schedules and all four
topologically valid two-read schedules. The atomic oracle has zero
mismatches; the incomplete profiles retain the canonical `R<X<C` and
`R1<R2<X<C` false-allow witnesses.

![Companion evidence-class upgrades. Panel (a) reports the 104 native state
classes. Panel (b) shows exact native-oracle agreement, mutation rejection,
and recomposition. Panel (c) contrasts the atomic guard with incomplete
revocation profiles over 93 cases each; all 96 injected fault cases recover
and no duplicate effect occurs. Counts are designed same-host laboratory
coverage, not rates.](figures/figL-evidence-class-upgrades.png){ width=97% }

The typed-transfer builder maps every native state and refuses partial
crosswalks. The EATF result preserves 16 rejection codes across 21/21
TypeScript/Python rows; the transaction result preserves 28 rejection gates
across 104/104 rows. Five of eight coarse analytic classes appear in both
corpora. If only the Boolean `REJECT` were retained, the most frequent native
code would identify 4/19 EATF rejects (21.1%) and the most frequent gate would
identify 14/89 transaction rejects (15.7%); more fundamentally, 498 unordered
pairs of distinct native rejection-code types become indistinguishable: 120
within EATF and 378 within the transaction corpus. These are code-type pairs,
not observed errors, lost bits, or proof of semantic equivalence. The
separately implemented SQLite path reproduces the coarse class for all 125 rows. Changing
each of the 46 mapping entries in turn causes at least one mismatch, and
removing each entry causes at least one unmapped row. This rules out a
vacuous or unused crosswalk entry and adds a separate execution path; it
does not make the mapping externally adjudicated.

The blind semantic-validation archive contains exactly 46 distinct native
states and four declared annotator files. It contains no author class,
expected class, oracle result, or validity flag; the frozen author mapping is
represented only by a coordinator-side SHA-256 seal. Two consecutive archive
builds are byte-identical and the response validator's synthetic self-test
passes. Because no expert has received or returned the packet, these facts
establish separation and readiness only, not semantic agreement.

![Typed first-failure states retained in the EATF and transaction corpora,
contrasted with one Boolean rejection state. The annotated pair counts are
the native distinctions erased by Boolean scalarization, not error
rates.](figures/figJ-typed-state-transfer.png){ width=92% }

The current offline container run regenerated the 104-transaction corpus with
SHA-256 `1ba6d40d...a43a8`, the native signed fixtures with
`09c868dc...583c8`, the single-fault Python answers with
`3ce82a8c...92e0`, the multi-fault Python answers with
`8596cb1d...0541`, and the revocation corpus with
`33625c8d...c563`. Each full digest matches its host reference. Inside the
container only the loopback interface existed, the route table was empty, and
an outbound literal-IP TCP connection failed with `ENETUNREACH`. This closes
the current **cross-environment** rerun, not the second-physical-host gate.

One negative provenance result is retained. An independent JavaScript
evaluator is frozen against `LABELLING-SPEC.md` version 1.0, whereas the
neutral packet uses version 1.1. The freeze therefore fails the packet's
integrity check. Its 90/90 output is a determinacy and implementation-diversity
observation about version 1.0, not an independent evaluation of version 1.1
and not an external-human label result. The neutral 104-case packet prepared
for future human labelling has not been sent to anyone.

## 7. Discussion

### 7.1 Policy is evidence about the appraisal procedure

The policy replay shows why policy should not remain ambient configuration.
The same evidence class was allowed or denied depending on whether the
verifier checked exact policy identity, version, freshness, digest, and
signature. A signed policy was not enough: stale, substituted, and
gate-isolated variants remained authentic objects while being inapplicable
to the intended decision, and the presence-oriented baselines admitted five
and six of them.

Two signed policy fields are operational in the composition:
`required_effect` and `required_measurement_profile`. Digest validation alone
cannot establish that either agrees with the action actually reported or the
measurement profile actually used. The binding stage therefore reads both.
`required_effect` is the source of
`canonical_action.effect` and is compared against the effect the signed
evidence reports and against the terminal granted tools;
`required_measurement_profile` is the source of
`canonical_action.measurement_profile` and is compared against the profile
identifier of the fixture the measurement layer actually appraised. Each
comparison has a named gate — `binding.effect` and
`binding.measurement_profile` — and each is decisive on the corpus, 3 and 1
transactions respectively. The claim is now supported in the specific sense
that removing either field, or writing a different value into it, changes a
verdict rather than only a digest.

The honest ceiling is unchanged by this. What the binding stage compares are
corpus-supplied strings; matching them establishes that two artifacts agree
about a subject, not that either artifact is true. What changed is that a
policy field now governs an outcome instead of decorating a hash.

The executed result supports including policy identity, digest, required
effect, and required measurement profile in a verifier execution passport;
activation evidence and appraisal time are motivated by the same argument
but were not exercised by any gate in this corpus. Neither list is
established to be complete.

### 7.2 Measurement support is not a scalar

Two fixtures had point estimates above threshold and still failed the
strict measurement rule: one lacked a sufficient lower bound and one
carried a different profile identity. The TOPSIS and overlap fixtures
expose two more semantics that a scalar value omits: reference-set choice
and sample dependence.

The contribution is not that every application must use one confidence
level or one reference scheme. The contribution is that those choices must
be bound to the evidence identity used to authorize an action.

### 7.3 Majority voting is the wrong composition

The comparison with the four-of-five majority is best stated as the identity
of Section 6.3, in its corrected form: a majority admits every single-fault
transaction by definition, and it also admits every transaction in which no
artifact verifier failed at all, so on any corpus its false allows are the
single-fault denies together with the cross-layer denials. No tuning of the
corpus changes that logic. The second term is the more damaging one, and it
is invisible to any composition that reduces the layers to a vote: a
cross-layer denial has zero failing verifiers, so a majority over those
verifiers has nothing to count. The design is intentionally adversarial to
compensation because the predicates answer different questions. A valid
policy cannot offset absent authority; an affirming attestation result cannot
offset replayed evidence; a high metric cannot offset a substituted effect;
and five passing verifiers describing different actions do not add up to one
authorized action.

This is analogous to safety interlocks rather than ranking. A scalar may
rank alternatives after every critical predicate passes, but it should not
purchase permission to ignore a failed critical predicate.

### 7.4 Exact verifier identity remains a dependency

An internally recorded verifier-provenance differential (public deposit
pending) found 11/11 contract matches for the current TypeScript and Python
entry points but 8/11, with three false accepts, for an older unversioned
demo entry point; a tracked-commit rebuild reproduced the outcome matrix.
This article therefore treats exact source and corpus hashes as required
artifact inputs and claims nothing further from that record.

### 7.5 From benchmark seed to evidence-carrying passport

The transaction object suggests a future evidence package:

```text
measurement passport
  + verifier execution passport
  + exact policy snapshot
  + runtime attestation result
  + authority path
  + canonical action record
  + signed reported-effect record (`observed_effect` in the current schema)
  + typed binding outcome
  + typed composition verdict
```

Building on the SAFE component and integration families of Kolesnikov and
Giudici [1, 2, 3], the measurement part can be made explicit as

$$
\mathrm{MP}=(m,\Sigma,D,\mathcal P,\mathcal A,\tau,\alpha,
t_{\mathrm{eval}},t_{\mathrm{exp}},v,\sigma),
$$

where $m$ is the component vector, $\Sigma$ its uncertainty/dependence
description, $D$ the data reference, $\mathcal P$ the measurement profile,
$\mathcal A$ the aggregation/reference-set semantics, $\tau$ the threshold,
$\alpha$ the confidence level, the two times delimit evaluation validity,
$v$ identifies the implementation, and $\sigma$ binds the record. This tuple
is our operational evidence proposal, not a tuple attributed to the cited
authors. An evidence-carrying decision package then adds the exact policy
snapshot, native verifier passports, runtime result, authority path, subject
records, decision clock, and typed binding/composition outcomes.

The package should preserve each native verdict and the protected subject it
describes. The composed verifier then checks semantic joins rather than
relabeling native verifiers as incorrect, and the 8 cross-layer denials are
the concrete demonstration of why the subject must travel with the verdict:
in each of them every native verdict was correct about its own object, and
the package as a whole was still not a basis for the action. In this artifact
the two subject records `canonical_action` and `observed_effect` are the
minimal form of that requirement.

### 7.6 Revocation must meet the effect at one boundary

The live race changes the design conclusion. Rechecking status immediately
before commit is useful but is not sufficient when the effect occurs in a
different operation. The double-read profile still has the schedule
`read(active) -> revoke -> effect`. The necessary interface is not simply
"fetch fresher status"; it is a guard whose revocation check and effect share
one linearization point, or an equivalent transactional protocol that makes
the same invariant externally auditable. This is a systems-design result
about the boundary between authorization and effect, not a claim that every
deployment can place both under one lock.

The decision clock also clarifies what must be carried in evidence. Client
timestamps alone cannot adjudicate a race with clock skew. A signed,
monotonic service sequence or append-only linearization receipt can. A future
passport should therefore record the revocation object, its sequence, the
guarded-commit receipt, and their common state-machine identity.

The process-isolated extension narrows an important alternative explanation:
the first live result could have been dismissed as one in-process lock
protecting one in-memory object. The new result keeps the invariant when
status and effect have different PIDs and listeners, after the effect service
loses its response or is killed and restarted, because the safety boundary is
the durable transaction rather than either process. It still does not show a
distributed protocol: SQLite is the shared serialization authority, all
processes use one host clock and kernel, and no partitioned multi-host state
was exercised.

### 7.7 Typed failure is a portable interface, not a universal taxonomy

The EATF transfer supports a modest but useful generalization: different
verifiers can preserve their native failure vocabularies while exposing the
same outer shape — verdict, first decisive state, protected subject,
implementation identity, and evidence digest. The coarse ontology allows
comparison, but its mapping is contestable and must remain visibly separate
from native semantics.

This is preferable to a forced universal error code. A monitoring system can
route `temporal_freshness` or `subject_binding` at a coarse level while a
domain specialist still sees `TSA_IMPRINT_MISMATCH`,
`evidence.replay`, or `binding.effect`. The 498 collapsed distinctions
quantify why retaining only `valid=false` is inadequate for diagnosis,
repair, or reviewer audit.

The SQLite mutation audit strengthens a different question from semantic
validity. It establishes that every mapping entry is live and that two
execution paths agree on the declared mapping. Whether
`TSA_IMPRINT_MISMATCH` and `binding.effect` should both be called
`subject_binding` remains an interpretive claim until independent domain
experts or executable external adapters corroborate it.

### 7.8 Native state evidence can replace a typed fixture without changing composition

The overlay is an evidence-class substitution experiment. The original
transaction subjects, other four layer results, binding records, and
composition rule are held fixed; only the state result is re-derived from a
native quote and frozen appraisal policy. Exact recomposition 104/104 shows
that this substitution is observationally conservative at the decision
interface while making quote, PCR, challenge, time-window, measurement, and
transaction bindings falsifiable.

That result does not transform `swtpm` into hardware. Its contribution is the
interface pattern: a typed state result can be backed by stronger evidence
without changing the composition algebra, provided the evidence binds the
same transaction subject and preserves the typed failure vocabulary. Hardware
TPM, manufacturer AK provenance, remote verifier sessions, and a deployed
workload remain separate experiments.

## 8. Threats to Validity

### Construct validity

The strict composition reflects the study's definition of a subject-bound
decision over the implemented projection. Other systems may use different
evaluation orders or distinguish
additional layers. The result does not imply that the five layers plus the
binding stage are a complete ontology, and the binding rules themselves are a
design choice: four comparisons in a fixed precedence, over subject fields
this artifact happens to carry. A deployment with a different notion of
"same action" would need different rules, and the time comparison here is
containment in a window rather than equality to one timestamp. The main
corpus's three decision-relevant constants are unrelated, so it does not
instantiate the full decision clock. The live revocation companion instead
uses server-side linearization indices for its critical order (Sections 4.2
and 5.6).

The policy corpus uses a test Ed25519 key and an experimental policy
profile. The authority objects are not production WAVE, JEDI, OAuth, or
MachineMandate credentials, and the authority layer's cryptographic flags
are corpus-supplied **in the 104-transaction main corpus**. The companion
native adapter and revocation laboratory verify real Ed25519 signatures but
use Tyche experimental credential/status profiles and deterministic test
keys; they do not retroactively make the main corpus cryptographic or
establish conformance with an external protocol. The frozen source corpus
still encodes its author-written state oracle in structural
attestation-result objects. The native overlay replaces the *evaluation* of
that predicate with 104 quote/PCR/challenge/reference-policy appraisals and
then recomposes, but it does not make those author-written reference policies
external ground truth or attest a deployed runtime. Its eight roots are
software TPMs created on one physical host; no hardware root, manufacturer AK
identity, protected trusted time, or remote workload exists. The measurement
data are synthetic boundary fixtures. The binding-stage ceiling of
Section 2 applies unchanged: a cross-layer denial on this corpus
demonstrates that the seam is representable and localizable, not that any
deployed system exhibits it.

### Internal validity

Expected labels and evaluators originate from the same research programme,
and at the composition level the labels are generated by the same shared
composition-rule module the verifier imports; that agreement is analytic.
Per-layer agreement is the non-analytic execution check; subject-record
agreement is explicitly a same-function plumbing check. The same split
applies, in a weaker
form, to the policy laboratory: there the expected verdict and expected
rejecting gate are machine-generated by a precedence ladder that the runner
re-implements, so agreement on those two fields is agreement between two
transcriptions of one function (Section 6.1).

Pure-Python/NumPy agreement and the relational re-composition paths reduce
implementation-path risk but do not create external label independence; only
the delegation-path oracle re-derives verdicts from raw case objects, and
even it shares case expansion and expected labels with the Python entry
point. Three of its four gate-isolation cases exercise a branch by flipping
the corpus-supplied Boolean that branch reads, which is branch coverage in
two implementations at once and not verification of the property the branch
names (Section 5.3).

The recorded Veraison freshness run motivating Section 5.1 and the
verifier-provenance differential of Section 7.4 are internal companion
artifacts of this research programme; public deposits are pending, and no
load-bearing claim depends on either record.

The mutation and revocation expectations are also author-written. A
pre-oracle freeze prevents moving evaluator outputs after the mutation oracle
is opened, but does not make that oracle independent or correct. The
revocation implementations share the same frozen packet and internal
expected labels. The independent-JavaScript freeze against the external-label
packet targets labelling specification 1.0, whereas the analysis uses
specification 1.1; it therefore does not validate the active labelling
specification.

Both live services derive their oracle from the state stored by the same
linearization mechanism that records the effect. This avoids client-clock
guessing but is not an independent implementation of the service semantics.
The durable extension narrows the one-process explanation, not the
centralized-oracle explanation: both services share one SQLite database. The
exact false-allow totals in same-release trials vary with scheduler order;
only the zero-error atomic invariant, zero-duplicate invariant, fault
recoveries, and deterministic counterexample placements are acceptance
conditions. The EATF crosswalk is author-written. Completeness, SQL agreement,
and mutation sensitivity are machine-checked, but the choice of eight coarse
classes is an interpretive analysis rather than ground truth.

The composed verifier imports source evaluator code. The corpus hash
closure prevents silent source-corpus substitution within the run. A
companion container run (Section 9) reproduced every reported experimental
quantity
under a different Linux distribution, CPython patch level, C library, and
SQLite engine, but that container shared the host kernel, the host CPU, and
the host's compiled NumPy and OpenSSL binaries. The container run includes
the 104-transaction binding corpus,
native signed adapter, mutation corpora, and revocation corpus; its
cross-environment claim remains a same-host claim (Section 9).

Two subsequent hosted-runner repetitions verify the sealed capsule, apply the
same hash-recorded overlay, and execute four declared lanes on separate
GitHub-hosted job VMs reporting x86_64 and ARM64, with exact
architecture-specific dependency resolution. They satisfy the frozen semantic
contract on both architectures and remove the cross-architecture gap for
policy replay, composed-corpus evaluation, typed transfer, and
process-isolated durable revocation. They do not execute the native-TPM
overlay, one-process live service, Java/model-check, or five-container labs on
ARM64; identify the underlying physical hosts; use a hardware TPM; or supply
outside-operator independence. Local hash-checked runs also cover the
native-TPM, live-service, neutral-packet, and typed-transfer companions. The
source capsule vendors the SAFE and boundary-seal trees plus an offline amd64
wheelhouse. A hash-bound JSON result and full log record a successful clean
temporary extraction on the same x86_64 host. The hosted workflow verifies
that exact 210-member source capsule, applies the declared
overlay, installs the same pinned dependencies natively for each architecture,
and completes its four-lane contract twice on both reported
architectures.

### External validity

The 104 deterministic transactions do not sample deployed agent populations.
False-allow counts compare profiles on this corpus, are partly determined by
corpus composition (Section 6.3), and must not be interpreted as real-world
rates. The count of 8 cross-layer denials is likewise a property of the
corpus we designed, not a frequency: it says that at least 8 distinct
subject-disagreement shapes are representable and were exercised, and it says
nothing about how often such disagreements arise anywhere.

The recorded A2A evidence adapter in the authority lineage is hybrid; the
experimental authority overlay remains synthetic. Separate local status and
effect services, concurrent revocation, response loss, and effect-service
restart were executed; a five-container extension adds two effect instances,
an internal bridge, and deterministic request/response loss, but shares one
physical host and SQLite volume. No public or remote service, payment, robot,
institutional workflow, distributed clock, network partition, or multi-host
revocation event was exercised, and no latency, throughput, or
resource-cost characterization is reported for the live services: the
study is correctness-scoped. The neutral external-label packet covers all
104 cases, its blind analysis pipeline is executable, and it remains
undispatched.

### Statistical validity

Bootstrap and TOPSIS cases were constructed to expose boundary behavior.
They show existence, not prevalence. The bootstrap uses the plain
percentile method with n as small as 18 and no BCa correction; the
companion seed/replicate sweep (Section 5.2) shows the reported outcomes
are not seed or replicate-count artifacts, but the boundary decision could
still move under a different estimator family. Across NumPy 2.4.4, 2.4.6, 2.5.0, and 2.5.1 on one
processor the lower bounds did not move at all (Section 9), but that probe
holds the CPU and its instruction dispatch fixed, so cross-build
reproducibility of that third decimal is not established in general. The
overlap fixture threshold was declared in the frozen corpus as a designed
counterexample. Larger studies must preregister realistic data-generating
processes, thresholds, and consequences of false allow and false deny.

The same-barrier and same-release live-race totals are scheduling
realizations, not
binomial estimates of a stable event probability. No confidence interval is
reported for them because the trials are not independent draws from a defined
deployment distribution. Their purpose is to exercise both linearization
orders and preserve exact event traces.

## 9. Reproducibility and Artifact Statement

The laboratory entry points are:

```bash
labs/policy-version-evidence-replay/run.sh
labs/composed-transaction-corpus/run.sh
labs/formal-composition-modelcheck/run.sh
labs/protocol-valid-unauthorized/verify_corpus.py
labs/protocol-valid-unauthorized/verify_delegation_paths.py
labs/protocol-valid-unauthorized/run_sql_oracle.py
labs/prospective-revocation-races/run.sh
labs/native-runtime-attestation/verify_runtime_attestation.py
labs/native-state-transaction-overlay/run.sh
labs/live-revocation-service/run_live_races.py
labs/distributed-revocation-service/run.sh
labs/containerized-durable-revocation/run.sh
labs/cross-ecosystem-typed-transfer/build_transfer.py
labs/cross-ecosystem-typed-transfer/verify_crosswalk_sql.py
external-label-packet-neutral-104/build_neutral_packet.py
external-label-packet-neutral-104/analyze_responses.py --self-test
companions/native-signed-authority-adapters/verify_fixtures.py
companions/thesis-v4-mutation-tests/evaluate_mutation_corpus.py
companions/thesis-v4-multifault-tests/freeze_and_compare.py
repro/verify_portable_source_capsule.py
repro/run_clean_capsule_replay.py
```

The composed laboratory's entry point runs, in order, the state-adapter
self-test, the corpus build, the cross-layer binding acceptance test, the
composed verifier, and the relational oracle, then verifies both checksum
manifests. The acceptance test is a gate: it exits non-zero if the Section 1
counterexample is allowed, if any of its five component verifiers fails on
that transaction, if the binding result or gate is not `EFFECT_MISMATCH` /
`binding.effect`, or if the matched lookalike is not allowed at gate
`verified`. The native signed authority adapter, both mutation
laboratories, and their input evaluator are committed under
`companions/`; their packet and result digests (`09c868dc…`, `af226bac…`,
`3ce82a8c…`, `5233577a…`, `8596cb1d…`) re-derive from the committed trees.

Each deterministic entry point was executed twice end to end against the
corpus reported here: every regenerated result file and the complete
standard output were byte-identical between runs, and all checksum
manifests verified from their owning directories, including the pinned
hashes of the frozen SAFE sources. The generated native overlay and both
live-race results are intentionally not byte-stable, because fresh
attestation-key material, TPM clock fields, operating-system scheduling,
and process identity are evidence; their acceptance assertions are
typed-class and recomposition parity, mutation rejection, atomic safety,
idempotent recovery, signature verification, and exposure of at least one
false allow in every incomplete profile. The live entry points bind only to
`127.0.0.1` and perform no external request.

A companion container reproduction re-executed the entry points offline
from a digest-pinned base image with no network namespace and a read-only
root filesystem; it reproduced the composition counts (104 transactions,
15 allows, 89 denies, 8 cross-layer denials), signed adapter 8/8,
single-fault 38/38, multi-fault 12/12, and revocation 13/13, with all six
regenerated artifact hashes equal to the host references. The container
changes Linux userland, CPython patch level, glibc, and SQLite version
while sharing the host kernel, CPU, and compiled NumPy/OpenSSL wheels, so
it is cross-environment evidence only.

A deterministic 22.1 MB portable source capsule (210 members, embedded
manifest, relative-path safety and payload digests verified) vendors the
laboratories, their frozen sibling inputs, reproduction scripts, and an
offline CPython 3.12 wheelhouse. A declared release overlay — which repairs
execute bits on three archived run scripts and replaces one hard-coded
architecture label with `platform.machine()`, changing no fixture,
evaluator, expected count, or assertion — ran the verified sealed capsule
twice on GitHub-hosted x86_64 and ARM64 job VMs. Both repetitions verified
210/210 capsule members, satisfied 20/20 architecture-neutral semantic
assertions per architecture, and agreed on all 11/11 cross-architecture
comparisons, with identical result counts: 16 policy vectors, 104 composed
transactions, eight binding denials, 21 EATF rows, 104 transfer rows, 372
revocation cases, and 96 fault cases. The runs install identical dependency
versions natively per architecture. A preserved hosted field reading `same
physical x86_64/aarch64 host` is a legacy topology label from the runner,
not physical-host attestation: one job VM per execution, underlying
physical identity unknown. The hosted anchors are source commits
`c85bc3aa…` (preferred) and `428ce24b…` (repeat) with their complete
downloaded-evidence manifests pinned in the artifact ledger. A direct
public-tree matrix run over source commit `d605e8d…` returned 20/20 on the
x86_64 job VM, 20/20 on the ARM64 job VM, and 8/8 in the cross-architecture
comparison, and a further matrix run at source commit `62d5df8…`
reproduced the same contract; the four lanes' code and fixtures are
unchanged between those commits and the present manuscript source.

A complementary execution domain is an identified Ubuntu 24.04 x86_64
Hyper-V VM/OS instance exposing a Microsoft vTPM, recorded in the artifact
under the host label `zeus2` and distinguished by hashed machine and boot
identifiers, DMI strings, and TPM manufacturer properties (`MSFT`). The
identified VM verifies the deterministic public source archive and then
satisfies the same four-lane contract (16 policy vectors, 104 composed
transactions, eight binding denials, 21 EATF rows, 104 transfer rows, 372
revocation cases, 96 fault cases, 20/20 semantic assertions). Its
non-destructive TPM companion first passes 11/11 static/input checks and
17/17 negative safety checks; the vTPM rejects `tpm2_createak` below a
generic transient endorsement primary with `TPM_RC_POLICY`, and a declared
compatibility overlay instead creates an owner-hierarchy transient primary
and an ordinary transient RSA signing key whose encrypted private blob
never leaves the temporary private directory. The final run verifies
104/104 quotes with `tpm2_checkquote`, one unique random challenge and
qualifying-data digest per transaction, and rejects all 64 predeclared
mutations. The identified VM's eight predeclared mutation classes follow
the hardware-companion plan (quote message, signature, PCR blob, challenge,
transaction substitution, source-corpus hash, capsule hash, and
qualifying-data representation); this plan shares six classes with the
native-overlay plan of Section 5.6 and replaces its measurement and
signed-window classes with the capsule and representation classes. A
read-only handle census returns zero new transient and zero persistent
handles, and the public bundle contains no `.ctx`, `.priv`, or PEM private
key. This is live vTPM evidence on an identified VM/OS, not discrete
hardware-TPM or physical-host attestation.

The execution domains and their contract counts are summarized below.
Cells are deterministic contract checks on designed corpora, not
deployed-system rates; the identified-VM row is a VM/OS with a Microsoft
vTPM, not evidence of the underlying physical host or a hardware root of
trust.

| Execution domain | Policy | Corpus | Transfer | Revocation | Quotes | Mutations |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Local x86_64, software TPM (8 fresh `swtpm` roots; one physical host) | 16 | 104 | 104 | 372 | 104/104 | 64/64 |
| Hosted x86_64 job VM (contract 20/20; physical host unknown) | 16 | 104 | 104 | 372 | — | — |
| Hosted ARM64 job VM (contract 20/20; physical host unknown) | 16 | 104 | 104 | 372 | — | — |
| Identified VM (`zeus2`), Hyper-V x86_64 (contract 20/20; Microsoft vTPM) | 16 | 104 | 104 | 372 | 104/104 | 64/64 |

The local software-TPM quote and mutation counts are verified
independently by the Python and compiled Java implementations; the
identified-VM counts are live Microsoft-vTPM verifications.

A blind-safe public artifact repository records Anton Sokolov as author,
ORCID 0000-0003-2452-7096, and Tyche Institute as affiliation:
<https://github.com/tyche-institute/subject-bound-evidence-composition-artifact>.
Original code and schemas carry Apache-2.0 terms; original prose, figures,
synthetic corpora, fixtures, and generated research data carry CC-BY-4.0
terms, with upstream notices preserved. The `v0.2.0-rc2` release is built
by a deterministic fail-closed sanitizer from an exact allowlist over a
clean source commit; two builds over the release-candidate tree and one
from a clean clone produced byte-identical archives, and a fresh anonymous
HTTPS clone of the public commit `212b2ff5…` independently verified the
root manifest, regenerated all four lanes, and satisfied 20/20 semantic
assertions and 4/4 replay-evidence manifest entries. Software Heritage
completed a full archival visit of the release. The release anchors the
code, corpora, and generated evidence, all unchanged in the range between
its source commit and the present manuscript source; the preprint copy
bundled inside the release is an earlier draft, so the manuscript of record
is the journal submission, and a release recut at the submitted commit is
planned as a separate, explicitly authorized step. A DOI is not asserted or required by
the scoped reproducibility claim.

The root content anchors are:

```text
composed transaction corpus (104 transactions) SHA-256:
  1ba6d40d07e62a862b98ec52ab5c189eb491f19e4e1e69a411fba73bbb9a43a8

shared composition-rule module SHA-256:
  ac430575a00e0090434202d41c430e9fb9818924fc435ea766c64759fe93e61d

process-isolated durable revocation archived result SHA-256:
  367f957503c3959acea1f1ee2ee9bebf506e2eed9878e4a0313423da47879358

portable second-host source capsule SHA-256:
  8c8919f9826381da289b73dfd35721938ad5aafea5cd3687b23187589a2d0386

public release archive SHA-256:
  9d3f2e38ad64fea29271c31d63ac1b57a35ce68e92152d36edcbda29ac8a867f

Software Heritage snapshot:
  swh:1:snp:f04ffb15417761d510910aa98d75add6fda83599

identified-VM provenance / evidence manifest SHA-256:
  8da49f87f6c0c589873d618786bee086f03d8030f3f360301118da07f51f86ed
  ce20410880c05f4ef0a5a65c8fed9006e63217d5e482e4d1a8395c9ff8ef7dcd
```

Every other per-artifact digest quoted in Sections 5 and 6 — source
corpora, mutation packets, native overlay and model-check results, hosted
evidence manifests, and container logs — is recorded in the repository's
checksum manifests (`SHA256SUMS`, per-laboratory manifests, and the
artifact ledger), which the entry points verify as part of their runs. The
shared composition-rule module is hashed because it is the single
implementation of the conjunction, the binding stage, and the gate ladder
imported by both the corpus builder and the verifier: its hash is what
makes the analytic character of composition-level agreement checkable
rather than merely asserted.

The sanitized artifact repository is public. The source/coordinator
repository and the blind-study coordination materials (sealed expected
labels, annotator archives, participant coordination records) remain
private so that the prepared external-labelling and semantic-validation
studies stay blind.

## 10. Conclusion

RQ1 is answered by the eight cross-layer denials and the ablation ladder of
Section 6.3; RQ2 by the native state overlay and the atomic
status-and-effect boundary of Section 6.4; RQ3 by the typed transfer result
of Section 6.4, at the analytic-crosswalk ceiling stated there.

The artifact study operationalizes a narrow proposition: individually valid
or plausible artifacts are insufficient when a required global relation is
absent from local verdicts. The executable result instantiates that proposition
only for effect, resource, report time, and measurement profile; it does not
bind the state/workload subject or prove one complete action identity. Five
scalar layer results alone cannot represent a transaction in which all five
pass but the transaction remains inadmissible under $C$. The binding stage
represents this class, and 8 such transactions exist in the frozen corpus,
each denied at a named binding gate
with every component verifier passing, each paired with a matched all-valid
lookalike that is allowed. The opening counterexample — a
correctly signed receipt reporting a WRITE effect where the valid delegation
path permits only READ — is denied at `binding.effect`, while its matched
lookalike is allowed.

Across the frozen fixtures, exact policy appraisal avoided the five or six
false allows created by weaker policy profiles on the 16-vector corpus.
Metamorphic tests exposed profile, uncertainty, dependence, and reference-set
semantics absent from a point score. On the 104-transaction composed corpus,
point-only, majority, and artifact-validity ablations produced 2, 31, and 48
false allows respectively; the majority count is an identity, but with the
single-fault denies *and* the cross-layer denials rather than with the
single-fault denies alone, and the failure of the narrower identity is itself
the result. The subject-aware partial joins leave 3, 2, and 1 false allows
when they omit both time and profile, time only, and profile only,
respectively. The counts are corpus coverage rather than rates, and the
composed verifier's 104/104 decomposes into an analytic composition-level
component, 104/104 per-layer execution agreement, and a 104/104 same-function
subject-record plumbing check, all stated in Section 6.3.

 Every companion mechanism —
native signed credentials, generated single- and multi-fault transactions,
scheduled revocation sequences, native quote appraisal with a separately
compiled verifier, the finite model check, process-isolated and
five-container durable revocation races, and typed transfer with a separate
SQL sensitivity audit — is executable from the committed trees. The live
result isolates the systems requirement the scheduled fixtures only
suggested: revocation status and effect need one linearization boundary,
and the recovery result shows why that boundary also needs idempotent
effects. The transfer result isolates one diagnostic cost of
Booleanization: 498 unordered within-corpus pairs of distinct
rejection-code types collapse to the same Boolean value.

The experimental ceiling is explicit rather than a queue of unearned future
claims. The verified capsule plus declared overlay completes its four-lane
contract twice on GitHub-hosted job VMs reporting x86_64 and ARM64, and once
on the identified Hyper-V VM/OS. The identified VM's Microsoft-vTPM
companion adds 104/104 live quote verifications and 64/64 mutation
rejections with a clean post-run handle census. These observations support portability across
the reported execution domains and a bounded vTPM evidence path. They do not
identify an underlying physical host, attest a hardware root, measure
multi-host consensus, or estimate deployed-system rates.

External human labels remain uncollected because the scoped study does not
use them as empirical observations: the designed corpus is evaluated against
an explicit author-defined reference specification, and the result claimed is
cross-implementation agreement plus counterexample coverage. The undispatched
neutral packet is an optional future construct-validity extension. Similarly,
the crosswalk is claimed only as an executable author-defined typed adapter
whose code preservation and mutation sensitivity are measured; no external
semantic consensus or interoperability claim is made. These two extensions
may broaden external validity, but their absence does not invalidate the
reported synthetic-benchmark result.

The manuscript is therefore a submission candidate for the
narrow claim actually tested: local Boolean validity cannot substitute for
typed composition over the implemented effect, resource, report-time, and
measurement-profile coordinates, and revocation status and effect require
one commit boundary in the implemented model. It remains a benchmark and
systems result, not a claim of production validity.

## Declarations

**Funding.** This research received no external funding.

**Competing interests.** The author declares no competing interests.

**Generative-AI assistance.** The author used Anthropic Claude
Code for unit testing, drafting and editing assistance, reference
verification, and reproducibility checks. All claims, results, design
decisions, and references are the author's own and verified by the
author, who takes full responsibility. Reported per COPE and ICMJE
recommendations.

**Data and code availability.** The sanitized public artifact repository,
deterministic release archive, and Software Heritage snapshot are
identified in Section 9, together with the root content anchors.

## References

[1] V. Kolesnikov. *A Proposal for a S.A.F.E-AI Compliance Score*. Master's
thesis, University of Pavia, academic year 2024--2025.
<https://hdl.handle.net/20.500.14239/29928>.

[2] P. Giudici and V. Kolesnikov. "SAFE AI Metrics: An Integrated Approach."
*Machine Learning with Applications* 23, 100821, 2026.
<https://doi.org/10.1016/j.mlwa.2025.100821>.

[3] P. Giudici and V. Kolesnikov. "Integrating SAFE AI Metrics." SSRN
5362574, 2025. <https://papers.ssrn.com/sol3/papers.cfm?abstract_id=5362574>.

[4] G. Babaei and P. Giudici. "A Statistical Package for Safe Artificial
Intelligence." *Statistical Methods & Applications* 34, 499--517, 2025.
<https://doi.org/10.1007/s10260-025-00796-y>.

[5] T. South et al. "Position: AI Agents Need Authenticated Delegation."
*Proceedings of the 42nd International Conference on Machine Learning*,
PMLR 267, 2025. <https://proceedings.mlr.press/v267/south25a.html>.

[6] M. Andersen et al. "WAVE: A Decentralized Authorization Framework with
Transitive Delegation." USENIX Security, 2019.
<https://www.usenix.org/conference/usenixsecurity19/presentation/andersen>.

[7] S. Kumar et al. "JEDI: Many-to-Many End-to-End Encryption and Key
Delegation for IoT." USENIX Security, 2019.
<https://www.usenix.org/conference/usenixsecurity19/presentation/kumar-sam>.

[8] Y. Kim et al. "TeamBench: Evaluating Agent Coordination under Enforced
Role Separation." arXiv:2605.07073, 2026.
<https://arxiv.org/abs/2605.07073>.

[9] H. Dingeto and W. Leeney. "AgentRedBench: Dynamic Redteaming and
Integration-Aware Defense for LLM Agents over SaaS Integrations."
arXiv:2606.02240, 2026. <https://arxiv.org/abs/2606.02240>.

[10] S. Hu, L. Liu, Z. Meng, and Z. Zhao. "ToolPrivacyBench: Benchmarking
Purpose-Bound Privacy in Tool-Using LLM Agents." arXiv:2606.28061, 2026.
<https://arxiv.org/abs/2606.28061>.

[11] Y.-S. Chen, S.-Y. Huang, C.-L. Yang, and Y.-N. Chen. "TraceSafe: A
Systematic Assessment of LLM Guardrails on Multi-Step Tool-Calling
Trajectories." arXiv:2604.07223, 2026. <https://arxiv.org/abs/2604.07223>.

[12] S. Deochake. "Heartbeat-Bound Hierarchical Credentials: Cryptographic
Revocation for AI Agent Swarms." arXiv:2605.20704, 2026.
<https://arxiv.org/abs/2605.20704>.

[13] J. Li. "Trusted Credentials, Untrusted Behavior: Benchmarking LLM-Agent
Security in High-Performance Computing." arXiv:2607.18485, 2026.
<https://arxiv.org/abs/2607.18485>. Cited for its benchmark of authenticated
account-level actions that depart from the user's assigned task.

[14] H. Birkholz et al. *Remote ATtestation procedureS (RATS) Architecture*.
RFC 9334, 2023. <https://datatracker.ietf.org/doc/rfc9334/>.

[15] H. Birkholz, A. Delignat-Lavaud, C. Fournet, Y. Deshpande, and
S. Lasker. *An Architecture for Trustworthy and Transparent Digital Supply
Chains*. RFC 9943, Standards Track, June 2026.
<https://www.rfc-editor.org/rfc/rfc9943>.

[16] Linux Foundation. *Agent2Agent (A2A) Protocol Specification*,
Version 1.0.0, accessed 2026-07-27. <https://a2a-protocol.org/latest/>.

[17] Model Context Protocol. *Authorization*, revision 2025-11-25, accessed
2026-07-27; a subsequent revision dated 2026-07-28 has been announced.
<https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization>.

[18] NIST NCCoE. *Accelerating the Adoption of Software and AI Agent
Identity and Authorization*. Concept paper, 2026.
<https://www.nccoe.nist.gov/publications/other/accelerating-adoption-software-and-ai-agent-identity-and-authorization-concept>.

[19] M. S. García-Cascales and M. T. Lamata. "On Rank Reversal and TOPSIS
Method." *Mathematical and Computer Modelling* 56(5--6), 123--132, 2012.
<https://doi.org/10.1016/j.mcm.2011.12.022>.

[20] Y.-M. Wang and Y. Luo. "On Rank Reversal in Decision Analysis."
*Mathematical and Computer Modelling* 49(5--6), 1221--1229, 2009.
<https://doi.org/10.1016/j.mcm.2008.06.019>.

[21] R. F. de F. Aires and L. Ferreira. "The Rank Reversal Problem in
Multi-Criteria Decision Making: A Literature Review." *Pesquisa
Operacional* 38(2), 331--362, 2018.
<https://doi.org/10.1590/0101-7438.2018.038.02.0331>.

[22] A. C. Cameron, J. B. Gelbach, and D. L. Miller. "Bootstrap-Based
Improvements for Inference with Clustered Errors." *The Review of
Economics and Statistics* 90(3), 414--427, 2008.
<https://doi.org/10.1162/rest.90.3.414>.

[23] H. R. Künsch. "The Jackknife and the Bootstrap for General Stationary
Observations." *The Annals of Statistics* 17(3), 1217--1241, 1989.
<https://doi.org/10.1214/aos/1176347265>.

[24] D. N. Politis and J. P. Romano. "The Stationary Bootstrap." *Journal
of the American Statistical Association* 89(428), 1303--1313, 1994.
<https://doi.org/10.1080/01621459.1994.10476870>.

[25] T. Y. Chen, S. C. Cheung, and S. M. Yiu. "Metamorphic Testing: A New
Approach for Generating Next Test Cases." Technical Report HKUST-CS98-01,
Hong Kong University of Science and Technology, 1998; arXiv:2002.12543.
<https://arxiv.org/abs/2002.12543>.

[26] S. Segura, G. Fraser, A. B. Sanchez, and A. Ruiz-Cortés. "A Survey on
Metamorphic Testing." *IEEE Transactions on Software Engineering* 42(9),
805--824, 2016. <https://doi.org/10.1109/TSE.2016.2532875>.

[27] K. Fisler, S. Krishnamurthi, L. A. Meyerovich, and M. C. Tschantz.
"Verification and Change-Impact Analysis of Access-Control Policies."
*Proceedings of the 27th International Conference on Software Engineering
(ICSE '05)*, 196--205, 2005. <https://doi.org/10.1145/1062455.1062502>.

[28] OASIS. *eXtensible Access Control Markup Language (XACML) Version
3.0*. OASIS Standard, January 2013.
<http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html>.

[29] J. Rushby. *Modular Certification*. NASA Contractor Report
NASA/CR-2002-212130, 2002. Available through the NASA Technical Reports
Server: <https://ntrs.nasa.gov/search?q=NASA%2FCR-2002-212130>.

[30] N. Criado. "Resource-bounded Norm Monitoring In Multi-agent Systems."
*Journal of Artificial Intelligence Research* 62, 153--192, 2018.
<https://doi.org/10.1613/jair.1.11206>.

[31] D. Dell'Anna, N. Alechina, F. Dalpiaz, M. Dastani, and B. Logan.
"Data-Driven Revision of Conditional Norms in Multi-Agent Systems."
*Journal of Artificial Intelligence Research* 75, 1549--1593, 2022.
<https://doi.org/10.1613/jair.1.13683>.

[32] S. Saisubramanian, E. Kamar, and S. Zilberstein. "Avoiding Negative
Side Effects of Autonomous Systems in the Open World." *Journal of
Artificial Intelligence Research* 74, 143--177, 2022.
<https://doi.org/10.1613/jair.1.13581>.

[33] Tyche Institute. *EATF Agent Evidence Package Toolkit*. Version 0.3.0,
2026; decision-path differential experiment, result commit
`1a6329495e6e1235c388f72d209f23eefa38fe38`.
<https://doi.org/10.5281/zenodo.21618887>;
<https://github.com/tyche-institute/eatf-verifier>. Published under the
historical expansion of AEP; the framework's current canonical expansion is
Action Evidence Package.

[34] M. P. Herlihy and J. M. Wing. "Linearizability: A Correctness
Condition for Concurrent Objects." *ACM Transactions on Programming
Languages and Systems* 12(3), 463--492, 1990.
<https://doi.org/10.1145/78969.78972>.

[35] Trusted Computing Group. *TPM 2.0 Library Specification*. Accessed
2026-07-27.
<https://trustedcomputinggroup.org/resource/tpm-library-specification/>.

[36] F. Belardinelli, A. Lomuscio, and F. Patrizi. "Verification of
Agent-Based Artifact Systems." *Journal of Artificial Intelligence Research*
51, 333--376, 2014. <https://doi.org/10.1613/JAIR.4424>.

[37] R. Micalizio and P. Torasso. "Cooperative Monitoring to Diagnose
Multiagent Plans." *Journal of Artificial Intelligence Research* 51, 1--70,
2014. <https://doi.org/10.1613/JAIR.4339>.

[38] N. Hardy. "The Confused Deputy (or why capabilities might have been
invented)." *ACM SIGOPS Operating Systems Review* 22(4), 36--38, 1988.
<https://doi.org/10.1145/54289.871709>.

[39] B. Campbell, J. Bradley, and N. Sakimura. *Resource Indicators for
OAuth 2.0*. RFC 8707, 2020. <https://www.rfc-editor.org/rfc/rfc8707>.

[40] T. Lodderstedt, J. Richer, and B. Campbell. *OAuth 2.0 Rich
Authorization Requests*. RFC 9396, 2023.
<https://www.rfc-editor.org/rfc/rfc9396>.

[41] D. Fett, B. Campbell, J. Bradley, T. Lodderstedt, M. Jones, and
D. Waite. *OAuth 2.0 Demonstrating Proof of Possession (DPoP)*. RFC 9449,
2023. <https://www.rfc-editor.org/rfc/rfc9449>.

[42] W3C. *Verifiable Credentials Data Model v2.0*. W3C Recommendation,
15 May 2025. <https://www.w3.org/TR/vc-data-model-2.0/>.

[43] SPIFFE Project. *Secure Production Identity Framework for Everyone
(SPIFFE) Standards*. Accessed 2026-07-31.
<https://github.com/spiffe/spiffe>.

[44] Open Policy Agent. *Policy Language (Rego)*. Documentation, accessed
2026-07-31. <https://www.openpolicyagent.org/docs/latest/policy-language/>.
