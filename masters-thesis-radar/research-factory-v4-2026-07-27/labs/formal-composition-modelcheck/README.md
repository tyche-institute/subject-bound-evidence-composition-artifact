# Standalone finite composition model check

This lab is an implementation-diverse check of three bounded claims used by
the flagship manuscript. It is a dependency-free Java program and imports no
Python adapter, corpus builder, SQL oracle, expected-label module, or saved
verdict stream.

It exhausts:

1. both possible outputs of an arbitrary Boolean-only composer on the
   all-local-pass vector, proving by cases that it must misclassify either the
   matched or subject-mismatched witness;
2. all 16 agreement/mismatch states over effect, resource, time, and
   measurement profile, checking the strict refinement lattice and the
   15/3/1/1/0 mismatch admissions of five schemas;
3. all six orders of read, revoke, and commit, plus all topologically valid
   two-read orders, checking zero atomic-oracle mismatches and exhibiting the
   `R<X<C` and `R1<R2<X<C` incomplete-profile counterexamples.

Run:

```bash
./run.sh
```

`results.json` and `SHA256SUMS` are generated deterministically.

Claim ceiling: this is exhaustive for the declared finite models, not a proof
of arbitrary code, distributed consensus, hardware behavior, or deployment
prevalence. Independence is implementation diversity, not an outside
operator or external peer review.
