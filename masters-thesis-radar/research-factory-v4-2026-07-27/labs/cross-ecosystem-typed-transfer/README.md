# Cross-ecosystem transfer of typed first-failure states

This lab asks a deliberately narrow transfer question: can the paper's
`first decisive gate` representation encode results from a separately
constructed artifact-verification stack without collapsing them to a Boolean?

The external stack is the public EATF Agent Evidence Package toolkit's
decision-path experiment (Apache-2.0).  Its frozen result contains 21 cases,
two first-party language implementations, and 16 rejection codes.  The second source is
the paper's 104-case composed transaction corpus.  Field-minimized local
snapshots preserve the observed TypeScript and Python verdict/code pairs and
the transaction first gates.  The builder hard-codes and enforces the snapshot
hashes **before parsing**, then verifies the upstream source hashes and EATF
commit embedded during the one-time freeze.  It exits non-zero on any drift,
requires a complete explicit crosswalk, and reports the information discarded
by Boolean scalarization.  Reproduction therefore needs no mutable path outside
this directory.

The shared ontology is an **analytic crosswalk**, not a standards mapping:
`representation`, `cryptographic_integrity`, `trust_or_authority`,
`temporal_freshness`, `subject_binding`, `policy_compatibility`,
`measurement_confidence`, and `runtime_state`.  Native codes remain in the
output; the ontology never replaces them.

`verify_crosswalk_sql.py` executes the frozen JSON crosswalk through SQLite,
independently of the Python dictionaries in `build_transfer.py`. It then
changes and removes every mapping entry in turn. Every class mutation must
produce a wrong row and every omission must produce an unmapped row. This
tests totality, implementation agreement, and sensitivity; it still does not
make the author-defined ontology externally valid.

## Run

```sh
python3 build_transfer.py
python3 verify_crosswalk_sql.py
sha256sum -c SHA256SUMS
```

Transfer here means representational reuse across two executable corpora.  It
does not establish semantic equivalence, interoperability, deployed-system
validity, implementation independence, or an external replication.
