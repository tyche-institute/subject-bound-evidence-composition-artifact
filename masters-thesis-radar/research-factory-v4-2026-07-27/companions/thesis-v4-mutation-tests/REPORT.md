# Thesis-v4 mutation differential report

- Status: **PASS**
- Corpus: 38 deterministic cases = 1 unmodified baseline + 37 isolated faults.
- Oracle verdict + first gate: **38/38**.
- Independent JS/Python typed layer fields: **570/570**.
- Mismatches: **0**.
- Freeze: `079957580ee3672da0c6872fd9c7712bfc12e6e799c9bd1555fb21249df6fdcb`.
- Mutation packet: `af226bac2a7223cb607a2eea075fc93831185c225c25dfcb2c717c99df2f63ab`.
- Oracle: `9ae611a9101432364d1df5280cd5ab0ddf9e98b669a7b01571906591363bd10b`.

## Interpretation

The mutation operators cover P1-P5, E1-E2, S1-S3, A0-A19 and M1-M3 with one
fault introduced at a time after selection of a fully passing transaction.
Both implementations were written and run without reading the mutation oracle;
their outputs and source files were hashed in `PREORACLE-FREEZE.json` before
comparison.

This is internal deterministic property evidence over a designed corpus. It
strengthens fault-localisation and implementation-independence evidence, but it
is not external ground truth, standards conformance, or deployed-system
validation.
