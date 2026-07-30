# Native TPM state overlay for the 104-transaction corpus

This laboratory replaces the composed corpus's structural state-field
comparison with native TPM 2.0 appraisal while leaving the frozen r4 corpus
and its other four evaluators unchanged.

It creates 104 transaction-bound quotes under eight independently initialized
software-TPM roots: four RSA and four ECC attestation keys, thirteen
transactions per root.  Every quote binds the frozen source-corpus digest,
transaction identifier, subject-derived capsule identifier, measured runtime
digest, signed validity interval, and a transaction-unique verifier challenge.
PCR 16 carries the measured runtime digest.

The native adapter does **not** consume the corpus's `status` field.  After
`tpm2_checkquote`, PCR, qualifying-data, transaction-binding, and challenge
checks, it applies a frozen reference policy in this order:

1. invalid native evidence -> `CRYPTOGRAPHIC_FAILURE`;
2. policy-denied measurement -> `CONTRAINDICATED`;
3. challenge or signed-window failure -> `STALE`;
4. measurement/reference disagreement -> `REFERENCE_MISMATCH`;
5. otherwise -> `PASS`.

The author-designed source classes are retained only as a sealed test oracle.
They are not external labels.  `verify_overlay.py` also applies eight
predeclared mutations to one vector from each root (64 negatives) and
recomposes all 104 decisions through the original `composition_rule.py`.

Run:

```sh
./run.sh
sha256sum -c results/SHA256SUMS
```

`run.sh` also compiles and executes the independent Java verifier in
`independent-java/`.  That path reimplements JSON parsing, transcript/PCR
derivation, policy appraisal, and mutation generation without importing the
Python adapter, compares all 104 baseline and 64 mutation outcomes, and checks
its own nested `results/SHA256SUMS`.

Requirements: `swtpm` and `tpm2-tools` 5.x.

Claim boundary: these are native TPM2 quotes from eight fresh **software-TPM**
roots on one x86_64 host.  They are not hardware-rooted evidence, manufacturer
AK certification, remote appraisal of a deployed runtime, trusted time, or an
independent-host reproduction.
