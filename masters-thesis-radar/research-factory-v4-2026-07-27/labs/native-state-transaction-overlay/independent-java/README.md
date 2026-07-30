# Independent compiled verifier for the native-state overlay

This directory contains a second implementation of the native-state appraisal
path.  It is intentionally separate from the Python implementation:

- it is compiled from `IndependentVerifier.java` with OpenJDK 21;
- it does not import, execute, or parse `native_state_adapter.py`;
- it does not read the structural corpus or any source `status` field;
- it implements its own JSON parser, transcript construction, SHA-256 and PCR
  derivation, policy checks, mutation generator, and result serializer using
  only the Java standard library;
- native TPM quote/signature/PCR checking is delegated directly to the
  independently packaged `tpm2_checkquote` executable.

The verifier appraises all 104 frozen vectors, independently regenerates the
same eight mutations for one representative of each of the eight software-TPM
roots (64 cases), and compares only the resulting state class and gate with the
primary path after its own appraisal has completed.  It additionally pins each
vector's AK public key to the root metadata and checks the profile, PCR index,
source-corpus digest, challenge, and subject capsule before accepting native
evidence.

Run:

```sh
./run.sh
```

Expected gates:

- 104/104 baseline state classes match the sealed author-designed oracle;
- 104/104 baseline state classes and gates agree with the primary verifier;
- 64/64 mutations fail closed as `CRYPTOGRAPHIC_FAILURE`;
- 64/64 mutation state classes and gates agree with the primary verifier.

Claim boundary: agreement between two implementations strengthens evidence for
the executable specification and catches transcription/implementation drift.
It does not make the author-designed labels external ground truth.  All quotes
still originate from eight fresh `swtpm` roots on one x86_64 host; the run does
not establish hardware-rooted identity, manufacturer-certified AKs, trusted
time, remote appraisal of a deployed runtime, or independent-host
reproduction.
