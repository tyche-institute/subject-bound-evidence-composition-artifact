# Native signed authority/effect adapter v0.1

This bounded laboratory replaces the earlier corpus-supplied
`issuer_signature_valid` and `native_evidence_valid` booleans with actual
Ed25519 verification.

The experimental envelope checks:

1. issuer signatures on every delegation;
2. parent digest, principal and role lineage;
3. delegation permission, status, freshness and scope attenuation;
4. terminal action subject, role and scope;
5. effect-receipt signature, terminal issuer, chain digest, time and action.

Eight deterministic fixtures cover one valid path and seven faults: bad
delegation signature, bad effect signature, signed action mismatch, expired
signed edge, correctly signed but wrong lineage, signed scope escalation, and
signed effect-time mismatch.

The fixed private-key seeds are used only inside `build_fixtures.py`; private
keys are not persisted. They are test keys, not production credentials.

## Claim boundary

This is a Tyche experimental profile and real cryptographic verification. It is
not an implementation or conformance result for WAVE, JEDI, A2A, DID, or any
other external protocol or standard.
