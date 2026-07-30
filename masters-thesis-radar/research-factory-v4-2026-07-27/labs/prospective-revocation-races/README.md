# Prospective signed-revocation races

This laboratory models credential-status races between appraisal and effect
commit.  It is a deterministic event-sequence benchmark, not a live
concurrency experiment.

Each case contains:

- an Ed25519-signed authority credential;
- an Ed25519-signed status snapshot at appraisal;
- an Ed25519-signed status snapshot at commit, or an explicit absence;
- fixed appraisal and commit times;
- an author-written expected verdict and first rejecting gate.

The strict profile verifies both signatures, the credential validity window,
snapshot binding and freshness, monotone status sequence numbers, active
status at appraisal, and active status again at commit.  Revocation is
effective at the instant represented by a signed snapshot; a revocation
snapshot whose `issued_at` equals the commit time therefore denies.

Three deliberately incomplete baselines expose the value of the checks:

1. `appraisal_only` performs no commit-time status check;
2. `commit_fail_open` treats a missing commit snapshot as active;
3. `timestamp_only` ignores monotone status sequence numbers.

Python and JavaScript implementations independently verify the same signed
objects.  `compare.py` compares both implementations with the frozen
author-written expectations and with each other.

Run:

```bash
./run.sh
```

## Claim boundary

This is an internal Tyche experimental credential/status profile with real
Ed25519 verification over designed scheduled event sequences.  It is not a
WAVE, JEDI, OAuth, DID, status-list, or other standards-conformance result;
it is not an experiment over a live revocation service; and its expected
labels are not external ground truth.
