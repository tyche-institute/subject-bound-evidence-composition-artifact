# Live concurrent revocation-service races

This lab turns the paper's scheduled revocation traces into concurrent HTTP
operations against an in-process status service.  The service linearizes
status reads, revocations, guarded commits, and unguarded effects under one
lock, and signs every status-bearing response with Ed25519.  Client and server
interact only over an ephemeral `127.0.0.1` TCP port.

Four profiles are compared:

- `atomic_guard`: the status service atomically checks revocation and commits
  the effect;
- `double_read`: a fresh status is read immediately before a separate effect;
- `single_read`: appraisal status is reused at effect time;
- `ttl_cache`: a status is reused only while a 50 ms client-side TTL remains
  valid; an expired entry triggers a signed status refresh.

The five deterministic placements are revoke-before-appraisal,
revoke-between-appraisal-and-commit, revoke after a forced 75 ms cache expiry,
revoke-after-final-read, and revoke-after-commit. The forced-expiry case
distinguishes `ttl_cache` from
`single_read`: the TTL profile refreshes and denies while the single-read
profile reuses appraisal state and false-allows.  A further 64 trials per
profile release revocation and commit clients from the same barrier.  The
service's linearization indices,
not client wall-clock guesses, determine whether an accepted effect was a
false allow.

`results.json` retains the raw Ed25519 public key and, for every server
response, the exact signed payload plus its base64 signature.  A reviewer can
therefore reverify the stored traces without rerunning the service.  Measured
round-trip times and client-side verification flags are deliberately outside
the signed payload.

## Run

```sh
python3 run_live_races.py
python3 verify_saved_results.py
sha256sum -c SHA256SUMS
```

This is a live local concurrency experiment, not an Internet-scale service,
multi-host replication, standards-conformance test, or latency benchmark.
The signing key is deterministic test material.
