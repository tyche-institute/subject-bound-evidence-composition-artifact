# Process-isolated durable revocation races

This laboratory extends the r4 loopback experiment from one Python process to
separate status and effect services, each with its own PID and TCP listener.
They coordinate only through a durable SQLite transaction log.  Revoker and
commit contenders are separate client processes in simultaneous trials.

The effect service implements both:

- `atomic_guard`: status check and idempotent effect insertion in one
  `BEGIN IMMEDIATE` transaction;
- weak commits used by `double_read`, `single_read`, and `ttl_cache`, where a
  prior signed status observation is separated from the effect transaction.

The run preserves the five scheduled placements and 64 same-release trials per
profile.  It additionally injects client disconnect after the commit request
but before reading the response, bounded retry, and effect-service
kill/restart.  A unique idempotency key lets the durable log distinguish a
recovered ambiguous client outcome from a duplicate external effect.

Run:

```sh
./run.sh
sha256sum -c SHA256SUMS
```

The primary safety oracle is the status recorded in the effect transaction's
linearization event, not client wall-clock order.  Zero false allows for the
atomic guard is an executable invariant check, not a population-rate estimate.
Randomized same-release counts are schedule-exposure observations only.

Claim boundary: one local operating-system instance, loopback TCP, separate OS
processes, durable transactional linearization, signed responses,
disconnect/retry and restart injection. The recorded architecture is an
environment label, not physical-host attestation. This is not multi-host
evidence, distributed consensus, independent-clock validation, Internet-scale
testing, or a performance result.
