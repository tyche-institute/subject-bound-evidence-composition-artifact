# Containerized durable-revocation replay

This lane separates one status service, two interchangeable effect-service
instances, a deterministic response-fault proxy, and the experiment runner
into distinct read-only containers on an internal Docker bridge. The status
and effect services share a named-volume SQLite WAL store solely to establish
durable per-transaction linearization.

The experiment executes:

- scheduled active and revoked guarded decisions;
- a scheduled false allow by a prior-read unguarded profile;
- 64 same-release revoke/commit races for each profile;
- request loss before forwarding;
- response loss after durable commit;
- retry through the second effect instance;
- idempotent replay of both an allowed and a denied decision.

Every observable service response is Ed25519-signed and saved. A separate
saved-result verifier checks those signatures, reconstructs the false-allow
predicate from the recorded effect-time status, verifies unique decision/effect
keys and a contiguous event sequence, and checks that the signed health records
came from three distinct service container hostnames. The verifier imports the
service's canonical JSON serializer for signature preimages; serialization is
therefore shared, while the safety, idempotency, ordering, database, and
hostname assertions are reconstructed separately.

Run locally:

```sh
./run.sh
```

The default runtime image is the already-built offline image
`tyche-v4-repro@sha256:e9d09e11129b6b53734d780c21fa90d1d92cf7e5f508357704c5fd34e319a173`.
Set `TYCHE_RUNTIME_IMAGE` only when intentionally testing another image.

## Claim boundary

This is same-physical-host evidence. It establishes live TCP interaction
across OS-isolated containers, an internal bridge, durable transactional
linearization, signed traces, deterministic lost-response injection, and
cross-instance idempotent recovery. All containers still share the host
kernel, CPU, and physical machine. The lane is not multi-host, distributed
consensus, independent-clock, deployed-service, Internet-scale, or performance
evidence. Atomic zero-false-allow is an executable invariant check, not a
population-rate discovery.
