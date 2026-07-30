# Live revocation-service race results

- Executed cases: **276**
- Same-barrier trials: **64 per profile**
- TTL cache: **50 ms**; forced-expiry delay: **75 ms**
- Signed traces verified: **276/276**
- Persisted signed responses: **890**
- Safety errors (false allow / false deny):
  - `atomic_guard`: **0 / 0**
  - `double_read`: **31 / 0**
  - `single_read`: **39 / 0**
  - `ttl_cache`: **31 / 0**
- Boundary: live local HTTP concurrency; not multi-host or a performance claim.
