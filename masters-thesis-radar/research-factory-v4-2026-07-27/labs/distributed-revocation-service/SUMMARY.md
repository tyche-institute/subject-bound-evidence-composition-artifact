# Process-isolated revocation results

- Cases: **372**
- Profile outcomes: **{'atomic_guard': {'cases': 93, 'false_allows': 0, 'false_denies': 0, 'duplicate_effects': 0}, 'double_read': {'cases': 93, 'false_allows': 63, 'false_denies': 0, 'duplicate_effects': 0}, 'single_read': {'cases': 93, 'false_allows': 67, 'false_denies': 0, 'duplicate_effects': 0}, 'ttl_cache': {'cases': 93, 'false_allows': 66, 'false_denies': 0, 'duplicate_effects': 0}}**
- Durable events/effects: **1478/301**
- Disconnect/restart recoveries: **96/96**
- Duplicate effects: **0**
- Distinct service PIDs: **34**
- Atomic-guard invariant: **PASS**
- Overall: **PASS**

Boundary: one local OS instance reporting x86_64; separate status/effect services and client contender processes over loopback TCP with durable SQLite linearization, signed responses, disconnect/retry and service restart; not multi-host or deployment evidence.
