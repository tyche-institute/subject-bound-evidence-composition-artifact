# Independent thesis-v4 evaluator comparison

Date: 2026-07-27

This is a cross-implementation comparison against sealed author-written programme-internal labels. It is stronger than same-code reruns but remains internal designed-corpus evidence, not external ground truth or deployed-system validity.

- Verdict matches: 90/90.
- First-gate matches: 90/90.
- Per-layer typed-result matches: 450/450.
- Fully exact transactions: 90/90.
- Transactions with any mismatch: 0.

The JavaScript implementation used only the labeller-facing packet before its result was hashed in `PRECOMPARISON-FREEZE.json`. It uses Node's Ed25519 verifier, an independently written canonical JSON serializer, authority ladder and bootstrap implementation.
