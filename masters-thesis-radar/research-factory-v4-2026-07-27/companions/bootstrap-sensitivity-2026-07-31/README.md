# Bootstrap seed/replicate sensitivity sweep (companion analysis)

Recomputes the SAFE measurement fixtures' one-sided percentile lower
confidence bounds under five seeds (11, 23, 47, 101, 977) x three
replicate counts (2,000 / 5,000 / 10,000), using the frozen laboratory's
exact bootstrap implementation, and re-checks the sampling-overlap
joint-vs-independent boundary comparison on the same grid. The frozen
laboratory's published values (seeds 101/102/103, 5,000 replicates) are
unchanged; this sweep addresses the previously stated limitation that no
sensitivity sweep had been run.

Result: every fixture's confidence outcome is unchanged at all 15 grid
points (per-fixture LCB spread <= 0.0017); the overlap fixture's designed
decision flip at threshold 0.737 persists at 15/15 grid points. The
percentile method's small-sample bias at n = 18 remains a stated
limitation (no BCa interval).

Run: python3 bootstrap_sensitivity_sweep.py <corpus.json> sweep-results.json
