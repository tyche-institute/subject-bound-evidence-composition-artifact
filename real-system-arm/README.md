# sbec-oidc-composition-arm

Real-system arm for *Subject-Bound Evidence Composition for Delegated Authorization*.
A GitHub Actions workflow requests a **real OIDC token** from GitHub's production identity
provider and evaluates the paper's non-compensable decision rule `Allow = P & E & S & A & M & B`
over it, for two matched policies. It shows that a token whose issuer, freshness, subject and
authority are each valid is still **denied at `binding.environment`** when the policy requires a
subject coordinate (`environment=production`) the token does not carry — a real instance of the
paper's composition boundary on a production authorization system. The signed token itself is never
printed; only its non-secret identity claims.
