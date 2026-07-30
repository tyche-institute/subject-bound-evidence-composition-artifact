# Correction to a legacy claim-boundary field

The four preserved `durable-revocation.log` files contain a generated field
beginning `same physical ... host`. That wording is not supported by the
GitHub-hosted evidence and is not an evidentiary assertion of this release.

What the records establish is execution inside one job-VM operating-system
instance reporting `x86_64` or `aarch64`, with separate processes communicating
over loopback. GitHub runner metadata does not identify or attest the
underlying physical machine. The adjacent `CLAIM-BOUNDARY.txt` files and both
comparison records state the intended boundary.

The raw logs are preserved byte-for-byte for auditability. The public replay
source replaces the legacy wording with `one local OS instance reporting
<architecture>`; no fixture, event rule, oracle, expected count, or safety
assertion is changed by that correction.
