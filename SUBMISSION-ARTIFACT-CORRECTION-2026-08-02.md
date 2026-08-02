# Post-submission artifact-availability correction

Date: 2026-08-02

Applies to: JAIR submission 23967, submitted 2026-08-01

Submitted PDF SHA-256: `8336906cc984c578e9d6fcd160dc45a1b92ad0329e9c666e7cffffa316de73da`

## Correction

The submitted manuscript's artifact-availability statement says that the
public `v0.2.0-rc2` release anchored the code, corpora, and evidence used by
the manuscript and that these were unchanged from the manuscript source. The
submission checklist also answered yes to public availability of the source
code required to reproduce the results.

Those statements were too broad. At submission time, `v0.2.0-rc2` did not
contain four companion trees used by the r8 manuscript or the associated
bootstrap-sensitivity companion. They were added to the public artifact in
the post-submission `v0.2.0-rc3` release. This repository version preserves
those additions and this correction.

The post-submission releases improve prospective reproducibility, but do not
make the public artifact complete retroactively as of submission. The exact
submitted PDF is retained unchanged so that its bytes remain auditable.

## Claim boundary

- This note is a public correction, not an editorial amendment or journal
  acceptance.
- It does not assert that JAIR has received or acknowledged the correction.
- The Git tag and GitHub release are movable service objects. Content claims
  should be checked against exact digests; the Software Heritage snapshot is
  the content-addressed archival anchor when one is listed.
- Hosted CI is a fresh execution on GitHub-managed VMs, not an independent
  outside-operator replay, a witnessed second physical host, or hardware-TPM
  evidence.
