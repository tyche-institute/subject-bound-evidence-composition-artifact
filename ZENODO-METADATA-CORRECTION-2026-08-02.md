# Draft deposit-metadata correction

Date: 2026-08-02

Public release `v0.2.0-rc4` retained a draft Zenodo metadata file whose
`version` still read `0.2.0-rc2` and whose `publication_date` read
`2026-07-30`. No deposit or DOI was created from that draft, but the metadata
was stale.

This release updates the draft to the current release version and date. The
presence of a metadata draft does not assert a Zenodo record, DOI, immutable
deposit or completed registration. `_status` must be removed only in an
authorized deposit workflow that records the exact uploaded archive digest.
