# Blind-safe public release and hostile-replay sequence

Version: 1.0-rc1
Status: prepared; public deposit intentionally held pending response seals

## Release identity

- title: *Subject-Bound Evidence Composition for Delegated AI Actions*;
- creator: Anton Sokolov;
- affiliation: Tyche Institute, Tallinn, Estonia;
- ORCID: 0000-0003-2452-7096;
- repository:
  `https://github.com/tyche-institute/subject-bound-evidence-composition`;
- planned version: `1.0.0`;
- code/schema licence: Apache-2.0;
- original text/figure/corpus/data licence: CC-BY-4.0;
- DOI: pending immutable deposit.

## Two-phase publication

### Phase A — blind private evidence collection

Keep the runner repository private. Dispatch only the neutral annotator
archives. Seal responses before exposing author labels or mappings. Keep
direct identifiers in a separate private administration ledger.

### Phase B — immutable public evidence release

After response seals:

1. run the deterministic sanitizer from an explicit allowlist;
2. fail on secrets, absolute local paths, direct human identifiers, mnemonic
   label leakage, unresolved licence holds, compiled debris, or undeclared
   files;
3. generate the source/data archive, SBOM, RO-Crate, CFF, CodeMeta, checksums,
   provenance statement, and claim/evidence/ceiling table;
4. create an immutable version tag and repository release from the exact
   sanitized commit;
5. deposit the identical archive in a DOI-minting repository;
6. download it again and verify that the DOI bytes have the recorded SHA-256;
7. freeze the DOI, tag, commit, archive digest, and metadata digest together.

## Outside hostile replay

The operator must not have built the package and receives only:

- the DOI landing page;
- the published checksums;
- the public hostile-replay protocol.

The first attempt is sealed before author contact. In addition to an
unmodified replay, the operator must verify rejection of:

1. one removed archive member;
2. one modified deterministic result;
3. one substituted policy anchor;
4. one changed signed-evidence payload;
5. one operator-chosen mutation not disclosed in advance.

Passing assertions:

```text
clean_first_attempt in {PASS, PASS_WITH_ENV_DIFF}
archive_member_removal == INTEGRITY_FAIL
result_substitution == INTEGRITY_FAIL
policy_anchor_substitution == INTEGRITY_FAIL
signed_payload_substitution in {INTEGRITY_FAIL, VERIFICATION_DENY}
operator_chosen_mutation != FALSE_ALLOW
doi_archive_sha256 == published_archive_sha256
```

No author-assisted repaired run can overwrite a failed first-attempt record.
