# JAIR r7 build and submission-metadata audit

Date: 2026-07-30  
Status: **PASS — submission-candidate PDF; no journal submission sent**

## Build

- format: JAIR 2025+ `jair` class, `manuscript,screen,review`;
- page size: US Letter;
- pages: 51;
- deterministic build controls: `SOURCE_DATE_EPOCH=1785110400`,
  `FORCE_SOURCE_DATE=1`, `TZ=UTC`, `LC_ALL=C.UTF-8`;
- two complete consecutive `latexmk -gg` builds: byte-identical;
- overfull boxes: zero;
- undefined references in final log: zero;
- figure descriptions: A--N present, including the r7 execution-domain/vTPM
  matrix.

## Publication metadata

The review PDF suppresses the production-only JAIR reference strip and uses
the neutral footer `Submitted manuscript, July 2026.` It contains no invented
Associate Editor, volume, article number, DOI, or publication date.

This is intentional. JAIR assigns an Associate Editor after a submission is
processed, and its Production Editor supplies volume and article numbers
after acceptance/formatting approval. The official current requirements were
checked on 2026-07-30:

- <https://www.jair.org/index.php/jair/about/submissions>
- <https://www.jair.org/index.php/jair/formatting>
- <https://www.jair.org/index.php/jair/authorinstrs>

The PDF includes the required completed reproducibility checklist and a
structured abstract.

## SHA-256

```text
main.tex
  5679ed06602d7765e4b64ec659a4b8c8ce83e0caabcf270006eae2b16fcd5f7f
body.tex
  a398093521c7cff46ecbd76ed67d2aeccb43f0e35a10074e5edcb48ea64a1e8a
references.bib
  22a3122ea3ff727223fc36fa34bf3af7fa6a0a11e35252fb5d85a7b3744d5273
submission-candidate PDF
  309a401b27410592188bd9bc60d8a1aafea39b4c27b8d3ba1aafe38f3ef2317e
figure N PDF
  8817d738495e7cdd86fb78c9de323263ca5ffddd542603a0e867e4f7a318018b
```

## Evidence boundary

The abstract and conclusion claim an executable result over author-defined
synthetic fixtures. They do not claim deployed-system rates, physical-host
identity, hardware-rooted attestation, human-label agreement, external
semantic consensus, or interoperability. The identified zeus2 observation is
reported as a distinct Hyper-V VM/OS plus Microsoft vTPM:

- four-lane semantic contract: 20/20;
- live transaction-bound quote verification: 104/104;
- predeclared native mutation rejection: 64/64;
- new transient handles after the run: 0;
- persistent handles created: 0;
- public private/context files: 0.
