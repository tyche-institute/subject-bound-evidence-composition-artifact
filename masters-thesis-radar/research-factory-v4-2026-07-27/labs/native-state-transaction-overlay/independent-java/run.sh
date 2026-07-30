#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p results/classes
javac -encoding UTF-8 -d results/classes IndependentVerifier.java
java -cp results/classes IndependentVerifier \
  --overlay ../native-state-overlay.json \
  --policy ../appraisal-policy.json \
  --primary-verdicts ../results/verdicts.jsonl \
  --primary-mutations ../results/mutation-verdicts.jsonl \
  --output results

(
  cd results
  sha256sum \
    ../README.md \
    ../IndependentVerifier.java \
    ../run.sh \
    classes/*.class \
    verdicts.jsonl \
    mutation-verdicts.jsonl \
    assertions.json \
    summary.json \
    run-metadata.json \
    > SHA256SUMS
  sha256sum -c SHA256SUMS
)
