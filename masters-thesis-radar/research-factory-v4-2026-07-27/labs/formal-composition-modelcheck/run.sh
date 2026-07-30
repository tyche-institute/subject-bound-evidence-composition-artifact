#!/usr/bin/env bash
set -euo pipefail

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$here"

classes=(
  CompositionModelCheck.class
  'CompositionModelCheck$BindingProfile.class'
  'CompositionModelCheck$ScheduleResult.class'
)
rm -f "${classes[@]}"
trap 'rm -f "${classes[@]}"' EXIT
javac -encoding UTF-8 CompositionModelCheck.java
java CompositionModelCheck results.json
python3 -m json.tool results.json >/dev/null
sha256sum CompositionModelCheck.java run.sh results.json README.md > SHA256SUMS
sha256sum -c SHA256SUMS
