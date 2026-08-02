#!/usr/bin/env python3
"""Execute the frozen Python mutation evaluator against the multifault packet."""

from __future__ import annotations

from pathlib import Path


HERE = Path(__file__).resolve().parent
SOURCE = (
    HERE.parent / "thesis-v4-mutation-tests/evaluate_mutation_corpus.py"
).read_text(encoding="utf-8")
SOURCE = SOURCE.replace(
    'HERE = Path(__file__).resolve().parent', f"HERE = Path({str(HERE)!r})"
)
SOURCE = SOURCE.replace(
    '"mutation-packet.json"', '"multifault-packet.json"'
)
SOURCE = SOURCE.replace("mutation-python-v1", "multifault-python-v1")
exec(compile(SOURCE, "<frozen-python-mutation-evaluator>", "exec"), {})
