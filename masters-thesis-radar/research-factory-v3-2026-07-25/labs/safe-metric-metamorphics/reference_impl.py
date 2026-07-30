"""Pure-Python reference implementation of SAFE integration operators."""

from __future__ import annotations

import math
from typing import Iterable, Sequence


def arithmetic_tensor(a: Sequence[float], b: Sequence[float], c: Sequence[float]) -> float:
    values = [(x + y + z) / 3.0 for x in a for y in b for z in c]
    return sum(values) / len(values)


def geometric_tensor(a: Sequence[float], b: Sequence[float], c: Sequence[float]) -> float:
    values = [(x * y * z) ** (1.0 / 3.0) for x in a for y in b for z in c]
    return sum(values) / len(values)


def rms_tensor(a: Sequence[float], b: Sequence[float], c: Sequence[float]) -> float:
    values = [
        math.sqrt((x * x + y * y + z * z) / 3.0)
        for x in a
        for y in b
        for z in c
    ]
    return sum(values) / len(values)


def arithmetic_factorized(
    a: Sequence[float], b: Sequence[float], c: Sequence[float]
) -> float:
    return (sum(a) / len(a) + sum(b) / len(b) + sum(c) / len(c)) / 3.0


def geometric_factorized(
    a: Sequence[float], b: Sequence[float], c: Sequence[float]
) -> float:
    means = [sum(x ** (1.0 / 3.0) for x in vector) / len(vector) for vector in (a, b, c)]
    return means[0] * means[1] * means[2]


def diagonal(
    a: Sequence[float], b: Sequence[float], c: Sequence[float], operator: str
) -> float:
    count = min(len(a), len(b), len(c))
    values = []
    for index in range(count):
        x, y, z = a[index], b[index], c[index]
        if operator == "arithmetic":
            values.append((x + y + z) / 3.0)
        elif operator == "geometric":
            values.append((x * y * z) ** (1.0 / 3.0))
        elif operator == "rms":
            values.append(math.sqrt((x * x + y * y + z * z) / 3.0))
        else:
            raise ValueError(operator)
    return sum(values) / len(values)


def topsis_dynamic(
    alternatives: Sequence[Sequence[float]], weights: Sequence[float]
) -> list[float]:
    columns = list(zip(*alternatives))
    denominators = [math.sqrt(sum(value * value for value in column)) for column in columns]
    normalized = [
        [row[j] / denominators[j] * weights[j] for j in range(len(weights))]
        for row in alternatives
    ]
    ideal = [max(row[j] for row in normalized) for j in range(len(weights))]
    anti = [min(row[j] for row in normalized) for j in range(len(weights))]
    scores = []
    for row in normalized:
        d_ideal = math.sqrt(sum((row[j] - ideal[j]) ** 2 for j in range(len(weights))))
        d_anti = math.sqrt(sum((row[j] - anti[j]) ** 2 for j in range(len(weights))))
        scores.append(d_anti / (d_ideal + d_anti))
    return scores


def topsis_fixed(
    alternatives: Sequence[Sequence[float]], weights: Sequence[float]
) -> list[float]:
    weighted = [
        [row[j] * weights[j] for j in range(len(weights))]
        for row in alternatives
    ]
    ideal = list(weights)
    anti = [0.0 for _ in weights]
    scores = []
    for row in weighted:
        d_ideal = math.sqrt(sum((row[j] - ideal[j]) ** 2 for j in range(len(weights))))
        d_anti = math.sqrt(sum((row[j] - anti[j]) ** 2 for j in range(len(weights))))
        scores.append(d_anti / (d_ideal + d_anti))
    return scores


def ranking(scores: Iterable[float]) -> list[int]:
    values = list(scores)
    return sorted(range(len(values)), key=lambda index: -values[index])
