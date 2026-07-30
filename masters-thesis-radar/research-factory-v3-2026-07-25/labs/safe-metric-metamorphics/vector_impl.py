"""NumPy implementation independent from the pure-Python loop path."""

from __future__ import annotations

import numpy as np


def tensor_values(
    a: list[float], b: list[float], c: list[float]
) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    return np.meshgrid(np.asarray(a), np.asarray(b), np.asarray(c), indexing="ij")


def arithmetic_tensor(a: list[float], b: list[float], c: list[float]) -> float:
    x, y, z = tensor_values(a, b, c)
    return float(np.mean((x + y + z) / 3.0))


def geometric_tensor(a: list[float], b: list[float], c: list[float]) -> float:
    x, y, z = tensor_values(a, b, c)
    return float(np.mean(np.cbrt(x * y * z)))


def rms_tensor(a: list[float], b: list[float], c: list[float]) -> float:
    x, y, z = tensor_values(a, b, c)
    return float(np.mean(np.sqrt((x * x + y * y + z * z) / 3.0)))


def topsis_dynamic(alternatives: list[list[float]], weights: list[float]) -> list[float]:
    matrix = np.asarray(alternatives, dtype=float)
    w = np.asarray(weights, dtype=float)
    normalized = matrix / np.sqrt(np.sum(matrix * matrix, axis=0)) * w
    ideal = np.max(normalized, axis=0)
    anti = np.min(normalized, axis=0)
    d_ideal = np.sqrt(np.sum((normalized - ideal) ** 2, axis=1))
    d_anti = np.sqrt(np.sum((normalized - anti) ** 2, axis=1))
    return (d_anti / (d_ideal + d_anti)).tolist()


def topsis_fixed(alternatives: list[list[float]], weights: list[float]) -> list[float]:
    matrix = np.asarray(alternatives, dtype=float)
    w = np.asarray(weights, dtype=float)
    weighted = matrix * w
    ideal = w
    anti = np.zeros_like(w)
    d_ideal = np.sqrt(np.sum((weighted - ideal) ** 2, axis=1))
    d_anti = np.sqrt(np.sum((weighted - anti) ** 2, axis=1))
    return (d_anti / (d_ideal + d_anti)).tolist()


def ranking(scores: list[float]) -> list[int]:
    return np.argsort(-np.asarray(scores)).tolist()
