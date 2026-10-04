"""Exponential normalization functions."""

from __future__ import annotations

import math
from typing import Any

from .base import clamp


def normalize_exponential_bad(x: float, scale: float = 1.0) -> float:
    """For negative metrics using exponential decay where each additional risk diminishes:

    x = 0 -> 1.0 (safest)
    x > 0 -> exp(-x / scale)
    """
    if scale <= 0:
        raise ValueError("Exponential scale must be > 0.")
    val = max(0.0, float(x))
    return clamp(math.exp(-val / scale))


class ExponentialBadNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        scale = float(params.get("scale", 1.0))
        return normalize_exponential_bad(val, scale)
