"""Logarithmic and adoption normalization functions."""

from __future__ import annotations

import math
from typing import Any
from packsafe.scoring.normalization.base import clamp


def normalize_log_positive(x: float, scale: float = 10.0) -> float:
    """For positive metrics with logarithmic scaling:

    x <= 0 -> 0.0
    x > 0  -> min(1.0, ln(1 + x) / ln(1 + scale))
    """
    if scale <= 0:
        raise ValueError("Logarithmic scale must be > 0.")
    val = max(0.0, float(x))
    return clamp(math.log1p(val) / math.log1p(scale))


def normalize_adoption(x: float, scale: float = 14.0) -> float:
    """Saturating adoption normalization preventing astronomical numbers from overwhelming:

    1.0 - exp(-ln(1 + x) / scale)
    """
    if scale <= 0:
        raise ValueError("Adoption scale must be > 0.")
    val = max(0.0, float(x))
    return clamp(1.0 - math.exp(-math.log1p(val) / scale))


class LogPositiveNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        scale = float(params.get("scale", 10.0))
        return normalize_log_positive(val, scale)


class AdoptionNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        scale = float(params.get("scale", 14.0))
        return normalize_adoption(val, scale)
