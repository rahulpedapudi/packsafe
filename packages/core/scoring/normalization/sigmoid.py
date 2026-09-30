"""Sigmoid normalization function."""

from __future__ import annotations

import math
from typing import Any
from packsafe.scoring.normalization.base import clamp


def normalize_sigmoid(x: float, midpoint: float = 0.0, slope: float = 1.0) -> float:
    """Logistic sigmoid function for positive direction metrics (e.g. growth).

    Returns values in (0.0, 1.0).
    """
    val = float(x)
    try:
        exp_val = math.exp(-slope * (val - midpoint))
        return clamp(1.0 / (1.0 + exp_val))
    except OverflowError:
        return 0.0 if (-slope * (val - midpoint)) > 0 else 1.0


class SigmoidNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        midpoint = float(params.get("midpoint", 0.0))
        slope = float(params.get("slope", 1.0))
        return normalize_sigmoid(val, midpoint, slope)
