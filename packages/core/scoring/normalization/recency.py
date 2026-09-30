"""Recency decay normalization functions."""

from __future__ import annotations

import math
from typing import Any
from packsafe.scoring.normalization.base import clamp


def normalize_recency(days: float, decay_days: float = 365.0) -> float:
    """Calculates recency decay score for days since event:

    days = 0   -> 1.0 (safest / most fresh)
    days = 365 -> exp(-1) ≈ 0.3678
    """
    if decay_days <= 0:
        raise ValueError("Decay days must be > 0.")
    val = max(0.0, float(days))
    return clamp(math.exp(-val / decay_days))


class RecencyNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        decay_days = float(params.get("decay_days", 365.0))
        return normalize_recency(val, decay_days)
