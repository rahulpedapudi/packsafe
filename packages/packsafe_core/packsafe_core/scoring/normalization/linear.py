"""Linear normalization functions."""

from __future__ import annotations

from typing import Any

from .base import clamp


def normalize_linear_bad(x: float, good: float = 0.0, bad: float = 1.0) -> float:
    """For negative metrics where lower raw value is better.

    x <= good -> 1.0 (safest)
    x >= bad  -> 0.0 (worst)
    """
    if bad == good:
        return 1.0 if x <= good else 0.0
    if x <= good:
        return 1.0
    if x >= bad:
        return 0.0
    return clamp(1.0 - ((x - good) / (bad - good)))


def normalize_linear_good(x: float, bad: float = 0.0, good: float = 1.0) -> float:
    """For positive metrics where higher raw value is better.

    x <= bad  -> 0.0 (worst)
    x >= good -> 1.0 (safest)
    """
    if good == bad:
        return 1.0 if x >= good else 0.0
    if x <= bad:
        return 0.0
    if x >= good:
        return 1.0
    return clamp((x - bad) / (good - bad))


class LinearBadNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        good = float(params.get("good", 0.0))
        bad = float(params.get("bad", 1.0))
        return normalize_linear_bad(val, good, bad)


class LinearGoodNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        val = float(value) if value is not None else 0.0
        bad = float(params.get("bad", 0.0))
        good = float(params.get("good", 1.0))
        return normalize_linear_good(val, bad, good)
