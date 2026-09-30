"""Base protocol and common clamping for normalizers."""

from __future__ import annotations

from typing import Any, Protocol


def clamp(val: float, min_val: float = 0.0, max_val: float = 1.0) -> float:
    """Clamps a numeric value to the interval [min_val, max_val]."""
    if val < min_val:
        return min_val
    if val > max_val:
        return max_val
    return val


class Normalizer(Protocol):
    """Protocol for normalization strategies."""

    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        """Transforms a raw metric value into a normalized safety score in [0.0, 1.0]."""
        ...
