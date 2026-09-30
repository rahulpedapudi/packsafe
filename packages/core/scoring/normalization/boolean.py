"""Boolean normalization functions."""

from __future__ import annotations

from typing import Any


def normalize_boolean_bad(val: Any) -> float:
    """If bad condition is True (e.g. archived=True, malware=True), return 0.0.

    If False, return 1.0 (safe).
    """
    if val is None:
        return 1.0
    if isinstance(val, str):
        return 0.0 if val.lower() in ("true", "1", "yes") else 1.0
    return 0.0 if bool(val) else 1.0


def normalize_boolean_good(val: Any) -> float:
    """If good condition is True, return 1.0.

    If False, return 0.0.
    """
    if val is None:
        return 0.0
    if isinstance(val, str):
        return 1.0 if val.lower() in ("true", "1", "yes") else 0.0
    return 1.0 if bool(val) else 0.0


class BooleanBadNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        return normalize_boolean_bad(value)


class BooleanGoodNormalizer:
    def normalize(self, value: Any, params: dict[str, Any]) -> float:
        return normalize_boolean_good(value)
