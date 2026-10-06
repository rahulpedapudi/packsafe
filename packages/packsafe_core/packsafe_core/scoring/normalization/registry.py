"""Registry for normalizers."""

from __future__ import annotations

from .base import Normalizer
from .boolean import BooleanBadNormalizer, BooleanGoodNormalizer
from .exponential import ExponentialBadNormalizer
from .linear import LinearBadNormalizer, LinearGoodNormalizer
from .logarithmic import AdoptionNormalizer, LogPositiveNormalizer
from .recency import RecencyNormalizer
from .sigmoid import SigmoidNormalizer


class NormalizerRegistry:
    """Registry maintaining instances of Normalizers."""

    def __init__(self) -> None:
        self._normalizers: dict[str, Normalizer] = {}
        self._register_defaults()

    def _register_defaults(self) -> None:
        self.register("linear_bad", LinearBadNormalizer())
        self.register("linear_good", LinearGoodNormalizer())
        self.register("exponential_bad", ExponentialBadNormalizer())
        self.register("log_positive", LogPositiveNormalizer())
        self.register("adoption", AdoptionNormalizer())
        self.register("recency", RecencyNormalizer())
        self.register("sigmoid", SigmoidNormalizer())
        self.register("boolean_bad", BooleanBadNormalizer())
        self.register("boolean_good", BooleanGoodNormalizer())

    def register(self, name: str, normalizer: Normalizer) -> None:
        self._normalizers[name] = normalizer

    def get(self, name: str) -> Normalizer:
        if name not in self._normalizers:
            raise KeyError(f"Normalizer '{name}' not found in registry.")
        return self._normalizers[name]

    def has(self, name: str) -> bool:
        return name in self._normalizers


_default_registry: NormalizerRegistry | None = None


def get_default_normalizer_registry() -> NormalizerRegistry:
    global _default_registry
    if _default_registry is None:
        _default_registry = NormalizerRegistry()
    return _default_registry
