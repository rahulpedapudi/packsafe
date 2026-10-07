import pytest
from packsafe_core.scoring.normalization.linear import (
    LinearBadNormalizer,
    normalize_linear_bad,
)


class TestLinearBad:
    def test_linear_bad_zero(self):
        """LB-NORM-001: Zero bad value"""
        result = normalize_linear_bad(0.0, good=0.0, bad=10.0)
        assert result == 1.0

    def test_linear_bad_very_small(self):
        """LB-NORM-002: Very small bad value"""
        result = normalize_linear_bad(0.1, good=0.0, bad=10.0)
        assert 0.0 < result < 1.0

    def test_linear_bad_low(self):
        """LB-NORM-003: Low bad value"""
        result = normalize_linear_bad(2.0, good=0.0, bad=10.0)
        assert result == 0.8

    def test_linear_bad_middle(self):
        """LB-NORM-004: Middle bad value"""
        result = normalize_linear_bad(5.0, good=0.0, bad=10.0)
        assert result == 0.5

    def test_linear_bad_high(self):
        """LB-NORM-005: High bad value"""
        result = normalize_linear_bad(8.0, good=0.0, bad=10.0)
        assert result == pytest.approx(0.2)

    def test_linear_bad_maximum(self):
        """LB-NORM-006: Maximum configured bad value"""
        result = normalize_linear_bad(10.0, good=0.0, bad=10.0)
        assert result == 0.0

    def test_linear_bad_above_maximum(self):
        """LB-NORM-007: Value above configured maximum"""
        result = normalize_linear_bad(15.0, good=0.0, bad=10.0)
        assert result == 0.0

    def test_linear_bad_missing(self):
        """LB-NORM-008: None/missing bad value"""
        normalizer = LinearBadNormalizer()
        result = normalizer.normalize(None, {"good": 0.0, "bad": 10.0})
        assert result == 1.0
