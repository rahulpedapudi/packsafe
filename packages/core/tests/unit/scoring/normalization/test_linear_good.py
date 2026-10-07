import pytest
from packages.core.scoring.normalization.linear import normalize_linear_good, LinearGoodNormalizer

class TestLinearGood:
    def test_linear_good_zero(self):
        """LG-NORM-001: Zero good value"""
        result = normalize_linear_good(0.0, bad=0.0, good=10.0)
        assert result == 0.0

    def test_linear_good_very_small(self):
        """LG-NORM-002: Very small good value"""
        result = normalize_linear_good(0.1, bad=0.0, good=10.0)
        assert 0.0 < result < 1.0

    def test_linear_good_low(self):
        """LG-NORM-003: Low good value"""
        result = normalize_linear_good(2.0, bad=0.0, good=10.0)
        assert result == 0.2

    def test_linear_good_middle(self):
        """LG-NORM-004: Middle good value"""
        result = normalize_linear_good(5.0, bad=0.0, good=10.0)
        assert result == 0.5

    def test_linear_good_high(self):
        """LG-NORM-005: High good value"""
        result = normalize_linear_good(8.0, bad=0.0, good=10.0)
        assert result == 0.8

    def test_linear_good_maximum(self):
        """LG-NORM-006: Maximum configured good value"""
        result = normalize_linear_good(10.0, bad=0.0, good=10.0)
        assert result == 1.0

    def test_linear_good_above_maximum(self):
        """LG-NORM-007: Value above configured maximum"""
        result = normalize_linear_good(15.0, bad=0.0, good=10.0)
        assert result == 1.0
