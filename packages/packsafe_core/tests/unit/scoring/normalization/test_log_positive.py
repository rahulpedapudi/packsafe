from packsafe_core.scoring.normalization.logarithmic import (
    LogPositiveNormalizer,
    normalize_log_positive,
)


class TestLogPositive:
    def test_log_positive_zero(self):
        """LOG-NORM-001: Zero input"""
        result = normalize_log_positive(0.0, scale=10.0)
        assert result == 0.0

    def test_log_positive_one(self):
        """LOG-NORM-002: Input value 1"""
        result = normalize_log_positive(1.0, scale=10.0)
        assert 0.0 < result < 1.0

    def test_log_positive_very_small(self):
        """LOG-NORM-003: Very small positive value"""
        result = normalize_log_positive(0.1, scale=10.0)
        assert 0.0 < result < 1.0
        assert result < normalize_log_positive(1.0, scale=10.0)

    def test_log_positive_small(self):
        """LOG-NORM-004: Small positive value"""
        result = normalize_log_positive(5.0, scale=10.0)
        assert 0.0 < result < 1.0
        assert result > normalize_log_positive(1.0, scale=10.0)

    def test_log_positive_medium(self):
        """LOG-NORM-005: Medium value"""
        result = normalize_log_positive(10.0, scale=10.0)
        assert result == 1.0

    def test_log_positive_large(self):
        """LOG-NORM-006: Large value"""
        result = normalize_log_positive(100.0, scale=10.0)
        assert result == 1.0

    def test_log_positive_very_large(self):
        """LOG-NORM-007: Very large value"""
        result = normalize_log_positive(1000000.0, scale=10.0)
        assert result == 1.0

    def test_log_positive_missing(self):
        """LOG-NORM-008: None/invalid input"""
        normalizer = LogPositiveNormalizer()
        result = normalizer.normalize(None, {"scale": 10.0})
        assert result == 0.0
