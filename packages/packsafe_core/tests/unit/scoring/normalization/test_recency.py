from packsafe_core.scoring.normalization.recency import (
    RecencyNormalizer,
    normalize_recency,
)


class TestRecency:
    def test_recency_zero(self):
        """REC-NORM-001: Zero days"""
        result = normalize_recency(0.0, decay_days=365.0)
        assert result == 1.0

    def test_recency_very_recent(self):
        """REC-NORM-002: Very recent release"""
        result = normalize_recency(1.0, decay_days=365.0)
        assert 0.0 < result < 1.0
        assert result < 1.0

    def test_recency_medium(self):
        """REC-NORM-003: Medium release age"""
        result = normalize_recency(180.0, decay_days=365.0)
        assert 0.0 < result < 1.0
        assert result < normalize_recency(1.0, decay_days=365.0)

    def test_recency_old(self):
        """REC-NORM-004: Old release"""
        result = normalize_recency(365.0, decay_days=365.0)
        assert 0.0 < result < 1.0
        assert result < normalize_recency(180.0, decay_days=365.0)

    def test_recency_very_old(self):
        """REC-NORM-005: Very old release"""
        result = normalize_recency(3650.0, decay_days=365.0)
        assert 0.0 < result < 1.0
        assert result < normalize_recency(365.0, decay_days=365.0)

    def test_recency_missing(self):
        """REC-NORM-006: None/missing release age"""
        normalizer = RecencyNormalizer()
        result = normalizer.normalize(None, {"decay_days": 365.0})
        assert result == 1.0
