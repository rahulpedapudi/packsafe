from packsafe_core.scoring.normalization.logarithmic import (
    AdoptionNormalizer,
    normalize_adoption,
)


class TestAdoption:
    def test_adoption_zero(self):
        """ADN-NORM-001: Zero adoption value."""
        result = normalize_adoption(0.0)
        assert 0.0 <= result <= 1.0
        assert result == 0.0

    def test_adoption_very_small(self):
        """ADN-NORM-002: Very small adoption value."""
        result = normalize_adoption(0.1)
        assert 0.0 <= result <= 1.0
        assert result > 0.0

    def test_adoption_low(self):
        """ADN-NORM-003: Low adoption value."""
        result = normalize_adoption(5.0)
        assert 0.0 <= result <= 1.0
        assert result > normalize_adoption(0.1)

    def test_adoption_medium(self):
        """ADN-NORM-004: Medium adoption value."""
        result = normalize_adoption(50.0)
        assert 0.0 <= result <= 1.0
        assert result > normalize_adoption(5.0)

    def test_adoption_high(self):
        """ADN-NORM-005: High adoption value."""
        result = normalize_adoption(1000.0)
        assert 0.0 <= result <= 1.0
        assert result > normalize_adoption(50.0)

    def test_adoption_very_high(self):
        """ADN-NORM-006: Very high adoption value."""
        result = normalize_adoption(1000000.0)
        assert 0.0 <= result <= 1.0
        assert result > normalize_adoption(1000.0)

    def test_adoption_boundary(self):
        """ADN-NORM-007: Adoption boundary."""
        result = normalize_adoption(10000000000.0)
        assert 0.0 <= result <= 1.0

    def test_adoption_missing(self):
        """ADN-NORM-008: Missing adoption value."""
        normalizer = AdoptionNormalizer()
        result = normalizer.normalize(None, {})
        assert result == 0.0
