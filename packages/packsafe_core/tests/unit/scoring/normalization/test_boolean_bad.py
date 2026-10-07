from packsafe_core.scoring.normalization.boolean import (
    normalize_boolean_bad,
)


class TestBooleanBad:
    def test_boolean_bad_false(self):
        """BOOL-NORM-001: False input"""
        result = normalize_boolean_bad(False)
        assert result == 1.0

    def test_boolean_bad_true(self):
        """BOOL-NORM-002: True input"""
        result = normalize_boolean_bad(True)
        assert result == 0.0

    def test_boolean_bad_integer_zero(self):
        """BOOL-NORM-003: Integer 0"""
        result = normalize_boolean_bad(0)
        assert result == 1.0

    def test_boolean_bad_integer_one(self):
        """BOOL-NORM-004: Integer 1"""
        result = normalize_boolean_bad(1)
        assert result == 0.0

    def test_boolean_bad_boundary(self):
        """BOOL-NORM-005: Boolean boundary behavior (string parsing)"""
        assert normalize_boolean_bad("true") == 0.0
        assert normalize_boolean_bad("False") == 1.0
        assert normalize_boolean_bad("1") == 0.0
        assert normalize_boolean_bad("yes") == 0.0

    def test_boolean_bad_missing(self):
        """BOOL-NORM-006: None/missing input"""
        result = normalize_boolean_bad(None)
        assert result == 1.0

    def test_boolean_bad_unexpected(self):
        """BOOL-NORM-007: Unexpected boolean-like input"""
        result = normalize_boolean_bad("unexpected_string")
        assert result == 1.0
