"""The wire contract, and above all the redaction it enforces."""

from __future__ import annotations

import json
from dataclasses import replace

import pytest
from packsafe_core.explain.contract import (
    SCHEMA_VERSION,
    CategoryExplain,
    ExplainRequest,
    FindingExplain,
    GateExplain,
    MetricExplain,
)


def _base_request() -> ExplainRequest:
    return ExplainRequest(
        package_name="requests",
        version="2.32.3",
        ecosystem="pypi",
        final_score=42.0,
        base_score=61.5,
        risk_level="HIGH",
        decision="WARN",
        confidence=88.0,
        categories=(
            CategoryExplain(
                name="security",
                score=40.0,
                weight=0.4,
                contribution=16.0,
                status="AVAILABLE",
            ),
        ),
        metrics=(
            MetricExplain(
                category="security",
                metric="vulnerability_combined_risk",
                normalized_value=0.2,
                weight=40.0,
                contribution=8.0,
                evidence_status="AVAILABLE",
                explanation="Combined vulnerability risk score from all applicable advisories",
            ),
        ),
        findings=(
            FindingExplain(
                title="Remote code execution",
                severity="CRITICAL",
                category="integrity",
                confidence=0.9,
            ),
        ),
        gates=(
            GateExplain(
                gate_id="GATE-REMOTE-EXEC",
                triggered=True,
                severity="CRITICAL",
                reason="Remote code execution detected.",
                decision_override="BLOCK",
            ),
        ),
        top_positive_signals=("+ Active repository maintenance",),
        top_negative_signals=("CRITICAL GATE: Remote code execution detected.",),
    )


def _request(**overrides) -> ExplainRequest:
    return replace(_base_request(), **overrides)


class TestRoundTrip:
    def test_payload_survives_a_round_trip(self):
        """The request a client holds must equal the one the service parses.

        Rounding happens in ``__post_init__`` rather than in ``to_payload`` precisely so
        this holds: if it happened only at serialization, the client's copy and the
        server's would differ in the last decimal and every comparison between them would
        need a tolerance.
        """
        original = _request()

        assert ExplainRequest.from_payload(original.to_payload()) == original

    def test_rounding_happens_at_construction_not_at_serialization(self):
        request = _request(final_score=94.70350351759157)

        # Already rounded in memory, so the prompt and the object cannot disagree.
        assert request.final_score == 94.7
        assert request.to_payload()["final_score"] == 94.7

    def test_payload_is_json_serializable(self):
        """The body crosses an HTTP boundary, so it cannot contain a datetime object."""
        assert json.loads(json.dumps(_request().to_payload()))


class TestSchemaVersion:
    def test_rejects_a_version_it_does_not_speak(self):
        payload = _request().to_payload()
        payload["schema_version"] = SCHEMA_VERSION + 1

        with pytest.raises(ValueError, match="schema_version"):
            ExplainRequest.from_payload(payload)

    def test_rejects_a_missing_version(self):
        payload = _request().to_payload()
        del payload["schema_version"]

        with pytest.raises(ValueError, match="schema_version"):
            ExplainRequest.from_payload(payload)


class TestValidation:
    """A stranger's body: reject it loudly rather than half-populate a prompt."""

    @pytest.mark.parametrize("field", ["package_name", "version", "ecosystem", "risk_level", "decision"])
    def test_rejects_a_missing_or_blank_identity_field(self, field):
        payload = _request().to_payload()
        payload[field] = ""

        with pytest.raises(ValueError, match=field):
            ExplainRequest.from_payload(payload)

    def test_rejects_a_non_numeric_score(self):
        payload = _request().to_payload()
        payload["final_score"] = "quite bad"

        with pytest.raises(ValueError, match="final_score"):
            ExplainRequest.from_payload(payload)

    def test_rejects_a_numeric_score_written_as_a_number_string(self):
        """`"88"` is accepted; `"high"` is not. Coercion, not silence."""
        payload = _request().to_payload()
        payload["confidence"] = "88"

        assert ExplainRequest.from_payload(payload).confidence == 88.0

    def test_rejects_a_collection_where_a_scalar_belongs(self):
        payload = _request().to_payload()
        payload["findings"] = {"not": "a list"}

        with pytest.raises(ValueError, match="findings"):
            ExplainRequest.from_payload(payload)

    def test_a_missing_optional_collection_defaults_to_empty(self):
        payload = _request().to_payload()
        payload["gates"] = None

        assert ExplainRequest.from_payload(payload).gates == ()

    def test_null_normalized_value_is_preserved(self):
        """A metric that could not be measured is meaningfully None, not zero."""
        payload = _request().to_payload()
        payload["metrics"][0]["normalized_value"] = None

        parsed = ExplainRequest.from_payload(payload)

        assert parsed.metrics[0].normalized_value is None


class TestRedaction:
    """The contract must not be able to carry archive-sourced text."""

    def test_finding_carries_only_a_label(self):
        payload = _request().to_payload()["findings"][0]

        assert set(payload) == {"title", "severity", "category", "confidence"}
        assert "evidence" not in payload
        assert "description" not in payload

    def test_gate_carries_the_reason_but_not_the_evidence_ids(self):
        payload = _request().to_payload()["gates"][0]

        assert payload["reason"] == "Remote code execution detected."
        assert "evidence_ids" not in payload