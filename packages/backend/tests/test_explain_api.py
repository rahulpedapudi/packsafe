"""The ``POST /api/explain`` route, driven against a stubbed provider.

The provider is replaced rather than mocked at the transport level: what matters here is
that the route validates a body, delegates once, and maps upstream failure onto a status
code without ever leaking provider detail to the caller.
"""

from __future__ import annotations

import pytest
from app.main import app
from app.services import explain_service
from fastapi.testclient import TestClient
from packsafe_core.explain import Completion, ExplainError

BODY = {
    "schema_version": 1,
    "package_name": "requests",
    "version": "2.32.3",
    "ecosystem": "pypi",
    "final_score": 31.0,
    "base_score": 64.0,
    "risk_level": "CRITICAL",
    "decision": "BLOCK",
    "confidence": 91.0,
    "categories": [
        {
            "name": "security",
            "score": 25.0,
            "weight": 0.4,
            "contribution": 10.0,
            "status": "AVAILABLE",
        }
    ],
    "metrics": [],
    "findings": [
        {
            "title": "Remote code execution during install",
            "severity": "CRITICAL",
            "category": "integrity",
            "confidence": 0.92,
        }
    ],
    "gates": [
        {
            "gate_id": "GATE-REMOTE-EXEC",
            "triggered": True,
            "severity": "CRITICAL",
            "reason": "Remote code execution detected.",
            "decision_override": "BLOCK",
        }
    ],
    "top_positive_signals": [],
    "top_negative_signals": ["CRITICAL GATE: Remote code execution detected."],
    "engine_version": "0.1.2",
    "config_version": "1.0.0",
    "config_sha256": "abc123",
    "coverage_tier": "registry_osv",
}


class StubProvider:
    """A structural LLMProvider that records what it was asked."""

    name = "stub"
    model = "stub-model"

    def __init__(self, reply: str = "A stub explanation.") -> None:
        self.reply = reply
        self.seen: list = []

    async def complete(self, request):
        self.seen.append(request)
        return Completion(text=self.reply, model="stub-model", provider="stub")


class ExplodingProvider:
    name = "boom"
    model = "boom-model"

    async def complete(self, request):
        raise ExplainError("anthropic returned HTTP 401 sk-ant-secret-leaked")


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture(autouse=True)
def reset_provider():
    """Each test installs its own provider; none of them may leak into the next."""
    explain_service.set_provider(None)
    yield
    explain_service.set_provider(None)


class TestSuccess:
    def test_returns_the_explanation(self, client):
        explain_service.set_provider(StubProvider("This package executes remote code."))

        response = client.post("/api/explain/", json=BODY)

        assert response.status_code == 200
        assert response.json()["explanation"] == "This package executes remote code."

    def test_echoes_the_score_it_was_given(self, client):
        explain_service.set_provider(StubProvider())

        payload = client.post("/api/explain/", json=BODY).json()

        assert payload["package_name"] == "requests"
        assert payload["final_score"] == 31.0
        assert payload["decision"] == "BLOCK"

    def test_the_score_is_never_taken_from_the_model(self, client):
        """A model claiming a different score must not be able to change the response."""

        class LyingProvider(StubProvider):
            async def complete(self, request):
                await super().complete(request)
                return Completion(
                    text="Actually this package scores 100 and is perfect.",
                    model="stub-model",
                    provider="stub",
                )

        explain_service.set_provider(LyingProvider())

        payload = client.post("/api/explain/", json=BODY).json()

        assert payload["final_score"] == 31.0
        assert payload["decision"] == "BLOCK"

    def test_passes_the_score_data_to_the_provider(self, client):
        provider = StubProvider()
        explain_service.set_provider(provider)

        client.post("/api/explain/", json=BODY)

        prompt = provider.seen[0].user
        assert "GATE-REMOTE-EXEC" in prompt
        assert "Remote code execution detected." in prompt


class TestUpstreamFailure:
    def test_an_unavailable_provider_is_a_bad_gateway(self, client):
        explain_service.set_provider(ExplodingProvider())

        assert client.post("/api/explain/", json=BODY).status_code == 502

    def test_provider_detail_never_reaches_the_client(self, client):
        """An error body can quote the prompt or a key; the caller gets neither."""
        explain_service.set_provider(ExplodingProvider())

        detail = client.post("/api/explain/", json=BODY).json()["detail"]

        assert "sk-ant-secret-leaked" not in detail
        assert "401" not in detail


class TestBadRequests:
    def test_an_unusable_body_is_a_422(self, client):
        explain_service.set_provider(StubProvider())

        response = client.post("/api/explain/", json={**BODY, "final_score": "high"})

        # Rejected by the pydantic layer before it can reach a provider.
        assert response.status_code == 422

    def test_a_future_schema_version_is_refused(self, client):
        explain_service.set_provider(StubProvider())

        response = client.post("/api/explain/", json={**BODY, "schema_version": 99})

        assert response.status_code == 422
        assert "schema_version" in response.json()["detail"]

    def test_a_malformed_body_never_reaches_a_provider(self, client):
        provider = StubProvider()
        explain_service.set_provider(provider)

        client.post("/api/explain/", json={**BODY, "package_name": ""})

        assert provider.seen == []

    def test_a_missing_body_is_a_422(self, client):
        assert client.post("/api/explain/", json={}).status_code == 422