"""``--explain``: the client half, and the promise that it cannot affect a verdict.

The tests here are mostly about failure. A feature that adds a network call to a security
tool has one job it must never do - change the answer the user already got - and every
test below is a different way of trying to make it do that.
"""

from __future__ import annotations

import importlib
from datetime import UTC, datetime

import httpx
import pytest
from packsafe_cli.explain import (
    RemoteExplainer,
    build_explainer,
    explain_and_render,
    request_explanation,
)
from packsafe_core.models.package import EcosystemType, PackageRequest
from packsafe_core.models.result import AnalysisOutcome
from packsafe_core.models.scoring import (
    Decision,
    RiskLevel,
    ScoreAttribution,
    ScoreResult,
)
from packsafe_core.pipeline.context import AnalysisContext
from rich.console import Console


@pytest.fixture(autouse=True)
def fresh_settings():
    """Reloads settings after each test that changes the environment.

    ``settings`` is a module-level singleton built at import, so its environment overrides
    are read once. A test that sets ``PACKSAFE_EXPLAIN_URL`` would otherwise leak into
    every test that runs after it.
    """
    import packsafe_core.config

    yield
    importlib.reload(packsafe_core.config)


def _outcome(final_score: float = 94.7, decision=Decision.ALLOW) -> AnalysisOutcome:
    score = ScoreResult(
        package_name="requests",
        ecosystem="pypi",
        version="2.32.3",
        final_score=final_score,
        base_score=final_score,
        risk_level=RiskLevel.SAFE,
        decision=decision,
        confidence=88.0,
        categories={},
        findings=(),
        gates=(),
        attribution=ScoreAttribution(
            category_contributions={},
            metric_attributions=(),
            top_positive_signals=(),
            top_negative_signals=(),
            primary_recommendation="",
        ),
        analyzed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_version="1.0.0",
        config_version="2026-09-v1.2",
        config_sha256="abc123",
    )
    return AnalysisOutcome(
        score=score,
        context=AnalysisContext(
            request=PackageRequest(name="requests", ecosystem=EcosystemType.pypi)
        ),
    )


def _reply(text: str = "Requests is well maintained.") -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "package_name": "requests",
            "final_score": 94.7,
            "decision": "ALLOW",
            "explanation": text,
            "provider": "openai",
            "model": "gpt-4o-mini",
            "generated_at": "2026-01-01T00:00:00+00:00",
        },
    )


@pytest.fixture
def console() -> Console:
    return Console(width=100, force_terminal=False, no_color=True, record=True)


def _explainer(handler, **kwargs) -> RemoteExplainer:
    return RemoteExplainer(
        "http://service.test",
        client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
        **kwargs,
    )


class TestSuccess:
    @pytest.mark.asyncio
    async def test_posts_the_score_and_returns_the_prose(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["url"] = str(request.url)
            seen["body"] = json.loads(request.content)
            return _reply()

        result = await _explainer(handler).explain(_outcome())

        assert result.explanation == "Requests is well maintained."
        assert seen["url"] == "http://service.test/api/explain/"
        assert seen["body"]["final_score"] == 94.7

    @pytest.mark.asyncio
    async def test_the_score_it_returns_is_the_one_we_computed(self):
        """Not the one in the response body.

        The service echoes these from the request, but taking them from the wire would
        mean trusting a network hop to have kept them straight - and these are printed
        beside the prose precisely so a reader can check them.
        """

        def handler(request: httpx.Request) -> httpx.Response:
            # A response claiming a different score than the one requested.
            body = _reply().json()
            body["final_score"] = 100.0
            body["decision"] = "SAFE"
            return httpx.Response(200, json=body)

        result = await _explainer(handler).explain(_outcome())

        assert result.final_score == 94.7
        assert result.decision == "ALLOW"

    @pytest.mark.asyncio
    async def test_sends_no_authorization_header_without_a_token(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return _reply()

        await _explainer(handler).explain(_outcome())

        assert seen["auth"] is None

    @pytest.mark.asyncio
    async def test_sends_the_token_when_configured(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return _reply()

        await _explainer(handler, token="secret").explain(_outcome())

        assert seen["auth"] == "Bearer secret"


class TestFailureNeverPropagates:
    """Every one of these must come back as ``None``, not an exception.

    Each installs its handler through ``build_explainer`` rather than reaching into
    ``request_explanation``. Without that, the tests would issue real requests to
    ``localhost:8000``: slow, dependent on whatever happens to be listening, and passing
    for the wrong reason.
    """

    @pytest.fixture
    def use(self, monkeypatch):
        """Points ``request_explanation`` at a stubbed transport."""

        def install(handler, **kwargs):
            monkeypatch.setattr(
                "packsafe_cli.explain.build_explainer",
                lambda *a, **k: _explainer(handler, **kwargs),
            )

        return install

    @pytest.mark.parametrize("status", [502, 500, 401, 404])
    def test_an_error_status_is_degraded(self, console, use, status):
        use(lambda r: httpx.Response(status, json={}))

        assert request_explanation(console, _outcome()) is None

    def test_a_transport_error_is_degraded(self, console, use):
        def handler(request):
            raise httpx.ConnectError("refused", request=request)

        use(handler)

        assert request_explanation(console, _outcome()) is None

    def test_a_timeout_is_degraded(self, console, use):
        def handler(request):
            raise httpx.ReadTimeout("too slow", request=request)

        use(handler)

        assert request_explanation(console, _outcome()) is None

    def test_a_non_json_response_is_degraded(self, console, use):
        use(lambda r: httpx.Response(200, text="<html>gateway</html>"))

        assert request_explanation(console, _outcome()) is None

    def test_a_missing_field_is_degraded(self, console, use):
        def handler(request):
            body = _reply().json()
            del body["explanation"]
            return httpx.Response(200, json=body)

        use(handler)

        assert request_explanation(console, _outcome()) is None

    def test_an_exploding_explainer_is_degraded(self, console, monkeypatch):
        """Even a bug in our own code cannot take down the analysis."""

        class Exploding:
            async def explain(self, outcome):
                raise RuntimeError("a bug in the renderer")

        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer", lambda *a, **k: Exploding()
        )

        assert request_explanation(console, _outcome()) is None

    def test_the_score_is_still_shown_when_explanation_fails(self, console, use):
        """The point of the whole design: a lost paragraph is not a lost verdict."""
        use(lambda r: httpx.Response(502, json={}))

        request_explanation(console, _outcome())

        # Rich wraps the note to the terminal width, so compare on collapsed whitespace
        # rather than hunting for a phrase that may straddle a line break.
        output = " ".join(console.export_text().split())
        assert "--explain:" in output
        assert "The score above is unaffected" in output


class TestRender:
    def test_the_explanation_is_not_gated_behind_a_prompt(self, console, monkeypatch):
        """`--explain` never asks a question.

        The report used to offer to expand its collapsed detail, which put a prompt in the
        middle of a non-interactive command. Anything that reads a score has to behave
        identically whether or not a human is watching.
        """
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply("Fine.")),
        )

        explain_and_render(console, _outcome())

        output = " ".join(console.export_text().split())
        assert "(y/n)" not in output
        assert "Show " not in output

    def test_a_blocked_package_still_gets_an_explanation(self, console, monkeypatch):
        outcome = _outcome(final_score=12.0, decision=Decision.BLOCK)
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            return _reply("This package runs remote code at install time.")

        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer", lambda *a, **k: _explainer(handler)
        )

        explain_and_render(console, outcome)

        # A block is exactly when a reader most needs the reason in words.
        assert seen["body"]["decision"] == "BLOCK"

    def test_the_explanation_is_printed_after_the_score(self, console, monkeypatch):
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply("All good here.")),
        )

        explain_and_render(console, _outcome())

        output = console.export_text()
        assert "Why This Score" in output
        # The score the prose describes is on screen, so a mismatch is visible.
        assert "94.7/100" in output or "95/100" in output

    def test_markup_in_model_output_is_printed_literally(self, console, monkeypatch):
        """The single most important rendering rule.

        Model output is the least trustworthy string this CLI prints - unlike a package
        name or a URL, nobody reviewed it for characters like ``[bold]``. Rich markup must
        not be interpreted, or a model can inject styling, or worse, terminal escapes.
        """
        hostile = "Looks [bold]safe[/bold] \x1b[31mred\x1b[0m [link=x]y[/link]"
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply(hostile)),
        )

        explain_and_render(console, _outcome())

        output = console.export_text()
        # Rich markup is escaped, so it reads as the characters the model produced.
        assert "[bold]safe[/bold]" in output
        assert "[link=x]y[/link]" in output

    def test_ansi_escapes_never_reach_the_terminal(self, console, monkeypatch):
        """The non-obvious half of the same rule.

        Rich escapes ``[bold]``, but a raw ANSI escape is not markup - it is an
        instruction to the terminal. Model output containing one could move the cursor,
        clear the screen, or set the window title via an OSC sequence. It must be removed
        before printing, not merely left unstyled.
        """
        hostile = "Safe \x1b[2J\x1b[H\x1b]0;pwned\x07 [red]alert\x1b[0m"
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply(hostile)),
        )

        explain_and_render(console, _outcome())

        output = console.export_text()
        for escape in ("\x1b[2J", "\x1b[H", "\x1b]0;", "\x07"):
            assert escape not in output
        # The readable text survives; only the control characters are gone.
        assert "Safe" in output
        assert "alert" in output

    def test_the_model_is_named(self, console, monkeypatch):
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply("Fine.")),
        )

        explain_and_render(console, _outcome())

        output = console.export_text()
        assert "openai/gpt-4o-mini" in output

    def test_an_absurdly_long_explanation_is_truncated(self, console, monkeypatch):
        monkeypatch.setattr(
            "packsafe_cli.explain.build_explainer",
            lambda *a, **k: _explainer(lambda r: _reply("blah " * 2000)),
        )

        explain_and_render(console, _outcome())

        assert "blah" in console.export_text()


class TestConfiguration:
    def test_the_token_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_EXPLAIN_TOKEN", "from-env")

        assert build_explainer().token == "from-env"

    def test_the_timeout_comes_from_the_environment(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_EXPLAIN_TIMEOUT", "12.5")

        assert build_explainer().timeout == 12.5

    def test_no_token_means_no_token(self, monkeypatch):
        monkeypatch.delenv("PACKSAFE_EXPLAIN_TOKEN", raising=False)

        assert build_explainer().token is None

    def test_a_trailing_slash_on_the_url_does_not_double_up(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_EXPLAIN_URL", "http://packsafe.example.com/")

        assert build_explainer().base_url == "http://packsafe.example.com"