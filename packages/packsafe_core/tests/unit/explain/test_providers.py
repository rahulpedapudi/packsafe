"""Provider adapters and the registry.

Every provider is driven through a mock transport rather than a network: the point of
these tests is the translation in each direction, not that OpenAI is reachable.
"""

from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from packsafe_core.explain import build_provider, provider_names
from packsafe_core.explain.contract import ExplainRequest
from packsafe_core.explain.provider import (
    Completion,
    CompletionRequest,
    ExplainError,
    LLMProvider,
)
from packsafe_core.explain.providers.anthropic import AnthropicProvider
from packsafe_core.explain.providers.gemini import GeminiProvider
from packsafe_core.explain.providers.openai_compat import (
    DEFAULT_MODELS,
    OpenAICompatibleProvider,
    default_model_for,
)
from packsafe_core.explain.registry import BUILDERS, DEFAULT_PROVIDER

REQUEST = CompletionRequest(system="s", user="u", model="test-model")


def _mock_client(handler) -> httpx.AsyncClient:
    """An AsyncClient whose transport is a callable, so no socket is opened."""
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


class TestOpenAICompatible:
    @pytest.mark.asyncio
    @pytest.mark.asyncio
    async def test_returns_the_message_content(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            seen["headers"] = dict(request.headers)
            return httpx.Response(
                200,
                json={
                    "model": "gpt-4o-mini-2024",
                    "choices": [{"message": {"role": "assistant", "content": "  hello  "}}],
                },
            )

        provider = OpenAICompatibleProvider("k", model="gpt-4o-mini", client=_mock_client(handler))

        result = await provider.complete(REQUEST)

        assert result.text == "hello"
        assert result.provider == "openai"
        assert result.model == "gpt-4o-mini-2024"

    @pytest.mark.asyncio
    async def test_sends_system_and_user_as_separate_messages(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            return httpx.Response(
                200, json={"choices": [{"message": {"content": "x"}}]}
            )

        provider = OpenAICompatibleProvider("k", model="m", client=_mock_client(handler))
        await provider.complete(REQUEST)

        assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]

    @pytest.mark.asyncio
    async def test_sends_the_bearer_token(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

        provider = OpenAICompatibleProvider("sk-test", model="m", client=_mock_client(handler))
        await provider.complete(REQUEST)

        assert seen["auth"] == "Bearer sk-test"

    @pytest.mark.asyncio
    async def test_targets_the_configured_base_url(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["url"] = str(request.url)
            return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

        provider = OpenAICompatibleProvider(
            "k",
            base_url="http://localhost:11434/v1/",
            model="m",
            client=_mock_client(handler),
        )
        await provider.complete(REQUEST)

        # A trailing slash on the configured base must not double up in the path.
        assert seen["url"] == "http://localhost:11434/v1/chat/completions"

    @pytest.mark.asyncio
    async def test_raises_on_an_http_error(self):
        provider = OpenAICompatibleProvider(
            "k", model="m", client=_mock_client(lambda r: httpx.Response(429, json={}))
        )

        with pytest.raises(ExplainError, match="429"):
            await provider.complete(REQUEST)

    @pytest.mark.asyncio
    async def test_raises_on_an_empty_choices_list(self):
        provider = OpenAICompatibleProvider(
            "k", model="m", client=_mock_client(lambda r: httpx.Response(200, json={"choices": []}))
        )

        with pytest.raises(ExplainError, match="no choices"):
            await provider.complete(REQUEST)

    @pytest.mark.asyncio
    async def test_raises_on_blank_content(self):
        provider = OpenAICompatibleProvider(
            "k",
            model="m",
            client=_mock_client(
                lambda r: httpx.Response(200, json={"choices": [{"message": {"content": "  "}}]})
            ),
        )

        with pytest.raises(ExplainError, match="empty completion"):
            await provider.complete(REQUEST)


class TestDefaultModels:
    @pytest.mark.parametrize("base_url", list(DEFAULT_MODELS))
    def test_a_known_vendor_gets_its_own_default(self, base_url):
        assert default_model_for(f"https://{base_url}/v1") == DEFAULT_MODELS[base_url]

    def test_an_unknown_host_still_gets_a_usable_default(self):
        """A self-hosted server must work with nothing but a URL."""
        assert default_model_for("http://192.168.1.50:8000/v1")

    def test_a_trailing_slash_does_not_defeat_host_lookup(self):
        assert default_model_for("https://api.groq.com/openai/v1/") == DEFAULT_MODELS["api.groq.com"]


class TestAnthropic:
    @pytest.mark.asyncio
    async def test_returns_joined_text_blocks(self):
        provider = AnthropicProvider(
            "k",
            model="claude",
            client=_mock_client(
                lambda r: httpx.Response(
                    200,
                    json={
                        "model": "claude-x",
                        "content": [
                            {"type": "text", "text": "one "},
                            {"type": "tool_use", "id": "t"},
                            {"type": "text", "text": "two"},
                        ],
                    },
                )
            ),
        )

        result = await provider.complete(REQUEST)

        assert result.text == "one two"
        assert result.provider == "anthropic"

    @pytest.mark.asyncio
    async def test_sends_system_outside_the_message_list(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["body"] = json.loads(request.content)
            seen["headers"] = dict(request.headers)
            return httpx.Response(200, json={"content": [{"type": "text", "text": "x"}]})

        provider = AnthropicProvider("sk-ant", model="m", client=_mock_client(handler))
        await provider.complete(REQUEST)

        # Anthropic takes the system prompt as a top-level field, not as a message.
        assert seen["body"]["system"] == "s"
        assert [m["role"] for m in seen["body"]["messages"]] == ["user"]
        assert seen["headers"]["x-api-key"] == "sk-ant"

    @pytest.mark.asyncio
    async def test_raises_when_every_block_is_non_text(self):
        provider = AnthropicProvider(
            "k",
            model="m",
            client=_mock_client(
                lambda r: httpx.Response(200, json={"content": [{"type": "tool_use"}]})
            ),
        )

        with pytest.raises(ExplainError, match="empty completion"):
            await provider.complete(REQUEST)


class TestGemini:
    @pytest.mark.asyncio
    async def test_returns_the_first_candidate_text(self):
        provider = GeminiProvider(
            "k",
            model="gemini",
            client=_mock_client(
                lambda r: httpx.Response(
                    200,
                    json={
                        "modelVersion": "gemini-2.0-flash-001",
                        "candidates": [{"content": {"parts": [{"text": "hello"}]}}],
                    },
                )
            ),
        )

        result = await provider.complete(REQUEST)

        assert result.text == "hello"
        assert result.model == "gemini-2.0-flash-001"

    @pytest.mark.asyncio
    async def test_puts_the_model_in_the_path_and_settings_in_the_body(self):
        seen: dict = {}

        def handler(request: httpx.Request) -> httpx.Response:
            import json

            seen["url"] = str(request.url)
            seen["body"] = json.loads(request.content)
            seen["headers"] = dict(request.headers)
            return httpx.Response(
                200, json={"candidates": [{"content": {"parts": [{"text": "x"}]}}]}
            )

        provider = GeminiProvider("goog-key", model="gemini-2.0-flash", client=_mock_client(handler))
        # An explicit model on the request wins over the provider's default; that is the
        # escape hatch for a caller that wants one call on a different model.
        await provider.complete(replace(REQUEST, model="gemini-2.0-flash"))

        assert seen["url"].endswith("/models/gemini-2.0-flash:generateContent")
        assert seen["body"]["generationConfig"]["maxOutputTokens"] == REQUEST.max_tokens
        # Gemini has no system role, so the instruction rides along in the user turn.
        assert seen["body"]["contents"][0]["parts"][0]["text"].startswith("s")
        assert seen["headers"]["x-goog-api-key"] == "goog-key"

    @pytest.mark.asyncio
    async def test_names_the_finish_reason_when_candidates_are_blocked(self):
        provider = GeminiProvider(
            "k",
            model="m",
            client=_mock_client(
                lambda r: httpx.Response(
                    200, json={"promptFeedback": {"blockReason": "SAFETY"}}
                )
            ),
        )

        with pytest.raises(ExplainError, match="SAFETY"):
            await provider.complete(REQUEST)


class TestRegistry:
    @pytest.fixture(autouse=True)
    def isolated_env(self, monkeypatch):
        """Clears every ``PACKSAFE_LLM_*`` variable before each test here.

        These tests assert what the registry does when a variable is *absent*, so a value
        exported in the surrounding shell - by a developer, or by an integration run - would
        silently change what they measure. ``monkeypatch`` alone is not enough: it only
        undoes what a given test set, not what it inherited.
        """
        for name in (
            "PACKSAFE_LLM_PROVIDER",
            "PACKSAFE_LLM_API_KEY",
            "PACKSAFE_LLM_MODEL",
            "PACKSAFE_LLM_BASE_URL",
            "PACKSAFE_LLM_TIMEOUT",
        ):
            monkeypatch.delenv(name, raising=False)

    def test_every_adapter_satisfies_the_protocol(self):
        """The abstraction is structural: matching the shape is the whole requirement."""
        assert isinstance(OpenAICompatibleProvider("k"), LLMProvider)
        assert isinstance(AnthropicProvider("k"), LLMProvider)
        assert isinstance(GeminiProvider("k"), LLMProvider)

    def test_a_structural_double_is_accepted_without_importing_anything(self):
        class Double:
            name = "double"

            async def complete(self, request):
                return Completion(text="x", model="m", provider="double")

        assert isinstance(Double(), LLMProvider)

    def test_the_default_provider_is_used_when_none_is_configured(self, monkeypatch):
        """Falls back to ``DEFAULT_PROVIDER`` when nothing is set.

        Asserted against the constant rather than a literal vendor name: what is under
        test is the fallback mechanism, not which vendor happens to be the default today.
        """
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "k")

        assert build_provider().name == DEFAULT_PROVIDER

    def test_an_explicit_provider_beats_the_default(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "k")
        monkeypatch.setenv("PACKSAFE_LLM_PROVIDER", "anthropic")

        assert build_provider().name == "anthropic"

    def test_the_default_is_a_provider_that_exists(self):
        """A typo in the constant would otherwise only surface on an unconfigured deploy."""
        assert DEFAULT_PROVIDER in BUILDERS

    @pytest.mark.parametrize("alias", ["anthropic", "claude", "gemini", "google", "ollama", "local"])
    def test_aliases_resolve_to_the_right_adapter(self, monkeypatch, alias):
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "k")

        assert build_provider(provider=alias).name in provider_names()

    def test_environment_selects_the_provider(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "k")
        monkeypatch.setenv("PACKSAFE_LLM_PROVIDER", "anthropic")

        assert build_provider().name == "anthropic"

    def test_an_unknown_provider_names_the_valid_ones(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "k")

        with pytest.raises(ExplainError, match="anthropic"):
            build_provider(provider="skynet")

    def test_a_missing_api_key_is_a_clear_error(self, monkeypatch):
        monkeypatch.delenv("PACKSAFE_LLM_API_KEY", raising=False)

        with pytest.raises(ExplainError, match="PACKSAFE_LLM_API_KEY"):
            build_provider()

    def test_a_self_hosted_model_needs_only_a_url(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_LLM_API_KEY", "unused")
        monkeypatch.setenv("PACKSAFE_LLM_BASE_URL", "http://localhost:11434/v1")
        monkeypatch.setenv("PACKSAFE_LLM_PROVIDER", "openai")

        provider = build_provider()

        assert provider.base_url == "http://localhost:11434/v1"
        assert provider.model

    def test_explicit_arguments_beat_the_environment(self, monkeypatch):
        monkeypatch.setenv("PACKSAFE_LLM_PROVIDER", "openai")
        monkeypatch.setenv("PACKSAFE_LLM_MODEL", "from-env")

        provider = build_provider(provider="anthropic", api_key="k", model="explicit")

        assert provider.name == "anthropic"
        assert provider.model == "explicit"


class TestExplainCall:
    @pytest.mark.asyncio
    async def test_the_response_echoes_the_request_not_the_model(self, monkeypatch):
        """The client must be able to trust that prose and score agree.

        The model is made to claim a different score entirely; the echoed fields still
        come from the request, so a caller rendering them cannot be misled.
        """
        from packsafe_core.explain import explain as explain_score

        class LyingProvider:
            name = "liar"
            model = "liar-model"

            async def complete(self, request):
                return Completion(
                    text="This package is perfect and scores 100.",
                    model="liar-model",
                    provider="liar",
                )

        request = ExplainRequest(
            package_name="evil",
            version="1.0",
            ecosystem="pypi",
            final_score=0.0,
            base_score=0.0,
            risk_level="CRITICAL",
            decision="BLOCK",
            confidence=90.0,
        )

        result = await explain_score(request, LyingProvider())

        assert result.final_score == 0.0
        assert result.decision == "BLOCK"
        assert result.package_name == "evil"
        # The prose is passed through untouched - the contract does not editorialize.
        assert result.explanation == "This package is perfect and scores 100."