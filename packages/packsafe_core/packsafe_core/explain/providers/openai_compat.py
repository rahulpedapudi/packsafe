"""Adapter for OpenAI's ``/chat/completions`` shape, and for everything that copies it.

This one adapter is not just OpenAI. The chat-completions request and response format is
the closest thing the industry has to a lingua franca: Groq, Together, DeepSeek,
Fireworks, OpenRouter, Mistral, xAI and the hosted and local inference servers
(LM Studio, vLLM, llama.cpp, Ollama's OpenAI-compatible endpoint) all accept it. Because
:data:`DEFAULT_MODELS` carries a default per *vendor*, pointing ``base_url`` at any of
them needs no code and usually no configuration beyond the URL.

Each of those vendors needs a different key and a different URL, so neither is hardcoded
here. An adapter that cannot be pointed somewhere else is a vendor lock-in bug wearing a
provider-abstraction costume.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..provider import Completion, CompletionRequest, ExplainError

logger = logging.getLogger(__name__)

# Overridable per deployment; every one of these vendors serves OpenAI's format.
DEFAULT_BASE_URL = "https://api.openai.com/v1"

#: Default model per known vendor, keyed by the host in ``base_url``. An unknown host
#: falls back to :data:`FALLBACK_MODEL`, so a self-hosted server works with just a URL.
DEFAULT_MODELS: dict[str, str] = {
    "api.openai.com": "gpt-4o-mini",
    "api.groq.com": "llama-3.3-70b-versatile",
    "api.together.xyz": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "api.deepseek.com": "deepseek-chat",
    "openrouter.ai": "openai/gpt-4o-mini",
    "api.fireworks.ai": "accounts/fireworks/models/llama-v3p3-70b-instruct",
    "api.mistral.ai": "mistral-small-latest",
}

FALLBACK_MODEL = "gpt-4o-mini"


class OpenAICompatibleProvider:
    """Talks to any endpoint that speaks OpenAI's chat-completions format."""

    name = "openai"

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        model: str | None = None,
        timeout: float = 30.0,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model = model or default_model_for(self.base_url)
        self.timeout = timeout
        # An injected client lets a test drive the response without a network, and lets a
        # long-lived service share one connection pool across requests.
        self._client = client
        self._owns_client = client is None

    async def complete(self, request: CompletionRequest) -> Completion:
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": [
                {"role": "system", "content": request.system},
                {"role": "user", "content": request.user},
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        response = await self._post("/chat/completions", payload)
        return Completion(
            text=_first_text(response),
            model=response.get("model") or payload["model"],
            provider=self.name,
        )

    async def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        url = f"{self.base_url}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            async with client:
                response = await client.post(url, json=payload, headers=headers)
        except httpx.HTTPError as e:
            logger.warning("explain provider transport error | %s | %s", self.name, e)
            raise ExplainError(f"{self.name} request failed: {e}") from e

        if response.status_code != 200:
            # The body can carry the provider's own error prose, which may quote the
            # prompt. Log it, but do not put it in the exception message that could reach
            # a user-facing surface.
            logger.warning(
                "explain provider http error | %s | status=%d | body=%s",
                self.name,
                response.status_code,
                response.text[:500],
            )
            raise ExplainError(
                f"{self.name} returned HTTP {response.status_code}"
            )

        try:
            return response.json()
        except ValueError as e:
            raise ExplainError(f"{self.name} returned a non-JSON response") from e


def default_model_for(base_url: str) -> str:
    """Picks a sensible default model for a base URL, falling back for unknown hosts."""
    host = httpx.URL(base_url).host or ""
    return DEFAULT_MODELS.get(host, FALLBACK_MODEL)


def _first_text(response: dict[str, Any]) -> str:
    """Pulls the reply out of a chat-completions response.

    ``choices`` may be empty on a refusal or a content filter, so the empty case raises
    rather than returning "" - an empty explanation would render as a section with
    nothing in it, which reads like a bug in the score.
    """
    choices = response.get("choices") or []
    if not choices:
        raise ExplainError("provider returned no choices")

    message = choices[0].get("message") or {}
    text = message.get("content")

    if not isinstance(text, str) or not text.strip():
        raise ExplainError("provider returned an empty completion")

    return text.strip()