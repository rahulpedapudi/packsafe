"""Adapter for Anthropic's Messages API.

Kept separate from the OpenAI-shaped adapter because the wire format genuinely differs -
the system prompt is a top-level field rather than a message, and the response nests the
text under ``content`` blocks instead of a single string. The awkward part is that
Anthropic splits the system prompt and user turn across *two* parameters instead of
interleaving them as roles, so the ``CompletionRequest`` shape does not map onto the API
one-to-one.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..provider import Completion, CompletionRequest, ExplainError

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://api.anthropic.com/v1"
API_VERSION = "2023-06-01"

# Named here because this vendor's model IDs are versioned tightly enough that a wrong
# one is a 404 rather than a fallback, and because there is no "small" default that
# stays current.
DEFAULT_MODEL = "claude-sonnet-4-5"


class AnthropicProvider:
    """Talks to Anthropic's ``/messages`` endpoint."""

    name = "anthropic"

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
        self.model = model or DEFAULT_MODEL
        self.timeout = timeout
        self._client = client

    async def complete(self, request: CompletionRequest) -> Completion:
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            # Anthropic takes the system prompt outside the message list entirely.
            "system": request.system,
            "messages": [{"role": "user", "content": request.user}],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": API_VERSION,
            "Content-Type": "application/json",
        }

        url = f"{self.base_url}/messages"
        try:
            client = self._client or httpx.AsyncClient(timeout=self.timeout)
            async with client:
                response = await client.post(url, json=payload, headers=headers)
        except httpx.HTTPError as e:
            logger.warning("explain provider transport error | %s | %s", self.name, e)
            raise ExplainError(f"{self.name} request failed: {e}") from e

        if response.status_code != 200:
            logger.warning(
                "explain provider http error | %s | status=%d | body=%s",
                self.name,
                response.status_code,
                response.text[:500],
            )
            raise ExplainError(f"{self.name} returned HTTP {response.status_code}")

        try:
            body = response.json()
        except ValueError as e:
            raise ExplainError(f"{self.name} returned a non-JSON response") from e

        return Completion(
            text=_block_text(body),
            model=body.get("model") or payload["model"],
            provider=self.name,
        )


def _block_text(body: dict[str, Any]) -> str:
    """Joins the text blocks of a Messages response.

    The content array can hold non-text blocks (tool calls, thinking); only ``text``
    blocks carry the answer, and a stop sequence can leave trailing blocks empty.
    """
    blocks = body.get("content") or []
    text = "".join(
        block.get("text", "")
        for block in blocks
        if isinstance(block, dict) and block.get("type") == "text"
    ).strip()

    if not text:
        raise ExplainError("provider returned an empty completion")
    return text