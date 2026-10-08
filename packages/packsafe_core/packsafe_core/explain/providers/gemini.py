"""Adapter for Google's Gemini ``generateContent`` API.

Structurally the odd one out: the model is named in the URL path rather than the body,
the generation settings live under a ``generationConfig`` key, and the reply is a list of
``candidates`` whose first entry holds ``content.parts`` - a further nesting step below
Anthropic's blocks.
"""

from __future__ import annotations

import logging
from typing import Any

import httpx

from ..provider import Completion, CompletionRequest, ExplainError

logger = logging.getLogger(__name__)

DEFAULT_BASE_URL = "https://generativelanguage.googleapis.com/v1beta"
DEFAULT_MODEL = "gemini-2.0-flash"


class GeminiProvider:
    """Talks to Gemini's ``generateContent`` endpoint."""

    name = "gemini"

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
        model = request.model or self.model
        payload: dict[str, Any] = {
            # Gemini has no system role; the instruction is a part of the user turn.
            "contents": [
                {"role": "user", "parts": [{"text": f"{request.system}\n\n{request.user}"}]}
            ],
            "generationConfig": {
                "maxOutputTokens": request.max_tokens,
                "temperature": request.temperature,
            },
        }

        headers = {"x-goog-api-key": self.api_key, "Content-Type": "application/json"}
        url = f"{self.base_url}/models/{model}:generateContent"

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
            text=_first_part_text(body),
            model=body.get("modelVersion") or model,
            provider=self.name,
        )


def _first_part_text(body: dict[str, Any]) -> str:
    """Pulls the reply out of a generateContent response."""
    candidates = body.get("candidates") or []
    if not candidates:
        # A safety block returns no candidates at all. Surfacing the finish reason makes
        # the difference between "the model refused" and "the request was malformed"
        # diagnosable from the log line alone.
        block = body.get("promptFeedback") or {}
        raise ExplainError(f"provider returned no candidates (finish: {block.get('blockReason')})")

    parts = (candidates[0].get("content") or {}).get("parts") or []
    text = "".join(
        part.get("text", "") for part in parts if isinstance(part, dict) and part.get("text")
    ).strip()

    if not text:
        raise ExplainError("provider returned an empty completion")
    return text