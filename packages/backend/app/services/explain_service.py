"""Resolves the configured provider once, at import, and turns requests into prose.

The provider is a module-level singleton on purpose: it owns an HTTP client, and
constructing one per request would discard connection pooling and re-read configuration
on every call. Because the provider is resolved lazily, importing this module does not
require an API key to be present - only *calling* the endpoint does - so the rest of the
service still boots without one.
"""

from __future__ import annotations

import logging
import os

from dotenv import load_dotenv
from packsafe_core.explain import (
    ExplainRequest,
    Explanation,
    LLMProvider,
    build_provider,
)
from packsafe_core.explain import (
    explain as generate,
)

from ..schemas.explain import ExplainRequestBody, ExplanationResponse

load_dotenv()
logger = logging.getLogger(__name__)


PROVIDER = os.getenv("PACKSAFE_LLM_PROVIDER")
API_KEY = os.getenv("PACKSAFE_LLM_API_KEY")
MODEL = os.getenv("PACKSAFE_LLM_MODEL")


_provider: LLMProvider | None = None


def get_provider() -> LLMProvider:
    """Returns the process-wide provider, building it on first use."""
    global _provider
    if _provider is None:
        _provider = build_provider(provider=PROVIDER, api_key=API_KEY, model=MODEL)
        logger.info(
            "explain provider ready | provider=%s",
            getattr(_provider, "name", "unknown"),
        )
    return _provider


def set_provider(provider: LLMProvider | None) -> None:
    """Overrides the provider. Intended for tests and for a service that swaps models."""
    global _provider
    _provider = provider


async def explain_score(body: ExplainRequestBody) -> ExplanationResponse:
    """Validates the body, asks the provider, and returns the explanation."""
    request = _to_request(body)
    result: Explanation = await generate(request, get_provider())
    return _to_response(result)


def _to_request(body: ExplainRequestBody) -> ExplainRequest:
    """Parses the wire body through the authoritative contract.

    Doing this here rather than trusting the pydantic model means one set of validation
    rules: the client builds a request with the same code path that will parse it, so a
    field can never mean one thing on the way out and another on the way in.
    """
    return ExplainRequest.from_payload(body.model_dump(mode="json"))


def _to_response(result: Explanation) -> ExplanationResponse:
    return ExplanationResponse(**result.to_payload())
