"""Chooses an LLM provider from configuration and builds the explanation.

The provider name never appears in calling code - it comes from ``PACKSAFE_LLM_PROVIDER``
and is resolved here. Adapters are imported lazily so that a deployment which only ever
uses one vendor does not pay import cost for the others, and so a provider added later
needs no edit to this file beyond a mapping entry.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Callable

from .contract import ExplainRequest, Explanation
from .prompt import build_completion_request
from .provider import Completion, CompletionRequest, ExplainError, LLMProvider

logger = logging.getLogger(__name__)

ENV_PROVIDER = "PACKSAFE_LLM_PROVIDER"
ENV_MODEL = "PACKSAFE_LLM_MODEL"
ENV_BASE_URL = "PACKSAFE_LLM_BASE_URL"
ENV_API_KEY = "PACKSAFE_LLM_API_KEY"
ENV_TIMEOUT = "PACKSAFE_LLM_TIMEOUT"

# OpenAI is the default because the OpenAI adapter is the one that covers the most
# providers: anything speaking that format is reachable by changing the base URL alone.
DEFAULT_PROVIDER = "gemini"


def _build_openai(api_key: str, **kwargs: object) -> LLMProvider:
    from .providers.openai_compat import OpenAICompatibleProvider

    return OpenAICompatibleProvider(api_key, **kwargs)  # type: ignore[arg-type]


def _build_anthropic(api_key: str, **kwargs: object) -> LLMProvider:
    from .providers.anthropic import AnthropicProvider

    return AnthropicProvider(api_key, **kwargs)  # type: ignore[arg-type]


def _build_gemini(api_key: str, **kwargs: object) -> LLMProvider:
    from .providers.gemini import GeminiProvider

    return GeminiProvider(api_key, **kwargs)  # type: ignore[arg-type]


#: Provider name -> constructor. Aliases point at the same builder on purpose: "llama"
#: is a model family, not an API shape, and users reach for it regardless.
BUILDERS: dict[str, Callable[..., LLMProvider]] = {
    "openai": _build_openai,
    "openai-compatible": _build_openai,
    "local": _build_openai,
    "ollama": _build_openai,
    "llama": _build_openai,
    "anthropic": _build_anthropic,
    "claude": _build_anthropic,
    "gemini": _build_gemini,
    "google": _build_gemini,
}


def provider_names() -> tuple[str, ...]:
    """Every accepted ``PACKSAFE_LLM_PROVIDER`` value, for error messages and docs."""
    return tuple(sorted(BUILDERS))


def build_provider(
    *,
    provider: str | None = None,
    api_key: str | None = None,
    base_url: str | None = None,
    model: str | None = None,
    timeout: float | None = None,
) -> LLMProvider:
    """Builds the configured provider.

    Configuration is read from the environment unless passed explicitly, which is what
    lets the service resolve one provider at startup while tests build one directly.
    """
    provider = (provider or os.getenv(ENV_PROVIDER) or DEFAULT_PROVIDER).strip().lower()
    api_key = api_key or os.getenv(ENV_API_KEY)
    base_url = base_url or os.getenv(ENV_BASE_URL)
    model = model or os.getenv(ENV_MODEL)

    if timeout is None:
        raw_timeout = os.getenv(ENV_TIMEOUT)
        timeout = float(raw_timeout) if raw_timeout else 30.0

    builder = BUILDERS.get(provider)
    if builder is None:
        raise ExplainError(
            f"unknown explain provider '{provider}'; expected one of "
            f"{', '.join(provider_names())}"
        )

    if not api_key:
        raise ExplainError(
            f"no API key configured for provider '{provider}'; set {ENV_API_KEY}"
        )

    kwargs: dict[str, object] = {"timeout": timeout}
    if base_url:
        kwargs["base_url"] = base_url
    if model:
        kwargs["model"] = model

    return builder(api_key, **kwargs)


async def explain(request: ExplainRequest, provider: LLMProvider) -> Explanation:
    """Asks ``provider`` to describe ``request``, and returns the prose.

    The score, decision and package name echoed back are copied from the *request*, never
    from the model's text. A caller can therefore trust that the response it renders
    alongside the explanation agrees with the score it computed itself, even if the model
    said something else.
    """
    model = getattr(provider, "model", "")
    completion: Completion = await provider.complete(
        build_completion_request(request, model=model)
    )

    logger.info(
        "explanation generated | provider=%s model=%s chars=%d",
        completion.provider,
        completion.model,
        len(completion.text),
    )

    return Explanation(
        package_name=request.package_name,
        final_score=request.final_score,
        decision=request.decision,
        explanation=completion.text,
        provider=completion.provider,
        model=completion.model,
    )


__all__ = [
    "ENV_API_KEY",
    "ENV_BASE_URL",
    "ENV_MODEL",
    "ENV_PROVIDER",
    "ENV_TIMEOUT",
    "CompletionRequest",
    "ExplainError",
    "Explanation",
    "LLMProvider",
    "build_provider",
    "explain",
    "provider_names",
]
