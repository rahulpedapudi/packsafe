"""The provider-independent interface every LLM adapter implements.

The adapters speak three very different wire formats, but they all do the same one thing:
turn a prompt into text. Normalizing that to a single :class:`CompletionRequest` in and a
single :class:`Completion` out is what makes the choice of provider a configuration
detail instead of a code change. Nothing downstream - the service, the route, the CLI -
is allowed to branch on which provider answered.

Deliberately *not* modeled here: streaming, tool calls, image input, logprobs, token
counting. An explanation is one short paragraph. Every extra capability added to this
interface is a capability every adapter must then implement, and the day one of them
cannot is the day the abstraction stops being worth having.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from ..exceptions import PackageAnalysisError


class ExplainError(PackageAnalysisError):
    """A provider could not produce an explanation.

    Inherits from ``PackageAnalysisError`` so callers that already handle analysis
    failures catch it, but it is never raised during scoring: an explanation is
    decoration, and a failed decoration must not fail the analysis that produced it.
    """


@dataclass(frozen=True)
class CompletionRequest:
    """A prompt plus the few knobs that change between providers."""

    system: str
    user: str
    model: str
    max_tokens: int = 700
    temperature: float = 0.2


@dataclass(frozen=True)
class Completion:
    """A provider's answer, normalized."""

    text: str
    model: str
    provider: str


@runtime_checkable
class LLMProvider(Protocol):
    """Anything that can turn a :class:`CompletionRequest` into a :class:`Completion`.

    A ``Protocol`` rather than an abstract base class, matching
    :class:`packsafe_core.sources.base_registry.PackageRegistry`: an adapter is a
    structural match, so a test double or a new provider needs no import from this module
    and no registration beyond picking it in configuration.
    """

    #: Stable identifier used in logs and echoed back to the caller, e.g. ``"anthropic"``.
    name: str

    async def complete(self, request: CompletionRequest) -> Completion:
        """Returns the model's reply, or raises :class:`ExplainError`."""
        ...