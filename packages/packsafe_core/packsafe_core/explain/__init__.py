"""Natural-language explanation of a computed PackSafe score.

Separated from :mod:`packsafe_core.scoring` on purpose. The score engine stays
deterministic, offline and auditable - see ``scoring/engine.py``, which performs zero
network calls - while everything in this package is I/O and nondeterminism, and can
therefore never influence a score. Nothing here is imported by the scoring path.

The layering, outer to inner:

* :mod:`~packsafe_core.explain.contract` - the wire format, shared by the client that
  builds a request and the service that validates one.
* :mod:`~packsafe_core.explain.provider` - the provider-independent interface.
* :mod:`~packsafe_core.explain.providers` - one adapter per wire format.
* :mod:`~packsafe_core.explain.prompt` - the prompt, identical for every provider.
* :mod:`~packsafe_core.explain.projection` - the redaction chokepoint, turning a score
  into the request.
* :mod:`~packsafe_core.explain.registry` - configuration to provider, plus the call.
"""

from .contract import (
    SCHEMA_VERSION,
    CategoryExplain,
    ExplainRequest,
    Explanation,
    FindingExplain,
    GateExplain,
    MetricExplain,
)
from .projection import build_explain_request
from .prompt import build_completion_request
from .provider import Completion, CompletionRequest, ExplainError, LLMProvider
from .registry import build_provider, explain, provider_names

__all__ = [
    "SCHEMA_VERSION",
    "CategoryExplain",
    "Completion",
    "CompletionRequest",
    "ExplainError",
    "ExplainRequest",
    "Explanation",
    "FindingExplain",
    "GateExplain",
    "LLMProvider",
    "MetricExplain",
    "build_completion_request",
    "build_explain_request",
    "build_provider",
    "explain",
    "provider_names",
]