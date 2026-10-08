"""Request and response bodies for the explanation endpoint.

Deliberately thin. The authoritative shape lives in
:mod:`packsafe_core.explain.contract`, which the CLI already imports to *build* a
request; these models exist only so FastAPI can generate an OpenAPI schema and reject an
obviously malformed body before any of it reaches a model. The collection fields are
``list[dict]`` rather than nested models on purpose - re-validating them here would mean
two definitions of the same shape, which is the drift
:mod:`packsafe_core.explain.contract` exists to prevent. Full validation happens once, in
``explain_service``, through the same code the client used to build the request.
"""

from __future__ import annotations

from datetime import datetime

from packsafe_core.explain.contract import SCHEMA_VERSION
from pydantic import BaseModel, Field


class ExplainRequestBody(BaseModel):
    """A finished score, as sent by a PackSafe client."""

    schema_version: int = SCHEMA_VERSION
    package_name: str
    version: str
    ecosystem: str
    final_score: float
    base_score: float
    risk_level: str
    decision: str
    confidence: float
    categories: list[dict] = Field(default_factory=list)
    metrics: list[dict] = Field(default_factory=list)
    findings: list[dict] = Field(default_factory=list)
    gates: list[dict] = Field(default_factory=list)
    top_positive_signals: list[str] = Field(default_factory=list)
    top_negative_signals: list[str] = Field(default_factory=list)
    engine_version: str = ""
    config_version: str = ""
    config_sha256: str = ""
    coverage_tier: str = ""


class ExplanationResponse(BaseModel):
    """Prose describing the score, plus the score it describes.

    ``package_name``, ``final_score`` and ``decision`` are echoed from the request, not
    from the model. The client renders them beside the explanation so a reader can see
    at a glance that the prose and the score agree - which matters precisely because the
    prose came from something that cannot be trusted to be accurate.
    """

    package_name: str
    final_score: float
    decision: str
    explanation: str
    provider: str
    model: str
    generated_at: datetime