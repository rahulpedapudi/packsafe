"""The request and response shapes exchanged with the explanation service.

These dataclasses are the single definition of the wire format. The CLI builds an
:class:`ExplainRequest` from a finished
:class:`~packsafe_core.models.result.AnalysisOutcome`; the backend validates the same
structure. Two independent definitions of this shape would drift, which is the failure
mode the CLI already guards against for its shared flags.

What is *not* here is as load-bearing as what is. Every field is either a number the
score engine already computed or a label PackSafe itself assigned - a metric name, a
finding type, a gate reason. Nothing carries prose out of a downloaded archive, and that
is a security decision rather than a size one: a package author controls every byte of
their own sdist and wheel, so author-controlled text must not reach a model whose output
a human will read as a security verdict. The prompt builder treats everything in here as
data for the same reason, and :func:`ExplainRequest.to_payload` is the one place a future
field has to be added deliberately.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

# Bumped when a field changes meaning or disappears. The service refuses a version it
# does not recognise rather than guessing at a payload whose shape it half-understands.
SCHEMA_VERSION = 1


def _round(value: float, digits: int) -> float:
    """Rounds a score component to the precision it is reported at."""
    return round(float(value), digits)


@dataclass(frozen=True)
class CategoryExplain:
    """One scored category and how much it moved the final number."""

    name: str
    score: float
    weight: float
    contribution: float
    status: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "score", _round(self.score, 2))
        object.__setattr__(self, "weight", _round(self.weight, 4))
        object.__setattr__(self, "contribution", _round(self.contribution, 2))

    def to_payload(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "score": self.score,
            "weight": self.weight,
            "contribution": self.contribution,
            "status": self.status,
        }


@dataclass(frozen=True)
class MetricExplain:
    """One metric's normalized value and its weight inside its category.

    ``explanation`` is the static ``explanation_template`` from ``metrics.yaml``, written
    by this project - not evidence, so it is safe to include and genuinely useful to the
    model as a label for what the number means.
    """

    category: str
    metric: str
    normalized_value: float | None
    weight: float
    contribution: float
    evidence_status: str
    explanation: str

    def __post_init__(self) -> None:
        if self.normalized_value is not None:
            object.__setattr__(
                self, "normalized_value", _round(self.normalized_value, 4)
            )
        object.__setattr__(self, "weight", _round(self.weight, 4))
        object.__setattr__(self, "contribution", _round(self.contribution, 2))

    def to_payload(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "metric": self.metric,
            "normalized_value": self.normalized_value,
            "weight": self.weight,
            "contribution": self.contribution,
            "evidence_status": self.evidence_status,
            "explanation": self.explanation,
        }


@dataclass(frozen=True)
class FindingExplain:
    """A finding reduced to its label.

    ``Finding.evidence`` and ``Finding.description`` are deliberately absent. Evidence is
    a code snippet copied verbatim out of the analyzed archive, and description carries
    advisory prose from a third party. Both are attacker-reachable; a title and a severity
    are enough for the model to say why the score moved.
    """

    title: str
    severity: str
    category: str
    confidence: float

    def __post_init__(self) -> None:
        object.__setattr__(self, "confidence", _round(self.confidence, 2))

    def to_payload(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class GateExplain:
    """Whether a policy gate fired, and the engine's own reason for it.

    ``evidence_ids`` is withheld: those strings embed archive file paths. ``reason`` is a
    literal from ``gates.yaml`` and is the part that actually explains the gate.
    """

    gate_id: str
    triggered: bool
    severity: str
    reason: str
    decision_override: str | None

    def to_payload(self) -> dict[str, Any]:
        return {
            "gate_id": self.gate_id,
            "triggered": self.triggered,
            "severity": self.severity,
            "reason": self.reason,
            "decision_override": self.decision_override,
        }


@dataclass(frozen=True)
class ExplainRequest:
    """A finished score, reduced to what a model needs in order to describe it.

    This is a *description of a verdict*, not a way to produce one. The service never
    recomputes the score and never overrides ``decision``: whoever calls it already knows
    the answer, and the only question is how to say it in a sentence a person understands.
    """

    package_name: str
    version: str
    ecosystem: str
    final_score: float
    base_score: float
    risk_level: str
    decision: str
    confidence: float
    categories: tuple[CategoryExplain, ...] = ()
    metrics: tuple[MetricExplain, ...] = ()
    findings: tuple[FindingExplain, ...] = ()
    gates: tuple[GateExplain, ...] = ()
    top_positive_signals: tuple[str, ...] = ()
    top_negative_signals: tuple[str, ...] = ()
    engine_version: str = ""
    config_version: str = ""
    config_sha256: str = ""
    coverage_tier: str = ""
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "final_score", _round(self.final_score, 2))
        object.__setattr__(self, "base_score", _round(self.base_score, 2))
        object.__setattr__(self, "confidence", _round(self.confidence, 2))

    def to_payload(self) -> dict[str, Any]:
        """Renders the request as the JSON body the service expects.

        Deliberately free of timestamps or any other value that varies between two
        requests describing the same score. That makes the rendered prompt a pure
        function of the verdict, which is what allows an explanation to be cached on the
        score's identity - and what lets a test assert that the prompt is unchanged.
        """
        return {
            "schema_version": self.schema_version,
            "package_name": self.package_name,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "final_score": self.final_score,
            "base_score": self.base_score,
            "risk_level": self.risk_level,
            "decision": self.decision,
            "confidence": self.confidence,
            "categories": [c.to_payload() for c in self.categories],
            "metrics": [m.to_payload() for m in self.metrics],
            "findings": [f.to_payload() for f in self.findings],
            "gates": [g.to_payload() for g in self.gates],
            "top_positive_signals": list(self.top_positive_signals),
            "top_negative_signals": list(self.top_negative_signals),
            "engine_version": self.engine_version,
            "config_version": self.config_version,
            "config_sha256": self.config_sha256,
            "coverage_tier": self.coverage_tier,
        }

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> ExplainRequest:
        """Rebuilds a request from an untrusted body.

        Raises ``ValueError`` on anything malformed. The service treats its input as a
        claim made by a stranger, so an unusable payload fails loudly here rather than
        reaching a model half-populated.
        """
        version = payload.get("schema_version")
        if version != SCHEMA_VERSION:
            raise ValueError(
                f"unsupported explain schema_version {version!r}; "
                f"this service speaks {SCHEMA_VERSION}"
            )

        return cls(
            package_name=_req_str(payload, "package_name"),
            version=_req_str(payload, "version"),
            ecosystem=_req_str(payload, "ecosystem"),
            final_score=_req_float(payload, "final_score"),
            base_score=_req_float(payload, "base_score"),
            risk_level=_req_str(payload, "risk_level"),
            decision=_req_str(payload, "decision"),
            confidence=_req_float(payload, "confidence"),
            categories=tuple(
                CategoryExplain(
                    name=_req_str(item, "name"),
                    score=_req_float(item, "score"),
                    weight=_req_float(item, "weight"),
                    contribution=_req_float(item, "contribution"),
                    status=_req_str(item, "status"),
                )
                for item in _req_list(payload, "categories")
            ),
            metrics=tuple(
                MetricExplain(
                    category=_req_str(item, "category"),
                    metric=_req_str(item, "metric"),
                    # Constructed, not assigned: `__post_init__` is what applies the rounding the client
                    # already applied, so a parsed request compares equal to the one that
                    # was sent.
                    normalized_value=_opt_float(item, "normalized_value"),
                    weight=_req_float(item, "weight"),
                    contribution=_req_float(item, "contribution"),
                    evidence_status=_req_str(item, "evidence_status"),
                    explanation=_req_str(item, "explanation"),
                )
                for item in _req_list(payload, "metrics")
            ),
            findings=tuple(
                FindingExplain(
                    title=_req_str(item, "title"),
                    severity=_req_str(item, "severity"),
                    category=_req_str(item, "category"),
                    confidence=_req_float(item, "confidence"),
                )
                for item in _req_list(payload, "findings")
            ),
            gates=tuple(
                GateExplain(
                    gate_id=_req_str(item, "gate_id"),
                    triggered=bool(item.get("triggered")),
                    severity=_req_str(item, "severity"),
                    reason=_req_str(item, "reason"),
                    decision_override=item.get("decision_override"),
                )
                for item in _req_list(payload, "gates")
            ),
            top_positive_signals=tuple(payload.get("top_positive_signals") or ()),
            top_negative_signals=tuple(payload.get("top_negative_signals") or ()),
            engine_version=str(payload.get("engine_version") or ""),
            config_version=str(payload.get("config_version") or ""),
            config_sha256=str(payload.get("config_sha256") or ""),
            coverage_tier=str(payload.get("coverage_tier") or ""),
            schema_version=version,
        )


@dataclass(frozen=True)
class Explanation:
    """What the service sends back: prose, plus enough context to not trust it blindly."""

    package_name: str
    final_score: float
    decision: str
    explanation: str
    provider: str
    model: str
    generated_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_payload(self) -> dict[str, Any]:
        return {
            "package_name": self.package_name,
            "final_score": round(self.final_score, 2),
            "decision": self.decision,
            "explanation": self.explanation,
            "provider": self.provider,
            "model": self.model,
            "generated_at": self.generated_at.isoformat(),
        }


# --------------------------------------------------------------------- coercion
#
# The service validates numbers that arrive as JSON, where a client may legitimately
# send `1` for a float but must never send `"high"`. Each helper coerces once, in one
# place, so the failure message names the actual field instead of surfacing as an
# unrelated TypeError twenty lines into model construction.


def _req_str(payload: Mapping[str, Any], field_name: str) -> str:
    value = payload.get(field_name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{field_name}' must be a non-empty string")
    return value


def _req_float(payload: Mapping[str, Any], field_name: str) -> float:
    # `bool` is excluded explicitly: it is an `int` subclass, so a client sending
    # `"confidence": true` would otherwise score as 1.0 rather than being rejected.
    #
    # ValueError, not TypeError, on purpose (ruff TRY004). A caller validates a body from
    # a stranger and catches one type to map onto a 422; splitting the failures across two
    # exception types would make "is this body usable?" a question with two answers. These
    # are bad values in an untrusted payload, not type errors in this codebase.
    value = payload.get(field_name)
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise ValueError(f"'{field_name}' must be a number")  # noqa: TRY004
    try:
        return float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"'{field_name}' must be a number") from exc


def _opt_float(payload: Mapping[str, Any], field_name: str) -> float | None:
    value = payload.get(field_name)
    if value is None:
        return None
    return _req_float(payload, field_name)


def _req_list(
    payload: Mapping[str, Any], field_name: str
) -> Iterable[Mapping[str, Any]]:
    value = payload.get(field_name)
    if value is None:
        return ()
    if not isinstance(value, list):
        # ValueError for the reason given in `_req_float`.
        raise ValueError(f"'{field_name}' must be a list")  # noqa: TRY004
    return value
