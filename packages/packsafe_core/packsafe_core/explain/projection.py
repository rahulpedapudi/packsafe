"""Reduces a finished :class:`AnalysisOutcome` to the :class:`ExplainRequest` the service accepts.

This is the only place that decides what leaves the machine. Keeping the reduction in one
pure, testable function - rather than scattering field picks across a CLI command - means
the redaction has a single chokepoint, and that adding an attacker-controlled field to
``ScoreResult`` cannot accidentally ship it: it has to be named here to travel.

What is dropped, and why, is documented on the contract's ``FindingExplain``. The short
version is that ``Finding.evidence`` is a code snippet copied out of an archive the
package author controls.
"""

from __future__ import annotations

from enum import Enum
from typing import Any

from ..models.result import AnalysisOutcome
from .contract import (
    CategoryExplain,
    ExplainRequest,
    FindingExplain,
    GateExplain,
    MetricExplain,
)

# The engine can emit a long tail of metrics; the most influential ones per category carry
# the explanation. Truncating by contribution keeps the prompt bounded without letting it
# be dominated by metrics that barely moved the number.
MAX_METRICS = 24


def _enum_value(value: Any) -> str:
    """Renders an enum or a plain string as its label.

    ``RiskLevel``, ``Decision`` and friends are ``str`` enums, but the dataclasses that
    hold them are not coerced on construction, so the same field can arrive as either.
    Normalizing once here keeps the projection from raising ``AttributeError`` on a
    hand-assembled score, and keeps ``risk_level`` from serializing as ``RiskLevel.CRITICAL``
    when the engine happened to pass the enum rather than its value.
    """
    return value.value if isinstance(value, Enum) else str(value)


def build_explain_request(outcome: AnalysisOutcome) -> ExplainRequest:
    """Projects a completed analysis onto the explanation wire format."""
    score = outcome.score
    attribution = score.attribution
    ctx = outcome.context

    return ExplainRequest(
        package_name=score.package_name or ctx.request.name,
        version=score.version or ctx.package.version or "unknown",
        # `ScoreResult.ecosystem` is populated from `PackageRequest.ecosystem`, which is a
        # `PackageIdentity.ecosystem` enum - so without normalizing it the payload would
        # serialize the literal string "EcosystemType.pypi".
        ecosystem=_enum_value(score.ecosystem or ctx.request.ecosystem),
        final_score=score.final_score,
        base_score=score.base_score,
        risk_level=_enum_value(score.risk_level),
        decision=_enum_value(score.decision),
        confidence=score.confidence,
        categories=tuple(
            CategoryExplain(
                name=name,
                score=cat.score,
                weight=cat.weight,
                contribution=cat.contribution,
                # `CategoryScore.status` is annotated as a MetricStatus but nothing
                # coerces it, so a score assembled from plain strings arrives with a str.
                # Accepting both is cheaper than assuming the annotation holds.
                status=_enum_value(cat.status),
            )
            for name, cat in score.categories.items()
        ),
        metrics=_top_metrics(attribution.metric_attributions),
        # Title and severity only. `evidence` and `description` stay behind.
        findings=tuple(
            FindingExplain(
                title=f.title,
                severity=f.severity,
                category=f.category,
                confidence=f.confidence,
            )
            for f in score.findings
        ),
        # `reason` is engine-authored text from gates.yaml; `evidence_ids` embeds archive
        # file paths and is withheld.
        gates=tuple(
            GateExplain(
                gate_id=g.gate_id,
                triggered=g.triggered,
                severity=_enum_value(g.severity),
                reason=g.reason,
                decision_override=(
                    _enum_value(g.decision_override) if g.decision_override else None
                ),
            )
            for g in score.gates
        ),
        top_positive_signals=attribution.top_positive_signals,
        top_negative_signals=attribution.top_negative_signals,
        engine_version=score.engine_version,
        config_version=score.config_version,
        config_sha256=score.config_sha256,
        coverage_tier=ctx.analysis_coverage_tier,
    )


def _top_metrics(attributions) -> tuple[MetricExplain, ...]:
    """Keeps the metrics that actually moved the score.

    Measured metrics outrank unmeasured ones: a metric with no evidence contributes
    nothing, so spending prompt budget on it teaches the model nothing. Within each
    group, the largest absolute contribution wins.
    """
    measured = [a for a in attributions if a.normalized_value is not None]
    unmeasured = [a for a in attributions if a.normalized_value is None]

    measured.sort(key=lambda a: abs(a.metric_contribution), reverse=True)
    unmeasured.sort(key=lambda a: abs(a.metric_contribution), reverse=True)

    kept = (measured + unmeasured)[:MAX_METRICS]
    return tuple(
        MetricExplain(
            category=a.category,
            metric=a.metric,
            normalized_value=a.normalized_value,
            weight=a.metric_weight,
            contribution=a.metric_contribution,
            evidence_status=a.evidence_status,
            explanation=a.explanation,
        )
        for a in kept
    )