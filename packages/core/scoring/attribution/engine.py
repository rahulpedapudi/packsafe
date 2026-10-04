"""Attribution Engine for deterministic score explainability with granular metric records."""

from __future__ import annotations

import logging

from ...models.scoring import (
    CategoryScore,
    Decision,
    GateResult,
    MetricAttribution,
    MetricResult,
    MetricStatus,
    RiskLevel,
    ScoreAttribution,
)
from ..config import EngineConfig

logger = logging.getLogger(__name__)


class AttributionEngine:
    """Explains score contributions, positive/negative drivers, and developer actions."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def generate(
        self,
        categories: dict[str, CategoryScore],
        metric_results: dict[str, MetricResult],
        gates: tuple[GateResult, ...] | list[GateResult],
        final_score: float,
        risk_level: RiskLevel,
        decision: Decision,
    ) -> ScoreAttribution:
        category_contributions: dict[str, float] = {}
        for cat_name, cat_score in categories.items():
            category_contributions[cat_name] = round(cat_score.contribution, 2)

        metric_attributions: list[MetricAttribution] = []
        positive_drivers: list[tuple[float, str]] = []
        negative_drivers: list[tuple[float, str]] = []

        for m_name, m_res in metric_results.items():
            metric_def = self.config.metrics.get(m_name)
            cat_name = metric_def.category if metric_def else "unknown"
            cat_weight = self.config.category_weights.get(cat_name, 0.0)

            attr = MetricAttribution(
                category=cat_name,
                metric=m_name,
                raw_value=m_res.raw_value,
                normalized_value=round(m_res.normalized_value, 4)
                if m_res.normalized_value is not None
                else None,
                metric_weight=m_res.weight,
                metric_contribution=round(m_res.contribution, 2),
                category_weight=cat_weight,
                source=m_res.source,
                evidence_status=m_res.status.value,
                confidence=round(m_res.confidence, 2),
                explanation=m_res.explanation,
            )
            metric_attributions.append(attr)

            if (
                m_res.status == MetricStatus.AVAILABLE
                and m_res.normalized_value is not None
            ):
                # Rank top drivers
                impact = m_res.weight * (m_res.normalized_value - 0.5)
                if m_res.normalized_value >= 0.85:
                    positive_drivers.append(
                        (
                            impact,
                            f"+ {m_res.explanation} (score: {m_res.normalized_value:.2f})",
                        )
                    )
                elif m_res.normalized_value <= 0.40:
                    negative_drivers.append(
                        (
                            abs(impact),
                            f"- {m_res.explanation} (score: {m_res.normalized_value:.2f})",
                        )
                    )

        # Sort drivers by absolute impact
        positive_drivers.sort(key=lambda x: x[0], reverse=True)
        negative_drivers.sort(key=lambda x: x[0], reverse=True)

        top_pos = [d[1] for d in positive_drivers[:4]]
        top_neg = [d[1] for d in negative_drivers[:4]]

        # Gate overrides if triggered
        triggered_gates = [g for g in gates if g.triggered]
        if triggered_gates:
            for g in triggered_gates:
                top_neg.insert(0, f"CRITICAL GATE: {g.reason}")

        # Primary recommendation
        if decision == Decision.BLOCK:
            rec = "Do NOT install this package. It triggered a non-compensable security block or critical risk threshold."
        elif decision == Decision.WARN:
            rec = "Review package findings before installing. Potential supply chain, maintenance, or integrity risks detected."
        elif decision == Decision.REVIEW:
            rec = "Review required against organization policy (e.g. license compliance or package authorization)."
        else:
            rec = "Package exhibits a healthy security posture and meets standard acceptance criteria."

        logger.info(
            "attribution | category_contributions=%s | top_positive=%d top_negative=%d "
            "| decision=%s -> recommendation=%s",
            category_contributions,
            len(top_pos),
            len(top_neg),
            decision.value,
            rec,
        )
        for signal in top_pos:
            logger.info("attribution driver (positive) | %s", signal)
        for signal in top_neg:
            logger.warning("attribution driver (negative) | %s", signal)

        return ScoreAttribution(
            category_contributions=category_contributions,
            metric_attributions=tuple(metric_attributions),
            top_positive_signals=tuple(top_pos),
            top_negative_signals=tuple(top_neg),
            primary_recommendation=rec,
        )
