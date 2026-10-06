"""Category Scoring Engine for computing multi-dimensional scores with missing-category exclusion."""

from __future__ import annotations

import logging

from ...models.scoring import CategoryScore, MetricResult, MetricStatus
from ...tracing import fmt_fields
from ..config import EngineConfig

logger = logging.getLogger(__name__)


class CategoryScoringEngine:
    """Computes scores for each of the five PackSafe categories using available metrics."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def calculate_category(
        self,
        category_name: str,
        category_metrics: list[MetricResult],
    ) -> CategoryScore:
        """Calculates a single category score using relative weights of AVAILABLE metrics."""
        category_weight = self.config.category_weights.get(category_name, 0.0)

        total_applicable_weight = sum(m.weight for m in category_metrics)
        available_metrics = [
            m for m in category_metrics if m.normalized_value is not None
        ]

        available_weight = sum(m.weight for m in available_metrics)

        if available_weight <= 0.0:
            # Entire category is missing: mark status MISSING and exclude from score calculation
            logger.info(
                "category=%s | EXCLUDED from score | score=0.00 | no metric had usable "
                "evidence (applicable_weight=%.4f across %d metrics) | %s",
                category_name,
                total_applicable_weight,
                len(category_metrics),
                fmt_fields(
                    {m.metric_name: m.status.value for m in category_metrics}
                ),
            )
            return CategoryScore(
                name=category_name,
                score=0.0,
                weight=category_weight,
                contribution=0.0,
                metrics=tuple(category_metrics),
                available_weight=0.0,
                total_applicable_weight=total_applicable_weight,
                status=MetricStatus.MISSING,
            )

        # Weighted sum: sum(w_i * norm_i) / sum(w_i) * 100
        weighted_sum = sum(m.weight * m.normalized_value for m in available_metrics)  # type: ignore
        raw_cat_score = (weighted_sum / available_weight) * 100.0
        cat_score = max(0.0, min(100.0, raw_cat_score))

        # Build updated metric results with immutable contribution
        updated_metrics: list[MetricResult] = []
        for m in category_metrics:
            if m.normalized_value is not None:
                contrib = (m.weight * m.normalized_value / available_weight) * 100.0
            else:
                contrib = 0.0
            updated_metrics.append(
                MetricResult(
                    metric_name=m.metric_name,
                    raw_value=m.raw_value,
                    normalized_value=m.normalized_value,
                    weight=m.weight,
                    contribution=contrib,
                    status=m.status,
                    source=m.source,
                    confidence=m.confidence,
                    explanation=m.explanation,
                )
            )

        contribution = cat_score * category_weight

        logger.info(
            "category=%s | score=%.4f weight=%.4f contribution=%.4f | "
            "weighted_sum=%.4f / available_weight=%.4f * 100 | coverage=%d/%d metrics "
            "(%d dropped: %s)",
            category_name,
            cat_score,
            category_weight,
            contribution,
            weighted_sum,
            available_weight,
            len(available_metrics),
            len(category_metrics),
            len(category_metrics) - len(available_metrics),
            fmt_fields(
                {
                    m.metric_name: m.status.value
                    for m in category_metrics
                    if m.normalized_value is None
                }
            ),
        )
        for m in sorted(available_metrics, key=lambda m: m.weight, reverse=True):
            logger.debug(
                "category=%s metric=%s raw=%s normalized=%.4f weight=%.4f "
                "contribution=%.4f source=%s confidence=%.2f",
                category_name,
                m.metric_name,
                m.raw_value,
                m.normalized_value,  # type: ignore[arg-type]
                m.weight,
                m.contribution,
                m.source,
                m.confidence,
            )

        return CategoryScore(
            name=category_name,
            score=cat_score,
            weight=category_weight,
            contribution=contribution,
            metrics=tuple(updated_metrics),
            available_weight=available_weight,
            total_applicable_weight=total_applicable_weight,
            status=MetricStatus.AVAILABLE,
        )

    def calculate_all(
        self,
        all_metric_results: dict[str, MetricResult],
    ) -> dict[str, CategoryScore]:
        """Calculates scores for all five categories."""
        grouped: dict[str, list[MetricResult]] = {
            "security": [],
            "integrity": [],
            "supply_chain": [],
            "maintenance": [],
            "adoption": [],
        }

        for metric_name, m_res in all_metric_results.items():
            metric_def = self.config.metrics.get(metric_name)
            if metric_def and metric_def.affects_categories:
                cats = metric_def.affects_categories
            elif metric_def:
                cats = (metric_def.category,)
            else:
                cats = ("integrity",)

            for cat in cats:
                if cat in grouped:
                    grouped[cat].append(m_res)

        category_scores: dict[str, CategoryScore] = {}
        for cat_name, metrics in grouped.items():
            category_scores[cat_name] = self.calculate_category(cat_name, metrics)

        return category_scores
