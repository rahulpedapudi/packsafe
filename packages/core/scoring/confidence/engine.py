"""Weighted Confidence Engine."""

from __future__ import annotations

from packsafe.evidence.models import PackageEvidence
from packsafe.scoring.config import EngineConfig
from packsafe.scoring.models import MetricResult, MetricStatus


class ConfidenceEngine:
    """Calculates evidence completeness, weighted source reliability, and analysis coverage."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def calculate(
        self,
        evidence: PackageEvidence,
        metric_results: dict[str, MetricResult],
    ) -> float:
        """Calculates confidence in [0.0, 100.0]."""
        applicable_metrics = [
            m for m in metric_results.values()
            if m.status != MetricStatus.NOT_APPLICABLE
        ]
        available_metrics = [
            m for m in applicable_metrics
            if m.status in (MetricStatus.AVAILABLE, MetricStatus.STALE) and m.normalized_value is not None
        ]

        if not applicable_metrics:
            return 0.0

        # 1. Category-Weighted Evidence Coverage
        cat_weights = self.config.category_weights
        cats: dict[str, list[MetricResult]] = {}
        for m in applicable_metrics:
            m_def = self.config.metrics.get(m.metric_name)
            cat = m_def.category if m_def else "unknown"
            cats.setdefault(cat, []).append(m)

        total_coverage = 0.0
        for cat, metrics in cats.items():
            cat_w = cat_weights.get(cat, 0.0)
            tot_m_w = sum(m.weight for m in metrics)
            avail_m_w = sum(m.weight for m in metrics if m.status == MetricStatus.AVAILABLE and m.normalized_value is not None)
            stale_m_w = sum(m.weight * 0.4 for m in metrics if m.status == MetricStatus.STALE and m.normalized_value is not None)
            if tot_m_w > 0:
                total_coverage += cat_w * ((avail_m_w + stale_m_w) / tot_m_w)

        # 2. Weighted Source Reliability
        available_metrics = [
            m for m in applicable_metrics
            if m.status in (MetricStatus.AVAILABLE, MetricStatus.STALE) and m.normalized_value is not None
        ]
        available_weight = sum(m.weight for m in available_metrics)
        if available_weight > 0:
            weighted_source_sum = 0.0
            for m in available_metrics:
                src = m.source.lower()
                rel = self.config.sources.get(src, 0.80)
                if m.status == MetricStatus.STALE:
                    rel *= 0.5
                weighted_source_sum += m.weight * rel
            weighted_source_reliability = weighted_source_sum / available_weight
        else:
            weighted_source_reliability = 0.50

        # 3. Analysis Coverage
        tier = getattr(evidence, "analysis_coverage_tier", "deep_static").lower()
        analysis_coverage = self.config.analysis_coverage_tiers.get(tier, 1.00)

        # 4. Final calculation
        raw_conf = 100.0 * total_coverage * weighted_source_reliability * analysis_coverage
        return round(max(0.0, min(100.0, raw_conf)), 2)
