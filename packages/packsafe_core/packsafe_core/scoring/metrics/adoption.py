"""Adoption and popularity metrics extractor."""

from __future__ import annotations

from ...models.scoring import MetricEvidence, MetricStatus
from ...pipeline.context import AnalysisContext


class AdoptionMetricsExtractor:
    """Extracts raw metric evidence for the Adoption category.

    Metrics:
        - download_count    : number of downloads in the last 30 days (from registry evidence)
        - download_growth   : growth rate of downloads in the last 30 days (from registry evidence)
        - dependents_count  : number of dependents (from registry evidence)
        - stars_count       : number of stars (from repository evidence)
        - forks_count       : number of forks (from repository evidence)
        - watchers_count    : number of watchers (from repository evidence)
    """

    def extract_all(self, context: AnalysisContext) -> dict[str, MetricEvidence]:
        """Extracts the adoption metrics from the context."""
        results: dict[str, MetricEvidence] = {}

        reg = context.registry
        repo = context.repository

        # converting status string into MetricStatus Enum
        reg_status = (
            MetricStatus[reg.status.upper()]
            if hasattr(MetricStatus, reg.status.upper())
            else MetricStatus.AVAILABLE
        )

        repo_status = (
            MetricStatus[repo.status.upper()]
            if hasattr(MetricStatus, repo.status.upper())
            else MetricStatus.AVAILABLE
        )

        # 1. Download count (30 days)
        results["download_count"] = MetricEvidence(
            metric_name="download_count",
            raw_value=reg.downloads_30d,
            status=reg_status,
            source="registry",
            confidence=0.98,
        )

        # 2. Download growth
        dg = reg.download_growth_rate
        results["download_growth"] = MetricEvidence(
            metric_name="download_growth",
            raw_value=dg,
            status=reg_status if dg is not None else MetricStatus.MISSING,
            source="registry",
            confidence=0.95 if dg is not None else 0.0,
        )

        # 3. Dependents count
        dependents_val = getattr(reg, "dependents_count", None)
        dependents_src = getattr(reg, "dependents_source", None) or "deps_dev"

        dep_status = (
            MetricStatus.AVAILABLE
            if dependents_val is not None
            else MetricStatus.MISSING
        )

        # Source reliability: deps.dev (0.90), libraries.io fallback (0.80), missing (0.0)
        if dependents_val is not None:
            dep_conf = 0.90 if dependents_src == "deps_dev" else 0.80
        else:
            dep_conf = 0.0

        results["dependents_count"] = MetricEvidence(
            metric_name="dependents_count",
            raw_value=dependents_val,
            status=dep_status,
            source=dependents_src if dependents_val is not None else "deps_dev",
            confidence=dep_conf,
        )

        # 4. Stars
        results["stars_count"] = MetricEvidence(
            metric_name="stars_count",
            raw_value=repo.stars,
            status=repo_status,
            source="github",
            confidence=0.95,
        )

        # 5. Forks
        results["forks_count"] = MetricEvidence(
            metric_name="forks_count",
            raw_value=repo.forks,
            status=repo_status,
            source="github",
            confidence=0.95,
        )

        # 6. Watchers
        results["watchers_count"] = MetricEvidence(
            metric_name="watchers_count",
            raw_value=repo.watchers,
            status=repo_status,
            source="github",
            confidence=0.95,
        )

        return results
