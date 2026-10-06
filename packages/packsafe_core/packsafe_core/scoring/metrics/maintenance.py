"""Maintenance health and activity metrics extractor."""

from __future__ import annotations

from datetime import UTC, datetime

from ...models.scoring import MetricEvidence, MetricStatus
from ...pipeline.context import AnalysisContext


class MaintenanceMetricsExtractor:
    """Extracts raw metric evidence for the Maintenance category.

    Metrics:
        - days_since_last_release   : float - Number of days since the last release. | (from registry_evidence)
        - releases_last_year        : float - Number of releases in the last year. | (from registry_evidence)
        - releases_last_3_months    : float - Number of releases in the last 3 months. | (from registry_evidence)
        - recent_commits            : float - Number of commits in the last 90 days. | (from repository_evidence)
        - recent_issue_activity     : float - Number of issues in the last 90 days. | (from repository_evidence)
        - maintainer_count          : float - Number of maintainers. | (from registry_evidence)
        - repository_archived       : bool  - Whether the repository is archived. | (from repository_evidence)
        - project_maturity_days     : float - Number of days since the project was created. | (from registry_evidence)
    """

    def extract_all(self, context: AnalysisContext) -> dict[str, MetricEvidence]:
        """Extracts the maintenance metrics from the context."""

        results: dict[str, MetricEvidence] = {}
        reg = context.registry
        repo = context.repository

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

        # 1. Days since last release
        days_release = reg.days_since_last_release
        if days_release == 0.0 and reg.published_at:
            delta = datetime.now(UTC) - reg.published_at
            days_release = max(0.0, float(delta.days))

        results["days_since_last_release"] = MetricEvidence(
            metric_name="days_since_last_release",
            raw_value=days_release,
            status=reg_status,
            source="registry",
            confidence=0.98,
        )

        # 2. Releases in last year
        results["releases_last_year"] = MetricEvidence(
            metric_name="releases_last_year",
            raw_value=reg.release_count_1y,
            status=reg_status,
            source="registry",
            confidence=0.98,
        )

        # 3. Releases in last 3 months
        results["releases_last_3_months"] = MetricEvidence(
            metric_name="releases_last_3_months",
            raw_value=reg.release_count_3m,
            status=reg_status,
            source="registry",
            confidence=0.98,
        )

        # 4. Recent commits (90 days)
        results["recent_commits"] = MetricEvidence(
            metric_name="recent_commits",
            raw_value=repo.recent_commits_90d,
            status=repo_status,
            source="github",
            confidence=0.95,
        )

        # 5. Recent issue activity (90 days)
        results["recent_issue_activity"] = MetricEvidence(
            metric_name="recent_issue_activity",
            raw_value=repo.recent_issues_90d,
            status=repo_status,
            source="github",
            confidence=0.95,
        )

        # 6. Maintainer count
        m_count = reg.maintainer_count
        results["maintainer_count"] = MetricEvidence(
            metric_name="maintainer_count",
            raw_value=m_count,
            status=reg_status if m_count is not None else MetricStatus.MISSING,
            source="registry",
            confidence=0.95 if m_count is not None else 0.0,
        )

        # 7. Repository archived (boolean: True = archived)
        results["repository_archived"] = MetricEvidence(
            metric_name="repository_archived",
            raw_value=repo.is_archived,
            status=repo_status,
            source="github",
            confidence=0.98,
        )

        # 8. Project maturity days
        results["project_maturity_days"] = MetricEvidence(
            metric_name="project_maturity_days",
            raw_value=reg.project_maturity_days,
            status=reg_status,
            source="registry",
            confidence=0.95,
        )

        return results
