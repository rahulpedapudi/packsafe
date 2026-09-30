"""Supply Chain dependency metrics extractor."""

from __future__ import annotations

from typing import Any
from packsafe.evidence.models import PackageEvidence
from packsafe.scoring.models import MetricEvidence, MetricStatus


class SupplyChainMetricsExtractor:
    """Extracts raw metric evidence for the Supply Chain category."""

    def extract_all(self, evidence: PackageEvidence) -> dict[str, MetricEvidence]:
        results: dict[str, MetricEvidence] = {}
        deps = evidence.dependencies
        status = MetricStatus[deps.status.upper()] if hasattr(MetricStatus, deps.status.upper()) else MetricStatus.AVAILABLE

        # Counts
        direct_count = deps.direct_count or len(deps.direct_dependencies)
        transitive_count = deps.transitive_count or len(deps.transitive_dependencies)
        depth = deps.max_depth or (1 if direct_count > 0 else 0)

        # Vulnerable dependencies
        direct_vuln_count = sum(1 for d in deps.direct_dependencies if d.vulnerabilities)
        transitive_vuln_count = sum(1 for d in deps.transitive_dependencies if d.vulnerabilities)
        vuln_exposure = deps.vulnerable_dependency_count or (direct_vuln_count + 0.5 * transitive_vuln_count)

        # Abandoned / new / churn
        abandoned_count = deps.abandoned_count or sum(1 for d in deps.direct_dependencies + deps.transitive_dependencies if d.is_archived)
        new_count = deps.new_dependencies_count
        churn = deps.churn_rate

        results["direct_dependency_count"] = MetricEvidence(
            metric_name="direct_dependency_count",
            raw_value=direct_count,
            status=status,
            source="registry",
            confidence=0.98,
        )

        results["transitive_dependency_count"] = MetricEvidence(
            metric_name="transitive_dependency_count",
            raw_value=transitive_count,
            status=status,
            source="deps_dev",
            confidence=0.92,
        )

        results["dependency_depth"] = MetricEvidence(
            metric_name="dependency_depth",
            raw_value=depth,
            status=status,
            source="deps_dev",
            confidence=0.92,
        )

        results["dependency_vulnerability_exposure"] = MetricEvidence(
            metric_name="dependency_vulnerability_exposure",
            raw_value=vuln_exposure,
            status=status,
            source="deps_dev",
            confidence=0.92,
        )

        results["direct_vulnerable_deps"] = MetricEvidence(
            metric_name="direct_vulnerable_deps",
            raw_value=direct_vuln_count,
            status=status,
            source="deps_dev",
            confidence=0.92,
        )

        results["transitive_vulnerable_deps"] = MetricEvidence(
            metric_name="transitive_vulnerable_deps",
            raw_value=transitive_vuln_count,
            status=status,
            source="deps_dev",
            confidence=0.90,
        )

        results["abandoned_dependencies"] = MetricEvidence(
            metric_name="abandoned_dependencies",
            raw_value=abandoned_count,
            status=status,
            source="deps_dev",
            confidence=0.90,
        )

        results["new_dependencies"] = MetricEvidence(
            metric_name="new_dependencies",
            raw_value=new_count,
            status=status if new_count is not None else MetricStatus.MISSING,
            source="deps_dev",
            confidence=0.90 if new_count is not None else 0.0,
        )

        results["dependency_churn"] = MetricEvidence(
            metric_name="dependency_churn",
            raw_value=churn,
            status=status if churn is not None else MetricStatus.MISSING,
            source="deps_dev",
            confidence=0.90 if churn is not None else 0.0,
        )

        return results
