"""Analysis coverage tier computation.

The tier records how much of the package was actually inspected, so the confidence
engine can discount a score that rests on partial evidence. Tier names must match the
``analysis_coverage_tiers`` keys in ``scoring/config/sources.yaml``.
"""

from __future__ import annotations

from .context import AnalysisContext


def compute_coverage_tier(context: AnalysisContext) -> str:
    """Returns the highest coverage tier justified by the collected evidence."""
    if context.static_analysis.status == "AVAILABLE":
        return "deep_static"

    if (
        context.repository.status == "AVAILABLE"
        and context.dependencies.status == "AVAILABLE"
    ):
        return "registry_osv_repository"

    return "registry_osv"
