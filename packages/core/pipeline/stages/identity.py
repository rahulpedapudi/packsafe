"""Truthful identity and typosquatting evaluation stage."""

import logging
import time

from ...models.evidence import IdentityEvidence
from ...pipeline.context import AnalysisContext
from ...sources.name_similarity import find_closest_popular_package

logger = logging.getLogger(__name__)

# Similarity at or above which a name is considered a plausible impersonation target.
POPULAR_MATCH_THRESHOLD = 0.70

# Similarity at or above which the resemblance itself is treated as typosquatting risk.
TYPOSQUATTING_THRESHOLD = 0.85


class IdentityStage:
    """Compares the package name against popular packages and checks repo consistency.

    Populates ``context.identity``. Must run after the existence and repository stages,
    since the repository URL comparison needs resolved repository evidence.
    """

    async def execute(self, context: AnalysisContext) -> None:
        start_time = time.perf_counter()
        logger.info(f"Identity Stage Started\nCurrent Context: {context}\n")

        package_name = context.package.name or ""
        ecosystem = context.package.ecosystem or "pypi"

        closest_pop, pop_sim = find_closest_popular_package(package_name, ecosystem)
        is_popular_match = pop_sim >= POPULAR_MATCH_THRESHOLD

        is_repo_mismatch = self._repo_mismatch(context)

        context.identity = IdentityEvidence(
            target_popular_package=closest_pop if is_popular_match else None,
            name_similarity=pop_sim if is_popular_match else 0.0,
            typosquatting_risk=pop_sim if pop_sim >= TYPOSQUATTING_THRESHOLD else 0.0,
            package_repo_mismatch=is_repo_mismatch,
            status=(
                "AVAILABLE"
                if context.registry.status == "AVAILABLE"
                else "MISSING"
            ),
        )

        if is_repo_mismatch:
            logger.warning(
                "Repository mismatch for %s: registry declares %s but GitHub reports %s",
                package_name,
                context.package.repository_url,
                context.repository.repository_url,
            )

        elapsed = time.perf_counter() - start_time
        logger.info(
            f"Identity Stage Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms\n"
        )

    @staticmethod
    def _repo_mismatch(context: AnalysisContext) -> bool:
        """True when the registry and the resolved repository disagree.

        Compared on a trailing-slash-stripped, lowercased basis so cosmetic URL
        differences do not register as mismatches.
        """
        declared = context.package.repository_url
        resolved = context.repository.repository_url

        if not declared or not resolved:
            return False

        return declared.rstrip("/").lower() != resolved.rstrip("/").lower()