import logging
import time

from ...models.evidence import EvidenceProvenance
from ...pipeline.context import AnalysisContext
from ...sources.github import GitHubCollector

logger = logging.getLogger(__name__)


class RepositoryStage:
    async def execute(self, context: AnalysisContext) -> None | EvidenceProvenance:

        start_time = time.perf_counter()
        logger.info(f"Repostory Stage Started\nCurrent Context: {context}\n")

        repo_url = context.package.repository_url

        if repo_url is not None:
            async with GitHubCollector() as github:
                (repo_evidence, repo_evidence_provenance) = await github.collect(
                    context.package.repository_url
                )

            context.repository = repo_evidence
            context.provenance += repo_evidence_provenance

            end_time = time.perf_counter() - start_time

            logger.info(
                f"Repository Stage Completed in {end_time:.2f} seconds | {end_time * 1000:.2f} ms\n"
            )
