import logging

from ...models.evidence import EvidenceProvenance
from ...pipeline.context import AnalysisContext
from ...sources.github import GitHubCollector
from ...tracing import pick, stage_trace

logger = logging.getLogger(__name__)


class RepositoryStage:
    async def execute(self, context: AnalysisContext) -> None | EvidenceProvenance:

        with stage_trace(
            "repository",
            logger,
            inputs=pick(context.package, ("name", "repository_url")),
            dump=context.repository,
        ) as span:
            repo_url = context.package.repository_url

            if repo_url is None:
                span.output(status="MISSING", repository_url=None)
                span.skip("no repository URL declared by the registry")
                return None

            async with GitHubCollector() as github:
                (repo_evidence, repo_evidence_provenance) = await github.collect(
                    context.package.repository_url
                )

            context.repository = repo_evidence
            if repo_evidence_provenance is not None:
                context.provenance.append(repo_evidence_provenance)

            span.output(
                **pick(
                    context.repository,
                    (
                        "status",
                        "repository_url",
                        "stars",
                        "forks",
                        "watchers",
                        "open_issues",
                        "recent_commits_90d",
                        "recent_issues_90d",
                        "is_archived",
                    ),
                )
            )
            if context.repository.status != "AVAILABLE":
                span.degrade(
                    f"github evidence unavailable for {repo_url}: "
                    f"{context.repository.status}"
                )
            return None