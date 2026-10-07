from unittest.mock import AsyncMock, patch

import pytest
from packsafe_core.models.evidence import (
    EvidenceProvenance,
    EvidenceStatus,
    RepositoryEvidence,
)
from packsafe_core.models.package import EcosystemType, PackageIdentity, PackageRequest
from packsafe_core.pipeline.context import AnalysisContext
from packsafe_core.pipeline.stages.repository import RepositoryStage


class TestRepository:
    @pytest.fixture
    def stage(self):
        return RepositoryStage()

    @pytest.fixture
    def context(self):
        ctx = AnalysisContext(
            request=PackageRequest(
                name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi
            )
        )
        ctx.package = PackageIdentity(
            name="testpkg",
            version="1.0.0",
            ecosystem=EcosystemType.pypi,
            repository_url="https://github.com/test/repo",
        )
        return ctx

    @pytest.mark.asyncio
    async def test_repository_instantiation(self, stage):
        assert stage is not None

    @pytest.mark.asyncio
    async def test_repository_no_url(self, stage, context):
        context.package = PackageIdentity(
            name="testpkg",
            version="1.0.0",
            ecosystem=EcosystemType.pypi,
            repository_url=None,
        )
        await stage.execute(context)

        # context.repository is left untouched

    @pytest.mark.asyncio
    @patch("packsafe_core.pipeline.stages.repository.GitHubCollector")
    async def test_repository_successful(self, mock_github_cls, stage, context):
        mock_github = AsyncMock()
        mock_github_cls.return_value = mock_github
        mock_github.__aenter__.return_value = mock_github

        mock_evidence = RepositoryEvidence(
            status=EvidenceStatus.AVAILABLE,
            repository_url="https://github.com/test/repo",
            stars=10,
        )
        mock_provenance = EvidenceProvenance(
            source="github", source_url="https://api.github.com/repos/test/repo"
        )

        mock_github.collect.return_value = (mock_evidence, mock_provenance)

        await stage.execute(context)

        assert context.repository == mock_evidence
        assert mock_provenance in context.provenance

    @pytest.mark.asyncio
    @patch("packsafe_core.pipeline.stages.repository.GitHubCollector")
    async def test_repository_missing(self, mock_github_cls, stage, context):
        mock_github = AsyncMock()
        mock_github_cls.return_value = mock_github
        mock_github.__aenter__.return_value = mock_github

        mock_evidence = RepositoryEvidence(
            status=EvidenceStatus.MISSING, repository_url=None
        )
        mock_github.collect.return_value = (mock_evidence, None)

        await stage.execute(context)

        assert context.repository.status == EvidenceStatus.MISSING

    @pytest.mark.asyncio
    @patch("packsafe_core.pipeline.stages.repository.GitHubCollector")
    async def test_repository_exception_propagates_or_handled(
        self, mock_github_cls, stage, context
    ):
        mock_github = AsyncMock()
        mock_github_cls.return_value = mock_github
        mock_github.__aenter__.return_value = mock_github

        mock_github.collect.side_effect = Exception("github error")

        with pytest.raises(Exception):
            await stage.execute(context)
