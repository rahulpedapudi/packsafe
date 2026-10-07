import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from dataclasses import replace

from packages.core.pipeline.analysis import AnalysisPipeline
from packages.core.models.package import PackageRequest, EcosystemType
from packages.core.exceptions import PackageNotFoundError
from packages.core.models.scoring import ScoreResult


class TestAnalysisPipeline:
    @pytest.fixture
    def pipeline(self):
        return AnalysisPipeline()

    @pytest.fixture
    def request_pypi(self):
        return PackageRequest(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi)

    @pytest.mark.asyncio
    async def test_an_001_initialization(self, pipeline):
        assert pipeline is not None

    @pytest.mark.asyncio
    @patch('packages.core.pipeline.analysis.ExistenceStage')
    @patch('packages.core.pipeline.analysis.VulnerabilityStage')
    @patch('packages.core.pipeline.analysis.RepositoryStage')
    @patch('packages.core.pipeline.analysis.DependencyStage')
    @patch('packages.core.pipeline.analysis.ArchiveStage')
    @patch('packages.core.pipeline.analysis.LicenseStage')
    @patch('packages.core.pipeline.analysis.IdentityStage')
    @patch('packages.core.pipeline.analysis.ScoreEngine')
    async def test_an_003_normal_execution(
        self,
        MockScoreEngine, MockId, MockLic, MockArch, MockDep, MockRepo, MockVuln, MockExist,
        pipeline, request_pypi
    ):
        mock_score = MagicMock()
        mock_score.final_score = 85.0
        MockScoreEngine.return_value.calculate.return_value = mock_score
        
        async def mock_existence_exec(context):
            context.package = replace(context.package, name="testpkg")
        
        MockExist.return_value.execute = AsyncMock(side_effect=mock_existence_exec)
        MockVuln.return_value.execute = AsyncMock()
        MockRepo.return_value.execute = AsyncMock()
        MockDep.return_value.execute = AsyncMock()
        MockArch.return_value.execute = AsyncMock()
        MockLic.return_value.execute = AsyncMock()
        MockId.return_value.execute = AsyncMock()

        outcome = await pipeline.run_detailed(request_pypi)
        
        assert outcome.score.final_score == 85.0
        assert outcome.context.request.name == "testpkg"
        MockScoreEngine.return_value.calculate.assert_called_once()
        
    @pytest.mark.asyncio
    @patch('packages.core.pipeline.analysis.ExistenceStage')
    async def test_an_011_package_not_found(self, MockExist, pipeline, request_pypi):
        async def mock_existence_exec(context):
            context.package = replace(context.package, name=None)
            
        MockExist.return_value.execute = AsyncMock(side_effect=mock_existence_exec)
        
        with pytest.raises(PackageNotFoundError):
            await pipeline.run_detailed(request_pypi)
            
    @pytest.mark.asyncio
    @patch('packages.core.pipeline.analysis.AnalysisPipeline.run_detailed')
    async def test_an_004_run_returns_score(self, mock_run_detailed, pipeline, request_pypi):
        mock_score = MagicMock()
        mock_outcome = MagicMock()
        mock_outcome.score = mock_score
        mock_run_detailed.return_value = mock_outcome
        
        result = await pipeline.run(request_pypi)
        assert result == mock_score
