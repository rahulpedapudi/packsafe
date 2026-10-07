import pytest
from unittest.mock import AsyncMock

from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest, PackageIdentity, EcosystemType
from packages.core.models.evidence import RegistryEvidence, EvidenceStatus
from packages.core.models.dependencies import DependencyEvidence
from packages.core.pipeline.stages.dependency import DependencyStage



class TestDependency:
    @pytest.fixture
    def stage(self):
        s = DependencyStage()
        s.deps_dev = AsyncMock()
        return s


    @pytest.fixture
    def context(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi))
        ctx.package = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi)
        ctx.registry = RegistryEvidence(status=EvidenceStatus.AVAILABLE)
        return ctx


    @pytest.mark.asyncio
    async def test_dependency_instantiation(self, stage):
        assert stage is not None


    @pytest.mark.asyncio
    async def test_dependency_successful(self, stage, context):
        mock_dep_evidence = DependencyEvidence(status=EvidenceStatus.AVAILABLE, direct_count=2, transitive_count=5)
        stage.deps_dev.collect_dependencies.return_value = mock_dep_evidence
        stage.deps_dev.collect_dependents_count.return_value = (100, "deps.dev")
    
        await stage.execute(context)
    
        assert context.dependencies == mock_dep_evidence
        assert context.registry.dependents_count == 100
        assert context.registry.dependents_source == "deps.dev"


    @pytest.mark.asyncio
    async def test_dependency_unavailable(self, stage, context):
        mock_dep_evidence = DependencyEvidence(status=EvidenceStatus.MISSING)
        stage.deps_dev.collect_dependencies.return_value = mock_dep_evidence
        stage.deps_dev.collect_dependents_count.return_value = (None, None)
    
        await stage.execute(context)
    
        assert context.dependencies.status == EvidenceStatus.MISSING
        assert context.registry.dependents_count is None


    @pytest.mark.asyncio
    async def test_dependency_exception(self, stage, context):
        stage.deps_dev.collect_dependencies.side_effect = Exception("network error")
    
        with pytest.raises(Exception):
            await stage.execute(context)
