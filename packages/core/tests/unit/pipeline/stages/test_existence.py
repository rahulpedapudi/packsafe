import pytest
from unittest.mock import AsyncMock, MagicMock

from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest, PackageIdentity, EcosystemType
from packages.core.models.evidence import RegistryEvidence, EvidenceProvenance, EvidenceStatus
from packages.core.pipeline.stages.existence import ExistenceStage
from packages.core.sources.base_registry import PackageRegistry



class TestExistence:
    @pytest.fixture
    def mock_registry(self):
        registry = AsyncMock(spec=PackageRegistry)
        return registry


    @pytest.fixture
    def stage(self, mock_registry):
        return ExistenceStage(registry=mock_registry)


    @pytest.fixture
    def context(self):
        return AnalysisContext(request=PackageRequest(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi))


    @pytest.mark.asyncio
    async def test_existence_instantiation(self, stage):
        assert stage is not None


    @pytest.mark.asyncio
    async def test_existence_found(self, stage, mock_registry, context):
        mock_identity = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi, distribution_url="https://example.com/dist", archive_hash="abc", package_url="pkg:pypi/testpkg@1.0.0", registry_integrity="good", repository_url="https://github.com/test/testpkg")
        mock_evidence = RegistryEvidence(status=EvidenceStatus.AVAILABLE, latest_version="1.0.0", release_count_1y=1, release_count_3m=1, days_since_last_release=1, project_maturity_days=1, maintainer_count=1, declared_license="MIT")
        mock_provenance = EvidenceProvenance(source="registry", source_url="https://pypi.org/project/testpkg/")
    
        mock_registry.exists.return_value = (True, (mock_identity, mock_evidence, mock_provenance, "https://example.com/dist"))
    
        await stage.execute(context)
    
        assert context.package is not None
        assert context.package.name == "testpkg"
        assert context.package.distribution_url == "https://example.com/dist"
        assert context.registry == mock_evidence
        assert mock_provenance in context.provenance


    @pytest.mark.asyncio
    async def test_existence_not_found(self, stage, mock_registry, context):
        mock_registry.exists.return_value = (False, None)
    
        await stage.execute(context)
    
        assert context.package.name is None

    @pytest.mark.asyncio
    async def test_existence_none_return(self, stage, mock_registry, context):
        mock_registry.exists.return_value = None
    
        await stage.execute(context)
    
        assert context.package.name is None
