import pytest
from unittest.mock import patch

from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest, PackageIdentity, EcosystemType
from packages.core.models.evidence import RegistryEvidence, RepositoryEvidence, EvidenceStatus
from packages.core.pipeline.stages.identity import IdentityStage



class TestIdentity:
    @pytest.fixture
    def stage(self):
        return IdentityStage()


    @pytest.fixture
    def context(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi))
        ctx.package = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi, repository_url="https://github.com/test/repo")
        ctx.registry = RegistryEvidence(status=EvidenceStatus.AVAILABLE)
        ctx.repository = RepositoryEvidence(status=EvidenceStatus.AVAILABLE, repository_url="https://github.com/test/repo")
        return ctx


    @pytest.mark.asyncio
    async def test_identity_instantiation(self, stage):
        assert stage is not None


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_normal(self, mock_find, stage, context):
        mock_find.return_value = (None, 0.0)
    
        await stage.execute(context)
    
        assert context.identity.status == EvidenceStatus.AVAILABLE
        assert context.identity.target_popular_package is None
        assert context.identity.name_similarity == 0.0
        assert context.identity.typosquatting_risk == 0.0
        assert context.identity.package_repo_mismatch is False


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_popular_match(self, mock_find, stage, context):
        mock_find.return_value = ("popularpkg", 0.75)
    
        await stage.execute(context)
    
        assert context.identity.target_popular_package == "popularpkg"
        assert context.identity.name_similarity == 0.75
        # threshold for typosquatting is 0.85
        assert context.identity.typosquatting_risk == 0.0


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_typosquatting(self, mock_find, stage, context):
        mock_find.return_value = ("requests", 0.95)
    
        await stage.execute(context)
    
        assert context.identity.target_popular_package == "requests"
        assert context.identity.name_similarity == 0.95
        assert context.identity.typosquatting_risk == 0.95


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_repo_mismatch(self, mock_find, stage, context):
        mock_find.return_value = (None, 0.0)
    
        context.package = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi, repository_url="https://github.com/test/repo")
        context.repository = RepositoryEvidence(status=EvidenceStatus.AVAILABLE, repository_url="https://github.com/hacker/repo")
    
        await stage.execute(context)
    
        assert context.identity.package_repo_mismatch is True


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_repo_mismatch_ignore_slash(self, mock_find, stage, context):
        mock_find.return_value = (None, 0.0)
    
        context.package = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi, repository_url="https://github.com/test/repo/")
        context.repository = RepositoryEvidence(status=EvidenceStatus.AVAILABLE, repository_url="https://github.com/test/repo")
    
        await stage.execute(context)
    
        assert context.identity.package_repo_mismatch is False


    @pytest.mark.asyncio
    @patch("packages.core.pipeline.stages.identity.find_closest_popular_package")
    async def test_identity_missing_registry(self, mock_find, stage, context):
        mock_find.return_value = (None, 0.0)
        context.registry.status = EvidenceStatus.MISSING
    
        await stage.execute(context)
    
        assert context.identity.status == EvidenceStatus.MISSING
