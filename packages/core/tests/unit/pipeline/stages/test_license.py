import pytest
from unittest.mock import MagicMock

from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest, PackageIdentity, EcosystemType
from packages.core.models.evidence import RegistryEvidence, LicenseEvidence, EvidenceStatus
from packages.core.pipeline.stages.license import LicenseStage
from packages.core.analysis.license.analyzer import LicenseAnalyzer



class TestLicense:
    @pytest.fixture
    def mock_analyzer(self):
        return MagicMock(spec=LicenseAnalyzer)


    @pytest.fixture
    def stage(self, mock_analyzer):
        return LicenseStage(analyzer=mock_analyzer)


    @pytest.fixture
    def context(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi))
        ctx.package = PackageIdentity(name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi)
        ctx.registry = RegistryEvidence(status=EvidenceStatus.AVAILABLE, declared_license="MIT")
        ctx.license_file_found = True
        return ctx


    @pytest.mark.asyncio
    async def test_license_instantiation(self, stage):
        assert stage is not None


    @pytest.mark.asyncio
    async def test_license_successful(self, stage, mock_analyzer, context):
        mock_license = LicenseEvidence(status=EvidenceStatus.AVAILABLE, declared_license="MIT", spdx_id="MIT", is_osi_approved=True, is_copyleft=False, license_file_present=True)
        mock_analyzer.analyze.return_value = mock_license
    
        await stage.execute(context)
    
        assert context.license == mock_license
        mock_analyzer.analyze.assert_called_once_with("MIT", license_file_found=True)


    @pytest.mark.asyncio
    async def test_license_missing_file(self, stage, mock_analyzer, context):
        context.license_file_found = False
        mock_license = LicenseEvidence(status=EvidenceStatus.AVAILABLE, declared_license="MIT", spdx_id="MIT", is_osi_approved=True, is_copyleft=False, license_file_present=False)
        mock_analyzer.analyze.return_value = mock_license
    
        await stage.execute(context)
    
        assert context.license == mock_license
        mock_analyzer.analyze.assert_called_once_with("MIT", license_file_found=False)


    @pytest.mark.asyncio
    async def test_license_missing_status(self, stage, mock_analyzer, context):
        mock_license = LicenseEvidence(status=EvidenceStatus.MISSING, declared_license="UNKNOWN")
        mock_analyzer.analyze.return_value = mock_license
    
        await stage.execute(context)
    
        assert context.license.status == EvidenceStatus.MISSING
