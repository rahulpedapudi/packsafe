from datetime import datetime

from packsafe_core.models.evidence import EvidenceStatus
from packsafe_core.models.package import EcosystemType, PackageRequest
from packsafe_core.pipeline.context import AnalysisContext


class TestContext:
    def test_ctx_001_initialization(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        assert ctx is not None
        assert isinstance(ctx.collected_at, datetime)

    def test_ctx_003_default_values(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        assert not ctx.license_file_found
        assert ctx.analysis_coverage_tier == "registry_osv"
        assert ctx.request.name == "testpkg"
        assert ctx.package.name is None

    def test_ctx_004_package_request(self):
        req = PackageRequest(
            name="testpkg", version="1.0.0", ecosystem=EcosystemType.pypi
        )
        ctx = AnalysisContext(request=req)
        assert ctx.request.name == "testpkg"

    def test_ctx_010_mutation(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        ctx.license_file_found = True
        assert ctx.license_file_found

        ctx.registry.status = EvidenceStatus.AVAILABLE
        assert ctx.registry.status == EvidenceStatus.AVAILABLE

    def test_ctx_016_isolated_instances(self):
        ctx1 = AnalysisContext(request=PackageRequest(name="test1"))
        ctx2 = AnalysisContext(request=PackageRequest(name="test2"))

        ctx1.license_file_found = True
        assert not ctx2.license_file_found
