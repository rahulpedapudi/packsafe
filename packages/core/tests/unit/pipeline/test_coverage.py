import pytest
from dataclasses import replace

from packages.core.pipeline.coverage import compute_coverage_tier
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest
from packages.core.models.evidence import EvidenceStatus


class TestCoverage:
    def test_cov_001_default(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        ctx.static_analysis = replace(ctx.static_analysis, status=EvidenceStatus.MISSING)
        ctx.repository = replace(ctx.repository, status=EvidenceStatus.MISSING)
        ctx.dependencies = replace(ctx.dependencies, status=EvidenceStatus.MISSING)
        tier = compute_coverage_tier(ctx)
        assert tier == "registry_osv"

    def test_cov_002_deep_static(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        ctx.static_analysis = replace(ctx.static_analysis, status=EvidenceStatus.AVAILABLE)
        tier = compute_coverage_tier(ctx)
        assert tier == "deep_static"

    def test_cov_003_registry_osv_repository(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        ctx.static_analysis = replace(ctx.static_analysis, status=EvidenceStatus.MISSING)
        ctx.repository = replace(ctx.repository, status=EvidenceStatus.AVAILABLE)
        ctx.dependencies = replace(ctx.dependencies, status=EvidenceStatus.AVAILABLE)
        tier = compute_coverage_tier(ctx)
        assert tier == "registry_osv_repository"

    def test_cov_004_partial_repo(self):
        ctx = AnalysisContext(request=PackageRequest(name="testpkg"))
        ctx.static_analysis = replace(ctx.static_analysis, status=EvidenceStatus.MISSING)
        ctx.repository = replace(ctx.repository, status=EvidenceStatus.AVAILABLE)
        ctx.dependencies = replace(ctx.dependencies, status=EvidenceStatus.MISSING)
        tier = compute_coverage_tier(ctx)
        assert tier == "registry_osv"
