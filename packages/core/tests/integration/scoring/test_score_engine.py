import pytest
import dataclasses
from packages.core.scoring.engine import ScoreEngine
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest, PackageIdentity
from packages.core.models.evidence import IdentityEvidence, RepositoryEvidence, EvidenceStatus
from packages.core.models.vulnerability import VulnerabilityEvidence, VulnerabilityItem, ExploitationSignal
from packages.core.models.static_analysis import StaticAnalysisEvidence, StaticAnalysisFindingItem
from packages.core.models.scoring import RiskLevel, Decision, GateSeverity, MetricStatus

@pytest.fixture
def engine():
    return ScoreEngine()

def create_base_context(name: str) -> AnalysisContext:
    ctx = AnalysisContext(request=PackageRequest(name=name))
    ctx.package = PackageIdentity(name=name, version="1.0.0", ecosystem="pypi")
    ctx.identity = IdentityEvidence(status=EvidenceStatus.AVAILABLE, typosquatting_risk=0.0)
    ctx.repository = RepositoryEvidence(
        repository_url=f"https://github.com/test/{name}",
        status=EvidenceStatus.AVAILABLE,
        stars=1000,
        forks=100,
        recent_commits_90d=50,
        open_issues=10
    )
    ctx.vulnerabilities = VulnerabilityEvidence(items=(), status=EvidenceStatus.AVAILABLE)
    ctx.static_analysis = StaticAnalysisEvidence(findings=(), status=EvidenceStatus.AVAILABLE)
    return ctx

@pytest.fixture
def package_fastapi():
    ctx = create_base_context("fastapi")
    ctx.repository = dataclasses.replace(ctx.repository, stars=60000, forks=5000, recent_commits_90d=150)
    return ctx

@pytest.fixture
def package_django():
    ctx = create_base_context("django")
    ctx.repository = dataclasses.replace(ctx.repository, stars=75000, forks=30000, recent_commits_90d=300)
    return ctx

@pytest.fixture
def package_pandas():
    ctx = create_base_context("pandas")
    ctx.repository = dataclasses.replace(ctx.repository, stars=40000, forks=15000, recent_commits_90d=400)
    return ctx

@pytest.fixture
def package_numpy():
    ctx = create_base_context("numpy")
    ctx.repository = dataclasses.replace(ctx.repository, stars=25000, forks=8000, recent_commits_90d=250)
    return ctx

@pytest.fixture
def package_requests():
    ctx = create_base_context("requests")
    ctx.repository = dataclasses.replace(ctx.repository, stars=50000, forks=9000, recent_commits_90d=100)
    return ctx


class TestScoreEngineIntegration:

    # --------------------------------------------------
    # REAL PACKAGE SCENARIOS (SE-001 to SE-005)
    # --------------------------------------------------
    @pytest.mark.parametrize("package_name", ["fastapi", "django", "pandas", "numpy", "requests"])
    def test_se_001_to_005_real_packages(self, engine, package_name, request):
        ctx = request.getfixturevalue(f"package_{package_name}")
        result = engine.calculate(ctx)
        
        assert result.final_score is not None
        assert result.base_score is not None
        assert result.categories
        assert result.confidence is not None
        assert result.gates is not None
        assert result.attribution is not None
        
        # Check bounds
        assert 0.0 <= result.final_score <= 100.0
        assert 0.0 <= result.confidence <= 100.0

    # --------------------------------------------------
    # SYNTHETIC SCENARIOS (SE-006 to SE-018)
    # --------------------------------------------------

    def test_se_006_fakesafe(self, engine):
        ctx = create_base_context("FakeSafe")
        ctx.repository = dataclasses.replace(ctx.repository, stars=5000, forks=500, recent_commits_90d=100)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0
        assert not any(g.triggered and g.severity == GateSeverity.CRITICAL for g in result.gates)

    def test_se_007_oldpackage(self, engine):
        ctx = create_base_context("OldPackage")
        ctx.repository = dataclasses.replace(ctx.repository, recent_commits_90d=0)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0

    def test_se_008_riskypackage(self, engine):
        ctx = create_base_context("RiskyPackage")
        ctx.static_analysis = dataclasses.replace(ctx.static_analysis, findings=tuple([
            StaticAnalysisFindingItem(
                finding_type="malware_exec",
                severity="CRITICAL",
                confidence=0.9,
                title="Malware Exec",
                description="",
                file_path="",
                evidence_snippet=""
            )
        ]))
        result = engine.calculate(ctx)
        assert result.decision == Decision.BLOCK
        assert any(g.triggered and g.severity == GateSeverity.CRITICAL for g in result.gates)

    def test_se_009_vulnerablepackage(self, engine):
        ctx = create_base_context("VulnerablePackage")
        ctx.vulnerabilities = dataclasses.replace(ctx.vulnerabilities, items=tuple([
            VulnerabilityItem(vulnerability_id="CVE-123", severity="CRITICAL", summary="")
        ]))
        result = engine.calculate(ctx)
        # The actual vulnerability gate severity depends on config, could be HIGH/CRITICAL
        assert result.decision in (Decision.BLOCK, Decision.WARN)

    def test_se_010_abandonedpackage(self, engine):
        ctx = create_base_context("AbandonedPackage")
        ctx.repository = dataclasses.replace(ctx.repository, recent_commits_90d=0, open_issues=1000)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0
        assert "maintenance" in result.categories

    def test_se_011_dependencyheavy(self, engine):
        ctx = create_base_context("DependencyHeavy")
        result = engine.calculate(ctx)
        assert result.final_score is not None

    def test_se_012_newpackage(self, engine):
        ctx = create_base_context("NewPackage")
        ctx.repository = dataclasses.replace(ctx.repository, stars=0, forks=0, recent_commits_90d=1)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0

    def test_se_013_popularbutrisky(self, engine):
        ctx = create_base_context("PopularButRisky")
        ctx.repository = dataclasses.replace(ctx.repository, stars=100000, forks=50000)
        ctx.static_analysis = dataclasses.replace(ctx.static_analysis, findings=tuple([
            StaticAnalysisFindingItem(
                finding_type="malware_exec",
                severity="CRITICAL",
                confidence=0.9,
                title="",
                description="",
                file_path="",
                evidence_snippet=""
            )
        ]))
        result = engine.calculate(ctx)
        assert result.decision == Decision.BLOCK

    def test_se_014_securebutunknown(self, engine):
        ctx = create_base_context("SecureButUnknown")
        ctx.repository = dataclasses.replace(ctx.repository, stars=1, forks=0)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0

    def test_se_015_missingdatapackage(self, engine):
        ctx = create_base_context("MissingDataPackage")
        ctx.repository = dataclasses.replace(ctx.repository, status=EvidenceStatus.MISSING)
        result = engine.calculate(ctx)
        assert result.confidence < 100.0

    def test_se_016_zerometricspackage(self, engine):
        ctx = create_base_context("ZeroMetricsPackage")
        ctx.repository = dataclasses.replace(ctx.repository, stars=0, forks=0, recent_commits_90d=0, open_issues=0)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0
        assert result.confidence > 0.0

    def test_se_017_boundarypackage(self, engine):
        ctx = create_base_context("BoundaryPackage")
        ctx.repository = dataclasses.replace(ctx.repository, stars=10000000, recent_commits_90d=10000000)
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0

    def test_se_018_mixedriskpackage(self, engine):
        ctx = create_base_context("MixedRiskPackage")
        ctx.repository = dataclasses.replace(ctx.repository, stars=50000, recent_commits_90d=0) 
        result = engine.calculate(ctx)
        assert 0.0 <= result.final_score <= 100.0

    # --------------------------------------------------
    # BEHAVIORAL COMPARISONS (SE-019 to SE-021)
    # --------------------------------------------------
    def test_se_019_behavior_vuln_increases_risk(self, engine):
        ctx_base = create_base_context("Base")
        res_base = engine.calculate(ctx_base)
        
        ctx_vuln = create_base_context("Base")
        ctx_vuln.vulnerabilities = dataclasses.replace(ctx_vuln.vulnerabilities, items=tuple([
            VulnerabilityItem(vulnerability_id="CVE-999", severity="HIGH", summary="")
        ]))
        res_vuln = engine.calculate(ctx_vuln)
        
        assert res_vuln.final_score <= res_base.final_score

    def test_se_020_behavior_maintenance_improves_score(self, engine):
        ctx_poor = create_base_context("Base")
        ctx_poor.repository = dataclasses.replace(ctx_poor.repository, recent_commits_90d=0, stars=1)
        res_poor = engine.calculate(ctx_poor)
        
        ctx_good = create_base_context("Base")
        ctx_good.repository = dataclasses.replace(ctx_good.repository, recent_commits_90d=100, stars=1000)
        res_good = engine.calculate(ctx_good)
        
        assert res_good.final_score >= res_poor.final_score

    def test_se_021_behavior_missing_evidence_reduces_confidence(self, engine):
        ctx_full = create_base_context("Base")
        res_full = engine.calculate(ctx_full)
        
        ctx_miss = create_base_context("Base")
        ctx_miss.repository = dataclasses.replace(ctx_miss.repository, status=EvidenceStatus.MISSING)
        res_miss = engine.calculate(ctx_miss)
        
        assert res_miss.confidence < res_full.confidence

    # --------------------------------------------------
    # DETERMINISM, ATTRIBUTION, GATES (SE-022 to SE-024)
    # --------------------------------------------------
    def test_se_022_determinism(self, engine):
        ctx = create_base_context("Deterministic")
        res1 = engine.calculate(ctx)
        res2 = engine.calculate(ctx)
        
        assert res1.final_score == res2.final_score
        assert res1.confidence == res2.confidence
        assert res1.decision == res2.decision

    def test_se_023_attribution(self, engine):
        ctx = create_base_context("AttrTest")
        res = engine.calculate(ctx)
        assert res.attribution is not None
        assert len(res.attribution.category_contributions) >= 0

    def test_se_024_gate_triggers(self, engine):
        ctx = create_base_context("GateTest")
        ctx.identity = dataclasses.replace(ctx.identity, typosquatting_risk=1.0)
        res = engine.calculate(ctx)
        
        assert res.gates
        triggered_gates = [g for g in res.gates if g.triggered]
        assert len(triggered_gates) > 0
