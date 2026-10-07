import pytest
import dataclasses
from packages.core.scoring.engine import ScoreEngine, map_risk_level, max_risk_level, map_vulnerability_risk_level
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.evidence import IdentityEvidence, RepositoryEvidence, EvidenceStatus
from packages.core.models.vulnerability import VulnerabilityEvidence, VulnerabilityItem, ExploitationSignal
from packages.core.models.static_analysis import StaticAnalysisEvidence, StaticAnalysisFindingItem
from packages.core.models.scoring import RiskLevel, Decision, GateSeverity, MetricStatus
from packages.core.models.package import PackageRequest

@pytest.fixture
def engine():
    return ScoreEngine()

@pytest.fixture
def base_context():
    ctx = AnalysisContext(request=PackageRequest(name="requests"))
    ctx.identity = IdentityEvidence(
        status=EvidenceStatus.AVAILABLE,
        typosquatting_risk=0.0
    )
    ctx.repository = RepositoryEvidence(
        repository_url="https://github.com/psf/requests",
        status=EvidenceStatus.AVAILABLE,
        stars=50000,
        forks=9000,
        recent_commits_90d=100
    )
    ctx.vulnerabilities = VulnerabilityEvidence(
        items=(),
        status=EvidenceStatus.AVAILABLE
    )
    ctx.static_analysis = StaticAnalysisEvidence(
        findings=(),
        status=EvidenceStatus.AVAILABLE
    )
    return ctx

# 1. Engine initialization
def test_score_engine_instantiation(engine):
    assert isinstance(engine, ScoreEngine)
    assert engine.config is not None

# 2. Basic scoring / Valid complete input
def test_valid_complete_scoring_input(engine, base_context):
    result = engine.calculate(base_context)
    assert result is not None
    assert isinstance(result.final_score, float)

def test_score_engine_returns_expected_result_type(engine, base_context):
    result = engine.calculate(base_context)
    assert result.__class__.__name__ == "ScoreResult"

def test_normal_package_scenario(engine, base_context):
    result = engine.calculate(base_context)
    assert 0.0 <= result.final_score <= 100.0
    assert result.decision in (Decision.ALLOW, Decision.WARN, Decision.BLOCK, Decision.REVIEW)

# 3. Component integration checks
def test_contains_all_scoring_components(engine, base_context):
    result = engine.calculate(base_context)
    assert hasattr(result, "final_score")
    assert hasattr(result, "categories")
    assert hasattr(result, "gates")
    assert hasattr(result, "confidence")
    assert hasattr(result, "attribution")
    assert hasattr(result, "findings")

def test_normalized_metrics_connected(engine, base_context):
    result = engine.calculate(base_context)
    # The metrics are passed inside attribution for explainability
    assert len(result.attribution.metric_attributions) > 0

def test_category_scores_included(engine, base_context):
    result = engine.calculate(base_context)
    assert len(result.categories) > 0
    # Common categories
    for cat in ["security", "maintenance"]:
        assert cat in result.categories

def test_confidence_result_included(engine, base_context):
    result = engine.calculate(base_context)
    assert 0.0 <= result.confidence <= 100.0

def test_gate_result_included(engine, base_context):
    result = engine.calculate(base_context)
    assert isinstance(result.gates, (list, tuple))

def test_attribution_information_included(engine, base_context):
    result = engine.calculate(base_context)
    assert result.attribution is not None
    assert len(result.attribution.category_contributions) > 0

# 4. Final Score Behavior
def test_healthy_package_score(engine, base_context):
    # A package with no vulns and good repo stats should score well
    result = engine.calculate(base_context)
    assert result.final_score > 60.0 # likely in the MODERATE, LOW, or SAFE range
    assert result.risk_level in (RiskLevel.SAFE, RiskLevel.LOW, RiskLevel.MODERATE)

def test_risky_package_score(engine, base_context):
    base_context.static_analysis = dataclasses.replace(base_context.static_analysis, findings=tuple([
        StaticAnalysisFindingItem(
            finding_type="malware_exec",
            severity="CRITICAL",
            confidence=0.9,
            title="Malicious",
            description="",
            file_path="",
            evidence_snippet=""
        )
    ]))
    result = engine.calculate(base_context)
    assert result.final_score <= 100.0
    assert result.decision in (Decision.WARN, Decision.BLOCK)

def test_zero_values_where_valid(engine, base_context):
    base_context.repository = dataclasses.replace(base_context.repository, stars=0, forks=0)
    result = engine.calculate(base_context)
    assert result.final_score >= 0.0

def test_single_metric_change_alters_score(engine, base_context):
    result1 = engine.calculate(base_context)
    
    # Change maintenance metric heavily
    base_context.repository = dataclasses.replace(base_context.repository, stars=0, recent_commits_90d=0, open_issues=1000)
    result2 = engine.calculate(base_context)
    
    assert result1.final_score != result2.final_score

# 5. Boundaries and limits
def test_configured_boundaries(engine, base_context):
    result = engine.calculate(base_context)
    assert 0.0 <= result.final_score <= 100.0
    assert 0.0 <= result.base_score <= 100.0

def test_minimum_valid_scoring_inputs(engine):
    # Completely empty context
    ctx = AnalysisContext(request=PackageRequest(name="test"))
    result = engine.calculate(ctx)
    assert 0.0 <= result.final_score <= 100.0

def test_maximum_valid_scoring_inputs(engine, base_context):
    # High stats
    base_context.repository = dataclasses.replace(base_context.repository, stars=1000000, forks=500000)
    result = engine.calculate(base_context)
    assert result.final_score <= 100.0

# 6. Gates + Final Score
def test_blocking_gate_final_result(engine, base_context):
    # Introduce a static analysis finding that maps to a CRITICAL gate (like malware)
    base_context.static_analysis = dataclasses.replace(base_context.static_analysis, findings=tuple([
        StaticAnalysisFindingItem(
            finding_type="malware_exec",
            severity="CRITICAL",
            confidence=0.9,
            title="Malicious code",
            description="",
            file_path="",
            evidence_snippet=""
        )
    ]))
    result = engine.calculate(base_context)
    
    # Should trigger gate
    assert any(g.triggered and g.severity == GateSeverity.CRITICAL for g in result.gates)
    assert result.decision == Decision.BLOCK
    assert result.risk_level == RiskLevel.CRITICAL
    # Final score should be clamped by the gate floor
    assert result.final_score <= 5.0 # Assuming default floor or similar

def test_no_gates_produces_normal_result(engine, base_context):
    result = engine.calculate(base_context)
    assert not any(g.triggered and g.severity == GateSeverity.CRITICAL for g in result.gates)
    assert result.final_score == result.base_score

def test_multiple_gate_conditions(engine, base_context):
    # Trigger warning gate + critical gate
    base_context.identity = dataclasses.replace(base_context.identity, typosquatting_risk=0.8) # Warning gate typically
    base_context.static_analysis = dataclasses.replace(base_context.static_analysis, findings=tuple([
        StaticAnalysisFindingItem(
            finding_type="malware_exec", severity="CRITICAL", confidence=0.9,
            title="", description="", file_path="", evidence_snippet=""
        )
    ]))
    result = engine.calculate(base_context)
    
    triggered = [g for g in result.gates if g.triggered]
    assert len(triggered) >= 1
    assert result.decision == Decision.BLOCK

def test_gate_decision_does_not_alter_categories(engine, base_context):
    # Run once clean
    clean_result = engine.calculate(base_context)
    
    # Run again with malware (CRITICAL gate)
    base_context.static_analysis = dataclasses.replace(base_context.static_analysis, findings=tuple([
        StaticAnalysisFindingItem(
            finding_type="malware_exec", severity="CRITICAL", confidence=0.9,
            title="", description="", file_path="", evidence_snippet=""
        )
    ]))
    gate_result = engine.calculate(base_context)
    
    # The base_score and category scores should remain mathematically similar before override
    # Note: Static finding will alter security category score, but OTHER categories (like maintenance) should remain identical.
    if "maintenance" in clean_result.categories and "maintenance" in gate_result.categories:
        assert clean_result.categories["maintenance"].score == pytest.approx(gate_result.categories["maintenance"].score)
    
    # Base score is overridden by final score, but base_score property still exists
    assert gate_result.final_score <= gate_result.base_score

# 7. Confidence + Final Score
def test_missing_evidence_handled_correctly(engine, base_context):
    # Mark repo as missing
    base_context.repository = dataclasses.replace(base_context.repository, status=EvidenceStatus.MISSING)
    result = engine.calculate(base_context)
    
    # Should reduce confidence and affect base score due to missing category penalty/neutral
    assert result.confidence < 100.0
    assert "maintenance" in result.categories

def test_partial_evidence(engine, base_context):
    base_context.identity = dataclasses.replace(base_context.identity, status=EvidenceStatus.MISSING)
    result = engine.calculate(base_context)
    assert result.confidence <= 100.0

# 8. Attribution
def test_attribution_survives_through_score_engine(engine, base_context):
    result = engine.calculate(base_context)
    # Check that sources are propagated
    sources = {m.source for m in result.attribution.metric_attributions if m.source}
    assert len(sources) > 0
    # Usually contains osv, identity, or github etc based on extractors.

# 9. Edge Cases / Missing Data
def test_none_values_supported(engine, base_context):
    base_context.repository = dataclasses.replace(base_context.repository, stars=None)
    result = engine.calculate(base_context)
    assert result.final_score >= 0.0

def test_partially_populated_input(engine):
    ctx = AnalysisContext(request=PackageRequest(name="test"))
    from packages.core.models.package import PackageIdentity
    ctx.package = PackageIdentity(name="test")
    result = engine.calculate(ctx)
    assert result.final_score >= 0.0

# 10. Determinism
def test_deterministic_behavior(engine, base_context):
    result1 = engine.calculate(base_context)
    result2 = engine.calculate(base_context)
    
    assert result1.final_score == result2.final_score
    assert result1.base_score == result2.base_score
    assert result1.confidence == result2.confidence
    assert result1.risk_level == result2.risk_level

def test_different_inputs_produce_different_results(engine, base_context):
    result1 = engine.calculate(base_context)
    
    base_context.repository = dataclasses.replace(base_context.repository, stars=1) # Poor repo
    result2 = engine.calculate(base_context)
    
    # Given requests base was 50000, 1 star should significantly drop maintenance/adoption
    assert result1.final_score != result2.final_score

# 11. Real Package Fixtures
# Since actual fixtures are missing from the mock env, we create a pseudo real fixture
def test_pseudo_real_package_scoring(engine):
    ctx = AnalysisContext(request=PackageRequest(name="requests"))
    from packages.core.models.package import PackageIdentity
    ctx.package = PackageIdentity(name="requests", version="2.31.0", ecosystem="pypi")
    
    ctx.identity = IdentityEvidence(status=EvidenceStatus.AVAILABLE, typosquatting_risk=0.0)
    ctx.repository = RepositoryEvidence(repository_url="https://github.com/psf/requests", status=EvidenceStatus.AVAILABLE, stars=50000, forks=9000, recent_commits_90d=100)
    ctx.vulnerabilities = VulnerabilityEvidence(items=(), status=EvidenceStatus.AVAILABLE)
    ctx.static_analysis = StaticAnalysisEvidence(findings=(), status=EvidenceStatus.AVAILABLE)
    
    result = engine.calculate(ctx)
    assert result.package_name == "requests"
    assert result.version == "2.31.0"
    assert result.final_score > 70.0

# 12. Output Structure Invariants
def test_final_score_consistent_with_categories(engine, base_context):
    result = engine.calculate(base_context)
    
    # Recompute base score
    num = sum(c.weight * c.score for c in result.categories.values() if c.status != MetricStatus.MISSING)
    den = sum(c.weight for c in result.categories.values() if c.status != MetricStatus.MISSING)
    
    if den > 0:
        expected_base = num / den
    else:
        expected_base = 0.0
        
    assert result.base_score == pytest.approx(expected_base, abs=0.1)

def test_map_risk_level():
    assert map_risk_level(95.0) == RiskLevel.SAFE
    assert map_risk_level(80.0) == RiskLevel.LOW
    assert map_risk_level(65.0) == RiskLevel.MODERATE
    assert map_risk_level(45.0) == RiskLevel.HIGH
    assert map_risk_level(20.0) == RiskLevel.CRITICAL

def test_max_risk_level():
    assert max_risk_level(RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MODERATE) == RiskLevel.CRITICAL
    assert max_risk_level(RiskLevel.SAFE, RiskLevel.SAFE) == RiskLevel.SAFE

def test_map_vulnerability_risk_level():
    class DummyVulnRes:
        risks = []
        combined_risk = 0.0
        
    assert map_vulnerability_risk_level(None, ()) == RiskLevel.SAFE
    
    dummy = DummyVulnRes()
    dummy.combined_risk = 0.8
    assert map_vulnerability_risk_level(dummy, ()) == RiskLevel.HIGH
    
    dummy.combined_risk = 0.3
    assert map_vulnerability_risk_level(dummy, ()) == RiskLevel.MODERATE
