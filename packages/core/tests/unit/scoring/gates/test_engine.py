import pytest
from packages.core.scoring.gates.engine import SecurityGateEngine
from packages.core.models.scoring import Finding, GateSeverity, Decision
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageIdentity, PackageRequest
from packages.core.models.vulnerability import VulnerabilityItem, VulnerabilityEvidence, ExploitationSignal
from packages.core.models.evidence import EvidenceStatus, IdentityEvidence
from packages.core.models.static_analysis import StaticAnalysisEvidence, StaticAnalysisFindingItem

@pytest.fixture
def base_evidence():
    identity = PackageIdentity(name="test-pkg", version="1.0.0", ecosystem="pypi")
    request = PackageRequest(name="test-pkg", version="1.0.0")
    context = AnalysisContext(package=identity, request=request)
    context.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=())
    context.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.AVAILABLE, items=())
    return context

@pytest.fixture
def engine(mock_config):
    return SecurityGateEngine(mock_config)

# GATE-001 — Verify engine instantiation
def test_engine_instantiation(engine, mock_config):
    assert engine.config == mock_config
    assert len(engine.config.gates) == 6

# GATE-002, GATE-003 — Valid healthy input
def test_healthy_input_passes_all_gates(engine, base_evidence):
    results = engine.evaluate(base_evidence, [])
    assert len(results) == 6
    for res in results:
        assert not res.triggered
        assert res.severity == GateSeverity.NONE

# GATE-004 — Clearly unsafe input
def test_unsafe_input_triggers_malware_gate(engine, base_evidence):
    f = Finding(
        finding_id="MAL-001",
        category="security",
        severity="CRITICAL",
        confidence=1.0,
        title="Malware confirmed",
        description="malicious",
        evidence="",
        source="static"
    )
    results = engine.evaluate(base_evidence, [f])
    malware_gate = next(g for g in results if g.gate_id == "GATE-MALWARE")
    assert malware_gate.triggered is True
    assert malware_gate.decision_override == Decision.BLOCK

# GATE-005, GATE-006, GATE-007 — Exact threshold condition (min_confidence)
@pytest.mark.parametrize("confidence, expected_trigger", [
    (0.69, False), # Just below
    (0.70, True),  # Exactly at boundary
    (0.85, True)   # Above boundary
])
def test_malware_gate_confidence_threshold(engine, base_evidence, confidence, expected_trigger):
    f = StaticAnalysisFindingItem(
        finding_type="MALWARE",
        severity="HIGH",
        confidence=confidence,
        title="MALWARE matches pattern",
        description="",
        evidence_snippet="",
        file_path="setup.py"
    )
    # The min_conf for static match in GATE-MALWARE is explicitly 0.70 in the engine code
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f,))
    results = engine.evaluate(base_evidence, [])
    gate = next(g for g in results if g.gate_id == "GATE-MALWARE")
    assert gate.triggered == expected_trigger

# GATE-008, GATE-009 — Active critical vulnerability conditions (min/max behavior)
@pytest.mark.parametrize("severity, signal, expected", [
    ("HIGH", ExploitationSignal.RECENTLY_LISTED, False),
    ("CRITICAL", ExploitationSignal.NONE, False),
    ("CRITICAL", ExploitationSignal.RECENTLY_LISTED, True),
    ("CRITICAL", ExploitationSignal.KNOWN_EXPLOITED, False) # Only RECENTLY_LISTED or known_ransomware_use triggers this specific gate
])
def test_active_critical_vuln_gate(engine, base_evidence, severity, signal, expected):
    v = VulnerabilityItem(
        vulnerability_id="CVE-123",
        aliases=(),
        severity=severity,
        exploitability=1.0,
        exposure=1.0,
        exploitation_signal=signal,
        affected_ranges=(),
        fixed_versions=()
    )
    base_evidence.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.AVAILABLE, items=(v,))
    results = engine.evaluate(base_evidence, [])
    gate = next(g for g in results if g.gate_id == "GATE-ACTIVE-CRITICAL")
    assert gate.triggered == expected

# GATE-010 — Ransomware campaign behavior
def test_active_critical_vuln_ransomware(engine, base_evidence):
    v = VulnerabilityItem(
        vulnerability_id="CVE-456",
        aliases=(),
        severity="CRITICAL",
        exploitability=1.0,
        exposure=1.0,
        exploitation_signal=ExploitationSignal.NONE,
        affected_ranges=(),
        fixed_versions=(),
        known_ransomware_use=True
    )
    base_evidence.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.AVAILABLE, items=(v,))
    results = engine.evaluate(base_evidence, [])
    gate = next(g for g in results if g.gate_id == "GATE-ACTIVE-CRITICAL")
    assert gate.triggered is True

# GATE-011, GATE-012, GATE-013 — Missing / Empty input
def test_missing_or_empty_evidence(engine, base_evidence):
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.MISSING, findings=())
    base_evidence.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.MISSING, items=())
    results = engine.evaluate(base_evidence, [])
    for res in results:
        assert not res.triggered

# GATE-014 — Multiple gates triggered simultaneously
def test_multiple_gates_triggered(engine, base_evidence):
    f = Finding(
        finding_id="MAL-001",
        category="security",
        severity="CRITICAL",
        confidence=1.0,
        title="MALWARE",
        description="",
        evidence="",
        source="static"
    )
    v = VulnerabilityItem(
        vulnerability_id="CVE-123",
        aliases=(),
        severity="CRITICAL",
        exploitability=1.0,
        exposure=1.0,
        exploitation_signal=ExploitationSignal.RECENTLY_LISTED,
        affected_ranges=(),
        fixed_versions=()
    )
    base_evidence.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.AVAILABLE, items=(v,))
    results = engine.evaluate(base_evidence, [f])
    
    triggers = [g for g in results if g.triggered]
    assert len(triggers) == 2
    assert {"GATE-MALWARE", "GATE-ACTIVE-CRITICAL"} == {g.gate_id for g in triggers}

# GATE-015, GATE-016 — Single changed input changes gate decision
def test_single_input_changes_gate(engine, base_evidence):
    # Base: does not trigger credential theft
    f = StaticAnalysisFindingItem(finding_type="OTHER", severity="HIGH", confidence=0.85, title="Test", description="", evidence_snippet="", file_path="main.py")
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f,))
    res1 = engine.evaluate(base_evidence, [])
    assert not any(g.triggered for g in res1 if g.gate_id == "GATE-CREDENTIAL-THEFT")
    
    # Changed input: triggers credential theft
    f2 = StaticAnalysisFindingItem(finding_type="CREDENTIAL_SECRET_ACCESS", severity="HIGH", confidence=0.85, title="Test", description="", evidence_snippet="", file_path="main.py")
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f2,))
    res2 = engine.evaluate(base_evidence, [])
    gate = next(g for g in res2 if g.gate_id == "GATE-CREDENTIAL-THEFT")
    assert gate.triggered is True

# GATE-018 — Blocking behavior
def test_blocking_behavior(engine, base_evidence):
    f = StaticAnalysisFindingItem(finding_type="REMOTE_PAYLOAD_EXECUTION", severity="HIGH", confidence=0.9, title="Test", description="", evidence_snippet="", file_path="main.py")
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f,))
    results = engine.evaluate(base_evidence, [])
    gate = next(g for g in results if g.gate_id == "GATE-REMOTE-EXEC")
    assert gate.triggered is True
    assert gate.decision_override == Decision.BLOCK

# GATE-019 — Warning behavior
def test_warning_behavior(engine, base_evidence):
    # Warning relies on typosquatting_risk directly in identity evidence
    base_evidence.identity = IdentityEvidence(typosquatting_risk=0.75)
    results = engine.evaluate(base_evidence, [])
    gate = next(g for g in results if g.gate_id == "GATE-SUSPICIOUS-WARN")
    assert gate.triggered is True
    assert gate.severity == GateSeverity.WARNING
    assert gate.decision_override == Decision.WARN

# GATE-020 — Deterministic behavior
def test_deterministic_behavior(engine, base_evidence):
    f = StaticAnalysisFindingItem(finding_type="INSTALL_MALWARE", severity="HIGH", confidence=0.9, title="Test", description="", evidence_snippet="", file_path="main.py")
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f,))
    res1 = engine.evaluate(base_evidence, [])
    res2 = engine.evaluate(base_evidence, [])
    assert [g.triggered for g in res1] == [g.triggered for g in res2]

# GATE-021 — Complete output structure
def test_output_structure(engine, base_evidence):
    results = engine.evaluate(base_evidence, [])
    gate = results[0]
    assert hasattr(gate, "gate_id")
    assert hasattr(gate, "triggered")
    assert hasattr(gate, "severity")
    assert hasattr(gate, "reason")
    assert hasattr(gate, "decision_override")
    assert hasattr(gate, "evidence_ids")
    assert isinstance(gate.evidence_ids, tuple)

# GATE-023 — Multiple realistic scenarios (mocked static analysis findings)
@pytest.mark.parametrize("finding_type, expected_gate_trigger", [
    ("CREDENTIAL_EXFILTRATION", "GATE-CREDENTIAL-THEFT"),
    ("FETCH_EXEC", "GATE-REMOTE-EXEC"),
    ("PERSISTENCE", "GATE-INSTALL-MALWARE"),
    ("OBFUSCAT", "GATE-SUSPICIOUS-WARN")
])
def test_realistic_static_findings(engine, base_evidence, finding_type, expected_gate_trigger):
    f = StaticAnalysisFindingItem(finding_type=finding_type, severity="HIGH", confidence=0.9, title="Found "+finding_type, description="", evidence_snippet="", file_path="main.py")
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f,))
    results = engine.evaluate(base_evidence, [])
    triggered = [g.gate_id for g in results if g.triggered]
    assert expected_gate_trigger in triggered

# GATE-024, GATE-025 — Consistency & end-to-end
def test_end_to_end_gate_scenario(engine, base_evidence):
    # A mix of vulnerabilities and static findings
    v = VulnerabilityItem(vulnerability_id="CVE-999", aliases=(), severity="CRITICAL", exploitability=1.0, exposure=1.0, exploitation_signal=ExploitationSignal.RECENTLY_LISTED, affected_ranges=(), fixed_versions=())
    base_evidence.vulnerabilities = VulnerabilityEvidence(status=EvidenceStatus.AVAILABLE, items=(v,))
    
    f1 = StaticAnalysisFindingItem(finding_type="SUSPICIOUS_NETWORK", severity="HIGH", confidence=0.9, title="Suspicious", description="", evidence_snippet="", file_path="main.py")
    f2 = StaticAnalysisFindingItem(finding_type="MALWARE", severity="LOW", confidence=0.5, title="Low conf", description="", evidence_snippet="", file_path="main.py") # Should be ignored due to low confidence (<0.7)
    
    base_evidence.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.AVAILABLE, findings=(f1, f2))
    
    results = engine.evaluate(base_evidence, [])
    
    active_crit = next(g for g in results if g.gate_id == "GATE-ACTIVE-CRITICAL")
    assert active_crit.triggered is True
    assert "CVE-999" in active_crit.evidence_ids[0]
    
    suspicious = next(g for g in results if g.gate_id == "GATE-SUSPICIOUS-WARN")
    assert suspicious.triggered is True
    
    malware = next(g for g in results if g.gate_id == "GATE-MALWARE")
    assert malware.triggered is False # Confidence was 0.5, below 0.70
