import pytest
import json
from pathlib import Path
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest
from packages.core.models.evidence import EvidenceStatus, RegistryEvidence, RepositoryEvidence, IdentityEvidence
from packages.core.models.static_analysis import StaticAnalysisEvidence, StaticAnalysisFindingItem
from packages.core.models.evidence import EvidenceStatus
from packages.core.scoring.metrics.malicious_behavior import IntegrityMetricsExtractor, TyposquattingEvaluator
from packages.core.models.scoring import MetricStatus

class TestMaliciousBehavior:
    @pytest.fixture
    def extractor(self):
        return IntegrityMetricsExtractor()

    @pytest.fixture
    def typo_evaluator(self):
        return TyposquattingEvaluator()

    @pytest.fixture
    def base_context(self):
        return AnalysisContext(
            request=PackageRequest(name="test-pkg"),
            registry=RegistryEvidence(),
            repository=RepositoryEvidence(),
            static_analysis=StaticAnalysisEvidence(),
            identity=IdentityEvidence()
        )

    # MAL-001 — Extract all malicious-behavior metrics
    def test_mal_001_extract_all_metrics(self, extractor, typo_evaluator, base_context):
        results = extractor.extract_all(base_context)
        typo_result = typo_evaluator.evaluate(base_context)
        assert len(results) == 10
        assert len(typo_result) == 4 # risk, target, similarity, context_risk

    # MAL-002 — Verify metric names
    def test_mal_002_verify_metric_names(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        expected_names = {
            'confirmed_malicious_behavior',
            'credential_secret_access',
            'suspicious_install_behavior',
            'remote_code_download',
            'shell_process_execution',
            'dynamic_code_execution',
            'obfuscation_patterns',
            'suspicious_network_behavior',
            'package_repo_mismatch',
            'publisher_anomaly',
        }
        assert set(results.keys()) == expected_names

    # MAL-003 — Confirmed malicious behavior — safe package
    def test_mal_003_confirmed_malicious_safe(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['confirmed_malicious_behavior'].raw_value is False

    # MAL-004 — Confirmed malicious behavior — positive evidence
    def test_mal_004_confirmed_malicious_positive(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="CONFIRMED_MALICIOUS", severity="CRITICAL", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['confirmed_malicious_behavior'].raw_value is True

    # MAL-005 — Credential/secret access absent
    def test_mal_005_credential_access_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['credential_secret_access'].raw_value == 0.0

    # MAL-006 — Credential/secret access present
    def test_mal_006_credential_access_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="CREDENTIAL_THEFT", severity="HIGH", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['credential_secret_access'].raw_value > 0.0

    # MAL-007 — Suspicious install behavior absent
    def test_mal_007_suspicious_install_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['suspicious_install_behavior'].raw_value == 0.0

    # MAL-008 — Suspicious install behavior present
    def test_mal_008_suspicious_install_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="PREINSTALL_HOOK", severity="MEDIUM", confidence=0.8, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['suspicious_install_behavior'].raw_value > 0.0

    # MAL-009 — Remote code download absent
    def test_mal_009_remote_code_download_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['remote_code_download'].raw_value == 0.0

    # MAL-010 — Remote code download present
    def test_mal_010_remote_code_download_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="REMOTE_DOWNLOAD", severity="HIGH", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['remote_code_download'].raw_value > 0.0

    # MAL-011 — Typosquatting risk absent
    def test_mal_011_typosquatting_absent(self, typo_evaluator, base_context):
        risk, _, _, _ = typo_evaluator.evaluate(base_context)
        assert risk == 0.0

    # MAL-012 — Typosquatting risk present
    def test_mal_012_typosquatting_present(self, typo_evaluator, base_context):
        base_context.identity = IdentityEvidence(
            name_similarity=0.95, target_popular_package="requests", context_risk=1.0
        )
        risk, target, sim, context = typo_evaluator.evaluate(base_context)
        assert risk > 0.0
        assert target == "requests"

    # MAL-013 — Package/repository mismatch absent
    def test_mal_013_package_repo_mismatch_absent(self, extractor, base_context):
        base_context.identity = IdentityEvidence(package_repo_mismatch=False)
        results = extractor.extract_all(base_context)
        assert results['package_repo_mismatch'].raw_value is False

    # MAL-014 — Package/repository mismatch present
    def test_mal_014_package_repo_mismatch_present(self, extractor, base_context):
        base_context.identity = IdentityEvidence(package_repo_mismatch=True)
        results = extractor.extract_all(base_context)
        assert results['package_repo_mismatch'].raw_value is True

    # MAL-015 — Shell/process execution absent
    def test_mal_015_shell_execution_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['shell_process_execution'].raw_value == 0.0

    # MAL-016 — Shell/process execution present
    def test_mal_016_shell_execution_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="SHELL_EXECUTION", severity="MEDIUM", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['shell_process_execution'].raw_value > 0.0

    # MAL-017 — Dynamic code execution absent
    def test_mal_017_dynamic_execution_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['dynamic_code_execution'].raw_value == 0.0

    # MAL-018 — Dynamic code execution present
    def test_mal_018_dynamic_execution_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="EVAL", severity="LOW", confidence=0.5, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['dynamic_code_execution'].raw_value > 0.0

    # MAL-019 — Obfuscation absent
    def test_mal_019_obfuscation_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['obfuscation_patterns'].raw_value == 0.0

    # MAL-020 — Obfuscation present
    def test_mal_020_obfuscation_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="OBFUSCATION_BASE64", severity="MEDIUM", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['obfuscation_patterns'].raw_value > 0.0

    # MAL-021 — Suspicious network behavior absent
    def test_mal_021_suspicious_network_absent(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['suspicious_network_behavior'].raw_value == 0.0

    # MAL-022 — Suspicious network behavior present
    def test_mal_022_suspicious_network_present(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(
            findings=(StaticAnalysisFindingItem(finding_type="SOCKET_CONNECTION", severity="LOW", confidence=1.0, title="", description="", evidence_snippet="", file_path=""),)
        )
        results = extractor.extract_all(base_context)
        assert results['suspicious_network_behavior'].raw_value > 0.0

    # MAL-023 — Publisher anomaly absent
    def test_mal_023_publisher_anomaly_absent(self, extractor, base_context):
        base_context.identity = IdentityEvidence(publisher_anomaly_score=0.0)
        results = extractor.extract_all(base_context)
        assert results['publisher_anomaly'].raw_value == 0.0

    # MAL-024 — Publisher anomaly present
    def test_mal_024_publisher_anomaly_present(self, extractor, base_context):
        base_context.identity = IdentityEvidence(publisher_anomaly_score=0.85)
        results = extractor.extract_all(base_context)
        assert results['publisher_anomaly'].raw_value == 0.85

    # MAL-025 — Missing security evidence
    def test_mal_025_missing_security_evidence(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(status=EvidenceStatus.MISSING)
        results = extractor.extract_all(base_context)
        assert results['confirmed_malicious_behavior'].status == MetricStatus.MISSING

    # MAL-026 — Unavailable security evidence
    def test_mal_026_unavailable_security_evidence(self, extractor, base_context):
        base_context.static_analysis = StaticAnalysisEvidence(status="UNAVAILABLE")
        results = extractor.extract_all(base_context)
        assert results['confirmed_malicious_behavior'].status == MetricStatus.AVAILABLE

    # MAL-027 — Boolean metric handling
    def test_mal_027_boolean_metric_handling(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert isinstance(results['confirmed_malicious_behavior'].raw_value, bool)

    # MAL-028 — Numeric risk metric handling
    def test_mal_028_numeric_risk_handling(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert isinstance(results['credential_secret_access'].raw_value, float)

    # MAL-029 — Source/confidence verification
    def test_mal_029_source_confidence(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results['confirmed_malicious_behavior'].source == "static_analysis"
        assert results['confirmed_malicious_behavior'].confidence > 0.0
