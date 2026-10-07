import pytest
import json
from pathlib import Path
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest
from packages.core.models.evidence import EvidenceStatus, RegistryEvidence, RepositoryEvidence
from packages.core.models.dependencies import DependencyEvidence, DependencyItem
from packages.core.scoring.metrics.dependency import SupplyChainMetricsExtractor
from packages.core.models.scoring import MetricStatus

class TestDependency:
    @pytest.fixture
    def extractor(self):
        return SupplyChainMetricsExtractor()

    @pytest.fixture
    def base_context(self):
        return AnalysisContext(
            request=PackageRequest(name="test-pkg"),
            registry=RegistryEvidence(),
            repository=RepositoryEvidence(),
            dependencies=DependencyEvidence()
        )

    # DEP-001 — Extract all dependency metrics
    def test_dep_001_extract_all_metrics(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_count=10, transitive_count=50)
        results = extractor.extract_all(base_context)
        assert len(results) == 9 # There are 9 metrics extracted

    # DEP-002 — Verify metric names
    def test_dep_002_verify_metric_names(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        expected_names = {
            'direct_dependency_count',
            'transitive_dependency_count',
            'dependency_depth',
            'dependency_vulnerability_exposure',
            'direct_vulnerable_deps',
            'transitive_vulnerable_deps',
            'abandoned_dependencies',
            'new_dependencies',
            'dependency_churn',
        }
        assert set(results.keys()) == expected_names
        for name, metric in results.items():
            assert metric.metric_name == name

    # DEP-003 — Direct dependency count
    def test_dep_003_direct_dependency_count(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_count=15)
        results = extractor.extract_all(base_context)
        assert results['direct_dependency_count'].raw_value == 15

    # DEP-004 — Direct dependency count zero
    def test_dep_004_direct_dependency_count_zero(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_count=0)
        results = extractor.extract_all(base_context)
        assert results['direct_dependency_count'].raw_value == 0

    # DEP-005 — Large direct dependency count
    def test_dep_005_large_direct_dependency_count(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_count=1500)
        results = extractor.extract_all(base_context)
        assert results['direct_dependency_count'].raw_value == 1500

    # DEP-006 — Transitive dependency count
    def test_dep_006_transitive_dependency_count(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(transitive_count=300)
        results = extractor.extract_all(base_context)
        assert results['transitive_dependency_count'].raw_value == 300

    # DEP-007 — Transitive dependency count zero
    def test_dep_007_transitive_dependency_count_zero(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(transitive_count=0)
        results = extractor.extract_all(base_context)
        assert results['transitive_dependency_count'].raw_value == 0

    # DEP-008 — Large transitive dependency count
    def test_dep_008_large_transitive_dependency_count(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(transitive_count=50000)
        results = extractor.extract_all(base_context)
        assert results['transitive_dependency_count'].raw_value == 50000

    # DEP-009 — Dependency depth
    def test_dep_009_dependency_depth(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(max_depth=5)
        results = extractor.extract_all(base_context)
        assert results['dependency_depth'].raw_value == 5

    # DEP-010 — Dependency depth zero/minimum
    def test_dep_010_dependency_depth_zero(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(max_depth=0)
        results = extractor.extract_all(base_context)
        assert results['dependency_depth'].raw_value == 0

    # DEP-011 — Dependency vulnerability exposure
    def test_dep_011_dependency_vulnerability_exposure(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(vulnerable_dependency_count=3)
        results = extractor.extract_all(base_context)
        assert results['dependency_vulnerability_exposure'].raw_value == 3

    # DEP-012 — No dependency vulnerability exposure
    def test_dep_012_no_dependency_vulnerability_exposure(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(vulnerable_dependency_count=0)
        results = extractor.extract_all(base_context)
        assert results['dependency_vulnerability_exposure'].raw_value == 0

    # DEP-013 — Direct vulnerable dependencies
    def test_dep_013_direct_vulnerable_deps(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_dependencies=(DependencyItem(name="vuln", version_spec="1", vulnerabilities=("CVE",)),))
        results = extractor.extract_all(base_context)
        assert results['direct_vulnerable_deps'].raw_value == 1

    # DEP-014 — Zero direct vulnerable dependencies
    def test_dep_014_zero_direct_vulnerable_deps(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(direct_dependencies=(DependencyItem(name="safe", version_spec="1"),))
        results = extractor.extract_all(base_context)
        assert results['direct_vulnerable_deps'].raw_value == 0

    # DEP-015 — Transitive vulnerable dependencies
    def test_dep_015_transitive_vulnerable_deps(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(transitive_dependencies=(DependencyItem(name="vuln", version_spec="1", vulnerabilities=("CVE",)), DependencyItem(name="vuln2", version_spec="1", vulnerabilities=("CVE",))))
        results = extractor.extract_all(base_context)
        assert results['transitive_vulnerable_deps'].raw_value == 2

    # DEP-016 — Zero transitive vulnerable dependencies
    def test_dep_016_zero_transitive_vulnerable_deps(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(transitive_dependencies=(DependencyItem(name="safe", version_spec="1"),))
        results = extractor.extract_all(base_context)
        assert results['transitive_vulnerable_deps'].raw_value == 0

    # DEP-017 — Abandoned dependencies
    def test_dep_017_abandoned_dependencies(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(abandoned_count=4)
        results = extractor.extract_all(base_context)
        assert results['abandoned_dependencies'].raw_value == 4

    # DEP-018 — No abandoned dependencies
    def test_dep_018_no_abandoned_dependencies(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(abandoned_count=0)
        results = extractor.extract_all(base_context)
        assert results['abandoned_dependencies'].raw_value == 0

    # DEP-019 — New dependencies
    def test_dep_019_new_dependencies(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(new_dependencies_count=2)
        results = extractor.extract_all(base_context)
        assert results['new_dependencies'].raw_value == 2

    # DEP-020 — No new dependencies
    def test_dep_020_no_new_dependencies(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(new_dependencies_count=0)
        results = extractor.extract_all(base_context)
        assert results['new_dependencies'].raw_value == 0

    # DEP-021 — Dependency churn
    def test_dep_021_dependency_churn(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(churn_rate=0.45)
        results = extractor.extract_all(base_context)
        assert results['dependency_churn'].raw_value == 0.45

    # DEP-022 — Zero dependency churn
    def test_dep_022_zero_dependency_churn(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(churn_rate=0.0)
        results = extractor.extract_all(base_context)
        assert results['dependency_churn'].raw_value == 0.0

    # DEP-023 — Typosquatting context (Skip, not applicable)
    def test_dep_023_typosquatting_context(self, extractor, base_context):
        pass

    # DEP-024 — Missing dependency evidence
    def test_dep_024_missing_dependency_evidence(self, extractor, base_context):
        base_context.dependencies = DependencyEvidence(status=EvidenceStatus.MISSING)
        results = extractor.extract_all(base_context)
        assert results['direct_dependency_count'].status == MetricStatus.MISSING

    # DEP-025 — Dependency status/source/confidence
    def test_dep_025_status_source_confidence(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        metric = results['direct_dependency_count']
        assert metric.status == MetricStatus.AVAILABLE
        assert metric.source == "registry"
        assert metric.confidence == 0.98
