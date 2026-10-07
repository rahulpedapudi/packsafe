import pytest
from packsafe_core.models.evidence import (
    EvidenceStatus,
    RegistryEvidence,
    RepositoryEvidence,
)
from packsafe_core.models.package import PackageRequest
from packsafe_core.models.scoring import MetricStatus
from packsafe_core.pipeline.context import AnalysisContext
from packsafe_core.scoring.metrics.adoption import AdoptionMetricsExtractor


class TestAdoption:
    @pytest.fixture
    def extractor(self):
        return AdoptionMetricsExtractor()

    @pytest.fixture
    def base_context(self):
        return AnalysisContext(
            request=PackageRequest(name="test-pkg"),
            registry=RegistryEvidence(),
            repository=RepositoryEvidence(),
        )

    # ADP-001 — Extract all metrics
    def test_adp_001_extract_all_metrics(self, extractor, base_context):
        base_context.registry.downloads_30d = 5000
        base_context.registry.download_growth_rate = 0.1
        base_context.registry.dependents_count = 100
        base_context.repository = RepositoryEvidence(stars=200, forks=50, watchers=10)

        results = extractor.extract_all(base_context)
        assert len(results) == 6

    # ADP-002 — Verify metric names
    def test_adp_002_verify_metric_names(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        expected_names = {
            "download_count",
            "download_growth",
            "dependents_count",
            "stars_count",
            "forks_count",
            "watchers_count",
        }
        assert set(results.keys()) == expected_names
        for name, metric in results.items():
            assert metric.metric_name == name

    # ADP-003 — Download count normal value
    def test_adp_003_download_count_normal(self, extractor, base_context):
        base_context.registry.downloads_30d = 10000
        results = extractor.extract_all(base_context)
        assert results["download_count"].raw_value == 10000

    # ADP-004 — Download count zero
    def test_adp_004_download_count_zero(self, extractor, base_context):
        base_context.registry.downloads_30d = 0
        results = extractor.extract_all(base_context)
        assert results["download_count"].raw_value == 0

    # ADP-005 — Download count large value
    def test_adp_005_download_count_large(self, extractor, base_context):
        base_context.registry.downloads_30d = 1000000
        results = extractor.extract_all(base_context)
        assert results["download_count"].raw_value == 1000000

    # ADP-006 — Download count status
    def test_adp_006_download_count_status(self, extractor, base_context):
        base_context.registry.status = EvidenceStatus.AVAILABLE
        results = extractor.extract_all(base_context)
        assert results["download_count"].status == MetricStatus.AVAILABLE

    # ADP-007 — Download count source
    def test_adp_007_download_count_source(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results["download_count"].source == "registry"

    # ADP-008 — Download count confidence
    def test_adp_008_download_count_confidence(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert results["download_count"].confidence == 0.98

    # ADP-009 — Download growth positive value
    def test_adp_009_download_growth_positive(self, extractor, base_context):
        base_context.registry.download_growth_rate = 0.25
        results = extractor.extract_all(base_context)
        assert results["download_growth"].raw_value == 0.25

    # ADP-010 — Download growth zero
    def test_adp_010_download_growth_zero(self, extractor, base_context):
        base_context.registry.download_growth_rate = 0.0
        results = extractor.extract_all(base_context)
        assert results["download_growth"].raw_value == 0.0

    # ADP-011 — Download growth negative value
    def test_adp_011_download_growth_negative(self, extractor, base_context):
        base_context.registry.download_growth_rate = -0.10
        results = extractor.extract_all(base_context)
        assert results["download_growth"].raw_value == -0.10

    # ADP-012 — Download growth missing
    def test_adp_012_download_growth_missing(self, extractor, base_context):
        base_context.registry.download_growth_rate = None
        results = extractor.extract_all(base_context)
        metric = results["download_growth"]
        assert metric.raw_value is None
        assert metric.status == MetricStatus.MISSING
        assert metric.confidence == 0.0

    # ADP-013 — Download growth confidence
    def test_adp_013_download_growth_confidence(self, extractor, base_context):
        base_context.registry.download_growth_rate = 0.15
        results = extractor.extract_all(base_context)
        assert results["download_growth"].confidence == 0.95

    # ADP-014 — Dependents from deps.dev
    def test_adp_014_dependents_deps_dev(self, extractor, base_context):
        base_context.registry.dependents_count = 500
        base_context.registry.dependents_source = "deps_dev"
        results = extractor.extract_all(base_context)
        metric = results["dependents_count"]
        assert metric.status == MetricStatus.AVAILABLE
        assert metric.confidence == 0.90
        assert metric.source == "deps_dev"

    # ADP-015 — Dependents from fallback source
    def test_adp_015_dependents_fallback(self, extractor, base_context):
        base_context.registry.dependents_count = 300
        base_context.registry.dependents_source = "libraries_io"
        results = extractor.extract_all(base_context)
        metric = results["dependents_count"]
        assert metric.confidence == 0.80
        assert metric.source == "libraries_io"

    # ADP-016 — Dependents missing
    def test_adp_016_dependents_missing(self, extractor, base_context):
        base_context.registry.dependents_count = None
        results = extractor.extract_all(base_context)
        metric = results["dependents_count"]
        assert metric.status == MetricStatus.MISSING
        assert metric.confidence == 0.0

    # ADP-017 — Dependents source missing
    def test_adp_017_dependents_source_missing(self, extractor, base_context):
        base_context.registry.dependents_count = 500
        base_context.registry.dependents_source = None
        results = extractor.extract_all(base_context)
        metric = results["dependents_count"]
        assert metric.source == "deps_dev"

    # ADP-018 — Dependents zero
    def test_adp_018_dependents_zero(self, extractor, base_context):
        base_context.registry.dependents_count = 0
        results = extractor.extract_all(base_context)
        metric = results["dependents_count"]
        assert metric.raw_value == 0
        assert metric.status == MetricStatus.AVAILABLE

    # ADP-019 — Stars normal value
    def test_adp_019_stars_normal(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(stars=1000)
        results = extractor.extract_all(base_context)
        assert results["stars_count"].raw_value == 1000

    # ADP-020 — Stars zero
    def test_adp_020_stars_zero(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(stars=0)
        results = extractor.extract_all(base_context)
        assert results["stars_count"].raw_value == 0

    # ADP-021 — Forks normal value
    def test_adp_021_forks_normal(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(forks=100)
        results = extractor.extract_all(base_context)
        assert results["forks_count"].raw_value == 100
        assert results["forks_count"].source == "github"

    # ADP-022 — Forks zero
    def test_adp_022_forks_zero(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(forks=0)
        results = extractor.extract_all(base_context)
        assert results["forks_count"].raw_value == 0

    # ADP-023 — Watchers normal value
    def test_adp_023_watchers_normal(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(watchers=50)
        results = extractor.extract_all(base_context)
        assert results["watchers_count"].raw_value == 50
        assert results["watchers_count"].source == "github"

    # ADP-024 — Repository unavailable status
    def test_adp_024_repository_unavailable(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(status=EvidenceStatus.MISSING)
        results = extractor.extract_all(base_context)
        assert results["stars_count"].status == MetricStatus.MISSING
        assert results["forks_count"].status == MetricStatus.MISSING
        assert results["watchers_count"].status == MetricStatus.MISSING

    # ADP-025 — Unknown status handling
    def test_adp_025_unknown_status_handling(self, extractor, base_context):
        # Simulate an unknown status string that isn't mapped directly
        # To bypass type checking in test, we assign an arbitrary string
        base_context.registry.status = "SOME_UNKNOWN_STATUS"  # type: ignore
        base_context.repository = RepositoryEvidence(status="ANOTHER_UNKNOWN_STATUS")  # type: ignore

        results = extractor.extract_all(base_context)

        assert results["download_count"].status == MetricStatus.AVAILABLE
        assert results["stars_count"].status == MetricStatus.AVAILABLE
