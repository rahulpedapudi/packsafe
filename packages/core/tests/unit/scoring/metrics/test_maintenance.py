import pytest
import json
from pathlib import Path
from packages.core.pipeline.context import AnalysisContext
from packages.core.models.package import PackageRequest
from packages.core.models.evidence import EvidenceStatus, RegistryEvidence, RepositoryEvidence
from packages.core.scoring.metrics.maintenance import MaintenanceMetricsExtractor
from packages.core.models.scoring import MetricStatus

class TestMaintenance:
    @pytest.fixture
    def extractor(self):
        return MaintenanceMetricsExtractor()

    @pytest.fixture
    def base_context(self):
        return AnalysisContext(
            request=PackageRequest(name="test-pkg"),
            registry=RegistryEvidence(),
            repository=RepositoryEvidence()
        )

    # MNT-001 — Extract all maintenance metrics
    def test_mnt_001_extract_all_metrics(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        assert len(results) == 8

    # MNT-002 — Verify metric names
    def test_mnt_002_verify_metric_names(self, extractor, base_context):
        results = extractor.extract_all(base_context)
        expected_names = {
            'days_since_last_release',
            'releases_last_year',
            'releases_last_3_months',
            'recent_commits',
            'recent_issue_activity',
            'maintainer_count',
            'repository_archived',
            'project_maturity_days'
        }
        assert set(results.keys()) == expected_names
        for name, metric in results.items():
            assert metric.metric_name == name

    # MNT-003 — Days since last release
    def test_mnt_003_days_since_last_release(self, extractor, base_context):
        base_context.registry.days_since_last_release = 15.5
        results = extractor.extract_all(base_context)
        assert results['days_since_last_release'].raw_value == 15.5

    # MNT-004 — Recently released package
    def test_mnt_004_recently_released_package(self, extractor, base_context):
        base_context.registry.days_since_last_release = 0.5
        results = extractor.extract_all(base_context)
        assert results['days_since_last_release'].raw_value == 0.5

    # MNT-005 — Old release
    def test_mnt_005_old_release(self, extractor, base_context):
        base_context.registry.days_since_last_release = 2000.0
        results = extractor.extract_all(base_context)
        assert results['days_since_last_release'].raw_value == 2000.0

    # MNT-006 — Missing release date
    def test_mnt_006_missing_release_date(self, extractor, base_context):
        base_context.registry.days_since_last_release = None
        results = extractor.extract_all(base_context)
        assert results['days_since_last_release'].raw_value is None

    # MNT-007 — Releases last year
    def test_mnt_007_releases_last_year(self, extractor, base_context):
        base_context.registry.release_count_1y = 12
        results = extractor.extract_all(base_context)
        assert results['releases_last_year'].raw_value == 12

    # MNT-008 — Zero releases last year
    def test_mnt_008_zero_releases_last_year(self, extractor, base_context):
        base_context.registry.release_count_1y = 0
        results = extractor.extract_all(base_context)
        assert results['releases_last_year'].raw_value == 0

    # MNT-009 — High release frequency
    def test_mnt_009_high_release_frequency(self, extractor, base_context):
        base_context.registry.release_count_1y = 500
        results = extractor.extract_all(base_context)
        assert results['releases_last_year'].raw_value == 500

    # MNT-010 — Releases last 3 months
    def test_mnt_010_releases_last_3_months(self, extractor, base_context):
        base_context.registry.release_count_3m = 3
        results = extractor.extract_all(base_context)
        assert results['releases_last_3_months'].raw_value == 3

    # MNT-011 — Zero releases last 3 months
    def test_mnt_011_zero_releases_last_3_months(self, extractor, base_context):
        base_context.registry.release_count_3m = 0
        results = extractor.extract_all(base_context)
        assert results['releases_last_3_months'].raw_value == 0

    # MNT-012 — Recent commits
    def test_mnt_012_recent_commits(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_commits_90d=50)
        results = extractor.extract_all(base_context)
        assert results['recent_commits'].raw_value == 50

    # MNT-013 — No recent commits
    def test_mnt_013_no_recent_commits(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_commits_90d=0)
        results = extractor.extract_all(base_context)
        assert results['recent_commits'].raw_value == 0

    # MNT-014 — High recent commit activity
    def test_mnt_014_high_recent_commit_activity(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_commits_90d=10000)
        results = extractor.extract_all(base_context)
        assert results['recent_commits'].raw_value == 10000

    # MNT-015 — Recent issue activity
    def test_mnt_015_recent_issue_activity(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_issues_90d=20)
        results = extractor.extract_all(base_context)
        assert results['recent_issue_activity'].raw_value == 20

    # MNT-016 — No recent issue activity
    def test_mnt_016_no_recent_issue_activity(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_issues_90d=0)
        results = extractor.extract_all(base_context)
        assert results['recent_issue_activity'].raw_value == 0

    # MNT-017 — High issue activity
    def test_mnt_017_high_issue_activity(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(recent_issues_90d=5000)
        results = extractor.extract_all(base_context)
        assert results['recent_issue_activity'].raw_value == 5000

    # MNT-018 — Maintainer count
    def test_mnt_018_maintainer_count(self, extractor, base_context):
        base_context.registry.maintainer_count = 5
        results = extractor.extract_all(base_context)
        assert results['maintainer_count'].raw_value == 5

    # MNT-019 — Single maintainer
    def test_mnt_019_single_maintainer(self, extractor, base_context):
        base_context.registry.maintainer_count = 1
        results = extractor.extract_all(base_context)
        assert results['maintainer_count'].raw_value == 1

    # MNT-020 — Multiple maintainers
    def test_mnt_020_multiple_maintainers(self, extractor, base_context):
        base_context.registry.maintainer_count = 50
        results = extractor.extract_all(base_context)
        assert results['maintainer_count'].raw_value == 50

    # MNT-021 — Repository archived
    def test_mnt_021_repository_archived(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(is_archived=True)
        results = extractor.extract_all(base_context)
        assert results['repository_archived'].raw_value is True

    # MNT-022 — Repository active
    def test_mnt_022_repository_active(self, extractor, base_context):
        base_context.repository = RepositoryEvidence(is_archived=False)
        results = extractor.extract_all(base_context)
        assert results['repository_archived'].raw_value is False

    # MNT-023 — Project maturity
    def test_mnt_023_project_maturity(self, extractor, base_context):
        base_context.registry.project_maturity_days = 365.25
        results = extractor.extract_all(base_context)
        assert results['project_maturity_days'].raw_value == 365.25

    # MNT-024 — Missing maintenance evidence
    def test_mnt_024_missing_maintenance_evidence(self, extractor, base_context):
        base_context.registry.maintainer_count = None
        results = extractor.extract_all(base_context)
        assert results['maintainer_count'].status == MetricStatus.MISSING
        assert results['maintainer_count'].raw_value is None

    # MNT-025 — Status/source/confidence
    def test_mnt_025_status_source_confidence(self, extractor, base_context):
        base_context.registry.status = EvidenceStatus.AVAILABLE
        results = extractor.extract_all(base_context)
        metric = results['days_since_last_release']
        assert metric.status == MetricStatus.AVAILABLE
        assert metric.source == "registry"
        assert metric.confidence == 0.98
