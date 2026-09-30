"""Canonical evidence models and contracts for the PackSafe Score Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


class EvidenceStatus(str, Enum):
    """Status of an evidence subsystem or collector."""
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class PackageRequest:
    """Initial user/API request to analyze a package."""
    name: str
    ecosystem: str = "pypi"
    version: Optional[str] = None
    scan_type: str = "standard"
    profile: str = "balanced"


@dataclass(frozen=True)
class PackageIdentity:
    """Canonical identifier for a package version."""
    name: str
    ecosystem: str
    version: str
    package_url: str | None = None
    repository_url: str | None = None
    archive_hash: str | None = None
    registry_integrity: str | None = None


@dataclass(frozen=True)
class VulnerabilityItem:
    """Individual vulnerability advisory detail."""
    vulnerability_id: str
    aliases: tuple[str, ...] = ()
    severity: str = "UNKNOWN"
    exploitability: float = 0.5
    exposure: float = 1.0
    actively_exploited: bool = False
    affected_ranges: tuple[str, ...] = ()
    fixed_versions: tuple[str, ...] = ()
    summary: str = ""
    source: str = "osv"
    applicability_status: str = "APPLICABLE"
    source_severities: tuple[tuple[str, str], ...] = ()
    severity_resolution: str = "MAX_SOURCE_SEVERITY"


@dataclass(frozen=True)
class VulnerabilityEvidence:
    """Collection of vulnerabilities affecting the package."""
    items: tuple[VulnerabilityItem, ...] = ()
    status: str = "AVAILABLE"
    osv_queried: bool = True
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    notes: str = ""


@dataclass(frozen=True)
class DependencyItem:
    """Individual dependency representation."""
    name: str
    version_spec: str = ""
    resolved_version: str | None = None
    depth: int = 1
    is_direct: bool = True
    is_dev: bool = False
    is_optional: bool = False
    is_archived: bool = False
    vulnerabilities: tuple[str, ...] = ()
    released_at: datetime | None = None


@dataclass(frozen=True)
class DependencyEvidence:
    """Dependency tree structure and metrics."""
    direct_count: Optional[int] = None
    transitive_count: Optional[int] = None
    max_depth: Optional[int] = None
    direct_dependencies: tuple[DependencyItem, ...] = ()
    transitive_dependencies: tuple[DependencyItem, ...] = ()
    abandoned_count: Optional[int] = None
    new_dependencies_count: Optional[int] = None
    churn_rate: Optional[float] = None
    vulnerable_dependency_count: Optional[int] = None
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class RegistryEvidence:
    """Package registry metadata (PyPI / npm)."""
    published_at: datetime | None = None
    latest_version: str | None = None
    release_count_1y: Optional[int] = None
    release_count_3m: Optional[int] = None
    days_since_last_release: Optional[float] = None
    project_maturity_days: Optional[float] = None
    maintainer_count: Optional[int] = None
    downloads_30d: Optional[int] = None
    download_growth_rate: Optional[float] = None
    dependents_count: Optional[int] = None
    dependents_source: Optional[str] = None
    declared_license: str | None = None
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class RepositoryEvidence:
    """VCS repository activity (GitHub / GitLab)."""
    repository_url: str | None = None
    stars: Optional[int] = None
    forks: Optional[int] = None
    watchers: Optional[int] = None
    open_issues: Optional[int] = None
    recent_commits_90d: Optional[int] = None
    recent_issues_90d: Optional[int] = None
    is_archived: bool = False
    default_branch: str = "main"
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class StaticAnalysisFindingItem:
    """Static analysis issue candidate."""
    finding_type: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence_snippet: str
    file_path: str
    line_number: int = 0


@dataclass(frozen=True)
class StaticAnalysisEvidence:
    """Static AST and archive inspection results."""
    findings: tuple[StaticAnalysisFindingItem, ...] = ()
    scanned_files_count: int = 0
    archive_sha256: str | None = None
    archive_size_bytes: int = 0
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class LicenseEvidence:
    """License compliance and extraction."""
    declared_license: str | None = None
    spdx_id: str = "UNKNOWN"
    is_osi_approved: bool = True
    is_copyleft: bool = False
    license_file_present: bool = True
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class IdentityEvidence:
    """Package name similarity and publisher identity."""
    target_popular_package: str | None = None
    name_similarity: Optional[float] = None
    context_risk: Optional[float] = None
    typosquatting_risk: Optional[float] = None
    publisher_anomaly_score: Optional[float] = None
    package_repo_mismatch: bool = False
    status: str = "AVAILABLE"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Audit trail for an evidence component."""
    source: str
    source_url: str
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    archive_sha256: str | None = None
    collector_version: str = "1.0.0"


@dataclass(frozen=True)
class PackageEvidence:
    """Unified immutable package evidence input for the Score Engine."""
    package: PackageIdentity
    registry: RegistryEvidence = field(default_factory=RegistryEvidence)
    repository: RepositoryEvidence = field(default_factory=RepositoryEvidence)
    vulnerabilities: VulnerabilityEvidence = field(default_factory=VulnerabilityEvidence)
    dependencies: DependencyEvidence = field(default_factory=DependencyEvidence)
    static_analysis: StaticAnalysisEvidence = field(default_factory=StaticAnalysisEvidence)
    identity: IdentityEvidence = field(default_factory=IdentityEvidence)
    license: LicenseEvidence = field(default_factory=LicenseEvidence)
    provenance: tuple[EvidenceProvenance, ...] = ()
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    analysis_coverage_tier: str = "deep_static"
