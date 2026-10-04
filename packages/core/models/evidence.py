from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class EvidenceStatus(str, Enum):
    """Status of an evidence subsystem or collector."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Audit trail for an evidence component."""

    source: str
    source_url: str
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    archive_sha256: str | None = None


@dataclass
class RegistryEvidence:
    """Package registry metadata (PyPI / npm)."""

    published_at: datetime | None = None
    latest_version: str | None = None
    release_count_1y: int | None = None
    release_count_3m: int | None = None
    days_since_last_release: int | None = None
    project_maturity_days: int | None = None
    maintainer_count: int | None = None
    downloads_30d: int | None = None
    download_growth_rate: float | None = None
    dependents_count: int | None = None
    dependents_source: str | None = None
    declared_license: str | None = None
    status: EvidenceStatus = EvidenceStatus.AVAILABLE


@dataclass(frozen=True)
class RepositoryEvidence:
    """VCS repository activity (GitHub / GitLab)."""

    repository_url: str | None = None
    stars: int | None = None
    forks: int | None = None
    watchers: int | None = None
    open_issues: int | None = None
    recent_commits_90d: int | None = None
    recent_issues_90d: int | None = None
    is_archived: bool = False
    default_branch: str = "main"
    status: EvidenceStatus = EvidenceStatus.AVAILABLE


@dataclass(frozen=True)
class IdentityEvidence:
    """Package name similarity and publisher identity."""

    target_popular_package: str | None = None
    name_similarity: float | None = None
    context_risk: float | None = None
    typosquatting_risk: float | None = None
    publisher_anomaly_score: float | None = None
    package_repo_mismatch: bool = False
    status: str = EvidenceStatus.AVAILABLE


@dataclass(frozen=True)
class LicenseEvidence:
    """License compliance and extraction."""

    declared_license: str | None = None
    spdx_id: str = "UNKNOWN"
    is_osi_approved: bool = True
    is_copyleft: bool = False
    license_file_present: bool = True
    status: str = EvidenceStatus.AVAILABLE
