from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..models.dependencies import DependencyEvidence
from ..models.evidence import (
    EvidenceProvenance,
    IdentityEvidence,
    LicenseEvidence,
    RegistryEvidence,
    RepositoryEvidence,
)
from ..models.package import PackageIdentity, PackageRequest
from ..models.static_analysis import StaticAnalysisEvidence
from ..models.vulnerability import VulnerabilityEvidence


# to accumulate everything during the analysis
@dataclass
class AnalysisContext:
    """The analysis context."""

    request: PackageRequest = field(default_factory=PackageRequest)  # user request

    package: PackageIdentity = field(
        default_factory=PackageIdentity
    )  # general identifier for a package

    registry: RegistryEvidence = field(default_factory=RegistryEvidence)

    repository: RepositoryEvidence = field(
        default_factory=RepositoryEvidence
    )  # repo activity

    vulnerabilities: VulnerabilityEvidence = field(
        default_factory=VulnerabilityEvidence
    )  # vulnerabilities affecting the package

    dependencies: DependencyEvidence = field(
        default_factory=DependencyEvidence
    )  # info about the package dependencies

    static_analysis: StaticAnalysisEvidence = field(
        default_factory=StaticAnalysisEvidence
    )  # static analysis of the package

    identity: IdentityEvidence = field(
        default_factory=IdentityEvidence
    )  # package identity

    license: LicenseEvidence = field(
        default_factory=LicenseEvidence
    )  # license information

    provenance: list[EvidenceProvenance] = field(
        default_factory=list
    )  # all the evidence collected from various sources

    license_file_found: bool = (
        False
    )  # set by ArchiveStage, consumed by LicenseStage

    analysis_coverage_tier: str = (
        "registry_osv"
    )  # how much of the package was actually inspected; read by ConfidenceEngine

    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
