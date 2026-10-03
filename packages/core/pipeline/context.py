from dataclasses import dataclass, field
from datetime import UTC, datetime

from ..models.dependencies import DependencyEvidence
from ..models.evidence import EvidenceProvenance, RegistryEvidence, RepositoryEvidence
from ..models.package import PackageIdentity, PackageRequest
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

    # static_analysis:

    provenance: tuple[EvidenceProvenance, ...] = field(
        default_factory=tuple
    )  # all the evidence collected from various sources

    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
