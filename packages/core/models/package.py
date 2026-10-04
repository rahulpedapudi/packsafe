from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class EcosystemType(str, Enum):
    pypi = "pypi"
    npm = "npm"


@dataclass(frozen=True)
class PackageIdentity:
    """Canonical identifier for a package version."""

    name: str | None = None
    ecosystem: str | None = None
    version: str | None = None
    package_url: str | None = None
    repository_url: str | None = None
    distribution_url: str | None = None
    archive_hash: str | None = None
    registry_integrity: str | None = None


@dataclass
class PackageMetadata:
    version: str | None = None
    description: str | None = None
    project_urls: dict[str, str] | None = None
    raw_deps: list[str] | None = None
    dependencies: list[dict] | None = None
    last_release_date: datetime | None = None
    initial_release_date: datetime | None = None


@dataclass(frozen=True)
class PackageRequest:
    """Initial user/API request to analyze a package."""

    name: str
    ecosystem: EcosystemType = EcosystemType.pypi
    version: str | None = None
    scan_type: str = "standard"
    profile: str = "balanced"
