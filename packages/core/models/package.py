from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class EcosystemType(str, Enum):
    pypi = "pypi"
    npm = "npm"


@dataclass
class PackageMetadata:
    version: str | None = None
    description: str | None = None
    project_urls: dict[str, str] | None = None
    raw_deps: list[str] | None = None
    dependencies: list[dict] | None = None
    last_release_date: datetime | None = None
    initial_release_date: datetime | None = None


@dataclass
class PackageRequest:
    name: str
    ecosystem: EcosystemType = EcosystemType.pypi
    version: str | None = None


@dataclass
class PackageInfo:
    name: str
    exists: bool
    ecosystem: EcosystemType = EcosystemType.pypi
    version: str | None = None
    metadata: PackageMetadata | None = None
