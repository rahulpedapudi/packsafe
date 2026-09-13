from dataclasses import dataclass
from datetime import datetime
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
    ecosystem: EcosystemType = "pypi"
    version: str | None = None


@dataclass
class PackageInfo:
    name: str
    exists: bool
    ecosystem: EcosystemType = "pypi"
    version: str | None = None
    metadata: PackageMetadata | None = None
