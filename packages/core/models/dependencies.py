from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class DependencyItem:
    """Individual dependency representation."""

    name: str  # name of the package
    version_spec: str  # version spec i.e.., which versions are compatible
    resolved_version: str | None = None  # resolved version
    depth: int = 1  # depth in the dependency tree
    is_direct: bool = True  # if the dependency is direct
    is_dev: bool = False  # if the dependency is dev
    is_optional: bool = False  # if the dependency is optional
    is_archived: bool = False  # if the dependency is archived
    vulnerabilities: tuple[str, ...] = ()  # Todo: find a way to scan vulnerabilities
    released_at: datetime | None = None


@dataclass(frozen=True)
class DependencyEvidence:
    """Dependency tree structure and metrics."""

    direct_count: int | None = None
    transitive_count: int | None = None
    max_depth: int | None = None
    direct_dependencies: tuple[DependencyItem, ...] = ()
    transitive_dependencies: tuple[DependencyItem, ...] = ()
    abandoned_count: int | None = None
    new_dependencies_count: int | None = None
    churn_rate: float | None = None
    vulnerable_dependency_count: int | None = None
    status: str = "AVAILABLE"
