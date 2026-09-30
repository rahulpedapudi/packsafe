"""Dependency graph representation and normalization with cycle detection and precedence."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from packsafe.evidence.models import DependencyEvidence, DependencyItem


@dataclass
class DependencyNode:
    name: str
    version: str | None
    version_spec: str
    depth: int
    is_direct: bool
    parent: str | None
    is_archived: bool | None = None
    is_vulnerable: bool | None = None
    is_new: bool | None = None


class DependencyGraph:
    """Directed Acyclic Graph (DAG) for package dependencies with cycle safety."""

    def __init__(self, root_package: str) -> None:
        self.root_package = root_package
        self.nodes: dict[str, DependencyNode] = {}
        self.edges: dict[str, list[str]] = {}  # parent -> children
        self.detected_cycles: list[tuple[str, str]] = []

    def _is_reachable(self, start: str, target: str, visited: set[str] | None = None) -> bool:
        """Determines if target is reachable from start in the current graph."""
        if visited is None:
            visited = set()
        if start == target:
            return True
        visited.add(start)
        for neighbor in self.edges.get(start, []):
            if neighbor not in visited:
                if self._is_reachable(neighbor, target, visited):
                    return True
        return False

    def add_dependency(
        self,
        name: str,
        version: str | None = None,
        version_spec: str = "",
        depth: int = 1,
        parent: str | None = None,
        is_direct: bool = True,
        is_archived: bool | None = None,
        is_vulnerable: bool | None = None,
        is_new: bool | None = None,
    ) -> bool:
        """Adds a dependency node with cycle detection. Returns True if added."""
        clean_name = name.strip().lower()
        if clean_name == self.root_package.lower():
            self.detected_cycles.append((parent or "root", clean_name))
            return False

        if parent and self._is_reachable(clean_name, parent.lower()):
            self.detected_cycles.append((parent, clean_name))
            return False

        # If already recorded at shallower depth, retain shallower
        if clean_name in self.nodes:
            existing = self.nodes[clean_name]
            if depth < existing.depth:
                self.nodes[clean_name] = DependencyNode(
                    name=clean_name,
                    version=version or existing.version,
                    version_spec=version_spec or existing.version_spec,
                    depth=depth,
                    is_direct=is_direct,
                    parent=parent,
                    is_archived=is_archived if is_archived is not None else existing.is_archived,
                    is_vulnerable=is_vulnerable if is_vulnerable is not None else existing.is_vulnerable,
                    is_new=is_new if is_new is not None else existing.is_new,
                )
            return True

        self.nodes[clean_name] = DependencyNode(
            name=clean_name,
            version=version,
            version_spec=version_spec,
            depth=depth,
            is_direct=is_direct,
            parent=parent,
            is_archived=is_archived,
            is_vulnerable=is_vulnerable,
            is_new=is_new,
        )

        p = (parent or self.root_package).lower()
        self.edges.setdefault(p, []).append(clean_name)
        return True

    def build_evidence(self) -> DependencyEvidence:
        """Constructs immutable DependencyEvidence from graph traversal."""
        direct_items: list[DependencyItem] = []
        transitive_items: list[DependencyItem] = []

        abandoned_count = 0
        new_count = 0
        vulnerable_count = 0
        max_depth = 0
        has_archived_info = False
        has_new_info = False
        has_vuln_info = False

        for node in self.nodes.values():
            if node.depth > max_depth:
                max_depth = node.depth
            if node.is_archived is not None:
                has_archived_info = True
                if node.is_archived:
                    abandoned_count += 1
            if node.is_new is not None:
                has_new_info = True
                if node.is_new:
                    new_count += 1
            if node.is_vulnerable is not None:
                has_vuln_info = True
                if node.is_vulnerable:
                    vulnerable_count += 1

            item = DependencyItem(
                name=node.name,
                version_spec=node.version_spec,
                resolved_version=node.version,
                depth=node.depth,
                is_direct=node.is_direct,
                is_archived=bool(node.is_archived),
                vulnerabilities=("KNOWN_VULNERABLE",) if node.is_vulnerable else (),
            )

            if node.is_direct:
                direct_items.append(item)
            else:
                transitive_items.append(item)

        return DependencyEvidence(
            direct_count=len(direct_items),
            transitive_count=len(transitive_items),
            max_depth=max_depth,
            direct_dependencies=tuple(direct_items),
            transitive_dependencies=tuple(transitive_items),
            abandoned_count=abandoned_count if has_archived_info else None,
            new_dependencies_count=new_count if has_new_info else None,
            churn_rate=None,
            vulnerable_dependency_count=vulnerable_count if has_vuln_info else None,
            status="AVAILABLE",
        )


class DependencyNormalizer:
    """Normalizes dependency evidence applying the source-of-truth hierarchy."""

    @staticmethod
    def merge_sources(
        root_package: str,
        manifest_deps: list[DependencyItem] | None = None,
        registry_deps: list[DependencyItem] | None = None,
        deps_dev_graph: list[dict[str, Any]] | None = None,
    ) -> DependencyEvidence:
        """Merges dependency sources following Manifest > Registry > deps.dev precedence."""
        graph = DependencyGraph(root_package)

        # 1. Manifest dependencies (highest priority direct)
        manifest_names: set[str] = set()
        if manifest_deps:
            for dep in manifest_deps:
                if not dep.is_dev:
                    graph.add_dependency(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        depth=1,
                        is_direct=True,
                    )
                    manifest_names.add(dep.name.lower())

        # 2. Registry dependencies (secondary priority direct)
        if registry_deps:
            for dep in registry_deps:
                if not dep.is_dev and dep.name.lower() not in manifest_names:
                    graph.add_dependency(
                        name=dep.name,
                        version_spec=dep.version_spec,
                        depth=1,
                        is_direct=True,
                    )

        # 3. deps.dev transitive graph
        if deps_dev_graph:
            for node in deps_dev_graph:
                name = node.get("name", "")
                if not name:
                    continue
                depth = int(node.get("depth", 2))
                is_direct = depth == 1
                graph.add_dependency(
                    name=name,
                    version=node.get("version"),
                    version_spec=node.get("version_spec", ""),
                    depth=depth,
                    parent=node.get("parent"),
                    is_direct=is_direct,
                    is_archived=node.get("is_archived"),
                    is_vulnerable=node.get("is_vulnerable"),
                    is_new=node.get("is_new"),
                )

        return graph.build_evidence()
