"""npm SemVer range parsing and dependency resolution from package.json."""

from __future__ import annotations

import json
import re
from typing import Any
from packsafe.evidence.models import DependencyItem


class NpmDependencyResolver:
    """Evaluates SemVer ranges and extracts dependencies from package.json."""

    @staticmethod
    def _parse_semver(v_str: str) -> tuple[int, int, int] | None:
        """Parses a version string into (major, minor, patch)."""
        # Strip prefixes like 'v' or '= '
        cleaned = re.sub(r"^[v=\s]+", "", v_str.strip())
        # Strip pre-releases e.g. -alpha.1
        cleaned = cleaned.split("-")[0].split("+")[0]
        parts = cleaned.split(".")
        try:
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
            patch = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            return (major, minor, patch)
        except (ValueError, IndexError):
            return None

    def is_version_compatible(self, version_str: str, specifier_str: str) -> bool:
        """Evaluates whether version_str satisfies a npm SemVer specifier."""
        v = self._parse_semver(version_str)
        if not v:
            return True  # If unable to parse version, pass conservatively

        spec = specifier_str.strip()
        if not spec or spec in ("*", "latest", "x", "X"):
            return True

        # Caret range: ^1.2.3 -> >=1.2.3 <2.0.0 (or ^0.2.3 -> >=0.2.3 <0.3.0)
        if spec.startswith("^"):
            base = self._parse_semver(spec[1:])
            if not base:
                return True
            if base[0] > 0:
                return (v >= base) and (v[0] == base[0])
            elif base[1] > 0:
                return (v >= base) and (v[0] == 0) and (v[1] == base[1])
            else:
                return v == base

        # Tilde range: ~1.2.3 -> >=1.2.3 <1.3.0
        if spec.startswith("~"):
            base = self._parse_semver(spec[1:])
            if not base:
                return True
            return (v >= base) and (v[0] == base[0]) and (v[1] == base[1])

        # Exact comparison
        if re.match(r"^\d+\.\d+\.\d+", spec):
            base = self._parse_semver(spec)
            return v == base

        # Greater than / less than
        if ">=" in spec or "<=" in spec or ">" in spec or "<" in spec:
            clauses = spec.split()
            satisfied = True
            for c in clauses:
                c = c.strip()
                if c.startswith(">="):
                    b = self._parse_semver(c[2:])
                    if b and v < b:
                        satisfied = False
                elif c.startswith(">"):
                    b = self._parse_semver(c[1:])
                    if b and v <= b:
                        satisfied = False
                elif c.startswith("<="):
                    b = self._parse_semver(c[2:])
                    if b and v > b:
                        satisfied = False
                elif c.startswith("<"):
                    b = self._parse_semver(c[1:])
                    if b and v >= b:
                        satisfied = False
            return satisfied

        return True

    def parse_package_json(self, content: str | dict[str, Any], include_dev: bool = True) -> list[DependencyItem]:
        """Extracts direct, dev, and optional dependencies from package.json."""
        if isinstance(content, str):
            try:
                data = json.loads(content)
            except Exception:
                return []
        else:
            data = content

        deps: list[DependencyItem] = []

        # Production direct dependencies
        for name, spec in data.get("dependencies", {}).items():
            deps.append(
                DependencyItem(
                    name=name,
                    version_spec=str(spec),
                    is_direct=True,
                    is_dev=False,
                    is_optional=False,
                )
            )

        # Peer dependencies (considered direct supply chain)
        for name, spec in data.get("peerDependencies", {}).items():
            deps.append(
                DependencyItem(
                    name=name,
                    version_spec=str(spec),
                    is_direct=True,
                    is_dev=False,
                    is_optional=False,
                )
            )

        # Optional dependencies
        for name, spec in data.get("optionalDependencies", {}).items():
            deps.append(
                DependencyItem(
                    name=name,
                    version_spec=str(spec),
                    is_direct=True,
                    is_dev=False,
                    is_optional=True,
                )
            )

        # Dev dependencies
        if include_dev:
            for name, spec in data.get("devDependencies", {}).items():
                deps.append(
                    DependencyItem(
                        name=name,
                        version_spec=str(spec),
                        is_direct=True,
                        is_dev=True,
                        is_optional=False,
                    )
                )

        return deps
