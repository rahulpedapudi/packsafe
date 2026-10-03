# """Python dependency and version range parsing supporting PEP 440 and PEP 508."""

# from __future__ import annotations

# import re
# import sys
# from pathlib import Path
# from typing import Any
# from packaging.markers import Marker
# from packaging.requirements import Requirement
# from packaging.specifiers import InvalidSpecifier, SpecifierSet
# from packaging.version import InvalidVersion, Version

# from packsafe.evidence.models import DependencyItem


# class PythonDependencyResolver:
#     """Parses and resolves Python dependencies with environment marker evaluation."""

#     def __init__(self, target_environment: dict[str, str] | None = None) -> None:
#         # Default target environment to standard modern runtime
#         self.target_env = target_environment or {
#             "python_version": f"{sys.version_info.major}.{sys.version_info.minor}",
#             "sys_platform": sys.platform,
#             "os_name": "posix" if sys.platform != "win32" else "nt",
#             "extra": "",
#         }

#     def parse_requirement_string(self, req_str: str) -> DependencyItem | None:
#         """Parses a single PEP 508 requirement line (e.g. 'urllib3>=1.21.1,<3; python_version >= "3.8"')."""
#         cleaned = req_str.strip()
#         if not cleaned or cleaned.startswith("#") or cleaned.startswith("-"):
#             return None

#         try:
#             req = Requirement(cleaned)
#         except Exception:
#             # Fallback simple regex if packaging cannot parse
#             match = re.match(r"^([a-zA-Z0-9_\-\.]+)(.*)$", cleaned)
#             if not match:
#                 return None
#             name = match.group(1).strip()
#             spec = match.group(2).strip()
#             return DependencyItem(name=name, version_spec=spec, is_direct=True)

#         # Evaluate environment markers
#         if req.marker:
#             try:
#                 if not req.marker.evaluate(self.target_env):
#                     return None  # Marker does not apply to target environment
#             except Exception:
#                 pass

#         return DependencyItem(
#             name=req.name,
#             version_spec=str(req.specifier) if req.specifier else "",
#             is_direct=True,
#             is_optional=bool(req.extras),
#         )

#     def is_version_compatible(self, version_str: str, specifier_str: str) -> bool:
#         """Checks if a concrete package version satisfies a PEP 440 specifier."""
#         if not specifier_str or specifier_str == "*":
#             return True
#         try:
#             v = Version(version_str)
#             spec = SpecifierSet(specifier_str)
#             return v in spec
#         except (InvalidVersion, InvalidSpecifier):
#             return True

#     def parse_requirements_txt(self, content: str) -> list[DependencyItem]:
#         """Parses requirements.txt content."""
#         deps: list[DependencyItem] = []
#         for line in content.splitlines():
#             item = self.parse_requirement_string(line)
#             if item:
#                 deps.append(item)
#         return deps

#     def parse_pyproject_toml(self, content: str) -> list[DependencyItem]:
#         """Extracts dependencies from pyproject.toml content."""
#         deps: list[DependencyItem] = []
#         # Support basic TOML parsing without mandatory tomli on older pythons
#         in_deps = False
#         for line in content.splitlines():
#             stripped = line.strip()
#             if stripped.startswith("[project]") or stripped.startswith("[project.dependencies]"):
#                 in_deps = True
#                 continue
#             if stripped.startswith("[") and not stripped.startswith("[project"):
#                 in_deps = False
#                 continue

#             if in_deps and stripped.startswith("dependencies = ["):
#                 continue
#             if in_deps and stripped.startswith('"') or stripped.startswith("'"):
#                 # Quoted requirement inside array
#                 val = stripped.strip('",\'')
#                 item = self.parse_requirement_string(val)
#                 if item:
#                     deps.append(item)
#         return deps

#     def parse_metadata_file(self, content: str) -> list[DependencyItem]:
#         """Parses wheel or sdist METADATA / PKG-INFO lines (Requires-Dist headers)."""
#         deps: list[DependencyItem] = []
#         for line in content.splitlines():
#             if line.startswith("Requires-Dist:"):
#                 raw_req = line.split(":", 1)[1].strip()
#                 item = self.parse_requirement_string(raw_req)
#                 if item:
#                     deps.append(item)
#         return deps
