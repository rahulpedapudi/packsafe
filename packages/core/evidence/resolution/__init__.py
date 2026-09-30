"""Dependency and version resolution for Python and npm ecosystems."""

from packsafe.evidence.resolution.python import PythonDependencyResolver
from packsafe.evidence.resolution.npm import NpmDependencyResolver

__all__ = ["PythonDependencyResolver", "NpmDependencyResolver"]
