"""PackSafe offline analysis package (static analysis and license inspection).

Contains no I/O: every analyzer parses content that has already been fetched and
extracted by :mod:`core.sources`.
"""

from .license.analyzer import LicenseAnalyzer
from .static.analyzer import StaticAnalyzer
from .static.javascript import JavaScriptStaticAnalyzer
from .static.python import PythonStaticAnalyzer

__all__ = [
    "JavaScriptStaticAnalyzer",
    "LicenseAnalyzer",
    "PythonStaticAnalyzer",
    "StaticAnalyzer",
]