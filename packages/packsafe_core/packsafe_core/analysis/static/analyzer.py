"""Unified Static Analysis Runner."""

from __future__ import annotations

from pathlib import Path

from ...models.static_analysis import (
    StaticAnalysisEvidence,
    StaticAnalysisFindingItem,
)
from .javascript import JavaScriptStaticAnalyzer
from .python import PythonStaticAnalyzer

PYTHON_SUFFIXES = frozenset({".py"})
JS_SUFFIXES = frozenset({".js", ".ts", ".mjs"})
PACKAGE_MANIFEST = "package.json"


class StaticAnalyzer:
    """Orchestrates static inspection for Python and npm packages.

    Purely offline: parses files already present on disk and never executes package code.
    """

    def __init__(
        self,
        py_analyzer: PythonStaticAnalyzer | None = None,
        js_analyzer: JavaScriptStaticAnalyzer | None = None,
    ) -> None:
        self.py_analyzer = py_analyzer or PythonStaticAnalyzer()
        self.js_analyzer = js_analyzer or JavaScriptStaticAnalyzer()

    def analyze_directory(self, dir_path: Path) -> StaticAnalysisEvidence:
        """Analyze every source file under dir_path and return the evidence bundle.

        Archive metadata (hash, size) is intentionally not populated here: only the
        caller that performed the download knows those values.
        """
        findings: list[StaticAnalysisFindingItem] = []
        scanned_count = 0

        for file_path in sorted(dir_path.rglob("*")):
            if not file_path.is_file():
                continue

            suffix = file_path.suffix
            if suffix in PYTHON_SUFFIXES:
                scanned_count += 1
                findings.extend(self.py_analyzer.analyze_file(file_path))
            elif suffix in JS_SUFFIXES:
                scanned_count += 1
                findings.extend(self.js_analyzer.analyze_js_file(file_path))
            elif file_path.name == PACKAGE_MANIFEST:
                scanned_count += 1
                findings.extend(self.js_analyzer.analyze_package_json(file_path))

        return StaticAnalysisEvidence(
            findings=tuple(findings),
            scanned_files_count=scanned_count,
            status="AVAILABLE",
        )