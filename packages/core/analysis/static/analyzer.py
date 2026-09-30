"""Unified Static Analysis Runner."""

from __future__ import annotations

from pathlib import Path
from packsafe.analysis.safe_archive import SafeArchiveExtractor
from packsafe.analysis.static.python import PythonStaticAnalyzer
from packsafe.analysis.static.javascript import JavaScriptStaticAnalyzer
from packsafe.evidence.models import StaticAnalysisEvidence, StaticAnalysisFindingItem


class StaticAnalyzer:
    """Orchestrates safe archive extraction and static inspection for Python and npm packages."""

    def __init__(self) -> None:
        self.extractor = SafeArchiveExtractor()
        self.py_analyzer = PythonStaticAnalyzer()
        self.js_analyzer = JavaScriptStaticAnalyzer()

    def analyze_directory(self, dir_path: Path) -> StaticAnalysisEvidence:
        findings: list[StaticAnalysisFindingItem] = []
        scanned_count = 0

        for file_path in dir_path.rglob("*"):
            if file_path.is_file():
                scanned_count += 1
                if file_path.suffix == ".py":
                    findings.extend(self.py_analyzer.analyze_file(file_path))
                elif file_path.suffix in (".js", ".ts", ".mjs"):
                    findings.extend(self.js_analyzer.analyze_js_file(file_path))
                elif file_path.name == "package.json":
                    findings.extend(self.js_analyzer.analyze_package_json(file_path))

        return StaticAnalysisEvidence(
            findings=findings,
            scanned_files_count=scanned_count,
            status="AVAILABLE",
        )
