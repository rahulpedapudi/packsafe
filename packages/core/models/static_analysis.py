from dataclasses import dataclass


@dataclass(frozen=True)
class StaticAnalysisFindingItem:
    """Static analysis issue candidate."""

    finding_type: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence_snippet: str
    file_path: str
    line_number: int = 0


@dataclass(frozen=True)
class StaticAnalysisEvidence:
    """Static AST and archive inspection results."""

    findings: tuple[StaticAnalysisFindingItem, ...] = ()
    scanned_files_count: int = 0
    archive_sha256: str | None = None
    archive_size_bytes: int = 0
    status: str = "AVAILABLE"
