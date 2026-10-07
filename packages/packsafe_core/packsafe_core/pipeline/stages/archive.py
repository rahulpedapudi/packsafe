"""Archive download, integrity verification and static analysis stage (PyPI only)."""

import asyncio
import logging
import time
from pathlib import Path

from ...analysis.static.analyzer import StaticAnalyzer
from ...models.evidence import EvidenceProvenance
from ...models.package import EcosystemType
from ...models.static_analysis import (
    StaticAnalysisEvidence,
    StaticAnalysisFindingItem,
)
from ...pipeline.context import AnalysisContext
from ...sources.archive import ArchiveCollector, ExtractedArchive
from ...sources.safe_archive import ArchiveSecurityError
from ...tracing import fmt_duration, pick, stage_trace

logger = logging.getLogger(__name__)

# Files that can execute code at interpreter startup when present on sys.path.
DANGEROUS_FILE_SUFFIXES = frozenset({".pth", ".so", ".pyd", ".dll", ".dylib", ".exe"})


class ArchiveStage:
    """Downloads the distribution archive, verifies it, and statically analyzes it.

    Populates ``context.static_analysis``, ``context.provenance`` and
    ``context.license_file_found``. Any failure degrades static analysis to MISSING
    rather than failing the pipeline.
    """

    def __init__(self, collector: ArchiveCollector | None = None) -> None:
        self.collector = collector or ArchiveCollector()

    async def execute(self, context: AnalysisContext) -> None:
        with stage_trace(
            "archive",
            logger,
            inputs=pick(
                context.package,
                ("name", "version", "ecosystem", "distribution_url", "archive_hash"),
            ),
        ) as span:
            # npm support is not implemented yet; skip rather than mis-analyze.
            if context.package.ecosystem != EcosystemType.pypi:
                span.skip("only the pypi ecosystem is supported")
                return

            dist_url = context.package.distribution_url
            if not dist_url:
                span.skip("no distribution URL available")
                return

            archive: ExtractedArchive | None = None
            try:
                analyze_start = time.perf_counter()
                archive = await self.collector.collect(
                    dist_url,
                    expected_sha256=context.package.archive_hash,
                )
                collect_elapsed = time.perf_counter() - analyze_start

                static_start = time.perf_counter()
                static_ev = await asyncio.to_thread(self._analyze, archive)
                static_elapsed = time.perf_counter() - static_start

                context.static_analysis = static_ev
                context.license_file_found = self._license_file_found(archive.files)

                context.provenance.append(
                    EvidenceProvenance(
                        source="archive",
                        source_url=dist_url,
                        archive_sha256=archive.sha256,
                    )
                )

                span.output(
                    status=static_ev.status,
                    archive_sha256=archive.sha256,
                    archive_size_bytes=archive.size_bytes,
                    files_extracted=len(archive.files),
                    files_scanned=static_ev.scanned_files_count,
                    findings=len(static_ev.findings),
                    license_file_found=context.license_file_found,
                )
                logger.debug(
                    "archive breakdown | download+extract=%s static_analysis=%s "
                    "(static analysis runs in a worker thread, so its time is not "
                    "concurrent with other stages)",
                    fmt_duration(collect_elapsed),
                    fmt_duration(static_elapsed),
                )

            except (ArchiveSecurityError, OSError, ValueError) as e:
                # Security-relevant: an integrity or containment failure must be visible.
                context.static_analysis = StaticAnalysisEvidence(status="MISSING")
                span.fail(f"archive inspection failed for {dist_url}: {e}")
            except asyncio.CancelledError:
                raise
            except Exception as e:
                context.static_analysis = StaticAnalysisEvidence(status="MISSING")
                span.degrade(f"live archive inspection failed: {e}")
            finally:
                if archive is not None:
                    archive.cleanup()
                await self.collector.aclose()

    def _analyze(self, archive: ExtractedArchive) -> StaticAnalysisEvidence:
        """Runs static analysis off the event loop and merges in archive metadata."""
        assert archive.extract_dir is not None
        static_ev = StaticAnalyzer().analyze_directory(archive.extract_dir)

        dangerous = self._dangerous_binaries(archive.files)

        return StaticAnalysisEvidence(
            findings=static_ev.findings + tuple(dangerous),
            scanned_files_count=static_ev.scanned_files_count,
            archive_sha256=archive.sha256,
            archive_size_bytes=archive.size_bytes,
            status="AVAILABLE",
        )

    @staticmethod
    def _dangerous_binaries(
        files: tuple[Path, ...],
    ) -> tuple[StaticAnalysisFindingItem, ...]:
        """Flags native extensions and .pth files, which can run at import time."""
        return tuple(
            _binary_finding(f.name, f.suffix.lower())
            for f in files
            if f.suffix.lower() in DANGEROUS_FILE_SUFFIXES
        )

    @staticmethod
    def _license_file_found(files: tuple[Path, ...]) -> bool:
        """True when any extracted file looks like a license file."""
        for f in files:
            name = f.name.lower()
            if name.startswith(("license", "licence", "copying")):
                return True
        return False


def _binary_finding(file_name: str, suffix: str) -> StaticAnalysisFindingItem:
    if suffix == ".pth":
        return StaticAnalysisFindingItem(
            finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
            severity="HIGH",
            confidence=0.70,
            title="Startup hook file present in distribution",
            description=(
                "A .pth file executes lines at interpreter startup when the "
                "distribution is on sys.path."
            ),
            evidence_snippet=file_name,
            file_path=file_name,
            line_number=0,
        )

    return StaticAnalysisFindingItem(
        finding_type="SUSPICIOUS_INSTALL_BEHAVIOR",
        severity="MEDIUM",
        confidence=0.50,
        title="Native binary shipped in source distribution",
        description=(
            f"Distribution contains a compiled binary ({suffix}) which cannot be "
            "reviewed as source."
        ),
        evidence_snippet=file_name,
        file_path=file_name,
        line_number=0,
    )
