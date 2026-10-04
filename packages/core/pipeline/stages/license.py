"""License evidence stage."""

import logging
import time

from ...analysis.license.analyzer import LicenseAnalyzer
from ...models.evidence import EvidenceStatus, LicenseEvidence
from ...pipeline.context import AnalysisContext

logger = logging.getLogger(__name__)


class LicenseStage:
    """Derives license evidence from the registry declaration and the archive contents.

    Runs after the archive stage so that ``context.license_file_found`` reflects what
    was actually shipped, not just what the registry metadata claims.
    """

    def __init__(self, analyzer: LicenseAnalyzer | None = None) -> None:
        self.analyzer = analyzer or LicenseAnalyzer()

    async def execute(self, context: AnalysisContext) -> None:
        start_time = time.perf_counter()
        logger.info(f"License Stage Started\nCurrent Context: {context}\n")

        declared = context.registry.declared_license

        context.license = self.analyzer.analyze(
            declared,
            license_file_found=context.license_file_found,
        )

        if context.license.status == EvidenceStatus.AVAILABLE:
            logger.debug(
                "License evidence resolved to %s (file present: %s)",
                context.license.spdx_id,
                context.license.license_file_present,
            )

        elapsed = time.perf_counter() - start_time
        logger.info(
            f"License Stage Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms\n"
        )