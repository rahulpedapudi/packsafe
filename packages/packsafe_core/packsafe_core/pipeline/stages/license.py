"""License evidence stage."""

import logging

from ...analysis.license.analyzer import LicenseAnalyzer
from ...models.evidence import EvidenceStatus, LicenseEvidence
from ...pipeline.context import AnalysisContext
from ...tracing import pick, stage_trace

logger = logging.getLogger(__name__)


class LicenseStage:
    """Derives license evidence from the registry declaration and the archive contents.

    Runs after the archive stage so that ``context.license_file_found`` reflects what
    was actually shipped, not just what the registry metadata claims.
    """

    def __init__(self, analyzer: LicenseAnalyzer | None = None) -> None:
        self.analyzer = analyzer or LicenseAnalyzer()

    async def execute(self, context: AnalysisContext) -> None:
        with stage_trace(
            "license",
            logger,
            inputs={
                "registry.declared_license": context.registry.declared_license,
                "license_file_found": context.license_file_found,
            },
            dump=context.license,
        ) as span:
            declared = context.registry.declared_license

            context.license = self.analyzer.analyze(
                declared,
                license_file_found=context.license_file_found,
            )

            span.output(**pick(context.license, (
                "status",
                "declared_license",
                "spdx_id",
                "is_osi_approved",
                "is_copyleft",
                "license_file_present",
            )))

            if context.license.status != EvidenceStatus.AVAILABLE:
                span.degrade(
                    "license could not be resolved: "
                    f"{context.license.status} (declared={declared})"
                )
            elif not context.license_file_found:
                # Metadata claims a license but no license file shipped with the
                # archive: a downgrade/typosquat signal worth surfacing.
                span.degrade(
                    f"registry declares {context.license.spdx_id} but no license file "
                    "was found in the distribution archive"
                )