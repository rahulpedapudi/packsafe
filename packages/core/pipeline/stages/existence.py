import logging
import time

from ...models.evidence import EvidenceProvenance
from ...models.package import PackageIdentity, PackageRequest
from ...pipeline.context import AnalysisContext
from ...sources.base_registry import PackageRegistry

logger = logging.getLogger(__name__)


class ExistenceStage:
    def __init__(self, registry: PackageRegistry):
        # the package existence check should work irrespective of type of registry
        # it doesnt need to know what registry its working with
        self.registry = registry

    async def execute(
        self, context: AnalysisContext
    ) -> None | tuple[EvidenceProvenance, str | None]:

        start_time = time.perf_counter()
        logger.info(f"Existence Stage Started\nCurrent Context: {context}\n")

        requested_package: PackageRequest = context.request
        (
            exists,
            (identity, evidence, provenance, dist_url),
        ) = await self.registry.exists(requested_package)

        end_time = time.perf_counter() - start_time

        logger.info(
            f"Existence Stage Completed in {end_time:.2f} seconds | {end_time * 1000:.2f} ms\n"
        )

        if exists:
            context.package = PackageIdentity(
                archive_hash=identity.archive_hash,
                distribution_url=dist_url,
                name=identity.name,
                ecosystem=identity.ecosystem,
                version=identity.version,
                package_url=identity.package_url,
                registry_integrity=identity.registry_integrity,
                repository_url=identity.repository_url,
            )
            context.registry = evidence
            context.provenance.append(provenance)

        return None
