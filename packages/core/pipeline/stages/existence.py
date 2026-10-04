import logging

from ...models.evidence import EvidenceProvenance
from ...models.package import PackageIdentity, PackageRequest
from ...pipeline.context import AnalysisContext
from ...sources.base_registry import PackageRegistry
from ...tracing import pick, stage_trace

logger = logging.getLogger(__name__)


class ExistenceStage:
    def __init__(self, registry: PackageRegistry):
        # the package existence check should work irrespective of type of registry
        # it doesnt need to know what registry its working with
        self.registry = registry

    async def execute(
        self, context: AnalysisContext
    ) -> None | tuple[EvidenceProvenance, str | None]:

        with stage_trace(
            "existence",
            logger,
            inputs=pick(
                context.request,
                ("name", "version", "ecosystem", "scan_type", "profile"),
            ),
            dump=context.request,
        ) as span:
            requested_package: PackageRequest = context.request
            result = await self.registry.exists(requested_package)

            exists = result[0] if result else False

            if not (exists and result[1] is not None):
                span.output(exists=False, package_name=None)
                span.skip("registry reported no usable package metadata")
                return None

            identity, evidence, provenance, dist_url = result[1]
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

            span.output(
                exists=True,
                **pick(
                    context.package,
                    (
                        "name",
                        "version",
                        "ecosystem",
                        "repository_url",
                        "distribution_url",
                        "archive_hash",
                    ),
                ),
                **pick(
                    context.registry,
                    (
                        "status",
                        "latest_version",
                        "release_count_1y",
                        "release_count_3m",
                        "days_since_last_release",
                        "project_maturity_days",
                        "maintainer_count",
                        "declared_license",
                    ),
                ),
            )
            return None