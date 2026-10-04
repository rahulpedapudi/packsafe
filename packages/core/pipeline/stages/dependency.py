import logging

from ...pipeline.context import AnalysisContext
from ...sources.deps_dev import DepsDevCollector
from ...tracing import pick, stage_trace

logger = logging.getLogger(__name__)


class DependencyStage:
    def __init__(self):
        self.deps_dev = DepsDevCollector()

    async def execute(self, context: AnalysisContext):

        with stage_trace(
            "dependency",
            logger,
            inputs=pick(context.package, ("name", "version", "ecosystem")),
            dump=context.dependencies,
        ) as span:
            dep_evidence = await self.deps_dev.collect_dependencies(
                context.package.name, context.package.version, context.package.ecosystem
            )

            (
                dependents_count,
                dependents_source,
            ) = await self.deps_dev.collect_dependents_count(
                context.package.name, context.package.ecosystem
            )

            context.dependencies = dep_evidence

            context.registry.dependents_count = dependents_count
            context.registry.dependents_source = dependents_source

            span.output(
                **pick(
                    context.dependencies,
                    (
                        "status",
                        "direct_count",
                        "transitive_count",
                        "max_depth",
                        "abandoned_count",
                        "new_dependencies_count",
                        "churn_rate",
                        "vulnerable_dependency_count",
                    ),
                ),
                dependents_count=dependents_count,
                dependents_source=dependents_source,
            )
            if context.dependencies.status != "AVAILABLE":
                span.degrade(
                    "dependency tree unavailable: "
                    f"{context.dependencies.status}"
                )
            if dependents_count is None:
                span.degrade("dependents count unavailable from any source")