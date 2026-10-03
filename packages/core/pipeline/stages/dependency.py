import logging
import time

from ...pipeline.context import AnalysisContext
from ...sources.deps_dev import DepsDevCollector

logger = logging.getLogger(__name__)


class DependencyStage:
    def __init__(self):
        self.deps_dev = DepsDevCollector()

    async def execute(self, context: AnalysisContext):

        start_time = time.perf_counter()
        logger.info(f"Dependency Stage Started\nCurrent Context: {context}\n")

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

        end_time = time.perf_counter() - start_time

        logger.info(
            f"Dependency Stage Completed in {end_time:.2f} seconds | {end_time * 1000:.2f} ms\n"
        )
