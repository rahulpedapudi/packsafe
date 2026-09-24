import logging

from ..models.package import PackageRequest
from ..sources.pypi import PyPIRegistry
from .context import AnalysisContext
from .stages.existence import ExistenceStage

logger = logging.getLogger(__name__)
import time


class AnalysisPipeline:
    async def run(self, request: PackageRequest) -> AnalysisContext:
        analysis_start = time.perf_counter()
        logger.info(f"Analysis Pipeline Started for {request}")
        # this context is passed to every stage; each stage add analytics/info to the same context object
        context = AnalysisContext(request=request)

        # creates respective registry based on the ecosystem
        # currently only supports PyPI
        registry = PyPIRegistry() if request.ecosystem == "pypi" else None

        # checks whether the package exists in the registry or not.
        # if existed, it also extracts the required metadata from the registry
        if registry is not None:
            await ExistenceStage(registry).execute(context)

        elapsed = time.perf_counter() - analysis_start
        logger.info(
            f"Analysis Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms"
        )
        return context
