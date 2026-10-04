import asyncio
import logging

from ..models.package import PackageRequest

# from ..scoring.engine import ScoreEngine
from ..sources.pypi import PyPIRegistry
from .context import AnalysisContext
from .stages.dependency import DependencyStage
from .stages.existence import ExistenceStage
from .stages.repository import RepositoryStage
from .stages.vulnerability import VulnerabilityStage

logging.basicConfig(
    filename="app-dev.log",
    filemode="w",
    # capturing INFO level and above
    level=logging.INFO,
    format=("%(asctime)s | %(levelname)s | %(name)s | %(message)s"),
)

logger = logging.getLogger(__name__)

import time


class AnalysisPipeline:
    async def run(self, request: PackageRequest) -> AnalysisContext:

        # 1. collect data from various sources - pypi, osv, github deps.dev etc
        # 2. normalize data if needed. (KEV Normalizer)
        # n. static analysis - AST, and direct exec call analysis
        analysis_start = time.perf_counter()
        logger.info(f"Analysis Pipeline Started for {request}")

        # this context is passed to every stage; each stage add analytics/info to the same context object
        context = AnalysisContext(request=request)

        # creates respective registry based on the ecosystem
        # currently only supports PyPI
        registry = PyPIRegistry() if request.ecosystem == "pypi" else None

        await ExistenceStage(registry).execute(context)

        await asyncio.gather(
            VulnerabilityStage().execute(context),
            RepositoryStage().execute(context),
            DependencyStage().execute(context),
        )

        # 4. Archive Download & Static Analysis & License Verification
        # 5. License Evidence
        # 6. Truthful Identity & Typosquatting Evaluation

        # Score Engine

        # score = ScoreEngine().calculate(context)

        elapsed = time.perf_counter() - analysis_start
        logger.info(
            f"Analysis Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms"
        )
        return context


async def main():
    pipeline = AnalysisPipeline()
    request = PackageRequest(name="litellm", ecosystem="pypi")
    score = await pipeline.run(request)
    # print(score)


if __name__ == "__main__":
    asyncio.run(main())
