import asyncio
import logging
import time

from ..exceptions import PackageNotFoundError
from ..models.package import PackageRequest
from ..models.scoring import ScoreResult
from ..scoring.engine import ScoreEngine
from ..sources.pypi import PyPIRegistry
from .context import AnalysisContext
from .coverage import compute_coverage_tier
from .stages.archive import ArchiveStage
from .stages.dependency import DependencyStage
from .stages.existence import ExistenceStage
from .stages.identity import IdentityStage
from .stages.license import LicenseStage
from .stages.repository import RepositoryStage
from .stages.vulnerability import VulnerabilityStage

logger = logging.getLogger(__name__)


class AnalysisPipeline:
    async def run(self, request: PackageRequest) -> ScoreResult:

        analysis_start = time.perf_counter()
        logger.info(f"Analysis Pipeline Started for {request}")

        # this context is passed to every stage; each stage add analytics/info to the same context object
        context = AnalysisContext(request=request)

        # creates respective registry based on the ecosystem
        # currently only supports PyPI
        registry = PyPIRegistry() if request.ecosystem == "pypi" else None

        await ExistenceStage(registry).execute(context)

        # A package that does not exist has no identity, version, or distribution
        # URL, so every downstream stage would operate on None. Raise instead: an
        # absent package must never be reported as a perfect score.
        if context.package.name is None:
            raise PackageNotFoundError(request.name, request.ecosystem)

        # Archive runs alongside the other existence-dependent stages: it only needs
        # context.package, which ExistenceStage has already populated.
        await asyncio.gather(
            VulnerabilityStage().execute(context),
            RepositoryStage().execute(context),
            DependencyStage().execute(context),
            ArchiveStage().execute(context),
        )

        # License needs license_file_found from the archive; Identity needs the
        # resolved repository. Both therefore wait for the batch above.
        await asyncio.gather(
            LicenseStage().execute(context),
            IdentityStage().execute(context),
        )

        context.analysis_coverage_tier = compute_coverage_tier(context)

        # Score Engine

        score = ScoreEngine().calculate(context)

        elapsed = time.perf_counter() - analysis_start
        logger.info(
            f"Analysis Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms"
        )
        return score


async def main():
    pipeline = AnalysisPipeline()
    request = PackageRequest(name="urllib3", ecosystem="pypi", version="2.7.2")
    score = await pipeline.run(request)
    print(score)


if __name__ == "__main__":
    asyncio.run(main())
