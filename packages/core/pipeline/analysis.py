import asyncio
import logging
import time

from ..exceptions import PackageNotFoundError
from ..models.package import PackageRequest
from ..models.scoring import ScoreResult
from ..scoring.engine import ScoreEngine
from ..sources.pypi import PyPIRegistry
from ..tracing import fmt_duration, fmt_fields, perf
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
        # Spans accumulate per process, so a second analysis in the same process would
        # otherwise report the first run's timings too.
        perf.reset()

        logger.info("=" * 100)
        logger.info(
            "PIPELINE START | %s",
            fmt_fields(
                {
                    "package": request.name,
                    "version": request.version,
                    "ecosystem": request.ecosystem,
                    "scan_type": request.scan_type,
                    "profile": request.profile,
                }
            ),
        )

        # this context is passed to every stage; each stage add analytics/info to the same context object
        context = AnalysisContext(request=request)

        # creates respective registry based on the ecosystem
        # currently only supports PyPI
        registry = PyPIRegistry() if request.ecosystem == "pypi" else None
        logger.info(
            "orchestration | registry=%s | batch1=[existence] -> batch2=[vulnerability, "
            "repository, dependency, archive] (concurrent) -> batch3=[license, identity] "
            "(concurrent) -> coverage -> score",
            type(registry).__name__ if registry else "unsupported",
        )

        await ExistenceStage(registry).execute(context)

        # A package that does not exist has no identity, version, or distribution
        # URL, so every downstream stage would operate on None. Raise instead: an
        # absent package must never be reported as a perfect score.
        if context.package.name is None:
            elapsed = time.perf_counter() - analysis_start
            logger.error(
                "PIPELINE ABORT | package not found | %s | elapsed=%s",
                fmt_fields({"package": request.name, "ecosystem": request.ecosystem}),
                fmt_duration(elapsed),
            )
            perf.log_summary(logger, wall_seconds=elapsed)
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

        coverage_start = time.perf_counter()
        context.analysis_coverage_tier = compute_coverage_tier(context)
        logger.info(
            "stage=coverage event=end | tier=%s | basis=static_analysis=%s repository=%s "
            "dependencies=%s | duration=%s",
            context.analysis_coverage_tier,
            context.static_analysis.status,
            context.repository.status,
            context.dependencies.status,
            fmt_duration(time.perf_counter() - coverage_start),
        )
        perf.record("coverage", time.perf_counter() - coverage_start)

        # Score Engine

        score_start = time.perf_counter()
        score = ScoreEngine().calculate(context)
        perf.record("score_engine", time.perf_counter() - score_start)

        elapsed = time.perf_counter() - analysis_start

        logger.info(
            "SCORE RESULT | %s",
            fmt_fields(
                {
                    "final_score": round(score.final_score, 2),
                    "base_score": round(score.base_score, 2),
                    "risk_level": score.risk_level.value,
                    "decision": score.decision.value,
                    "confidence": score.confidence,
                    "coverage_tier": context.analysis_coverage_tier,
                    "categories": ", ".join(
                        f"{name}={cat.score:.1f}"
                        for name, cat in score.categories.items()
                    ),
                    "findings": len(score.findings),
                    "gates_triggered": sum(1 for g in score.gates if g.triggered),
                }
            ),
        )
        logger.info(
            "PIPELINE COMPLETE | package=%s version=%s | total=%s | evidence_sources=%d | "
            "provenance_records=%d",
            score.package_name,
            score.version,
            fmt_duration(elapsed),
            len({p.source for p in context.provenance}),
            len(context.provenance),
        )
        perf.log_summary(logger, wall_seconds=elapsed)
        return score


async def main():
    pipeline = AnalysisPipeline()
    request = PackageRequest(name="urllib3", ecosystem="pypi", version="2.7.2")
    score = await pipeline.run(request)
    print(score)


if __name__ == "__main__":
    asyncio.run(main())
