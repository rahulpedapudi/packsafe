from ..models.package import PackageRequest
from ..sources.pypi import PyPIRegistry
from .context import AnalysisContext
from .stages.existence import ExistenceStage


class AnalysisPipeline:
    def run(self, request: PackageRequest) -> AnalysisContext:
        # this context is passed to every stage; each stage add analytics/info to the same context object
        context = AnalysisContext(request=request)

        # creates respective registry based on the ecosystem
        # currently only supports PyPI
        registry = PyPIRegistry() if request.ecosystem == "pypi" else None

        # checks whether the package exists in the registry or not.
        # if existed, it also extracts the required metadata from the registry
        ExistenceStage(registry).execute(context)

        return context
