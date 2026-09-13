from ...models.package import PackageInfo
from ...pipeline.context import AnalysisContext
from ...sources.base import PackageRegistry


class ExistenceStage:
    def __init__(self, registry: PackageRegistry):
        # the package existence check should work irrespective of type of registry
        # it doesnt need to know what registry its working with
        self.registry = registry

    def execute(self, context: AnalysisContext) -> None:

        requested_package = context.request

        # checks for package existence
        exists, metadata = self.registry.exists(requested_package)

        # accumulates context with package info
        context.package = PackageInfo(
            name=requested_package.name,
            version=requested_package.version,
            exists=exists,
            metadata=metadata,
        )
