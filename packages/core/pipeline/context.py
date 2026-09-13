from dataclasses import dataclass

from ..models.package import PackageInfo, PackageRequest


# to accumulate everything during the analysis
@dataclass
class AnalysisContext:
    request: PackageRequest
    package: PackageInfo | None = None
