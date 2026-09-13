from typing import Protocol

from ..models.package import PackageMetadata, PackageRequest


class PackageRegistry(Protocol):
    # Protocol means - anything that has exists() method with this compatible signature can be treated as a PackageRegistry

    def exists(
        self, package: PackageRequest
    ) -> tuple[bool, PackageMetadata | None]: ...

    def extract_metadata(self, data: dict) -> PackageMetadata: ...
