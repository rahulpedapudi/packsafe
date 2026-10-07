from typing import Protocol

import httpx

from ..models.evidence import EvidenceProvenance, RegistryEvidence
from ..models.package import PackageIdentity, PackageMetadata, PackageRequest


class PackageRegistry(Protocol):
    # Protocol means - anything that has exists() method with this compatible signature can be treated as a PackageRegistry

    async def exists(
        self, package: PackageRequest
    ) -> tuple[
        bool,
        tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None] | None,
    ]: ...

    def extract_metadata(self, data: dict) -> PackageMetadata: ...

    async def get_stats(self, client: httpx.AsyncClient, package: PackageRequest): ...
