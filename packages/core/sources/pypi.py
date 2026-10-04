import asyncio
import logging
import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx

from ..config import settings
from ..models.evidence import EvidenceProvenance, RegistryEvidence
from ..models.package import EcosystemType, PackageIdentity, PackageRequest

logger = logging.getLogger(__name__)


class PyPIRegistry:
    async def exists(
        self, package: PackageRequest
    ) -> tuple[
        bool,
        tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None] | None,
    ]:
        start = time.perf_counter()
        logger.info(f"Checking PyPI Registry for {package}")

        try:
            async with httpx.AsyncClient() as client:
                network_start = time.perf_counter()
                response = await client.get(
                    f"{settings.PYPI_BASE_URL}/{package.name}/json", timeout=5
                )
                network_elapsed = time.perf_counter() - network_start

                logger.info(
                    f"Network Call Completed in {network_elapsed:.2f} seconds | {network_elapsed * 1000:.2f} ms"
                )

                if response.status_code == 200:
                    # extracts all the package info from pypi
                    return (
                        True,
                        self.extract_metadata(
                            package.name, package.version, response.json()
                        ),
                    )
                else:
                    return (False, None)

        except httpx.HTTPError as e:
            raise httpx.HTTPError(f"Could not fetch the data from pypi: {e}")
        finally:
            elapsed = time.perf_counter() - start
            logger.info(
                f"Checking PyPI Registry Completed in {elapsed:.2f} seconds | {elapsed * 1000:.2f} ms"
            )

    def _extract_repository_url(self, info: dict[str, Any]) -> str | None:
        return (
            info.get("Source")
            or info.get("Repository")
            or info.get("Source Code")
            or info.get("Homepage")
        )

    def extract_metadata(
        self, name: str, version: str | None, data: dict
    ) -> tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None]:
        now = datetime.now(UTC)

        info = data.get("info", {})
        releases = data.get("releases", {})

        resolved_version = (
            version if version is not None else info.get("version", "1.0.0")
        )
        project_urls = info.get("project_urls") or {}

        repo_url = self._extract_repository_url(project_urls)

        # Distinct version publication timestamps
        version_timestamps: dict[str, datetime] = {}
        for ver, files in releases.items():
            for file_info in files:
                upload_str = file_info.get("upload_time_iso_8601") or file_info.get(
                    "upload_time"
                )
                if upload_str:
                    try:
                        dt = datetime.fromisoformat(upload_str)
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=UTC)
                        if (
                            ver not in version_timestamps
                            or dt < version_timestamps[ver]
                        ):
                            version_timestamps[ver] = dt
                    except Exception as e:
                        logger.info(f"Failed to Parse upload date: {e}")

        # Calculate temporal metrics on DISTINCT versions
        one_year_ago = now - timedelta(days=365)
        three_months_ago = now - timedelta(days=90)

        all_v_times = list(version_timestamps.values())
        rel_1y = (
            sum(1 for t in all_v_times if t >= one_year_ago) if all_v_times else None
        )
        rel_3m = (
            sum(1 for t in all_v_times if t >= three_months_ago)
            if all_v_times
            else None
        )

        days_since_last: float | None = None
        maturity_days: float | None = None
        if all_v_times:
            all_v_times.sort()
            earliest = all_v_times[0]
            latest = all_v_times[-1]
            days_since_last = max(0.0, (now - latest).total_seconds() / 86400.0)
            maturity_days = max(0.0, (now - earliest).total_seconds() / 86400.0)

        # Find archive download URL and hash for this version
        dist_url: str | None = None
        archive_hash: str | None = None
        version_files = releases.get(resolved_version, [])
        for f in version_files:
            f_url = f.get("url", "")
            if f_url.endswith((".tar.gz", ".whl")):
                dist_url = f_url
                archive_hash = f.get("digests", {}).get("sha256")
                break

        # TODO: Implement download statistics from pypistats API
        # downloads_30d, growth_rate = self.get_stats(package_name)

        identity = PackageIdentity(
            name=name,
            ecosystem=EcosystemType.pypi,
            version=resolved_version,
            package_url=info.get("package_url"),
            repository_url=repo_url,
            archive_hash=archive_hash,
        )

        # Extract unique maintainers/authors from PyPI metadata
        maintainers_set: set[str] = set()
        for field in (
            "maintainer",
            "maintainer_email",
            "author",
            "author_email",
        ):
            val = info.get(field)
            if val and isinstance(val, str):
                for part in re.split(r"[,;/\n]+", val):
                    cleaned = part.strip()
                    if cleaned:
                        maintainers_set.add(cleaned.lower())
        parsed_maintainer_count = len(maintainers_set) if maintainers_set else None

        reg_ev = RegistryEvidence(
            published_at=all_v_times[-1] if all_v_times else None,
            latest_version=info.get("version"),
            release_count_1y=rel_1y,
            release_count_3m=rel_3m,
            days_since_last_release=int(days_since_last) if days_since_last else None,
            project_maturity_days=int(maturity_days) if maturity_days else None,
            maintainer_count=parsed_maintainer_count,
            # downloads_30d=downloads_30d,
            # download_growth_rate=growth_rate,
            declared_license=info.get("license") or "UNKNOWN",
            status="AVAILABLE",
        )

        prov = EvidenceProvenance(
            source="registry",
            source_url=settings.PYPI_BASE_URL,
            retrieved_at=now,
            archive_sha256=archive_hash,
        )

        return (identity, reg_ev, prov, dist_url)

    # fetch stats from packsafe backend server
    async def get_stats(self, package: PackageRequest): ...


if __name__ == "__main__":
    pypi = PyPIRegistry()
    pypi_result = asyncio.run(pypi.exists(PackageRequest(name="fastapi")))
    print(pypi_result)
