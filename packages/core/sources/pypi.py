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
from ..tracing import fmt_duration, fmt_fields, log_http

logger = logging.getLogger(__name__)


class PyPIRegistry:
    async def exists(
        self, package: PackageRequest
    ) -> tuple[
        bool,
        tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None] | None,
    ]:
        start = time.perf_counter()
        url = f"{settings.PYPI_BASE_URL}/{package.name}/json"
        logger.info(
            "pypi lookup | %s",
            fmt_fields({"package": package.name, "requested_version": package.version}),
        )

        try:
            async with httpx.AsyncClient() as client:
                network_start = time.perf_counter()
                response = await client.get(url, timeout=5)
                network_elapsed = time.perf_counter() - network_start

                log_http(
                    logger,
                    "pypi",
                    method="GET",
                    url=url,
                    status=response.status_code,
                    elapsed=network_elapsed,
                )

                if response.status_code == 200:
                    metadata = await self.extract_metadata(
                        package.name, package.version, response.json()
                    )
                    identity, reg_ev, _, dist_url = metadata
                    logger.info(
                        "pypi fetch ok | resolved_version=%s latest_version=%s "
                        "declared_license=%s dist_url=%s archive_sha256=%s",
                        identity.version,
                        reg_ev.latest_version,
                        reg_ev.declared_license,
                        dist_url or "none",
                        identity.archive_hash or "none",
                    )
                    return (True, metadata)

                logger.warning(
                    "pypi fetch | HTTP %d for %s: treating the package as non-existent",
                    response.status_code,
                    package.name,
                )
                return (False, None)

        except httpx.HTTPError as e:
            logger.error("pypi fetch failed for %s: %s", package.name, e)
            raise httpx.HTTPError(f"Could not fetch the data from pypi: {e}")
        finally:
            elapsed = time.perf_counter() - start
            logger.info("pypi lookup complete | duration=%s", fmt_duration(elapsed))

    def _extract_repository_url(self, info: dict[str, Any]) -> str | None:
        # PyPI has no standard key for this: popular projects use "Source", "Code" or
        # "Repository" interchangeably, and a few only declare a "Homepage".
        return (
            info.get("Source")
            or info.get("Repository")
            or info.get("Code")
            or info.get("Source Code")
            or info.get("Homepage")
        )

    async def extract_metadata(
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
                logger.debug(
                    "pypi parse | release %s -> earliest upload %s",
                    ver,
                    dt.isoformat(timespec="seconds"),
                )

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

        logger.debug(
            "pypi metadata extraction | releases_total=%d distinct_release_dates=%d "
            "files_for_resolved_version=%d dist_url=%s",
            len(releases),
            len(all_v_times),
            len(version_files),
            dist_url or "NOT FOUND (archive stage will be skipped)",
        )
        if not dist_url:
            logger.warning(
                "pypi metadata | no .tar.gz/.whl distribution found for %s==%s, so no "
                "archive can be downloaded and static analysis is impossible",
                name,
                resolved_version,
            )

        downloads_30d, growth_rate = await self._fetch_downloads(package_name=name)

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
            downloads_30d=downloads_30d,
            download_growth_rate=growth_rate,
            # Modern metadata (PEP 639) dropped the free-text license field for
            # license_expression; older projects only fill in one of the two.
            declared_license=info.get("license")
            or info.get("license_expression")
            or "UNKNOWN",
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
    # async def get_stats(self, package: PackageRequest): ...

    # ! Not Ideal for production, use bigquery instead
    async def _fetch_downloads(
        self, package_name: str
    ) -> tuple[int | None, float | None]:
        """Queries pypistats for recent 30d download counts without fabricating unmeasured growth."""
        stats_url = f"https://pypistats.org/api/packages/{package_name}/recent"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(stats_url)
                if resp.status_code == 200:
                    data = resp.json().get("data", {})
                    last_month = data.get("last_month")
                if last_month is not None:
                    # Previous 30-day baseline is not provided in pypistats recent endpoint;
                    # truthfully return None for growth rather than an ad-hoc approximation.
                    return (int(last_month), None)
        except Exception:
            pass
        return (None, None)


if __name__ == "__main__":
    pypi = PyPIRegistry()
    pypi_result = asyncio.run(pypi.exists(PackageRequest(name="fastapi")))
    print(pypi_result)
