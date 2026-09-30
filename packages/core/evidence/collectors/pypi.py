"""PyPI Registry evidence collector with truthful timestamp calculation and download metrics."""

from __future__ import annotations

import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Any
import httpx

from packsafe.evidence.models import (
    EvidenceProvenance,
    PackageIdentity,
    RegistryEvidence,
)

import time

logger = logging.getLogger(__name__)


class PyPICollector:
    """Collects metadata from PyPI JSON API and download statistics with retry support."""

    def __init__(
        self,
        timeout: tuple[float, float] = (5.0, 15.0),
        max_retries: int = 2,
        client: httpx.Client | None = None,
    ) -> None:
        self.timeout = httpx.Timeout(connect=timeout[0], read=timeout[1], write=10.0, pool=10.0)
        self.max_retries = max_retries
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(
            timeout=self.timeout,
            follow_redirects=True,
            headers={"User-Agent": "PackSafeScoreEngine/1.0.0 (security-audit; contact@packsafe.io)"},
        )

    def _extract_repository_url(self, info: dict[str, Any]) -> str | None:
        project_urls = info.get("project_urls") or {}
        return (
            project_urls.get("Source")
            or project_urls.get("Repository")
            or project_urls.get("Source Code")
            or project_urls.get("Homepage")
        )

    def collect(
        self,
        package_name: str,
        version: str | None = None,
    ) -> tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None]:
        """Collects package metadata from PyPI.

        Returns (PackageIdentity, RegistryEvidence, EvidenceProvenance, distribution_download_url).
        """
        url = f"https://pypi.org/pypi/{package_name}/json"
        now = datetime.now(timezone.utc)
        client = self._get_client()

        for attempt in range(self.max_retries + 1):
            try:
                resp = client.get(url)
                if resp.status_code == 200:
                    data = resp.json()
                    info = data.get("info", {})
                    releases = data.get("releases", {})

                    resolved_version = version or info.get("version", "1.0.0")
                    repo_url = self._extract_repository_url(info)

                    # Distinct version publication timestamps
                    version_timestamps: dict[str, datetime] = {}
                    for ver, files in releases.items():
                        for file_info in files:
                            upload_str = file_info.get("upload_time_iso_8601") or file_info.get("upload_time")
                            if upload_str:
                                try:
                                    dt = datetime.fromisoformat(upload_str.replace("Z", "+00:00"))
                                    if dt.tzinfo is None:
                                        dt = dt.replace(tzinfo=timezone.utc)
                                    if ver not in version_timestamps or dt < version_timestamps[ver]:
                                        version_timestamps[ver] = dt
                                except Exception:
                                    pass

                    # Calculate temporal metrics on DISTINCT versions
                    one_year_ago = now - timedelta(days=365)
                    three_months_ago = now - timedelta(days=90)

                    all_v_times = list(version_timestamps.values())
                    rel_1y = sum(1 for t in all_v_times if t >= one_year_ago) if all_v_times else None
                    rel_3m = sum(1 for t in all_v_times if t >= three_months_ago) if all_v_times else None

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
                        if f_url.endswith(".tar.gz") or f_url.endswith(".whl"):
                            dist_url = f_url
                            archive_hash = f.get("digests", {}).get("sha256")
                            break

                    # Query download statistics from pypistats API if available
                    downloads_30d, growth_rate = self._fetch_downloads(client, package_name)

                    identity = PackageIdentity(
                        name=package_name,
                        ecosystem="pypi",
                        version=resolved_version,
                        package_url=info.get("package_url"),
                        repository_url=repo_url,
                        archive_hash=archive_hash,
                    )

                    # Extract unique maintainers/authors from PyPI metadata
                    maintainers_set: set[str] = set()
                    for field in ("maintainer", "maintainer_email", "author", "author_email"):
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
                        days_since_last_release=days_since_last,
                        project_maturity_days=maturity_days,
                        maintainer_count=parsed_maintainer_count,
                        downloads_30d=downloads_30d,
                        download_growth_rate=growth_rate,
                        declared_license=info.get("license") or "UNKNOWN",
                        status="AVAILABLE",
                    )

                    prov = EvidenceProvenance(
                        source="registry",
                        source_url=url,
                        retrieved_at=now,
                        archive_sha256=archive_hash,
                    )

                    return (identity, reg_ev, prov, dist_url)
                elif resp.status_code == 404:
                    logger.info(f"PyPI package '{package_name}' not found (404).")
                    break
                elif resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 1.0 + attempt * 2))
                    time.sleep(min(retry_after, 5.0))
                    continue
                elif resp.status_code >= 500:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.debug(f"PyPI collection error on attempt {attempt}: {e}")
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                else:
                    break
            except Exception as e:
                logger.debug(f"PyPI collection failed for '{package_name}': {e}")
                break

        # Missing fallback
        identity = PackageIdentity(
            name=package_name,
            ecosystem="pypi",
            version=version or "1.0.0",
        )
        reg_ev = RegistryEvidence(status="MISSING")
        prov = EvidenceProvenance(source="registry", source_url=url, retrieved_at=now)
        return (identity, reg_ev, prov, None)

    def _fetch_downloads(self, client: httpx.Client, package_name: str) -> tuple[int | None, float | None]:
        """Queries pypistats for recent 30d download counts without fabricating unmeasured growth."""
        stats_url = f"https://pypistats.org/api/packages/{package_name}/recent"
        try:
            resp = client.get(stats_url)
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
