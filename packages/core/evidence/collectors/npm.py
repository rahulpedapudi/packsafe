"""npm Registry evidence collector with truthful publication window and download metrics."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any
import httpx

from packsafe.evidence.models import (
    EvidenceProvenance,
    PackageIdentity,
    RegistryEvidence,
)

logger = logging.getLogger(__name__)


class NpmCollector:
    """Collects package metadata and download statistics from npm registry."""

    def __init__(
        self,
        timeout: tuple[float, float] = (5.0, 15.0),
        client: httpx.Client | None = None,
    ) -> None:
        self.timeout = httpx.Timeout(connect=timeout[0], read=timeout[1], write=10.0, pool=10.0)
        self._client = client

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout, follow_redirects=True)

    def collect(
        self,
        package_name: str,
        version: str | None = None,
    ) -> tuple[PackageIdentity, RegistryEvidence, EvidenceProvenance, str | None]:
        """Collects package metadata from npm registry.

        Returns (PackageIdentity, RegistryEvidence, EvidenceProvenance, tarball_download_url).
        """
        encoded_pkg = package_name.replace("/", "%2F")
        url = f"https://registry.npmjs.org/{encoded_pkg}"
        now = datetime.now(timezone.utc)
        client = self._get_client()

        try:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                dist_tags = data.get("dist-tags", {})
                latest = dist_tags.get("latest", "1.0.0")
                resolved_version = version or latest

                versions = data.get("versions", {})
                v_data = versions.get(resolved_version, {})
                repo = data.get("repository") or v_data.get("repository")
                repo_raw = repo.get("url") if isinstance(repo, dict) else str(repo) if repo else None
                repo_url: str | None = None
                if repo_raw:
                    repo_url = repo_raw.replace("git+", "").replace("git://", "https://")
                    if repo_url.endswith(".git"):
                        repo_url = repo_url[:-4]
                    if repo_url.startswith("ssh://git@"):
                        repo_url = "https://" + repo_url[len("ssh://git@"):]

                # Parse release publication timestamps from time dictionary
                time_dict = data.get("time", {})
                all_timestamps: list[datetime] = []
                for v_key, t_str in time_dict.items():
                    if v_key in ("created", "modified"):
                        continue
                    try:
                        dt = datetime.fromisoformat(t_str.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        all_timestamps.append(dt)
                    except Exception:
                        pass

                one_year_ago = now - timedelta(days=365)
                three_months_ago = now - timedelta(days=90)

                rel_1y = sum(1 for t in all_timestamps if t >= one_year_ago) if all_timestamps else None
                rel_3m = sum(1 for t in all_timestamps if t >= three_months_ago) if all_timestamps else None

                days_since_last: float | None = None
                maturity_days: float | None = None

                created_str = time_dict.get("created")
                if created_str:
                    try:
                        c_dt = datetime.fromisoformat(created_str.replace("Z", "+00:00")).replace(tzinfo=timezone.utc)
                        maturity_days = max(0.0, (now - c_dt).total_seconds() / 86400.0)
                    except Exception:
                        pass

                if all_timestamps:
                    all_timestamps.sort()
                    latest_time = all_timestamps[-1]
                    days_since_last = max(0.0, (now - latest_time).total_seconds() / 86400.0)
                    if maturity_days is None:
                        maturity_days = max(0.0, (now - all_timestamps[0]).total_seconds() / 86400.0)

                # Extract tarball URL and registry integrity (SRI or shasum)
                dist_info = v_data.get("dist", {})
                tarball_url = dist_info.get("tarball")
                registry_integrity = dist_info.get("integrity") or dist_info.get("shasum")

                # Maintainer count
                maintainers = data.get("maintainers")
                maintainer_count = len(maintainers) if isinstance(maintainers, list) else None

                # Query npm downloads
                downloads_30d = self._fetch_downloads(client, encoded_pkg)

                identity = PackageIdentity(
                    name=package_name,
                    ecosystem="npm",
                    version=resolved_version,
                    package_url=f"https://www.npmjs.com/package/{package_name}",
                    repository_url=repo_url,
                    archive_hash=None,  # Computed directly upon downloading archive bytes
                    registry_integrity=registry_integrity,
                )

                reg_ev = RegistryEvidence(
                    published_at=all_timestamps[-1] if all_timestamps else None,
                    latest_version=latest,
                    release_count_1y=rel_1y,
                    release_count_3m=rel_3m,
                    days_since_last_release=days_since_last,
                    project_maturity_days=maturity_days,
                    maintainer_count=maintainer_count,
                    downloads_30d=downloads_30d,
                    download_growth_rate=None,  # npm point API only gives 30d total, not history
                    declared_license=v_data.get("license") or data.get("license"),
                    status="AVAILABLE",
                )

                prov = EvidenceProvenance(
                    source="registry",
                    source_url=url,
                    retrieved_at=now,
                )

                return (identity, reg_ev, prov, tarball_url)
            elif resp.status_code == 404:
                logger.info(f"npm package '{package_name}' not found (404).")
        except Exception as e:
            logger.debug(f"npm collection failed for '{package_name}': {e}")

        identity = PackageIdentity(
            name=package_name,
            ecosystem="npm",
            version=version or "1.0.0",
        )
        reg_ev = RegistryEvidence(status="MISSING")
        prov = EvidenceProvenance(source="registry", source_url=url, retrieved_at=now)
        return (identity, reg_ev, prov, None)

    def _fetch_downloads(self, client: httpx.Client, encoded_pkg: str) -> int | None:
        """Queries npm point downloads API for 30-day downloads."""
        url = f"https://api.npmjs.org/downloads/point/last-month/{encoded_pkg}"
        try:
            resp = client.get(url)
            if resp.status_code == 200:
                d = resp.json().get("downloads")
                if d is not None:
                    return int(d)
        except Exception:
            pass
        return None
