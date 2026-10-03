"""CISA Known Exploited Vulnerabilities (KEV) catalog collector with caching."""

from __future__ import annotations

import asyncio
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ..config import settings

logger = logging.getLogger(__name__)


class KEVCollector:
    """Collects and caches official CISA Known Exploited Vulnerabilities catalog."""

    def __init__(
        self,
        cache_ttl_seconds: int = 86400,  # 24 hours
        timeout: tuple[float, float] = (5.0, 30.0),
    ) -> None:
        self.cache_ttl = cache_ttl_seconds
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )

        self._cached_cves: dict[str, dict[str, Any]] = {}
        self._last_fetched: float = 0.0

    async def fetch_catalog(self) -> dict[str, dict[str, Any]]:
        """Fetches and caches the KEV catalog, returning mapping of CVE -> metadata."""
        now = time.time()

        # probably i need to implement local cache mechanism
        if self._cached_cves and (now - self._last_fetched) < self.cache_ttl:
            return self._cached_cves

        try:
            async with httpx.AsyncClient(
                timeout=self.timeout, follow_redirects=True
            ) as client:
                resp = await client.get(settings.CISA_FEED_URL)

                if resp.status_code == 200:
                    data = resp.json()
                    catalog: dict[str, dict[str, Any]] = {}

                    for item in data.get("vulnerabilities", []):
                        cve = item.get("cveID", "").strip().upper()
                        if cve:
                            catalog[cve] = {
                                "vendor_project": item.get("vendorProject"),
                                "product": item.get("product"),
                                "date_added": item.get("dateAdded"),
                                "short_description": item.get("shortDescription"),
                                "required_action": item.get("requiredAction"),
                            }

                    self._cached_cves = catalog
                    self._last_fetched = now
                    return self._cached_cves

        except httpx.HTTPError as e:
            logger.debug(f"Failed to fetch live CISA KEV feed: {e}")
            raise httpx.HTTPError(f"Couldn't fetch the data {e}")

        return self._cached_cves


if __name__ == "__main__":
    kev = KEVCollector()
    kev_fetched = asyncio.run(kev.fetch_catalog())
    print(kev_fetched)
