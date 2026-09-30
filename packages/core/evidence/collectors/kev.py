"""CISA Known Exploited Vulnerabilities (KEV) catalog collector with caching."""

from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
import httpx

logger = logging.getLogger(__name__)


class KEVCollector:
    """Collects and caches official CISA Known Exploited Vulnerabilities catalog."""

    FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    def __init__(
        self,
        feed_url: str | None = None,
        cache_ttl_seconds: int = 86400,  # 24 hours
        timeout: tuple[float, float] = (5.0, 30.0),
        client: httpx.Client | None = None,
    ) -> None:
        self.feed_url = feed_url or self.FEED_URL
        self.cache_ttl = cache_ttl_seconds
        self.timeout = httpx.Timeout(connect=timeout[0], read=timeout[1], write=10.0, pool=10.0)
        self._client = client
        self._cached_cves: dict[str, dict[str, Any]] = {}
        self._last_fetched: float = 0.0

    def _get_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        return httpx.Client(timeout=self.timeout, follow_redirects=True)

    def fetch_catalog(self) -> dict[str, dict[str, Any]]:
        """Fetches and caches the KEV catalog, returning mapping of CVE -> metadata."""
        now = time.time()
        if self._cached_cves and (now - self._last_fetched) < self.cache_ttl:
            return self._cached_cves

        client = self._get_client()
        try:
            resp = client.get(self.feed_url)
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
        except Exception as e:
            logger.debug(f"Failed to fetch live CISA KEV feed: {e}")

        return self._cached_cves
