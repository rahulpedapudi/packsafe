"""CISA Known Exploited Vulnerabilities (KEV) catalog collector with caching.

KEV membership means "exploitation of this CVE was observed at some point". CISA
rarely removes entries, so membership is *not* evidence of current exploitation. The
listing date and the ransomware flag are carried through so downstream consumers can
reason about recency instead of treating membership as a live signal.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import httpx

from ..config import settings
from ..tracing import fmt_duration, log_http

logger = logging.getLogger(__name__)

CACHE_FILENAME = "kev_catalog.json"


@dataclass(frozen=True)
class KEVEntry:
    """A single CISA KEV catalog record."""

    cve_id: str
    date_added: date
    ransomware: bool  # knownRansomwareCampaignUse == "Known"


class KEVCollector:
    """Collects and caches the official CISA Known Exploited Vulnerabilities catalog."""

    def __init__(
        self,
        cache_ttl_seconds: int = 86400,  # 24 hours
        timeout: tuple[float, float] = (5.0, 30.0),
        cache_path: Path | None = None,
    ) -> None:
        self.cache_ttl = cache_ttl_seconds
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )
        self.cache_path = cache_path or (settings.APP_ROOT / CACHE_FILENAME)

        self._cached: dict[str, KEVEntry] = {}
        self._last_fetched: float = 0.0
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ caching

    def _disk_cache_is_fresh(self) -> bool:
        try:
            age = time.time() - self.cache_path.stat().st_mtime
        except OSError:
            return False
        return age < self.cache_ttl

    def _load_disk_cache(self) -> dict[str, KEVEntry]:
        """Loads the on-disk catalog. Returns {} if absent or unreadable."""
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
            fetched_at = float(raw.get("fetched_at", 0.0))
        except (OSError, ValueError, TypeError) as e:
            logger.debug("KEV disk cache unreadable: %s", e)
            return {}

        if (time.time() - fetched_at) >= self.cache_ttl:
            return {}

        catalog: dict[str, KEVEntry] = {}
        for item in raw.get("entries", []):
            try:
                catalog[item["cve_id"]] = KEVEntry(
                    cve_id=item["cve_id"],
                    date_added=date.fromisoformat(item["date_added"]),
                    ransomware=bool(item["ransomware"]),
                )
            except (KeyError, ValueError, TypeError):
                continue

        if catalog:
            self._last_fetched = fetched_at
        return catalog

    def _write_disk_cache(self, catalog: dict[str, KEVEntry], fetched_at: float) -> None:
        """Best-effort persist. A failed write only costs a refetch next run."""
        payload = {
            "fetched_at": fetched_at,
            "source": settings.CISA_FEED_URL,
            "entries": [
                {
                    "cve_id": e.cve_id,
                    "date_added": e.date_added.isoformat(),
                    "ransomware": e.ransomware,
                }
                for e in catalog.values()
            ],
        }
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as e:
            logger.debug("Could not persist KEV cache: %s", e)

    # ------------------------------------------------------------------ parsing

    @staticmethod
    def parse_catalog(data: dict[str, Any]) -> dict[str, KEVEntry]:
        """Builds a CVE -> KEVEntry mapping from the raw feed payload.

        Entries with a missing or unparseable dateAdded are skipped: recency is
        load-bearing for the exploitation signal, so a dateless entry cannot be
        classified honestly.
        """
        catalog: dict[str, KEVEntry] = {}

        for item in data.get("vulnerabilities", []):
            cve = str(item.get("cveID", "")).strip().upper()
            if not cve:
                continue
            try:
                added = date.fromisoformat(str(item.get("dateAdded", ""))[:10])
            except ValueError:
                logger.debug("Skipping KEV entry %s: unusable dateAdded", cve)
                continue

            catalog[cve] = KEVEntry(
                cve_id=cve,
                date_added=added,
                ransomware=(
                    str(item.get("knownRansomwareCampaignUse", "")).strip().lower()
                    == "known"
                ),
            )

        return catalog

    async def _fetch_live(self) -> dict[str, KEVEntry]:
        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            request_start = time.perf_counter()
            resp = await client.get(settings.CISA_FEED_URL)
            request_elapsed = time.perf_counter() - request_start

            log_http(
                logger,
                "cisa_kev",
                method="GET",
                url=settings.CISA_FEED_URL,
                status=resp.status_code,
                elapsed=request_elapsed,
            )
            resp.raise_for_status()

            raw_count = len(resp.json().get("vulnerabilities", []))
            catalog = self.parse_catalog(resp.json())
            logger.info(
                "kev catalog fetched | raw_entries=%d usable_entries=%d skipped=%d "
                "(entries without a parseable dateAdded cannot be classified by recency) "
                "| duration=%s",
                raw_count,
                len(catalog),
                raw_count - len(catalog),
                fmt_duration(request_elapsed),
            )
            return catalog

    # ------------------------------------------------------------------- public

    async def aclose(self) -> None:
        """No persistent client is held, so there is nothing to release."""
        return None

    async def __aenter__(self) -> KEVCollector:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def fetch_catalog(self) -> dict[str, KEVEntry]:
        """Returns the KEV catalog as a CVE -> KEVEntry mapping.

        Memory cache first, then disk cache, then the live feed. A failed fetch falls
        back to whatever is cached so a network outage degrades rather than raises.
        """
        async with self._lock:
            now = time.time()
            if self._cached and (now - self._last_fetched) < self.cache_ttl:
                logger.debug(
                    "kev catalog | memory cache hit, %d entries, %.0fs old",
                    len(self._cached),
                    now - self._last_fetched,
                )
                return self._cached

            if not self._cached:
                self._cached = self._load_disk_cache()
                if self._cached:
                    logger.info(
                        "kev catalog | disk cache hit, %d entries loaded from %s",
                        len(self._cached),
                        self.cache_path,
                    )
                    return self._cached

            try:
                catalog = await self._fetch_live()
            except (httpx.HTTPError, ValueError) as e:
                logger.warning(
                    "kev catalog | live CISA feed unavailable (%s: %s); falling back to "
                    "%d cached entries. Exploitation signals may be stale.",
                    type(e).__name__,
                    e,
                    len(self._cached),
                )
                return self._cached

            self._cached = catalog
            self._last_fetched = now
            self._write_disk_cache(catalog, now)
            logger.info(
                "kev catalog | %d entries cached to %s for %ds",
                len(catalog),
                self.cache_path,
                self.cache_ttl,
            )
            return self._cached


async def main():
    async with KEVCollector() as collector:
        catalog = await collector.fetch_catalog()
        print(len(catalog))
        for entry in list(catalog.values())[:5]:
            print(entry)


if __name__ == "__main__":
    asyncio.run(main())