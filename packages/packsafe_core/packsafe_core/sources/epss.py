"""FIRST EPSS (Exploit Prediction Scoring System) collector.

EPSS is the forward-looking counterpart to KEV: KEV says "exploitation happened at
some point", EPSS estimates the probability of exploitation in the next 30 days.
Scores are updated daily and require no authentication.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Iterable

import httpx

from ..config import settings
from ..tracing import log_http

logger = logging.getLogger(__name__)

# Stay well under practical URL length limits while keeping request count low.
EPSS_CHUNK_SIZE = 50

# Below this percentile a CVE is not meaningfully different from the bulk of CVEs,
# so it is treated as "no signal" rather than propagated as near-zero noise.
EPSS_FLOOR = 0.001


class EPSSCollector:
    """Fetches EPSS probability and percentile scores for a set of CVEs."""

    def __init__(
        self,
        timeout: tuple[float, float] = (5.0, 20.0),
        max_retries: int = 2,
    ) -> None:
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )
        self.max_retries = max_retries

    @staticmethod
    def _chunks(items: list[str], size: int) -> Iterable[list[str]]:
        for i in range(0, len(items), size):
            yield items[i : i + size]

    async def fetch_scores(
        self, cves: Iterable[str]
    ) -> dict[str, tuple[float, float]]:
        """Returns {CVE: (epss_score, percentile)} for every CVE with usable data.

        CVEs absent from the response are simply missing from the mapping. Callers must
        treat absence as "unknown", not as zero.
        """
        wanted = sorted({c.upper() for c in cves if c})
        if not wanted:
            return {}

        logger.info(
            "epss fetch | %d CVE(s) requested in chunks of %d", len(wanted), EPSS_CHUNK_SIZE
        )

        results: dict[str, tuple[float, float]] = {}

        async with httpx.AsyncClient(
            timeout=self.timeout, follow_redirects=True
        ) as client:
            for chunk in self._chunks(wanted, EPSS_CHUNK_SIZE):
                results.update(await self._fetch_chunk(client, chunk))

        logger.info(
            "epss fetch complete | requested=%d returned=%d | missing_from_response=%d "
            "(absent means unknown, not zero)",
            len(wanted),
            len(results),
            len(wanted) - len(results),
        )
        logger.debug(
            "epss scores | %s",
            {
                cve: f"score={score:.4f} percentile={pct:.4f}"
                for cve, (score, pct) in sorted(results.items())
            },
        )

        return results

    async def _fetch_chunk(
        self, client: httpx.AsyncClient, chunk: list[str]
    ) -> dict[str, tuple[float, float]]:
        params = {"cve": ",".join(chunk)}

        for attempt in range(self.max_retries + 1):
            request_start = time.perf_counter()
            try:
                resp = await client.get(settings.EPSS_BASE_URL, params=params)
                request_elapsed = time.perf_counter() - request_start

                log_http(
                    logger,
                    "epss",
                    method="GET",
                    url=settings.EPSS_BASE_URL,
                    status=resp.status_code,
                    elapsed=request_elapsed,
                    attempt=attempt,
                    detail=f"cves={len(chunk)}",
                )

                if resp.status_code == 200:
                    parsed = self._parse(resp.json())
                    logger.debug(
                        "epss chunk | requested=%d usable=%d", len(chunk), len(parsed)
                    )
                    return parsed

                if resp.status_code == 429:
                    backoff = min(1.0 + attempt * 2, 5.0)
                    logger.warning(
                        "epss rate limited, sleeping %.1fs before attempt %d",
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)
                    continue

                if resp.status_code >= 500:
                    backoff = 0.5 * (2**attempt)
                    logger.warning(
                        "epss server error %d, sleeping %.1fs before attempt %d",
                        resp.status_code,
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)
                    continue

                # 400 means a malformed request; retrying will not help.
                logger.warning(
                    "epss request rejected with HTTP %s; EPSS is a best-effort "
                    "enrichment and will be treated as unknown",
                    resp.status_code,
                )
                return {}

            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.warning(
                    "epss network error on attempt %d/%d: %s",
                    attempt + 1,
                    self.max_retries + 1,
                    e,
                )
                if attempt < self.max_retries:
                    await asyncio.sleep(0.5 * (2**attempt))
                    continue
                return {}

        logger.warning(
            "epss exhausted %d attempts; exploitation signal falls back to whatever "
            "the source collector reported",
            self.max_retries + 1,
        )
        return {}

    @staticmethod
    def _parse(payload: dict) -> dict[str, tuple[float, float]]:
        """EPSS returns every numeric field as a string, so both are cast."""
        parsed: dict[str, tuple[float, float]] = {}

        for row in payload.get("data", []) or []:
            cve = str(row.get("cve", "")).strip().upper()
            if not cve:
                continue
            try:
                score = float(row.get("epss", ""))
                percentile = float(row.get("percentile", ""))
            except (TypeError, ValueError):
                logger.debug("Skipping malformed EPSS row for %s", cve)
                continue

            # Percentile is the comparable quantity: raw scores are tiny for the
            # median CVE, so they barely move a risk score on their own.
            if score < EPSS_FLOOR and percentile < EPSS_FLOOR:
                logger.debug(
                    "epss row %s dropped: score=%.6f percentile=%.6f are both below "
                    "the %.6f floor",
                    cve,
                    score,
                    percentile,
                    EPSS_FLOOR,
                )
                continue

            parsed[cve] = (score, percentile)

        return parsed