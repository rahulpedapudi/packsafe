import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from ..config import settings
from ..models.evidence import EvidenceProvenance, EvidenceStatus
from ..models.package import EcosystemType
from ..models.vulnerability import VulnerabilityEvidence, VulnerabilityItem
from ..tracing import log_http
from .helpers import calculate_severity

logger = logging.getLogger(__name__)


def _severity_mix(items: list[VulnerabilityItem]) -> str:
    """Counts advisories per severity for the fetch summary line."""
    counts: dict[str, int] = {}
    for item in items:
        key = (item.severity or "UNKNOWN").upper()
        counts[key] = counts.get(key, 0) + 1
    return ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"


class OSVCollector:
    """Queries OSV.dev for vulnerabilities affecting a package with retry and range parsing."""

    def __init__(
        self, timeout: tuple[float, float] = (5.0, 15.0), max_retries: int = 2
    ) -> None:
        self.timeout = httpx.Timeout(
            connect=timeout[0], read=timeout[1], write=10.0, pool=10.0
        )
        self.max_retries = max_retries

    async def fetch(
        self,
        package_name: str,
        ecosystem: EcosystemType = EcosystemType.pypi,
        version: str | None = None,
    ) -> tuple[VulnerabilityEvidence, EvidenceProvenance]:

        # payload to send to osv api.
        payload: dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI" if ecosystem.lower() == "pypi" else "npm",
            }
        }

        if version:
            payload["version"] = version

        now = datetime.now(UTC)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            # auto retrying
            for attempt in range(self.max_retries + 1):
                try:
                    request_start = time.perf_counter()
                    resp = await client.post(settings.OSV_BASE_URL, json=payload)
                    request_elapsed = time.perf_counter() - request_start

                    log_http(
                        logger,
                        "osv",
                        method="POST",
                        url=settings.OSV_BASE_URL,
                        status=resp.status_code,
                        elapsed=request_elapsed,
                        attempt=attempt,
                        detail=f"package={package_name} version={version or 'latest'}",
                    )

                    if resp.status_code == 200:
                        try:
                            data = resp.json()
                        except Exception:
                            return (
                                VulnerabilityEvidence(
                                    items=(),
                                    status=EvidenceStatus.INVALID,
                                    osv_queried=True,
                                ),
                                EvidenceProvenance(
                                    source="osv",
                                    source_url=settings.OSV_BASE_URL,
                                    retrieved_at=now,
                                ),
                            )

                        raw_vulns = data.get("vulns", [])
                        items: list[VulnerabilityItem] = []

                        for v in raw_vulns:
                            v_id = v.get("id", "UNKNOWN")
                            aliases = tuple(v.get("aliases", []))

                            # severity
                            sev_str = calculate_severity(v.get("severity", []))

                            # Extract affected ranges and fixed versions from OSV events
                            ranges: list[str] = []
                            fixed: list[str] = []

                            for aff in v.get("affected", []):
                                # Explicit versions
                                for ver_str in aff.get("versions", []):
                                    ranges.append(f"=={ver_str}")

                                # Event ranges (introduced, fixed, last_affected)
                                for r in aff.get("ranges", []):
                                    current_intro: str | None = None
                                    for event in r.get("events", []):
                                        if "introduced" in event:
                                            current_intro = event["introduced"]
                                        elif "fixed" in event:
                                            fix_v = event["fixed"]
                                            fixed.append(fix_v)
                                            if current_intro and current_intro != "0":
                                                ranges.append(
                                                    f">={current_intro},<{fix_v}"
                                                )
                                            else:
                                                ranges.append(f"<{fix_v}")
                                            current_intro = None
                                        elif "last_affected" in event:
                                            last_aff = event["last_affected"]
                                            if current_intro and current_intro != "0":
                                                ranges.append(
                                                    f">={current_intro},<={last_aff}"
                                                )
                                            else:
                                                ranges.append(f"<={last_aff}")
                                            current_intro = None
                                        elif "limit" in event:
                                            limit_v = event["limit"]
                                            if current_intro and current_intro != "0":
                                                ranges.append(
                                                    f">={current_intro},<{limit_v}"
                                                )
                                            else:
                                                ranges.append(f"<{limit_v}")
                                            current_intro = None

                                    if current_intro:
                                        if current_intro != "0":
                                            ranges.append(f">={current_intro}")
                                        else:
                                            ranges.append("*")

                            items.append(
                                VulnerabilityItem(
                                    vulnerability_id=v_id,
                                    aliases=aliases,
                                    severity=sev_str[1],
                                    # Exploitation evidence is layered on by
                                    # ExploitationNormalizer (KEV + EPSS). OSV
                                    # itself reports no exploitation signal.
                                    exploitability=0.50,
                                    exposure=1.0,
                                    affected_ranges=tuple(ranges),
                                    fixed_versions=tuple(fixed),
                                    summary=v.get("summary", ""),
                                    source="osv",
                                )
                            )

                        vuln_ev = VulnerabilityEvidence(
                            items=tuple(items),
                            status=EvidenceStatus.AVAILABLE,
                            osv_queried=True,
                            retrieved_at=now,
                        )
                        prov = EvidenceProvenance(
                            source="osv",
                            source_url=settings.OSV_BASE_URL,
                            retrieved_at=now,
                        )

                        logger.info(
                            "osv fetch | %d advisory record(s) parsed into %d "
                            "vulnerability item(s) in %s | severity_mix=%s",
                            len(raw_vulns),
                            len(items),
                            f"{request_elapsed:.3f}s",
                            _severity_mix(items),
                        )
                        logger.debug(
                            "osv parse detail | %s",
                            {
                                item.vulnerability_id: (
                                    f"severity={item.severity} "
                                    f"ranges={list(item.affected_ranges)} "
                                    f"fixed={list(item.fixed_versions)}"
                                )
                                for item in items
                            },
                        )

                        # returns when everything went fine.
                        return (vuln_ev, prov)

                    elif resp.status_code == 404:
                        logger.warning(
                            "osv fetch | 404 for %s@%s: OSV has no record of this "
                            "package; vulnerability evidence is MISSING, not clean",
                            package_name,
                            version,
                        )
                        return (
                            VulnerabilityEvidence(
                                items=(),
                                status=EvidenceStatus.MISSING,
                                osv_queried=True,
                            ),
                            EvidenceProvenance(
                                source="osv",
                                source_url=settings.OSV_BASE_URL,
                                retrieved_at=now,
                            ),
                        )
                    elif resp.status_code == 429:
                        retry_after = float(
                            resp.headers.get("Retry-After", 1.0 + attempt * 2)
                        )
                        backoff = min(retry_after, 5.0)
                        logger.warning(
                            "osv fetch | rate limited (429), sleeping %.1fs before "
                            "attempt %d",
                            backoff,
                            attempt + 1,
                        )
                        time.sleep(backoff)
                        continue
                    elif resp.status_code >= 500:
                        backoff = 0.5 * (2**attempt)
                        logger.warning(
                            "osv fetch | server error %d, sleeping %.1fs before "
                            "attempt %d",
                            resp.status_code,
                            backoff,
                            attempt + 1,
                        )
                        time.sleep(backoff)
                        continue
                    else:
                        logger.warning(
                            "osv fetch | unexpected HTTP %d for %s@%s; treating "
                            "evidence as INVALID",
                            resp.status_code,
                            package_name,
                            version,
                        )
                        return (
                            VulnerabilityEvidence(
                                items=(),
                                status=EvidenceStatus.INVALID,
                                osv_queried=True,
                            ),
                            EvidenceProvenance(
                                source="osv",
                                source_url=settings.OSV_BASE_URL,
                                retrieved_at=now,
                            ),
                        )
                except (httpx.TimeoutException, httpx.NetworkError) as e:
                    logger.warning(
                        "osv fetch | network error on attempt %d/%d: %s",
                        attempt + 1,
                        self.max_retries + 1,
                        e,
                    )
                    if attempt < self.max_retries:
                        time.sleep(0.5 * (2**attempt))
                    else:
                        logger.warning(
                            "osv fetch | gave up after %d attempts; vulnerability "
                            "evidence is MISSING, so the security category cannot "
                            "contribute to the score",
                            self.max_retries + 1,
                        )
                        return (
                            VulnerabilityEvidence(
                                items=(),
                                status=EvidenceStatus.MISSING,
                                osv_queried=False,
                            ),
                            EvidenceProvenance(
                                source="osv",
                                source_url=settings.OSV_BASE_URL,
                                retrieved_at=now,
                            ),
                        )
                except Exception as e:
                    logger.warning(
                        "osv fetch | unexpected error, treating evidence as INVALID: "
                        "%s: %s",
                        type(e).__name__,
                        e,
                    )
                    return (
                        VulnerabilityEvidence(
                            items=(), status=EvidenceStatus.INVALID, osv_queried=False
                        ),
                        EvidenceProvenance(
                            source="osv",
                            source_url=settings.OSV_BASE_URL,
                            retrieved_at=now,
                        ),
                    )

        logger.warning(
            "osv fetch | exhausted %d attempts without a usable response; "
            "vulnerability evidence is MISSING",
            self.max_retries + 1,
        )
        return (
            VulnerabilityEvidence(
                items=(), status=EvidenceStatus.MISSING, osv_queried=False
            ),
            EvidenceProvenance(
                source="osv", source_url=settings.OSV_BASE_URL, retrieved_at=now
            ),
        )


if __name__ == "__main__":
    osv = OSVCollector()
    print(osv.fetch("httpx", version="0.27"))
