"""OSV.dev vulnerability collector."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import httpx

from packsafe.evidence.models import (
    EvidenceProvenance,
    VulnerabilityEvidence,
    VulnerabilityItem,
)


import logging
import time

logger = logging.getLogger(__name__)


class OSVCollector:
    """Queries OSV.dev for vulnerabilities affecting a package with retry and range parsing."""

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
        return httpx.Client(timeout=self.timeout)

    def collect(self, package_name: str, ecosystem: str = "PyPI", version: str | None = None) -> tuple[VulnerabilityEvidence, EvidenceProvenance]:
        url = "https://api.osv.dev/v1/query"
        payload: dict[str, Any] = {
            "package": {
                "name": package_name,
                "ecosystem": "PyPI" if ecosystem.lower() == "pypi" else "npm",
            }
        }
        if version:
            payload["version"] = version

        now = datetime.now(timezone.utc)
        client = self._get_client()

        for attempt in range(self.max_retries + 1):
            try:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        return (
                            VulnerabilityEvidence(items=(), status="INVALID", osv_queried=True),
                            EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
                        )

                    raw_vulns = data.get("vulns", [])
                    items: list[VulnerabilityItem] = []

                    for v in raw_vulns:
                        v_id = v.get("id", "UNKNOWN")
                        aliases = tuple(v.get("aliases", []))
                        database_specific = v.get("database_specific", {})
                        sev_str = database_specific.get("severity", "MEDIUM")

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
                                            ranges.append(f">={current_intro},<{fix_v}")
                                        else:
                                            ranges.append(f"<{fix_v}")
                                        current_intro = None
                                    elif "last_affected" in event:
                                        last_aff = event["last_affected"]
                                        if current_intro and current_intro != "0":
                                            ranges.append(f">={current_intro},<={last_aff}")
                                        else:
                                            ranges.append(f"<={last_aff}")
                                        current_intro = None
                                    elif "limit" in event:
                                        limit_v = event["limit"]
                                        if current_intro and current_intro != "0":
                                            ranges.append(f">={current_intro},<{limit_v}")
                                        else:
                                            ranges.append(f"<{limit_v}")
                                        current_intro = None

                                if current_intro:
                                    if current_intro != "0":
                                        ranges.append(f">={current_intro}")
                                    else:
                                        ranges.append("*")

                        items.append(VulnerabilityItem(
                            vulnerability_id=v_id,
                            aliases=aliases,
                            severity=sev_str,
                            exploitability=0.50,
                            exposure=1.0,
                            actively_exploited=False,  # Enriched downstream via KEVNormalizer
                            affected_ranges=tuple(ranges),
                            fixed_versions=tuple(fixed),
                            summary=v.get("summary", ""),
                            source="osv",
                        ))

                    vuln_ev = VulnerabilityEvidence(
                        items=tuple(items),
                        status="AVAILABLE",
                        osv_queried=True,
                        retrieved_at=now,
                    )
                    prov = EvidenceProvenance(
                        source="osv",
                        source_url=url,
                        retrieved_at=now,
                    )
                    return (vuln_ev, prov)

                elif resp.status_code == 404:
                    return (
                        VulnerabilityEvidence(items=(), status="MISSING", osv_queried=True),
                        EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
                    )
                elif resp.status_code == 429:
                    retry_after = float(resp.headers.get("Retry-After", 1.0 + attempt * 2))
                    time.sleep(min(retry_after, 5.0))
                    continue
                elif resp.status_code >= 500:
                    time.sleep(0.5 * (2 ** attempt))
                    continue
                else:
                    return (
                        VulnerabilityEvidence(items=(), status="INVALID", osv_queried=True),
                        EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
                    )
            except (httpx.TimeoutException, httpx.NetworkError) as e:
                logger.debug(f"OSV request error on attempt {attempt}: {e}")
                if attempt < self.max_retries:
                    time.sleep(0.5 * (2 ** attempt))
                else:
                    return (
                        VulnerabilityEvidence(items=(), status="MISSING", osv_queried=False),
                        EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
                    )
            except Exception:
                return (
                    VulnerabilityEvidence(items=(), status="INVALID", osv_queried=False),
                    EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
                )

        return (
            VulnerabilityEvidence(items=(), status="MISSING", osv_queried=False),
            EvidenceProvenance(source="osv", source_url=url, retrieved_at=now),
        )
