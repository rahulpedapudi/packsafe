"""Normalizer that maps raw static analysis items and advisories into canonical Finding objects."""

from __future__ import annotations

import logging
import uuid

from ..models.scoring import Finding
from ..models.static_analysis import StaticAnalysisFindingItem
from ..models.vulnerability import ExploitationSignal, VulnerabilityItem

logger = logging.getLogger(__name__)


def describe_exploitation(vuln: VulnerabilityItem) -> str:
    """Renders exploitation evidence as a claim the source data actually supports.

    Never says "actively exploited": KEV records that exploitation was observed at some
    point, and entries are rarely removed, so that phrasing would misrepresent a
    multi-year-old listing as a live threat.
    """
    parts: list[str] = []

    if vuln.kev_date_added is not None:
        parts.append(f"Listed in CISA KEV (added {vuln.kev_date_added.isoformat()})")
    if vuln.known_ransomware_use:
        parts.append("known ransomware campaign use")

    if vuln.epss_percentile is not None:
        parts.append(f"EPSS percentile {vuln.epss_percentile:.1%}")

    if not parts:
        return ""

    return "; ".join(parts)


class FindingNormalizer:
    """Produces canonical, immutable Finding objects consumable by gates, attribution, API, and LLM."""

    # Class-level, not instance-level: these are consumed by @classmethod methods.
    CATEGORY_MAP = {
        "CONFIRMED_MALICIOUS": "integrity",
        "CREDENTIAL_SECRET_ACCESS": "integrity",
        "SUSPICIOUS_INSTALL_BEHAVIOR": "integrity",
        "REMOTE_CODE_DOWNLOAD": "integrity",
        "REMOTE_PAYLOAD_EXECUTION": "integrity",
        "SHELL_PROCESS_EXECUTION": "integrity",
        "DYNAMIC_CODE_EXECUTION": "integrity",
        "OBFUSCATION_PATTERNS": "integrity",
        "SUSPICIOUS_NETWORK_BEHAVIOR": "integrity",
        "ENVIRONMENT_VARIABLE_ACCESS": "integrity",
        "VULNERABILITY": "security",
        "TYPOSQUATTING": "integrity",
    }

    GATE_MAP = {
        "CONFIRMED_MALICIOUS": "GATE-MALWARE",
        "REMOTE_PAYLOAD_EXECUTION": "GATE-REMOTE-EXEC",
        "SUSPICIOUS_INSTALL_BEHAVIOR": "GATE-INSTALL-MALWARE",
    }

    SEVERITY_PENALTY = {
        "CRITICAL": 15.0,
        "HIGH": 8.0,
        "MEDIUM": 3.0,
    }

    # Findings at or above this confidence are treated as confirmed enough to gate.
    GATE_CONFIDENCE_THRESHOLD = 0.85
    WARN_CONFIDENCE_THRESHOLD = 0.50

    @classmethod
    def from_static_finding(
        cls,
        item: StaticAnalysisFindingItem,
        package_version: str | None = None,
    ) -> Finding:
        """Converts a StaticAnalysisFindingItem into a canonical Finding."""
        ftype = item.finding_type.upper()
        category = cls.CATEGORY_MAP.get(ftype, "integrity")

        gate_triggered = None
        if (
            ftype == "CREDENTIAL_SECRET_ACCESS"
            and item.confidence >= cls.GATE_CONFIDENCE_THRESHOLD
        ):
            gate_triggered = "GATE-CREDENTIAL-THEFT"
        elif ftype in cls.GATE_MAP and item.confidence >= cls.GATE_CONFIDENCE_THRESHOLD:
            gate_triggered = cls.GATE_MAP[ftype]
        elif (
            item.confidence >= cls.WARN_CONFIDENCE_THRESHOLD
            and ftype not in ("ENVIRONMENT_VARIABLE_ACCESS",)
        ):
            gate_triggered = "GATE-SUSPICIOUS-WARN"

        score_penalty = cls.SEVERITY_PENALTY.get(item.severity.upper(), 0.0)

        logger.debug(
            "finding from static analysis | type=%s severity=%s confidence=%.2f -> "
            "category=%s gate=%s score_penalty=%.1f | %s:%s",
            ftype,
            item.severity,
            item.confidence,
            category,
            gate_triggered or "none",
            score_penalty,
            item.file_path,
            item.line_number,
        )

        return Finding(
            finding_id=f"FINDING-{uuid.uuid4().hex[:8].upper()}",
            category=category,
            severity=item.severity.upper(),
            confidence=item.confidence,
            title=item.title or ftype.replace("_", " ").title(),
            description=item.description,
            evidence=f"{item.file_path}:{item.line_number} - {item.evidence_snippet}",
            source="static_analysis",
            affected_version=package_version,
            affects_categories=(category,),
            score_penalty=score_penalty,
            gate_triggered=gate_triggered,
        )

    @classmethod
    def from_vulnerability(
        cls,
        vuln: VulnerabilityItem,
        package_version: str | None = None,
        risk: float = 0.0,
    ) -> Finding:
        """Converts an applicable VulnerabilityItem into a canonical Finding."""
        vid_upper = vuln.vulnerability_id.upper()
        summary_upper = (vuln.summary or "").upper()
        is_malware = (
            vid_upper.startswith("MAL-")
            or "MALICIOUS" in summary_upper
            or "MALWARE" in summary_upper
        )

        # Describe exploitation evidence precisely. "Actively exploited" would be a
        # claim the underlying data cannot support.
        exploitation_note = describe_exploitation(vuln)

        gate_triggered = None
        category = "integrity" if is_malware else "security"

        if is_malware:
            gate_triggered = "GATE-MALWARE"
        elif (
            vuln.severity.upper() == "CRITICAL"
            and vuln.known_ransomware_use
        ) or (
            vuln.severity.upper() == "CRITICAL"
            and vuln.exploitation_signal == ExploitationSignal.RECENTLY_LISTED
        ):
            # Only imminent exploitation evidence justifies a hard block. KEV
            # membership alone would block on any CVE CISA has ever listed.
            gate_triggered = "GATE-ACTIVE-CRITICAL"

        score_penalty = (
            20.0 if vuln.severity.upper() == "CRITICAL" or is_malware else 10.0
        )

        logger.debug(
            "finding from advisory | id=%s severity=%s malware=%s aliases=%s -> "
            "category=%s gate=%s score_penalty=%.1f exploitation=%s",
            vuln.vulnerability_id,
            vuln.severity,
            is_malware,
            list(vuln.aliases) or "none",
            category,
            gate_triggered or "none",
            score_penalty,
            exploitation_note or "no exploitation evidence",
        )

        return Finding(
            finding_id=vuln.vulnerability_id,
            category=category,
            severity="CRITICAL" if is_malware else vuln.severity.upper(),
            confidence=0.95,
            title=f"Malicious Package Advisory {vuln.vulnerability_id}"
            if is_malware
            else f"Vulnerability {vuln.vulnerability_id}",
            description=(
                f"{exploitation_note}. {vuln.summary}"
                if exploitation_note and vuln.summary
                else exploitation_note
                or vuln.summary
                or f"Known advisory affecting {package_version or 'package'}"
            ),
            evidence=(
                f"Advisory {vuln.vulnerability_id} "
                f"(Aliases: {', '.join(vuln.aliases) if vuln.aliases else 'None'})"
                + (f" | {exploitation_note}" if exploitation_note else "")
            ),
            source=vuln.source,
            affected_version=package_version,
            affects_categories=(category,),
            score_penalty=score_penalty,
            gate_triggered=gate_triggered,
            aliases=vuln.aliases,
            risk=risk,
            source_severities=vuln.source_severities,
            severity_resolution=vuln.severity_resolution,
        )
