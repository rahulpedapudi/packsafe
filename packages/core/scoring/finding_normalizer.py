"""Normalizer that maps raw static analysis items and advisories into canonical Finding objects."""

from __future__ import annotations

import uuid

from ..models.scoring import Finding
from ..models.vulnerability import StaticAnalysisFindingItem, VulnerabilityItem


class FindingNormalizer:
    """Produces canonical, immutable Finding objects consumable by gates, attribution, API, and LLM."""

    def __init__(self):

        self.CATEGORY_MAP = {
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

        self.GATE_MAP = {
            "CONFIRMED_MALICIOUS": "GATE-MALWARE",
            "REMOTE_PAYLOAD_EXECUTION": "GATE-REMOTE-EXEC",
            "SUSPICIOUS_INSTALL_BEHAVIOR": "GATE-INSTALL-MALWARE",
        }

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
        if ftype == "CREDENTIAL_SECRET_ACCESS" and item.confidence >= 0.85:
            gate_triggered = "GATE-CREDENTIAL-THEFT"
        elif ftype in cls.GATE_MAP and item.confidence >= 0.85:
            gate_triggered = cls.GATE_MAP[ftype]
        elif item.confidence >= 0.50 and ftype not in ("ENVIRONMENT_VARIABLE_ACCESS",):
            gate_triggered = "GATE-SUSPICIOUS-WARN"

        score_penalty = 0.0
        if item.severity == "CRITICAL":
            score_penalty = 15.0
        elif item.severity == "HIGH":
            score_penalty = 8.0
        elif item.severity == "MEDIUM":
            score_penalty = 3.0

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

        gate_triggered = None
        category = "integrity" if is_malware else "security"

        if is_malware:
            gate_triggered = "GATE-MALWARE"
        elif vuln.severity.upper() == "CRITICAL" and vuln.actively_exploited:
            gate_triggered = "GATE-ACTIVE-CRITICAL"

        score_penalty = (
            20.0 if vuln.severity.upper() == "CRITICAL" or is_malware else 10.0
        )

        return Finding(
            finding_id=vuln.vulnerability_id,
            category=category,
            severity="CRITICAL" if is_malware else vuln.severity.upper(),
            confidence=0.95,
            title=f"Malicious Package Advisory {vuln.vulnerability_id}"
            if is_malware
            else f"Vulnerability {vuln.vulnerability_id}",
            description=vuln.summary
            or f"Known advisory affecting {package_version or 'package'}",
            evidence=f"Advisory {vuln.vulnerability_id} (Aliases: {', '.join(vuln.aliases) if vuln.aliases else 'None'})",
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
