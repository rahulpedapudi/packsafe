"""Security Gate Engine for evaluating non-compensable security threats."""

from __future__ import annotations

from typing import Any
from packsafe.evidence.models import PackageEvidence
from packsafe.scoring.config import EngineConfig
from packsafe.scoring.models import Decision, GateResult, GateSeverity, Finding


class SecurityGateEngine:
    """Evaluates security gates in strict priority order.

    Hard security gates override BaseScore and set final_score <= score_floor,
    risk_level = CRITICAL, decision = BLOCK.
    """

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def evaluate(
        self,
        evidence: PackageEvidence,
        calculated_findings: list[Finding] | tuple[Finding, ...] | None = None,
    ) -> tuple[GateResult, ...]:
        """Evaluates all gates against the evidence and findings."""
        gate_results: list[GateResult] = []
        static_findings = evidence.static_analysis.findings
        all_findings = calculated_findings or ()

        def find_static_matches(types: list[str], min_conf: float = 0.85) -> list[str]:
            matched_snippets: list[str] = []
            for f in static_findings:
                ft = f.finding_type.upper()
                if any(t in ft for t in types) and f.confidence >= min_conf:
                    matched_snippets.append(f"{f.file_path}:{f.line_number} - {f.title}")
            return matched_snippets

        for gate_cfg in self.config.gates:
            gate_id = gate_cfg["id"]
            score_floor = gate_cfg.get("score_floor")
            min_conf = float(gate_cfg.get("min_confidence", 0.85))

            # 1. GATE-MALWARE
            if gate_id == "GATE-MALWARE":
                malware_matches = find_static_matches(["MALWARE", "CONFIRMED_MALICIOUS"], min_conf=0.70)
                for f in all_findings:
                    fid = f.finding_id.upper()
                    ftitle = f.title.upper()
                    fdesc = (f.description or "").upper()
                    if (
                        f.gate_triggered == "GATE-MALWARE"
                        or fid.startswith("MAL-")
                        or "MALWARE" in fid
                        or "MALICIOUS" in fid
                        or "MALWARE" in ftitle
                        or "MALICIOUS" in ftitle
                        or "MALICIOUS" in fdesc
                        or "MALWARE" in fdesc
                        or (f.category == "integrity" and f.severity == "CRITICAL" and ftitle.startswith("CONFIRMED"))
                    ):
                        malware_matches.append(f"{f.finding_id}: {f.title}")

                if malware_matches:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.CRITICAL,
                        reason="Confirmed malicious package signature or advisory match.",
                        decision_override=Decision.BLOCK,
                        score_floor=score_floor,
                        evidence_ids=tuple(malware_matches),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No confirmed malware signatures detected.",
                        evidence_ids=(),
                    ))

            # 2. GATE-ACTIVE-CRITICAL
            elif gate_id == "GATE-ACTIVE-CRITICAL":
                active_critical_vulns = [
                    v.vulnerability_id for v in evidence.vulnerabilities.items
                    if v.severity.upper() == "CRITICAL" and v.actively_exploited
                ]
                if active_critical_vulns:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.CRITICAL,
                        reason=f"Actively exploited critical vulnerability: {', '.join(active_critical_vulns)}",
                        decision_override=Decision.BLOCK,
                        score_floor=score_floor,
                        evidence_ids=tuple(active_critical_vulns),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No actively exploited critical vulnerabilities.",
                        evidence_ids=(),
                    ))

            # 3. GATE-CREDENTIAL-THEFT
            elif gate_id == "GATE-CREDENTIAL-THEFT":
                # Must be verified credential theft / exfiltration finding with confidence >= 0.85
                cred_matches = find_static_matches(
                    ["CREDENTIAL_SECRET_ACCESS", "CREDENTIAL_EXFILTRATION"],
                    min_conf=min_conf,
                )
                if cred_matches:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.CRITICAL,
                        reason="High-confidence detection of credential harvesting or exfiltration.",
                        decision_override=Decision.BLOCK,
                        score_floor=score_floor,
                        evidence_ids=tuple(cred_matches),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No high-confidence credential theft detected.",
                        evidence_ids=(),
                    ))

            # 4. GATE-REMOTE-EXEC
            elif gate_id == "GATE-REMOTE-EXEC":
                # Must be remote payload download + execution with confidence >= 0.85
                remote_matches = find_static_matches(
                    ["REMOTE_PAYLOAD_EXECUTION", "FETCH_EXEC"],
                    min_conf=min_conf,
                )
                if remote_matches:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.CRITICAL,
                        reason="Remote payload download and execution detected during package installation.",
                        decision_override=Decision.BLOCK,
                        score_floor=score_floor,
                        evidence_ids=tuple(remote_matches),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No remote payload execution detected.",
                        evidence_ids=(),
                    ))

            # 5. GATE-INSTALL-MALWARE
            elif gate_id == "GATE-INSTALL-MALWARE":
                install_matches = find_static_matches(
                    ["INSTALL_MALWARE", "PERSISTENCE", "ROOTKIT", "DESTRUCTIVE_EXEC"],
                    min_conf=min_conf,
                )
                if install_matches:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.CRITICAL,
                        reason="Malicious or destructive installation behavior detected.",
                        decision_override=Decision.BLOCK,
                        score_floor=score_floor,
                        evidence_ids=tuple(install_matches),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No malicious installation hooks detected.",
                        evidence_ids=(),
                    ))

            # 6. GATE-SUSPICIOUS-WARN
            elif gate_id == "GATE-SUSPICIOUS-WARN":
                suspicious_matches = find_static_matches(
                    ["OBFUSCAT", "SUSPICIOUS_NETWORK", "DYNAMIC_CODE_EXECUTION", "SHELL_PROCESS_EXECUTION"],
                    min_conf=min_conf,
                )
                # Typosquatting warning (alone triggers warning, never block)
                if evidence.identity.typosquatting_risk is not None and evidence.identity.typosquatting_risk >= 0.70:
                    suspicious_matches.append(
                        f"High typosquatting similarity to {evidence.identity.target_popular_package or 'popular package'}"
                    )

                if suspicious_matches:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=True,
                        severity=GateSeverity.WARNING,
                        reason="Suspicious or anomalous patterns detected that warrant review: " + "; ".join(suspicious_matches),
                        decision_override=Decision.WARN,
                        score_floor=None,
                        evidence_ids=tuple(suspicious_matches),
                    ))
                else:
                    gate_results.append(GateResult(
                        gate_id=gate_id,
                        triggered=False,
                        severity=GateSeverity.NONE,
                        reason="No suspicious behavior warnings.",
                        evidence_ids=(),
                    ))

        return tuple(gate_results)
