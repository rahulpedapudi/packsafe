"""Security Gate Engine for evaluating non-compensable security threats."""

from __future__ import annotations

import logging

from ...models.vulnerability import ExploitationSignal
from ...pipeline.context import AnalysisContext
from ..config import EngineConfig
from ..models import Decision, Finding, GateResult, GateSeverity

logger = logging.getLogger(__name__)


def _log_gate(result: GateResult) -> None:
    """Records one gate's verdict: pass lines carry the reason they did not trigger."""
    detail = (
        f"severity={result.severity.value} score_floor="
        f"{result.score_floor if result.score_floor is not None else '-'} "
        f"decision_override={result.decision_override.value if result.decision_override else '-'} "
        f"evidence={list(result.evidence_ids) or 'none'} | {result.reason}"
    )
    if result.triggered:
        logger.info("gate=%s TRIGGERED | %s", result.gate_id, detail)
    else:
        logger.debug("gate=%s passed | %s", result.gate_id, detail)


class SecurityGateEngine:
    """Evaluates security gates in strict priority order.

    Hard security gates override BaseScore and set final_score <= score_floor,
    risk_level = CRITICAL, decision = BLOCK.
    """

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    @staticmethod
    def _is_imminent_exploitation(v: object) -> bool:
        """True when exploitation evidence justifies a hard block.

        KEV membership on its own is insufficient: CISA almost never delists entries,
        so an old listing means exploitation was observed at some point, not now.
        """
        if getattr(v, "known_ransomware_use", False):
            return True
        return getattr(v, "exploitation_signal", None) == (
            ExploitationSignal.RECENTLY_LISTED
        )

    def evaluate(
        self,
        evidence: AnalysisContext,
        calculated_findings: list[Finding] | tuple[Finding, ...] | None = None,
    ) -> tuple[GateResult, ...]:
        """Evaluates all gates against the evidence and findings."""
        gate_results: list[GateResult] = []
        static_findings = evidence.static_analysis.findings
        all_findings = calculated_findings or ()

        logger.info(
            "gate evaluation | gates_in_config=%d static_findings=%d canonical_findings=%d",
            len(self.config.gates),
            len(static_findings),
            len(all_findings),
        )

        def find_static_matches(types: list[str], min_conf: float = 0.85) -> list[str]:
            matched_snippets: list[str] = []
            for f in static_findings:
                ft = f.finding_type.upper()
                if any(t in ft for t in types) and f.confidence >= min_conf:
                    matched_snippets.append(
                        f"{f.file_path}:{f.line_number} - {f.title}"
                    )
            return matched_snippets

        for gate_cfg in self.config.gates:
            gate_id = gate_cfg["id"]
            score_floor = gate_cfg.get("score_floor")
            min_conf = float(gate_cfg.get("min_confidence", 0.85))

            # 1. GATE-MALWARE
            if gate_id == "GATE-MALWARE":
                malware_matches = find_static_matches(
                    ["MALWARE", "CONFIRMED_MALICIOUS"], min_conf=0.70
                )
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
                        or (
                            f.category == "integrity"
                            and f.severity == "CRITICAL"
                            and ftitle.startswith("CONFIRMED")
                        )
                    ):
                        malware_matches.append(f"{f.finding_id}: {f.title}")

                if malware_matches:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.CRITICAL,
                            reason="Confirmed malicious package signature or advisory match.",
                            decision_override=Decision.BLOCK,
                            score_floor=score_floor,
                            evidence_ids=tuple(malware_matches),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason="No confirmed malware signatures detected.",
                            evidence_ids=(),
                        )
                    )

            # 2. GATE-ACTIVE-CRITICAL
            elif gate_id == "GATE-ACTIVE-CRITICAL":
                # This gate BLOCKs at score_floor, so it holds a much higher bar than
                # a risk multiplier: CRITICAL severity AND a recent KEV listing OR
                # reported ransomware use. A stale KEV entry alone will not trigger it,
                # because CISA rarely removes entries and that is not evidence of
                # current exploitation.
                active_critical_vulns: list[str] = []
                for v in evidence.vulnerabilities.items:
                    if v.severity.upper() != "CRITICAL":
                        continue
                    if not self._is_imminent_exploitation(v):
                        continue
                    detail = (
                        "ransomware campaign use reported"
                        if v.known_ransomware_use
                        else f"added to CISA KEV on {v.kev_date_added}"
                    )
                    active_critical_vulns.append(f"{v.vulnerability_id} ({detail})")

                if active_critical_vulns:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.CRITICAL,
                            reason=(
                                "Critical vulnerability with current exploitation "
                                f"evidence: {', '.join(active_critical_vulns)}"
                            ),
                            decision_override=Decision.BLOCK,
                            score_floor=score_floor,
                            evidence_ids=tuple(active_critical_vulns),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason=(
                                "No critical vulnerability with recent exploitation "
                                "evidence."
                            ),
                            evidence_ids=(),
                        )
                    )

            # 3. GATE-CREDENTIAL-THEFT
            elif gate_id == "GATE-CREDENTIAL-THEFT":
                # Must be verified credential theft / exfiltration finding with confidence >= 0.85
                cred_matches = find_static_matches(
                    ["CREDENTIAL_SECRET_ACCESS", "CREDENTIAL_EXFILTRATION"],
                    min_conf=min_conf,
                )
                if cred_matches:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.CRITICAL,
                            reason="High-confidence detection of credential harvesting or exfiltration.",
                            decision_override=Decision.BLOCK,
                            score_floor=score_floor,
                            evidence_ids=tuple(cred_matches),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason="No high-confidence credential theft detected.",
                            evidence_ids=(),
                        )
                    )

            # 4. GATE-REMOTE-EXEC
            elif gate_id == "GATE-REMOTE-EXEC":
                # Must be remote payload download + execution with confidence >= 0.85
                remote_matches = find_static_matches(
                    ["REMOTE_PAYLOAD_EXECUTION", "FETCH_EXEC"],
                    min_conf=min_conf,
                )
                if remote_matches:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.CRITICAL,
                            reason="Remote payload download and execution detected during package installation.",
                            decision_override=Decision.BLOCK,
                            score_floor=score_floor,
                            evidence_ids=tuple(remote_matches),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason="No remote payload execution detected.",
                            evidence_ids=(),
                        )
                    )

            # 5. GATE-INSTALL-MALWARE
            elif gate_id == "GATE-INSTALL-MALWARE":
                install_matches = find_static_matches(
                    ["INSTALL_MALWARE", "PERSISTENCE", "ROOTKIT", "DESTRUCTIVE_EXEC"],
                    min_conf=min_conf,
                )
                if install_matches:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.CRITICAL,
                            reason="Malicious or destructive installation behavior detected.",
                            decision_override=Decision.BLOCK,
                            score_floor=score_floor,
                            evidence_ids=tuple(install_matches),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason="No malicious installation hooks detected.",
                            evidence_ids=(),
                        )
                    )

            # 6. GATE-SUSPICIOUS-WARN
            elif gate_id == "GATE-SUSPICIOUS-WARN":
                suspicious_matches = find_static_matches(
                    [
                        "OBFUSCAT",
                        "SUSPICIOUS_NETWORK",
                        "DYNAMIC_CODE_EXECUTION",
                        "SHELL_PROCESS_EXECUTION",
                    ],
                    min_conf=min_conf,
                )
                # Typosquatting warning (alone triggers warning, never block)
                if (
                    evidence.identity.typosquatting_risk is not None
                    and evidence.identity.typosquatting_risk >= 0.70
                ):
                    suspicious_matches.append(
                        f"High typosquatting similarity to {evidence.identity.target_popular_package or 'popular package'}"
                    )

                if suspicious_matches:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=True,
                            severity=GateSeverity.WARNING,
                            reason="Suspicious or anomalous patterns detected that warrant review: "
                            + "; ".join(suspicious_matches),
                            decision_override=Decision.WARN,
                            score_floor=None,
                            evidence_ids=tuple(suspicious_matches),
                        )
                    )
                else:
                    gate_results.append(
                        GateResult(
                            gate_id=gate_id,
                            triggered=False,
                            severity=GateSeverity.NONE,
                            reason="No suspicious behavior warnings.",
                            evidence_ids=(),
                        )
                    )

        for gate_result in gate_results:
            _log_gate(gate_result)

        logger.info(
            "gate evaluation complete | evaluated=%d triggered=%d | %s",
            len(gate_results),
            sum(1 for g in gate_results if g.triggered),
            ", ".join(
                f"{g.gate_id}={g.severity.value}" for g in gate_results if g.triggered
            )
            or "no gate triggered",
        )

        return tuple(gate_results)
