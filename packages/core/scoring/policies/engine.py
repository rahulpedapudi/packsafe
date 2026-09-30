"""Policy Engine for translating objective ScoreResult into actionable decisions."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping
from packsafe.evidence.models import PackageEvidence
from packsafe.evidence.normalization.vulnerability import is_version_affected
from packsafe.scoring.config import EngineConfig
from packsafe.scoring.models import Decision, GateSeverity, RiskLevel, ScoreResult, SeverityRank


@dataclass(frozen=True)
class PolicyEvaluationResult:
    """Outcome of policy evaluation."""
    decision: Decision
    profile: str
    reason: str
    details: Mapping[str, Any]

    def __post_init__(self) -> None:
        if isinstance(self.details, dict):
            object.__setattr__(self, "details", MappingProxyType(self.details))


class PolicyEngine:
    """Evaluates ScoreResult against policy profiles with strict precedence hierarchy."""

    def __init__(self, config: EngineConfig) -> None:
        self.config = config

    def evaluate(
        self,
        score_result: ScoreResult,
        profile_name: str = "balanced",
        evidence: PackageEvidence | None = None,
    ) -> PolicyEvaluationResult:
        profiles = self.config.profiles
        profile = profiles.get(profile_name.lower(), profiles.get("balanced", {}))
        pkg_name = score_result.package_name.lower()

        # 1. Hard Security Gate Triggered (Always beats any list or policy)
        triggered_gates = [g for g in score_result.gates if g.triggered]
        critical_gates = [g for g in triggered_gates if g.severity == GateSeverity.CRITICAL]

        if critical_gates:
            gate_reasons = "; ".join(g.reason for g in critical_gates)
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                profile=profile_name,
                reason=f"Hard security gate triggered: {gate_reasons}",
                details={"triggered_gates": [g.gate_id for g in critical_gates]},
            )

        # 2. Blocked Package List (Enterprise or configured profile)
        blocked_pkgs = [p.lower() for p in profile.get("blocked_packages", [])]
        if pkg_name in blocked_pkgs:
            return PolicyEvaluationResult(
                decision=Decision.BLOCK,
                profile=profile_name,
                reason=f"Package '{pkg_name}' is explicitly blocked by enterprise policy.",
                details={"blocked_package": pkg_name},
            )

        # 3. Approved Package List (Enterprise)
        approved_pkgs = [p.lower() for p in profile.get("approved_packages", [])]
        if pkg_name in approved_pkgs:
            return PolicyEvaluationResult(
                decision=Decision.ALLOW,
                profile=profile_name,
                reason=f"Package '{pkg_name}' is on the pre-approved enterprise package list.",
                details={"approved_package": pkg_name},
            )

        # 4. License Policy Violation (Enterprise)
        if evidence and "allowed_licenses" in profile:
            allowed_lics = [lic.upper() for lic in profile.get("allowed_licenses", [])]
            pkg_lic = (evidence.license.spdx_id or "UNKNOWN").upper()
            if pkg_lic != "UNKNOWN" and allowed_lics and pkg_lic not in allowed_lics:
                return PolicyEvaluationResult(
                    decision=Decision.REVIEW,
                    profile=profile_name,
                    reason=f"License '{pkg_lic}' is not in approved organization licenses ({', '.join(allowed_lics)}).",
                    details={"declared_license": pkg_lic},
                )

        # 5. Maximum Vulnerability Severity Violation (Enterprise)
        # MUST evaluate only applicable vulnerabilities affecting this package version
        if "maximum_vulnerability_severity" in profile and evidence:
            max_allowed_str = profile.get("maximum_vulnerability_severity", "HIGH")
            max_allowed_rank = SeverityRank.from_str(max_allowed_str)
            pkg_version = evidence.package.version
            ecosystem = evidence.package.ecosystem

            for vuln in evidence.vulnerabilities.items:
                is_aff = is_version_affected(
                    pkg_version,
                    vuln.affected_ranges,
                    vuln.fixed_versions,
                    ecosystem,
                )
                if is_aff:
                    vuln_rank = SeverityRank.from_str(vuln.severity)
                    if vuln_rank > max_allowed_rank:
                        return PolicyEvaluationResult(
                            decision=Decision.BLOCK,
                            profile=profile_name,
                            reason=f"Applicable vulnerability {vuln.vulnerability_id} severity ({vuln.severity}) exceeds policy limit ({max_allowed_str}).",
                            details={"vulnerability": vuln.vulnerability_id, "severity": vuln.severity},
                        )

        # 6. Score Threshold & Risk Level Evaluation
        score = score_result.final_score
        risk = score_result.risk_level

        # Check warning gates (e.g. suspicious behavior, typosquatting)
        warning_gates = [g for g in triggered_gates if g.severity == GateSeverity.WARNING]

        if profile_name.lower() == "strict":
            block_thresh = float(profile.get("block_score_threshold", 75.0))
            warn_thresh = float(profile.get("warn_score_threshold", 90.0))
            block_risks = profile.get("block_on_risks", ["MODERATE", "HIGH", "CRITICAL"])

            if score < block_thresh or risk.value in block_risks:
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    profile=profile_name,
                    reason=f"Strict policy: score {score:.1f} is below block threshold ({block_thresh}) or risk is {risk.value}.",
                    details={"score": score, "risk": risk.value},
                )
            elif score < warn_thresh or warning_gates:
                return PolicyEvaluationResult(
                    decision=Decision.WARN,
                    profile=profile_name,
                    reason=f"Strict policy: score {score:.1f} is below warn threshold ({warn_thresh}) or security warnings present.",
                    details={"score": score, "risk": risk.value},
                )
            return PolicyEvaluationResult(
                decision=Decision.ALLOW,
                profile=profile_name,
                reason="Package meets strict policy acceptance criteria.",
                details={"score": score, "risk": risk.value},
            )

        elif profile_name.lower() == "enterprise":
            min_score = float(profile.get("minimum_score", 80.0))
            if score < min_score:
                return PolicyEvaluationResult(
                    decision=Decision.BLOCK,
                    profile=profile_name,
                    reason=f"Enterprise policy: score {score:.1f} is below required minimum ({min_score}).",
                    details={"score": score, "minimum_score": min_score},
                )
            return PolicyEvaluationResult(
                decision=Decision.ALLOW,
                profile=profile_name,
                reason="Package satisfies enterprise security score requirements.",
                details={"score": score},
            )

        elif profile_name.lower() == "permissive":
            warn_thresh = float(profile.get("warn_score_threshold", 40.0))
            if score < warn_thresh:
                return PolicyEvaluationResult(
                    decision=Decision.WARN,
                    profile=profile_name,
                    reason=f"Permissive policy: score {score:.1f} is below warning threshold ({warn_thresh}).",
                    details={"score": score},
                )
            return PolicyEvaluationResult(
                decision=Decision.ALLOW,
                profile=profile_name,
                reason="Package meets permissive policy acceptance criteria.",
                details={"score": score},
            )

        else:
            # Default "balanced"
            warn_thresh = float(profile.get("warn_score_threshold", 75.0))
            warn_risks = profile.get("warn_on_risks", ["HIGH", "CRITICAL"])
            if score < warn_thresh or risk.value in warn_risks or warning_gates:
                reason = "Balanced policy: package warrants developer review"
                if warning_gates:
                    reason = f"Balanced policy warning: {warning_gates[0].reason}"
                return PolicyEvaluationResult(
                    decision=Decision.WARN,
                    profile=profile_name,
                    reason=reason,
                    details={"score": score, "risk": risk.value},
                )
            return PolicyEvaluationResult(
                decision=Decision.ALLOW,
                profile=profile_name,
                reason="Package meets balanced security criteria.",
                details={"score": score, "risk": risk.value},
            )
