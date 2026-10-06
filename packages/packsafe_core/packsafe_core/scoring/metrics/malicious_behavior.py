"""Integrity metrics and malicious behavior extractors."""

from __future__ import annotations

from ...models.scoring import MetricEvidence, MetricStatus
from ...pipeline.context import AnalysisContext

# Severity multipliers used to weight finding counts into a risk score.
SEVERITY_MULTIPLIER = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0}


def _metric_status(evidence_status: object) -> MetricStatus:
    """Maps an evidence status onto a metric status, defaulting to AVAILABLE."""
    if isinstance(evidence_status, MetricStatus):
        return evidence_status
    try:
        return MetricStatus(str(evidence_status).upper())
    except ValueError:
        return MetricStatus.AVAILABLE


class IntegrityMetricsExtractor:
    """Extracts raw metric evidence for the Integrity category."""

    def _weighted_count(
        self, findings: tuple, finding_types: tuple[str, ...]
    ) -> float:
        """Sums confidence x severity weight for findings matching any given type."""
        score = 0.0
        for f in findings:
            ft = f.finding_type.upper()
            if any(t in ft for t in finding_types):
                conf = max(0.1, min(1.0, float(f.confidence)))
                mult = SEVERITY_MULTIPLIER.get(f.severity.upper(), 0.5)
                score += conf * mult
        return score

    def extract_all(self, context: AnalysisContext) -> dict[str, MetricEvidence]:
        results: dict[str, MetricEvidence] = {}

        findings = context.static_analysis.findings
        status = _metric_status(context.static_analysis.status)

        # 1. Confirmed malicious behavior
        has_confirmed_malware = any(
            "CONFIRMED_MALICIOUS" in f.finding_type.upper()
            or "MALWARE" in f.finding_type.upper()
            for f in findings
        )
        results["confirmed_malicious_behavior"] = MetricEvidence(
            metric_name="confirmed_malicious_behavior",
            raw_value=has_confirmed_malware,
            status=status,
            source="static_analysis",
            confidence=1.0 if has_confirmed_malware else 0.9,
        )

        # 2. Credential/secret access
        results["credential_secret_access"] = MetricEvidence(
            metric_name="credential_secret_access",
            raw_value=self._weighted_count(
                findings,
                ("CREDENTIAL", "SECRET", "TOKEN", "ENV_THEFT", "SSH"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.95,
        )

        # 3. Suspicious install behavior
        results["suspicious_install_behavior"] = MetricEvidence(
            metric_name="suspicious_install_behavior",
            raw_value=self._weighted_count(
                findings,
                ("INSTALL", "SETUP", "HOOK", "PREINSTALL", "POSTINSTALL"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 4. Remote code download
        results["remote_code_download"] = MetricEvidence(
            metric_name="remote_code_download",
            raw_value=self._weighted_count(
                findings,
                ("REMOTE_DOWNLOAD", "DOWNLOAD_PAYLOAD", "C2", "FETCH_EXEC"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 5. Shell/process execution
        results["shell_process_execution"] = MetricEvidence(
            metric_name="shell_process_execution",
            raw_value=self._weighted_count(
                findings,
                ("SUBPROCESS", "SHELL", "OS_SYSTEM", "SPAWN", "EXEC_PROCESS"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 6. Dynamic code execution
        results["dynamic_code_execution"] = MetricEvidence(
            metric_name="dynamic_code_execution",
            raw_value=self._weighted_count(
                findings,
                ("EVAL", "EXEC", "COMPILE", "DYNAMIC_IMPORT", "VM_RUN"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 7. Obfuscation patterns
        results["obfuscation_patterns"] = MetricEvidence(
            metric_name="obfuscation_patterns",
            raw_value=self._weighted_count(
                findings,
                ("OBFUSCAT", "BASE64", "COMPRESS", "ENTROPY", "ENCRYPT"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.85,
        )

        # 8. Suspicious network behavior
        results["suspicious_network_behavior"] = MetricEvidence(
            metric_name="suspicious_network_behavior",
            raw_value=self._weighted_count(
                findings,
                ("SOCKET", "RAW_IP", "SUSPICIOUS_NETWORK", "DNS_TUNNEL"),
            ),
            status=status,
            source="static_analysis",
            confidence=0.85,
        )

        # 9. Package / repo mismatch
        results["package_repo_mismatch"] = MetricEvidence(
            metric_name="package_repo_mismatch",
            raw_value=context.identity.package_repo_mismatch,
            status=MetricStatus.AVAILABLE,
            source="identity",
            confidence=0.95,
        )

        # 10. Publisher anomaly
        results["publisher_anomaly"] = MetricEvidence(
            metric_name="publisher_anomaly",
            raw_value=context.identity.publisher_anomaly_score,
            status=MetricStatus.AVAILABLE,
            source="identity",
            confidence=0.90,
        )

        return results


class TyposquattingEvaluator:
    """Evaluates typosquatting similarity and contextual mimic risk."""

    # Similarity below this is not considered a candidate impersonation at all.
    SIMILARITY_FLOOR = 0.85

    def evaluate(
        self, context: AnalysisContext
    ) -> tuple[float, str | None, float, float]:
        """Returns (typosquatting_risk, target_package, name_similarity, context_risk)."""
        identity = context.identity

        target_pkg = identity.target_popular_package
        name_sim = float(identity.name_similarity or 0.0)

        if name_sim < self.SIMILARITY_FLOOR:
            return (0.0, target_pkg, name_sim, 0.0)

        context_risk = (
            float(identity.context_risk)
            if identity.context_risk is not None and identity.context_risk > 0
            else calculate_context_risk(context)
        )

        typo_risk = name_sim * context_risk
        return (max(0.0, min(1.0, typo_risk)), target_pkg, name_sim, context_risk)


def calculate_context_risk(context: AnalysisContext) -> float:
    """Calculates a contextual trust anomaly score in [0.0, 1.0]."""
    # 1. Low adoption signal (35%)
    downloads = context.registry.downloads_30d
    if downloads is None or downloads < 100:
        s_low_adoption = 1.0
    elif downloads < 1000:
        s_low_adoption = 0.7
    elif downloads < 10000:
        s_low_adoption = 0.3
    else:
        s_low_adoption = 0.0

    # 2. New package signal (20%)
    maturity_days = context.registry.project_maturity_days
    if maturity_days is None or maturity_days < 30:
        s_new_pkg = 1.0
    elif maturity_days < 90:
        s_new_pkg = 0.6
    else:
        s_new_pkg = 0.0

    # 3. Weak/anomalous publisher signal (15%)
    s_weak_pub = (
        context.identity.publisher_anomaly_score
        if context.identity.publisher_anomaly_score is not None
        else 0.0
    )

    # 4. Missing repository signal (15%)
    repo_url = context.repository.repository_url or ""
    stars = context.repository.stars if context.repository.stars is not None else 0
    s_missing_repo = 1.0 if (not repo_url or stars < 5) else 0.0

    # 5. Suspicious installation/static behavior signal (15%)
    has_suspicious_static = any(
        f.severity.upper() in ("HIGH", "CRITICAL")
        for f in context.static_analysis.findings
    )
    s_suspicious = 1.0 if has_suspicious_static else 0.0

    context_risk = (
        0.35 * s_low_adoption
        + 0.20 * s_new_pkg
        + 0.15 * s_weak_pub
        + 0.15 * s_missing_repo
        + 0.15 * s_suspicious
    )
    return max(0.0, min(1.0, context_risk))