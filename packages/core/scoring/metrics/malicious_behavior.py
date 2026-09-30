"""Integrity metrics and malicious behavior extractors."""

from __future__ import annotations

from typing import Any
from packsafe.evidence.models import PackageEvidence, StaticAnalysisFindingItem
from packsafe.scoring.models import MetricEvidence, MetricStatus


class IntegrityMetricsExtractor:
    """Extracts raw metric evidence for the Integrity category."""

    def extract_all(self, evidence: PackageEvidence) -> dict[str, MetricEvidence]:
        results: dict[str, MetricEvidence] = {}
        findings = evidence.static_analysis.findings
        status = MetricStatus[evidence.static_analysis.status.upper()] if hasattr(MetricStatus, evidence.static_analysis.status.upper()) else MetricStatus.AVAILABLE

        # Count occurrences or maximum severity confidence by finding type
        def get_weighted_count(finding_types: list[str]) -> float:
            score = 0.0
            for f in findings:
                ft = f.finding_type.upper()
                if any(t in ft for t in finding_types):
                    conf = max(0.1, min(1.0, float(f.confidence)))
                    sev = f.severity.upper()
                    mult = 1.0
                    if sev == "CRITICAL":
                        mult = 3.0
                    elif sev == "HIGH":
                        mult = 2.0
                    elif sev == "MEDIUM":
                        mult = 1.0
                    else:
                        mult = 0.5
                    score += conf * mult
            return score

        # 1. Confirmed malicious behavior
        has_confirmed_malware = any(
            "CONFIRMED_MALICIOUS" in f.finding_type.upper() or "MALWARE" in f.finding_type.upper()
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
        cred_score = get_weighted_count(["CREDENTIAL", "SECRET", "TOKEN", "ENV_THEFT", "SSH"])
        results["credential_secret_access"] = MetricEvidence(
            metric_name="credential_secret_access",
            raw_value=cred_score,
            status=status,
            source="static_analysis",
            confidence=0.95,
        )

        # 3. Suspicious install behavior
        install_score = get_weighted_count(["INSTALL", "SETUP", "HOOK", "PREINSTALL", "POSTINSTALL"])
        results["suspicious_install_behavior"] = MetricEvidence(
            metric_name="suspicious_install_behavior",
            raw_value=install_score,
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 4. Remote code download
        download_score = get_weighted_count(["REMOTE_DOWNLOAD", "DOWNLOAD_PAYLOAD", "C2", "FETCH_EXEC"])
        results["remote_code_download"] = MetricEvidence(
            metric_name="remote_code_download",
            raw_value=download_score,
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 5. Shell/process execution
        shell_score = get_weighted_count(["SUBPROCESS", "SHELL", "OS_SYSTEM", "SPAWN", "EXEC_PROCESS"])
        results["shell_process_execution"] = MetricEvidence(
            metric_name="shell_process_execution",
            raw_value=shell_score,
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 6. Dynamic code execution
        dynamic_score = get_weighted_count(["EVAL", "EXEC", "COMPILE", "DYNAMIC_IMPORT", "VM_RUN"])
        results["dynamic_code_execution"] = MetricEvidence(
            metric_name="dynamic_code_execution",
            raw_value=dynamic_score,
            status=status,
            source="static_analysis",
            confidence=0.90,
        )

        # 7. Obfuscation patterns
        obfuscation_score = get_weighted_count(["OBFUSCAT", "BASE64", "COMPRESS", "ENTROPY", "ENCRYPT"])
        results["obfuscation_patterns"] = MetricEvidence(
            metric_name="obfuscation_patterns",
            raw_value=obfuscation_score,
            status=status,
            source="static_analysis",
            confidence=0.85,
        )

        # 8. Suspicious network behavior
        network_score = get_weighted_count(["SOCKET", "RAW_IP", "SUSPICIOUS_NETWORK", "DNS_TUNNEL"])
        results["suspicious_network_behavior"] = MetricEvidence(
            metric_name="suspicious_network_behavior",
            raw_value=network_score,
            status=status,
            source="static_analysis",
            confidence=0.85,
        )

        # 9. Package / repo mismatch
        repo_mismatch = evidence.identity.package_repo_mismatch
        results["package_repo_mismatch"] = MetricEvidence(
            metric_name="package_repo_mismatch",
            raw_value=repo_mismatch,
            status=MetricStatus.AVAILABLE,
            source="registry",
            confidence=0.95,
        )

        # 10. Publisher anomaly
        pub_anomaly = evidence.identity.publisher_anomaly_score
        results["publisher_anomaly"] = MetricEvidence(
            metric_name="publisher_anomaly",
            raw_value=pub_anomaly,
            status=MetricStatus.AVAILABLE,
            source="registry",
            confidence=0.90,
        )

        return results
