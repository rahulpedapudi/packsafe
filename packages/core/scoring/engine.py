"""Core deterministic Score Engine for PackSafe with normalized findings and missing category handling."""

from __future__ import annotations

from datetime import datetime, timezone
from packsafe.evidence.models import PackageEvidence
from packsafe.evidence.normalization.vulnerability import VulnerabilityDeduplicator, is_version_affected
from packsafe.scoring.attribution.engine import AttributionEngine
from packsafe.scoring.categories.engine import CategoryScoringEngine
from packsafe.scoring.confidence.engine import ConfidenceEngine
from packsafe.scoring.config import EngineConfig, load_engine_config
from packsafe.scoring.finding_normalizer import FindingNormalizer
from packsafe.scoring.gates.engine import SecurityGateEngine
from packsafe.scoring.models import (
    Decision,
    Finding,
    GateSeverity,
    MetricStatus,
    RiskLevel,
    ScoreResult,
)
from packsafe.scoring.registry import MetricRegistry


def map_risk_level(score: float) -> RiskLevel:
    """Deterministic mapping from safety score to risk level."""
    if score >= 90.0:
        return RiskLevel.SAFE
    elif score >= 75.0:
        return RiskLevel.LOW
    elif score >= 60.0:
        return RiskLevel.MODERATE
    elif score >= 40.0:
        return RiskLevel.HIGH
    return RiskLevel.CRITICAL


RISK_RANK = {
    RiskLevel.SAFE: 0,
    RiskLevel.LOW: 1,
    RiskLevel.MODERATE: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


def max_risk_level(*risks: RiskLevel) -> RiskLevel:
    """Returns the most severe RiskLevel among the candidates."""
    return max(risks, key=lambda r: RISK_RANK.get(r, 0))


def map_vulnerability_risk_level(vuln_res: Any | None, findings: tuple[Finding, ...]) -> RiskLevel:
    """Maps canonical vulnerability findings and aggregate risk to a standardized RiskLevel."""
    if not vuln_res:
        return RiskLevel.SAFE

    # Actively exploited vulnerability -> CRITICAL
    if any(getattr(r, "actively_exploited", False) for r in getattr(vuln_res, "risks", [])):
        return RiskLevel.CRITICAL

    vuln_findings = [f for f in findings if f.category == "security"]
    has_critical = any(f.severity.upper() == "CRITICAL" for f in vuln_findings)
    has_high = any(f.severity.upper() == "HIGH" for f in vuln_findings)
    has_medium = any(f.severity.upper() in ("MEDIUM", "MODERATE") for f in vuln_findings)
    has_low = any(f.severity.upper() == "LOW" for f in vuln_findings)

    combined = getattr(vuln_res, "combined_risk", 0.0)
    if has_critical or combined >= 0.70:
        return RiskLevel.HIGH
    elif has_high or combined >= 0.40:
        return RiskLevel.HIGH
    elif has_medium or combined >= 0.20:
        return RiskLevel.MODERATE
    elif has_low or combined > 0.0:
        return RiskLevel.LOW
    return RiskLevel.SAFE


class ScoreEngine:
    """Deterministic, pure security score engine.

    Performs zero network calls or file I/O during calculation.
    """

    def __init__(self, config: EngineConfig | None = None) -> None:
        self.config = config or load_engine_config()
        self.metric_registry = MetricRegistry(self.config)
        self.category_engine = CategoryScoringEngine(self.config)
        self.gate_engine = SecurityGateEngine(self.config)
        self.confidence_engine = ConfidenceEngine(self.config)
        self.attribution_engine = AttributionEngine(self.config)
        self.vuln_deduplicator = VulnerabilityDeduplicator()

    def calculate(self, evidence: PackageEvidence) -> ScoreResult:
        """Calculates a deterministic security-risk assessment from the supplied evidence."""
        # 1. Extract and evaluate all metrics (includes canonical vulnerability risk evaluation)
        metric_results = self.metric_registry.extract_and_evaluate_all(evidence)
        vuln_res = getattr(self.metric_registry, "last_vuln_eval_result", None)
        risk_map = {r.vulnerability_id: r.individual_risk for r in vuln_res.risks} if vuln_res else {}

        # 2. Normalize findings from static analysis and applicable canonical vulnerabilities
        normalized_findings: list[Finding] = []
        pkg_version = evidence.package.version
        ecosystem = evidence.package.ecosystem

        for sf in evidence.static_analysis.findings:
            normalized_findings.append(FindingNormalizer.from_static_finding(sf, pkg_version))

        # Deduplicate vulnerabilities to canonical items (one finding per canonical CVE/advisory cluster)
        deduped_vulns = self.vuln_deduplicator.deduplicate(evidence.vulnerabilities.items)
        for v in deduped_vulns:
            if is_version_affected(pkg_version, v.affected_ranges, v.fixed_versions, ecosystem):
                indiv_risk = risk_map.get(v.vulnerability_id, 0.0)
                normalized_findings.append(FindingNormalizer.from_vulnerability(v, pkg_version, risk=indiv_risk))

        immutable_findings = tuple(normalized_findings)

        # 3. Compute category scores
        categories = self.category_engine.calculate_all(metric_results)

        # 4. Compute BaseScore with missing-category denominator rule:
        # BaseScore = sum(cat.weight * cat.score for cat in available) / sum(cat.weight for cat in available)
        available_categories = [
            cat for cat in categories.values()
            if cat.status != MetricStatus.MISSING and cat.available_weight > 0.0
        ]
        total_avail_cat_weight = sum(cat.weight for cat in available_categories)

        if total_avail_cat_weight > 0.0:
            base_score = sum(cat.weight * cat.score for cat in available_categories) / total_avail_cat_weight
        else:
            base_score = 0.0

        base_score = max(0.0, min(100.0, base_score))

        # 5. Evaluate Security Gates with findings
        gate_results = self.gate_engine.evaluate(evidence, immutable_findings)

        # 6. Apply Gate Overrides
        critical_gates = [g for g in gate_results if g.triggered and g.severity == GateSeverity.CRITICAL]
        warning_gates = [g for g in gate_results if g.triggered and g.severity == GateSeverity.WARNING]

        if critical_gates:
            floor = min(
                (g.score_floor for g in critical_gates if g.score_floor is not None),
                default=5.0,
            )
            final_score = min(base_score, floor)
            score_risk = map_risk_level(final_score)
            vuln_risk = map_vulnerability_risk_level(vuln_res, immutable_findings)
            risk = RiskLevel.CRITICAL
            decision = Decision.BLOCK
        else:
            final_score = base_score
            score_risk = map_risk_level(final_score)
            vuln_risk = map_vulnerability_risk_level(vuln_res, immutable_findings)
            risk = max_risk_level(score_risk, vuln_risk)
            if warning_gates or risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                decision = Decision.WARN
            else:
                decision = Decision.ALLOW

        # 7. Compute Confidence
        confidence = self.confidence_engine.calculate(evidence, metric_results)

        # 8. Update metric results with granular category contributions for attribution
        resolved_metric_results = dict(metric_results)
        for cat_score in categories.values():
            for m in cat_score.metrics:
                resolved_metric_results[m.metric_name] = m

        # 9. Generate Attribution
        attribution = self.attribution_engine.generate(
            categories=categories,
            metric_results=resolved_metric_results,
            gates=gate_results,
            final_score=final_score,
            risk_level=risk,
            decision=decision,
        )

        # 9. Evidence coverage summary
        ev_summary = {
            "available": sum(1 for m in metric_results.values() if m.status == MetricStatus.AVAILABLE),
            "missing": sum(1 for m in metric_results.values() if m.status == MetricStatus.MISSING),
            "stale": sum(1 for m in metric_results.values() if m.status == MetricStatus.STALE),
            "invalid": sum(1 for m in metric_results.values() if m.status == MetricStatus.INVALID),
            "not_applicable": sum(1 for m in metric_results.values() if m.status == MetricStatus.NOT_APPLICABLE),
        }

        return ScoreResult(
            package_name=evidence.package.name,
            ecosystem=evidence.package.ecosystem,
            version=evidence.package.version,
            final_score=final_score,
            base_score=base_score,
            risk_level=risk,
            decision=decision,
            confidence=confidence,
            score_risk_level=score_risk,
            vulnerability_risk_level=vuln_risk,
            categories=categories,
            findings=immutable_findings,
            gates=gate_results,
            attribution=attribution,
            analyzed_at=datetime.now(timezone.utc),
            engine_version=self.config.engine_version,
            config_version=self.config.config_version,
            config_sha256=self.config.config_sha256,
            evidence_coverage_summary=ev_summary,
        )
