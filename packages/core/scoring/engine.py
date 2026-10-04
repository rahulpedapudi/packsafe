"""Core deterministic Score Engine for PackSafe with normalized findings and missing category handling."""

from __future__ import annotations

import logging
import time
from datetime import UTC, datetime
from typing import Any

from ..models.scoring import (
    Decision,
    Finding,
    GateSeverity,
    MetricStatus,
    RiskLevel,
    ScoreResult,
)
from ..models.vulnerability import ExploitationSignal
from ..pipeline.context import AnalysisContext
from ..sources.normalizers.vulnerability import (
    VulnerabilityDeduplicator,
    is_version_affected,
)
from ..tracing import COMPUTE_KIND, fmt_duration, fmt_fields, fmt_value, perf
from .attribution.engine import AttributionEngine
from .categories.engine import CategoryScoringEngine
from .confidence.engine import ConfidenceEngine
from .config import EngineConfig, load_engine_config
from .finding_normalizer import FindingNormalizer
from .gates.engine import SecurityGateEngine
from .registry import MetricRegistry

logger = logging.getLogger(__name__)


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


def is_imminent_exploitation(risk: Any) -> bool:
    """True when exploitation evidence is strong enough to warrant a CRITICAL rating.

    Deliberately narrow. KEV membership alone is not enough: CISA rarely delists, so a
    multi-year-old listing does not mean a CVE is being exploited today. Requiring a
    recent listing or reported ransomware use keeps this from overclaiming.
    """
    signal = getattr(risk, "exploitation_signal", None)

    if getattr(risk, "known_ransomware_use", False):
        return True

    return signal == ExploitationSignal.RECENTLY_LISTED


def map_vulnerability_risk_level(
    vuln_res: Any | None, findings: tuple[Finding, ...]
) -> RiskLevel:
    """Maps canonical vulnerability findings and aggregate risk to a standardized RiskLevel."""
    if not vuln_res:
        return RiskLevel.SAFE

    # Imminent exploitation (recent KEV listing or ransomware use) -> CRITICAL
    if any(is_imminent_exploitation(r) for r in getattr(vuln_res, "risks", [])):
        return RiskLevel.CRITICAL

    vuln_findings = [f for f in findings if f.category == "security"]
    has_critical = any(f.severity.upper() == "CRITICAL" for f in vuln_findings)
    has_high = any(f.severity.upper() == "HIGH" for f in vuln_findings)
    has_medium = any(
        f.severity.upper() in ("MEDIUM", "MODERATE") for f in vuln_findings
    )
    has_low = any(f.severity.upper() == "LOW" for f in vuln_findings)

    combined = getattr(vuln_res, "combined_risk", 0.0)
    if has_critical or combined >= 0.70 or has_high or combined >= 0.40:
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

    def calculate(self, evidence: AnalysisContext) -> ScoreResult:
        """Calculates a deterministic security-risk assessment from the supplied evidence."""
        calc_start = time.perf_counter()

        # ------------------------------------------------------------------ inputs
        logger.info("-" * 100)
        logger.info(
            "SCORE INPUTS | package=%s version=%s ecosystem=%s | %s",
            evidence.package.name,
            evidence.package.version,
            fmt_value(evidence.package.ecosystem),
            fmt_fields(
                {
                    "registry": evidence.registry.status,
                    "repository": evidence.repository.status,
                    "vulnerabilities": evidence.vulnerabilities.status,
                    "dependencies": evidence.dependencies.status,
                    "static_analysis": evidence.static_analysis.status,
                    "identity": evidence.identity.status,
                    "license": evidence.license.status,
                    "coverage_tier": evidence.analysis_coverage_tier,
                    "static_findings": len(evidence.static_analysis.findings),
                    "advisories": len(evidence.vulnerabilities.items),
                    "provenance": len(evidence.provenance),
                }
            ),
        )
        logger.info(
            "SCORE CONFIG | engine_version=%s config_version=%s config_sha256=%s "
            "metrics=%d categories=%s",
            self.config.engine_version,
            self.config.config_version,
            self.config.config_sha256[:12],
            len(self.config.metrics),
            fmt_fields(self.config.category_weights),
        )

        # 1. Extract and evaluate all metrics (includes canonical vulnerability risk evaluation)
        step_start = time.perf_counter()
        metric_results = self.metric_registry.extract_and_evaluate_all(evidence)
        perf.record(
            "compute:metric_extraction",
            time.perf_counter() - step_start,
            kind=COMPUTE_KIND,
        )
        vuln_res = getattr(self.metric_registry, "last_vuln_eval_result", None)
        risk_map = (
            {r.vulnerability_id: r.individual_risk for r in vuln_res.risks}
            if vuln_res
            else {}
        )

        status_counts: dict[str, int] = {}
        for m in metric_results.values():
            key = m.status.value
            status_counts[key] = status_counts.get(key, 0) + 1

        logger.info(
            "STEP 1 metrics | evaluated=%d | %s | contributing=%d",
            len(metric_results),
            fmt_fields(status_counts),
            sum(
                1
                for m in metric_results.values()
                if m.normalized_value is not None
            ),
        )

        # 2. Normalize findings from static analysis and applicable canonical vulnerabilities
        normalized_findings: list[Finding] = []
        pkg_version = evidence.package.version
        ecosystem = evidence.package.ecosystem

        for sf in evidence.static_analysis.findings:
            normalized_findings.append(
                FindingNormalizer.from_static_finding(sf, pkg_version)
            )

        # Deduplicate vulnerabilities to canonical items (one finding per canonical CVE/advisory cluster)
        deduped_vulns = self.vuln_deduplicator.deduplicate(
            evidence.vulnerabilities.items
        )
        not_applicable = 0
        for v in deduped_vulns:
            if is_version_affected(
                pkg_version, v.affected_ranges, v.fixed_versions, ecosystem
            ):
                indiv_risk = risk_map.get(v.vulnerability_id, 0.0)
                normalized_findings.append(
                    FindingNormalizer.from_vulnerability(
                        v, pkg_version, risk=indiv_risk
                    )
                )
            else:
                not_applicable += 1

        immutable_findings = tuple(normalized_findings)

        finding_severities: dict[str, int] = {}
        for f in immutable_findings:
            key = f.severity.upper()
            finding_severities[key] = finding_severities.get(key, 0) + 1

        logger.info(
            "STEP 2 findings | static=%d advisories_raw=%d deduped=%d applicable=%d "
            "skipped_not_affected=%d | %s",
            len(evidence.static_analysis.findings),
            len(evidence.vulnerabilities.items),
            len(deduped_vulns),
            len(deduped_vulns) - not_applicable,
            not_applicable,
            fmt_fields(finding_severities) if finding_severities else "none",
        )
        for f in immutable_findings:
            logger.debug(
                "finding | id=%s category=%s severity=%s confidence=%.2f "
                "score_penalty=%.1f risk=%.4f gate=%s | %s",
                f.finding_id,
                f.category,
                f.severity,
                f.confidence,
                f.score_penalty,
                f.risk,
                f.gate_triggered,
                f.title,
            )

        # 3. Compute category scores
        step_start = time.perf_counter()
        categories = self.category_engine.calculate_all(metric_results)
        perf.record(
            "compute:category_scoring",
            time.perf_counter() - step_start,
            kind=COMPUTE_KIND,
        )

        # 4. Compute BaseScore with missing-category denominator rule:
        # BaseScore = sum(cat.weight * cat.score for cat in available) / sum(cat.weight for cat in available)
        available_categories = [
            cat
            for cat in categories.values()
            if cat.status != MetricStatus.MISSING and cat.available_weight > 0.0
        ]
        excluded_categories = [
            cat for cat in categories.values() if cat not in available_categories
        ]
        total_avail_cat_weight = sum(cat.weight for cat in available_categories)
        numerator = sum(cat.weight * cat.score for cat in available_categories)

        if total_avail_cat_weight > 0.0:
            base_score = numerator / total_avail_cat_weight
        else:
            base_score = 0.0

        base_score = max(0.0, min(100.0, base_score))

        logger.info(
            "STEP 4 base_score | numerator=sum(weight*score)=%.4f denominator="
            "sum(weight)=%.4f base_score=%.4f | included=%s | excluded=%s",
            numerator,
            total_avail_cat_weight,
            base_score,
            fmt_fields({c.name: round(c.score, 2) for c in available_categories}),
            fmt_fields(
                {c.name: c.status.value for c in excluded_categories}
            )
            if excluded_categories
            else "none",
        )

        # 5. Evaluate Security Gates with findings
        step_start = time.perf_counter()
        gate_results = self.gate_engine.evaluate(evidence, immutable_findings)
        perf.record(
            "compute:gate_evaluation",
            time.perf_counter() - step_start,
            kind=COMPUTE_KIND,
        )

        # 6. Apply Gate Overrides
        critical_gates = [
            g
            for g in gate_results
            if g.triggered and g.severity == GateSeverity.CRITICAL
        ]
        warning_gates = [
            g
            for g in gate_results
            if g.triggered and g.severity == GateSeverity.WARNING
        ]

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
            logger.info(
                "STEP 6 override | CRITICAL GATE(s)=%s applied | base_score=%.4f "
                "score_floor=%.2f final_score=%.4f | rule=final_score<=score_floor, "
                "risk=CRITICAL, decision=BLOCK",
                fmt_fields({g.gate_id: g.score_floor for g in critical_gates}),
                base_score,
                floor,
                final_score,
            )
        else:
            final_score = base_score
            score_risk = map_risk_level(final_score)
            vuln_risk = map_vulnerability_risk_level(vuln_res, immutable_findings)
            risk = max_risk_level(score_risk, vuln_risk)
            if warning_gates or risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                decision = Decision.WARN
            else:
                decision = Decision.ALLOW
            logger.info(
                "STEP 6 override | no critical gate | final_score=%.4f=base_score | "
                "score_risk=%s vulnerability_risk=%s -> risk=%s (max) | warning_gates=%s "
                "-> decision=%s",
                final_score,
                score_risk.value,
                vuln_risk.value,
                risk.value,
                fmt_fields({g.gate_id: g.severity.value for g in warning_gates})
                if warning_gates
                else "none",
                decision.value,
            )

        # 7. Compute Confidence
        step_start = time.perf_counter()
        confidence = self.confidence_engine.calculate(evidence, metric_results)
        perf.record(
            "compute:confidence",
            time.perf_counter() - step_start,
            kind=COMPUTE_KIND,
        )

        # 8. Update metric results with granular category contributions for attribution
        resolved_metric_results = dict(metric_results)
        for cat_score in categories.values():
            for m in cat_score.metrics:
                resolved_metric_results[m.metric_name] = m

        # 9. Generate Attribution
        step_start = time.perf_counter()
        attribution = self.attribution_engine.generate(
            categories=categories,
            metric_results=resolved_metric_results,
            gates=gate_results,
            final_score=final_score,
            risk_level=risk,
            decision=decision,
        )
        perf.record(
            "compute:attribution",
            time.perf_counter() - step_start,
            kind=COMPUTE_KIND,
        )

        # 9. Evidence coverage summary
        ev_summary = {
            "available": sum(
                1 for m in metric_results.values() if m.status == MetricStatus.AVAILABLE
            ),
            "missing": sum(
                1 for m in metric_results.values() if m.status == MetricStatus.MISSING
            ),
            "stale": sum(
                1 for m in metric_results.values() if m.status == MetricStatus.STALE
            ),
            "invalid": sum(
                1 for m in metric_results.values() if m.status == MetricStatus.INVALID
            ),
            "not_applicable": sum(
                1
                for m in metric_results.values()
                if m.status == MetricStatus.NOT_APPLICABLE
            ),
        }

        elapsed = time.perf_counter() - calc_start
        logger.info(
            "SCORE OUTPUT | final_score=%.4f base_score=%.4f risk_level=%s "
            "decision=%s confidence=%.2f%% | %s",
            final_score,
            base_score,
            risk.value,
            decision.value,
            confidence,
            fmt_fields(ev_summary),
        )
        logger.info("SCORE COMPLETE | duration=%s", fmt_duration(elapsed))
        logger.info("-" * 100)

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
            analyzed_at=datetime.now(UTC),
            engine_version=self.config.engine_version,
            config_version=self.config.config_version,
            config_sha256=self.config.config_sha256,
            evidence_coverage_summary=ev_summary,
        )
