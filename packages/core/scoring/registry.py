"""Metric Registry and unified evaluation orchestrator."""

from __future__ import annotations

from ..models.scoring import (
    MetricEvidence,
    MetricResult,
    MetricStatus,
)
from ..pipeline.context import AnalysisContext
from .config import EngineConfig
from .metrics.adoption import AdoptionMetricsExtractor
from .metrics.dependency import SupplyChainMetricsExtractor
from .metrics.maintenance import MaintenanceMetricsExtractor

# from .metrics.malicious_behavior import IntegrityMetricsExtractor
# from .metrics.typosquatting import TyposquattingEvaluator
from .metrics.vulnerability import VulnerabilityRiskEngine
from .normalization.registry import (
    NormalizerRegistry,
    get_default_normalizer_registry,
)


class MetricRegistry:
    """Orchestrates metric evidence extraction and normalization against definitions."""

    def __init__(
        self,
        config: EngineConfig,
        normalizer_registry: NormalizerRegistry | None = None,
    ) -> None:
        self.config = config
        self.normalizer_reg = normalizer_registry or get_default_normalizer_registry()

        # Component extractors
        self.vuln_engine = VulnerabilityRiskEngine(
            factors_config=config.normalization.get("vulnerability_factors")
        )
        # self.integrity_extractor = IntegrityMetricsExtractor()
        # self.typo_evaluator = TyposquattingEvaluator()
        self.supply_chain_extractor = SupplyChainMetricsExtractor()
        self.maintenance_extractor = MaintenanceMetricsExtractor()
        self.adoption_extractor = AdoptionMetricsExtractor()

    def extract_and_evaluate_all(
        self,
        context: AnalysisContext,
    ) -> dict[str, MetricResult]:
        """Extracts and normalizes all 36 metrics defined in the frozen configuration."""
        raw_evidence_map: dict[str, MetricEvidence] = {}

        # 1. Vulnerability Evaluation
        vuln_res = self.vuln_engine.evaluate(context)
        self.last_vuln_eval_result = vuln_res
        norm_vuln_val = vuln_res.normalized_value
        vuln_risks = vuln_res.risks
        vuln_status = vuln_res.status
        combined_risk = vuln_res.combined_risk

        raw_evidence_map["vulnerability_combined_risk"] = MetricEvidence(
            metric_name="vulnerability_combined_risk",
            raw_value=round(combined_risk, 4),
            status=vuln_status,
            source="osv",
            confidence=1.0 if vuln_status == MetricStatus.AVAILABLE else 0.5,
            notes=f"{len(vuln_risks)} applicable vulnerabilities (combined risk: {combined_risk:.4f})",
        )

        # 2. Typosquatting Evaluation
        # if context.identity.status == "MISSING":
        #     raw_evidence_map["typosquatting_risk"] = MetricEvidence(
        #         metric_name="typosquatting_risk",
        #         raw_value=None,
        #         status=MetricStatus.MISSING,
        #         source="identity",
        #         confidence=0.0,
        #     )
        #     raw_evidence_map["typosquatting_context"] = MetricEvidence(
        #         metric_name="typosquatting_context",
        #         raw_value=None,
        #         status=MetricStatus.MISSING,
        #         source="identity",
        #         confidence=0.0,
        #     )
        # else:
        #     typo_risk, typo_target, typo_sim, typo_ctx = self.typo_evaluator.evaluate(
        #         context
        #     )
        #     raw_evidence_map["typosquatting_risk"] = MetricEvidence(
        #         metric_name="typosquatting_risk",
        #         raw_value=typo_risk,
        #         status=MetricStatus.AVAILABLE,
        #         source="identity",
        #         confidence=0.90,
        #         notes=f"Similarity: {typo_sim:.1%}, Target: {typo_target or 'none'}",
        #     )
        #     raw_evidence_map["typosquatting_context"] = MetricEvidence(
        #         metric_name="typosquatting_context",
        #         raw_value=typo_risk,
        #         status=MetricStatus.AVAILABLE,
        #         source="identity",
        #         confidence=0.90,
        #     )

        # # 3. Integrity Metrics
        # raw_evidence_map.update(self.integrity_extractor.extract_all(context))

        # 4. Supply Chain Metrics
        raw_evidence_map.update(self.supply_chain_extractor.extract_all(context))

        # 5. Maintenance Metrics
        raw_evidence_map.update(self.maintenance_extractor.extract_all(context))

        # 6. Adoption Metrics
        raw_evidence_map.update(self.adoption_extractor.extract_all(context))

        # 7. Normalize against MetricDefinition
        results: dict[str, MetricResult] = {}

        for name, metric_def in self.config.metrics.items():
            ev = raw_evidence_map.get(name)

            raw_status = ev.status if ev else MetricStatus.MISSING
            if isinstance(raw_status, str):
                try:
                    status = MetricStatus(raw_status.upper())
                except ValueError:
                    status = MetricStatus.MISSING
            else:
                status = raw_status

            # Evidence Truthfulness: If raw_value is None, metric data is MISSING
            if ev is None or ev.raw_value is None:
                status = MetricStatus.MISSING

            is_available = status == MetricStatus.AVAILABLE
            is_stale = status == MetricStatus.STALE

            if not is_available and not (
                is_stale and metric_def.stale_policy == "penalize_confidence"
            ):
                norm_val = None
                if status != MetricStatus.MISSING:
                    if metric_def.missing_policy == "penalty":
                        norm_val = 0.0
                    elif metric_def.missing_policy == "neutral":
                        norm_val = 0.5

                results[name] = MetricResult(
                    metric_name=name,
                    raw_value=ev.raw_value if ev else None,
                    normalized_value=norm_val,
                    weight=metric_def.weight,
                    contribution=0.0,
                    status=status,
                    source=ev.source
                    if ev
                    else (
                        metric_def.required_evidence[0]
                        if metric_def.required_evidence
                        else "unknown"
                    ),
                    confidence=ev.confidence
                    if (ev and status != MetricStatus.MISSING)
                    else 0.0,
                    explanation=f"Metric data {status.value.lower()}",
                )
                continue

            # Special case for vulnerability_combined_risk: already evaluated via VulnerabilityRiskEngine
            if name == "vulnerability_combined_risk":
                norm_val = norm_vuln_val
            else:
                normalizer = self.normalizer_reg.get(metric_def.normalization)
                norm_val = normalizer.normalize(
                    ev.raw_value, metric_def.normalization_params
                )

            # Clamp normalized value to [0.0, 1.0]
            norm_val = max(0.0, min(1.0, float(norm_val)))

            conf = ev.confidence
            if is_stale and metric_def.stale_policy == "penalize_confidence":
                conf = max(0.0, min(1.0, conf * 0.5))

            # Relative contribution placeholder (final contribution computed inside category engine)
            results[name] = MetricResult(
                metric_name=name,
                raw_value=ev.raw_value,
                normalized_value=norm_val,
                weight=metric_def.weight,
                contribution=0.0,
                status=status,
                source=ev.source,
                confidence=conf,
                explanation=metric_def.explanation_template,
            )

        return results
