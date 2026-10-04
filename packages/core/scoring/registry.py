"""Metric Registry and unified evaluation orchestrator."""

from __future__ import annotations

import logging

from ..models.scoring import (
    MetricEvidence,
    MetricResult,
    MetricStatus,
)
from ..pipeline.context import AnalysisContext
from ..tracing import fmt_fields
from .config import EngineConfig
from .metrics.adoption import AdoptionMetricsExtractor
from .metrics.dependency import SupplyChainMetricsExtractor
from .metrics.maintenance import MaintenanceMetricsExtractor
from .metrics.malicious_behavior import (
    IntegrityMetricsExtractor,
    TyposquattingEvaluator,
)
from .metrics.vulnerability import VulnerabilityRiskEngine
from .normalization.registry import (
    NormalizerRegistry,
    get_default_normalizer_registry,
)

logger = logging.getLogger(__name__)


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
        self.integrity_extractor = IntegrityMetricsExtractor()
        self.typo_evaluator = TyposquattingEvaluator()
        self.supply_chain_extractor = SupplyChainMetricsExtractor()
        self.maintenance_extractor = MaintenanceMetricsExtractor()
        self.adoption_extractor = AdoptionMetricsExtractor()

    def extract_and_evaluate_all(
        self,
        context: AnalysisContext,
    ) -> dict[str, MetricResult]:
        """Extracts and normalizes all 36 metrics defined in the frozen configuration."""
        raw_evidence_map: dict[str, MetricEvidence] = {}
        evidence_origin: dict[str, str] = {}

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
        evidence_origin["vulnerability_combined_risk"] = "vulnerability"

        logger.info(
            "vulnerability evidence | status=%s advisories_in=%d applicable=%d | "
            "combined_risk=%.4f -> normalized_safety=%.4f (1.0 - combined_risk) | "
            "per_vuln_risk=%s",
            vuln_status.value,
            len(context.vulnerabilities.items),
            len(vuln_risks),
            combined_risk,
            norm_vuln_val,
            fmt_fields(
                {r.vulnerability_id: round(r.individual_risk, 4) for r in vuln_risks}
            )
            if vuln_risks
            else "none",
        )

        # 2. Typosquatting Evaluation
        if context.identity.status == "MISSING":
            raw_evidence_map["typosquatting_risk"] = MetricEvidence(
                metric_name="typosquatting_risk",
                raw_value=None,
                status=MetricStatus.MISSING,
                source="identity",
                confidence=0.0,
            )
            raw_evidence_map["typosquatting_context"] = MetricEvidence(
                metric_name="typosquatting_context",
                raw_value=None,
                status=MetricStatus.MISSING,
                source="identity",
                confidence=0.0,
            )
            evidence_origin["typosquatting_risk"] = "typosquatting"
            evidence_origin["typosquatting_context"] = "typosquatting"
            logger.info(
                "typosquatting evidence | MISSING: identity evidence unavailable, so "
                "no name-similarity comparison was possible"
            )
        else:
            (
                typo_risk,
                typo_target,
                typo_sim,
                _typo_ctx,
            ) = self.typo_evaluator.evaluate(context)
            logger.info(
                "typosquatting evidence | similarity=%.4f target=%s context_risk=%.4f "
                "-> typosquatting_risk=%.4f (similarity * context_risk, below the "
                "%.2f similarity floor treated as no signal)",
                typo_sim,
                typo_target or "none",
                _typo_ctx,
                typo_risk,
                TyposquattingEvaluator.SIMILARITY_FLOOR,
            )
            raw_evidence_map["typosquatting_risk"] = MetricEvidence(
                metric_name="typosquatting_risk",
                raw_value=typo_risk,
                status=MetricStatus.AVAILABLE,
                source="identity",
                confidence=0.90,
                notes=f"Similarity: {typo_sim:.1%}, Target: {typo_target or 'none'}",
            )
            raw_evidence_map["typosquatting_context"] = MetricEvidence(
                metric_name="typosquatting_context",
                raw_value=typo_risk,
                status=MetricStatus.AVAILABLE,
                source="identity",
                confidence=0.90,
            )
            evidence_origin["typosquatting_risk"] = "typosquatting"
            evidence_origin["typosquatting_context"] = "typosquatting"

        # 3. Integrity Metrics
        self._absorb(
            raw_evidence_map,
            evidence_origin,
            self.integrity_extractor.extract_all(context),
            extractor="integrity",
        )

        # 4. Supply Chain Metrics
        self._absorb(
            raw_evidence_map,
            evidence_origin,
            self.supply_chain_extractor.extract_all(context),
            extractor="supply_chain",
        )

        # 5. Maintenance Metrics
        self._absorb(
            raw_evidence_map,
            evidence_origin,
            self.maintenance_extractor.extract_all(context),
            extractor="maintenance",
        )

        # 6. Adoption Metrics
        self._absorb(
            raw_evidence_map,
            evidence_origin,
            self.adoption_extractor.extract_all(context),
            extractor="adoption",
        )

        logger.info(
            "metric evidence extracted=%d from %s | %s",
            len(raw_evidence_map),
            fmt_fields(
                {
                    extractor: sum(
                        1 for o in evidence_origin.values() if o == extractor
                    )
                    for extractor in sorted(set(evidence_origin.values()))
                }
            ),
            fmt_fields(
                {name: ev.source for name, ev in sorted(raw_evidence_map.items())}
            ),
        )

        # Metrics declared in config that no extractor produced: a silent hole in the
        # score, so it is called out rather than left to be discovered as a low score.
        unproduced = sorted(set(self.config.metrics) - set(raw_evidence_map))
        if unproduced:
            logger.warning(
                "metrics in config with no evidence produced by any extractor: %s",
                fmt_fields({name: True for name in unproduced}),
            )

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

                logger.debug(
                    "metric=%s | EXCLUDED | status=%s missing_policy=%s "
                    "stale_policy=%s normalized=%s weight=%.4f extractor=%s | "
                    "reason=%s",
                    name,
                    status.value,
                    metric_def.missing_policy,
                    metric_def.stale_policy,
                    "excluded" if norm_val is None else f"{norm_val:.4f}",
                    metric_def.weight,
                    evidence_origin.get(name, "none"),
                    "raw value absent"
                    if ev is None or ev.raw_value is None
                    else "status not available",
                )

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
                normalizer_name = "VulnerabilityRiskEngine"
            else:
                normalizer = self.normalizer_reg.get(metric_def.normalization)
                normalizer_name = type(normalizer).__name__
                norm_val = normalizer.normalize(
                    ev.raw_value, metric_def.normalization_params
                )

            # Clamp normalized value to [0.0, 1.0]
            norm_val = max(0.0, min(1.0, float(norm_val)))

            conf = ev.confidence
            confidence_note = ""
            if is_stale and metric_def.stale_policy == "penalize_confidence":
                conf = max(0.0, min(1.0, conf * 0.5))
                confidence_note = f" (stale: halved from {ev.confidence:.2f})"

            logger.debug(
                "metric=%s | raw=%s -> normalized=%.4f | %s(%s) params=%s | "
                "status=%s source=%s confidence=%.2f%s weight=%.4f extractor=%s",
                name,
                ev.raw_value,
                norm_val,
                normalizer_name,
                metric_def.normalization,
                fmt_fields(metric_def.normalization_params),
                status.value,
                ev.source,
                conf,
                confidence_note,
                metric_def.weight,
                evidence_origin.get(name, "none"),
            )

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

    @staticmethod
    def _absorb(
        into: dict[str, MetricEvidence],
        origin: dict[str, str],
        extracted: dict[str, MetricEvidence],
        *,
        extractor: str,
    ) -> None:
        """Merges one extractor's output and remembers which extractor produced it."""
        into.update(extracted)
        for name in extracted:
            origin[name] = extractor
