import dataclasses

import pytest
from packsafe_core.models.scoring import (
    CategoryScore,
    Decision,
    GateResult,
    GateSeverity,
    MetricResult,
    MetricStatus,
    RiskLevel,
    ScoreAttribution,
)
from packsafe_core.scoring.attribution.engine import AttributionEngine


@pytest.fixture
def engine(mock_config):
    return AttributionEngine(mock_config)


@pytest.fixture
def base_categories():
    return {
        "security": CategoryScore(
            name="security",
            score=80.0,
            weight=0.4,
            contribution=32.0,
            available_weight=1.0,
            total_applicable_weight=1.0,
        ),
        "integrity": CategoryScore(
            name="integrity",
            score=50.0,
            weight=0.2,
            contribution=10.0,
            available_weight=1.0,
            total_applicable_weight=1.0,
        ),
    }


@pytest.fixture
def base_metrics():
    return {
        "sec_metric": MetricResult(
            metric_name="sec_metric",
            raw_value=1,
            normalized_value=0.9,
            weight=0.6,
            contribution=54.0,
            status=MetricStatus.AVAILABLE,
            source="osv",
            confidence=1.0,
            explanation="Security is good",
        ),
        "int_metric": MetricResult(
            metric_name="int_metric",
            raw_value=1,
            normalized_value=0.3,
            weight=0.4,
            contribution=12.0,
            status=MetricStatus.AVAILABLE,
            source="npm",
            confidence=1.0,
            explanation="Integrity is bad",
        ),
    }


@pytest.fixture
def base_gates():
    return []


# 1. Engine initialization
def test_engine_instantiation(engine, mock_config):
    assert engine.config == mock_config
    assert isinstance(engine, AttributionEngine)


# 2. Basic attribution / metric mapping
def test_valid_input_produces_valid_attribution(
    engine, base_categories, base_metrics, base_gates
):
    attr = engine.generate(
        base_categories,
        base_metrics,
        base_gates,
        final_score=75.0,
        risk_level=RiskLevel.LOW,
        decision=Decision.ALLOW,
    )
    assert isinstance(attr, ScoreAttribution)
    assert "security" in attr.category_contributions
    assert attr.category_contributions["security"] == 32.0
    assert attr.category_contributions["integrity"] == 10.0


def test_correct_source_attributed(engine, base_categories, base_metrics, base_gates):
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    metric_attrs = {m.metric: m for m in attr.metric_attributions}
    assert metric_attrs["sec_metric"].source == "osv"
    assert metric_attrs["int_metric"].source == "npm"


def test_metric_to_category_mapping(engine, base_categories, base_metrics, base_gates):
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    metric_attrs = {m.metric: m for m in attr.metric_attributions}
    assert metric_attrs["sec_metric"].category == "security"
    assert metric_attrs["int_metric"].category == "integrity"


# 3. Aggregation and drivers (positive/negative impact)
def test_positive_driver_ranking(engine, base_categories, base_metrics, base_gates):
    base_metrics["sec_metric"] = dataclasses.replace(
        base_metrics["sec_metric"],
        normalized_value=0.95,
        explanation="Awesome security",
    )  # >= 0.85
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert any("Awesome security" in pos for pos in attr.top_positive_signals)


def test_negative_driver_ranking(engine, base_categories, base_metrics, base_gates):
    base_metrics["int_metric"] = dataclasses.replace(
        base_metrics["int_metric"],
        normalized_value=0.2,
        explanation="Terrible integrity",
    )  # <= 0.40
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert any("Terrible integrity" in neg for neg in attr.top_negative_signals)


def test_no_driver_for_neutral_scores(
    engine, base_categories, base_metrics, base_gates
):
    # Middle values [0.41, 0.84] do not generate top drivers
    base_metrics["sec_metric"] = dataclasses.replace(
        base_metrics["sec_metric"], normalized_value=0.6, explanation="Neutral sec"
    )
    base_metrics["int_metric"] = dataclasses.replace(
        base_metrics["int_metric"], normalized_value=0.6, explanation="Neutral int"
    )
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert len(attr.top_positive_signals) == 0
    assert len(attr.top_negative_signals) == 0


def test_driver_sorting_by_impact(engine, base_categories, base_gates):
    # Impact = weight * (norm - 0.5)
    # metric 1: weight 0.6, norm 1.0 => impact 0.6 * 0.5 = 0.3
    # metric 2: weight 0.8, norm 1.0 => impact 0.8 * 0.5 = 0.4 (Highest pos)
    metrics = {
        "m1": MetricResult(
            metric_name="m1",
            raw_value=1,
            normalized_value=1.0,
            weight=0.6,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="x",
            confidence=1.0,
            explanation="M1 pos",
        ),
        "m2": MetricResult(
            metric_name="m2",
            raw_value=1,
            normalized_value=1.0,
            weight=0.8,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="y",
            confidence=1.0,
            explanation="M2 pos",
        ),
    }
    engine.config.metrics["m1"] = engine.config.metrics["sec_metric"]
    engine.config.metrics["m2"] = engine.config.metrics["sec_metric"]

    attr = engine.generate(
        base_categories, metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert len(attr.top_positive_signals) == 2
    assert "M2 pos" in attr.top_positive_signals[0]  # Should be first


# 4. Gate interaction
def test_gate_override_prepended_to_negative_drivers(
    engine, base_categories, base_metrics
):
    gates = [
        GateResult(
            gate_id="GATE-TEST",
            triggered=True,
            severity=GateSeverity.CRITICAL,
            reason="Malware block",
        )
    ]
    base_metrics["int_metric"] = dataclasses.replace(
        base_metrics["int_metric"], normalized_value=0.2, explanation="Bad int"
    )
    attr = engine.generate(
        base_categories, base_metrics, gates, 0.0, RiskLevel.CRITICAL, Decision.BLOCK
    )
    assert attr.top_negative_signals[0] == "CRITICAL GATE: Malware block"
    assert "Bad int" in attr.top_negative_signals[1]


# 5. Recommendation rules
@pytest.mark.parametrize(
    "decision, expected_snippet",
    [
        (Decision.BLOCK, "Do NOT install"),
        (Decision.WARN, "Review package findings"),
        (Decision.REVIEW, "Review required against organization policy"),
        (Decision.ALLOW, "Package exhibits a healthy security posture"),
    ],
)
def test_primary_recommendation(
    engine, base_categories, base_metrics, base_gates, decision, expected_snippet
):
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 50.0, RiskLevel.MODERATE, decision
    )
    assert expected_snippet in attr.primary_recommendation


# 6. Missing/None handling
def test_missing_metric_value(engine, base_categories, base_metrics, base_gates):
    base_metrics["sec_metric"] = dataclasses.replace(
        base_metrics["sec_metric"], normalized_value=None, status=MetricStatus.MISSING
    )
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    metric_attrs = {m.metric: m for m in attr.metric_attributions}
    assert metric_attrs["sec_metric"].normalized_value is None
    assert metric_attrs["sec_metric"].evidence_status == "MISSING"


def test_missing_category_mapping(engine, base_categories, base_metrics, base_gates):
    # Metric not in config
    base_metrics["unknown_metric"] = MetricResult(
        metric_name="unknown_metric",
        raw_value=1,
        normalized_value=1.0,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    metric_attrs = {m.metric: m for m in attr.metric_attributions}
    assert metric_attrs["unknown_metric"].category == "unknown"
    assert metric_attrs["unknown_metric"].category_weight == 0.0


def test_empty_metrics(engine, base_categories, base_gates):
    attr = engine.generate(
        base_categories, {}, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert len(attr.metric_attributions) == 0


# 7. Multiple metrics / identical sources
def test_multiple_metrics_same_source(
    engine, base_categories, base_metrics, base_gates
):
    base_metrics["sec_metric"] = dataclasses.replace(
        base_metrics["sec_metric"], source="osv"
    )
    base_metrics["int_metric"] = dataclasses.replace(
        base_metrics["int_metric"], source="osv"
    )
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert all(m.source == "osv" for m in attr.metric_attributions)


# 8. Precision / Output structure
def test_rounding_precision(engine, base_categories, base_metrics, base_gates):
    base_categories["security"] = dataclasses.replace(
        base_categories["security"], contribution=32.123456
    )
    base_metrics["sec_metric"] = dataclasses.replace(
        base_metrics["sec_metric"], contribution=54.987654, normalized_value=0.912345
    )
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert attr.category_contributions["security"] == 32.12
    m_attr = next(m for m in attr.metric_attributions if m.metric == "sec_metric")
    assert m_attr.metric_contribution == 54.99
    assert m_attr.normalized_value == 0.9123


def test_output_structure_fields(engine, base_categories, base_metrics, base_gates):
    attr = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert hasattr(attr, "category_contributions")
    assert hasattr(attr, "metric_attributions")
    assert hasattr(attr, "top_positive_signals")
    assert hasattr(attr, "top_negative_signals")
    assert hasattr(attr, "primary_recommendation")
    assert isinstance(attr.metric_attributions, tuple)
    assert isinstance(attr.top_positive_signals, tuple)


def test_deterministic_generation(engine, base_categories, base_metrics, base_gates):
    attr1 = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    attr2 = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )
    assert attr1 == attr2


# 9. Realistic scenarios
def test_realistic_attribution_scenario(engine, base_categories, base_metrics):
    base_metrics["sc_metric"] = MetricResult(
        metric_name="sc_metric",
        raw_value=1,
        normalized_value=0.1,
        weight=0.5,
        contribution=5.0,
        status=MetricStatus.AVAILABLE,
        source="npm",
        confidence=1.0,
        explanation="Bad supply chain",
    )
    gates = [
        GateResult(
            gate_id="GATE-TEST", triggered=False, severity=GateSeverity.NONE, reason=""
        )
    ]

    attr = engine.generate(
        base_categories, base_metrics, gates, 40.0, RiskLevel.HIGH, Decision.WARN
    )

    assert "security" in attr.category_contributions
    assert len(attr.metric_attributions) == 3
    assert len(attr.top_positive_signals) > 0
    assert len(attr.top_negative_signals) > 0
    assert "Review package findings" in attr.primary_recommendation


def test_unrelated_metric_change_does_not_affect_attribution(
    engine, base_categories, base_metrics, base_gates
):
    attr1 = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )

    # Add an unrelated metric
    base_metrics["other_metric"] = MetricResult(
        metric_name="other_metric",
        raw_value=1,
        normalized_value=1.0,
        weight=0.0,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    attr2 = engine.generate(
        base_categories, base_metrics, base_gates, 75.0, RiskLevel.LOW, Decision.ALLOW
    )

    m_attr1 = next(m for m in attr1.metric_attributions if m.metric == "sec_metric")
    m_attr2 = next(m for m in attr2.metric_attributions if m.metric == "sec_metric")
    assert m_attr1 == m_attr2
