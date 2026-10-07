import pytest
from packsafe_core.models.scoring import CategoryScore, MetricResult, MetricStatus
from packsafe_core.scoring.categories.engine import CategoryScoringEngine


# Fixtures for shared components
@pytest.fixture
def engine(mock_config):
    return CategoryScoringEngine(mock_config)


@pytest.fixture
def sec_metrics():
    return [
        MetricResult(
            metric_name="sec_metric",
            raw_value=1,
            normalized_value=0.5,
            weight=0.6,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="heuristic",
            confidence=1.0,
            explanation="",
        )
    ]


# CAT-001 — Engine instantiation
def test_engine_instantiation(engine, mock_config):
    assert engine.config == mock_config
    assert isinstance(engine, CategoryScoringEngine)


# CAT-002 — Valid complete input
def test_valid_complete_input(engine):
    m = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.8,
        weight=1.0,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_all({"sec_metric": m})
    assert "security" in res
    assert isinstance(res["security"], CategoryScore)


# CAT-003 — Security category calculation
def test_security_category_calculation(engine, sec_metrics):
    sec_metrics[0] = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.75,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", sec_metrics)
    assert res.score == pytest.approx(75.0)


# CAT-004 — Integrity category calculation
def test_integrity_category_calculation(engine):
    m = [
        MetricResult(
            metric_name="int_metric",
            raw_value=1,
            normalized_value=0.5,
            weight=0.4,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        )
    ]
    res = engine.calculate_category("integrity", m)
    assert res.score == pytest.approx(50.0)


# CAT-005 — Supply Chain category calculation
def test_supply_chain_category_calculation(engine):
    m = [
        MetricResult(
            metric_name="sc_metric",
            raw_value=1,
            normalized_value=0.9,
            weight=0.5,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        )
    ]
    res = engine.calculate_category("supply_chain", m)
    assert res.score == pytest.approx(90.0)


# CAT-006 — Maintenance category calculation
def test_maintenance_category_calculation(engine):
    m = [
        MetricResult(
            metric_name="maint_metric",
            raw_value=1,
            normalized_value=0.3,
            weight=0.3,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        )
    ]
    res = engine.calculate_category("maintenance", m)
    assert res.score == pytest.approx(30.0)


# CAT-007 — Adoption category calculation
def test_adoption_category_calculation(engine):
    m = [
        MetricResult(
            metric_name="adopt_metric",
            raw_value=1,
            normalized_value=0.1,
            weight=0.2,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        )
    ]
    res = engine.calculate_category("adoption", m)
    assert res.score == pytest.approx(10.0)


# CAT-008 — All expected categories returned
def test_all_expected_categories_returned(engine):
    res = engine.calculate_all({})
    expected_categories = {
        "security",
        "integrity",
        "supply_chain",
        "maintenance",
        "adoption",
    }
    assert set(res.keys()) == expected_categories


# CAT-009 — Correct metric-to-category mapping
def test_correct_metric_to_category_mapping(engine):
    m = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.5,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_all({"sec_metric": m})
    assert res["security"].status == MetricStatus.AVAILABLE
    assert res["integrity"].status == MetricStatus.MISSING


# CAT-010 to CAT-014 — Weight calculation
@pytest.mark.parametrize(
    "cat_name, metric_name, weight1, norm1, weight2, norm2, expected_score",
    [
        ("security", "sec_metric", 0.6, 0.8, 0.4, 0.2, 56.0),
        ("integrity", "int_metric", 0.4, 0.5, 0.6, 0.5, 50.0),
        ("supply_chain", "sc_metric", 0.5, 0.9, 0.5, 0.1, 50.0),
        ("maintenance", "maint_metric", 0.3, 0.3, 0.7, 0.0, 9.0),
        ("adoption", "adopt_metric", 0.2, 0.1, 0.8, 0.9, 74.0),
    ],
)
def test_weight_calculation(
    engine, cat_name, metric_name, weight1, norm1, weight2, norm2, expected_score
):
    m1 = MetricResult(
        metric_name=metric_name,
        raw_value=1,
        normalized_value=norm1,
        weight=weight1,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    m2 = MetricResult(
        metric_name=f"{metric_name}_2",
        raw_value=1,
        normalized_value=norm2,
        weight=weight2,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category(cat_name, [m1, m2])
    assert res.score == pytest.approx(expected_score)


# CAT-015 — All normalized metrics at minimum
def test_all_normalized_metrics_at_minimum(engine, sec_metrics):
    sec_metrics[0] = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.0,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", sec_metrics)
    assert res.score == 0.0


# CAT-016 — All normalized metrics at maximum
def test_all_normalized_metrics_at_maximum(engine, sec_metrics):
    sec_metrics[0] = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=1.0,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", sec_metrics)
    assert res.score == 100.0


# CAT-017 — All metrics at middle value
def test_all_metrics_at_middle_value(engine, sec_metrics):
    sec_metrics[0] = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.5,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", sec_metrics)
    assert res.score == 50.0


# CAT-018 — One metric changes
def test_one_metric_changes(engine):
    m1 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.5,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    m2_base = MetricResult(
        metric_name="sec_metric_2",
        raw_value=1,
        normalized_value=0.5,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res1 = engine.calculate_category("security", [m1, m2_base])

    m2_changed = MetricResult(
        metric_name="sec_metric_2",
        raw_value=1,
        normalized_value=1.0,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res2 = engine.calculate_category("security", [m1, m2_changed])
    assert res2.score > res1.score


# CAT-019, CAT-020 — High/Low-weight metric impact
def test_weight_impact_comparisons(engine):
    m_high = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=1.0,
        weight=0.9,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    m_low = MetricResult(
        metric_name="sec_metric_2",
        raw_value=1,
        normalized_value=0.0,
        weight=0.1,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m_high, m_low])
    assert res.score == 90.0


# CAT-021 — Zero metric value
def test_zero_metric_value(engine, sec_metrics):
    sec_metrics[0] = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.0,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", sec_metrics)
    assert res.score == 0.0
    assert res.status == MetricStatus.AVAILABLE


# CAT-022, CAT-023 — Missing metric
def test_missing_metric_behavior(engine):
    m1 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.8,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    m2 = MetricResult(
        metric_name="sec_metric_2",
        raw_value=1,
        normalized_value=None,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.MISSING,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m1, m2])
    # Total available weight is 0.5, weighted sum is 0.8 * 0.5, score = 80.0
    assert res.score == 80.0
    assert res.available_weight == 0.5


# CAT-024 — All metrics missing
def test_all_metrics_missing(engine):
    m1 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=None,
        weight=0.5,
        contribution=0.0,
        status=MetricStatus.MISSING,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m1])
    assert res.score == 0.0
    assert res.status == MetricStatus.MISSING


# CAT-025 — None metric value
def test_none_metric_value(engine):
    m1 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=None,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m1])
    assert res.score == 0.0
    assert res.status == MetricStatus.MISSING


# CAT-026 — Category score boundary
@pytest.mark.parametrize("norm_val", [-0.5, 1.5, 0.0, 1.0])
def test_category_score_boundary(engine, norm_val):
    m = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=norm_val,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m])
    assert 0.0 <= res.score <= 100.0


# CAT-027 — Deterministic calculation
def test_deterministic_calculation(engine, sec_metrics):
    res1 = engine.calculate_category("security", sec_metrics)
    res2 = engine.calculate_category("security", sec_metrics)
    assert res1.score == res2.score
    assert res1.contribution == res2.contribution


# CAT-028 — Different input produces different result
def test_different_input_produces_different_result(engine):
    m1 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.5,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    m2 = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.9,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    assert (
        engine.calculate_category("security", [m1]).score
        != engine.calculate_category("security", [m2]).score
    )


# CAT-029 — Positive metric direction
def test_positive_metric_direction(engine):
    res_low = engine.calculate_category(
        "security",
        [
            MetricResult(
                metric_name="sec_metric",
                raw_value=1,
                normalized_value=0.2,
                weight=0.6,
                contribution=0.0,
                status=MetricStatus.AVAILABLE,
                source="",
                confidence=1.0,
                explanation="",
            )
        ],
    )
    res_high = engine.calculate_category(
        "security",
        [
            MetricResult(
                metric_name="sec_metric",
                raw_value=1,
                normalized_value=0.8,
                weight=0.6,
                contribution=0.0,
                status=MetricStatus.AVAILABLE,
                source="",
                confidence=1.0,
                explanation="",
            )
        ],
    )
    assert res_high.score > res_low.score


# CAT-030 — Negative/bad metric direction
def test_negative_metric_direction_handling(engine):
    # Category engine just uses normalized value. We verify it doesn't double-invert it.
    res = engine.calculate_category(
        "security",
        [
            MetricResult(
                metric_name="sec_metric",
                raw_value=1,
                normalized_value=0.3,
                weight=0.6,
                contribution=0.0,
                status=MetricStatus.AVAILABLE,
                source="",
                confidence=1.0,
                explanation="",
            )
        ],
    )
    assert res.score == 30.0


# CAT-031, CAT-032 — Realistic package datasets
@pytest.mark.parametrize(
    "pkg_metrics, expected_valid",
    [
        (
            {
                "sec_metric": MetricResult(
                    metric_name="sec_metric",
                    raw_value=1,
                    normalized_value=0.8,
                    weight=1.0,
                    contribution=0.0,
                    status=MetricStatus.AVAILABLE,
                    source="",
                    confidence=1.0,
                    explanation="",
                )
            },
            True,
        ),
        ({}, False),
    ],
)
def test_realistic_package_datasets(engine, pkg_metrics, expected_valid):
    res = engine.calculate_all(pkg_metrics)
    assert "security" in res
    if expected_valid:
        assert res["security"].status == MetricStatus.AVAILABLE
    else:
        assert res["security"].status == MetricStatus.MISSING


# CAT-033 — Result structure
def test_result_structure(engine, sec_metrics):
    res = engine.calculate_category("security", sec_metrics)
    assert hasattr(res, "name")
    assert hasattr(res, "score")
    assert hasattr(res, "weight")
    assert hasattr(res, "contribution")
    assert hasattr(res, "metrics")
    assert hasattr(res, "available_weight")
    assert hasattr(res, "status")
    assert res.name == "security"


# CAT-034 — Category calculation consistency
def test_category_calculation_consistency(engine):
    m = MetricResult(
        metric_name="sec_metric",
        raw_value=1,
        normalized_value=0.5,
        weight=0.6,
        contribution=0.0,
        status=MetricStatus.AVAILABLE,
        source="",
        confidence=1.0,
        explanation="",
    )
    res = engine.calculate_category("security", [m])
    assert res.metrics[0].contribution == 50.0
    assert res.contribution == res.score * engine.config.category_weights["security"]


# CAT-035 — Complete category engine scenario
def test_complete_category_engine_scenario(engine):
    all_metrics = {
        "sec_metric": MetricResult(
            metric_name="sec_metric",
            raw_value=1,
            normalized_value=0.9,
            weight=0.6,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        ),
        "int_metric": MetricResult(
            metric_name="int_metric",
            raw_value=1,
            normalized_value=0.8,
            weight=0.4,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        ),
        "sc_metric": MetricResult(
            metric_name="sc_metric",
            raw_value=1,
            normalized_value=0.7,
            weight=0.5,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        ),
        "maint_metric": MetricResult(
            metric_name="maint_metric",
            raw_value=1,
            normalized_value=None,
            weight=0.3,
            contribution=0.0,
            status=MetricStatus.MISSING,
            source="",
            confidence=1.0,
            explanation="",
        ),
        "adopt_metric": MetricResult(
            metric_name="adopt_metric",
            raw_value=1,
            normalized_value=0.5,
            weight=0.2,
            contribution=0.0,
            status=MetricStatus.AVAILABLE,
            source="",
            confidence=1.0,
            explanation="",
        ),
    }
    res = engine.calculate_all(all_metrics)

    assert res["security"].score == pytest.approx(90.0)
    assert res["integrity"].score == pytest.approx(80.0)
    assert res["supply_chain"].score == pytest.approx(70.0)
    assert res["maintenance"].score == pytest.approx(0.0)
    assert res["maintenance"].status == MetricStatus.MISSING
    assert res["adoption"].score == pytest.approx(50.0)
