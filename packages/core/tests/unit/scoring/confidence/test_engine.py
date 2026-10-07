import pytest
import dataclasses
from packages.core.scoring.confidence.engine import ConfidenceEngine
from packages.core.models.scoring import MetricResult, MetricStatus
from packages.core.pipeline.context import AnalysisContext

@pytest.fixture
def engine(mock_config):
    return ConfidenceEngine(mock_config)

@pytest.fixture
def base_evidence():
    class DummyContext:
        analysis_coverage_tier = "deep_static"
    return DummyContext()

@pytest.fixture
def all_available_metrics():
    return {
        "sec_metric": MetricResult(metric_name="sec_metric", raw_value=1, normalized_value=1.0, weight=0.6, contribution=0.0, status=MetricStatus.AVAILABLE, source="osv", confidence=1.0, explanation=""),
        "int_metric": MetricResult(metric_name="int_metric", raw_value=1, normalized_value=1.0, weight=0.4, contribution=0.0, status=MetricStatus.AVAILABLE, source="osv", confidence=1.0, explanation=""),
        "sc_metric": MetricResult(metric_name="sc_metric", raw_value=1, normalized_value=1.0, weight=0.5, contribution=0.0, status=MetricStatus.AVAILABLE, source="osv", confidence=1.0, explanation=""),
        "maint_metric": MetricResult(metric_name="maint_metric", raw_value=1, normalized_value=1.0, weight=0.3, contribution=0.0, status=MetricStatus.AVAILABLE, source="osv", confidence=1.0, explanation=""),
        "adopt_metric": MetricResult(metric_name="adopt_metric", raw_value=1, normalized_value=1.0, weight=0.2, contribution=0.0, status=MetricStatus.AVAILABLE, source="osv", confidence=1.0, explanation="")
    }

# 1. Engine initialization
def test_engine_instantiation(engine, mock_config):
    assert engine.config == mock_config
    assert isinstance(engine, ConfidenceEngine)

# 2. Normal confidence calculation
def test_valid_complete_evidence(engine, base_evidence, all_available_metrics):
    # Coverage=1.0, Reliability(osv)=1.0, Analysis=1.0
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 100.0

def test_heuristic_source_reliability(engine, base_evidence, all_available_metrics):
    for k, m in all_available_metrics.items():
        all_available_metrics[k] = dataclasses.replace(m, source="heuristic") # 0.8
    # Coverage=1.0, Reliability=0.8, Analysis=1.0
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 80.0

# 3. Confidence boundaries
def test_minimum_confidence_boundary(engine, base_evidence):
    # All metrics missing => coverage = 0.0 => conf = 0.0
    metrics = {
        "sec_metric": MetricResult(metric_name="sec_metric", raw_value=None, normalized_value=None, weight=0.6, contribution=0.0, status=MetricStatus.MISSING, source="osv", confidence=1.0, explanation="")
    }
    conf = engine.calculate(base_evidence, metrics)
    assert conf == 0.0

def test_maximum_confidence_boundary(engine, base_evidence, all_available_metrics):
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 100.0

def test_clamping_behavior(engine, base_evidence, all_available_metrics):
    # Simulate a scenario where config somehow causes > 100% (e.g. source rel > 1.0)
    for k, m in all_available_metrics.items():
        all_available_metrics[k] = dataclasses.replace(m, source="super_source")
    engine.config.sources["super_source"] = 1.5
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 100.0 # Clamped

# 4. Evidence quality / status
def test_unavailable_error_evidence(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], status=MetricStatus.INVALID, normalized_value=None)
    # Security cat coverage becomes 0.
    # Base coverage without security = 0.6. Reliability(osv)=1.0, Analysis=1.0. 100 * 0.6 = 60.0
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 60.0

def test_stale_evidence_behavior(engine, base_evidence, all_available_metrics):
    for k, m in all_available_metrics.items():
        all_available_metrics[k] = dataclasses.replace(m, source="heuristic") # Base reliability 0.8
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], status=MetricStatus.STALE)
    
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == pytest.approx(51.68)

def test_partially_available_evidence(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], status=MetricStatus.MISSING, normalized_value=None)
    all_available_metrics["int_metric"] = dataclasses.replace(all_available_metrics["int_metric"], status=MetricStatus.MISSING, normalized_value=None)
    
    # Missing sec and int. Coverage = 0.2 + 0.1 + 0.1 = 0.4.
    # Reliability = 1.0.
    # Conf = 40.0.
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 40.0

# 5. Missing / None / partial evidence
def test_missing_evidence_behavior(engine, base_evidence):
    conf = engine.calculate(base_evidence, {})
    assert conf == 0.0

def test_none_evidence_behavior(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], normalized_value=None)
    conf = engine.calculate(base_evidence, all_available_metrics)
    # Treated same as missing
    assert conf == 60.0

def test_not_applicable_evidence_filtered(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], status=MetricStatus.NOT_APPLICABLE)
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 60.0

# 6. Aggregation / weighting
def test_analysis_coverage_tier(engine, base_evidence, all_available_metrics):
    base_evidence.analysis_coverage_tier = "metadata_only" # maps to 0.5
    conf = engine.calculate(base_evidence, all_available_metrics)
    # 100 * 1.0 * 1.0 * 0.5 = 50.0
    assert conf == 50.0

def test_unknown_analysis_coverage_tier(engine, base_evidence, all_available_metrics):
    base_evidence.analysis_coverage_tier = "unknown_tier" # Defaults to 1.0
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 100.0

def test_source_priority_weighting(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], source="npm") # 0.9
    all_available_metrics["int_metric"] = dataclasses.replace(all_available_metrics["int_metric"], source="osv") # 1.0
    all_available_metrics["sc_metric"] = dataclasses.replace(all_available_metrics["sc_metric"], source="heuristic") # 0.8
    # weight mapping: sec(0.6), int(0.4), sc(0.5), maint(0.3), adopt(0.2)
    # Total available weight = 2.0
    # Rel = (0.6*0.9 + 0.4*1.0 + 0.5*0.8 + 0.3*1.0 + 0.2*1.0) / 2.0 = (0.54 + 0.40 + 0.40 + 0.30 + 0.20) / 2.0 = 1.84 / 2.0 = 0.92
    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == 92.0

# 7. Precision / output structure
def test_confidence_rounding(engine, base_evidence, all_available_metrics):
    # Tweak weights to produce a non-round float
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], source="npm")
    engine.config.sources["npm"] = 0.9333333333
    conf = engine.calculate(base_evidence, all_available_metrics)
    # Ensure it's a rounded float
    assert isinstance(conf, float)
    assert len(str(conf).split('.')[-1]) <= 2

def test_deterministic_calculation(engine, base_evidence, all_available_metrics):
    conf1 = engine.calculate(base_evidence, all_available_metrics)
    conf2 = engine.calculate(base_evidence, all_available_metrics)
    assert conf1 == conf2

# 8. Real fixture scenarios
@pytest.mark.parametrize("status, source, expected_conf", [
    (MetricStatus.AVAILABLE, "osv", 100.0),
    (MetricStatus.STALE, "osv", 50.0),
    (MetricStatus.MISSING, "osv", 0.0),
])
def test_single_metric_scenario(engine, base_evidence, status, source, expected_conf):
    metrics = {
        "sec_metric": MetricResult(metric_name="sec_metric", raw_value=1, normalized_value=1.0 if status != MetricStatus.MISSING else None, weight=0.6, contribution=0.0, status=status, source=source, confidence=1.0, explanation="")
    }
    # Note: sec_metric belongs to 'security', cat_w=0.4.
    conf = engine.calculate(base_evidence, metrics)
    if status == MetricStatus.AVAILABLE:
        assert conf == 40.0
    elif status == MetricStatus.STALE:
        assert conf == pytest.approx(8.0)
    else:
        assert conf == 0.0

def test_different_evidence_quality_produces_different_confidence(engine, base_evidence, all_available_metrics):
    conf_high = engine.calculate(base_evidence, all_available_metrics)
    
    for k, m in all_available_metrics.items():
        all_available_metrics[k] = dataclasses.replace(m, source="heuristic")
    conf_med = engine.calculate(base_evidence, all_available_metrics)
    
    for k, m in all_available_metrics.items():
        all_available_metrics[k] = dataclasses.replace(m, status=MetricStatus.STALE)
    conf_low = engine.calculate(base_evidence, all_available_metrics)
    
    assert conf_high > conf_med > conf_low

# 9. Complete realistic scenarios
def test_realistic_scenario(engine, base_evidence, all_available_metrics):
    all_available_metrics["sec_metric"] = dataclasses.replace(all_available_metrics["sec_metric"], source="osv")
    all_available_metrics["int_metric"] = dataclasses.replace(all_available_metrics["int_metric"], source="heuristic")
    all_available_metrics["sc_metric"] = dataclasses.replace(all_available_metrics["sc_metric"], status=MetricStatus.MISSING, normalized_value=None)
    all_available_metrics["maint_metric"] = dataclasses.replace(all_available_metrics["maint_metric"], status=MetricStatus.STALE, source="npm")
    all_available_metrics["adopt_metric"] = dataclasses.replace(all_available_metrics["adopt_metric"], source="npm")

    conf = engine.calculate(base_evidence, all_available_metrics)
    assert conf == pytest.approx(60.93)
