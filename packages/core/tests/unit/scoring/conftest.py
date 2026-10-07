import pytest
from packages.core.scoring.config import EngineConfig
from packages.core.models.scoring import MetricDefinition

@pytest.fixture
def mock_config():
    metrics_def = {
        "sec_metric": MetricDefinition(
            name="sec_metric", category="security", weight=0.6, direction="positive",
            normalization="linear", normalization_params={}, required_evidence=(),
            missing_policy="exclude", stale_policy="penalize_confidence",
            affects_categories=("security",), explanation_template=""
        ),
        "int_metric": MetricDefinition(
            name="int_metric", category="integrity", weight=0.4, direction="positive",
            normalization="linear", normalization_params={}, required_evidence=(),
            missing_policy="exclude", stale_policy="penalize_confidence",
            affects_categories=("integrity",), explanation_template=""
        ),
        "sc_metric": MetricDefinition(
            name="sc_metric", category="supply_chain", weight=0.5, direction="positive",
            normalization="linear", normalization_params={}, required_evidence=(),
            missing_policy="exclude", stale_policy="penalize_confidence",
            affects_categories=("supply_chain",), explanation_template=""
        ),
        "maint_metric": MetricDefinition(
            name="maint_metric", category="maintenance", weight=0.3, direction="positive",
            normalization="linear", normalization_params={}, required_evidence=(),
            missing_policy="exclude", stale_policy="penalize_confidence",
            affects_categories=("maintenance",), explanation_template=""
        ),
        "adopt_metric": MetricDefinition(
            name="adopt_metric", category="adoption", weight=0.2, direction="positive",
            normalization="linear", normalization_params={}, required_evidence=(),
            missing_policy="exclude", stale_policy="penalize_confidence",
            affects_categories=("adoption",), explanation_template=""
        ),
    }

    return EngineConfig(
        engine_version="1.0.0",
        config_version="1.0",
        config_sha256="abc",
        category_weights={
            "security": 0.4,
            "integrity": 0.2,
            "supply_chain": 0.2,
            "maintenance": 0.1,
            "adoption": 0.1
        },
        metrics=metrics_def,
        normalization={},
        gates=[
            {"id": "GATE-MALWARE", "priority": 1, "score_floor": 0.0, "min_confidence": 0.85},
            {"id": "GATE-ACTIVE-CRITICAL", "priority": 2, "score_floor": 0.0},
            {"id": "GATE-CREDENTIAL-THEFT", "priority": 3, "score_floor": 0.0, "min_confidence": 0.85},
            {"id": "GATE-REMOTE-EXEC", "priority": 4, "score_floor": 0.0, "min_confidence": 0.85},
            {"id": "GATE-INSTALL-MALWARE", "priority": 5, "score_floor": 0.0, "min_confidence": 0.85},
            {"id": "GATE-SUSPICIOUS-WARN", "priority": 6, "score_floor": None, "min_confidence": 0.85},
        ],
        profiles={},
        sources={"heuristic": 0.8, "npm": 0.9, "osv": 1.0},
        analysis_coverage_tiers={"deep_static": 1.0, "metadata_only": 0.5},
        freshness_ttls={}
    )
