"""Configuration loader, validator, and integrity hasher for PackSafe."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..models.scoring import MetricDefinition

CONFIG_DIR = Path(__file__).parent / "config"

VALID_CATEGORIES = {
    "security",
    "integrity",
    "supply_chain",
    "maintenance",
    "adoption",
}


class ConfigValidationError(ValueError):
    """Raised when configuration fails schema or business invariant validation."""


@dataclass
class EngineConfig:
    """Consolidated validated configuration for the ScoreEngine."""

    engine_version: str
    config_version: str
    config_sha256: str
    category_weights: dict[str, float]
    metrics: dict[str, MetricDefinition]
    normalization: dict[str, Any]
    gates: list[dict[str, Any]]
    profiles: dict[str, Any]
    sources: dict[str, float]
    analysis_coverage_tiers: dict[str, float]
    freshness_ttls: dict[str, Any]


def compute_configs_sha256(config_dir: Path) -> str:
    """Computes a deterministic SHA-256 hash across all configuration YAML files."""
    hasher = hashlib.sha256()
    yaml_files = sorted(config_dir.glob("*.yaml"))
    for file_path in yaml_files:
        hasher.update(file_path.name.encode("utf-8"))
        hasher.update(file_path.read_bytes())
    return hasher.hexdigest()


def load_yaml(file_path: Path) -> dict[str, Any]:
    """Safely loads a YAML file."""
    if not file_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {file_path}")
    with open(file_path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    return data


def load_engine_config(config_dir: Path | None = None) -> EngineConfig:
    """Loads, validates, and hashes all PackSafe configurations."""
    dir_path = config_dir or CONFIG_DIR

    weights_data = load_yaml(dir_path / "weights.yaml")
    metrics_data = load_yaml(dir_path / "metrics.yaml")
    norm_data = load_yaml(dir_path / "normalization.yaml")
    gates_data = load_yaml(dir_path / "gates.yaml")
    profiles_data = load_yaml(dir_path / "profiles.yaml")
    sources_data = load_yaml(dir_path / "sources.yaml")
    freshness_data = load_yaml(dir_path / "freshness.yaml")

    config_sha256 = compute_configs_sha256(dir_path)

    # 1. Validate Category Weights
    category_weights = weights_data.get("categories", {})
    if not category_weights:
        raise ConfigValidationError(
            "weights.yaml must contain 'categories' dictionary."
        )

    for cat, weight in category_weights.items():
        if cat not in VALID_CATEGORIES:
            raise ConfigValidationError(f"Invalid category '{cat}' in weights.yaml.")
        if weight <= 0:
            raise ConfigValidationError(f"Category weight for '{cat}' must be > 0.")

    total_weight = sum(category_weights.values())
    if abs(total_weight - 1.0) > 1e-6:
        raise ConfigValidationError(
            f"Category weights must sum to 1.00, got {total_weight:.6f}"
        )

    # 2. Validate Metrics
    raw_metrics = metrics_data.get("metrics", [])
    if not raw_metrics:
        raise ConfigValidationError(
            "metrics.yaml must contain at least one metric definition."
        )

    metrics_dict: dict[str, MetricDefinition] = {}
    for m in raw_metrics:
        name = m.get("name")
        if not name:
            raise ConfigValidationError("Metric definition missing 'name'.")
        category = m.get("category")
        if category not in VALID_CATEGORIES:
            raise ConfigValidationError(
                f"Metric '{name}' has invalid category '{category}'."
            )
        weight = float(m.get("weight", 0))
        if weight <= 0:
            raise ConfigValidationError(f"Metric '{name}' weight must be > 0.")

        direction = m.get("direction")
        if direction not in ("positive", "negative"):
            raise ConfigValidationError(
                f"Metric '{name}' direction must be 'positive' or 'negative'."
            )

        normalization = m.get("normalization")
        norm_params = m.get("normalization_params", {}) or {}

        # Invariant: sigmoid is strictly restricted to direction == 'positive'
        if normalization == "sigmoid" and direction != "positive":
            raise ConfigValidationError(
                f"Metric '{name}' uses 'sigmoid' normalizer which is strictly restricted to positive-direction metrics."
            )

        # Validate scale parameter is positive if present
        if "scale" in norm_params and norm_params["scale"] <= 0:
            raise ConfigValidationError(
                f"Metric '{name}' normalization scale must be > 0."
            )

        metric_def = MetricDefinition(
            name=name,
            category=category,
            weight=weight,
            direction=direction,
            normalization=normalization,
            normalization_params=norm_params,
            required_evidence=tuple(m.get("required_evidence", [])),
            missing_policy=m.get("missing_policy", "exclude"),
            stale_policy=m.get("stale_policy", "penalize_confidence"),
            affects_categories=tuple(m.get("affects_categories", [category])),
            explanation_template=m.get("explanation_template", ""),
        )
        metrics_dict[name] = metric_def

    # 3. Validate Gates
    gates_list = gates_data.get("gates", [])
    seen_priorities = set()
    for g in gates_list:
        priority = g.get("priority")
        if priority in seen_priorities:
            raise ConfigValidationError(
                f"Duplicate gate priority {priority} in gates.yaml."
            )
        seen_priorities.add(priority)

    return EngineConfig(
        engine_version=weights_data.get("engine_version", "1.0.0"),
        config_version=weights_data.get("config_version", "2026-09-v1.2"),
        config_sha256=config_sha256,
        category_weights=category_weights,
        metrics=metrics_dict,
        normalization=norm_data,
        gates=sorted(gates_list, key=lambda x: x.get("priority", 99)),
        profiles=profiles_data.get("profiles", {}),
        sources=sources_data.get("source_reliability", {}),
        analysis_coverage_tiers=sources_data.get("analysis_coverage_tiers", {}),
        freshness_ttls=freshness_data.get("freshness_ttl_hours", {}),
    )
