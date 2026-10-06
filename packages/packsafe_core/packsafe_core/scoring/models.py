"""Core scoring domain models, enums, and dataclasses for the PackSafe Score Engine."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal


class RiskLevel(str, Enum):
    """Overall security risk level."""
    SAFE = "SAFE"
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Decision(str, Enum):
    """Actionable decision from the policy evaluation."""
    ALLOW = "ALLOW"
    WARN = "WARN"
    BLOCK = "BLOCK"
    REVIEW = "REVIEW"


class EvidenceStatus(str, Enum):
    """Status of an evidence subsystem or collector."""
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class MetricStatus(str, Enum):
    """Status of evidence for a specific metric."""
    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class GateSeverity(str, Enum):
    """Severity tier of a security gate."""
    NONE = "none"
    WARNING = "warning"
    HIGH = "high"
    CRITICAL = "critical"


class SeverityRank(int, Enum):
    """Numeric severity rank for strict comparison."""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str | None) -> SeverityRank:
        if not s:
            return cls.NONE
        norm = s.strip().upper()
        if norm in ("CRIT", "CRITICAL"):
            return cls.CRITICAL
        elif norm in ("HIGH", "H"):
            return cls.HIGH
        elif norm in ("MED", "MEDIUM", "MODERATE"):
            return cls.MEDIUM
        elif norm in ("LOW", "L"):
            return cls.LOW
        return cls.NONE


from types import MappingProxyType
from typing import Any, Literal, Mapping


@dataclass(frozen=True)
class MetricDefinition:
    """Definition and configuration for a scoring metric."""
    name: str
    category: str
    weight: float
    direction: Literal["positive", "negative"]
    normalization: str
    normalization_params: Mapping[str, Any]
    required_evidence: tuple[str, ...]
    missing_policy: Literal["exclude", "penalty", "neutral"]
    stale_policy: Literal["penalize_confidence", "mark_missing"]
    affects_categories: tuple[str, ...]
    explanation_template: str

    def __post_init__(self) -> None:
        if isinstance(self.normalization_params, dict):
            object.__setattr__(self, "normalization_params", MappingProxyType(self.normalization_params))


@dataclass(frozen=True)
class MetricEvidence:
    """Raw evidence collected for an individual metric."""
    metric_name: str
    raw_value: Any
    status: MetricStatus = MetricStatus.AVAILABLE
    source: str = "heuristic"
    collected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    notes: str = ""


@dataclass(frozen=True)
class MetricResult:
    """Calculated metric evaluation result."""
    metric_name: str
    raw_value: Any
    normalized_value: float | None
    weight: float
    contribution: float
    status: MetricStatus
    source: str
    confidence: float
    explanation: str


@dataclass(frozen=True)
class CategoryScore:
    """Category aggregate score."""
    name: str
    score: float
    weight: float
    contribution: float
    metrics: tuple[MetricResult, ...] = ()
    available_weight: float = 0.0
    total_applicable_weight: float = 0.0
    status: MetricStatus = MetricStatus.AVAILABLE


@dataclass(frozen=True)
class Finding:
    """Security or integrity finding produced by static analysis or advisories."""
    finding_id: str
    category: str
    severity: str
    confidence: float
    title: str
    description: str
    evidence: str
    source: str
    affected_version: str | None = None
    affects_categories: tuple[str, ...] = ("integrity",)
    score_penalty: float = 0.0
    gate_triggered: str | None = None
    aliases: tuple[str, ...] = ()
    risk: float = 0.0
    source_severities: tuple[tuple[str, str], ...] = ()
    severity_resolution: str = "MAX_SOURCE_SEVERITY"


@dataclass(frozen=True)
class GateResult:
    """Outcome of evaluating an individual security gate."""
    gate_id: str
    triggered: bool
    severity: GateSeverity
    reason: str
    decision_override: Decision | None = None
    score_floor: float | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class MetricAttribution:
    """Attribution item explaining an individual metric's effect."""
    category: str
    metric: str
    raw_value: Any
    normalized_value: float | None
    metric_weight: float
    metric_contribution: float
    category_weight: float
    source: str
    evidence_status: str
    confidence: float
    explanation: str


@dataclass(frozen=True)
class ScoreAttribution:
    """Comprehensive explanation and attribution of the final score."""
    category_contributions: Mapping[str, float]
    metric_attributions: tuple[MetricAttribution, ...]
    top_positive_signals: tuple[str, ...]
    top_negative_signals: tuple[str, ...]
    primary_recommendation: str

    def __post_init__(self) -> None:
        if isinstance(self.category_contributions, dict):
            object.__setattr__(self, "category_contributions", MappingProxyType(self.category_contributions))


@dataclass(frozen=True)
class ScoreResult:
    """Immutable, strongly-typed result of the ScoreEngine calculation."""
    package_name: str
    ecosystem: str
    version: str

    final_score: float
    base_score: float

    risk_level: RiskLevel
    decision: Decision

    confidence: float

    categories: Mapping[str, CategoryScore]
    findings: tuple[Finding, ...]
    gates: tuple[GateResult, ...]
    attribution: ScoreAttribution

    analyzed_at: datetime
    engine_version: str
    config_version: str
    config_sha256: str
    score_risk_level: RiskLevel = RiskLevel.SAFE
    vulnerability_risk_level: RiskLevel = RiskLevel.SAFE
    evidence_coverage_summary: Mapping[str, int] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.categories, dict):
            object.__setattr__(self, "categories", MappingProxyType(self.categories))
        if isinstance(self.evidence_coverage_summary, dict):
            object.__setattr__(self, "evidence_coverage_summary", MappingProxyType(self.evidence_coverage_summary))
