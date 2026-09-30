"""Evidence Freshness evaluation and TTL enforcement."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
import yaml
from pathlib import Path

from packsafe.evidence.models import EvidenceStatus


class FreshnessEvaluator:
    """Evaluates whether an evidence record is fresh or stale based on configured TTLs."""

    DEFAULT_TTL_HOURS = {
        "osv": 6,
        "registry": 24,
        "github": 24,
        "downloads": 24,
        "deps_dev": 12,
        "identity": 24,
        "static_analysis": None,  # Immutable by archive SHA-256
    }

    def __init__(self, config_path: Path | None = None) -> None:
        self.ttls: dict[str, int | None] = dict(self.DEFAULT_TTL_HOURS)
        if config_path and config_path.exists():
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    data = yaml.safe_load(f) or {}
                    configured = data.get("freshness_ttl_hours", {})
                    self.ttls.update(configured)
            except Exception:
                pass

    def evaluate(self, evidence_type: str, retrieved_at: datetime | float) -> EvidenceStatus:
        """Determines if the evidence timestamp is AVAILABLE or STALE."""
        ttl_hours = self.ttls.get(evidence_type)
        if ttl_hours is None:
            return EvidenceStatus.AVAILABLE  # Immutable or no TTL

        now = datetime.now(timezone.utc)
        if isinstance(retrieved_at, (int, float)):
            retrieved_dt = datetime.fromtimestamp(retrieved_at, tz=timezone.utc)
        else:
            retrieved_dt = retrieved_at
            if retrieved_dt.tzinfo is None:
                retrieved_dt = retrieved_dt.replace(tzinfo=timezone.utc)

        age_hours = (now - retrieved_dt).total_seconds() / 3600.0
        if age_hours > ttl_hours:
            return EvidenceStatus.STALE

        return EvidenceStatus.AVAILABLE
