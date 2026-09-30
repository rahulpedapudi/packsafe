from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum


class EvidenceStatus(str, Enum):
    """Status of an evidence subsystem or collector."""

    AVAILABLE = "AVAILABLE"
    MISSING = "MISSING"
    STALE = "STALE"
    INVALID = "INVALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"


@dataclass(frozen=True)
class EvidenceProvenance:
    """Audit trail for an evidence component."""

    source: str
    source_url: str
    retrieved_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    archive_sha256: str | None = None
    collector_version: str = "1.0.0"
