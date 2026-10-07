"""Shared visual language for PackSafe CLI output.

Icons, colors and value formatters live here so every command reports risk the same
way: one icon always means one verdict, and the same quantity is always formatted the
same number of digits deep.
"""

from __future__ import annotations

from dataclasses import dataclass

from packsafe_core.models.scoring import Decision, GateSeverity, RiskLevel


@dataclass(frozen=True)
class CheckState:
    """How a single check reads at a glance: its icon and its color.

    A check is either clean, worth noticing, actively bad, or was never measured. The
    unknown state is deliberately distinct from a passing one: "we did not look" must
    not render like "we looked and it was fine".
    """

    icon: str
    style: str


OK = CheckState(icon="✓", style="green")
WARN = CheckState(icon="!", style="yellow")
RISK = CheckState(icon="✗", style="red")
UNKNOWN = CheckState(icon="?", style="bright_black")


@dataclass(frozen=True)
class CheckRow:
    """One line of the checks block: what was examined, what it found, how bad."""

    label: str
    detail: str
    state: CheckState


RISK_STYLE = {
    RiskLevel.SAFE: "bold green",
    RiskLevel.LOW: "green",
    RiskLevel.MODERATE: "yellow",
    RiskLevel.HIGH: "bold red",
    RiskLevel.CRITICAL: "bold red",
}

RISK_WORD = {
    RiskLevel.SAFE: "SAFE RISK",
    RiskLevel.LOW: "LOW RISK",
    RiskLevel.MODERATE: "MODERATE RISK",
    RiskLevel.HIGH: "HIGH RISK",
    RiskLevel.CRITICAL: "CRITICAL RISK",
}

DECISION_STYLE = {
    Decision.ALLOW: "bold green",
    Decision.WARN: "bold yellow",
    Decision.REVIEW: "bold yellow",
    Decision.BLOCK: "bold red",
}

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "MODERATE": "yellow",
    "LOW": "cyan",
    "INFO": "bright_black",
}

GATE_SEVERITY_STYLE = {
    GateSeverity.CRITICAL: "red",
    GateSeverity.HIGH: "red",
    GateSeverity.WARNING: "yellow",
}

# How each evidence-subsystem status reads. A collector that never ran must not look
# like one that ran and found nothing.
STATUS_STYLE = {
    "AVAILABLE": "green",
    "MISSING": "yellow",
    "STALE": "yellow",
    "INVALID": "red",
    "NOT_APPLICABLE": "bright_black",
}

FIELD_LABEL_STYLE = "bright_black"
FIELD_VALUE_STYLE = ""

# Severity buckets in the order they should always be counted and printed: worst first.
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

# Section rules are deliberately quiet: the risk content is the loud part.
RULE_STYLE = "grey35"
SECTION_TITLE = "bold white"
LABEL_STYLE = "bold"


def human_int(value: int | None) -> str:
    """Abbreviates a count the way a human would say it: 3212 -> ``3.2k``."""
    if value is None:
        return "unknown"
    magnitude = abs(value)
    if magnitude < 1000:
        return f"{value:,}"
    if magnitude < 1_000_000:
        return f"{value / 1000:.1f}k".replace(".0k", "k")
    return f"{value / 1_000_000:.1f}M".replace(".0M", "M")


def human_days(days: int | None) -> str:
    """Renders an age in the largest unit that stays legible: 1460 -> ``4y``."""
    if days is None:
        return "unknown"
    if days <= 0:
        return "today"
    if days < 45:
        return f"{days}d"
    months = days // 30
    if months < 24:
        return f"{months}mo"
    years, remainder = divmod(months, 12)
    return f"{years}y" if not remainder else f"{years}y {remainder}mo"


def short_url(url: str | None) -> str:
    """Strips transport noise off a repository URL so it fits in a table cell."""
    if not url:
        return "unknown"
    cleaned = url.strip().rstrip("/")
    for prefix in ("git+https://", "git+http://", "https://", "http://"):
        if cleaned.startswith(prefix):
            cleaned = cleaned[len(prefix) :]
            break
    return cleaned.removesuffix(".git")


def short_hash(digest: str | None, length: int = 12) -> str:
    """Truncates a sha256 for display, never inventing a value it does not have."""
    if not digest:
        return "unknown"
    return digest[:length]


def plural(count: int, noun: str, plural_form: str | None = None) -> str:
    """``plural(3, "advisory", "advisories")`` -> ``3 advisories``."""
    if count == 1:
        return f"{count} {noun}"
    return f"{count} {plural_form or noun + 's'}"
