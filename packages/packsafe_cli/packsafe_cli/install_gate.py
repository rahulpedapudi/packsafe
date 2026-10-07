"""The install gate: turns a score into a decision about whether to install.

Deliberately a pure function of the score. The command can then be tested against every
decision path without running a package manager, and the policy stays in one readable
place instead of being spread through the command's control flow.
"""

from __future__ import annotations

from dataclasses import dataclass

from packsafe_core.models.scoring import Decision, RiskLevel, ScoreResult, SeverityRank

# A score engine BLOCK is a hard veto. A CRITICAL risk level on its own is treated the
# same way: nothing that scores in the danger band gets installed on an automated path,
# whatever the gate engine happened to conclude.
BLOCKED_RISK_LEVELS = frozenset({RiskLevel.CRITICAL})


@dataclass(frozen=True)
class InstallGate:
    """The verdict on one package, plus the reason a human needs to see."""

    verdict: Decision
    reason: str
    blockers: tuple[str, ...] = ()

    @property
    def blocked(self) -> bool:
        return self.verdict is Decision.BLOCK

    @property
    def needs_confirmation(self) -> bool:
        """True when a human should decide, either interactively or via --yes."""
        return self.verdict in (Decision.WARN, Decision.REVIEW)


def evaluate(
    score: ScoreResult,
    *,
    min_score: float | None = None,
) -> InstallGate:
    """Decides whether a package may be installed.

    ``min_score`` is an optional extra floor for callers who want a stricter bar than the
    engine's own policy. It can only tighten the decision, never loosen it.
    """
    blockers: list[str] = []

    if score.risk_level in BLOCKED_RISK_LEVELS:
        blockers.append(f"risk level is {score.risk_level.value}")

    triggered = [g for g in score.gates if g.triggered]
    if any(g.severity.value == "critical" for g in triggered):
        blockers.extend(f"gate {g.gate_id}: {g.reason}" for g in triggered)

    if min_score is not None and score.final_score < min_score:
        blockers.append(
            f"score {score.final_score:.0f} is below the --min-score floor {min_score:.0f}"
        )

    if blockers:
        return InstallGate(
            Decision.BLOCK, "Blocked by PackSafe policy", tuple(blockers)
        )

    if score.decision is Decision.BLOCK:
        return InstallGate(
            Decision.BLOCK,
            "Blocked by PackSafe policy",
            tuple(f"gate {g.gate_id}: {g.reason}" for g in triggered)
            or ("policy decision is BLOCK",),
        )

    if score.decision is Decision.ALLOW:
        return InstallGate(Decision.ALLOW, "No blocking signals were found")

    # Worth naming the findings here rather than only in the reason: this list is what the
    # user reads while deciding whether to type yes.
    return InstallGate(
        score.decision,
        "Risks were found that need a human decision",
        tuple(_finding_reasons(score)),
    )


def _finding_reasons(score: ScoreResult) -> list[str]:
    """The findings worth naming in a confirmation prompt.

    The count matters as much as the worst entry: "1 risk factor" and "14 risk factors"
    deserve very different amounts of caution from someone typing yes. Falls back to the
    score itself when a warning carries no findings, so the prompt is never unexplained.
    """
    findings = score.findings
    if not findings:
        return [
            f"safety score {score.final_score:.0f}/100 with no clean bill of health"
        ]

    worst = max(findings, key=lambda f: SeverityRank.from_str(f.severity))
    reasons = [
        f"{len(findings)} risk factor(s), worst: {worst.severity} {worst.title}",
    ]

    # One line per distinct gate. Listing a gate once per finding that tripped it says
    # nothing the count in the line above does not already say.
    for gate_id in dict.fromkeys(
        f.gate_triggered for f in findings if f.gate_triggered
    ):
        triggered = sum(1 for f in findings if f.gate_triggered == gate_id)
        count = f" ({triggered} findings)" if triggered > 1 else ""
        reasons.append(f"gate {gate_id}{count}")

    return reasons
