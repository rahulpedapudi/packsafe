"""Renders the PackSafe analysis report.

The report is ordered the way a reviewer reads a package: what it is, how bad it is,
which checks fired, the evidence behind those checks, and what to do about it. A section
that has nothing to report says so in one line rather than disappearing, so a reader can
tell "clean" apart from "not covered by this run".

The two long sections - risk factors and policy gates - are collapsed to a summary by
default. ``expand=True`` (the CLI's ``--all``) prints them in full up front; otherwise an
interactive terminal is offered the detail once the report is done, and a
non-interactive one (CI, a pipe, a script) never blocks and simply keeps the summary.
"""

from __future__ import annotations

import sys
from collections import Counter

from rich.console import Console
from rich.padding import Padding
from rich.prompt import Confirm
from rich.table import Table
from rich.text import Text

from ...core.models.result import AnalysisOutcome
from ...core.models.scoring import Decision, Finding, ScoreResult, SeverityRank
from ...core.pipeline.context import AnalysisContext
from .checks import build_checks, sort_findings
from .theme import (
    DECISION_STYLE,
    GATE_SEVERITY_STYLE,
    LABEL_STYLE,
    RISK,
    RISK_STYLE,
    RISK_WORD,
    RULE_STYLE,
    SECTION_TITLE,
    SEVERITY_ORDER,
    SEVERITY_STYLE,
    WARN,
    CheckRow,
    plural,
    short_hash,
    short_url,
)

# Even expanded, findings are a long tail; past this the report stops being scannable and
# the remaining detail belongs in the analysis log.
MAX_RISK_FACTORS = 10

# A gate reason can list every finding that fired; the report already lists them.
GATE_REASON_LIMIT = 110

# The headline finding gets one line in the collapsed view, not a paragraph.
WORST_FINDING_LIMIT = 70

ECOSYSTEM_NAME = {"pypi": "PyPI", "npm": "npm"}

BAR_WIDTH = 48

# What to do, keyed by the decision the score engine reached.
RECOMMENDATIONS = {
    Decision.BLOCK: (
        "DO NOT INSTALL",
        (
            "A blocking gate fired: the evidence is strong enough that installing this "
            "package would put your machine and your users at risk."
        ),
    ),
    Decision.WARN: (
        "INSTALL WITH CAUTION",
        (
            "Nothing here is confirmed malicious, but the signals below need a human "
            "decision before this package earns a place in your dependencies."
        ),
    ),
    Decision.REVIEW: (
        "REVIEW BEFORE INSTALLING",
        "The evidence is incomplete. Inspect the flagged signals manually, then decide.",
    ),
    Decision.ALLOW: (
        "SAFE TO INSTALL",
        "No blocking signals were found in the checks that could run.",
    ),
}

# Below this the score rests on partial evidence, and the report says so instead of
# letting a clean-looking verdict imply full coverage.
LOW_CONFIDENCE = 60


def render_report(console: Console, outcome: AnalysisOutcome, *, expand: bool = False) -> None:
    """Prints the analysis report.

    Risk factors and policy gates collapse to a summary unless ``expand`` is set. When they
    are collapsed and the terminal can answer a prompt, the detail is offered afterwards
    instead of being forced on the reader up front.
    """
    score = outcome.score
    context = outcome.context

    console.print()
    _render_header(console, score, context)
    _render_verdict(console, score)
    _render_checks(console, score, context)
    _render_risk_factors(console, score, expanded=expand)
    _render_gates(console, score, expanded=expand)
    _render_recommendation(console, score)
    _render_footer(console, score, context)

    if not expand and _has_withheld_detail(score) and _offer_withheld_detail(console, score):
        _render_risk_factors(console, score, expanded=True)
        _render_gates(console, score, expanded=True)


def _has_withheld_detail(score: ScoreResult) -> bool:
    """True when something was left out of the report and could still be shown."""
    return bool(score.findings) or any(g.triggered for g in score.gates)


def _offer_withheld_detail(console: Console, score: ScoreResult) -> bool:
    """Asks whether to print the collapsed detail now, but only if someone can answer.

    Anything non-interactive - CI, a pipe, a script - must never stop and wait for a
    keypress, so the prompt is skipped rather than defaulted.
    """
    if not console.is_interactive or not sys.stdin.isatty():
        return False

    hidden = []
    if score.findings:
        hidden.append(plural(len(score.findings), "risk factor"))
    gates = sum(1 for g in score.gates if g.triggered)
    if gates:
        hidden.append(plural(gates, "gate reason"))

    try:
        return Confirm.ask(f"Show {' and '.join(hidden)}?", default=False, console=console)
    except (EOFError, KeyboardInterrupt):
        return False


# --------------------------------------------------------------------- header


def _render_header(console: Console, score: ScoreResult, ctx: AnalysisContext) -> None:
    console.print(Text("PackSafe Security Analysis", style="bold cyan"))
    console.rule(style=RULE_STYLE)
    console.print()

    fields = Table.grid(padding=(0, 2))
    fields.add_column(style="bright_black", no_wrap=True)
    fields.add_column(overflow="fold")

    rows = [
        ("Package", score.package_name or ctx.request.name),
        ("Version", score.version or ctx.package.version or "unknown"),
        (
            "Ecosystem",
            ECOSYSTEM_NAME.get(score.ecosystem, score.ecosystem or "unknown"),
        ),
    ]
    if ctx.package.package_url:
        rows.append(("Homepage", short_url(ctx.package.package_url)))

    for label, value in rows:
        fields.add_row(label, value or "unknown")

    console.print(fields)


def _section(console: Console, title: str) -> None:
    """Prints a blank line and a titled rule, the separator used between sections."""
    console.print()
    console.rule(Text(title, style=SECTION_TITLE), style=RULE_STYLE, align="left")


# -------------------------------------------------------------------- verdict


def _render_verdict(console: Console, score: ScoreResult) -> None:
    risk_style = RISK_STYLE.get(score.risk_level, "white")
    console.print()

    headline = Text()
    headline.append("SAFETY SCORE  ", style="bright_black")
    headline.append(f"{score.final_score:.0f}/100", style=f"bold {risk_style}")
    headline.append("   ")
    headline.append(RISK_WORD.get(score.risk_level, score.risk_level.value), style=risk_style)
    console.print(headline)

    console.print(_score_bar(console, score.final_score, risk_style))

    meta = Text()
    meta.append("Decision ", style="bright_black")
    meta.append(score.decision.value, style=DECISION_STYLE.get(score.decision, "white"))
    meta.append(f"   ·   Confidence {score.confidence:.0f}%", style="bright_black")
    console.print(meta)


def _score_bar(console: Console, score: float, style: str) -> Text:
    """A filled/empty bar sized to the terminal, so it never wraps on its own."""
    width = max(10, min(BAR_WIDTH, console.width - 4))
    filled = round(max(0.0, min(100.0, score)) / 100 * width)

    bar = Text("  ")
    bar.append("█" * filled, style=style)
    bar.append("░" * (width - filled), style="grey30")
    return bar


# --------------------------------------------------------------------- checks


def _render_checks(console: Console, score: ScoreResult, ctx: AnalysisContext) -> None:
    rows = build_checks(score, ctx)
    if not rows:
        return

    _section(console, "Checks")

    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True)
    grid.add_column(no_wrap=True, min_width=18, style=LABEL_STYLE)
    grid.add_column(overflow="fold")

    for row in rows:
        grid.add_row(
            Text(row.state.icon, style=row.state.style),
            row.label,
            _detail_text(row),
        )

    console.print(grid)


def _detail_text(row: CheckRow) -> Text:
    """Colors a detail line by severity so a skim never mistakes a warning for a pass."""
    text = Text(row.detail or "no data")
    if row.state in (RISK, WARN):
        text.stylize(row.state.style)
    return text


# ---------------------------------------------------------------- risk factors


def _render_risk_factors(console: Console, score: ScoreResult, *, expanded: bool) -> None:
    findings = sort_findings(score.findings)

    _section(console, f"Risk Factors ({len(findings)})")

    if not findings:
        console.print("  [green]✓[/green]  Nothing suspicious was found.")
        return

    if not expanded:
        _print_withheld_summary(
            console, _severity_histogram(findings), _worst_finding_line(findings)
        )
        return

    grid = Table.grid(padding=(0, 2))
    grid.add_column(no_wrap=True, min_width=8)
    grid.add_column(overflow="fold")

    for finding in findings[:MAX_RISK_FACTORS]:
        grid.add_row(_severity_tag(finding), _finding_body(finding))

    console.print(grid)

    hidden = len(findings) - MAX_RISK_FACTORS
    if hidden > 0:
        console.print(
            Text(
                f"  … {plural(hidden, 'lower-severity finding')} not shown; "
                f"full detail is in the analysis log.",
                style="bright_black",
            )
        )


def _severity_histogram(findings: list[Finding]) -> Text:
    """The counts a collapsed view needs: how much of what, worst first."""
    counts = Counter(SeverityRank.from_str(f.severity).name for f in findings)

    line = Text("  ")
    for index, rank in enumerate(r for r in SEVERITY_ORDER if counts[r]):
        if index:
            line.append(" · ", style="bright_black")
        line.append(f"{counts[rank]} {rank.lower()}", style=SEVERITY_STYLE.get(rank, "white"))

    return line


def _worst_finding_line(findings: list[Finding]) -> str:
    """The headline finding, so the collapsed view still says what is actually wrong."""
    return f"worst: {_one_line(findings[0].title, WORST_FINDING_LIMIT)}"


def _print_withheld_summary(console: Console, summary: str | Text, headline: str) -> None:
    """Prints the collapsed body of a section plus how to see the rest."""
    console.print(summary)
    if headline:
        console.print(Padding(Text(headline, style="dim"), (0, 1, 0, 2)))
    console.print(
        Padding(Text("Detail withheld · re-run with --all", style="bright_black"), (0, 1, 0, 2))
    )


def _severity_tag(finding: Finding) -> Text:
    severity = finding.severity.upper()
    return Text(severity, style=SEVERITY_STYLE.get(severity, "white"))


def _finding_body(finding: Finding) -> Text:
    body = Text()
    body.append(finding.title, style="bold")

    if finding.affected_version:
        body.append(f"  v{finding.affected_version}", style="bright_black")

    provenance = _finding_provenance(finding)
    if provenance:
        body.append(f"\n  {provenance}", style="bright_black")

    if finding.description.strip():
        body.append(f"\n  {finding.description.strip()}", style="dim")

    if finding.gate_triggered:
        body.append(f"\n  gate {finding.gate_triggered}", style="bright_black")

    return body


def _finding_provenance(finding: Finding) -> str:
    """The one line that says where the finding came from.

    Static findings need their archive location and code snippet. Advisories already name
    themselves in the title, so only the alias set is worth adding; repeating the raw
    evidence string there would just restate the CVE id and the exploitation note.
    """
    if finding.source == "static_analysis":
        return finding.evidence
    if finding.aliases:
        return f"also known as {', '.join(finding.aliases)}"
    return finding.evidence


# ---------------------------------------------------------------------- gates


def _render_gates(console: Console, score: ScoreResult, *, expanded: bool) -> None:
    triggered = [g for g in score.gates if g.triggered]
    if not triggered:
        return

    _section(console, "Policy Gates")

    if not expanded:
        summary = Text("  ")
        for index, gate in enumerate(triggered):
            if index:
                summary.append(" · ", style="bright_black")
            summary.append(gate.gate_id, style=GATE_SEVERITY_STYLE.get(gate.severity, "red"))
            summary.append(f" ({gate.severity.value})", style="bright_black")

        _print_withheld_summary(console, summary, "")
        return

    for gate in triggered:
        style = GATE_SEVERITY_STYLE.get(gate.severity, "red")
        line = Text()
        line.append(gate.gate_id, style=f"bold {style}")
        line.append(f"  {gate.severity.value}", style=style)
        line.append(f"  {_one_line(gate.reason, GATE_REASON_LIMIT)}", style="dim")
        if gate.decision_override:
            line.append(f"  → {gate.decision_override.value}", style=f"bold {style}")
        console.print(Padding(line, (0, 1, 0, 2)))


def _one_line(text: str, limit: int) -> str:
    """Collapses a reason into a single scannable line.

    Gate reasons can enumerate every finding that fired, which is useful in the log and
    unreadable on a terminal that is already showing those findings one by one.
    """
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"


# -------------------------------------------------------------- recommendation


def _render_recommendation(console: Console, score: ScoreResult) -> None:
    headline, rationale = RECOMMENDATIONS.get(
        score.decision, ("REVIEW MANUALLY", "No automated decision was reached.")
    )
    style = DECISION_STYLE.get(score.decision, "white")
    icon = (
        "✗"
        if score.decision is Decision.BLOCK
        else "✓"
        if score.decision is Decision.ALLOW
        else "!"
    )

    _section(console, "Recommendation")

    verdict = Text()
    verdict.append(f"  {icon}  ", style=style)
    verdict.append(headline, style=style)
    console.print(verdict)

    lines = [rationale]
    if score.confidence < LOW_CONFIDENCE:
        lines.append(
            f"Only {score.confidence:.0f}% of the evidence was available, so treat "
            f"this verdict as provisional."
        )

    # Padding rather than leading spaces: a wrapped line keeps the indent instead of
    # sliding back to column zero.
    for line in (*lines, _next_step(score)):
        console.print(Padding(Text(line, style="dim"), (0, 1, 0, 2)))


def _next_step(score: ScoreResult) -> str:
    """A concrete instruction, so the report ends with an action and not just a verdict."""
    if score.decision is Decision.BLOCK:
        return "Drop this name from your requirements and use the upstream package instead."
    if score.decision in (Decision.WARN, Decision.REVIEW):
        return "Confirm the maintainer, read the release notes, then pin an exact version."
    return "Pin the exact version and re-run the check on every upgrade."


# --------------------------------------------------------------------- footer


def _render_footer(console: Console, score: ScoreResult, ctx: AnalysisContext) -> None:
    coverage = score.evidence_coverage_summary
    total = sum(coverage.values()) if coverage else 0

    measured = (
        f"{coverage.get('available', 0)}/{total} metrics measured" if total else "unavailable"
    )

    parts = [
        f"evidence {measured}",
        f"coverage tier {ctx.analysis_coverage_tier}",
        f"engine {score.engine_version}",
        f"{score.analyzed_at:%Y-%m-%d %H:%M UTC}",
    ]
    if ctx.static_analysis.archive_sha256:
        parts.append(f"archive {short_hash(ctx.static_analysis.archive_sha256)}")

    console.print(Padding(Text(" · ".join(parts), style="bright_black"), (0, 1, 0, 2)))
