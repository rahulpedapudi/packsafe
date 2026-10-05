"""Composite results returned by the analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field

from ..pipeline.context import AnalysisContext
from .scoring import ScoreResult


@dataclass(frozen=True)
class AnalysisOutcome:
    """A finished analysis: the immutable score together with the evidence behind it.

    ``ScoreResult`` is enough to rank a package, but anything that has to *explain* the
    verdict - a CLI report, an API response - needs the underlying evidence too: which
    popular package the name imitates, how active the repository is, where in the
    archive the suspicious code lives. The score deliberately carries only derived
    numbers, so explainers read those details from here instead of re-fetching them.
    """

    score: ScoreResult
    context: AnalysisContext = field(repr=False)
