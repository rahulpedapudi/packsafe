"""Structured tracing: stage inputs/outputs, score arithmetic and performance spans.

Call sites stay short and the log format stays consistent because three concerns live
here:

* :func:`stage_trace` - context manager logging what a pipeline stage consumed, what it
  produced, its outcome and how long it took.
* :func:`log_http` - one consistent line per outbound request, including retries, so
  network time can be attributed to a source.
* :data:`perf` - accumulates timings and renders the end-of-run performance summary.

Every record uses lazy ``%``-style logging arguments, so DEBUG-only detail is never
formatted when the level is not enabled.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

# Long values (summaries, evidence snippets, URLs with signatures) are clipped so one
# record cannot swamp the log.
MAX_VALUE_CHARS = 160

# Mappings up to this size are rendered inline (severity mixes, status counts); larger
# ones collapse to a length so a big payload cannot flood the log.
MAX_INLINE_MAPPING = 8

STAGE_KIND = "stage"
HTTP_KIND = "http"
COMPUTE_KIND = "compute"


def fmt_value(value: Any, *, max_chars: int = MAX_VALUE_CHARS) -> str:
    """Renders a single value compactly and predictably for log scanning."""
    if value is None:
        return "-"
    if isinstance(value, Enum):
        return fmt_value(value.value, max_chars=max_chars)
    if isinstance(value, bool):
        return str(value)
    if isinstance(value, float):
        text = f"{value:.4f}".rstrip("0").rstrip(".")
        return text or "0"
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, (list, tuple, set, frozenset)):
        return f"{type(value).__name__}(len={len(value)})"
    if isinstance(value, Mapping):
        if not value or len(value) > MAX_INLINE_MAPPING:
            return f"dict(len={len(value)})"
        inner = ",".join(
            f"{k}={fmt_value(v, max_chars=max_chars // 2)}" for k, v in value.items()
        )
        return f"{{{inner}}}"

    text = str(value)
    if len(text) > max_chars:
        return text[: max_chars - 1] + "…"
    return text


def fmt_fields(fields: Mapping[str, Any] | None, *, prefix: str = "") -> str:
    """Renders a mapping as ``key=value key=value`` for one-line log records."""
    if not fields:
        return "-"
    return prefix + " ".join(f"{k}={fmt_value(v)}" for k, v in fields.items())


def fmt_duration(seconds: float) -> str:
    """Renders a duration with millisecond precision."""
    return f"{seconds:.3f}s ({seconds * 1000:.1f}ms)"


def pick(obj: Any, fields: Iterable[str]) -> dict[str, Any]:
    """Collects the named attributes from ``obj``; absent attributes become ``None``.

    Stages use this to declare exactly which context fields they consume, which is what
    makes "what did this stage feed in" answerable without dumping the whole context.
    """
    return {name: getattr(obj, name, None) for name in fields}


@dataclass
class SpanRecord:
    """One timed unit of work."""

    name: str
    kind: str
    seconds: float
    outcome: str = "ok"
    detail: str | None = None


class PerfRecorder:
    """Collects span timings for the end-of-run performance summary.

    A single list rather than a tree: stages and their nested HTTP calls are reported as
    separate sections, and nesting is stated explicitly instead of implied by arithmetic
    that does not add up.
    """

    def __init__(self) -> None:
        self._spans: list[SpanRecord] = []

    def reset(self) -> None:
        self._spans.clear()

    def record(
        self,
        name: str,
        seconds: float,
        *,
        kind: str = STAGE_KIND,
        outcome: str = "ok",
        detail: str | None = None,
    ) -> None:
        self._spans.append(
            SpanRecord(
                name=name, kind=kind, seconds=seconds, outcome=outcome, detail=detail
            )
        )

    def spans(self, kind: str | None = None) -> list[SpanRecord]:
        if kind is None:
            return list(self._spans)
        return [s for s in self._spans if s.kind == kind]

    def total(self, kind: str | None = None) -> float:
        return sum(s.seconds for s in self.spans(kind))

    def slowest(self, kind: str | None = None) -> SpanRecord | None:
        found = self.spans(kind)
        return max(found, key=lambda s: s.seconds) if found else None

    @staticmethod
    def _render_table(
        logger: logging.Logger,
        title: str,
        spans: list[SpanRecord],
        wall_seconds: float,
        *,
        note: str | None = None,
        show_share: bool = True,
        aggregate: bool = False,
    ) -> None:
        if not spans:
            return

        total = sum(s.seconds for s in spans)
        if show_share:
            header = (
                f"perf {title} | {len(spans)} span(s) | sum={fmt_duration(total)} | "
                f"share_of_wall={100.0 * total / wall_seconds if wall_seconds else 0.0:.1f}%"
            )
        else:
            header = f"perf {title} | {len(spans)} span(s) | sum={fmt_duration(total)}"
        logger.info("%s%s", header, f" | {note}" if note else "")

        if aggregate:
            # Requests to one source are often issued concurrently, so a per-call share of
            # wall time would be meaningless. Total and average per call are not.
            grouped: dict[str, list[SpanRecord]] = {}
            for span in spans:
                grouped.setdefault(span.name, []).append(span)
            rows = sorted(
                grouped.items(), key=lambda kv: sum(s.seconds for s in kv[1]), reverse=True
            )
            width = max(len(name) for name, _ in rows)
            for name, group in rows:
                spent = sum(s.seconds for s in group)
                outcomes = sorted({s.outcome for s in group if s.outcome != "ok"})
                logger.info(
                    "perf   %-*s calls=%-3d total=%-18s avg=%-18s%s",
                    width,
                    name,
                    len(group),
                    fmt_duration(spent),
                    fmt_duration(spent / len(group)),
                    f"outcome={','.join(outcomes)}" if outcomes else "",
                )
            return

        rows = sorted(spans, key=lambda s: s.seconds, reverse=True)
        width = max(len(s.name) for s in rows)
        for span in rows:
            if show_share:
                share = f"{100.0 * span.seconds / wall_seconds if wall_seconds else 0.0:6.1f}%"
                share_text = f"{share}  "
            else:
                share_text = " " * 8
            logger.info(
                "perf   %-*s %s%s outcome=%s%s",
                width,
                span.name,
                share_text,
                fmt_duration(span.seconds).ljust(8),
                span.outcome,
                f" | {span.detail}" if span.detail else "",
            )

    def log_summary(
        self, logger: logging.Logger, wall_seconds: float | None = None
    ) -> None:
        """Logs the performance breakdown, slowest first, grouped by span kind."""
        total = wall_seconds if wall_seconds is not None else self.total(STAGE_KIND)
        logger.info("=" * 100)
        logger.info(
            "PERFORMANCE SUMMARY | wall=%s | stage_time=%s | stages run concurrently, "
            "so stage_time can exceed wall time",
            fmt_duration(total),
            fmt_duration(self.total(STAGE_KIND)),
        )

        slowest = self.slowest(STAGE_KIND)
        if slowest:
            logger.info(
                "PERFORMANCE BOTTLENECK | stage=%s took %s (%.1f%% of wall)",
                slowest.name,
                fmt_duration(slowest.seconds),
                100.0 * slowest.seconds / total if total else 0.0,
            )

        self._render_table(logger, "stages", self.spans(STAGE_KIND), total)
        self._render_table(
            logger,
            "network (nested within stages)",
            self.spans(HTTP_KIND),
            total,
            note="included in stage time; requests per source may be concurrent",
            show_share=False,
            aggregate=True,
        )
        self._render_table(
            logger,
            "scoring (nested within pipeline)",
            self.spans(COMPUTE_KIND),
            total,
            note="included in total wall time",
        )
        logger.info("=" * 100)


perf = PerfRecorder()


class StageOutcome(str, Enum):
    """Terminal state of a stage, used to pick the log level of its completion record."""

    OK = "ok"
    SKIPPED = "skipped"
    DEGRADED = "degraded"
    FAILED = "failed"


_OUTCOME_LEVEL = {
    StageOutcome.OK: logging.INFO,
    StageOutcome.SKIPPED: logging.INFO,
    StageOutcome.DEGRADED: logging.WARNING,
    StageOutcome.FAILED: logging.ERROR,
}


@dataclass
class StageSpan:
    """Mutable handle used inside :func:`stage_trace` to report a stage's output."""

    name: str
    logger: logging.Logger
    inputs: dict[str, Any] = field(default_factory=dict)
    outcome: StageOutcome = StageOutcome.OK
    outputs: dict[str, Any] = field(default_factory=dict)
    detail: str | None = None
    dump: Any = None
    started_at: float = field(default_factory=time.perf_counter)
    elapsed: float | None = None

    def output(self, **fields: Any) -> None:
        """Records fields the stage wrote into the context."""
        self.outputs.update(fields)

    def set_outcome(self, outcome: StageOutcome, detail: str | None = None) -> None:
        self.outcome = outcome
        if detail:
            self.detail = detail

    def skip(self, reason: str) -> None:
        self.set_outcome(StageOutcome.SKIPPED, reason)

    def degrade(self, reason: str) -> None:
        self.set_outcome(StageOutcome.DEGRADED, reason)

    def fail(self, reason: str) -> None:
        self.set_outcome(StageOutcome.FAILED, reason)

    @property
    def level(self) -> int:
        return _OUTCOME_LEVEL[self.outcome]

    def log_start(self) -> None:
        self.logger.info(
            "stage=%s event=start | %s",
            self.name,
            fmt_fields(self.inputs, prefix="input: "),
        )
        if self.dump is not None and self.logger.isEnabledFor(logging.DEBUG):
            self.logger.debug(
                "stage=%s input.dump | %r", self.name, self.dump
            )

    def log_end(self) -> None:
        self.logger.log(
            self.level,
            "stage=%s event=end outcome=%s duration=%s | %s%s",
            self.name,
            self.outcome.value,
            fmt_duration(self.elapsed or 0.0),
            fmt_fields(self.outputs, prefix="output: "),
            f" | {self.detail}" if self.detail else "",
        )


@contextmanager
def stage_trace(
    name: str,
    logger: logging.Logger,
    *,
    inputs: Mapping[str, Any] | None = None,
    dump: Any = None,
) -> Iterator[StageSpan]:
    """Logs a stage's inputs, records its duration, then logs its outputs and outcome.

    The duration is recorded even when the stage raises, so a crashed stage still shows
    up in the performance summary and in the log as the last thing that happened.
    """
    span = StageSpan(name=name, logger=logger, inputs=dict(inputs or {}), dump=dump)
    span.log_start()
    try:
        yield span
    except BaseException as exc:
        span.elapsed = time.perf_counter() - span.started_at
        span.fail(f"{type(exc).__name__}: {exc}")
        span.log_end()
        perf.record(name, span.elapsed, outcome=span.outcome.value)
        raise
    span.elapsed = time.perf_counter() - span.started_at
    span.log_end()
    perf.record(
        name,
        span.elapsed,
        outcome=span.outcome.value,
        detail=span.detail,
    )


def log_http(
    logger: logging.Logger,
    source: str,
    *,
    method: str,
    url: str,
    status: int | None = None,
    elapsed: float | None = None,
    attempt: int | None = None,
    outcome: str = "ok",
    detail: str | None = None,
) -> None:
    """Logs one outbound request at DEBUG and attributes its duration to ``perf``.

    Retries are logged at WARNING because they are the usual explanation for a stage that
    is slow for no visible reason.
    """
    record = f"source={source} {method} {url}"
    if status is not None:
        record += f" -> {status}"
    if attempt is not None:
        record += f" attempt={attempt}"
    if elapsed is not None:
        record += f" in {fmt_duration(elapsed)}"
    record += f" outcome={outcome}"
    if detail:
        record += f" | {detail}"

    if attempt is not None and attempt > 0:
        logger.warning("http retry | %s", record)
    elif logger.isEnabledFor(logging.DEBUG):
        logger.debug("http %s", record)

    # Recorded regardless of level: the per-request line is optional, the network time
    # in the performance summary is not.
    if elapsed is not None:
        perf.record(
            f"http:{source}",
            elapsed,
            kind=HTTP_KIND,
            outcome=outcome,
        )


def log_compute(
    logger: logging.Logger, name: str, elapsed: float, *, detail: str | None = None
) -> None:
    """Records a CPU-bound scoring phase so it is distinguishable from I/O time."""
    perf.record(name, elapsed, kind=COMPUTE_KIND, detail=detail)