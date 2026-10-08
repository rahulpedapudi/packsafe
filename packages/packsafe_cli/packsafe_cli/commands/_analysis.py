"""Runs the analysis pipeline for a command and turns failures into readable panels.

`analyze` and `inspect` differ only in how they present a result, so they share the run
step and the failure handling: the same spinner, the same log records, the same exit
codes. Anything that changes how a failure is reported to the user belongs here rather
than in one command.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated

import typer
from packsafe_core.exceptions import (
    InvalidPackageDataError,
    PackageNotFoundError,
    RegistryAPIError,
)
from packsafe_core.models.package import PackageRequest
from packsafe_core.models.result import AnalysisOutcome
from packsafe_core.pipeline.analysis import AnalysisPipeline
from packsafe_core.tracing import fmt_fields
from rich.console import Console
from rich.panel import Panel

logger = logging.getLogger(__name__)

# Distinct exit codes so a script can tell a missing package from an unreachable
# registry from a crash.
EXIT_NOT_FOUND = 1
EXIT_NETWORK = 2
EXIT_BAD_DATA = 3
EXIT_INTERNAL = 1
EXIT_INTERRUPTED = 130

# Every command that looks a package up takes the same options. Declared once here so the
# flags cannot drift apart between `analyze` and `inspect`. The package *argument* is not
# shared: a Typer argument cannot be re-wrapped in another Annotated, and each command
# wants its own wording there anyway.
version_option = Annotated[
    str | None,
    typer.Option("--version", "-V", help="Target a specific version (default: latest)."),
]
ecosystem_option = Annotated[
    str,
    typer.Option("--ecosystem", "-e", help="Registry to look the package up in."),
]

# Declared here for the same reason as the options above: `--explain` is a request for
# something derived from a finished analysis, so any command that finishes an analysis can
# offer it, and its wording must not drift between them.
explain_option = Annotated[
    bool,
    typer.Option(
        "--explain",
        help=(
            "Add a plain-language paragraph explaining why the score came out this way. "
            "Costs a network call to the PackSafe service; the score itself is unchanged "
            "if that call fails."
        ),
    ),
]


def run_analysis(
    console: Console,
    package_name: str,
    *,
    version: str | None = None,
    ecosystem: str = "pypi",
) -> AnalysisOutcome:
    """Runs the pipeline for one package, exiting the CLI with a readable message on failure.

    Never returns ``None`` and never raises for an expected failure: a command that gets
    an outcome back can always render it.
    """
    request = PackageRequest(name=package_name, version=version, ecosystem=ecosystem)

    try:
        with console.status(
            f"[bold cyan]Analyzing[/bold cyan] [bold green]{package_name}[/bold green]...",
            spinner="dots",
        ):
            logger.info("Analyzing Package - %s", package_name)
            logger.debug("analysis context snapshot | %r", request)
            return asyncio.run(AnalysisPipeline().run_detailed(request))

    except PackageNotFoundError as e:
        logger.warning("analysis aborted | package not found: %s", e)
        console.print(
            Panel(
                f"[bold red]Not Found:[/bold red] Package [yellow]'{e.package_name}'[/yellow] does not exist on [blue]{e.ecosystem}[/blue].\n"
                f"[dim]Please check the package spelling or ecosystem name.[/dim]",
                title="[bold red]Error[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=EXIT_NOT_FOUND) from e

    except RegistryAPIError as e:
        logger.error("analysis aborted | registry API error: %s", e)
        status_info = f" (Status code: {e.status_code})" if e.status_code else ""
        console.print(
            Panel(
                f"[bold red]Registry API Error:[/bold red] Could not reach the [blue]{request.ecosystem}[/blue] API{status_info}.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Network Error[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=EXIT_NETWORK) from e

    except InvalidPackageDataError as e:
        logger.error("analysis aborted | invalid package data: %s", e)
        console.print(
            Panel(
                f"[bold red]Parsing Failure:[/bold red] Failed to parse package details.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Data Error[/bold red]",
                border_style="magenta",
            )
        )
        raise typer.Exit(code=EXIT_BAD_DATA) from e

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Cancelled by user.[/bold yellow]")
        logger.warning("analysis aborted by user (KeyboardInterrupt)")
        raise typer.Exit(code=EXIT_INTERRUPTED) from None

    except Exception as e:
        # The console shows a friendly panel; the traceback belongs in the log, where it
        # can actually be diagnosed. logger.exception attaches the traceback itself, so
        # only the exception type is worth naming.
        logger.exception("analysis failed with an unhandled error: %s", type(e).__name__)
        console.print(
            Panel(
                f"[bold red]Unexpected Error:[/bold red] An internal pipeline crash occurred.\n"
                f"[dim]{type(e).__name__}: {e}[/dim]",
                title="[bold red]Internal Error[/bold red]",
                border_style="bright_red",
            )
        )
        raise typer.Exit(code=EXIT_INTERNAL) from e


def log_verdict(outcome: AnalysisOutcome) -> None:
    """Records the verdict once, so the log line is identical for every command."""
    score = outcome.score
    logger.info(
        "verdict | %s",
        fmt_fields(
            {
                "package": score.package_name,
                "version": score.version,
                "final_score": round(score.final_score, 2),
                "base_score": round(score.base_score, 2),
                "risk_level": score.risk_level.value,
                "decision": score.decision.value,
                "confidence": score.confidence,
                "findings": len(score.findings),
                "gates_triggered": sum(1 for g in score.gates if g.triggered),
            }
        ),
    )
