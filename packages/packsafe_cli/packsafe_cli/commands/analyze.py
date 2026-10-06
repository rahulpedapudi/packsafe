import asyncio
import logging
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel

from packsafe_core.exceptions import (
    InvalidPackageDataError,
    PackageNotFoundError,
    RegistryAPIError,
)
from packsafe_core.models.package import PackageRequest
from packsafe_core.pipeline.analysis import AnalysisPipeline
from packsafe_core.tracing import fmt_fields
from ..display.report import render_report

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)


@app.command()
def analyze(
    package_name: Annotated[str, typer.Argument(help="Name of the package to analyze")],
    version: Annotated[
        str | None,
        typer.Option("--version", "-V", help="Analyze a specific version (default: latest)."),
    ] = None,
    ecosystem: Annotated[
        str,
        typer.Option("--ecosystem", "-e", help="Registry to look the package up in."),
    ] = "pypi",
    show_all: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="List every risk factor and full gate reason instead of the collapsed summary.",
        ),
    ] = False,
):
    """Analyze a package and report its supply-chain risk."""
    req: PackageRequest = PackageRequest(name=package_name, version=version, ecosystem=ecosystem)

    try:
        with console.status(
            f"[bold cyan]Analyzing[/bold cyan] [bold green]{package_name}[/bold green]...",
            spinner="dots",
        ):
            logger.info(f"Analyzing Package - {package_name}")
            logger.debug("analysis context snapshot | %r", req)
            pipeline = AnalysisPipeline()
            outcome = asyncio.run(pipeline.run_detailed(req))

    except PackageNotFoundError as e:
        logger.warning("analyze aborted | package not found: %s", e)
        console.print(
            Panel(
                f"[bold red]Not Found:[/bold red] Package [yellow]'{e.package_name}'[/yellow] does not exist on [blue]{e.ecosystem}[/blue].\n"
                f"[dim]Please check the package spelling or ecosystem name.[/dim]",
                title="[bold red]Error[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=1)

    except RegistryAPIError as e:
        logger.error("analyze aborted | registry API error: %s", e)
        status_info = f" (Status code: {e.status_code})" if e.status_code else ""
        console.print(
            Panel(
                f"[bold red]Registry API Error:[/bold red] Could not reach the [blue]{req.ecosystem}[/blue] API{status_info}.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Network Error[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=2)

    except InvalidPackageDataError as e:
        logger.error("analyze aborted | invalid package data: %s", e)
        console.print(
            Panel(
                f"[bold red]Parsing Failure:[/bold red] Failed to parse package details.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Data Error[/bold red]",
                border_style="magenta",
            )
        )
        raise typer.Exit(code=3)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Cancelled by user.[/bold yellow]")
        logger.warning("analyze aborted by user (KeyboardInterrupt)")
        raise typer.Exit(code=130)

    except Exception as e:
        # The console shows a friendly panel; the traceback belongs in the log, where it
        # can actually be diagnosed.
        logger.exception("analyze failed with an unhandled error: %s: %s", type(e).__name__, e)
        console.print(
            Panel(
                f"[bold red]Unexpected Error:[/bold red] An internal pipeline crash occurred.\n"
                f"[dim]{type(e).__name__}: {e}[/dim]",
                title="[bold red]Internal Error[/bold red]",
                border_style="bright_red",
            )
        )
        raise typer.Exit(code=1)

    score = outcome.score

    logger.info(
        "analyze verdict | %s",
        fmt_fields(
            {
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

    render_report(console, outcome, expand=show_all)
