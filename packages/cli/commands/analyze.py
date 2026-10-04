import asyncio
import logging

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ...core.exceptions import (
    InvalidPackageDataError,
    PackageNotFoundError,
    RegistryAPIError,
)
from ...core.models.package import PackageRequest
from ...core.pipeline.analysis import AnalysisPipeline
from ...core.tracing import fmt_fields

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)

RISK_STYLE = {
    "SAFE": "bold green",
    "LOW": "green",
    "MODERATE": "yellow",
    "HIGH": "bold red",
    "CRITICAL": "bold white on red",
}

DECISION_STYLE = {"ALLOW": "bold green", "WARN": "bold yellow", "BLOCK": "bold red"}


@app.command()
def analyze(package_name: str, version: str | None = None, ecosystem: str = "pypi"):
    req: PackageRequest = PackageRequest(
        name=package_name, version=version, ecosystem=ecosystem
    )

    try:
        with console.status(
            f"[bold cyan]Analyzing package[/bold cyan] [bold green]{package_name}[/bold green]...",
            spinner="dots",
        ):
            logger.info(f"Analyzing Package - {package_name}")
            logger.debug("analysis context snapshot | %r", req)
            pipeline = AnalysisPipeline()
            result = asyncio.run(pipeline.run(req))

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
        logger.exception(
            "analyze failed with an unhandled error: %s: %s", type(e).__name__, e
        )
        console.print(
            Panel(
                f"[bold red]Unexpected Error:[/bold red] An internal pipeline crash occurred.\n"
                f"[dim]{type(e).__name__}: {e}[/dim]",
                title="[bold red]Internal Error[/bold red]",
                border_style="bright_red",
            )
        )
        raise typer.Exit(code=1)

    pkg = result

    logger.info(
        "analyze verdict | %s",
        fmt_fields(
            {
                "final_score": round(pkg.final_score, 2),
                "base_score": round(pkg.base_score, 2),
                "risk_level": pkg.risk_level.value,
                "decision": pkg.decision.value,
                "confidence": pkg.confidence,
                "findings": len(pkg.findings),
                "gates_triggered": sum(1 for g in pkg.gates if g.triggered),
            }
        ),
    )

    # ---------------------------------------------------------------- summary
    header_text = Text()
    header_text.append(f"{pkg.package_name} ", style="bold magenta")
    header_text.append(f"v{pkg.version or 'Unknown'}\n", style="bold cyan")
    header_text.append(
        f"{pkg.final_score:.1f}/100  ",
        style=RISK_STYLE.get(pkg.risk_level.value, "white"),
    )
    header_text.append(
        pkg.risk_level.value, style=RISK_STYLE.get(pkg.risk_level.value, "white")
    )
    header_text.append("   decision: ", style="dim")
    header_text.append(
        pkg.decision.value, style=DECISION_STYLE.get(pkg.decision.value, "white")
    )
    header_text.append(f"\nconfidence: {pkg.confidence:.1f}%", style="dim")

    console.print(Panel(header_text, title="PackSafe Verdict", border_style="cyan"))

    # ------------------------------------------------------------- categories
    table = Table(
        title="Security Categories", show_header=True, header_style="bold blue"
    )
    table.add_column("Category", style="dim", width=16)
    table.add_column("Score", justify="right", width=8)
    table.add_column("Weight", justify="right", width=8)
    table.add_column("Status", width=14)

    for name, cat in pkg.categories.items():
        table.add_row(
            name,
            f"{cat.score:.1f}",
            f"{cat.weight:.2f}",
            cat.status.value,
        )

    console.print(table)

    # --------------------------------------------------------------- findings
    if pkg.findings:
        ft = Table(
            title=f"Findings ({len(pkg.findings)})",
            show_header=True,
            header_style="bold blue",
        )
        ft.add_column("Severity", width=10)
        ft.add_column("Finding", style="bold")
        ft.add_column("Confidence", justify="right", width=11)
        ft.add_column("Evidence", style="dim")

        for f in pkg.findings:
            ft.add_row(
                f.severity,
                f.title,
                f"{f.confidence:.2f}",
                (f.evidence or "")[:60],
            )

        console.print(ft)

    # ------------------------------------------------------------------ gates
    triggered = [g for g in pkg.gates if g.triggered]
    if triggered:
        gt = Table(
            title="Triggered Security Gates", show_header=True, header_style="bold red"
        )
        gt.add_column("Gate", style="bold")
        gt.add_column("Severity", width=10)
        gt.add_column("Reason", style="dim")
        for g in triggered:
            gt.add_row(g.gate_id, g.severity.value, g.reason)
        console.print(gt)

    # -------------------------------------------------------- coverage summary
    cov = pkg.evidence_coverage_summary
    console.print(
        f"[dim]Evidence coverage: {cov['available']} available, "
        f"{cov['missing']} missing, {cov['stale']} stale, "
        f"{cov['invalid']} invalid, {cov['not_applicable']} n/a[/dim]"
    )
