import logging
from typing import Annotated

import typer
from rich.console import Console

from ..display.report import render_report
from ..explain import explain_and_render
from ._analysis import (
    ecosystem_option,
    explain_option,
    log_verdict,
    run_analysis,
    version_option,
)

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)


@app.command()
def analyze(
    package_name: Annotated[str, typer.Argument(help="Name of the package to analyze")],
    version: version_option = None,
    ecosystem: ecosystem_option = "pypi",
    show_all: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="List every risk factor and full gate reason instead of the collapsed summary.",
        ),
    ] = False,
    explain: explain_option = False,
):
    """Analyze a package and report its supply-chain risk."""
    logger.info(f"Analyzing Package - {package_name}")

    outcome = run_analysis(console, package_name, version=version, ecosystem=ecosystem)
    log_verdict(outcome)

    render_report(console, outcome, expand=show_all)

    # Deliberately last, and deliberately outside run_analysis. The report is complete and
    # the verdict is already decided by this point, so an explanation that fails, hangs, or
    # errors cannot change what was printed or the exit code the caller sees.
    if explain:
        explain_and_render(console, outcome)
