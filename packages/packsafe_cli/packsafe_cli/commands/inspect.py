import logging
from typing import Annotated

import typer
from rich.console import Console

from ..display.inspect import render_inspection
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
def inspect(
    package_name: Annotated[str, typer.Argument(help="Name of the package to inspect")],
    version: version_option = None,
    ecosystem: ecosystem_option = "pypi",
    show_all: Annotated[
        bool,
        typer.Option(
            "--all",
            "-a",
            help="List every advisory and static finding instead of the bounded default.",
        ),
    ] = False,
    explain: explain_option = False,
):
    """Show everything PackSafe knows about a package."""
    logger.info(f"Inspecting Package - {package_name}")

    outcome = run_analysis(console, package_name, version=version, ecosystem=ecosystem)
    log_verdict(outcome)

    render_inspection(console, outcome, expand=show_all)

    # Last, and outside run_analysis, for the reason given in `analyze`.
    if explain:
        explain_and_render(console, outcome)
