from pathlib import Path
from typing import Annotated

import typer
from packsafe_core.logging_config import setup_logging

from .commands.analyze import app as analyze_app
from .commands.audit import app as audit_app
from .commands.init import app as init_app
from .commands.inspect import app as inspect_app
from .commands.install import app as install_app
from .version import version_info

# Configure at import time so anything logged during startup still reaches the file.
# The callback below reconfigures once the user's flags are known.
setup_logging()

app = typer.Typer(no_args_is_help=True)


def _version_callback(
    value: bool,
) -> None:
    """Prints the version and exits, the way every other CLI answers ``--version``."""
    if value:
        typer.echo(version_info())
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Show the installed PackSafe version and exit.",
            callback=_version_callback,
            is_eager=True,
        ),
    ] = False,
    verbose: Annotated[
        bool,
        typer.Option(
            "--verbose",
            "-v",
            help="Log DEBUG detail: every metric's raw->normalized math, HTTP calls and retries.",
        ),
    ] = False,
    log_level: Annotated[
        str | None,
        typer.Option(
            "--log-level",
            help="Explicit log level (DEBUG, INFO, WARNING, ERROR). Overrides --verbose.",
        ),
    ] = None,
    log_file: Annotated[
        Path | None,
        typer.Option(
            "--log-file",
            help="Where to write the trace log (default: app-dev.log in the current directory).",
        ),
    ] = None,
) -> None:
    """PackSafe: an intelligent security gatekeeper for the open-source supply chain."""
    # The version flag is eager and exits on its own; this body only configures logging.
    level = log_level or ("DEBUG" if verbose else None)
    setup_logging(level=level, log_file=log_file, reconfigure=True)


app.add_typer(init_app)
app.add_typer(inspect_app)
app.add_typer(analyze_app)
app.add_typer(install_app)
app.add_typer(audit_app)

if __name__ == "__main__":
    app()
