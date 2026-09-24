import logging
import tomllib

import typer
from rich.console import Console

from ...core.db.helpers import get_app_path
from ...core.exceptions import ApplicationError, InitializationError
from ..config.config import Config
from ..display.art import ASCII_ART1

app = typer.Typer()
console = Console()

logger = logging.getLogger(__name__)


@app.command()
def init():
    """Initialize PackSafe configuration and local storage."""

    console.print(f"[bold cyan]{ASCII_ART1}[/bold cyan]")
    console.print("[bold]Initializing PackSafe[/bold]")

    try:
        app_root = get_app_path()
        config_file = app_root / "config.toml"
        config = Config(config_path=config_file)

        app_root_exists = app_root.exists()
        config_exists = config_file.exists()

        with console.status("[green]Preparing PackSafe...", spinner="dots"):
            app_root.mkdir(parents=True, exist_ok=True)

            if not config_exists:
                # creates a default config
                config.save_default_config()

        logger.info(f"PackSafe root: {app_root}")
        logger.info(f"PackSafe config: {config_file}")

    except InitializationError as e:
        console.print()
        console.print("[bold red]✗ Initialization failed[/bold red]")
        console.print(f"[dim]{e}[/dim]")
        raise typer.Exit(code=1)

    except ApplicationError as e:
        console.print()
        console.print("[bold red]✗ Unexpected error[/bold red]")
        console.print(f"[dim]{type(e).__name__}: {e}[/dim]")
        raise typer.Exit(code=1)

    console.print()

    if app_root_exists and config_exists:
        console.print("[yellow]PackSafe is already initialized.[/yellow]")
    else:
        console.print("[bold green]✓ PackSafe initialized successfully[/bold green]")

    console.print()
    console.print(f"[dim]Config:[/dim] {config_file}")
    console.print()
