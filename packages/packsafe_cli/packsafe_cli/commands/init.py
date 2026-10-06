import asyncio
import logging

import typer
from rich.console import Console

from packsafe_core.config import settings
from packsafe_core.db.database import engine, init_db
from packsafe_core.exceptions import ApplicationError, InitializationError
from packsafe_core.sources.kev import KEVCollector
from ..config.config import Config
from ..display.art import ASCII_ART1

app = typer.Typer()
console = Console()

logger = logging.getLogger(__name__)


async def _warm_kev_cache() -> int:
    """Pre-fetches the CISA KEV catalog into the on-disk cache.

    Returns the number of cached entries, or 0 if the feed was unreachable.
    """
    try:
        async with KEVCollector() as collector:
            return len(await collector.fetch_catalog())
    except Exception as e:
        logger.debug(f"KEV cache warm-up failed: {e}")
        return 0


@app.command()
def init():
    """Initialize PackSafe configuration and local storage."""

    console.print(f"[bold cyan]{ASCII_ART1}[/bold cyan]")
    console.print("[bold]Initializing PackSafe[/bold]")

    try:
        app_root = settings.APP_ROOT
        config_file = settings.APP_CONFIG
        cache_file = settings.APP_CACHE

        config = Config(config_path=config_file)

        app_root_exists = app_root.exists()
        config_exists = config_file.exists()
        cache_exists = cache_file.exists()

        with console.status("[green]Preparing PackSafe...", spinner="dots"):
            app_root.mkdir(parents=True, exist_ok=True)

            if not config_exists:
                # creates a default config
                config.save_default_config()

            if not cache_exists:
                # creates cache.db file
                asyncio.run(init_db(engine))

            # Warm the CISA KEV catalog cache once, so the first analysis does not pay
            # for a ~1700-entry download. Best effort: a failure here must not block
            # initialization, and the collector falls back to a live fetch later.
            kev_entries = asyncio.run(_warm_kev_cache())
            if kev_entries:
                console.print(
                    f"[dim]Cached {kev_entries} CISA KEV entries for offline use.[/dim]"
                )
            else:
                console.print(
                    "[yellow]Could not pre-cache CISA KEV; it will be fetched on first use.[/yellow]"
                )

        logger.info(f"PackSafe root: {app_root}")
        logger.info(f"PackSafe config: {config_file}")
        logger.info(f"Packsafe cache: {cache_file}")

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
    console.print(f"[dim]Cache:[/dim] {cache_file}")
    console.print()
