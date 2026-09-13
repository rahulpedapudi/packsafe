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
from ...core.models.package import PackageMetadata, PackageRequest
from ...core.pipeline.analysis import AnalysisPipeline

app = typer.Typer()
console = Console()


@app.command()
def analyze(package_name: str):
    # !do i need to pass the version of the package explicitly? or is there a way to retrieve the package version?
    req: PackageRequest = PackageRequest(package_name)

    try:
        with console.status(
            f"[bold cyan]Analyzing package[/bold cyan] [bold green]{req.name}[/bold green]...",
            spinner="dots",
        ):
            # initializes analysis pipeline
            pipeline = AnalysisPipeline()

            # pipeline return analysis context which contains the infomation accumulated during the analysis
            context = pipeline.run(req)

        # TODO: if package is not found, suggest alternative packages instead of just showing error and exiting; this should be interactive.
        if not context.package or not context.package.exists:
            raise PackageNotFoundError(package_name, req.ecosystem)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Cancelled by user.[/bold yellow]")
        raise typer.Exit(code=130)

    except PackageNotFoundError as e:
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
        status_info = f" (Status code: {e.status_code})" if e.status_code else ""
        console.print(
            Panel(
                f"[bold red]Registry API Error:[/bold red] Could not reach the {req.ecosystem} API{status_info}.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Network Error[/bold red]",
                border_style="red",
            )
        )
        raise typer.Exit(code=2)

    except InvalidPackageDataError as e:
        console.print(
            Panel(
                f"[bold red]Parsing Failure:[/bold red] Failed to parse package details.\n"
                f"[dim]Details: {e}[/dim]",
                title="[bold red]Data Error[/bold red]",
                border_style="magenta",
            )
        )
        raise typer.Exit(code=3)

    except Exception as e:
        # Fallback unexpected internal crash
        console.print(
            Panel(
                f"[bold red]Unexpected Error:[/bold red] An internal pipeline crash occurred.\n"
                f"[dim]{type(e).__name__}: {e}[/dim]",
                title="[bold red]Internal Error[/bold red]",
                border_style="bright_red",
            )
        )
        raise typer.Exit(code=1)

    pkg = context.package
    meta = pkg.metadata or PackageMetadata()

    # Create main overview panel header
    header_text = Text()
    header_text.append(f"{pkg.name} ", style="bold magenta")

    # version is always the latest, cuz we are displaying the info of the latest release
    header_text.append(f"v{meta.version or 'Unknown'}\n", style="bold cyan")

    if meta.description:
        header_text.append(f"{meta.description}\n", style="italic white")

    console.print(Panel(header_text, title="Package Overview", border_style="cyan"))

    # Metadata & Details Table
    table = Table(
        title="Metadata & Release Details", show_header=True, header_style="bold blue"
    )
    table.add_column("Property", style="dim", width=20)
    table.add_column("Value")

    table.add_row("Ecosystem", pkg.ecosystem)
    table.add_row(
        "Initial Release",
        meta.initial_release_date.strftime("%Y-%m-%d")
        if meta.initial_release_date
        else "N/A",
    )
    table.add_row(
        "Last Release",
        meta.last_release_date.strftime("%Y-%m-%d")
        if meta.last_release_date
        else "N/A",
    )

    # Render Project URLs
    if meta.project_urls:
        urls_str = "\n".join(
            [f"[link={v}]{k}[/link]: {v}" for k, v in meta.project_urls.items()]
        )
        table.add_row("Project Links", urls_str)

    # TODO: i dont possibly need these
    # Render Direct Dependencies count / list preview
    deps_count = len(meta.raw_deps) if meta.raw_deps else 0
    deps_preview = ", ".join(meta.raw_deps[:5]) if meta.raw_deps else "None"
    if deps_count > 5:
        deps_preview += f" ... (+{deps_count - 5} more)"

    table.add_row("Dependencies", f"{deps_count} total ({deps_preview})")

    console.print(table)
