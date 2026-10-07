import logging
from typing import Annotated

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from ..exit_codes import EXIT_BLOCKED, EXIT_INSTALL_FAILED
from ..install_gate import evaluate
from ..installer import (
    InstallerError,
    PackageManager,
    build_command,
    requirement,
    resolve,
    run,
)
from ..prompts import can_prompt, confirm
from ._analysis import ecosystem_option, log_verdict, run_analysis, version_option

app = typer.Typer()
console = Console()
logger = logging.getLogger(__name__)

# install takes flags the analysis commands do not (--pip/--uv), so unknown options are
# forwarded to the package manager instead of erroring out.
CONTEXT_SETTINGS = {"allow_extra_args": True, "ignore_unknown_options": True}


@app.command(context_settings=CONTEXT_SETTINGS)
def install(
    ctx: typer.Context,
    package_name: Annotated[str, typer.Argument(help="Name of the package to install")],
    use_pip: Annotated[bool, typer.Option("--pip", help="Install with pip.")] = False,
    use_uv: Annotated[bool, typer.Option("--uv", help="Install with uv.")] = False,
    version: version_option = None,
    ecosystem: ecosystem_option = "pypi",
    assume_yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help="Install without asking, even when the analysis reports warnings.",
        ),
    ] = False,
    min_score: Annotated[
        float | None,
        typer.Option(
            "--min-score",
            help="Refuse to install below this safety score (0-100). Tightens the policy.",
        ),
    ] = None,
):
    """Analyze a package, then install it only if it is safe to."""
    manager = _select_manager(use_pip, use_uv)
    specifier = requirement(package_name, version)

    # Resolve the toolchain before spending a minute on the analysis: failing to find pip
    # should not come after a verdict the user was already shown.
    try:
        installer = resolve(manager)
    except InstallerError as e:
        _fail(str(e), "Package Manager Missing")
        raise typer.Exit(code=EXIT_INSTALL_FAILED) from e

    if installer.note:
        console.print(f"[yellow]![/yellow] {installer.note}")

    outcome = run_analysis(console, package_name, version=version, ecosystem=ecosystem)
    log_verdict(outcome)

    score = outcome.score
    gate = evaluate(score, min_score=min_score)
    logger.info(
        "install gate | manager=%s specifier=%s verdict=%s score=%.1f blockers=%d",
        manager.value,
        specifier,
        gate.verdict.value,
        score.final_score,
        len(gate.blockers),
    )

    if gate.blocked:
        _render_blocked(score, gate, specifier)
        raise typer.Exit(code=EXIT_BLOCKED)

    if gate.needs_confirmation:
        if not _approved(gate, assume_yes, specifier, score):
            _render_declined(score, specifier)
            raise typer.Exit(code=EXIT_BLOCKED)
        _render_approved_with_warnings(score, gate, specifier, assume_yes)

    _render_installing(score, specifier, installer)
    command = build_command(installer, specifier, ctx.args)
    try:
        code = run(command, console)
    except InstallerError as e:
        _fail(str(e), "Install Failed")
        raise typer.Exit(code=EXIT_INSTALL_FAILED) from e

    if code != 0:
        _fail(f"{installer.label} exited with code {code}.", "Install Failed")
        raise typer.Exit(code=EXIT_INSTALL_FAILED)

    _render_installed(specifier, installer.label)


# ----------------------------------------------------------------- decisions


def _select_manager(use_pip: bool, use_uv: bool) -> PackageManager:
    """Exactly one package manager, so the command is never ambiguous."""
    if use_pip and use_uv:
        console.print(
            _panel(
                "Choose one package manager: pass [bold]--pip[/bold] or [bold]--uv[/bold], not both.",
                "Conflicting Options",
                "yellow",
            )
        )
        raise typer.Exit(code=2)

    if use_pip:
        return PackageManager.PIP
    if use_uv:
        return PackageManager.UV

    console.print(
        _panel(
            "Say how to install: [bold]--pip[/bold] or [bold]--uv[/bold].",
            "Missing Option",
            "yellow",
        )
    )
    raise typer.Exit(code=2)


def _approved(gate, assume_yes: bool, specifier: str, score) -> bool:
    """Decides a warned-about package, asking the user unless they pre-approved.

    ``--yes`` is the only way to get a warning-level package installed unattended; without
    it a non-interactive run refuses, so a pipeline can never talk its way past a warning.
    """
    if assume_yes:
        return True

    if not can_prompt(console):
        console.print(
            _panel(
                "This package has warnings and there is no terminal to ask.\n"
                "Re-run with [bold]--yes[/bold] to accept the risk, or [bold]--min-score[/bold] to change the bar.",
                "Confirmation Required",
                "yellow",
            )
        )
        return False

    return confirm(
        console,
        f"Install [bold]{specifier}[/bold] anyway "
        f"(safety score {score.final_score:.0f}/100, {gate.verdict.value})?",
    )


# ------------------------------------------------------------------- output


def _render_blocked(score, gate, specifier: str) -> None:
    lines = Text()
    lines.append(f"{specifier}  ", style="bold")
    lines.append(
        f"{score.final_score:.0f}/100  {score.risk_level.value}  {score.decision.value}\n",
        style="bold red",
    )
    for reason in gate.blockers:
        lines.append(f"  • {reason}\n", style="red")
    lines.append(
        f"\nInstall the upstream package instead, or investigate with:\n"
        f"  packsafe inspect {specifier}",
        style="dim",
    )

    console.print()
    console.print(_panel(lines, "Install Blocked", "red"))


def _render_approved_with_warnings(
    score, gate, specifier: str, assume_yes: bool
) -> None:
    """States plainly what is being waved through, before the install runs.

    Approving a warning is the one moment where the user overrides the tool's judgement,
    so the reasons travel with the decision into the log.
    """
    lines = Text()
    for reason in gate.blockers:
        lines.append(f"  • {reason}\n", style="yellow")

    console.print()
    console.print(
        _panel(
            lines,
            "Warnings Accepted" if assume_yes else "Proceeding With Warnings",
            "yellow",
        )
    )
    console.print(
        f"[dim]{specifier} scored {score.final_score:.0f}/100 and is being installed "
        f"anyway.[/dim]\n"
    )


def _render_declined(score, specifier: str) -> None:
    console.print()
    console.print(
        _panel(
            f"Not installing [bold]{specifier}[/bold]. "
            f"Nothing was changed; the safety score was {score.final_score:.0f}/100.",
            "Install Declined",
            "yellow",
        )
    )


def _render_installing(score, specifier: str, installer) -> None:
    style = "green" if score.decision.value == "ALLOW" else "yellow"
    console.print()
    console.print(
        _panel(
            f"Installing [bold]{specifier}[/bold] with {installer.label} "
            f"(safety score {score.final_score:.0f}/100, {score.risk_level.value}).",
            "Install Cleared",
            style,
        )
    )


def _render_installed(specifier: str, manager_label: str) -> None:
    console.print()
    console.print(f"[bold green]✓[/bold green] Installed [bold]{specifier}[/bold].")


def _fail(message: str, title: str) -> None:
    console.print(_panel(message, title, "red"))


def _panel(body, title: str, border: str) -> Panel:
    return Panel(body, title=f"[bold {border}]{title}[/]", border_style=border)
