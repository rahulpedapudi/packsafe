"""Resolving and running the package manager behind `packsafe install`.

Kept apart from the command so the gate decision (should we install at all?) and the
mechanics (how do we install?) can be reasoned about and tested separately. Nothing here
makes a security decision: by the time this module runs, the package has already been
cleared or explicitly approved by a human.
"""

from __future__ import annotations

import importlib.util
import logging
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum

from rich.console import Console

logger = logging.getLogger(__name__)

# uv's pip-compatible interface targets an environment, which is the closest equivalent
# to `pip install`. `uv add` would instead edit the project's pyproject.toml, a different
# operation with its own tradeoffs.
UV_SUBCOMMAND = ("pip", "install")

INSTALL_SUBCOMMAND = ("install",)


class PackageManager(str, Enum):
    """A supported package manager."""

    PIP = "pip"
    UV = "uv"

    @property
    def executable(self) -> str:
        return "pip" if self is PackageManager.PIP else "uv"


@dataclass(frozen=True)
class Installer:
    """A resolved package manager: the argv prefix that performs an install.

    ``note`` carries anything the user should know about where the install will land,
    which matters most when the package manager turns out to belong to a different
    environment than the one running PackSafe.
    """

    manager: PackageManager
    argv_prefix: tuple[str, ...]
    note: str | None = None

    @property
    def label(self) -> str:
        return self.manager.value


class InstallerError(RuntimeError):
    """The requested package manager cannot be used, with a reason worth showing."""


def resolve(manager: PackageManager) -> Installer:
    """Works out how to invoke the package manager, or explains why it cannot be used.

    Resolved before the analysis runs, so the user is not shown a clean verdict and then
    told at the last step that the tool is missing.
    """
    if manager is PackageManager.UV:
        return Installer(manager, (require_on_path(manager), *UV_SUBCOMMAND))
    return _resolve_pip()


def _resolve_pip() -> Installer:
    """Prefers the pip belonging to the interpreter running PackSafe.

    A bare ``pip`` on PATH is frequently a different environment's - a shim, a system
    install, another virtualenv - and installing a vetted package into the wrong
    environment is its own kind of supply-chain accident. Falling back to PATH pip is
    still allowed, but the caller is told, because the user can no longer assume the
    install landed next to PackSafe.
    """
    if importlib.util.find_spec("pip") is not None:
        return Installer(
            PackageManager.PIP, (sys.executable, "-m", "pip", *INSTALL_SUBCOMMAND)
        )

    executable = require_on_path(PackageManager.PIP)
    logger.info(
        "pip resolved from PATH | %s (no pip in %s)", executable, sys.executable
    )
    return Installer(
        PackageManager.PIP,
        (executable, *INSTALL_SUBCOMMAND),
        note=(
            f"pip came from PATH and may target a different environment than "
            f"{sys.executable}; the install may not land next to PackSafe."
        ),
    )


def require_on_path(manager: PackageManager) -> str:
    path = shutil.which(manager.executable)
    if not path:
        raise InstallerError(
            f"{manager.value} was not found on PATH. "
            f"Install {manager.value}, or re-run with the other package manager."
        )

    logger.info("package manager resolved | %s -> %s", manager.value, path)
    return path


def build_command(
    installer: Installer,
    requirement: str,
    extra_args: Sequence[str] = (),
) -> list[str]:
    """Builds the argv for an install.

    ``requirement`` is a pinned specifier (``name`` or ``name==version``) so the artifact
    that was analyzed is the artifact that gets installed.
    """
    return [*installer.argv_prefix, requirement, *extra_args]


def run(command: Sequence[str], console: Console) -> int:
    """Runs the installer, streaming its output, and returns its exit code.

    Output is streamed rather than captured so a slow download shows progress instead of
    a frozen terminal, and so the installer speaks for itself when it fails. Markup and
    highlighting are disabled on its output: those lines are package names and URLs from
    a third party, not console syntax.
    """
    logger.info("installing | %s", " ".join(command))
    console.print(f"[dim]Running:[/dim] [bold]{' '.join(command)}[/bold]")

    try:
        # argv list, never a shell string: package names and forwarded arguments are
        # untrusted input and must not reach a shell.
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
    except OSError as e:
        raise InstallerError(f"Could not start {command[0]}: {e}") from e

    assert process.stdout is not None  # guaranteed by stdout=PIPE above
    with process.stdout:
        for line in process.stdout:
            console.print(line.rstrip(), markup=False, highlight=False)

    return process.wait()


def requirement(name: str, version: str | None) -> str:
    """The exact specifier to install: what was analyzed is what gets installed."""
    return f"{name}=={version}" if version else name
