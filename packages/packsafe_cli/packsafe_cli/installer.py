"""Resolving and running the package manager behind `packsafe install`.

Kept apart from the command so the gate decision (should we install at all?) and the
mechanics (how and where do we install?) can be reasoned about and tested separately.
Nothing here makes a security decision: by the time this module runs, the package has
already been cleared or explicitly approved by a human.

The central rule is that an install lands in the environment belonging to the directory
the command was run in. A bare ``pip`` on PATH, or the interpreter running PackSafe
itself, are both wrong targets: one is usually a system install, the other is the tool's
own virtualenv. Putting a vetted package into either is its own supply-chain accident.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

from rich.console import Console

logger = logging.getLogger(__name__)

# uv's pip-compatible interface targets an environment, which is the closest equivalent
# to `pip install`. `uv add` would instead edit the project's pyproject.toml, a different
# operation with its own tradeoffs.
UV_SUBCOMMAND = ("pip", "install")

INSTALL_SUBCOMMAND = ("install",)

#: The conventional project-local environment, checked when none is active.
LOCAL_ENV_DIR = ".venv"

VIRTUAL_ENV_VAR = "VIRTUAL_ENV"


class PackageManager(str, Enum):
    """A supported package manager."""

    PIP = "pip"
    UV = "uv"

    @property
    def executable(self) -> str:
        return "pip" if self is PackageManager.PIP else "uv"


@dataclass(frozen=True)
class Target:
    """The environment an install will land in, and how that was decided."""

    python: Path
    origin: str

    @property
    def description(self) -> str:
        return f"{self.python} (from {self.origin})"


@dataclass(frozen=True)
class Installer:
    """A resolved package manager: the argv prefix that performs an install.

    ``note`` carries anything the user should know about how the install will be applied,
    such as relying on a package manager newer than the project may have.
    """

    manager: PackageManager
    target: Target
    argv_prefix: tuple[str, ...]
    note: str | None = None

    @property
    def label(self) -> str:
        return self.manager.value


class InstallerError(RuntimeError):
    """The install cannot proceed, with a reason worth showing."""


def resolve_target(
    explicit: str | Path | None = None,
    *,
    cwd: Path | None = None,
) -> Target:
    """Decides which environment the install belongs to.

    Precedence, strongest intent first: an explicit ``--python``, then an activated
    ``VIRTUAL_ENV``, then a project-local ``.venv``. When two of those disagree the
    activated environment wins, because activating a venv is a deliberate act while a
    ``.venv`` directory is often just left lying around.

    Raises rather than guessing: with no environment in sight, falling back to a global
    install would put the package somewhere the user did not ask for, which is precisely
    the surprise this module exists to prevent.
    """
    base = cwd or Path.cwd()

    if explicit:
        python = _interpreter(explicit)
        logger.info("install target | --python %s", python)
        return Target(python, "--python")

    active = os.environ.get(VIRTUAL_ENV_VAR)
    if active:
        python = _interpreter(active)
        logger.info("install target | %s=%s", VIRTUAL_ENV_VAR, active)
        return Target(python, f"${VIRTUAL_ENV_VAR}")

    local = base / LOCAL_ENV_DIR
    if local.exists():
        python = _interpreter(local)
        logger.info("install target | local %s", local)
        return Target(python, LOCAL_ENV_DIR)

    raise InstallerError(
        f"No Python environment found for {base}.\n"
        f"Create one with [bold]uv venv[/bold] (or [bold]python -m venv {LOCAL_ENV_DIR}[/bold]), "
        f"activate one, or point at it with [bold]--python[/bold]."
    )


def _interpreter(env: str | Path) -> Path:
    """Finds the interpreter inside an environment directory, or validates an explicit one.

    Accepts either a venv directory or a path straight to an interpreter, because both
    are things a person will reasonably type.

    The path is made absolute but deliberately *not* resolved: a virtualenv's
    ``bin/python`` is normally a symlink to the base interpreter, and resolving it would
    hand the package manager the shared base environment instead of the venv - silently
    installing outside the directory the user pointed at.
    """
    path = Path(env).expanduser()

    if path.is_file():
        return path.absolute()

    if not path.is_dir():
        raise InstallerError(f"No such environment or interpreter: {path}")

    scripts = path / ("Scripts" if os.name == "nt" else "bin")
    for name in ("python", "python3", "python.exe"):
        interpreter = scripts / name
        if interpreter.exists():
            return interpreter.absolute()

    # A bare interpreter name on PATH was also acceptable input.
    located = shutil.which(path.name)
    if located:
        return Path(located).absolute()

    raise InstallerError(
        f"{path} looks like a directory but contains no Python interpreter. "
        f"Expected one at {scripts / 'python'}."
    )


def resolve(manager: PackageManager, target: Target) -> Installer:
    """Builds the argv prefix for this manager, targeting the chosen environment."""
    if manager is PackageManager.UV:
        executable = require_on_path(manager)
        return Installer(
            manager,
            target,
            (executable, *UV_SUBCOMMAND, "--python", str(target.python)),
        )

    return _resolve_pip(target)


def _resolve_pip(target: Target) -> Installer:
    """Prefers the target environment's own pip, then PATH pip with an explicit target.

    A virtualenv created by ``uv venv`` has no pip at all, so PATH pip with
    ``--python`` is the fallback rather than an edge case.
    """
    scripts = target.python.parent
    local_pip = shutil.which("pip", path=str(scripts))

    if local_pip:
        logger.info("pip resolved from target env | %s", local_pip)
        return Installer(PackageManager.PIP, target, (local_pip, *INSTALL_SUBCOMMAND))

    executable = require_on_path(PackageManager.PIP)
    logger.info(
        "pip resolved from PATH | %s (target env has no pip; using --python)",
        executable,
    )
    # --python is a pip-wide option and must precede the subcommand. After `install` pip
    # rejects it with "must be placed before the pip subcommand name".
    return Installer(
        PackageManager.PIP,
        target,
        (executable, "--python", str(target.python), *INSTALL_SUBCOMMAND),
        note=(
            "The target environment has no pip of its own, so PATH pip was used with "
            "--python. That needs pip 22.3 or newer."
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


def current_interpreter() -> Path:
    """The interpreter running PackSafe, for diagnostics in the install panel."""
    return Path(sys.executable)
