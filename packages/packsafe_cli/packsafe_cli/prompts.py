"""Interactive prompts, and the rules for when PackSafe is allowed to ask one.

A security tool that installs packages must never hang a pipeline. Every prompt goes
through here so the "can we ask?" decision is made in exactly one place: a terminal that
can answer is the only place a question is allowed to exist.

Only ``install`` prompts. It is about to modify an environment, so asking permission is
the point rather than an obstacle. ``analyze`` and ``inspect`` never ask: they report, and
a report that stops for a keypress would hang in CI and would produce different output
depending on whether a human was watching.
"""

from __future__ import annotations

import sys

from rich.console import Console
from rich.prompt import Confirm


def can_prompt(console: Console) -> bool:
    """True only when a human is actually there to answer.

    Both sides matter: a redirected stdout means the answer is not going to a person, and
    a redirected stdin means there is nothing to read an answer from.
    """
    return console.is_interactive and sys.stdin.isatty()


def confirm(console: Console, question: str, *, default: bool = False) -> bool:
    """Asks a yes/no question, answering ``default`` when nobody can respond.

    Never raises for an unreachable or closed stdin: a cancelled prompt is a refusal to
    proceed, not a crash.
    """
    if not can_prompt(console):
        return default

    try:
        return Confirm.ask(question, default=default, console=console)
    except (EOFError, KeyboardInterrupt):
        # Ctrl-C at a prompt means "stop", not "yes".
        console.print()
        return False
