"""Layout primitives shared by the PackSafe reports.

Both `analyze` and `inspect` need the same two things - a titled separator between
sections and an aligned field/value block - so they live here rather than being copied
into each renderer.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from datetime import date, datetime
from enum import Enum
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.text import Text

from .theme import FIELD_LABEL_STYLE, FIELD_VALUE_STYLE, RULE_STYLE, SECTION_TITLE

# Longest label we lay out for without shrinking the gap; wider labels just push the
# value column right, which keeps the block readable instead of truncating the label.
MAX_FIELD_LABEL = 22

UNKNOWN = "unknown"


def section(console: Console, title: str) -> None:
    """Prints a blank line and a titled rule: the separator between sections."""
    console.print()
    console.rule(Text(title, style=SECTION_TITLE), style=RULE_STYLE, align="left")


def field_table(
    rows: Iterable[tuple[str, Any]],
    *,
    width: int = MAX_FIELD_LABEL,
    indent: int = 2,
) -> Table:
    """Builds an aligned ``label  value`` block.

    A ``None`` value is dropped rather than rendered, so a section shows only the facts
    that were actually collected. Use :data:`UNKNOWN` for a field that is known to be
    absent - that distinction is the whole point of an evidence view.
    """
    table = Table.grid(padding=(0, 2))
    table.add_column(style=FIELD_LABEL_STYLE, no_wrap=True, width=width)
    table.add_column(style=FIELD_VALUE_STYLE, overflow="fold")

    for label, value in rows:
        if value is None:
            continue
        table.add_row(label, _cell(value))

    table.indent = indent
    return table


def print_fields(console: Console, rows: Iterable[tuple[str, Any]], **kwargs: Any) -> None:
    """Convenience wrapper around :func:`field_table` for direct printing."""
    console.print(field_table(rows, **kwargs))


def _cell(value: Any) -> Text | str:
    """Renders one field value, keeping rich markup out of raw evidence strings.

    Evidence fields carry URLs, snippets and advisory text gathered from third parties.
    Printing them through markup would let a package name or a code fragment in that
    text be interpreted as console styling, so anything non-numeric is plain text.
    """
    if isinstance(value, Text):
        return value
    # Enums render as "EcosystemType.pypi" through str(); evidence wants the value.
    if isinstance(value, Enum):
        value = value.value
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, datetime):
        return f"{value:%Y-%m-%d %H:%M} UTC"
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, int):
        return f"{value:,}"
    if isinstance(value, (list, tuple)):
        return ", ".join(str(item) for item in value) if value else UNKNOWN
    # Collapse embedded newlines: a registry field carrying a multi-line body (a whole
    # license text, a long description) would otherwise inject hard line breaks into the
    # grid and break the alignment of every row below it.
    return " ".join(str(value).split())


def bullet(content: Text | str) -> Text:
    """A dimmed bullet marker followed by its content; the caller sets the indent.

    Returned rather than printed so the caller can wrap it in ``Padding`` and keep a long
    value's continuation lines indented too.
    """
    line = Text("· ", style="bright_black")
    if isinstance(content, Text):
        line.append_text(content)
    else:
        line.append(content)
    return line


def joined(values: Sequence[str], limit: int = 4) -> str:
    """Joins a short list, counting what was dropped instead of hiding it."""
    present = [v for v in values if v]
    if not present:
        return UNKNOWN
    if len(present) <= limit:
        return ", ".join(present)
    return f"{', '.join(present[:limit])} +{len(present) - limit} more"
