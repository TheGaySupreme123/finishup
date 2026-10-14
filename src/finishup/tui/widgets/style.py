"""Turn the pure renderers' plain lines into styled terminal text.

Colour is applied in exactly one place, keyed on the leading status symbol, so
that ``render.py`` can stay a pure string function and no widget can pick its
own meaning for green. The palette is the restrained one the product asks for:
cyan for things you can act on, green only for verified success, yellow for
limitations and unproven states, red for blocks and failures, dim for anything
secondary.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Final

from rich.text import Text

from finishup.tui.symbols import Level, symbol_for

__all__ = ["COLOURS", "styled", "styled_line"]

COLOURS: Final[dict[Level, str]] = {
    Level.SELECTED: "bold cyan",
    Level.ACTIVE: "cyan",
    Level.VERIFIED: "green",
    Level.UNPROVEN: "yellow",
    Level.BLOCKED: "red",
    Level.OPTIONAL: "bright_black",
}

_BY_SYMBOL: Final[dict[str, Level]] = {symbol_for(level): level for level in Level}

# Lines that are purely secondary information read better dimmed whole.
_DIM_PREFIXES: Final[tuple[str, ...]] = ("    ", "  · ", "· ")


def styled_line(line: str) -> Text:
    """Style one rendered line according to its leading symbol, if any."""

    stripped = line.lstrip()
    indent = len(line) - len(stripped)
    if stripped[:1] in _BY_SYMBOL and stripped[1:2] in {" ", ""}:
        level = _BY_SYMBOL[stripped[0]]
        text = Text(" " * indent)
        text.append(stripped[0], style=COLOURS[level])
        remainder = stripped[1:]
        if level is Level.SELECTED:
            text.append(remainder, style="bold")
        else:
            text.append(remainder)
        return text
    if line.startswith(_DIM_PREFIXES) and line.strip():
        return Text(line, style="bright_black")
    if stripped.startswith("/") and " " in stripped:
        # A command token followed by its plain-language description.
        token, _, description = stripped.partition(" ")
        text = Text(" " * indent)
        text.append(token, style="cyan")
        text.append(" " + description.lstrip(), style="bright_black")
        return text
    return Text(line)


def styled(lines: Iterable[str]) -> Text:
    """Join rendered lines into one styled block."""

    result = Text()
    for index, line in enumerate(lines):
        if index:
            result.append("\n")
        result.append_text(styled_line(line))
    return result
