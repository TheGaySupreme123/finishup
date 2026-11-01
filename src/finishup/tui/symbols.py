"""Status symbols and the restrained colour vocabulary of the FinishUP terminal UI.

The symbol set is deliberately tiny and load-bearing: it is the only place the
interface is allowed to make a claim about how sure FinishUP is. ``VERIFIED`` means
a postcondition was actually observed; ``UNPROVEN`` means a step was configured
but never demonstrated. Nothing in the presentation layer may upgrade one to the
other, so both the glyph and the style live here rather than at each call site.
"""

from __future__ import annotations

from enum import Enum
from typing import Final

__all__ = [
    "STYLE_COMMAND",
    "STYLE_DIM",
    "STYLE_FAILURE",
    "STYLE_SELECTED",
    "STYLE_SUCCESS",
    "STYLE_WARNING",
    "Level",
    "style_for",
    "symbol_for",
]

# Rich style names resolved by the stylesheet; kept as tokens so pure render
# helpers stay free of any Textual import.
STYLE_SELECTED: Final = "finishup-selected"
STYLE_COMMAND: Final = "finishup-command"
STYLE_SUCCESS: Final = "finishup-success"
STYLE_WARNING: Final = "finishup-warning"
STYLE_FAILURE: Final = "finishup-failure"
STYLE_DIM: Final = "finishup-dim"


class Level(Enum):
    """How sure FinishUP is about one line of the interface."""

    SELECTED = "selected"
    """Cursor position in a temporary picker."""

    ACTIVE = "active"
    """Work is running right now."""

    VERIFIED = "verified"
    """A postcondition was observed. Never used for 'configured' alone."""

    UNPROVEN = "unproven"
    """Configured, limited, stale, or simply never demonstrated."""

    BLOCKED = "blocked"
    """Failed, refused, or stopped by a safety boundary."""

    OPTIONAL = "optional"
    """Not configured, disabled, or deliberately switched off."""


_SYMBOLS: Final[dict[Level, str]] = {
    Level.SELECTED: "›",
    Level.ACTIVE: "•",
    Level.VERIFIED: "✓",
    Level.UNPROVEN: "!",
    Level.BLOCKED: "■",
    Level.OPTIONAL: "○",
}

_STYLES: Final[dict[Level, str]] = {
    Level.SELECTED: STYLE_SELECTED,
    Level.ACTIVE: STYLE_COMMAND,
    Level.VERIFIED: STYLE_SUCCESS,
    Level.UNPROVEN: STYLE_WARNING,
    Level.BLOCKED: STYLE_FAILURE,
    Level.OPTIONAL: STYLE_DIM,
}


def symbol_for(level: Level) -> str:
    """Return the single display glyph for one certainty level."""

    return _SYMBOLS[level]


def style_for(level: Level) -> str:
    """Return the stylesheet token for one certainty level."""

    return _STYLES[level]
