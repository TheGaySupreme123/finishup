"""Width-aware text helpers shared by every FinishUP terminal view.

Narrow terminals are a first-class case, not a degradation: a path is more
useful with its head and tail than with either half, and a description is more
useful wrapped than clipped. These helpers are pure so the layout decisions they
encode can be asserted directly instead of through a rendered screen.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from typing import Final

__all__ = [
    "ELLIPSIS",
    "middle_truncate",
    "pad_columns",
    "truncate",
    "wrap",
]

ELLIPSIS: Final = "…"
_MIN_TRUNCATED: Final = 2


def truncate(value: str, width: int) -> str:
    """Clip ``value`` to ``width`` columns, marking the loss with an ellipsis."""

    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width < _MIN_TRUNCATED:
        return ELLIPSIS[:width]
    return value[: width - 1] + ELLIPSIS


def middle_truncate(value: str, width: int) -> str:
    """Keep the head and tail of ``value``, dropping the middle.

    Used for filesystem paths and executable locations, where the leading
    directory and the final component both carry identity and the middle rarely
    does.
    """

    if width <= 0:
        return ""
    if len(value) <= width:
        return value
    if width <= _MIN_TRUNCATED:
        return ELLIPSIS[:width]
    remaining = width - 1
    head = (remaining + 1) // 2
    tail = remaining - head
    if tail == 0:
        return value[:head] + ELLIPSIS
    return value[:head] + ELLIPSIS + value[len(value) - tail :]


def wrap(value: str, width: int) -> tuple[str, ...]:
    """Word-wrap ``value`` to ``width`` columns without breaking on hyphens.

    A word longer than the whole width is hard-split rather than allowed to
    overflow the pane; that keeps a stray digest or URL from forcing the body to
    scroll sideways.
    """

    if width <= 0:
        return ()
    words = value.split()
    if not words:
        return ("",)
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= width:
            current = candidate
            continue
        if current:
            lines.append(current)
            current = ""
        while len(word) > width:
            lines.append(word[:width])
            word = word[width:]
        current = word
    if current:
        lines.append(current)
    return tuple(lines)


def pad_columns(rows: Iterable[Sequence[str]], *, gap: int = 2) -> tuple[str, ...]:
    """Left-align ragged rows into aligned columns with a fixed gap.

    Used by the readiness and status listings, where the label column must line
    up but the value column is free text of unknown length.
    """

    materialized = [tuple(row) for row in rows]
    if not materialized:
        return ()
    columns = max(len(row) for row in materialized)
    widths = [0] * columns
    for row in materialized:
        for index, cell in enumerate(row):
            widths[index] = max(widths[index], len(cell))
    lines: list[str] = []
    for row in materialized:
        parts: list[str] = []
        for index, cell in enumerate(row):
            # The final populated cell never carries trailing padding.
            if index == len(row) - 1:
                parts.append(cell)
            else:
                parts.append(cell.ljust(widths[index]))
        lines.append((" " * gap).join(parts).rstrip())
    return tuple(lines)
