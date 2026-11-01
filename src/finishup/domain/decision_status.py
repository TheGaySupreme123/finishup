"""The decision-point ledger line (#1139): counted records, never a correctness claim.

The kernel composes the line from closed tokens, counts and service-minted obligation ids only, so
every reader may echo it after this re-gate. Free of pydantic: the Stop hook path imports it.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

__all__ = [
    "STATUS_LINE_DETAIL",
    "STATUS_LINE_PREFIX",
    "compose_status_line",
    "find_status_line",
    "named",
    "safe_status_line",
]

STATUS_LINE_PREFIX: Final = "Ledger (records, not correctness): "
STATUS_LINE_DETAIL: Final = "per-obligation detail: status view=obligations."
# The parts never contain "." or "=", so the fixed tail ends the line unambiguously.
_BODY: Final = r"[a-z0-9_ ,;:()+-]{1,1900}?"
_LINE: Final = re.compile(
    re.escape(STATUS_LINE_PREFIX) + _BODY + re.escape(STATUS_LINE_DETAIL), re.ASCII
)
# At most this many ids per counted part; the rest are counted as "+N more".
NAMED_IDS: Final = 2


def named(count: int, label: str, ids: Sequence[str]) -> str:
    """``"<count> <label>"`` with at most ``NAMED_IDS`` ids; empty for a zero count."""

    if count <= 0:
        return ""
    shown = tuple(ids[:NAMED_IDS])
    if not shown:
        return f"{count} {label}"
    more = f" +{len(ids) - len(shown)} more" if len(ids) > len(shown) else ""
    return f"{count} {label} ({', '.join(shown)}{more})"


def compose_status_line(parts: Sequence[str]) -> str:
    """Join non-empty parts after the fixed prefix and before the fixed detail pointer."""

    body = "; ".join(part for part in parts if part)
    if not body:
        return ""
    line = f"{STATUS_LINE_PREFIX}{body}; {STATUS_LINE_DETAIL}"
    return line if _LINE.fullmatch(line) is not None else ""


def safe_status_line(value: object) -> str:
    """The line when ``value`` is exactly one well-formed line; otherwise empty."""

    return value if type(value) is str and _LINE.fullmatch(value) is not None else ""


def find_status_line(text: object) -> str:
    """The first well-formed line inside a longer service-composed body (a receipt section)."""

    if type(text) is not str:
        return ""
    found = _LINE.search(text)
    return "" if found is None else found.group(0)
