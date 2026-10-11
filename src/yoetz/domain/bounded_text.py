"""One never-raising composer for every size-bounded, agent-facing text (tb4n3 RC-2, #1025).

Before this module each bounded builder (the MCP summaries, the Stop-gate text, the receipt
renderings) appended its optional clauses with no budget, budgeted only the late list-shaped ones,
and then enforced the bound by raising or by discarding everything. A data-only change that filled
one optional clause therefore turned the closing ``check`` of a run into ``INTERNAL_ERROR`` while
the check itself had committed (tb4n3: 10 of 13 deterministic runs).

``compose_bounded`` inverts that: the **required** parts are reserved first, then each **optional**
item (given as progressively shorter variants) takes the longest variant that still fits beside
everything already reserved, in priority order. It does not raise for any input.

Contract
--------
* ``limit`` counts characters. With ``ascii_only=True`` (the default) every output character is
  ASCII, so characters and bytes agree and a ``.encode("ascii")`` of the result cannot fail.
* ``required`` parts, then the chosen optional variants, then ``tail`` parts are joined with
  ``sep`` in that order. Every part is trimmed and an empty part is skipped. ``tail`` is required
  text that must read last (a frontier or a closing instruction); it exists only so a caller does
  not have to place optional text in front of it by hand.
* Optional items are served in list order: an earlier item has priority over a later one, and a
  later item may still use leftover room that an earlier one could not. Variants are tried in the
  order given (longest first); the first that fits wins; an item with no fitting variant is
  dropped. The result reports what was shortened and what was dropped, so a caller can say so.
* The required text is never dropped. It is shortened only when it alone exceeds ``limit``, by the
  documented last-resort cut: the longest part loses its tail first and ends with ``marker``;
  once every part is down to the marker the joined text is cut hard and still ends with
  ``marker``. A cut is always visible and is reported as ``cut_required``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DEFAULT_CUT_MARKER",
    "Composition",
    "ascii_safe",
    "clip_to_limit",
    "compose_bounded",
    "compose_bounded_detail",
]

DEFAULT_CUT_MARKER: Final = "..."

# Typographic characters that real prose and platform messages carry; folded to the plain ASCII a
# bounded text uses. Anything else non-ASCII becomes ``?`` rather than raising.
_ASCII_FOLD: Final = str.maketrans(
    {
        "‘": "'",
        "’": "'",
        "‚": "'",
        "“": '"',
        "”": '"',
        "„": '"',
        "‐": "-",
        "‑": "-",
        "‒": "-",
        "–": "-",
        "—": "-",
        "―": "-",
        "−": "-",
        "…": "...",
        " ": " ",
        "•": "*",
        "→": "->",
        "←": "<-",
        "×": "x",
    }
)


def ascii_safe(text: str) -> str:
    """Return ``text`` as printable ASCII: typographic punctuation folded, the rest ``?``.

    Control characters other than newline and tab become ``?`` too. Never raises, including for a
    lone surrogate.
    """

    folded = text.translate(_ASCII_FOLD)
    ascii_text = folded.encode("ascii", errors="replace").decode("ascii")
    if ascii_text.isprintable():
        return ascii_text
    return "".join(char if char in "\n\t" or char.isprintable() else "?" for char in ascii_text)


@dataclass(frozen=True, slots=True)
class Composition:
    """The composed text and what the budget did to the caller's optional items."""

    text: str
    # Indexes into the ``optional`` argument.
    kept: tuple[int, ...]
    shortened: tuple[int, ...]
    dropped: tuple[int, ...]
    cut_required: bool


def _variants(item: str | Sequence[str]) -> tuple[str, ...]:
    # A bare string is one variant, never a sequence of characters.
    if isinstance(item, str):
        return (item,)
    return tuple(item)


def _clean(text: str, *, ascii_only: bool) -> str:
    return (ascii_safe(text) if ascii_only else text).strip()


def clip_to_limit(
    text: str,
    limit: int,
    *,
    marker: str = DEFAULT_CUT_MARKER,
    ascii_only: bool = True,
) -> str:
    """Cut ``text`` to at most ``limit`` characters, ending with ``marker`` when it was cut."""

    value = ascii_safe(text) if ascii_only else text
    if limit <= 0:
        return ""
    if len(value) <= limit:
        return value
    if limit <= len(marker):
        return marker[:limit]
    return value[: limit - len(marker)] + marker


def _joined_length(parts: Sequence[str], sep: str) -> int:
    if not parts:
        return 0
    return sum(len(part) for part in parts) + len(sep) * (len(parts) - 1)


def _cut_longest(parts: list[str], limit: int, sep: str, marker: str) -> bool:
    """Shorten the longest part until the join fits, or every part is down to the marker."""

    cut = False
    while _joined_length(parts, sep) > limit:
        excess = _joined_length(parts, sep) - limit
        index = -1
        longest = len(marker)
        for position, part in enumerate(parts):
            if len(part) > longest:
                index, longest = position, len(part)
        if index < 0:
            break
        part = parts[index]
        target = max(len(marker), len(part) - excess)
        parts[index] = part[: target - len(marker)] + marker
        cut = True
    return cut


def compose_bounded_detail(
    required: Sequence[str],
    optional: Sequence[str | Sequence[str]],
    limit: int,
    *,
    sep: str = " ",
    tail: Sequence[str] = (),
    marker: str = DEFAULT_CUT_MARKER,
    ascii_only: bool = True,
) -> Composition:
    """Compose within ``limit`` and report what was shortened or dropped. Never raises."""

    separator = ascii_safe(sep) if ascii_only else sep
    cut_marker = ascii_safe(marker) if ascii_only else marker
    head = [
        part for part in (_clean(raw, ascii_only=ascii_only) for raw in _variants(required)) if part
    ]
    foot = [
        part for part in (_clean(raw, ascii_only=ascii_only) for raw in _variants(tail)) if part
    ]
    core = head + foot
    cut = False
    if _joined_length(core, separator) > limit:
        cut = _cut_longest(core, limit, separator, cut_marker)
        if _joined_length(core, separator) > limit:
            # Many tiny parts, or separators alone, exceed the budget: one hard cut of the join.
            hard = clip_to_limit(separator.join(core), limit, marker=cut_marker, ascii_only=False)
            return Composition(
                text=hard,
                kept=(),
                shortened=(),
                dropped=tuple(range(len(optional))),
                cut_required=True,
            )
        head, foot = core[: len(head)], core[len(head) :]
    remaining = limit - _joined_length(head + foot, separator)
    present = len(head) + len(foot)
    chosen: list[tuple[int, str]] = []
    shortened: list[int] = []
    dropped: list[int] = []
    for index, raw_item in enumerate(optional):
        variants = [
            variant
            for variant in (_clean(raw, ascii_only=ascii_only) for raw in _variants(raw_item))
            if variant
        ]
        picked: str | None = None
        for rank, variant in enumerate(variants):
            cost = len(variant) + (len(separator) if present + len(chosen) > 0 else 0)
            if cost <= remaining:
                picked = variant
                remaining -= cost
                if rank > 0:
                    shortened.append(index)
                break
        if picked is None:
            dropped.append(index)
        else:
            chosen.append((index, picked))
    text = separator.join(head + [value for _, value in chosen] + foot)
    if len(text) > limit:
        # Unreachable by construction; kept so the contract does not rest on the arithmetic.
        text = clip_to_limit(text, limit, marker=cut_marker, ascii_only=False)
        cut = True
    return Composition(
        text=text,
        kept=tuple(index for index, _ in chosen),
        shortened=tuple(shortened),
        dropped=tuple(dropped),
        cut_required=cut,
    )


def compose_bounded(
    required: Sequence[str],
    optional: Sequence[str | Sequence[str]],
    limit: int,
    *,
    sep: str = " ",
    tail: Sequence[str] = (),
    marker: str = DEFAULT_CUT_MARKER,
    ascii_only: bool = True,
) -> str:
    """Compose ``required`` plus as much of ``optional`` as fits in ``limit``. Never raises.

    ``required`` is kept (cut only as the module docstring documents). Each ``optional`` item is a
    list of progressively shorter variants, served in priority order: the longest variant that
    still fits wins, else the next, else the item is dropped. ``tail`` is required text placed
    after the optional items.
    """

    return compose_bounded_detail(
        required,
        optional,
        limit,
        sep=sep,
        tail=tail,
        marker=marker,
        ascii_only=ascii_only,
    ).text
