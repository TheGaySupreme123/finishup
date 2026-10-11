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
* ``compose_bounded`` joins ``required`` parts, then the chosen optional variants, then ``tail``
  parts with ``sep``. Every part is trimmed and an empty part is skipped. ``tail`` is required text
  that must read last (a frontier or a closing instruction).
* Optional items are served in list order: an earlier item has priority over a later one, and a
  later item may still use leftover room that an earlier one could not. Variants are tried in the
  order given (longest first); the first that fits wins; an item with no fitting variant is
  dropped. ``compose_bounded_detail`` reports what was shortened and what was dropped, so a caller
  can say so.
* The required text is never dropped. It is shortened only when it alone exceeds ``limit``, by the
  documented last-resort cut: the longest part loses its tail first and ends with ``marker``;
  once every part is down to the marker the joined text is cut hard and still ends with
  ``marker``. A cut is always visible and is reported as ``cut_required``.

``compose_parts`` is the general form for a builder whose reading order differs from its priority
order: every ``Part`` renders at its list position, but room is granted by priority. A required
part may carry shorter variants too: its shortest variant is reserved first and a longer one is
granted, in priority order, only when room remains.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

__all__ = [
    "DEFAULT_CUT_MARKER",
    "Composition",
    "Part",
    "ascii_safe",
    "clip_to_limit",
    "compose_bounded",
    "compose_bounded_detail",
    "compose_parts",
    "list_variants",
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
class Part:
    """One piece of a composed text.

    ``variants`` are alternative renderings, longest first. A ``required`` part is always present
    (its shortest variant is reserved up front). An optional part is present only when one of its
    variants fits. ``priority`` orders who is granted room first (lower first); it defaults to the
    part's list position, with every required part ahead of every optional one.
    """

    variants: tuple[str, ...]
    required: bool = False
    priority: int | None = None


@dataclass(frozen=True, slots=True)
class Composition:
    """The composed text and what the budget did to the caller's parts.

    Indexes refer to the sequence the caller passed (``optional`` for ``compose_bounded_detail``,
    ``parts`` for ``compose_parts``).
    """

    text: str
    kept: tuple[int, ...]
    shortened: tuple[int, ...]
    dropped: tuple[int, ...]
    cut_required: bool


def _as_variants(item: str | Sequence[str]) -> tuple[str, ...]:
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


def list_variants(
    prefix: str,
    values: Sequence[str],
    *,
    joiner: str = ", ",
    more: str = "; +{n} more",
    suffix: str = "",
    max_variants: int = 64,
) -> tuple[str, ...]:
    """Progressively shorter renderings of a bounded token list, longest first.

    The first variant names every value; each next one names one value fewer and counts the rest
    with ``more`` (``{n}`` is the omitted count). Nothing is returned for an empty list. At most
    ``max_variants`` renderings are produced, so a very long list is thinned rather than costly.
    """

    if not values:
        return ()
    total = len(values)
    counts = list(range(total, 0, -1))
    if len(counts) > max_variants:
        step = -(-len(counts) // max_variants)
        counts = counts[::step]
        if counts[-1] != 1:
            counts.append(1)
    variants: list[str] = []
    for shown in counts:
        omitted = total - shown
        tail = more.format(n=omitted) if omitted else ""
        variants.append(f"{prefix}{joiner.join(values[:shown])}{tail}{suffix}")
    return tuple(variants)


def _joined_length(lengths: Sequence[int], sep: str) -> int:
    if not lengths:
        return 0
    return sum(lengths) + len(sep) * (len(lengths) - 1)


def _cut_longest(parts: list[str], limit: int, sep: str, marker: str) -> bool:
    """Shorten the longest part until the join fits, or every part is down to the marker."""

    cut = False
    while _joined_length([len(part) for part in parts], sep) > limit:
        excess = _joined_length([len(part) for part in parts], sep) - limit
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


def compose_parts(
    parts: Sequence[Part],
    limit: int,
    *,
    sep: str = " ",
    marker: str = DEFAULT_CUT_MARKER,
    ascii_only: bool = True,
) -> Composition:
    """Render ``parts`` in list order, granting room by priority. Never raises."""

    separator = ascii_safe(sep) if ascii_only else sep
    cut_marker = ascii_safe(marker) if ascii_only else marker
    variants: list[tuple[str, ...]] = [
        tuple(
            value
            for value in (_clean(raw, ascii_only=ascii_only) for raw in part.variants)
            if value
        )
        for part in parts
    ]
    # The variant currently granted to each part (None = absent). A required part starts at its
    # shortest variant; an optional part starts absent.
    granted: list[int | None] = [None] * len(parts)
    for index, part in enumerate(parts):
        if part.required and variants[index]:
            lengths = [len(value) for value in variants[index]]
            granted[index] = lengths.index(min(lengths))

    def text_of(index: int) -> str:
        rank = granted[index]
        return "" if rank is None else variants[index][rank]

    present = [index for index, rank in enumerate(granted) if rank is not None]
    base = [text_of(index) for index in present]
    if _joined_length([len(value) for value in base], separator) > limit:
        cut = _cut_longest(base, limit, separator, cut_marker)
        text = separator.join(base)
        if len(text) > limit:
            text = clip_to_limit(text, limit, marker=cut_marker, ascii_only=False)
        return Composition(
            text=text,
            kept=tuple(present),
            shortened=(),
            dropped=tuple(
                index for index, rank in enumerate(granted) if rank is None and variants[index]
            ),
            cut_required=True,
        )
    used = _joined_length([len(value) for value in base], separator)
    count = len(present)
    order = sorted(
        (index for index in range(len(parts)) if variants[index]),
        key=lambda index: (
            0 if parts[index].required else 1,
            parts[index].priority if parts[index].priority is not None else index,
            index,
        ),
    )
    for index in order:
        held = len(text_of(index))
        for rank, value in enumerate(variants[index]):
            if granted[index] is not None and len(value) <= held:
                continue  # not an upgrade over what the part already holds
            extra = len(value) - held
            if granted[index] is None and count > 0:
                extra += len(separator)
            if used + extra > limit:
                continue
            if granted[index] is None:
                count += 1
            granted[index] = rank
            used += extra
            break
    text = separator.join(
        text_of(index) for index in range(len(parts)) if granted[index] is not None
    )
    cut = False
    if len(text) > limit:
        # Unreachable by construction; kept so the contract does not rest on the arithmetic.
        text = clip_to_limit(text, limit, marker=cut_marker, ascii_only=False)
        cut = True
    return Composition(
        text=text,
        kept=tuple(index for index, rank in enumerate(granted) if rank is not None),
        shortened=tuple(index for index, rank in enumerate(granted) if rank),
        dropped=tuple(
            index for index, rank in enumerate(granted) if rank is None and variants[index]
        ),
        cut_required=cut,
    )


def compose_bounded_detail(
    required: Sequence[str | Sequence[str]],
    optional: Sequence[str | Sequence[str]],
    limit: int,
    *,
    sep: str = " ",
    tail: Sequence[str | Sequence[str]] = (),
    marker: str = DEFAULT_CUT_MARKER,
    ascii_only: bool = True,
) -> Composition:
    """Compose within ``limit`` and report what was shortened or dropped. Never raises."""

    head_parts = [Part(_as_variants(item), required=True) for item in _as_items(required)]
    tail_parts = [Part(_as_variants(item), required=True) for item in _as_items(tail)]
    optional_items = _as_items(optional)
    optional_parts = [Part(_as_variants(item), required=False) for item in optional_items]
    offset = len(head_parts)
    result = compose_parts(
        [*head_parts, *optional_parts, *tail_parts],
        limit,
        sep=sep,
        marker=marker,
        ascii_only=ascii_only,
    )
    window = range(offset, offset + len(optional_parts))

    def within(indexes: tuple[int, ...]) -> tuple[int, ...]:
        return tuple(index - offset for index in indexes if index in window)

    return Composition(
        text=result.text,
        kept=within(result.kept),
        shortened=within(result.shortened),
        dropped=within(result.dropped),
        cut_required=result.cut_required,
    )


def _as_items(
    items: str | Sequence[str | Sequence[str]],
) -> tuple[str | Sequence[str], ...]:
    # A bare string passed where a list of parts is expected is one part, not its characters.
    if isinstance(items, str):
        return (items,)
    return tuple(items)


def compose_bounded(
    required: Sequence[str | Sequence[str]],
    optional: Sequence[str | Sequence[str]],
    limit: int,
    *,
    sep: str = " ",
    tail: Sequence[str | Sequence[str]] = (),
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
