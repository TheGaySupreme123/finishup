"""Prove a reviewer quote against the exact text the provider received (issue #976).

A reviewer quote is admitted as evidence only when it is text the provider was actually sent.
The test used to be a raw substring test. That rejected quotes that were faithful copies of what
the reviewer read but differed in transport form: the packet carries most rows as JSON documents,
so a quoted sentence containing a newline, an apostrophe outside ASCII or an escaped double quote
never matched the encoded row; a reviewer reflowed whitespace; or a reviewer quoting across
Yoetz's own ``[REDACTED]`` marker spelled the marker differently.

The tolerant match below closes those gaps without loosening what a quote proves:

* Both sides are compared after the same normalization: typographic quotes and dashes folded to
  ASCII and every whitespace run collapsed to one space. Letters, digits and case are never
  changed, and no character may be skipped or elided.
* A row whose content is a JSON document is also searched through its decoded string values, which
  is the text the reviewer read inside the encoding.
* A redaction placeholder in the quote matches only Yoetz's own ``[REDACTED]`` marker at the same
  position in the sent text. A quote that is nothing but a placeholder proves nothing.

The admitted snippet is the exact span the quote matched, never the reviewer's spelling of it:
verbatim sent text, or, for a JSON row, verbatim text of one of its decoded strings (the text the
reviewer read inside the encoding). A span carrying control
or format characters (NUL, bidirectional overrides, lone surrogates) is never admitted.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable, Iterator
from typing import Final, cast

from yoetz.protocol.canonical import strict_json_parse
from yoetz.protocol.models import MAX_REVIEW_TEXT_BYTES

__all__ = ["REDACTION_MARKER", "prove_quote"]

REDACTION_MARKER: Final = "[REDACTED]"
# Placeholder spellings a reviewer uses for a withheld span. Only these are folded to Yoetz's
# marker; each still has to line up with a real marker in the sent text.
_PLACEHOLDER: Final = re.compile(
    r"\[\s*redacted[^\]\n]{0,32}\]|<\s*redacted\s*>|\(\s*redacted\s*\)", re.IGNORECASE
)
_FOLD: Final = {
    "‘": "'",
    "’": "'",
    "‚": "'",
    "‛": "'",
    "′": "'",
    "“": '"',
    "”": '"',
    "„": '"',
    "‟": '"',
    "″": '"',
    "‐": "-",
    "‑": "-",
    "‒": "-",
    "–": "-",
    "—": "-",
    "―": "-",
    "−": "-",
}
_UNESCAPED_QUOTE: Final = re.compile(r'(?<!\\)"')
# JSON documents larger than this are searched in their raw form only; decoding is bounded work.
_MAX_DECODE_BYTES: Final = 262_144
_MAX_JSON_STRINGS: Final = 4_096
# A quote with more placeholders than this is matched exactly or not at all.
_MAX_PLACEHOLDERS: Final = 16


def _normalized(text: str) -> tuple[str, tuple[int, ...]]:
    """Normalize *text* and map every normalized character back to its source index.

    Only the explicit fold table and whitespace collapse apply: no compatibility decomposition, so
    a letter or digit is never rewritten (``x²`` never matches ``x2``). A collapsed space maps to
    the first whitespace character of its run, so a span ending or starting on it trims cleanly.
    """

    out: list[str] = []
    index: list[int] = []
    space_at: int | None = None
    for position, char in enumerate(text):
        if char.isspace():
            if out and space_at is None:
                space_at = position
            continue
        if space_at is not None:
            out.append(" ")
            index.append(space_at)
            space_at = None
        out.append(_FOLD.get(char, char))
        index.append(position)
    return "".join(out), tuple(index)


def _admissible_span(span: str) -> bool:
    """A recorded quote must be valid UTF-8 text without control or format characters."""

    try:
        encoded = span.encode("utf-8")
    except UnicodeEncodeError:
        return False
    if not 1 <= len(encoded) <= MAX_REVIEW_TEXT_BYTES:
        return False
    return not any(
        unicodedata.category(char) in {"Cc", "Cf", "Cs", "Co", "Cn"} and char not in "\t\n\r"
        for char in span
    )


def _json_strings(text: str) -> Iterator[str]:
    """Decoded string values (and keys) of a JSON document, else nothing."""

    stripped = text.lstrip()
    if not stripped.startswith(("{", "[")) or len(text) > _MAX_DECODE_BYTES:
        return
    try:
        document = strict_json_parse(text.encode("utf-8"), validate=False)
    except ValueError, UnicodeEncodeError:
        return
    stack: list[object] = [document]
    emitted = 0
    while stack and emitted < _MAX_JSON_STRINGS:
        node = stack.pop()
        if isinstance(node, str):
            emitted += 1
            yield node
        elif isinstance(node, dict):
            for key, value in cast(dict[str, object], node).items():
                emitted += 1
                yield key
                stack.append(value)
        elif isinstance(node, (list, tuple)):
            stack.extend(cast(Iterable[object], node))


def _quote_variants(quote: str) -> tuple[str, ...]:
    """The quote as written, plus its JSON-unescaped form when it was copied from encoded text."""

    variants = [quote]
    if "\\" in quote:
        decoded: object = None
        for wrapped in (quote, _UNESCAPED_QUOTE.sub('\\"', quote)):
            try:
                decoded = strict_json_parse(('"' + wrapped + '"').encode("utf-8"), validate=False)
            except ValueError, UnicodeEncodeError:
                continue
            break
        if isinstance(decoded, str) and decoded and decoded != quote:
            variants.append(decoded)
    return tuple(variants)


def _pattern(quote: str) -> re.Pattern[str] | None:
    """A literal pattern for the normalized quote with placeholders bound to the real marker.

    Each marker may be separated from its neighbour by at most one optional space, emitted once,
    so the pattern has no ambiguous adjacent optional parts and matches in linear time.
    """

    segments = _PLACEHOLDER.split(quote)
    if len(segments) == 1:
        normalized, _ = _normalized(quote)
        return re.compile(re.escape(normalized)) if normalized else None
    if len(segments) - 1 > _MAX_PLACEHOLDERS:
        return None
    texts = [_normalized(segment)[0] for segment in segments]
    # A quote made only of placeholders (and whitespace) is not evidence of anything sent.
    if not any(texts):
        return None
    pieces: list[str] = []
    for position, text in enumerate(texts):
        if text:
            if position > 0:
                pieces.append(" ?")  # between the previous marker and this text
            pieces.append(re.escape(text))
        if position < len(texts) - 1:
            if text or position > 0:
                pieces.append(" ?")  # between this text (or the previous marker) and the marker
            pieces.append(re.escape(REDACTION_MARKER))
    return re.compile("".join(pieces))


def _match_in(patterns: list[re.Pattern[str]], text: str) -> str | None:
    normalized, index = _normalized(text)
    for pattern in patterns:
        found = pattern.search(normalized)
        if found is None or found.end() == found.start():
            continue
        span = text[index[found.start()] : index[found.end() - 1] + 1]
        # Trim the collapsed-space edges a placeholder pattern may have absorbed.
        span = span.strip()
        if span and _admissible_span(span):
            return span
    return None


def prove_quote(quote: str, texts: Iterable[str]) -> str | None:
    """Return the exact sent span *quote* matches in *texts*, or ``None`` if it is unproven.

    An exact substring is returned unchanged. Otherwise the tolerant match described in the module
    docstring runs over each sent text and the decoded strings of any JSON document among them.
    The returned span is verbatim sent (or decoded JSON) text, free of control characters, within a recorded
    quote's byte bound.
    """

    candidates = tuple(texts)
    if not quote or not candidates:
        return None
    if not _normalized(_PLACEHOLDER.sub(" ", quote))[0]:
        # Only placeholders and whitespace: exact or not, it is evidence of nothing sent.
        return None
    if any(quote in text for text in candidates):
        return quote if _admissible_span(quote) else None
    patterns = [
        pattern for variant in _quote_variants(quote) if (pattern := _pattern(variant)) is not None
    ]
    if not patterns:
        return None
    for text in candidates:
        for searchable in (text, *_json_strings(text)):
            span = _match_in(patterns, searchable)
            if span is not None:
                return span
    return None
