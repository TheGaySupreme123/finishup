"""Recorded positions of FinishUP's own replacement markers (#1248, owner decision P-D1).

Whenever FinishUP writes a replacement marker into text it records the span it wrote. The scanner
exempts exactly those spans, so nothing about a marker is inferred from its text or from the
escapes around it: a marker-shaped value FinishUP did not write at that position, or one written
before positions were recorded, is judged like any other value.

A span is a pair of UTF-8 byte offsets ``(start, end)`` into the bytes it was recorded for. A
review packet's spans are recorded in the packet's own bytes. Where those bytes travel inside a
JSON string (the reviewer conversation, a provider request body) the spans are carried through
that string's escapes by its exact offset map, never re-derived.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from typing import Final

from finishup.protocol.canonical import canonical_encode

__all__ = [
    "MarkerSpans",
    "container_marker_spans",
    "decoded_string_spans",
    "encoded_string_spans",
    "packet_row_marker_spans",
    "packet_rows_marker_spans",
    "shift_marker_spans",
    "valid_marker_spans",
]

MarkerSpans = tuple[tuple[int, int], ...]

# FinishUP's own fixed markers: ``[REDACTED]`` and the possible-credential placeholder. Kept here
# (and asserted equal to the scanner's) so this module has no import cycle with the scanner.
_MARKERS: Final = frozenset({b"[REDACTED]", b"[withheld-by-yoetz:possible-credential]"})
_MAX_SPANS: Final = 65_536
_WHITESPACE: Final = re.compile(rb"[ \t\r\n]*")
_STRING: Final = re.compile(rb'"(?:[^"\\]|\\.)*"', re.DOTALL)
_SCALAR: Final = re.compile(rb"-?[0-9][0-9.eE+-]*|true|false|null")
_MAX_DEPTH: Final = 64


def valid_marker_spans(data: bytes, spans: Iterable[tuple[int, int]]) -> MarkerSpans:
    """``spans`` that each cover exactly one FinishUP marker in ``data``, sorted, deduplicated.

    A span whose bytes are not a marker, or one out of range or overlapping another, is dropped:
    a bad record can only take an exemption away, never grant one.
    """

    kept: list[tuple[int, int]] = []
    for start, end in sorted(set(spans)):
        if (
            type(start) is not int
            or type(end) is not int
            or not 0 <= start < end <= len(data)
            or data[start:end] not in _MARKERS
            or (kept and start < kept[-1][1])
        ):
            continue
        kept.append((start, end))
        if len(kept) >= _MAX_SPANS:
            break
    return tuple(kept)


def shift_marker_spans(spans: Iterable[tuple[int, int]], offset: int) -> MarkerSpans:
    return tuple((start + offset, end + offset) for start, end in spans)


def _token_offsets(token: bytes) -> tuple[list[int], list[int]]:
    """For a JSON string token: the encoded offset of each decoded byte boundary, and back.

    ``encoded[d]`` is where decoded byte ``d`` starts in ``token``; ``decoded[e]`` the decoded
    byte that encoded byte ``e`` starts (``-1`` inside an escape). Both include the end.
    """

    encoded: list[int] = []
    decoded = [-1] * (len(token) + 1)
    index, end = 1, len(token) - 1
    while index < end:
        decoded[index] = len(encoded)
        if token[index] != 0x5C:
            encoded.append(index)
            index += 1
            continue
        escape = token[index + 1]
        if escape != 0x75:
            encoded.append(index)
            index += 2
            continue
        code = int(token[index + 2 : index + 6], 16)
        width = 6
        if 0xD800 <= code < 0xDC00 and token[index + 6 : index + 8] == b"\\u":
            low = int(token[index + 8 : index + 12], 16)
            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
            width = 12
        encoded.extend([index] * len(chr(code).encode("utf-8", "surrogatepass")))
        index += width
    decoded[end] = len(encoded)
    encoded.append(end)
    return encoded, decoded


def encoded_string_spans(token: bytes, spans: Iterable[tuple[int, int]]) -> MarkerSpans:
    """Spans of the decoded text carried to their offsets inside its JSON string ``token``."""

    encoded, _decoded = _token_offsets(token)
    out: list[tuple[int, int]] = []
    for start, end in spans:
        if 0 <= start < end < len(encoded):
            # A marker has no byte JSON escapes, so it stays one contiguous run of equal length.
            mapped = (encoded[start], encoded[end])
            if mapped[1] - mapped[0] == end - start:
                out.append(mapped)
    return tuple(out)


def decoded_string_spans(token: bytes, spans: Iterable[tuple[int, int]]) -> MarkerSpans:
    """Spans inside a JSON string ``token`` carried to its decoded text."""

    _encoded, decoded = _token_offsets(token)
    out: list[tuple[int, int]] = []
    for start, end in spans:
        if 0 < start < end < len(decoded) and decoded[start] >= 0 and decoded[end] >= 0:
            mapped = (decoded[start], decoded[end])
            if mapped[1] - mapped[0] == end - start:
                out.append(mapped)
    return tuple(out)


def container_marker_spans(container: bytes, packet: bytes, spans: MarkerSpans) -> MarkerSpans:
    """``spans`` of ``packet`` wherever ``container`` carries that exact packet.

    ``container`` is the packet itself, or JSON that holds the packet as one string (the reviewer
    conversation, a provider request body). The string is found by the packet's own exact
    encoding, which no other content can equal, and every occurrence carries the same spans.
    """

    if not spans:
        return ()
    if container == packet:
        return spans
    try:
        token = canonical_encode(packet.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return ()
    inner = encoded_string_spans(token, spans)
    out: list[tuple[int, int]] = []
    found = container.find(token)
    while found >= 0 and len(out) < _MAX_SPANS:
        out.extend(shift_marker_spans(inner, found))
        found = container.find(token, found + len(token))
    return valid_marker_spans(container, out)


# -- review packets ---------------------------------------------------------------------------


class _Unparsed(ValueError):
    pass


_Path = tuple[str | int, ...]


def _skip(data: bytes, index: int) -> int:
    match = _WHITESPACE.match(data, index)
    return index if match is None else match.end()


def _value(data: bytes, index: int, path: _Path, strings: list[tuple[int, int, _Path]]) -> int:
    """Parse one JSON value at ``index``; collect every string value's token span and path."""

    if len(path) > _MAX_DEPTH:
        raise _Unparsed
    index = _skip(data, index)
    lead = data[index : index + 1]
    if lead == b"{":
        index = _skip(data, index + 1)
        if data[index : index + 1] == b"}":
            return index + 1
        while True:
            key = _STRING.match(data, index)
            if key is None:
                raise _Unparsed
            name = key.group()[1:-1].decode("utf-8", "replace")
            index = _skip(data, key.end())
            if data[index : index + 1] != b":":
                raise _Unparsed
            index = _skip(data, _value(data, index + 1, (*path, name), strings))
            if data[index : index + 1] == b",":
                index = _skip(data, index + 1)
                continue
            if data[index : index + 1] != b"}":
                raise _Unparsed
            return index + 1
    if lead == b"[":
        index = _skip(data, index + 1)
        if data[index : index + 1] == b"]":
            return index + 1
        position = 0
        while True:
            index = _skip(data, _value(data, index, (*path, position), strings))
            position += 1
            if data[index : index + 1] == b",":
                index += 1
                continue
            if data[index : index + 1] != b"]":
                raise _Unparsed
            return index + 1
    if lead == b'"':
        match = _STRING.match(data, index)
        if match is None:
            raise _Unparsed
        strings.append((index, match.end(), path))
        return match.end()
    match = _SCALAR.match(data, index)
    if match is None:
        raise _Unparsed
    return match.end()


def _strings(document: bytes) -> list[tuple[int, int, _Path]]:
    """Every string value of a JSON ``document``, by token span and path; empty when invalid."""

    strings: list[tuple[int, int, _Path]] = []
    try:
        end = _value(document, 0, (), strings)
    except (_Unparsed, IndexError, ValueError, RecursionError):
        return []
    if _skip(document, end) != len(document):
        return []
    return strings


def _rows(strings: list[tuple[int, int, _Path]], packet: bytes) -> dict[int, tuple[str, int, int]]:
    """Each root ``items`` row: its position, ``item_id`` and content token span."""

    ids: dict[int, str] = {}
    contents: dict[int, tuple[int, int]] = {}
    for start, end, path in strings:
        if len(path) == 3 and path[0] == "items" and type(path[1]) is int:
            if path[2] == "item_id":
                ids[path[1]] = packet[start + 1 : end - 1].decode("utf-8", "replace")
            elif path[2] == "content":
                contents[path[1]] = (start, end)
    return {row: (ids[row], *contents[row]) for row in sorted(contents) if row in ids}


def _decoded_value(token: bytes) -> str | None:
    try:
        value = json.loads(token)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return None
    return value if type(value) is str else None


def packet_rows_marker_spans(
    packet: bytes,
    content_spans: Mapping[str, Iterable[tuple[int, int]]],
    *,
    envelope: bytes = b"",
    envelope_spans: MarkerSpans = (),
) -> MarkerSpans:
    """The recorded spans of every marker FinishUP wrote into a review packet, in its bytes.

    ``content_spans`` maps a row's ``item_id`` to spans in that row's decoded content; only the
    packet root's ``items`` rows are read, by position, never content that merely looks like a
    row. ``envelope_spans`` are spans in the structural ``envelope`` document the packet was
    assembled from: each is carried, with the envelope string it sits in, to wherever the packet
    outside its rows holds that same FinishUP-written string.
    """

    strings = _strings(packet)
    out: list[tuple[int, int]] = []
    for item_id, start, end in _rows(strings, packet).values():
        spans = content_spans.get(item_id)
        if spans:
            out.extend(shift_marker_spans(encoded_string_spans(packet[start:end], spans), start))
    carried: dict[str, MarkerSpans] = {}
    if envelope_spans:
        for start, end, _path in _strings(envelope):
            inside = tuple(
                (s - start, e - start) for s, e in envelope_spans if start < s and e < end
            )
            value = _decoded_value(envelope[start:end]) if inside else None
            if value is not None:
                carried[value] = decoded_string_spans(envelope[start:end], inside)
    if carried:
        for start, end, path in strings:
            if path[:1] == ("items",):
                continue
            value = _decoded_value(packet[start:end])
            if value is not None and value in carried:
                out.extend(
                    shift_marker_spans(
                        encoded_string_spans(packet[start:end], carried[value]), start
                    )
                )
    return valid_marker_spans(packet, out)


def packet_row_marker_spans(packet: bytes, spans: MarkerSpans) -> dict[str, MarkerSpans]:
    """The inverse for rows: each row's spans in its own decoded content, by ``item_id``."""

    out: dict[str, MarkerSpans] = {}
    if not spans:
        return out
    for item_id, start, end in _rows(_strings(packet), packet).values():
        inside = tuple((s - start, e - start) for s, e in spans if start < s and e < end)
        if inside:
            out[item_id] = decoded_string_spans(packet[start:end], inside)
    return out
