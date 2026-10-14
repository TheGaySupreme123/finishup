"""Spliced canonical fragments are byte- and error-identical to inline encoding (#689).

The local observation store re-encodes a large document whose immutable members rarely change,
so it encodes each member once and splices the text. The codec is load-bearing for digests and
stored identities, so these cases pin the splice against inline encoding: the emitted bytes, the
nesting bound, and the fact that no caller can forge a fragment's text.
"""

from __future__ import annotations

import random

import pytest

from finishup.protocol.canonical import (
    MAX_JSON_DEPTH,
    CanonicalFragment,
    JsonValue,
    canonical_digest,
    canonical_encode,
    canonical_fragment,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError

_VALUES: tuple[JsonValue, ...] = (
    None,
    True,
    0,
    -(2**53 - 1),
    "",
    'quote " backslash \\ control \x01 newline \n',
    "BMP ￿ astral \U0001f600 mixed",
    [],
    {},
    [1, [2, [3, {"k": None}]]],
    {"\U0001f600": 1, "￿": 2, "a": {"z": [], "b": "x"}},
)


def _outcome(value: JsonValue) -> bytes | str:
    try:
        return canonical_encode(value)
    except ProtocolValueError as error:
        return f"error:{error}"


@pytest.mark.parametrize("value", _VALUES)
def test_splicing_is_byte_identical_in_every_position(value: JsonValue) -> None:
    fragment = canonical_fragment(value)
    assert fragment.text.encode("utf-8") == canonical_encode(value)
    assert fragment.byte_length == len(canonical_encode(value))
    inline: JsonValue = {"z": [value, {"nested": value}], "a": value}
    spliced: JsonValue = {"z": [fragment, {"nested": fragment}], "a": fragment}  # pyright: ignore[reportAssignmentType]
    assert canonical_encode(spliced) == canonical_encode(inline)
    assert canonical_digest(spliced) == canonical_digest(inline)
    assert strict_json_parse(canonical_encode(spliced)) == strict_json_parse(
        canonical_encode(inline)
    )
    # A fragment of a fragment-bearing value splices the same bytes again.
    assert canonical_fragment(spliced).text == canonical_encode(inline).decode("utf-8")  # pyright: ignore[reportArgumentType]


def test_random_documents_splice_identically() -> None:
    generator = random.Random(689)

    def build(depth: int) -> JsonValue:
        kind = generator.randrange(6 if depth < 6 else 3)
        if kind == 0:
            return generator.choice((None, True, False))
        if kind == 1:
            return generator.randrange(-(2**31), 2**31)
        if kind == 2:
            return "".join(
                chr(generator.choice((0x22, 0x5C, 0x0A, 0x41, 0xE9, 0xFFFF, 0x1F600)))
                for _ in range(generator.randrange(8))
            )
        if kind == 3:
            return [build(depth + 1) for _ in range(generator.randrange(4))]
        return {f"k{generator.randrange(50)}": build(depth + 1) for _ in range(4)}

    for _ in range(200):
        members = [build(0) for _ in range(5)]
        inline: JsonValue = {"members": members}
        spliced: JsonValue = {"members": [canonical_fragment(item) for item in members]}  # pyright: ignore[reportAssignmentType]
        assert canonical_encode(spliced) == canonical_encode(inline)


@pytest.mark.parametrize("levels", (60, 62, 63))
@pytest.mark.parametrize("wraps", range(4))
def test_nesting_bound_matches_inline_encoding_exactly(levels: int, wraps: int) -> None:
    deep: JsonValue = 0
    for _ in range(levels):
        deep = [deep]
    fragment = canonical_fragment(deep)
    inline: JsonValue = deep
    spliced: JsonValue = fragment  # pyright: ignore[reportAssignmentType]
    for _ in range(wraps):
        inline = {"k": inline}
        spliced = {"k": spliced}
    assert _outcome(spliced) == _outcome(inline)


def test_invalid_values_never_become_fragments() -> None:
    too_deep: JsonValue = 0
    for _ in range(MAX_JSON_DEPTH + 1):
        too_deep = [too_deep]
    for invalid in ("\x00", "\ud800", 2**53, too_deep):
        with pytest.raises(ProtocolValueError):
            canonical_fragment(invalid)


def test_fragments_cannot_be_forged_or_mutated() -> None:
    with pytest.raises(TypeError, match="canonical_fragment_private"):
        CanonicalFragment('{"forged":1}', 0)
    fragment = canonical_fragment({"a": 1})
    with pytest.raises(AttributeError, match="canonical_fragment_immutable"):
        fragment.text = "{}"
    assert canonical_fragment(fragment) is fragment  # pyright: ignore[reportArgumentType]
