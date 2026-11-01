"""Differential equivalence for the canonical string fast paths (#290).

``_validate_string`` and ``_encode_string`` replaced per-character Python loops
with a single regex scan plus a fallback to the original logic. The codec is
load-bearing for digests, manifests, and stored identities, so a character
class that is off by one codepoint silently changes every downstream identity
rather than failing loudly. These cases pin the fast paths against the
pre-change implementations — reproduced verbatim below — over every BMP
codepoint plus the surrogate, control, and astral boundaries, comparing both
the emitted bytes and the identity of the raised error.
"""

from __future__ import annotations

import random
from collections.abc import Callable

import pytest

from finishup.protocol.canonical import (
    _encode_string,  # pyright: ignore[reportPrivateUsage]
    _validate_string,  # pyright: ignore[reportPrivateUsage]
)
from finishup.protocol.errors import ProtocolValueError


def _reference_validate_string(value: str) -> None:
    """The pre-#290 implementation, verbatim."""

    for character in value:
        codepoint = ord(character)
        if codepoint == 0:
            raise ProtocolValueError("nul_byte_forbidden")
        if 0xD800 <= codepoint <= 0xDFFF:
            raise ProtocolValueError("lone_surrogate")


def _reference_encode_string(value: str) -> str:
    """The pre-#290 implementation, verbatim."""

    _reference_validate_string(value)
    parts: list[str] = ['"']
    for character in value:
        codepoint = ord(character)
        if character == '"':
            parts.append(r"\"")
        elif character == "\\":
            parts.append(r"\\")
        elif codepoint == 0x08:
            parts.append(r"\b")
        elif codepoint == 0x09:
            parts.append(r"\t")
        elif codepoint == 0x0A:
            parts.append(r"\n")
        elif codepoint == 0x0C:
            parts.append(r"\f")
        elif codepoint == 0x0D:
            parts.append(r"\r")
        elif 0x01 <= codepoint <= 0x1F:
            parts.append(f"\\u{codepoint:04x}")
        else:
            parts.append(character)
    parts.append('"')
    return "".join(parts)


def _outcome(operation: Callable[[str], object], value: str) -> object:
    """Return the value or the exact identity of the error, never both."""

    try:
        return ("ok", operation(value))
    except ProtocolValueError as exc:
        return ("error", type(exc).__name__, str(exc), exc.args)


_PAIRS: tuple[tuple[Callable[[str], object], Callable[[str], object]], ...] = (
    (_validate_string, _reference_validate_string),
    (_encode_string, _reference_encode_string),
)


def _assert_equivalent(value: str) -> None:
    for fast, reference in _PAIRS:
        assert _outcome(fast, value) == _outcome(reference, value), (
            f"{fast.__name__} diverged on {value!r}"
        )


def test_every_bmp_codepoint_encodes_identically() -> None:
    """Any character-class boundary error shows up here, alone or embedded."""

    for codepoint in range(0x0000, 0x10000):
        character = chr(codepoint)
        _assert_equivalent(character)
        _assert_equivalent("a" + character + "b")


@pytest.mark.parametrize(
    "value",
    [
        "",
        "plain",
        "\x00",
        "a\x00",
        "\ud800",
        "\udbff",
        "\udc00",
        "\udfff",
        # First offender wins: the fast path reports the same one the loop did.
        "\x00\ud800",
        "\ud800\x00",
        'a"\x00',
        "a\\\ud800",
        "\x1f\x00",
        "\x00\x1f",
        '"',
        "\\",
        "\x07\x08\x09\x0a\x0b\x0c\x0d\x0e",
        "\x1f\x20\x7f",
        "\U0001f600",
        "\U0010ffff",
        "\U00010000",
        "  ﻿￿",
        "x" * 4_096,
        "x" * 4_096,
        "x" * 4_096 + '"',
        '"' + "x" * 4_096,
        "x" * 2_048 + "\x00" + "x" * 2_048,
        "x" * 2_048 + "\ud800" + "x" * 2_048,
    ],
)
def test_boundary_strings_encode_identically(value: str) -> None:
    _assert_equivalent(value)


def test_astral_codepoints_are_not_mistaken_for_surrogates() -> None:
    """Astral characters are single codepoints, never a surrogate pair here."""

    for codepoint in range(0x10000, 0x110000, 1_021):
        _assert_equivalent(chr(codepoint))
        _assert_equivalent('\\"' + chr(codepoint))


def test_random_boundary_weighted_strings_encode_identically() -> None:
    alphabet = (
        [chr(code) for code in range(0x00, 0x25)]
        + ['"', "\\", "/", "a", "Z", "0", "é", "€", "中", "\x7f", "\x80"]
        + [chr(code) for code in (0xD7FF, 0xD800, 0xDBFF, 0xDC00, 0xDFFF, 0xE000)]
        + ["\U0001f600", "\U0010ffff"]
    )
    rng = random.Random(290)
    for _ in range(20_000):
        length = rng.choice((0, 1, 2, 3, 7, 17, 64))
        _assert_equivalent("".join(rng.choice(alphabet) for _ in range(length)))
