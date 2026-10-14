"""Restricted-JCS canonicalization and digest helpers for FinishUP protocol values."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from typing import Final, NoReturn, cast

from finishup.protocol.errors import ProtocolValueError

__all__ = [
    "CanonicalFragment",
    "JsonValue",
    "MAX_JSON_DEPTH",
    "canonical_digest",
    "canonical_encode",
    "canonical_fragment",
    "container_levels",
    "canonical_integer_string",
    "ensure_canonical_set",
    "ensure_canonical_value",
    "entry_digest",
    "parse_canonical_integer_string",
    "request_digest",
    "strict_json_parse",
]

type JsonValue = (
    None | bool | int | str | list[JsonValue] | tuple[JsonValue, ...] | Mapping[str, JsonValue]
)

MAX_JSON_DEPTH: Final = 64

_MAX_SAFE_INTEGER: Final = 2**53 - 1
_MAX_SQLITE_SIGNED_INTEGER: Final = 2**63 - 1
_MIN_SQLITE_SIGNED_INTEGER: Final = -(2**63)
_REQUEST_DIGEST_FENCE_KEYS: Final = frozenset(
    {
        "ingestion_sequence",
        "accepted_at",
        "previous_entry_digest",
        "object_id",
        "ledger",
    }
)
_ACCEPTED_ENTRY_PREIMAGE_KEYS: Final = frozenset(
    {
        "artifact_refs",
        "author",
        "causal_parents",
        "coverage",
        "event_id",
        "evidence_refs",
        "ledger",
        "occurred_at",
        "operation_id",
        "payload_ref",
        "protocol",
        "protocol_version",
        "publication_channel",
        "redaction",
        "schema",
        "session_id",
        "task_id",
        "writer",
    }
)


class CanonicalFragment:
    """The canonical text of one already-validated value, for splicing into a larger value.

    Canonical encoding is compositional: a value's text inside any enclosing document is exactly
    its own canonical text. A caller that re-encodes a large document whose members rarely change
    (the local observation state, issue #689) can therefore encode each immutable member once and
    splice it. Only :func:`canonical_fragment` builds one, from a value this module validated, so
    a fragment can never carry text the profile would reject; parsing never produces one.

    ``levels`` is the deepest relative nesting level that holds a container (``-1`` for a
    scalar), so splicing enforces exactly the nesting bound inline encoding would.
    """

    __slots__ = ("byte_length", "levels", "text")

    def __init__(self, text: str, levels: int, *, _token: object = None) -> None:
        if _token is not _FRAGMENT_TOKEN:
            raise TypeError("canonical_fragment_private")
        self.text = text
        self.levels = levels
        self.byte_length = len(text.encode("utf-8"))

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("canonical_fragment_immutable")
        object.__setattr__(self, name, value)


_FRAGMENT_TOKEN: Final = object()


def canonical_fragment(value: JsonValue | CanonicalFragment) -> CanonicalFragment:
    """Validate and encode *value* once, returning a splice-ready fragment."""

    if type(value) is CanonicalFragment:
        return value
    return CanonicalFragment(
        _canonical_text(value),
        container_levels(value),
        _token=_FRAGMENT_TOKEN,
    )


def container_levels(value: object) -> int:
    """Return the deepest relative level holding a container, or ``-1`` for a scalar.

    A value whose root sits at depth ``d`` satisfies the nesting bound exactly when
    ``d + container_levels(value) < MAX_JSON_DEPTH``.
    """

    if type(value) is CanonicalFragment:
        return value.levels
    if type(value) in {list, tuple}:
        items = cast(Sequence[object], value)
        return 1 + max((container_levels(item) for item in items), default=-1)
    if _is_actual_mapping(value):
        source = cast(Mapping[str, object], value)
        return 1 + max((container_levels(item) for item in source.values()), default=-1)
    return -1


def canonical_encode(value: JsonValue) -> bytes:
    """Encode a restricted canonical JSON value to UTF-8 bytes."""

    return _canonical_text(value).encode("utf-8")


def canonical_digest(value: JsonValue) -> str:
    """Return the SHA-256 digest of the canonical bytes for *value*."""

    return f"sha256:{hashlib.sha256(canonical_encode(value)).hexdigest()}"


def strict_json_parse(data: bytes | bytearray, *, validate: bool = True) -> JsonValue:
    """Parse strict wire JSON into the FinishUP JSON profile.

    ``validate=False`` keeps every lexical check (UTF-8, no NUL byte or BOM, no duplicate key,
    no float or non-finite constant, safe integers) and skips only the final profile walk; the
    caller then owns :func:`ensure_canonical_value` for every subtree it accepts.
    """

    if type(data) is bytearray:
        raw = bytes(data)
    elif type(data) is bytes:
        raw = data
    else:
        raise ProtocolValueError("input_not_bytes")

    if b"\x00" in raw:
        raise ProtocolValueError("nul_byte_forbidden")

    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolValueError("invalid_utf8") from exc

    if text.startswith("\ufeff"):
        raise ProtocolValueError("byte_order_mark_forbidden")

    def _reject_float(_: str) -> NoReturn:
        raise ProtocolValueError("float_forbidden")

    def _reject_constant(_: str) -> NoReturn:
        raise ProtocolValueError("float_forbidden")

    def _parse_int(literal: str) -> int:
        if literal == "-0":
            raise ProtocolValueError("float_forbidden")
        value = int(literal)
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("integer_out_of_safe_range")
        return value

    def _decode_object_pairs(
        pairs: list[tuple[str, object]],
    ) -> dict[str, object]:
        # dict() collapses duplicate keys, so a length mismatch is exactly the
        # duplicate case; the C constructor keeps this hook off the profile of
        # every large-state parse (#290).
        result: dict[str, object] = dict(pairs)
        if len(result) != len(pairs):
            raise ProtocolValueError("duplicate_object_key")
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_decode_object_pairs,
            parse_float=_reject_float,
            parse_int=_parse_int,
            parse_constant=_reject_constant,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolValueError("malformed_json") from exc
    except RecursionError as exc:
        raise ProtocolValueError("nesting_too_deep") from exc

    if validate:
        ensure_canonical_value(cast(JsonValue, parsed))
    return cast(JsonValue, parsed)


def ensure_canonical_value(value: JsonValue, *, depth: int = 0) -> None:
    """Validate a parsed value against the canonical JSON profile.

    ``depth`` is the value's nesting depth inside an enclosing document, so validating a
    document's members one by one enforces exactly the bound validating it whole would.
    """

    _canonical_text(value, depth=depth)


def ensure_canonical_set(values: list[str] | tuple[str, ...]) -> None:
    """Validate a set-valued field without normalizing its order."""

    if not isinstance(cast(object, values), list | tuple):
        raise ProtocolValueError("unsupported_json_type")

    previous: bytes | None = None
    for member in values:
        if type(member) is not str:
            raise ProtocolValueError("set_member_not_ascii")
        try:
            encoded = member.encode("ascii")
        except UnicodeEncodeError as exc:
            raise ProtocolValueError("set_member_not_ascii") from exc
        if previous is not None:
            if encoded == previous:
                raise ProtocolValueError("duplicate_set_member")
            if encoded < previous:
                raise ProtocolValueError("unsorted_set_field")
        previous = encoded


def canonical_integer_string(value: int) -> str:
    """Render a nonnegative integer in canonical decimal form."""

    if type(value) is not int or not 0 <= value <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ProtocolValueError("integer_out_of_sqlite_range")
    return str(value)


def parse_canonical_integer_string(value: str, *, signed: bool = False) -> int:
    """Parse a canonical decimal integer string."""

    if type(value) is not str:
        raise ProtocolValueError("noncanonical_integer_string")

    if not value or len(value) > (20 if signed else 19):
        raise ProtocolValueError("noncanonical_integer_string")

    if signed:
        if value == "-0" or not _matches_integer_pattern(value, signed=True):
            raise ProtocolValueError("noncanonical_integer_string")
    elif not _matches_integer_pattern(value, signed=False):
        raise ProtocolValueError("noncanonical_integer_string")

    parsed = int(value)
    if signed:
        if not _MIN_SQLITE_SIGNED_INTEGER <= parsed <= _MAX_SQLITE_SIGNED_INTEGER:
            raise ProtocolValueError("noncanonical_integer_string")
    elif not 0 <= parsed <= _MAX_SQLITE_SIGNED_INTEGER:
        raise ProtocolValueError("noncanonical_integer_string")
    return parsed


def request_digest(identity: JsonValue) -> str:
    """Digest a logical publication request identity tree."""

    _reject_ledger_assigned_fields(identity)
    ensure_canonical_value(identity)
    return canonical_digest(identity)


def entry_digest(preimage: JsonValue) -> str:
    """Digest an accepted-entry preimage after its exact top-level envelope gate."""

    if not _is_actual_mapping(preimage):
        raise ProtocolValueError("not_an_accepted_envelope")
    source = cast(Mapping[str, JsonValue], preimage)
    try:
        if frozenset(source) != _ACCEPTED_ENTRY_PREIMAGE_KEYS:
            raise ProtocolValueError("not_an_accepted_envelope")
        protocol = source["protocol"]
    except ProtocolValueError:
        raise
    except Exception as exc:
        raise ProtocolValueError("not_an_accepted_envelope") from exc

    # Frozen legacy identifier (ADR-048): the recorded event envelope protocol tag.
    if type(protocol) is not str or protocol != "yoetz.event":
        raise ProtocolValueError("not_an_accepted_envelope")

    ensure_canonical_value(source)
    return canonical_digest(source)


def _matches_integer_pattern(value: str, *, signed: bool) -> bool:
    if signed:
        if value == "0":
            return True
        if value.startswith("-"):
            digits = value[1:]
        else:
            digits = value
        return bool(digits) and digits[0] != "0" and _is_ascii_digits(digits)
    return value == "0" or (value[0] != "0" and _is_ascii_digits(value))


def _is_ascii_digits(value: str) -> bool:
    return all("0" <= character <= "9" for character in value)


def _reject_ledger_assigned_fields(value: JsonValue) -> None:
    def _walk(node: JsonValue, depth: int) -> None:
        if _is_actual_mapping(node):
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            source = cast(Mapping[str, JsonValue], node)
            for key, item in source.items():
                if type(key) is str and key in _REQUEST_DIGEST_FENCE_KEYS:
                    raise ProtocolValueError("ledger_assigned_field_in_request_identity")
                _walk(item, depth + 1)
            return
        if type(node) is list:
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            for item in node:
                _walk(cast(JsonValue, item), depth + 1)
        elif type(node) is tuple:
            if depth >= MAX_JSON_DEPTH:
                raise ProtocolValueError("nesting_too_deep")
            for item in node:
                _walk(cast(JsonValue, item), depth + 1)

    _walk(value, 0)


def _canonical_text(value: JsonValue | CanonicalFragment, *, depth: int = 0) -> str:
    if type(value) is CanonicalFragment:
        if value.levels >= 0 and depth + value.levels >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        return value.text
    if value is None:
        return "null"
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is int:
        if not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            raise ProtocolValueError("integer_out_of_safe_range")
        return str(value)
    if _is_actual_float(value):
        raise ProtocolValueError("float_forbidden")
    if type(value) is str:
        return _encode_string(value)
    if type(value) in {list, tuple}:
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        sequence = cast(Sequence[JsonValue], value)
        return "[" + ",".join(_canonical_text(item, depth=depth + 1) for item in sequence) + "]"
    if _is_actual_mapping(value):
        if depth >= MAX_JSON_DEPTH:
            raise ProtocolValueError("nesting_too_deep")
        source = cast(Mapping[str, JsonValue], value)
        items: list[tuple[bytes, str, JsonValue]] = []
        for key, item in source.items():
            if type(key) is not str:
                raise ProtocolValueError("object_key_not_string")
            _validate_string(key)
            items.append((key.encode("utf-16-be"), key, item))
        items.sort(key=lambda entry: entry[0])
        return (
            "{"
            + ",".join(
                f"{_encode_string(key)}:{_canonical_text(item, depth=depth + 1)}"
                for _, key, item in items
            )
            + "}"
        )
    raise ProtocolValueError("unsupported_json_type")


def _is_actual_mapping(value: object) -> bool:
    try:
        return issubclass(type(value), Mapping)
    except BaseException:
        return False


def _is_actual_float(value: object) -> bool:
    try:
        return issubclass(type(value), float)
    except BaseException:
        return False


# One C-level scan replaces the per-character Python loops below for the
# overwhelmingly common plain string; both fall back to the exact original
# logic when a match is found, so output and error identity never change.
# The per-character loops dominated hook wall time on a ~1 MiB state (#290).
_INVALID_STRING_CHARS: Final = re.compile("[\\u0000\\ud800-\\udfff]")
_ESCAPED_STRING_CHARS: Final = re.compile("[\\u0000-\\u001f\\u0022\\u005c\\ud800-\\udfff]")


def _validate_string(value: str) -> None:
    matched = _INVALID_STRING_CHARS.search(value)
    if matched is None:
        return
    if matched.group() == "\x00":
        raise ProtocolValueError("nul_byte_forbidden")
    raise ProtocolValueError("lone_surrogate")


def _encode_string(value: str) -> str:
    if _ESCAPED_STRING_CHARS.search(value) is None:
        # Nothing to escape and nothing to reject: the escaped-character
        # class is a superset of the invalid-character class.
        return f'"{value}"'
    _validate_string(value)
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
