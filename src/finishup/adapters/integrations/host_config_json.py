"""Read host-owned JSON configuration for observation only (#1278).

Hosts own files such as Claude Code's ``.claude.json`` and Cursor's ``mcp.json``, and they write
values FinishUP's wire profile does not admit: Claude Code records decimal costs, frame rates and
feature-flag rates beside the ``mcpServers`` tables FinishUP reads. The strict wire parser rejects
the whole file for one such number, which turned every used Claude Code installation into an
unreadable, ``ambiguous`` MCP owner.

This reader keeps the structural checks that matter for ownership decisions (UTF-8 only, no NUL
byte or byte-order mark, no duplicate key, bounded nesting) and replaces each value the canonical
profile cannot hold (a decimal or non-finite number, an integer outside the safe range) with
``null``. FinishUP reads only string and table fields from these files, so a replaced number never
reaches an ownership or launcher decision.

Use it for read-only observation. Every read-modify-write path keeps
:func:`finishup.protocol.canonical.strict_json_parse` and refuses such a file, so a lossy read can
never be written back over the host's own values.
"""

from __future__ import annotations

import json
from typing import Final, cast

from finishup.protocol.canonical import MAX_JSON_DEPTH, JsonValue, ensure_canonical_value
from finishup.protocol.errors import ProtocolValueError

_MAX_SAFE_INTEGER: Final = 2**53 - 1


class _Unrepresentable:
    """Marks one host value the canonical profile cannot hold; replaced by ``null``."""


_UNREPRESENTABLE: Final = _Unrepresentable()


def parse_host_config_json(data: bytes) -> JsonValue:
    """Parse one host-owned JSON document, nulling values outside the canonical profile."""

    if type(data) is not bytes:
        raise ProtocolValueError("input_not_bytes")
    if b"\x00" in data:
        raise ProtocolValueError("nul_byte_forbidden")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ProtocolValueError("invalid_utf8") from exc
    if text.startswith("﻿"):
        raise ProtocolValueError("byte_order_mark_forbidden")

    def _number(_: str) -> object:
        return _UNREPRESENTABLE

    def _integer(literal: str) -> object:
        value = int(literal)
        if literal == "-0" or not -_MAX_SAFE_INTEGER <= value <= _MAX_SAFE_INTEGER:
            return _UNREPRESENTABLE
        return value

    def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ProtocolValueError("duplicate_object_key")
        return result

    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_pairs,
            parse_float=_number,
            parse_int=_integer,
            parse_constant=_number,
        )
    except json.JSONDecodeError as exc:
        raise ProtocolValueError("malformed_json") from exc
    except RecursionError as exc:
        raise ProtocolValueError("nesting_too_deep") from exc
    value = _replace(parsed, depth=0)
    ensure_canonical_value(value)
    return value


def _replace(value: object, *, depth: int) -> JsonValue:
    if value is _UNREPRESENTABLE:
        return None
    if depth > MAX_JSON_DEPTH:
        raise ProtocolValueError("nesting_too_deep")
    if isinstance(value, dict):
        return {
            key: _replace(item, depth=depth + 1)
            for key, item in cast(dict[str, object], value).items()
        }
    if isinstance(value, list):
        return [_replace(item, depth=depth + 1) for item in cast(list[object], value)]
    return cast(JsonValue, value)
