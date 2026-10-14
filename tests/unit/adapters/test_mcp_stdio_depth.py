"""Bounded nesting for the MCP stdio frame parser (#394)."""

from __future__ import annotations

import json
import sys

import pytest

from finishup.adapters import mcp_stdio as transport
from finishup.adapters.mcp_stdio import MAX_JSON_NESTING_DEPTH, TransportFailure
from finishup.protocol.canonical import MAX_JSON_DEPTH


def _frame(params: object) -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": 1, "method": "ping", "params": params},
        separators=(",", ":"),
    ).encode("utf-8")


def _nested_arrays(levels: int) -> bytes:
    return b"[" * levels + b"]" * levels


def _frame_with_nested_params(array_levels: int) -> bytes:
    # Root object (1) -> params object (2) -> "a" arrays (3 ..).
    prefix = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":{"a":'
    return prefix + _nested_arrays(array_levels) + b"}}"


def test_depth_bound_is_the_canonical_codec_bound() -> None:
    assert MAX_JSON_NESTING_DEPTH == MAX_JSON_DEPTH == 64


def test_frame_at_the_exact_nesting_bound_is_admitted() -> None:
    # 2 container levels of envelope + (MAX - 2) array levels == MAX total.
    frame = _frame_with_nested_params(MAX_JSON_NESTING_DEPTH - 2)
    message = transport._parse_frame(frame)  # pyright: ignore[reportPrivateUsage]
    assert message.message.model_dump(by_alias=True)["id"] == 1


def test_frame_one_level_past_the_bound_is_invalid_json() -> None:
    frame = _frame_with_nested_params(MAX_JSON_NESTING_DEPTH - 1)
    with pytest.raises(TransportFailure) as caught:
        transport._parse_frame(frame)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_json"


def test_nesting_past_the_interpreter_recursion_limit_is_invalid_json() -> None:
    levels = sys.getrecursionlimit() * 4
    frame = _frame_with_nested_params(levels)
    assert len(frame) < transport.MAX_JSON_FRAME_BYTES
    with pytest.raises(TransportFailure) as caught:
        transport._parse_frame(frame)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_json"


def test_object_nesting_is_bounded_like_array_nesting() -> None:
    levels = MAX_JSON_NESTING_DEPTH + 8
    body = b'{"k":' * levels + b"1" + b"}" * levels
    frame = b'{"jsonrpc":"2.0","id":1,"method":"ping","params":' + body + b"}"
    with pytest.raises(TransportFailure) as caught:
        transport._parse_frame(frame)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_json"


def test_tree_walk_is_iterative_and_bounded_without_recursion() -> None:
    """A parsed structure deeper than any interpreter frame budget still yields the fixed reason."""

    levels = sys.getrecursionlimit() * 8
    deep: list[object] = []
    cursor = deep
    for _ in range(levels):
        inner: list[object] = []
        cursor.append(inner)
        cursor = inner
    with pytest.raises(TransportFailure) as caught:
        transport._validate_tree({"params": deep})  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_json"


def test_unencodable_text_deep_inside_an_admitted_frame_is_still_invalid_json() -> None:
    levels = MAX_JSON_NESTING_DEPTH - 3
    parsed = json.loads(_frame_with_nested_params(levels))
    cursor = parsed["params"]["a"]
    for _ in range(levels - 1):
        cursor = cursor[0]
    cursor.append("\udc80")
    with pytest.raises(TransportFailure) as caught:
        transport._validate_tree(parsed)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason == "invalid_json"


def test_wide_shallow_frames_are_unaffected_by_the_depth_bound() -> None:
    frame = _frame(
        {"items": [[i] for i in range(2_000)], "keys": {str(i): i for i in range(2_000)}}
    )
    message = transport._parse_frame(frame)  # pyright: ignore[reportPrivateUsage]
    assert message.message.model_dump(by_alias=True)["id"] == 1
