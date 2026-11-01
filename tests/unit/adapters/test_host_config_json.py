"""Host-owned JSON configuration is observed despite values the wire profile rejects (#1278)."""

from __future__ import annotations

import pytest

from finishup.adapters.integrations.host_config_json import parse_host_config_json
from finishup.protocol.canonical import strict_json_parse
from finishup.protocol.errors import ProtocolValueError


def test_decimals_and_unsafe_integers_read_as_null_and_the_rest_is_kept() -> None:
    raw = (
        b'{"numStartups": 3, "lastCost": 22.0157, "flags": {"rate": 0.15, "big": 9007199254740993,'
        b' "neg": -0, "inf": Infinity}, "mcpServers": {"finishup": {"command": "finishup",'
        b' "args": ["mcp", "serve"]}}, "list": [1, 2.5, "x"]}'
    )
    with pytest.raises(ProtocolValueError):
        strict_json_parse(raw)

    parsed = parse_host_config_json(raw)

    assert parsed == {
        "numStartups": 3,
        "lastCost": None,
        "flags": {"rate": None, "big": None, "neg": None, "inf": None},
        "mcpServers": {"finishup": {"command": "finishup", "args": ["mcp", "serve"]}},
        "list": [1, None, "x"],
    }


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (b'{"a": 1, "a": 2}', "duplicate_object_key"),
        (b"\xef\xbb\xbf{}", "byte_order_mark_forbidden"),
        (b'{"a": "\x00"}', "nul_byte_forbidden"),
        (b"\xff", "invalid_utf8"),
        (b"{", "malformed_json"),
        (b"[" * 200 + b"]" * 200, "nesting_too_deep"),
    ],
)
def test_structural_problems_still_make_the_file_unreadable(raw: bytes, reason: str) -> None:
    with pytest.raises(ProtocolValueError) as error:
        parse_host_config_json(raw)
    assert str(error.value) == reason or reason in repr(error.value)
