"""Installed-process-style bounded MCP stdio frame tests."""

from __future__ import annotations

import json
import os
import subprocess
import sys

_CHILD = r"""
import anyio
import sys
from finishup.adapters.mcp_stdio import bounded_stdio_server

async def main():
    maximum = int(sys.argv[1])
    async with bounded_stdio_server(maximum) as (read_stream, write_stream):
        async with write_stream:
            async for message in read_stream:
                await write_stream.send(message)

anyio.run(main)
"""


def _run(data: bytes, maximum: int = 512) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(("tests", "tests/subprocess", "src"))
    return subprocess.run(
        [sys.executable, "-I", "-c", _CHILD, str(maximum)],
        input=data,
        capture_output=True,
        check=False,
        env=environment,
        timeout=5,
    )


def _request(identifier: int = 1, padding: str = "") -> bytes:
    return json.dumps(
        {"jsonrpc": "2.0", "id": identifier, "method": "ping", "params": {"padding": padding}},
        separators=(",", ":"),
    ).encode("utf-8")


def test_multiple_frames_and_split_independent_jsonl_round_trip() -> None:
    first = _request(1)
    second = _request(2)
    result = _run(first + b"\n" + second + b"\n")
    assert result.returncode == 0
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row["id"] for row in rows] == [1, 2]


def test_malformed_frames_emit_fixed_null_id_errors_and_continue() -> None:
    valid = _request(3)
    data = b'\n\xef\xbb\xbf{}\n{"jsonrpc":"2.0","id":1,"id":2}\n' + valid + b"\n"
    result = _run(data)
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row.get("id") for row in rows] == [None, None, None, 3]
    assert [row["error"]["data"]["reason"] for row in rows[:3]] == [
        "empty_frame",
        "bom_rejected",
        "duplicate_object_key",
    ]


def test_cap_plus_one_emits_one_error_and_never_forwards_prefix() -> None:
    maximum = 256
    result = _run(b"x" * (maximum + 1), maximum)
    assert result.returncode == 0
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows == [
        {
            "jsonrpc": "2.0",
            "id": None,
            "error": {
                "code": -32600,
                "message": "Frame exceeds maximum size",
                "data": {"reason": "frame_too_large"},
            },
        }
    ]


def test_exact_payload_limit_is_accepted() -> None:
    base = _request(9)
    maximum = 256
    padding = "x" * (maximum - len(base))
    frame = _request(9, padding)
    # Recalculate once for the changed JSON string; compact ASCII makes the delta exact.
    padding = "x" * (maximum - len(frame) + len(padding))
    frame = _request(9, padding)
    assert len(frame) == maximum
    result = _run(frame + b"\n", maximum)
    assert result.returncode == 0
    assert json.loads(result.stdout)["id"] == 9


def test_deeply_nested_frame_is_invalid_json_and_the_bridge_keeps_serving() -> None:
    """Excessive nesting yields the fixed parse error, never a RecursionError exit (#394)."""

    from finishup.adapters.mcp_stdio import MAX_JSON_FRAME_BYTES

    levels = sys.getrecursionlimit() * 4
    nested = (
        b'{"jsonrpc":"2.0","id":7,"method":"ping","params":{"a":'
        + (b"[" * levels + b"]" * levels)
        + b"}}"
    )
    assert len(nested) < MAX_JSON_FRAME_BYTES
    result = _run(nested + b"\n" + _request(8) + b"\n", MAX_JSON_FRAME_BYTES)
    assert result.returncode == 0, result.stderr
    assert b"Traceback" not in result.stderr
    assert b"RecursionError" not in result.stderr
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert [row.get("id") for row in rows] == [None, 8]
    assert rows[0]["error"] == {
        "code": -32700,
        "message": "Parse error",
        "data": {"reason": "invalid_json"},
    }


def test_invalid_utf8_nul_and_partial_eof_never_enter_sdk_stream() -> None:
    result = _run(b'\xff\n{"jsonrpc":"2.0",\x00}\n' + _request(4)[:-1])
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert result.returncode == 0
    assert [row["error"]["data"]["reason"] for row in rows] == [
        "invalid_utf8",
        "nul_rejected",
    ]
    assert b'"id":4' not in result.stdout
    assert b"Traceback" not in result.stderr


def test_injected_read_failure_closes_cleanly_without_os_detail_leakage() -> None:
    home_leak = "/" + "Users/private"
    child = f"""
import anyio
import errno
import finishup.adapters.mcp_stdio as transport

def fail_read(fd, maximum):
    del fd, maximum
    raise OSError(errno.EIO, "secret {home_leak}/hostile-input.json")

transport._read_fd = fail_read

async def main():
    async with transport.bounded_stdio_server(512) as (read_stream, write_stream):
        async with write_stream:
            async for message in read_stream:
                await write_stream.send(message)

anyio.run(main)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(("tests", "tests/subprocess", "src"))
    result = subprocess.run(
        [sys.executable, "-I", "-c", child],
        input=b"x",
        capture_output=True,
        check=False,
        env=environment,
        timeout=5,
    )
    assert result.returncode == 0
    assert result.stdout == b""
    assert b"Traceback" not in result.stderr
    assert home_leak.encode() not in result.stderr
    assert b"hostile-input" not in result.stderr


def test_lone_surrogate_is_rejected_before_sdk_construction_then_recovers() -> None:
    hostile = b'{"jsonrpc":"2.0","id":1,"method":"\\ud800"}\n'
    result = _run(hostile + _request(5) + b"\n")
    rows = [json.loads(line) for line in result.stdout.splitlines()]
    assert rows[0]["id"] is None
    assert rows[0]["error"]["data"]["reason"] == "invalid_json"
    assert rows[1]["id"] == 5
