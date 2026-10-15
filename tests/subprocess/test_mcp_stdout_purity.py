"""MCP stdout contains protocol frames only even when application code prints."""

from __future__ import annotations

import json
import os
import subprocess
import sys


def test_python_stdout_is_redirected_while_transport_owns_fd_one() -> None:
    child = r"""
import anyio
import sys
from finishup.adapters.mcp_stdio import bounded_stdio_server

async def main():
    async with bounded_stdio_server(512) as (read_stream, write_stream):
        print("accidental application noise")
        sys.stdout.buffer.write(b"buffered application noise\n")
        sys.stdout.buffer.flush()
        async with write_stream:
            async for message in read_stream:
                await write_stream.send(message)

anyio.run(main)
"""
    environment = dict(os.environ)
    environment["PYTHONPATH"] = os.pathsep.join(("tests", "tests/subprocess", "src"))
    request = b'{"jsonrpc":"2.0","id":1,"method":"ping"}\n'
    result = subprocess.run(
        [sys.executable, "-I", "-c", child],
        input=request,
        capture_output=True,
        check=False,
        env=environment,
        timeout=5,
    )
    assert result.returncode == 0
    assert b"accidental application noise" not in result.stdout
    assert b"accidental application noise" in result.stderr
    assert b"buffered application noise" not in result.stdout
    assert b"buffered application noise" in result.stderr
    assert result.stdout.count(b"\n") == 1
    assert b"Traceback" not in result.stderr
    assert json.loads(result.stdout)["id"] == 1
