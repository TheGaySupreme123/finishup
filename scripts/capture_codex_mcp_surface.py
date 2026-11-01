#!/usr/bin/env python3
"""Capture one Codex app-server MCP inventory for compatibility evidence.

The caller owns scratch-home creation and MCP registration. This script never edits Codex
configuration; it starts the selected binary against that scratch home, requests the full MCP
server inventory, and writes the bounded JSON-RPC responses to the requested output path.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import threading
from pathlib import Path
from typing import BinaryIO, cast

_TIMEOUT_SECONDS = 30.0
_READ_CHUNK_BYTES = 65_536
_MAX_STDOUT_BYTES = 8_000_000
_MAX_STDOUT_MESSAGES = 10_000
_MAX_STDERR_BYTES = 262_144
_MAX_JSON_MESSAGE_BYTES = 4_000_000
_MAX_OUTPUT_BYTES = 8_000_000
type _StreamItem = bytes | RuntimeError | None


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--codex-binary", required=True, type=Path)
    parser.add_argument("--codex-testing-home", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def _put_message(sink: queue.Queue[_StreamItem], message: bytes, message_count: int) -> int:
    if not message:
        return message_count
    message_count += 1
    if message_count > _MAX_STDOUT_MESSAGES:
        raise RuntimeError("codex_app_server_stdout_message_budget_exceeded")
    if len(message) > _MAX_JSON_MESSAGE_BYTES:
        raise RuntimeError("codex_app_server_json_message_budget_exceeded")
    sink.put(message)
    return message_count


def _drain_stdout(stream: BinaryIO, sink: queue.Queue[_StreamItem]) -> None:
    """Frame bounded JSONL messages without retaining an unbounded line or stream."""

    total_bytes = 0
    message_count = 0
    pending = bytearray()
    try:
        while chunk := os.read(stream.fileno(), _READ_CHUNK_BYTES):
            total_bytes += len(chunk)
            if total_bytes > _MAX_STDOUT_BYTES:
                raise RuntimeError("codex_app_server_stdout_byte_budget_exceeded")
            pending.extend(chunk)
            while (newline := pending.find(b"\n")) >= 0:
                message = bytes(pending[:newline])
                del pending[: newline + 1]
                message_count = _put_message(sink, message, message_count)
            if len(pending) > _MAX_JSON_MESSAGE_BYTES:
                raise RuntimeError("codex_app_server_json_message_budget_exceeded")
        _put_message(sink, bytes(pending), message_count)
    except RuntimeError as exc:
        sink.put(exc)
    finally:
        sink.put(None)


def _drain_stderr(stream: BinaryIO, failures: queue.Queue[_StreamItem]) -> None:
    """Discard bounded diagnostics and signal immediately if the child exceeds the budget."""

    total_bytes = 0
    while chunk := os.read(stream.fileno(), _READ_CHUNK_BYTES):
        total_bytes += len(chunk)
        if total_bytes > _MAX_STDERR_BYTES:
            failures.put(RuntimeError("codex_app_server_stderr_byte_budget_exceeded"))
            return


def _send(stream: BinaryIO, message: dict[str, object]) -> None:
    stream.write(
        json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"
    )
    stream.flush()


def _read_response(lines: queue.Queue[_StreamItem], request_id: int) -> dict[str, object]:
    while True:
        try:
            line = lines.get(timeout=_TIMEOUT_SECONDS)
        except queue.Empty as exc:
            raise RuntimeError(f"codex_app_server_response_timeout:{request_id}") from exc
        if isinstance(line, RuntimeError):
            raise line
        if line is None:
            raise RuntimeError(f"codex_app_server_closed:{request_id}")
        parsed = cast(object, json.loads(line))
        if type(parsed) is not dict:
            continue
        message = cast(dict[object, object], parsed)
        if message.get("id") == request_id:
            return cast(dict[str, object], message)


def main() -> int:
    args = _parse_args()
    codex_binary = cast(Path, args.codex_binary).resolve(strict=True)
    codex_testing_home = cast(Path, args.codex_testing_home).resolve(strict=True)
    output = cast(Path, args.output)
    if not codex_testing_home.is_dir() or codex_testing_home.is_symlink():
        raise RuntimeError("codex_testing_home_invalid")
    if output.exists() and output.is_symlink():
        raise RuntimeError("capture_output_symlink_forbidden")

    environment = os.environ.copy()
    environment["CODEX_TESTING_HOME"] = str(codex_testing_home)
    process = subprocess.Popen(
        [str(codex_binary), "app-server", "--listen", "stdio://"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
    )
    if process.stdin is None or process.stdout is None or process.stderr is None:
        process.kill()
        raise RuntimeError("codex_app_server_pipe_unavailable")
    process_stdin = cast(BinaryIO, process.stdin)
    process_stdout = cast(BinaryIO, process.stdout)
    process_stderr = cast(BinaryIO, process.stderr)

    stdout_lines: queue.Queue[_StreamItem] = queue.Queue()
    threading.Thread(
        target=_drain_stdout,
        args=(process_stdout, stdout_lines),
        daemon=True,
    ).start()
    threading.Thread(
        target=_drain_stderr,
        args=(process_stderr, stdout_lines),
        daemon=True,
    ).start()
    try:
        _send(
            process_stdin,
            {
                "method": "initialize",
                "id": 1,
                "params": {
                    "clientInfo": {
                        "name": "finishup-boundary-probe",
                        "title": "FinishUP boundary probe",
                        "version": "0.1.0",
                    },
                    "capabilities": {
                        "experimentalApi": True,
                        "requestAttestation": False,
                        "mcpServerOpenaiFormElicitation": False,
                    },
                },
            },
        )
        initialize = _read_response(stdout_lines, 1)
        _send(
            process_stdin,
            {
                "method": "mcpServerStatus/list",
                "id": 2,
                "params": {"detail": "full", "limit": 10},
            },
        )
        inventory = _read_response(stdout_lines, 2)
        output.parent.mkdir(parents=True, exist_ok=True)
        capture_bytes = (
            json.dumps(
                {"initialize": initialize, "inventory": inventory},
                ensure_ascii=True,
                indent=2,
                sort_keys=True,
            )
            + "\n"
        )
        encoded_capture = capture_bytes.encode("utf-8")
        if len(encoded_capture) > _MAX_OUTPUT_BYTES:
            raise RuntimeError("codex_capture_output_byte_budget_exceeded")
        output.write_bytes(encoded_capture)
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
    print(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
