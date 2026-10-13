"""Yoetz's own record of the tool calls its MCP server answered with an error (tb4n5, #1041).

A host fires no ``PostToolUse`` for a tool call whose result is not a success: Codex runs post-tool
hooks only when the output's ``success_for_logging`` holds (``codex-rs/core/src/tools/registry.rs``),
and an MCP result with ``isError: true`` is not a success (``McpToolOutput::success_for_logging``).
A Yoetz call the server rejected therefore left its ``PreToolUse`` pending until it expired as
``pending_attempt_expired`` (17 of 18 tb4n5 attempts; the pre-minus-post surplus was at least the
number of rejected Yoetz calls in every attempt). That gap claims a pipeline loss that did not
happen: Yoetz itself answered the call.

The MCP bridge records each error result it returns for a Yoetz tool whose arguments carry a valid
``request_id``; the local observation store closes a pending Yoetz attempt with the same request as
rejected by Yoetz instead of letting it expire. Only a bounded commitment crosses this file:
SHA-256 over a domain tag, the tool's basename and the request id. No argument, message, session or
workspace value is written. The record is best-effort: a call it misses still expires as before,
which remains a disclosed gap, never a silent one.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Final, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms do not host hooks
    fcntl = None  # type: ignore[assignment]

from yoetz.config.paths import state_dir
from yoetz.domain.yoetz_tools import YOETZ_MCP_TOOL_NAMES, yoetz_tool_spelling
from yoetz.protocol.ids import safe_request_id_from

__all__ = [
    "REJECTED_CALLS_FILENAME",
    "RejectedYoetzCall",
    "read_rejected_yoetz_calls",
    "record_rejected_yoetz_call",
    "rejected_call_commitment",
    "yoetz_tool_basename",
]

REJECTED_CALLS_FILENAME: Final = "yoetz-rejected-calls.json"
_LOCK_FILENAME: Final = ".yoetz-rejected-calls.lock"
_SCHEMA: Final = "yoetz.rejected-calls/1"
_DOMAIN: Final = b"yoetz/rejected-call/v1\x00"
# A pending attempt lives at most ten minutes (``_OPEN_PRE_TTL_MS``); the newest entries cover far
# more than that at any plausible rejection rate.
_MAX_ENTRIES: Final = 256
_MAX_FILE_BYTES: Final = 64 * 1024
_NAMES: Final = frozenset(YOETZ_MCP_TOOL_NAMES)


# ``(commitment, rejected at in Unix milliseconds)``.
type RejectedYoetzCall = tuple[str, int]


def yoetz_tool_basename(tool: object) -> str | None:
    """The registry name of a Yoetz tool in any host spelling (``mcp__yoetz__check`` -> ``check``)."""

    if yoetz_tool_spelling(tool) is None:
        return None
    lowered = cast(str, tool).casefold()
    for separator in ("__", ":"):
        lowered = lowered.rsplit(separator, 1)[-1]
    return lowered if lowered in _NAMES else None


def rejected_call_commitment(tool: object, request_id: object) -> str | None:
    """The commitment both sides compute for one Yoetz call, or ``None`` when it has no identity."""

    basename = yoetz_tool_basename(tool)
    request = safe_request_id_from({"request_id": request_id})
    if basename is None or request is None:
        return None
    digest = hashlib.sha256(
        _DOMAIN + basename.encode("ascii") + b"\x00" + request.encode("ascii")
    ).hexdigest()
    return f"sha256:{digest}"


def _directory(state_root: Path | None) -> Path:
    return (state_dir() if state_root is None else state_root) / "observation"


def _parse(raw: bytes) -> list[RejectedYoetzCall]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, ValueError:
        return []
    if not isinstance(document, Mapping):
        return []
    body = cast(Mapping[str, object], document)
    entries = body.get("entries")
    if body.get("schema") != _SCHEMA or not isinstance(entries, list):
        return []
    result: list[RejectedYoetzCall] = []
    for entry in cast(list[object], entries)[-_MAX_ENTRIES:]:
        if not isinstance(entry, Mapping):
            continue
        item = cast(Mapping[str, object], entry)
        commitment = item.get("commitment")
        at_ms = item.get("at_ms")
        if (
            type(commitment) is str
            and len(commitment) == 71
            and commitment.startswith("sha256:")
            and type(at_ms) is int
            and at_ms >= 0
        ):
            result.append((commitment, at_ms))
    return result


def _read(path: Path) -> list[RejectedYoetzCall]:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return []
    try:
        raw = os.read(descriptor, _MAX_FILE_BYTES + 1)
    except OSError:
        return []
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_FILE_BYTES:
        return []
    return _parse(raw)


def read_rejected_yoetz_calls(observation_root: Path) -> tuple[RejectedYoetzCall, ...]:
    """The recorded rejections under one observation directory, oldest first; empty if none."""

    return tuple(_read(observation_root / REJECTED_CALLS_FILENAME))


def record_rejected_yoetz_call(
    tool: object,
    arguments: object,
    *,
    state_root: Path | None = None,
    now_ms: int | None = None,
) -> bool:
    """Record that the Yoetz MCP server answered one call with an error. Never raises.

    Nothing is written when the call names no Yoetz tool, carries no valid ``request_id``, or
    observation was never set up under the state root (no hook can be waiting on it then).
    """

    try:
        request = safe_request_id_from(arguments)
        commitment = rejected_call_commitment(tool, request)
        if commitment is None:
            return False
        directory = _directory(state_root)
        if not directory.is_dir() or directory.is_symlink():
            return False
        at_ms = int(time.time() * 1000) if now_ms is None else now_ms
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        lock = os.open(directory / _LOCK_FILENAME, flags, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(lock, fcntl.LOCK_EX)
            path = directory / REJECTED_CALLS_FILENAME
            entries = [*_read(path), (commitment, at_ms)][-_MAX_ENTRIES:]
            payload = json.dumps(
                {
                    "entries": [
                        {"at_ms": entry_at, "commitment": entry_commitment}
                        for entry_commitment, entry_at in entries
                    ],
                    "schema": _SCHEMA,
                },
                separators=(",", ":"),
                sort_keys=True,
            ).encode("ascii")
            temporary = directory / f".{REJECTED_CALLS_FILENAME}.{os.urandom(8).hex()}.tmp"
            write_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                write_flags |= os.O_NOFOLLOW
            descriptor = os.open(temporary, write_flags, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            try:
                os.replace(temporary, path)
            except OSError:
                with contextlib.suppress(OSError):
                    temporary.unlink()
                return False
        finally:
            if fcntl is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(lock, fcntl.LOCK_UN)
            os.close(lock)
    except Exception:
        return False
    return True
