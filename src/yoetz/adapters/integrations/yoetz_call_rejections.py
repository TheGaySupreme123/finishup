"""Yoetz's own record of the tool calls its MCP server answered with an error (tb4n5, #1041).

A host fires no ``PostToolUse`` for a tool call whose result is not a success: Codex runs post-tool
hooks only when the output's ``success_for_logging`` holds (``codex-rs/core/src/tools/registry.rs``),
and an MCP result with ``isError: true`` is not a success (``McpToolOutput::success_for_logging``).
A Yoetz call the server rejected therefore left its ``PreToolUse`` pending until it expired as
``pending_attempt_expired`` (17 of 18 tb4n5 attempts; the pre-minus-post surplus was at least the
number of rejected Yoetz calls in every attempt). That gap claims a pipeline loss that did not
happen: Yoetz itself answered the call.

The MCP bridge records each error result it returns for a Yoetz tool whose arguments carry a valid
``request_id``; the local observation store closes a pending Yoetz attempt with the same call as
rejected by Yoetz instead of letting it expire. A call is identified by its operation scope, not
its ``request_id`` alone (replay identity is ``(task, writer, request_id)``, INTERFACES): the
commitment covers the tool's basename, the request's Yoetz ``session_id`` and ``writer_id`` when it
names them, and the ``request_id``. Only that SHA-256 commitment and a millisecond time cross this
file; no argument, message, session or workspace value is written. Each rejection is consumed
installation-wide, under the file's lock, by the first attempt it closes, so one rejection never
closes attempts in two workspaces. The record is best-effort: a call it misses still expires as
before, which remains a disclosed gap, never a silent one.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Callable, Generator, Mapping
from pathlib import Path
from typing import Final, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms do not host hooks
    fcntl = None  # type: ignore[assignment]

from yoetz.config.paths import state_dir
from yoetz.domain.yoetz_tools import YOETZ_MCP_TOOL_NAMES, yoetz_tool_spelling
from yoetz.protocol.ids import IdKind, is_valid_id, safe_request_id_from

__all__ = [
    "REJECTED_CALLS_FILENAME",
    "RejectedYoetzCall",
    "consume_rejected_yoetz_call",
    "read_rejected_yoetz_calls",
    "record_rejected_yoetz_call",
    "rejected_call_commitment",
    "yoetz_tool_basename",
]

REJECTED_CALLS_FILENAME: Final = "yoetz-rejected-calls.json"
_LOCK_FILENAME: Final = ".yoetz-rejected-calls.lock"
_SCHEMA: Final = "yoetz.rejected-calls/2"
_DOMAIN: Final = b"yoetz/rejected-call/v2\x00"
# A pending attempt lives at most ten minutes (``_OPEN_PRE_TTL_MS``); the newest entries cover far
# more than that at any plausible rejection rate.
_MAX_ENTRIES: Final = 256
_MAX_FILE_BYTES: Final = 64 * 1024
_NAMES: Final = frozenset(YOETZ_MCP_TOOL_NAMES)


# ``(commitment, rejected at in Unix milliseconds, claimant or None)``: the claimant is the opaque
# digest of the one pending attempt that consumed the rejection.
type RejectedYoetzCall = tuple[str, int, str | None]
type _Entry = RejectedYoetzCall


def yoetz_tool_basename(tool: object) -> str | None:
    """The registry name of a Yoetz tool in any host spelling (``mcp__yoetz__check`` -> ``check``)."""

    if yoetz_tool_spelling(tool) is None:
        return None
    lowered = cast(str, tool).casefold()
    for separator in ("__", ":"):
        lowered = lowered.rsplit(separator, 1)[-1]
    return lowered if lowered in _NAMES else None


def _scope_token(arguments: Mapping[object, object], key: str, kind: IdKind) -> bytes:
    value = arguments.get(key)
    return value.encode("ascii") if type(value) is str and is_valid_id(kind, value) else b"-"


def rejected_call_commitment(tool: object, arguments: object) -> str | None:
    """The commitment both sides compute for one Yoetz call, or ``None`` when it has no identity.

    ``arguments`` is the call's argument mapping as the host sent it (hook ``tool_input``, MCP
    ``arguments``); only its ``request_id``, ``session_id`` and ``writer_id`` are read.
    """

    basename = yoetz_tool_basename(tool)
    request = safe_request_id_from(arguments)
    if basename is None or request is None or not isinstance(arguments, Mapping):
        return None
    scope = cast(Mapping[object, object], arguments)
    digest = hashlib.sha256(
        b"\x00".join(
            (
                _DOMAIN + basename.encode("ascii"),
                _scope_token(scope, "session_id", IdKind.SESSION),
                _scope_token(scope, "writer_id", IdKind.WRITER),
                request.encode("ascii"),
            )
        )
    ).hexdigest()
    return f"sha256:{digest}"


def _directory(state_root: Path | None) -> Path:
    return (state_dir() if state_root is None else state_root) / "observation"


def _parse(raw: bytes) -> list[_Entry]:
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
    result: list[_Entry] = []
    for entry in cast(list[object], entries)[-_MAX_ENTRIES:]:
        if not isinstance(entry, Mapping):
            continue
        item = cast(Mapping[str, object], entry)
        commitment = item.get("commitment")
        at_ms = item.get("at_ms")
        claimant = item.get("claimant")
        if (
            type(commitment) is str
            and len(commitment) == 71
            and commitment.startswith("sha256:")
            and type(at_ms) is int
            and at_ms >= 0
            and (claimant is None or (type(claimant) is str and 1 <= len(claimant) <= 64))
        ):
            result.append((commitment, at_ms, claimant))
    return result


def _read(path: Path) -> list[_Entry]:
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


def _write(directory: Path, entries: list[_Entry]) -> bool:
    payload = json.dumps(
        {
            "entries": [
                {"at_ms": at_ms, "claimant": claimant, "commitment": commitment}
                for commitment, at_ms, claimant in entries[-_MAX_ENTRIES:]
            ],
            "schema": _SCHEMA,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    temporary = directory / f".{REJECTED_CALLS_FILENAME}.{os.urandom(8).hex()}.tmp"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, directory / REJECTED_CALLS_FILENAME)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()
        return False
    return True


@contextlib.contextmanager
def _locked(directory: Path) -> Generator[None]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock = os.open(directory / _LOCK_FILENAME, flags, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _update(directory: Path, change: Callable[[list[_Entry]], list[_Entry] | None]) -> bool:
    """Apply one change to the record under its lock; ``None`` from ``change`` writes nothing."""

    if not directory.is_dir() or directory.is_symlink():
        return False
    with _locked(directory):
        updated = change(_read(directory / REJECTED_CALLS_FILENAME))
        return updated is not None and _write(directory, updated)


def read_rejected_yoetz_calls(observation_root: Path) -> tuple[RejectedYoetzCall, ...]:
    """Every recorded rejection with the attempt that claimed it (or ``None``), oldest first."""

    return tuple(_read(observation_root / REJECTED_CALLS_FILENAME))


def consume_rejected_yoetz_call(
    observation_root: Path, commitment: str, at_ms: int, claimant: str
) -> bool:
    """Claim one recorded rejection for one pending attempt; ``True`` only for that attempt.

    Consumption is installation-wide and serialized by the record's lock, so a rejection closes at
    most one attempt in any workspace. It is idempotent for its claimant: a store transaction that
    is rerun under the store lock, or rolled back and retried, claims the same rejection again
    instead of losing it. An unreadable or unwritable record claims nothing.
    """

    def change(entries: list[_Entry]) -> list[_Entry] | None:
        for index, (entry_commitment, entry_at, entry_claimant) in enumerate(entries):
            if entry_commitment != commitment or entry_at != at_ms:
                continue
            if entry_claimant is not None:
                return entries if entry_claimant == claimant else None
            entries[index] = (entry_commitment, entry_at, claimant)
            return entries
        return None

    try:
        return _update(observation_root, change)
    except Exception:
        return False


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
        commitment = rejected_call_commitment(tool, arguments)
        if commitment is None:
            return False
        at_ms = int(time.time() * 1000) if now_ms is None else now_ms
        return _update(
            _directory(state_root),
            lambda entries: [*entries, (commitment, at_ms, None)][-_MAX_ENTRIES:],
        )
    except Exception:
        return False
