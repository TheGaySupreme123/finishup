"""FinishUP's own record of the tool calls its MCP server answered with an error (tb4n5, #1041).

A host fires no ``PostToolUse`` for a tool call whose result is not a success: Codex runs post-tool
hooks only when the output's ``success_for_logging`` holds (``codex-rs/core/src/tools/registry.rs``),
and an MCP result with ``isError: true`` is not a success (``McpToolOutput::success_for_logging``).
A FinishUP call the server rejected therefore left its ``PreToolUse`` pending until it expired as
``pending_attempt_expired`` (17 of 18 tb4n5 attempts; the pre-minus-post surplus was at least the
number of rejected FinishUP calls in every attempt). That gap claims a pipeline loss that did not
happen: FinishUP itself answered the call.

The MCP bridge records each error result it returns for a FinishUP tool whose arguments carry a valid
``request_id``; the local observation store closes a pending FinishUP attempt with the same call as
rejected by FinishUP instead of letting it expire. A call is identified by its operation scope, not
its ``request_id`` alone (replay identity is ``(task, writer, request_id)``, INTERFACES): the
commitment covers the tool's basename, the request's FinishUP ``session_id`` and ``writer_id`` when it
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

from finishup.config.paths import state_dir
from finishup.domain.finishup_tools import (
    FINISHUP_MCP_TOOL_NAMES,
    FINISHUP_READ_TOOL_BASENAMES,
    finishup_tool_spelling,
)
from finishup.protocol.ids import IdKind, is_valid_id, safe_request_id_from

__all__ = [
    "REJECTED_CALLS_FILENAME",
    "SERVED_READS_FILENAME",
    "SERVED_READ_MAX_AGE_MS",
    "RejectedFinishUpCall",
    "consume_rejected_finishup_call",
    "read_rejected_finishup_calls",
    "claim_served_finishup_read",
    "record_rejected_finishup_call",
    "record_served_finishup_read",
    "rejected_call_commitment",
    "finishup_tool_basename",
]

# Frozen legacy identifier (ADR-048): these file names, tags and the domain separator stay in the
# protocol-0.1 ``yoetz`` families; development builds already wrote them into the state folder.
REJECTED_CALLS_FILENAME: Final = "yoetz-rejected-calls.json"
_LOCK_FILENAME: Final = ".yoetz-rejected-calls.lock"
_SCHEMA: Final = "yoetz.rejected-calls/2"
_DOMAIN: Final = b"yoetz/rejected-call/v2\x00"
# A pending attempt lives at most ten minutes (``_OPEN_PRE_TTL_MS``); the newest entries cover far
# more than that at any plausible rejection rate.
_MAX_ENTRIES: Final = 256
_MAX_FILE_BYTES: Final = 64 * 1024
_NAMES: Final = frozenset(FINISHUP_MCP_TOOL_NAMES)
# Served reads (round 2 of tb4 n5): Cursor's ordinary hooks name a FinishUP call ``MCP:<tool>`` with no
# server, so a hook cannot tell FinishUP's ``status`` from another server's ``status``. The bridge
# records each successful FinishUP read it served under the same commitment; a post-event whose
# commitment is recorded is provably FinishUP's own call. The record precedes the response the host
# acts on, so the post-event always finds it; anything unproven is delivered as ordinary evidence.
# Frozen legacy identifier (ADR-048): as above, for the served-read record.
SERVED_READS_FILENAME: Final = "yoetz-served-reads.json"
_SERVED_LOCK_FILENAME: Final = ".yoetz-served-reads.lock"
_SERVED_SCHEMA: Final = "yoetz.served-reads/1"
_READ_NAMES: Final = frozenset(FINISHUP_READ_TOOL_BASENAMES)
# A served read proves at most one post-event, and only within this age (round 3).
SERVED_READ_MAX_AGE_MS: Final = 120_000


# ``(commitment, rejected at in Unix milliseconds, claimant or None)``: the claimant is the opaque
# digest of the one pending attempt that consumed the rejection.
type RejectedFinishUpCall = tuple[str, int, str | None]
type _Entry = RejectedFinishUpCall


def finishup_tool_basename(tool: object) -> str | None:
    """The registry name of a FinishUP tool in any host spelling (``mcp__finishup__check`` -> ``check``)."""

    if finishup_tool_spelling(tool) is None:
        return None
    lowered = cast(str, tool).casefold()
    for separator in ("__", ":"):
        lowered = lowered.rsplit(separator, 1)[-1]
    return lowered if lowered in _NAMES else None


def _scope_token(arguments: Mapping[object, object], key: str, kind: IdKind) -> bytes:
    value = arguments.get(key)
    return value.encode("ascii") if type(value) is str and is_valid_id(kind, value) else b"-"


def rejected_call_commitment(tool: object, arguments: object) -> str | None:
    """The commitment both sides compute for one FinishUP call, or ``None`` when it has no identity.

    ``arguments`` is the call's argument mapping as the host sent it (hook ``tool_input``, MCP
    ``arguments``); only its ``request_id``, ``session_id`` and ``writer_id`` are read.
    """

    basename = finishup_tool_basename(tool)
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


def _parse(raw: bytes, schema: str = _SCHEMA) -> list[_Entry]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except UnicodeDecodeError, ValueError:
        return []
    if not isinstance(document, Mapping):
        return []
    body = cast(Mapping[str, object], document)
    entries = body.get("entries")
    if body.get("schema") != schema or not isinstance(entries, list):
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


def _read(path: Path, schema: str = _SCHEMA) -> list[_Entry]:
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
    return _parse(raw, schema)


def _write(
    directory: Path,
    entries: list[_Entry],
    name: str = REJECTED_CALLS_FILENAME,
    schema: str = _SCHEMA,
) -> bool:
    payload = json.dumps(
        {
            "entries": [
                {"at_ms": at_ms, "claimant": claimant, "commitment": commitment}
                for commitment, at_ms, claimant in entries[-_MAX_ENTRIES:]
            ],
            "schema": schema,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    temporary = directory / f".{name}.{os.urandom(8).hex()}.tmp"
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
        os.replace(temporary, directory / name)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()
        return False
    return True


@contextlib.contextmanager
def _locked(directory: Path, lock_name: str = _LOCK_FILENAME) -> Generator[None]:
    flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    lock = os.open(directory / lock_name, flags, 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


def _update(
    directory: Path,
    change: Callable[[list[_Entry]], list[_Entry] | None],
    name: str = REJECTED_CALLS_FILENAME,
    schema: str = _SCHEMA,
    lock_name: str = _LOCK_FILENAME,
) -> bool:
    """Apply one change to the record under its lock; ``None`` from ``change`` writes nothing."""

    if not directory.is_dir() or directory.is_symlink():
        return False
    with _locked(directory, lock_name):
        updated = change(_read(directory / name, schema))
        return updated is not None and _write(directory, updated, name, schema)


def read_rejected_finishup_calls(observation_root: Path) -> tuple[RejectedFinishUpCall, ...]:
    """Every recorded rejection with the attempt that claimed it (or ``None``), oldest first."""

    return tuple(_read(observation_root / REJECTED_CALLS_FILENAME))


def consume_rejected_finishup_call(
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


def record_rejected_finishup_call(
    tool: object,
    arguments: object,
    *,
    state_root: Path | None = None,
    now_ms: int | None = None,
) -> bool:
    """Record that the FinishUP MCP server answered one call with an error. Never raises.

    Nothing is written when the call names no FinishUP tool, carries no valid ``request_id``, or
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


def _served_read_commitment(tool: object, arguments: object) -> str | None:
    if finishup_tool_basename(tool) not in _READ_NAMES:
        return None
    return rejected_call_commitment(tool, arguments)


def record_served_finishup_read(
    tool: object,
    arguments: object,
    *,
    state_root: Path | None = None,
    now_ms: int | None = None,
) -> bool:
    """Record that the FinishUP MCP server answered one read (``status`` and kin) successfully.

    Never raises. Nothing is written for a write tool, a call without a valid ``request_id``, or
    where observation was never set up. Only the call commitment and a time are written.
    """

    try:
        commitment = _served_read_commitment(tool, arguments)
        if commitment is None:
            return False
        at_ms = int(time.time() * 1000) if now_ms is None else now_ms
        return _update(
            _directory(state_root),
            lambda entries: [*entries, (commitment, at_ms, None)][-_MAX_ENTRIES:],
            SERVED_READS_FILENAME,
            _SERVED_SCHEMA,
            _SERVED_LOCK_FILENAME,
        )
    except Exception:
        return False


def claim_served_finishup_read(
    tool: object,
    arguments: object,
    *,
    state_root: Path | None = None,
    now_ms: int | None = None,
) -> bool:
    """Claim, once, the bridge's record of serving exactly this FinishUP read. Never raises.

    ``True`` removes the matching record under the record's lock, so one served read suppresses
    at most one post-event; a later call that reuses the same request scope (a replay, or a
    foreign tool sent the same arguments, in any host session) finds nothing and is delivered. A
    record older than ``SERVED_READ_MAX_AGE_MS`` proves nothing: the post-event of a served call
    follows its result within seconds. The bridge cannot see Cursor's conversation or tool-call
    id (the MCP request carries neither), so they cannot join the commitment; single use and the
    expiry bound what a record can prove instead (tb4 n5 round 3).
    """

    try:
        commitment = _served_read_commitment(tool, arguments)
        if commitment is None:
            return False
        at_now = int(time.time() * 1000) if now_ms is None else now_ms
        claimed = False

        def change(entries: list[_Entry]) -> list[_Entry] | None:
            nonlocal claimed
            for index, (entry_commitment, entry_at, _claimant) in enumerate(entries):
                if entry_commitment != commitment:
                    continue
                if not 0 <= at_now - entry_at <= SERVED_READ_MAX_AGE_MS:
                    continue
                claimed = True
                return [*entries[:index], *entries[index + 1 :]]
            return None

        written = _update(
            _directory(state_root),
            change,
            SERVED_READS_FILENAME,
            _SERVED_SCHEMA,
            _SERVED_LOCK_FILENAME,
        )
        return claimed and written
    except Exception:
        return False
