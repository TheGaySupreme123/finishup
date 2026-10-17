"""Host-owned operation identity for a ``publish_work`` call that omits ``request_id`` (ADR-050).

Issue #1084 lets an agent leave ``request_id`` out of a publish body. The identity is never derived
from the body: two deliberately identical publications (a review mode switched ``ai_powered`` ->
``local`` -> ``ai_powered``, a repeated blocker confirmation) are two operations, and a content hash
would replay the second as the first (review R1 of PR #1088). Instead the host side -- the MCP
bridge, or the CLI for ``finishup publish-work`` -- mints one ``req_`` id per call and binds it
here, durably, *before* the body is sent:

* every retry the host itself makes for that call (reconnect, the timeout probe and its replay)
  reuses the bound id, as before;
* a call whose outcome was never delivered (an error that leaves the write unknown, a cancelled
  call, a bridge process that died mid-call) leaves its binding resumable. The *next* call from
  the same writer with exactly the same body reuses that id, so a lost reply is retried safely and
  the service replays the stored outcome instead of appending twice;
* once an outcome is delivered (``ok: true``), the binding is gone and every unresolved binding of
  that writer is dropped. A later identical body is a new call with a fresh id and is recorded.

Only commitments and minted ids cross this file: SHA-256 over the FinishUP session and writer and
the canonical body (never the body itself), the minted ``request_id``, an owner token and process
id, and a millisecond time. A binding expires after :data:`RESUME_WINDOW_MS`. The record lives under
the user state directory in an owner-only folder and is written atomically and fsynced; a host that
cannot write it refuses to send an id-less body rather than send one it could not recover.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import time
from collections.abc import Callable, Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms do not host the bridge
    fcntl = None  # type: ignore[assignment]

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.ids import IdKind, is_valid_id, new_id

__all__ = [
    "PUBLISH_CALLS_DIRECTORY",
    "RESUME_WINDOW_MS",
    "PublishCallBinding",
    "PublishCallIdentities",
    "PublishCallIdentityUnavailable",
    "publish_call_commitment",
]

PUBLISH_CALLS_DIRECTORY: Final = "publish-calls"
_RECORD: Final = "calls.json"
_LOCK: Final = ".calls.lock"
_SCHEMA: Final = "finishup.publish-calls/1"
_COMMITMENT_DOMAIN: Final = b"finishup/publish-call/body/v1\x00"
_SCOPE_DOMAIN: Final = b"finishup/publish-call/scope/v1\x00"
# An unresolved call is resumable for one hour: far longer than any host retry, short enough that
# a stale binding never captures a deliberate repeat made much later.
RESUME_WINDOW_MS: Final = 3_600_000
_MAX_ENTRIES: Final = 256
_MAX_FILE_BYTES: Final = 128 * 1024

type _State = Literal["in_flight", "unresolved"]


class PublishCallIdentityUnavailable(Exception):
    """The binding could not be made durable, so the id-less call must not be sent."""


@dataclass(frozen=True, slots=True)
class PublishCallBinding:
    """One id-less publish call bound to its request id before it is sent."""

    request_id: str
    commitment: str
    scope: str
    # True when this call reuses the id of an earlier call of the same body whose outcome was
    # never delivered (the service then replays that call if it committed).
    resumed: bool


@dataclass(slots=True)
class _Entry:
    commitment: str
    scope: str
    request_id: str
    state: _State
    owner: str | None
    pid: int | None
    at_ms: int

    def as_json(self) -> dict[str, JsonValue]:
        return {
            "at_ms": self.at_ms,
            "commitment": self.commitment,
            "owner": self.owner,
            "pid": self.pid,
            "request_id": self.request_id,
            "scope": self.scope,
            "state": self.state,
        }


def _digest(domain: bytes, value: JsonValue) -> str:
    return "sha256:" + hashlib.sha256(domain + canonical_encode(value)).hexdigest()


def publish_call_commitment(arguments: object) -> tuple[str, str] | None:
    """``(scope, commitment)`` of one id-less publish body, or ``None`` when it cannot be bound.

    ``None`` for a body that names a ``request_id`` (any value), a declared dry run (it consumes no
    identity), a body without a valid FinishUP ``session_id`` and ``writer_id``, or one that has no
    canonical JSON form. The commitment covers the whole body as sent, so any change -- a corrected
    field, an added value -- is a different call.
    """

    if not isinstance(arguments, Mapping):
        return None
    source = cast(Mapping[object, object], arguments)
    if "request_id" in source or source.get("dry_run") is True:
        return None
    if any(type(key) is not str for key in source):
        return None
    session, writer = source.get("session_id"), source.get("writer_id")
    if not (
        type(session) is str
        and is_valid_id(IdKind.SESSION, session)
        and type(writer) is str
        and is_valid_id(IdKind.WRITER, writer)
    ):
        return None
    try:
        scope = _digest(_SCOPE_DOMAIN, {"session_id": session, "writer_id": writer})
        commitment = _digest(_COMMITMENT_DOMAIN, cast(JsonValue, dict(source)))
    except Exception:  # noqa: BLE001 - a body with no canonical form is simply not bindable
        return None
    return scope, commitment


def _now_ms() -> int:
    return int(time.time() * 1000)


def _owner_alive(pid: int | None) -> bool:
    """Whether the process that owns an in-flight binding may still be running its call."""

    if pid is None or pid == os.getpid():
        # The same pid with a different owner token is a previous process this one replaced.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except OSError:
        return True
    return True


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
    for raw_entry in cast(list[object], entries)[-_MAX_ENTRIES:]:
        if not isinstance(raw_entry, Mapping):
            continue
        item = cast(Mapping[str, object], raw_entry)
        commitment, scope = item.get("commitment"), item.get("scope")
        request_id, state = item.get("request_id"), item.get("state")
        owner, pid, at_ms = item.get("owner"), item.get("pid"), item.get("at_ms")
        if (
            type(commitment) is str
            and len(commitment) == 71
            and commitment.startswith("sha256:")
            and type(scope) is str
            and len(scope) == 71
            and scope.startswith("sha256:")
            and type(request_id) is str
            and is_valid_id(IdKind.REQUEST, request_id)
            and state in {"in_flight", "unresolved"}
            and (owner is None or (type(owner) is str and 1 <= len(owner) <= 64))
            and (pid is None or (type(pid) is int and pid > 0))
            and type(at_ms) is int
            and at_ms >= 0
        ):
            result.append(
                _Entry(
                    commitment,
                    scope,
                    request_id,
                    cast(_State, state),
                    owner,
                    pid,
                    at_ms,
                )
            )
    return result


def _open_flags(*, write: bool) -> int:
    flags = (os.O_RDWR | os.O_CREAT if write else os.O_RDONLY) | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _read(directory: Path) -> list[_Entry]:
    try:
        descriptor = os.open(directory / _RECORD, _open_flags(write=False))
    except FileNotFoundError:
        return []
    try:
        raw = os.read(descriptor, _MAX_FILE_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_FILE_BYTES:
        return []
    return _parse(raw)


def _write(directory: Path, entries: list[_Entry]) -> None:
    payload = json.dumps(
        {"entries": [entry.as_json() for entry in entries[-_MAX_ENTRIES:]], "schema": _SCHEMA},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")
    temporary = directory / f".{_RECORD}.{os.urandom(8).hex()}.tmp"
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
        os.replace(temporary, directory / _RECORD)
    except OSError:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise
    # The rename itself must survive a crash before the bound call is sent.
    directory_descriptor = os.open(directory, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


@contextlib.contextmanager
def _locked(directory: Path) -> Generator[None]:
    lock = os.open(directory / _LOCK, _open_flags(write=True), 0o600)
    try:
        if fcntl is not None:
            fcntl.flock(lock, fcntl.LOCK_EX)
        yield
    finally:
        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(lock, fcntl.LOCK_UN)
        os.close(lock)


class PublishCallIdentities:
    """The durable binding of id-less publish calls to minted request ids, for one host process.

    ``state_root`` defaults to the user state directory; ``owner`` identifies this process's
    in-flight calls (a fresh random token per instance). ``clock_ms`` and ``mint`` are seams for
    tests.
    """

    def __init__(
        self,
        *,
        state_root: Path | None = None,
        owner: str | None = None,
        clock_ms: Callable[[], int] = _now_ms,
        mint: Callable[[], str] | None = None,
    ) -> None:
        self._state_root = state_root
        self._owner = owner if owner is not None else os.urandom(16).hex()
        self._clock_ms = clock_ms
        self._mint = mint if mint is not None else (lambda: new_id(IdKind.REQUEST))

    def _directory(self) -> Path:
        root = state_dir() if self._state_root is None else self._state_root
        return root / PUBLISH_CALLS_DIRECTORY

    def _update[T](self, change: Callable[[list[_Entry]], T], *, create: bool) -> T | None:
        directory = self._directory()
        if create:
            ensure_owner_only_dir(directory)
        elif not directory.is_dir() or directory.is_symlink():
            return None
        with _locked(directory):
            entries = _read(directory)
            now = self._clock_ms()
            live = [entry for entry in entries if 0 <= now - entry.at_ms <= RESUME_WINDOW_MS]
            before = [entry.as_json() for entry in live]
            outcome = change(live)
            if [entry.as_json() for entry in live] != before or len(live) != len(entries):
                _write(directory, live)
            return outcome

    def bind(self, arguments: Mapping[str, object]) -> PublishCallBinding:
        """Mint (or resume) and durably record the request id of one id-less publish call.

        Raises :class:`PublishCallIdentityUnavailable` when the body cannot be bound or the record
        cannot be written; the caller must then not send the body.
        """

        identity = publish_call_commitment(arguments)
        if identity is None:
            raise PublishCallIdentityUnavailable("publish_call_not_bindable")
        scope, commitment = identity

        def change(entries: list[_Entry]) -> PublishCallBinding:
            now = self._clock_ms()
            for entry in reversed(entries):
                if entry.commitment != commitment:
                    continue
                resumable = entry.state == "unresolved" or (
                    entry.owner != self._owner and not _owner_alive(entry.pid)
                )
                if not resumable:
                    # Still running in a live process (a concurrent identical call): never share
                    # its identity; this call is its own operation.
                    break
                entry.state, entry.owner, entry.pid, entry.at_ms = (
                    "in_flight",
                    self._owner,
                    os.getpid(),
                    now,
                )
                return PublishCallBinding(entry.request_id, commitment, scope, True)
            request_id = self._mint()
            if not is_valid_id(IdKind.REQUEST, request_id):
                raise PublishCallIdentityUnavailable("publish_call_mint_invalid")
            entries.append(
                _Entry(commitment, scope, request_id, "in_flight", self._owner, os.getpid(), now)
            )
            del entries[:-_MAX_ENTRIES]
            return PublishCallBinding(request_id, commitment, scope, False)

        try:
            binding = self._update(change, create=True)
        except PublishCallIdentityUnavailable:
            raise
        except (OSError, PathSafetyError, ValueError) as exc:
            raise PublishCallIdentityUnavailable("publish_call_record_unavailable") from exc
        if binding is None:  # pragma: no cover - create=True always yields an outcome
            raise PublishCallIdentityUnavailable("publish_call_record_unavailable")
        return binding

    def settle(self, binding: PublishCallBinding, *, delivered: bool) -> None:
        """Close one bound call. Never raises.

        ``delivered``: an ``ok: true`` outcome reached the caller, so the binding and every other
        unresolved binding of the same writer are dropped. Otherwise the binding stays resumable
        by the next identical call from that writer.
        """

        def change(entries: list[_Entry]) -> None:
            now = self._clock_ms()
            if delivered:
                entries[:] = [
                    entry
                    for entry in entries
                    if entry.request_id != binding.request_id
                    and not (entry.scope == binding.scope and entry.state == "unresolved")
                ]
                return
            for entry in entries:
                if entry.request_id == binding.request_id and entry.owner == self._owner:
                    entry.state, entry.owner, entry.pid, entry.at_ms = "unresolved", None, None, now

        with contextlib.suppress(Exception):
            self._update(change, create=False)

    def settle_caller_identity(self, arguments: Mapping[str, object], request_id: str) -> None:
        """Close the binding a caller-sent ``request_id`` delivered. Never raises.

        An agent told to retry a call "with the same request_id" sends the bound id itself. Once
        that retry delivers, the binding is closed exactly as if the host had sent it, so a later
        deliberate identical body is a new publication.
        """

        session, writer = arguments.get("session_id"), arguments.get("writer_id")
        if type(session) is not str or type(writer) is not str:
            return
        try:
            scope = _digest(_SCOPE_DOMAIN, {"session_id": session, "writer_id": writer})
        except Exception:  # noqa: BLE001 - never fail a delivered call over its bookkeeping
            return

        def change(entries: list[_Entry]) -> None:
            entries[:] = [
                entry
                for entry in entries
                if entry.request_id != request_id
                and not (entry.scope == scope and entry.state == "unresolved")
            ]

        with contextlib.suppress(Exception):
            self._update(change, create=False)
