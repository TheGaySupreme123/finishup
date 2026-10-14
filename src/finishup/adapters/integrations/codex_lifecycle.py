"""Private Codex↔FinishUP structural lifecycle correlation mapping store."""

from __future__ import annotations

import contextlib
import os
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Final, cast

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError
from finishup.protocol.ids import IdKind, is_valid_id, validate_id

try:
    import fcntl
except ImportError:  # pragma: no cover - lifecycle hosts are POSIX in production
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "MAPPING_VERSION",
    "LifecycleMapping",
    "RouteHistory",
    "acquire_session_lock",
    "acquire_workspace_recovery_lock",
    "apply_pending_mapping",
    "clear_mapping",
    "codex_lifecycle_dir",
    "encode_frontier_token",
    "load_latest_mapping",
    "load_mapping",
    "mapping_from_start_ids",
    "mapping_path",
    "load_route_history",
    "parse_frontier_token",
    "queue_mapping_clear",
    "queue_mapping_store",
    "is_scoped_child_session_id",
    "scoped_child_session_id",
    "store_mapping",
    "validate_codex_session_id",
]

MAPPING_VERSION: Final = 1
_MAPPING_KEYS: Final = frozenset(
    {
        "mapping_version",
        "codex_session_id",
        "yoetz_task_id",
        "yoetz_session_id",
        "yoetz_writer_id",
        "last_frontier",
    }
)
_MAX_MAPPING_BYTES: Final = 4_096
_MAX_ROUTE_HISTORY_BYTES: Final = 4_096
_MAX_ROUTE_HISTORY: Final = 5
_ROUTE_HISTORY_SCHEMA: Final = "yoetz.codex-route-history/1"
_MAX_PENDING_MAPPING_BYTES: Final = 8_192
_MAX_CODEX_SESSION_ID_CHARS: Final = 128
_MAX_FRONTIER_TOKEN_CHARS: Final = 128
_LOCK_STALE_SECONDS: Final = 30.0
_MAX_LOCK_TOKEN_BYTES: Final = 128
_MAX_LOCK_PID_DIGITS: Final = 10
_CODEX_SESSION_ID_RE: Final = re.compile(r"^[!-~]+$", re.ASCII)
# Frozen legacy identifier (ADR-048): scoped child-lane session ids are recorded in lifecycle
# mappings, so their prefix keeps the pre-rename spelling.
_SCOPED_CHILD_SESSION_PREFIX: Final = "yoetz-child-lane-"
_SCOPED_CHILD_SESSION_RE: Final = re.compile(
    rf"^{re.escape(_SCOPED_CHILD_SESSION_PREFIX)}[0-9a-f]{{64}}$", re.ASCII
)
_CHILD_LANE_HOSTS: Final = frozenset({"claude", "codex", "cursor"})
_CHILD_LANE_IDENTITY_KINDS: Final = frozenset({"host", "task"})
_WORKSPACE_COMMITMENT_RE: Final = re.compile(r"^hmac-sha256:[0-9a-f]{64}$", re.ASCII)
_FRONTIER_DIGEST_RE: Final = re.compile(
    r"^(?:genesis|sha256:[0-9a-f]{64})$",
    re.ASCII,
)


@dataclass(frozen=True, slots=True)
class LifecycleMapping:
    """Allowlisted structural Codex session → FinishUP identity correlation."""

    mapping_version: int
    codex_session_id: str
    yoetz_task_id: str
    yoetz_session_id: str
    yoetz_writer_id: str
    last_frontier: str | None

    def to_wire(self) -> dict[str, JsonValue]:
        return {
            "mapping_version": self.mapping_version,
            "codex_session_id": self.codex_session_id,
            "yoetz_task_id": self.yoetz_task_id,
            "yoetz_session_id": self.yoetz_session_id,
            "yoetz_writer_id": self.yoetz_writer_id,
            "last_frontier": self.last_frontier,
        }


@dataclass(frozen=True, slots=True)
class RouteHistory:
    """Bounded predecessor bindings retained for one Codex lifecycle mapping."""

    routes: tuple[tuple[str, str], ...]
    truncated: bool


def validate_codex_session_id(value: object) -> str:
    """Validate a bounded opaque Codex session token (no path separators)."""

    if type(value) is not str:
        raise ProtocolValueError("id_wrong_type")
    if not 1 <= len(value) <= _MAX_CODEX_SESSION_ID_CHARS:
        raise ProtocolValueError("id_wrong_length")
    if "/" in value or "\\" in value or "\0" in value:
        raise ProtocolValueError("id_malformed_uuid")
    if _CODEX_SESSION_ID_RE.fullmatch(value) is None:
        raise ProtocolValueError("id_not_ascii")
    return value


def scoped_child_session_id(
    parent_codex_session_id: object,
    *,
    host: object,
    identity: object,
    identity_kind: object,
) -> str:
    """Derive a bounded opaque lane for one validated native child identity.

    A child lane is deliberately a digest rather than a concatenation of host supplied
    identifiers.  The parent session, host adapter, and identity namespace are all part of
    the preimage, so an arbitrary native identifier cannot collide with a different lane or
    with an ordinary host-session mapping.  The returned value is safe for the lifecycle
    mapping filename and for all public request validation paths.
    """

    parent = validate_codex_session_id(parent_codex_session_id)
    if type(host) is not str or host not in _CHILD_LANE_HOSTS:
        raise ProtocolValueError("id_malformed_uuid")
    if type(identity_kind) is not str or identity_kind not in _CHILD_LANE_IDENTITY_KINDS:
        raise ProtocolValueError("id_malformed_uuid")
    child_identity = validate_codex_session_id(identity)
    material: dict[str, JsonValue] = {
        "domain": "yoetz/codex-child-lane/v1",
        "parent_session_id": parent,
        "host": host,
        "identity_kind": identity_kind,
        "identity": child_identity,
    }
    digest = canonical_digest(material).removeprefix("sha256:")
    return _SCOPED_CHILD_SESSION_PREFIX + digest


def is_scoped_child_session_id(value: object) -> bool:
    """Return whether *value* is an opaque child-lane identifier we derived."""

    return type(value) is str and _SCOPED_CHILD_SESSION_RE.fullmatch(value) is not None


def encode_frontier_token(*, sequence: str, head_digest: str) -> str:
    """Encode a frontier as a bounded opaque structural token."""

    if type(sequence) is not str or type(head_digest) is not str:
        raise ProtocolValueError("invalid_frontier")
    if not sequence.isascii() or not sequence.isdecimal():
        raise ProtocolValueError("invalid_frontier")
    if _FRONTIER_DIGEST_RE.fullmatch(head_digest) is None:
        raise ProtocolValueError("invalid_frontier")
    token = f"{sequence}:{head_digest}"
    if len(token) > _MAX_FRONTIER_TOKEN_CHARS:
        raise ProtocolValueError("invalid_frontier")
    return token


def parse_frontier_token(token: str) -> tuple[str, str]:
    """Parse a previously encoded frontier token."""

    if type(token) is not str or len(token) > _MAX_FRONTIER_TOKEN_CHARS:
        raise ProtocolValueError("invalid_frontier")
    sequence, separator, digest = token.partition(":")
    if separator != ":" or not sequence or not digest:
        raise ProtocolValueError("invalid_frontier")
    validated = encode_frontier_token(sequence=sequence, head_digest=digest)
    left, _, right = validated.partition(":")
    return left, right


def _ensure_lifecycle_dir(path: Path) -> None:
    try:
        ensure_owner_only_dir(path)
    except PathSafetyError:
        # Concurrent creators can race on mkdir; accept an already-private directory.
        if not path.is_dir() or path.is_symlink():
            raise
        mode = path.stat().st_mode & 0o777
        if mode != 0o700:
            raise


def codex_lifecycle_dir(*, _state: Path | None = None) -> Path:
    """Return the private plugin lifecycle state directory under the FinishUP state root."""

    root = state_dir() if _state is None else _state
    path = root / "codex-lifecycle"
    _ensure_lifecycle_dir(root)
    _ensure_lifecycle_dir(path)
    return path


def mapping_path(codex_session_id: str, *, _state: Path | None = None) -> Path:
    """Return the mapping file path for one validated Codex session id."""

    session_id = validate_codex_session_id(codex_session_id)
    return codex_lifecycle_dir(_state=_state) / f"{session_id}.json"


def _route_history_path(codex_session_id: str, *, _state: Path | None = None) -> Path:
    session_id = validate_codex_session_id(codex_session_id)
    directory = codex_lifecycle_dir(_state=_state) / "route-history"
    _ensure_lifecycle_dir(directory)
    # Keep the sidecar namespace separate from mapping files. Codex session
    # ids are printable opaque tokens, so a suffix-based sibling name could
    # collide with another valid session id (``session.history`` vs
    # ``session``).
    return directory / f"{session_id}.json"


def _write_private_atomic(path: Path, payload: bytes) -> None:
    """Write one owner-only lifecycle file with cleanup on every failure path."""

    temporary = path.with_name(f".{path.name}.{os.urandom(8).hex()}.tmp")
    descriptor: int | None = None
    try:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(temporary, flags, 0o600)
        try:
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short_write")
                view = view[written:]
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
            descriptor = None
        os.replace(temporary, path)
        os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        if descriptor is not None:
            with contextlib.suppress(OSError):
                os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _decode_route_history(raw: object) -> tuple[str, RouteHistory] | None:
    if not isinstance(raw, Mapping):
        return None
    document = cast(Mapping[str, JsonValue], raw)
    if frozenset(document) != frozenset({"schema", "task_id", "routes", "truncated"}):
        return None
    if document.get("schema") != _ROUTE_HISTORY_SCHEMA:
        return None
    task_id = document.get("task_id")
    if type(task_id) is not str:
        return None
    try:
        task_id = validate_id(IdKind.TASK, task_id)
    except ProtocolValueError:
        return None
    raw_routes = document.get("routes")
    truncated = document.get("truncated")
    if type(truncated) is not bool:
        return None
    if not isinstance(raw_routes, (list, tuple)):
        return None
    routes_raw = cast(list[JsonValue] | tuple[JsonValue, ...], raw_routes)
    if not 0 <= len(routes_raw) <= _MAX_ROUTE_HISTORY:
        return None
    routes: list[tuple[str, str]] = []
    for raw_route in routes_raw:
        if not isinstance(raw_route, Mapping):
            return None
        route_document = cast(Mapping[str, JsonValue], raw_route)
        if frozenset(route_document) != frozenset({"session_id", "writer_id"}):
            return None
        session_id = route_document.get("session_id")
        writer_id = route_document.get("writer_id")
        try:
            session_id = validate_id(IdKind.SESSION, session_id)
            writer_id = validate_id(IdKind.WRITER, writer_id)
        except ProtocolValueError:
            return None
        route = (session_id, writer_id)
        if route not in routes:
            routes.append(route)
    return task_id, RouteHistory(tuple(routes), truncated)


def load_route_history(
    mapping: LifecycleMapping, *, _state: Path | None = None
) -> RouteHistory | None:
    """Load bounded predecessor routes retained beside a lifecycle mapping.

    The mapping file is a one-slot cache and may be replaced after a session
    retirement.  This sidecar keeps the session/writer pairs that were present
    before those replacements, so a process restart can still probe legacy
    session-bound observation operations.  A missing sidecar is an empty,
    complete history; a present malformed sidecar is reported as ``None`` so
    callers fail closed instead of reminting an old operation graph.  A valid
    sidecar for another task is ignored. ``truncated`` records that an older
    predecessor was evicted at the bound.
    """

    if type(mapping) is not LifecycleMapping:
        return None
    try:
        path = _route_history_path(mapping.codex_session_id, _state=_state)
        if not path.exists() and not path.is_symlink():
            return RouteHistory((), False)
        if path.is_symlink() or not path.is_file():
            return None
        if path.stat().st_size <= 0 or path.stat().st_size > _MAX_ROUTE_HISTORY_BYTES:
            return None
        raw_bytes = path.read_bytes()
        if not 0 < len(raw_bytes) <= _MAX_ROUTE_HISTORY_BYTES:
            return None
        parsed = strict_json_parse(raw_bytes)
        decoded = _decode_route_history(parsed)
    except OSError, ProtocolValueError, UnicodeError, TypeError, ValueError:
        return None
    if decoded is None:
        return None
    if decoded[0] != mapping.yoetz_task_id:
        return RouteHistory((), False)
    return decoded[1]


def _write_route_history(
    mapping: LifecycleMapping,
    routes: tuple[tuple[str, str], ...],
    *,
    truncated: bool,
    _state: Path | None,
) -> None:
    if not 0 <= len(routes) <= _MAX_ROUTE_HISTORY or type(truncated) is not bool:
        raise ProtocolValueError("unsupported_json_type")
    payload = (
        canonical_encode(
            {
                "schema": _ROUTE_HISTORY_SCHEMA,
                "task_id": mapping.yoetz_task_id,
                "routes": tuple(
                    {"session_id": session_id, "writer_id": writer_id}
                    for session_id, writer_id in routes
                ),
                "truncated": truncated,
            }
        )
        + b"\n"
    )
    if len(payload) > _MAX_ROUTE_HISTORY_BYTES:
        raise ProtocolValueError("unsupported_json_type")
    _write_private_atomic(_route_history_path(mapping.codex_session_id, _state=_state), payload)


def _retain_predecessor_route(mapping: LifecycleMapping, *, _state: Path | None) -> None:
    prior = load_route_history(mapping, _state=_state)
    if prior is None:
        raise ProtocolValueError("unsupported_json_type")
    route = (mapping.yoetz_session_id, mapping.yoetz_writer_id)
    if route in prior.routes:
        return
    routes = (*prior.routes, route)
    _write_route_history(
        mapping,
        routes[-_MAX_ROUTE_HISTORY:],
        truncated=prior.truncated or len(routes) > _MAX_ROUTE_HISTORY,
        _state=_state,
    )


def _parse_mapping(
    raw: Mapping[str, JsonValue], *, expected_session: str | None
) -> LifecycleMapping:
    if frozenset(raw) != _MAPPING_KEYS:
        raise ProtocolValueError("unsupported_json_type")
    version = raw.get("mapping_version")
    if type(version) is not int or version != MAPPING_VERSION:
        raise ProtocolValueError("unsupported_json_type")
    codex_session_id = validate_codex_session_id(raw.get("codex_session_id"))
    if expected_session is not None and codex_session_id != expected_session:
        raise ProtocolValueError("unsupported_json_type")
    task_id = validate_id(IdKind.TASK, raw.get("yoetz_task_id"))
    session_id = validate_id(IdKind.SESSION, raw.get("yoetz_session_id"))
    writer_id = validate_id(IdKind.WRITER, raw.get("yoetz_writer_id"))
    frontier = raw.get("last_frontier")
    if frontier is not None:
        if type(frontier) is not str:
            raise ProtocolValueError("invalid_frontier")
        parse_frontier_token(frontier)
    return LifecycleMapping(
        mapping_version=MAPPING_VERSION,
        codex_session_id=codex_session_id,
        yoetz_task_id=task_id,
        yoetz_session_id=session_id,
        yoetz_writer_id=writer_id,
        last_frontier=frontier,
    )


def load_mapping(codex_session_id: str, *, _state: Path | None = None) -> LifecycleMapping | None:
    """Load one mapping; malformed/unknown-version/oversized files are treated as absent."""

    try:
        path = mapping_path(codex_session_id, _state=_state)
    except ProtocolValueError:
        return None
    try:
        if not path.is_file() or path.is_symlink():
            return None
        size = path.stat().st_size
        if size <= 0 or size > _MAX_MAPPING_BYTES:
            return None
        raw_bytes = path.read_bytes()
        if len(raw_bytes) > _MAX_MAPPING_BYTES:
            return None
        parsed = strict_json_parse(raw_bytes)
        if not isinstance(parsed, Mapping):
            return None
        return _parse_mapping(
            cast(Mapping[str, JsonValue], parsed), expected_session=codex_session_id
        )
    except OSError, ProtocolValueError, UnicodeError, TypeError, ValueError:
        return None


def load_latest_mapping(
    codex_session_ids: tuple[str, ...], *, _state: Path | None = None
) -> LifecycleMapping | None:
    """Load the most recently written valid mapping from bounded local candidates.

    The caller owns workspace and lifecycle eligibility. This adapter only ranks the
    already-known session selectors by the owner-only mapping file's modification time;
    malformed, missing, and symlinked candidates remain absent exactly as in ``load_mapping``.
    """

    latest: tuple[int, bytes, LifecycleMapping] | None = None
    for codex_session_id in codex_session_ids:
        mapping = load_mapping(codex_session_id, _state=_state)
        if mapping is None:
            continue
        try:
            path = mapping_path(codex_session_id, _state=_state)
            if path.is_symlink():
                continue
            modified_ns = path.stat().st_mtime_ns
        except OSError, ProtocolValueError:
            continue
        candidate = (modified_ns, codex_session_id.encode("ascii"), mapping)
        if latest is None or candidate[:2] > latest[:2]:
            latest = candidate
    return None if latest is None else latest[2]


def store_mapping(mapping: LifecycleMapping, *, _state: Path | None = None) -> None:
    """Atomically write one allowlisted mapping (0600). Rejects non-allowlisted content."""

    if type(mapping) is not LifecycleMapping:
        raise ProtocolValueError("unsupported_json_type")
    validated = _parse_mapping(mapping.to_wire(), expected_session=mapping.codex_session_id)
    previous = load_mapping(validated.codex_session_id, _state=_state)
    if previous is None or previous.yoetz_task_id != validated.yoetz_task_id:
        # A clear can stop after unlinking the mapping but before its history.
        # Reset that orphan before publishing a new attachment of the same host.
        history = _route_history_path(validated.codex_session_id, _state=_state)
        if history.exists() or history.is_symlink():
            _write_route_history(validated, (), truncated=False, _state=_state)
    if (
        previous is not None
        and previous.yoetz_task_id == validated.yoetz_task_id
        and (
            previous.yoetz_session_id != validated.yoetz_session_id
            or previous.yoetz_writer_id != validated.yoetz_writer_id
        )
    ):
        # Persist the predecessor before replacing the one-slot mapping. A
        # process can die after the replacement and before the observation
        # request reaches its ledger lookup; the next process must still know
        # which session-bound legacy writers to probe.
        _retain_predecessor_route(previous, _state=_state)
    path = mapping_path(validated.codex_session_id, _state=_state)
    encoded = canonical_encode(validated.to_wire()) + b"\n"
    if len(encoded) > _MAX_MAPPING_BYTES:
        raise ProtocolValueError("unsupported_json_type")
    _write_private_atomic(path, encoded)


def clear_mapping(codex_session_id: str, *, _state: Path | None = None) -> None:
    """Remove one mapping file if present; ignores absence."""

    try:
        path = mapping_path(codex_session_id, _state=_state)
    except ProtocolValueError:
        return
    with contextlib.suppress(OSError, FileNotFoundError):
        if path.is_file() and not path.is_symlink():
            path.unlink()
    history = _route_history_path(codex_session_id, _state=_state)
    with contextlib.suppress(OSError, FileNotFoundError):
        if history.is_file() and not history.is_symlink():
            history.unlink()


def _pending_mapping_path(codex_session_id: str, *, _state: Path | None = None) -> Path:
    session_id = validate_codex_session_id(codex_session_id)
    return codex_lifecycle_dir(_state=_state) / f".{session_id}.pending.json"


def _queue_mapping_operation(
    codex_session_id: str,
    payload: Mapping[str, JsonValue],
    *,
    _state: Path | None,
) -> None:
    path = _pending_mapping_path(codex_session_id, _state=_state)
    encoded = canonical_encode(dict(payload)) + b"\n"
    if len(encoded) > _MAX_PENDING_MAPPING_BYTES:
        raise ProtocolValueError("unsupported_json_type")
    _write_private_atomic(path, encoded)


def queue_mapping_store(mapping: LifecycleMapping, *, _state: Path | None = None) -> None:
    """Durably queue one validated mapping until its session lock is available."""

    if type(mapping) is not LifecycleMapping:
        raise ProtocolValueError("unsupported_json_type")
    validated = _parse_mapping(mapping.to_wire(), expected_session=mapping.codex_session_id)
    _queue_mapping_operation(
        validated.codex_session_id,
        {
            "schema": "yoetz.pending-mapping/1",
            "operation": "store",
            "mapping": validated.to_wire(),
        },
        _state=_state,
    )


def queue_mapping_clear(codex_session_id: str, *, _state: Path | None = None) -> None:
    """Durably queue a mapping clear independent of observation consent."""

    session_id = validate_codex_session_id(codex_session_id)
    _queue_mapping_operation(
        session_id,
        {
            "schema": "yoetz.pending-mapping/1",
            "operation": "clear",
            "codex_session_id": session_id,
        },
        _state=_state,
    )


def _load_pending_mapping_operation(
    codex_session_id: str, *, _state: Path | None = None, claimed_path: Path | None = None
) -> tuple[str, LifecycleMapping | None] | None:
    try:
        path = claimed_path or _pending_mapping_path(codex_session_id, _state=_state)
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size > _MAX_PENDING_MAPPING_BYTES
        ):
            return None
        raw = strict_json_parse(path.read_bytes())
        if not isinstance(raw, Mapping) or raw.get("schema") != "yoetz.pending-mapping/1":
            return None
        operation = raw.get("operation")
        if operation == "clear" and raw.get("codex_session_id") == codex_session_id:
            return ("clear", None)
        if operation != "store" or not isinstance(raw.get("mapping"), Mapping):
            return None
        mapping = _parse_mapping(
            cast(Mapping[str, JsonValue], raw["mapping"]),
            expected_session=codex_session_id,
        )
        return ("store", mapping)
    except OSError, ProtocolValueError, UnicodeError, TypeError, ValueError:
        return None


def apply_pending_mapping(codex_session_id: str, *, _state: Path | None = None) -> bool:
    """Apply and remove one queued mapping operation; caller holds the session lock."""

    pending = _pending_mapping_path(codex_session_id, _state=_state)
    path = pending.with_name(pending.name + ".applying")
    # Only the session-lock owner claims work. Producers replace only `pending`,
    # so a new update cannot be removed when this claimed operation completes.
    # A crash leaves the claimed operation available for idempotent replay.
    if not path.exists() and not path.is_symlink():
        try:
            os.replace(pending, path)
        except FileNotFoundError:
            return False
    operation = _load_pending_mapping_operation(codex_session_id, _state=_state, claimed_path=path)
    if operation is None:
        return False
    kind, mapping = operation
    if kind == "clear":
        clear_mapping(codex_session_id, _state=_state)
    elif mapping is not None:
        # Derived child lanes are identity reservations. A stale pending write
        # must never retarget an alias that has since been claimed by another
        # task; malformed existing state remains pending for an explicit
        # attribution gap rather than being replaced.
        if is_scoped_child_session_id(codex_session_id):
            existing_path = mapping_path(codex_session_id, _state=_state)
            if existing_path.exists() or existing_path.is_symlink():
                existing = load_mapping(codex_session_id, _state=_state)
                if existing is None or existing.yoetz_task_id != mapping.yoetz_task_id:
                    return False
        store_mapping(mapping, _state=_state)
    else:
        return False
    with contextlib.suppress(OSError, FileNotFoundError):
        if path.is_file() and not path.is_symlink():
            path.unlink()
    return True


def _lock_path(codex_session_id: str, *, _state: Path | None = None) -> Path:
    session_id = validate_codex_session_id(codex_session_id)
    return codex_lifecycle_dir(_state=_state) / f".{session_id}.lock"


def _workspace_recovery_lock_path(workspace_commitment: str, *, _state: Path | None = None) -> Path:
    """Return one collision-safe lock path for a validated workspace commitment."""

    if (
        type(workspace_commitment) is not str
        or _WORKSPACE_COMMITMENT_RE.fullmatch(workspace_commitment) is None
    ):
        raise ProtocolValueError("invalid_commitment")
    digest = workspace_commitment.removeprefix("hmac-sha256:")
    directory = codex_lifecycle_dir(_state=_state) / "workspace-recovery-locks"
    _ensure_lifecycle_dir(directory)
    # Keep workspace reservations in a dedicated directory.  A host session id
    # is intentionally allowed to contain this prefix, so a filename prefix
    # alone would collide with the per-session lock namespace.
    return directory / f"{digest}.lock"


def acquire_session_lock(
    codex_session_id: str,
    *,
    _state: Path | None = None,
    stale_seconds: float = _LOCK_STALE_SECONDS,
) -> _SessionLock:
    """Acquire a per-session lock file; context manager yields True when this caller owns the lock.

    Duplicate concurrent session-start events must not stampede the service. A stale lock older
    than ``stale_seconds`` is broken once. Callers that do not acquire the lock should no-op.
    """

    return _SessionLock(codex_session_id, _state=_state, stale_seconds=stale_seconds)


def acquire_workspace_recovery_lock(
    workspace_commitment: str,
    *,
    _state: Path | None = None,
    stale_seconds: float = _LOCK_STALE_SECONDS,
) -> _WorkspaceRecoveryLock:
    """Acquire the nonblocking reservation held while a workspace recovers.

    Membership creators use this reservation before their per-session lock. A
    recovery pass holds it across scan revalidation, the service RPC, and route
    rewrites, without holding the observation store lock over the network wait.
    """

    return _WorkspaceRecoveryLock(
        _workspace_recovery_lock_path(workspace_commitment, _state=_state),
        stale_seconds=stale_seconds,
    )


class _LifecycleLock:
    __slots__ = ("_guard_descriptor", "_owned", "_path", "_stale_seconds", "_token")

    def __init__(
        self,
        path: Path,
        *,
        stale_seconds: float,
    ) -> None:
        if type(stale_seconds) is not float or not 0.1 <= stale_seconds <= 300.0:
            raise ValueError("lock_stale_timeout_invalid")
        self._path = path
        self._stale_seconds = stale_seconds
        self._owned = False
        self._token: bytes | None = None
        # The takeover guard is held for the entire lifetime of a claimed
        # marker.  Re-acquiring it only during ``__exit__`` leaves a window in
        # which a stale contender can replace the marker before the old owner
        # unlinks it.
        self._guard_descriptor: int | None = None

    @staticmethod
    def _owner_is_dead(token: bytes) -> bool:
        """Return true only when the lock payload names a definitively dead PID."""

        pid_raw, separator, _stamp = token.rstrip(b"\n").partition(b":")
        if separator != b":" or not pid_raw.isdigit() or len(pid_raw) > _MAX_LOCK_PID_DIGITS:
            return False
        try:
            pid = int(pid_raw)
        except ValueError:
            return False
        if pid <= 0 or pid > 2_147_483_647:
            return False
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except OSError:
            # Permission and platform errors are unknown ownership, so stale
            # takeover fails closed instead of replacing a live owner.
            return False
        return False

    def _read_token(self) -> tuple[bytes, float] | None:
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(self._path, flags)
        except OSError:
            return None
        try:
            facts = os.fstat(descriptor)
            if not stat.S_ISREG(facts.st_mode) or facts.st_size > _MAX_LOCK_TOKEN_BYTES:
                return None
            token = os.read(descriptor, _MAX_LOCK_TOKEN_BYTES + 1)
            if len(token) > _MAX_LOCK_TOKEN_BYTES:
                return None
            return token, facts.st_mtime
        except OSError:
            return None
        finally:
            os.close(descriptor)

    def _stale_token(self) -> bytes | None:
        snapshot = self._read_token()
        if snapshot is None:
            return None
        token, modified = snapshot
        if time.time() - modified < self._stale_seconds:
            return None
        if not self._owner_is_dead(token):
            return None
        return token

    def _open_takeover_guard(self) -> int | None:
        """Open and claim the persistent guard, or return ``None`` on failure."""

        if fcntl is None:
            # O_EXCL still serializes fresh creation. Stale takeover is disabled
            # by ``__enter__`` below because compare/unlink is not a CAS here.
            return None
        guard_path = self._path.with_name(self._path.name + ".takeover")
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor: int | None = None
        try:
            descriptor = os.open(guard_path, flags, 0o600)
            facts = os.fstat(descriptor)
            owner = os.geteuid() if hasattr(os, "geteuid") else os.getuid()
            if (
                not stat.S_ISREG(facts.st_mode)
                or stat.S_IMODE(facts.st_mode) != 0o600
                or facts.st_uid != owner
            ):
                with contextlib.suppress(OSError):
                    os.close(descriptor)
                return None
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return descriptor
        except OSError:
            if descriptor is not None:
                with contextlib.suppress(OSError):
                    os.close(descriptor)
            return None

    @staticmethod
    def _close_takeover_guard(descriptor: int) -> None:
        """Release one held advisory guard descriptor."""

        if fcntl is not None:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        with contextlib.suppress(OSError):
            os.close(descriptor)

    def _take_over(self, expected: bytes, flags: int, payload: bytes) -> bool:
        """Remove one unchanged dead-owner file and claim its path."""

        try:
            current = self._read_token()
            if current is None or current[0] != expected:
                return False
            self._path.unlink()
        except OSError:
            return False
        try:
            descriptor = os.open(self._path, flags, 0o600)
            try:
                os.write(descriptor, payload)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except FileExistsError:
            return False
        except OSError:
            # The old token was already removed. Never unlink again here: a
            # concurrent claimant may have replaced the path after our open.
            return False
        self._token = payload
        self._owned = True
        return True

    def __enter__(self) -> bool:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        payload = f"{os.getpid()}:{time.time_ns()}\n".encode("ascii")
        guard_descriptor = self._open_takeover_guard()
        if fcntl is not None and guard_descriptor is None:
            return False
        try:
            try:
                descriptor = os.open(self._path, flags, 0o600)
                try:
                    os.write(descriptor, payload)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                self._owned = True
                self._token = payload
            except FileExistsError:
                if fcntl is not None:
                    stale_token = self._stale_token()
                    if stale_token is not None:
                        # The held guard serializes the re-read, unlink, and
                        # claim; another stale contender cannot remove our
                        # replacement before this owner releases it.
                        self._take_over(stale_token, flags, payload)
            if self._owned:
                self._guard_descriptor = guard_descriptor
                guard_descriptor = None
        finally:
            if guard_descriptor is not None:
                self._close_takeover_guard(guard_descriptor)
        return self._owned

    def __exit__(self, *_exc: object) -> None:
        if self._owned and self._token is not None:
            release_failed = False
            try:
                current = self._read_token()
                if current is not None and current[0] == self._token:
                    self._path.unlink()
            except OSError:
                # Keep the ownership fields when release failed.  Clearing
                # them while leaving a live marker behind would make the
                # marker appear ownerless to this process and could wedge the
                # lifecycle until stale recovery.
                release_failed = True
            finally:
                descriptor = self._guard_descriptor
                self._guard_descriptor = None
                if descriptor is not None:
                    self._close_takeover_guard(descriptor)
            if not release_failed:
                self._owned = False
                self._token = None


class _SessionLock(_LifecycleLock):
    __slots__ = ()

    def __init__(
        self,
        codex_session_id: str,
        *,
        _state: Path | None,
        stale_seconds: float,
    ) -> None:
        super().__init__(_lock_path(codex_session_id, _state=_state), stale_seconds=stale_seconds)


class _WorkspaceRecoveryLock(_LifecycleLock):
    __slots__ = ()

    def __init__(self, path: Path, *, stale_seconds: float) -> None:
        super().__init__(path, stale_seconds=stale_seconds)


def mapping_from_start_ids(
    *,
    codex_session_id: str,
    yoetz_task_id: str,
    yoetz_session_id: str,
    yoetz_writer_id: str,
    last_frontier: str | None,
) -> LifecycleMapping:
    """Build a validated mapping from already-extracted structural IDs."""

    if last_frontier is not None and not (
        type(last_frontier) is str and len(last_frontier) <= _MAX_FRONTIER_TOKEN_CHARS
    ):
        raise ProtocolValueError("invalid_frontier")
    if last_frontier is not None:
        parse_frontier_token(last_frontier)
    if not is_valid_id(IdKind.TASK, yoetz_task_id):
        raise ProtocolValueError("id_wrong_prefix")
    return LifecycleMapping(
        mapping_version=MAPPING_VERSION,
        codex_session_id=validate_codex_session_id(codex_session_id),
        yoetz_task_id=validate_id(IdKind.TASK, yoetz_task_id),
        yoetz_session_id=validate_id(IdKind.SESSION, yoetz_session_id),
        yoetz_writer_id=validate_id(IdKind.WRITER, yoetz_writer_id),
        last_frontier=last_frontier,
    )
