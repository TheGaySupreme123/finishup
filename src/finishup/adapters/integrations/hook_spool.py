"""Crash-safe, structural-only ingress spool for synchronous legacy hooks.

The hook process deliberately does not open the observation state document.  It
only appends one bounded structural record; the READY service owns hydration,
mapping, outbox insertion and forwarding.
"""

from __future__ import annotations

import contextlib
import os
import uuid
from collections.abc import Generator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Final, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX hosts provide the spool lock primitive
    fcntl = None  # type: ignore[assignment]

from finishup.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from finishup.domain.observation import workspace_commitment_from_path
from finishup.protocol.canonical import JsonValue, canonical_encode, strict_json_parse

__all__ = ["HookSpool", "SpooledHookObservation"]

_MAX_RECORD_BYTES: Final = 8 * 1024
DEFAULT_HOOK_SPOOL_CLAIM_LIMIT: Final = 64
_SpoolFileIdentity = tuple[int, int]
_SAFE_FIELDS: Final = frozenset(
    {
        "session_id",
        "tool_name",
        "tool_use_id",
        "tool_call_id",
        "correlation_id",
        "parent_tool_call_id",
        "permission_decision",
        "permission_kind",
        "decision_reason_code",
        "result_status",
        "subagent_id",
        "claim_kind",
        "action",
        "changed_paths_digest",
        "command_commitment",
        "command_segment_commitments",
        "command_composition",
        "mapping_hint",
        "capability_profile_id",
        "codex_version",
        "exit_status",
        "duration_ms",
        "attempt",
        "success",
        "denied",
        "decision",
    }
)


@dataclass(frozen=True, slots=True)
class SpooledHookObservation:
    workspace_commitment: str
    event_name: str
    payload: Mapping[str, JsonValue]


class HookSpool:
    """An owner-only append spool with rename-based, replay-safe consumption."""

    def __init__(self, *, _state: Path | None = None) -> None:
        root = state_dir() if _state is None else _state
        self._root = root / "hook-spool"
        self._key_path = root / "observation" / "key-material.bin"

    def workspace_commitment(self, workspace: str) -> str:
        return workspace_commitment_from_path(self._key_material(), workspace)

    def append(self, *, workspace: str, event_name: str, payload: Mapping[str, JsonValue]) -> bool:
        """Durably append one bounded structural observation.

        This is intentionally the only write on a legacy host's critical path.
        It never opens the observation store or contacts the service.
        """

        if type(event_name) is not str or not event_name or len(event_name) > 128:
            return False
        safe = {key: value for key, value in payload.items() if key in _SAFE_FIELDS}
        session_id = safe.get("session_id")
        if type(session_id) is not str or not session_id or len(session_id) > 128:
            return False
        # Frozen legacy identifier (ADR-048): the key spooled payloads are replayed by, including
        # payloads an older release spooled before the upgrade.
        safe["_yoetz_spool_id"] = str(uuid.uuid4())
        commitment = self.workspace_commitment(workspace)
        body = {
            "event": event_name,
            "payload": safe,
            "workspace_commitment": commitment,
        }
        try:
            line = canonical_encode(cast(JsonValue, body)) + b"\n"
        except (TypeError, ValueError):
            return False
        if len(line) > _MAX_RECORD_BYTES:
            return False
        try:
            ensure_owner_only_dir(self._root)
            with self._workspace_lock(commitment):
                digest = commitment.removeprefix("hmac-sha256:")
                pending = self._root / f"{digest}.jsonl"
                draining = self._root / f"{digest}.draining"
                if draining.is_symlink() or pending.is_symlink():
                    return False
                # Once a service has claimed a file, append to that same inode. This keeps the
                # durable byte cursor ordered without a tail merge that could race a legacy hook.
                path = draining if draining.exists() else pending
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_APPEND
                    | os.O_CREAT
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    written = 0
                    while written < len(line):
                        written += os.write(descriptor, line[written:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            return True
        except (OSError, PathSafetyError):
            return False

    def pending_workspaces(self) -> tuple[str, ...]:
        try:
            ensure_owner_only_dir(self._root)
            names = list(self._root.glob("*.jsonl")) + list(self._root.glob("*.draining"))
        except (OSError, PathSafetyError):
            return ()
        result: set[str] = set()
        for path in names:
            if path.is_symlink() or not path.is_file() or len(path.stem) != 64:
                continue
            result.add(f"hmac-sha256:{path.stem}")
        return tuple(sorted(result, key=str.encode))

    def has_pending(self, workspace_commitment: str) -> bool:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        return len(digest) == 64 and any(
            (self._root / f"{digest}{suffix}").exists() for suffix in (".jsonl", ".draining")
        )

    @contextlib.contextmanager
    def claim(
        self,
        workspace_commitment: str,
        *,
        limit: int = DEFAULT_HOOK_SPOOL_CLAIM_LIMIT,
    ) -> Generator[tuple[SpooledHookObservation, ...]]:
        """Fence one bounded batch; failure leaves the durable cursor unchanged.

        ``.draining`` remains the append target while a claim is active. The cursor sidecar is
        advanced only after the caller's processing succeeds, so a crash or rejected record
        replays the batch at least once while a file larger than ``limit`` advances in FIFO
        batches instead of being loaded into memory or deleted as one giant pass.
        """

        if type(limit) is not int or isinstance(limit, bool) or limit < 1:
            raise ValueError("hook_spool_claim_limit_invalid")
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        pending = self._root / f"{digest}.jsonl"
        draining = self._root / f"{digest}.draining"
        if len(digest) != 64:
            yield ()
            return
        handle: BinaryIO | None = None
        try:
            records, next_offset, identity, handle = self._claim_batch(
                workspace_commitment,
                pending,
                draining,
                limit,
            )
        except (OSError, PathSafetyError):
            yield ()
            return
        try:
            yield records
        except BaseException:
            # Leave the old cursor and full claimed file for at-least-once replay. The caller's
            # exception is its own outcome and must not be transformed into a spool mutation.
            raise
        else:
            if identity is not None:
                with contextlib.suppress(OSError, PathSafetyError):
                    self._commit_batch(workspace_commitment, draining, next_offset, identity)
        finally:
            if handle is not None:
                handle.close()

    def _claim_batch(
        self,
        workspace_commitment: str,
        pending: Path,
        draining: Path,
        limit: int,
    ) -> tuple[
        tuple[SpooledHookObservation, ...],
        int,
        _SpoolFileIdentity | None,
        BinaryIO | None,
    ]:
        ensure_owner_only_dir(self._root)
        with self._workspace_lock(workspace_commitment):
            if pending.is_symlink() or draining.is_symlink():
                raise PathSafetyError("hook_spool_symlink")
            if pending.exists() and not draining.exists():
                # A crash can leave the previous file's cursor after its draining inode was
                # removed. Clear it before fencing a new pending inode; otherwise a new file that
                # happens to be longer than the stale offset would skip its prefix.
                self._clear_offset(workspace_commitment)
                os.replace(pending, draining)
            if not draining.exists():
                return (), 0, None, None
            handle = draining.open("rb")
            try:
                stat = os.fstat(handle.fileno())
                size = stat.st_size
                identity = (stat.st_dev, stat.st_ino)
                offset = self._read_offset(workspace_commitment, size)
                records, next_offset = self._read_batch(
                    handle,
                    workspace_commitment,
                    offset,
                    limit,
                )
            except BaseException:
                handle.close()
                raise
            return records, next_offset, identity, handle

    def _commit_batch(
        self,
        workspace_commitment: str,
        draining: Path,
        next_offset: int,
        identity: _SpoolFileIdentity,
    ) -> None:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        cursor = self._root / f"{digest}.offset"
        with self._workspace_lock(workspace_commitment):
            if not draining.exists() or draining.is_symlink():
                return
            stat = draining.stat()
            current_identity = (stat.st_dev, stat.st_ino)
            if current_identity != identity:
                # A later generation replaced the claimed inode after this worker yielded. Its
                # cursor and file lifecycle are no longer ours to advance or delete.
                return
            size = stat.st_size
            current_offset = self._read_offset(workspace_commitment, size)
            if current_offset > next_offset:
                # Another generation committed a later batch while this worker was processing
                # its snapshot. Never move the cursor backwards and make that later batch replay
                # forever.
                return
            if next_offset < size:
                self._write_offset(cursor, next_offset)
                return
            # Appenders take the same lock and therefore cannot create a new line between this
            # size check and the unlink. A legacy pending file, if present from an older runtime,
            # remains untouched and is claimed on the next pass.
            with contextlib.suppress(OSError):
                draining.unlink()
            with contextlib.suppress(OSError):
                cursor.unlink()

    def _clear_offset(self, workspace_commitment: str) -> None:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        cursor = self._root / f"{digest}.offset"
        if cursor.is_symlink():
            raise PathSafetyError("hook_spool_offset_symlink")
        with contextlib.suppress(FileNotFoundError):
            cursor.unlink()

    def _read_offset(self, workspace_commitment: str, size: int) -> int:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        cursor = self._root / f"{digest}.offset"
        if not cursor.exists() or cursor.is_symlink():
            return 0
        descriptor: int | None = None
        try:
            descriptor = os.open(
                cursor,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
            raw = os.read(descriptor, 32)
            if os.read(descriptor, 1):
                raise OSError("hook_spool_offset_invalid")
            offset = int(raw.decode("ascii"))
        except (OSError, UnicodeDecodeError, ValueError) as exc:
            raise OSError("hook_spool_offset_invalid") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)
        return offset if 0 <= offset <= size else 0

    def _write_offset(self, cursor: Path, offset: int) -> None:
        temporary = self._root / f".{cursor.stem}.{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary,
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            data = str(offset).encode("ascii")
            written = 0
            while written < len(data):
                written += os.write(descriptor, data[written:])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        try:
            os.replace(temporary, cursor)
        except BaseException:
            with contextlib.suppress(OSError):
                temporary.unlink()
            raise

    def _read_batch(
        self,
        handle: BinaryIO,
        workspace_commitment: str,
        offset: int,
        limit: int,
    ) -> tuple[tuple[SpooledHookObservation, ...], int]:
        records: list[SpooledHookObservation] = []
        handle.seek(offset)
        next_offset = offset
        handle_is_continuation = False
        if offset > 0:
            handle.seek(offset - 1)
            handle_is_continuation = handle.read(1) != b"\n"
            handle.seek(offset)
        for _ in range(limit):
            item = self._read_bounded_line(handle)
            if item is None:
                break
            line, terminated = item
            next_offset = handle.tell()
            if handle_is_continuation:
                # The previous bounded claim ended in the middle of an oversized line. Do
                # not reinterpret any valid-looking JSON fragment before its newline as a
                # new structural record.
                if terminated:
                    handle_is_continuation = False
                continue
            if not terminated and not line:
                handle_is_continuation = True
                continue
            row = self._parse_line(line, workspace_commitment)
            if row is not None:
                records.append(row)
        return tuple(records), next_offset

    @staticmethod
    def _read_bounded_line(handle: BinaryIO) -> tuple[bytes, bool] | None:
        """Read one bounded chunk; oversized corrupt lines advance over multiple passes."""

        chunk = handle.readline(_MAX_RECORD_BYTES + 1)
        if not chunk:
            return None
        # Appenders reject records above _MAX_RECORD_BYTES. A corrupt giant line is consumed in
        # bounded chunks and discarded, so close cannot leave a worker scanning an unbounded line.
        terminated = chunk.endswith(b"\n")
        return (chunk if len(chunk) <= _MAX_RECORD_BYTES else b"", terminated)

    @contextlib.contextmanager
    def _workspace_lock(self, workspace_commitment: str) -> Generator[None]:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        lock_path = self._root / f"{digest}.lock"
        descriptor: int | None = None
        try:
            descriptor = os.open(
                lock_path,
                os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            os.fchmod(descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            if descriptor is not None:
                try:
                    if fcntl is not None:
                        fcntl.flock(descriptor, fcntl.LOCK_UN)
                finally:
                    os.close(descriptor)

    @staticmethod
    def _parse_line(line: bytes, workspace: str) -> SpooledHookObservation | None:
        if not line or len(line) > _MAX_RECORD_BYTES:
            return None
        try:
            value = strict_json_parse(line)
        except Exception:
            return None
        if not isinstance(value, Mapping):
            return None
        event = value.get("event")
        payload = value.get("payload")
        commitment = value.get("workspace_commitment")
        if event is None or commitment != workspace or not isinstance(payload, Mapping):
            return None
        if type(event) is not str or type(commitment) is not str:
            return None
        return SpooledHookObservation(
            workspace_commitment=commitment,
            event_name=event,
            payload=cast(Mapping[str, JsonValue], payload),
        )

    def _key_material(self) -> bytes:
        ensure_owner_only_dir(self._root)
        try:
            descriptor = os.open(
                self._key_path,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
            )
        except FileNotFoundError as exc:
            raise OSError("hook_spool_key_missing") from exc
        else:
            try:
                key = os.read(descriptor, 65)
            finally:
                os.close(descriptor)
            if not 16 <= len(key) <= 64:
                raise OSError("hook_spool_key_invalid")
            return key
