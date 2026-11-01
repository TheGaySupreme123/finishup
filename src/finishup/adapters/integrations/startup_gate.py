"""Private, structural required-startup state; no observation or ledger access."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import stat
import uuid
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from finishup.config.paths import ensure_owner_only_dir, state_dir
from finishup.protocol.canonical import JsonValue
from finishup.protocol.ids import IdKind, is_valid_id

_MAX_BYTES = 65_536


@dataclass
class GateScope:
    generation: str
    began_at: str
    needs_start: bool = True
    route: tuple[str, str, str] | None = None
    plan_id: str | None = None
    plan_version: int = 0
    plan_refs: list[str] = field(default_factory=lambda: list[str]())
    required_refs: list[str] = field(default_factory=lambda: list[str]())
    plan_generation: str | None = None
    pending: dict[str, str] = field(default_factory=lambda: dict[str, str]())
    pending_refs: dict[str, list[str]] = field(default_factory=lambda: dict[str, list[str]]())
    pending_generations: dict[str, str] = field(default_factory=lambda: dict[str, str]())

    @classmethod
    def fresh(cls, previous: GateScope | None = None) -> GateScope:
        return cls(
            generation=str(uuid.uuid4()),
            began_at=datetime.now(UTC).isoformat(timespec="milliseconds"),
            needs_start=True if previous is None else previous.needs_start,
            route=None if previous is None else previous.route,
            plan_id=None if previous is None else previous.plan_id,
            plan_version=0 if previous is None else previous.plan_version,
            plan_refs=[] if previous is None else previous.plan_refs.copy(),
            required_refs=[] if previous is None else previous.required_refs.copy(),
            pending={} if previous is None else previous.pending.copy(),
            pending_refs={} if previous is None else previous.pending_refs.copy(),
            pending_generations={} if previous is None else previous.pending_generations.copy(),
        )

    @property
    def candidate(self) -> bool:
        return (
            self.route is not None
            and not self.needs_start
            and self.plan_id is not None
            and self.plan_generation == self.generation
            and bool(self.plan_refs)
            and set(self.required_refs).issubset(self.plan_refs)
            and not self.pending
        )


def _decode(raw: bytes) -> GateScope:
    obj: JsonValue = json.loads(raw)
    if not isinstance(obj, dict) or set(obj) != {"schema", *GateScope.__dataclass_fields__}:
        raise ValueError("startup_gate_state_invalid")
    if obj.pop("schema") != "yoetz.startup-gate/1":
        raise ValueError("startup_gate_state_invalid")
    if type(obj["needs_start"]) is not bool:
        raise ValueError("startup_gate_state_invalid")
    for name in ("generation", "plan_generation"):
        value = obj[name]
        if name == "plan_generation" and value is None:
            continue
        if not isinstance(value, str) or str(uuid.UUID(value)) != value:
            raise ValueError("startup_gate_state_invalid")
    if not isinstance(obj["began_at"], str):
        raise ValueError("startup_gate_state_invalid")
    if datetime.fromisoformat(obj["began_at"]).tzinfo is None:
        raise ValueError("startup_gate_state_invalid")
    route = obj["route"]
    if route is not None:
        if (
            not isinstance(route, list)
            or len(route) != 3
            or not all(
                isinstance(value, str) and is_valid_id(kind, value)
                for kind, value in zip(
                    (IdKind.TASK, IdKind.SESSION, IdKind.WRITER), route, strict=True
                )
            )
        ):
            raise ValueError("startup_gate_state_invalid")
    if obj["plan_id"] is not None and (
        not isinstance(obj["plan_id"], str) or not is_valid_id(IdKind.EVENT, obj["plan_id"])
    ):
        raise ValueError("startup_gate_state_invalid")
    if type(obj["plan_version"]) is not int or not 0 <= obj["plan_version"] <= 2**53 - 1:
        raise ValueError("startup_gate_state_invalid")
    for name in ("plan_refs", "required_refs"):
        refs = obj[name]
        if (
            not isinstance(refs, list)
            or len(refs) > 256
            or not all(isinstance(ref, str) and is_valid_id(IdKind.OBLIGATION, ref) for ref in refs)
        ):
            raise ValueError("startup_gate_state_invalid")
        if refs != sorted(set(cast(list[str], refs))):
            raise ValueError("startup_gate_state_invalid")
    pending = obj["pending"]
    if (
        not isinstance(pending, dict)
        or len(pending) > 32
        or not all(
            is_valid_id(IdKind.REQUEST, key) and value in {"start", "publish_work"}
            for key, value in pending.items()
        )
    ):
        raise ValueError("startup_gate_state_invalid")
    pending_refs = obj["pending_refs"]
    pending_generations = obj["pending_generations"]
    if not isinstance(pending_refs, dict) or not isinstance(pending_generations, dict):
        raise ValueError("startup_gate_state_invalid")
    if set(pending_refs) != set(pending) or set(pending_generations) != set(pending):
        raise ValueError("startup_gate_state_invalid")
    for rid, refs in pending_refs.items():
        if (
            not isinstance(refs, list)
            or len(refs) > 100
            or not all(isinstance(ref, str) and is_valid_id(IdKind.OBLIGATION, ref) for ref in refs)
        ):
            raise ValueError("startup_gate_state_invalid")
        epoch = pending_generations[rid]
        if not isinstance(epoch, str) or str(uuid.UUID(epoch)) != epoch:
            raise ValueError("startup_gate_state_invalid")
    return GateScope(
        generation=cast(str, obj["generation"]),
        began_at=obj["began_at"],
        needs_start=obj["needs_start"],
        route=None if route is None else cast(tuple[str, str, str], tuple(route)),
        plan_id=obj["plan_id"],
        plan_version=obj["plan_version"],
        plan_refs=cast(list[str], obj["plan_refs"]),
        required_refs=cast(list[str], obj["required_refs"]),
        plan_generation=cast(str | None, obj["plan_generation"]),
        pending=cast(dict[str, str], pending),
        pending_refs=cast(dict[str, list[str]], pending_refs),
        pending_generations=cast(dict[str, str], pending_generations),
    )


def _read_private(path: Path) -> bytes | None:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("startup_gate_state_unsafe")
        raw = stream.read(_MAX_BYTES + 1)
    if len(raw) > _MAX_BYTES:
        raise ValueError("startup_gate_state_invalid")
    return raw


class GateStore:
    """One nonblocking per-session lock, separate from all observation locks.

    Filenames retain only a digest of workspace and host identity. Contents are
    generated epochs, protocol ids and bounded sets; no prompt/tool prose.
    """

    def __init__(self, host: str, session: str, workspace: str, *, root: Path | None = None):
        if host not in {"claude", "cursor"} or not session or len(session) > 128:
            raise ValueError("startup_gate_identity_invalid")
        base = state_dir() if root is None else root
        ensure_owner_only_dir(base)
        self.directory = base / "startup-gates"
        ensure_owner_only_dir(self.directory)
        key = hashlib.sha256(json.dumps([host, session, workspace]).encode()).hexdigest()
        self.path = self.directory / f"{key}.json"
        self.lock_path = self.directory / f"{key}.lock"
        self.invalidation_path = self.directory / f"{key}.invalid"

    @contextmanager
    def locked(self) -> Generator[None]:
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise ValueError("startup_gate_state_unsafe")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            yield
        finally:
            os.close(fd)

    def read(self) -> GateScope | None:
        # A reset that could not be persisted leaves this durable marker behind.
        # It takes precedence over any stale scope, including one rewritten by a
        # process that held the lock while the reset was contended.
        if _read_private(self.invalidation_path) is not None:
            return None
        raw = _read_private(self.path)
        return None if raw is None else _decode(raw)

    def read_for_reset(self) -> GateScope | None:
        """Read the previous scope while the reset lock is held.

        A reset must preserve the route and every pending request identity from
        the previous sidecar.  The invalidation marker still makes ordinary
        readers fail closed, but a reset that owns the lock is the recovery
        operation which may replace that marker with a freshly written scope.
        """

        raw = _read_private(self.path)
        return None if raw is None else _decode(raw)

    def is_invalidated(self) -> bool:
        """Return whether ordinary writes must wait for a successful reset."""

        return _read_private(self.invalidation_path) is not None

    def invalidate(self) -> bool:
        """Durably make this scope unreadable until a reset succeeds."""

        try:
            fd = os.open(
                self.invalidation_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
            )
        except FileExistsError:
            return True
        except OSError:
            return False
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(b"invalidated\n")
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            return True
        except OSError:
            return False

    def clear_invalidation(self) -> None:
        """Clear a prior invalidation only after a reset state was written."""

        self.invalidation_path.unlink(missing_ok=True)

    def write(self, scope: GateScope) -> None:
        data = json.dumps(
            {"schema": "yoetz.startup-gate/1", **asdict(scope)}, sort_keys=True
        ).encode()
        _decode(data)
        if len(data) > _MAX_BYTES:
            raise ValueError("startup_gate_state_invalid")
        temporary = self.directory / f".{uuid.uuid4()}.tmp"
        try:
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            temporary.unlink(missing_ok=True)


def accepted_publication(
    scope: GateScope, request: Mapping[str, JsonValue], result: Mapping[str, JsonValue]
) -> None:
    """Nominate a plan from exact accepted drafts, never from a ready flag.

    The live service still has to confirm the route and effective plan before
    every substantive tool. Unknown/redacted output cannot nominate readiness.
    """

    if (
        scope.route is None
        or (request.get("session_id"), request.get("writer_id")) != scope.route[1:]
    ):
        scope.plan_generation = None
        return
    if (result.get("task_id"), result.get("session_id"), result.get("writer_id")) != scope.route:
        scope.plan_generation = None
        return
    rows = result.get("accepted_events")
    drafts = request.get("event_drafts")
    if result.get("ok") is not True or result.get("outcome") != "accepted":
        return
    if not isinstance(rows, list) or not isinstance(drafts, list) or len(drafts) > 100:
        scope.plan_generation = None
        return
    accepted = {
        cast(str, row.get("event_id")): row
        for row in rows
        if isinstance(row, dict) and isinstance(row.get("event_id"), str)
    }
    for position, draft in enumerate(drafts):
        if not isinstance(draft, dict):
            scope.plan_generation = None
            return
        # Issue #1084: a draft may omit ``event_id``; the service minted it, and accepted events
        # are returned in draft order, so the row at the same position names it.
        event_id_value: object = draft.get("event_id")
        if event_id_value is None and len(rows) == len(drafts):
            positional = rows[position]
            event_id_value = positional.get("event_id") if isinstance(positional, dict) else None
        if not isinstance(event_id_value, str) or event_id_value not in accepted:
            scope.plan_generation = None
            return
        draft_event_id = event_id_value
        row = accepted[draft_event_id]
        schema, payload = draft.get("schema"), draft.get("payload")
        if not isinstance(schema, dict) or not isinstance(payload, dict):
            scope.plan_generation = None
            return
        name = schema.get("name")
        if row.get("schema_name") != name:
            scope.plan_generation = None
            return
        if name == "obligation_published":
            obligation = payload.get("obligation_id")
            if not isinstance(obligation, str) or not is_valid_id(IdKind.OBLIGATION, obligation):
                scope.plan_generation = None
                return
            required = set(scope.required_refs)
            # acknowledged_not_done (#1002) is not resolved: still required, like open.
            if payload.get("status") in {"open", "acknowledged_not_done"}:
                required.add(obligation)
            elif payload.get("status") == "resolved":
                required.discard(obligation)
            scope.required_refs = sorted(required)
        if name not in {"plan_published", "plan_revised"}:
            continue
        if draft_event_id == scope.plan_id and scope.plan_generation != scope.generation:
            # Wall clocks can share a millisecond (or move backwards). An
            # idempotent replay of the previous plan is not a new scope.
            scope.plan_generation = None
            continue
        accepted_at = row.get("accepted_at")
        if not isinstance(accepted_at, str) or (
            datetime.fromisoformat(accepted_at) < datetime.fromisoformat(scope.began_at)
        ):
            scope.plan_generation = None
            continue
        version = payload.get("plan_version")
        if type(version) is not int:
            scope.plan_generation = None
            return
        if name == "plan_published":
            refs = payload.get("obligation_refs")
            if not isinstance(refs, list) or not all(
                isinstance(ref, str) and is_valid_id(IdKind.OBLIGATION, ref) for ref in refs
            ):
                scope.plan_generation = None
                return
            scope.plan_refs = sorted(set(cast(list[str], refs)))
        else:
            changes = payload.get("obligation_changes")
            if scope.plan_version != payload.get("supersedes_plan_version") or not isinstance(
                changes, list
            ):
                scope.plan_generation = None
                return
            refs = set(scope.plan_refs)
            for change in changes:
                if not isinstance(change, dict):
                    raise ValueError("startup_gate_plan_invalid")
                obligation = change.get("obligation_id")
                if not isinstance(obligation, str):
                    raise ValueError("startup_gate_plan_invalid")
                if change.get("change") in {"superseded", "waived"}:
                    refs.discard(obligation)
                    scope.required_refs = [ref for ref in scope.required_refs if ref != obligation]
                    replacements = change.get("replacement_obligation_ids", [])
                    if not isinstance(replacements, list) or not all(
                        isinstance(ref, str) for ref in replacements
                    ):
                        raise ValueError("startup_gate_plan_invalid")
                    refs.update(cast(list[str], replacements))
                elif change.get("change") == "carried":
                    refs.add(obligation)
            scope.plan_refs = sorted(refs)
        scope.plan_version = version
        scope.plan_id = draft_event_id
        scope.plan_generation = scope.generation
