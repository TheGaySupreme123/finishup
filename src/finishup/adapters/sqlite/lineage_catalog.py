"""SQLite implementation of the service-owned lineage catalog.

The normal start catalog owns route identity and the task/session tables.  This adapter owns the
additional durable rows needed by delegation: operation phases, opaque attach capabilities, and
the frozen dependency manifest.  It deliberately shares the start catalog connection, so a
reservation cannot create a second in-memory authority for a task.

The numbered catalog migration owns all DDL.  Opening this adapter only validates that migration
has been applied; it never changes the schema itself.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import datetime, timedelta
from types import TracebackType
from typing import Final, Literal, cast

import apsw

from finishup.application.lineage import (
    AttachHandle,
    DelegationOperation,
    DelegationOperationState,
    DelegationPhase,
    DependencyManifest,
    LineageSnapshot,
    LineageStore,
)
from finishup.domain.coordination import (
    SESSION_LEASE_SECONDS,
    LineageAcceptance,
    LineageOrigin,
    SessionHealth,
    WorkState,
)
from finishup.domain.values import (
    format_rfc3339_millis,
    frontier_from_json,
    parse_rfc3339_millis,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.start_catalog import SessionState
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, validate_id

__all__ = ["SqliteLineageStore"]


_ROUTE_FIELDS: Final = """
task_id, active_session_id, bundle_relpath, route_generation,
active_route_identity_digest, state, repository_privacy_commitment,
parent_task_id, depth, lineage_digest, origin, acceptance, work_state,
created_at, updated_at
"""
_SESSION_FIELDS: Final = "task_id, session_id, health, changed_at, lease_expires_at, actor_id"
_MAX_SAFE_INTEGER: Final = 2**53 - 1


def _error(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    reason: str | None = None,
) -> PublicOperationError:
    details: dict[str, object] = {}
    if reason is not None:
        details["reason_code"] = reason
    return PublicOperationError(code, message, retryable, safe_details=details)


def _text(value: object) -> str:
    if type(value) is not str:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    return _text(value)


def _integer(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
    return value


def _digest(value: object) -> str:
    if type(value) is not str or len(value) != 71 or not value.startswith("sha256:"):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
    if any(item not in "0123456789abcdef" for item in value[7:]):
        raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
    return value


def _timestamp(value: object) -> datetime:
    try:
        return parse_rfc3339_millis(value)
    except (TypeError, ValueError) as exc:
        raise _error(
            PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent."
        ) from exc


def _manifest_integer(value: object, *, optional: bool = False) -> int | None:
    """Decode numeric manifest fields without accepting booleans or string coercions."""

    if optional and value is None:
        return None
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise ValueError("manifest_integer_invalid")
    return value


class _Transaction:
    def __init__(self, db: apsw.Connection) -> None:
        self.db = db

    def __enter__(self) -> None:
        try:
            self.db.execute("BEGIN IMMEDIATE")
        except apsw.BusyError as exc:
            raise _error(
                PublicErrorCode.BUNDLE_BUSY,
                "The lineage catalog is temporarily busy.",
                retryable=True,
                reason="lineage_catalog_busy",
            ) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> Literal[False]:
        if exc_type is None:
            self.db.execute("COMMIT")
        else:
            self.db.execute("ROLLBACK")
        return False


class SqliteLineageStore(LineageStore):
    """Durable lineage store sharing the installation catalog connection."""

    def __init__(
        self,
        connection: apsw.Connection,
        *,
        installation_id: str,
        clock: ClockPort,
        ids: IdPort | None = None,
        contact_lost_recovery_seconds: int = 300,
    ) -> None:
        if type(connection) is not apsw.Connection:
            raise TypeError("lineage_connection_invalid")
        self._db = connection
        self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)
        self._clock = clock
        self._ids = ids
        if (
            type(contact_lost_recovery_seconds) is not int
            or not 1 <= contact_lost_recovery_seconds <= 86_400
        ):
            raise ValueError("lineage_recovery_window_invalid")
        self._contact_lost_recovery_seconds = contact_lost_recovery_seconds
        self._validate_tables()

    @property
    def connection(self) -> apsw.Connection:
        """Return the shared connection for service composition and migration inspection."""

        return self._db

    def _validate_tables(self) -> None:
        """Require the numbered catalog migration to have installed lineage tables."""

        expected = {
            "lineage_task_meta",
            "lineage_operations",
            "lineage_operations_pending",
            "lineage_attach_handles",
            "lineage_manifests",
        }
        rows = self._db.execute(
            "SELECT name FROM sqlite_schema WHERE name IN "
            "('lineage_task_meta', 'lineage_operations', 'lineage_operations_pending', "
            "'lineage_attach_handles', 'lineage_manifests')"
        )
        present = {cast(str, row[0]) for row in rows if len(row) == 1 and type(row[0]) is str}
        if present != expected:
            raise _error(
                PublicErrorCode.MIGRATION_REQUIRED,
                "The catalog does not contain the lineage migration.",
                reason="lineage_catalog_migration_required",
            )

    def _rows(self, sql: str, bindings: tuple[apsw.Binding, ...] = ()) -> list[tuple[object, ...]]:
        return [cast(tuple[object, ...], row) for row in self._db.execute(sql, bindings)]

    def _new_session(self) -> str:
        if self._ids is None:
            from finishup.protocol.ids import new_id

            value = new_id(IdKind.SESSION)
        else:
            value = self._ids.new(IdKind.SESSION)
        return validate_id(IdKind.SESSION, value)

    def _route(self, task_id: str) -> tuple[object, ...] | None:
        rows = self._rows(
            f"SELECT {_ROUTE_FIELDS} FROM task_routes WHERE task_id = ? LIMIT 2",
            (task_id,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
        return None if not rows else rows[0]

    def _meta(
        self, task_id: str
    ) -> tuple[int, datetime | None, datetime | None, str | None, datetime | None]:
        rows = self._rows(
            "SELECT lineage_authority_revision, contact_lost_at, abandonment_deadline, "
            "abandonment_reason, quiet_until FROM lineage_task_meta WHERE task_id = ? LIMIT 2",
            (task_id,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
        if not rows:
            return 1, None, None, None, None
        row = rows[0]
        revision = _integer(row[0])
        if revision < 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage catalog is inconsistent.")
        return (
            revision,
            None if row[1] is None else _timestamp(row[1]),
            None if row[2] is None else _timestamp(row[2]),
            _optional_text(row[3]),
            None if row[4] is None else _timestamp(row[4]),
        )

    def _session_for_route(
        self, task_id: str, session_id: str
    ) -> tuple[SessionHealth, datetime, datetime | None]:
        rows = self._rows(
            f"SELECT {_SESSION_FIELDS} FROM task_sessions WHERE task_id = ? AND session_id = ? LIMIT 2",
            (task_id, session_id),
        )
        if len(rows) != 1:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The lineage session state is inconsistent."
            )
        row = rows[0]
        try:
            health = SessionHealth(_text(row[2]))
        except ValueError as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The lineage session state is inconsistent."
            ) from exc
        return health, _timestamp(row[3]), None if row[4] is None else _timestamp(row[4])

    def _snapshot_from_route(self, row: tuple[object, ...]) -> LineageSnapshot:
        if len(row) != 15:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage route is inconsistent.")
        task_id = _text(row[0])
        route_session = _text(row[1])
        try:
            health, _changed_at, lease_expires = self._session_for_route(task_id, route_session)
            revision, contact_lost_at, abandonment_deadline, abandonment_reason, quiet_until = (
                self._meta(task_id)
            )
            if health is SessionHealth.ACTIVE and (
                lease_expires is None or lease_expires <= self._clock.now_utc()
            ):
                # Status reads are observational.  Lease expiry is derived from the injected
                # clock; the service sweep owns the durable contact-lost transition and its
                # abandonment deadline.
                now = self._clock.now_utc()
                health = SessionHealth.CONTACT_LOST
                contact_lost_at = contact_lost_at or now
                abandonment_deadline = abandonment_deadline or (
                    now + timedelta(seconds=self._contact_lost_recovery_seconds)
                )
            active_session = route_session if health is not SessionHealth.ENDED else None
            return LineageSnapshot(
                task_id=task_id,
                parent_task_id=_optional_text(row[7]),
                depth=_integer(row[8]),
                origin=None if row[10] is None else LineageOrigin(_text(row[10])),
                acceptance=None if row[11] is None else LineageAcceptance(_text(row[11])),
                work_state=WorkState(_text(row[12])),
                session_health=health,
                active_session_id=active_session,
                repository_commitment=_optional_text(row[6]),
                contact_lost_at=contact_lost_at,
                abandonment_deadline=abandonment_deadline,
                lineage_authority_revision=revision,
                abandonment_reason=abandonment_reason,
                quiet_until=quiet_until,
            )
        except PublicOperationError:
            raise
        except (TypeError, ValueError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The lineage route is inconsistent."
            ) from exc

    async def get_task(self, task_id: str) -> LineageSnapshot | None:
        task = validate_id(IdKind.TASK, task_id)
        row = self._route(task)
        return None if row is None else self._snapshot_from_route(row)

    async def list_children(self, parent_task_id: str) -> tuple[LineageSnapshot, ...]:
        parent = validate_id(IdKind.TASK, parent_task_id)
        rows = self._rows(
            f"SELECT {_ROUTE_FIELDS} FROM task_routes WHERE parent_task_id = ? "
            "ORDER BY task_id ASC",
            (parent,),
        )
        return tuple(self._snapshot_from_route(row) for row in rows)

    async def list_tasks(self) -> tuple[LineageSnapshot, ...]:
        rows = self._rows(f"SELECT {_ROUTE_FIELDS} FROM task_routes ORDER BY task_id ASC")
        return tuple(self._snapshot_from_route(row) for row in rows)

    async def get_session_task(self, session_id: str) -> str | None:
        session = validate_id(IdKind.SESSION, session_id)
        rows = self._rows(
            "SELECT task_id FROM task_sessions WHERE session_id = ? LIMIT 2",
            (session,),
        )
        if len(rows) > 1:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The lineage session state is inconsistent."
            )
        if not rows:
            return None
        return validate_id(IdKind.TASK, _text(rows[0][0]))

    async def expire_session_leases(
        self, now: datetime | None = None, *, limit: int = 256
    ) -> tuple[SessionState, ...]:
        """Persist contact loss and its recovery deadline for expired task sessions.

        The start catalog has a similarly named operation, but the lineage store is the authority
        used by ``Application.recover_lineage``.  Keeping this write here is necessary after a
        process crash between the lease transition and the lineage metadata update: the next
        process must still know when the abandonment window ends.  This sweep is the only place
        that changes an expired lease; status reads remain observational.
        """

        effective_now = self._clock.now_utc() if now is None else now
        try:
            now_wire = format_rfc3339_millis(effective_now)
            if type(limit) is not int or not 1 <= limit <= 256:
                raise ValueError("session_expiry_limit_invalid")
        except (TypeError, ValueError) as exc:
            raise _error(
                PublicErrorCode.INVALID_REQUEST, "The session expiry request is invalid."
            ) from exc
        deadline_wire = format_rfc3339_millis(
            effective_now + timedelta(seconds=self._contact_lost_recovery_seconds)
        )
        with _Transaction(self._db):
            rows = self._rows(
                "SELECT task_id, session_id, health, changed_at, lease_expires_at, actor_id "
                "FROM task_sessions WHERE health = 'active' "
                "AND (lease_expires_at IS NULL OR lease_expires_at <= ?) "
                "ORDER BY session_id ASC LIMIT ?",
                (now_wire, limit),
            )
            expired: list[SessionState] = []
            for row in rows:
                if len(row) != 6:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The lineage session state is inconsistent.",
                    )
                task_id = validate_id(IdKind.TASK, _text(row[0]))
                session_id = validate_id(IdKind.SESSION, _text(row[1]))
                actor_id = _optional_text(row[5])
                self._db.execute(
                    "UPDATE task_sessions SET health = 'contact_lost', changed_at = ?, "
                    "lease_expires_at = NULL WHERE session_id = ? AND task_id = ? "
                    "AND health = 'active' AND (lease_expires_at IS NULL OR lease_expires_at <= ?)",
                    (now_wire, session_id, task_id, now_wire),
                )
                if self._db.changes() != 1:
                    continue
                self._db.execute(
                    "INSERT INTO lineage_task_meta(task_id, lineage_authority_revision, "
                    "contact_lost_at, abandonment_deadline) VALUES (?, 1, ?, ?) "
                    "ON CONFLICT(task_id) DO UPDATE SET "
                    "lineage_authority_revision = lineage_task_meta.lineage_authority_revision + 1, "
                    "contact_lost_at = COALESCE(lineage_task_meta.contact_lost_at, excluded.contact_lost_at), "
                    "abandonment_deadline = COALESCE(lineage_task_meta.abandonment_deadline, excluded.abandonment_deadline)",
                    (task_id, now_wire, deadline_wire),
                )
                expired.append(
                    SessionState(
                        task_id=task_id,
                        session_id=session_id,
                        health=SessionHealth.CONTACT_LOST,
                        changed_at=effective_now,
                        lease_expires_at=None,
                        actor_id=actor_id,
                    )
                )
            return tuple(expired)

    def _save_task_locked(
        self,
        snapshot: LineageSnapshot,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None:
        task = validate_id(IdKind.TASK, snapshot.task_id)
        now = self._clock.now_utc()
        now_wire = format_rfc3339_millis(now)
        route = self._route(task)
        lineage_digest = (
            "sha256:"
            + hashlib.sha256(
                canonical_encode(
                    {
                        "acceptance": None
                        if snapshot.acceptance is None
                        else snapshot.acceptance.value,
                        "depth": snapshot.depth,
                        "origin": None if snapshot.origin is None else snapshot.origin.value,
                        "parent_task_id": snapshot.parent_task_id,
                    }
                )
            ).hexdigest()
        )
        if route is None:
            route_session = snapshot.active_session_id or self._new_session()
            route_digest = canonical_digest(
                {"bundle_relpath": f"tasks/{task}", "route_generation": 1, "task_id": task}
            )
            # A delegated/self-registered child uses the parent's authenticated workspace as its
            # source scope. The lineage value itself intentionally carries only relationship and
            # repository facts; the shared start catalog owns the edit identity. Leaving these
            # commitments NULL would make the C9 source gate reject every accepted child read,
            # even when parent and child were minted in the same workspace.
            parent_workspace: str | None = None
            parent_external: str | None = None
            if (workspace_commitment is None) != (external_commitment is None):
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "The child source identity is invalid.",
                )
            if snapshot.parent_task_id is not None:
                # ``_ROUTE_FIELDS`` is intentionally the lineage projection and does not carry
                # the start catalog's workspace/external commitments.  Read those two source
                # bindings explicitly; using route tuple positions here would copy the parent's
                # session id and bundle path into commitment columns and make every child source
                # provenance invalid at the C9 gate.
                parent_rows = self._rows(
                    "SELECT workspace_ref_commitment, external_ref_commitment "
                    "FROM task_routes WHERE task_id = ? LIMIT 2",
                    (snapshot.parent_task_id,),
                )
                if len(parent_rows) > 1:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The parent route is inconsistent.",
                    )
                if parent_rows:
                    parent_workspace = _optional_text(parent_rows[0][0])
                    parent_external = _optional_text(parent_rows[0][1])
            if workspace_commitment is not None:
                parent_workspace = workspace_commitment
                parent_external = external_commitment
            self._db.execute(
                "INSERT INTO task_routes (task_id, workspace_ref_commitment, external_ref_commitment, "
                "active_session_id, bundle_relpath, route_generation, active_route_identity_digest, state, "
                "quarantine_code, created_at, updated_at, repository_privacy_commitment, parent_task_id, "
                "depth, lineage_digest, origin, acceptance, work_state) VALUES (?, ?, ?, ?, ?, 1, ?, "
                "'initializing', NULL, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    task,
                    parent_workspace,
                    parent_external,
                    route_session,
                    f"tasks/{task}",
                    route_digest,
                    now_wire,
                    now_wire,
                    snapshot.repository_commitment,
                    snapshot.parent_task_id,
                    snapshot.depth,
                    lineage_digest,
                    None if snapshot.origin is None else snapshot.origin.value,
                    None if snapshot.acceptance is None else snapshot.acceptance.value,
                    snapshot.work_state.value,
                ),
            )
            route = self._route(task)
            if route is None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT, "The lineage route could not be created."
                )
        else:
            if (
                _optional_text(route[6]) != snapshot.repository_commitment
                or _optional_text(route[7]) != snapshot.parent_task_id
                or _integer(route[8]) != snapshot.depth
                or (None if route[10] is None else LineageOrigin(_text(route[10])))
                != snapshot.origin
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage relationship is immutable.",
                    reason="lineage_task_conflict",
                )
            route_session = _text(route[1])
            if snapshot.active_session_id is None:
                # Preserve the ended placeholder when replaying an idempotent terminal write.
                # A new placeholder is needed only if this route still points at a live session.
                try:
                    current_health, _changed, _lease = self._session_for_route(task, route_session)
                except PublicOperationError:
                    current_health = SessionHealth.ENDED
                if current_health is not SessionHealth.ENDED:
                    route_session = self._new_session()
            else:
                route_session = validate_id(IdKind.SESSION, snapshot.active_session_id)
            self._db.execute(
                "UPDATE task_routes SET active_session_id = ?, depth = ?, lineage_digest = ?, "
                "origin = ?, acceptance = ?, work_state = ?, updated_at = ? WHERE task_id = ?",
                (
                    route_session,
                    snapshot.depth,
                    _text(route[9]),
                    None if snapshot.origin is None else snapshot.origin.value,
                    None if snapshot.acceptance is None else snapshot.acceptance.value,
                    snapshot.work_state.value,
                    now_wire,
                    task,
                ),
            )
        # A task has one active route session, but the history remains per-session.  Closing older
        # active rows here prevents a second writer from being mistaken for the current route.
        # This also applies when the task is ended: the route moves to an inert placeholder and
        # the previous live session must not remain a durable active row behind it.
        self._db.execute(
            "UPDATE task_sessions SET health = 'ended', changed_at = ?, ended_at = ?, "
            "lease_expires_at = NULL WHERE task_id = ? AND session_id != ? AND health != 'ended'",
            (now_wire, now_wire, task, route_session),
        )
        if snapshot.active_session_id is not None:
            lease = (
                format_rfc3339_millis(now + timedelta(seconds=SESSION_LEASE_SECONDS))
                if snapshot.session_health is SessionHealth.ACTIVE
                else None
            )
            changed_wire = now_wire
            if snapshot.session_health is SessionHealth.ACTIVE:
                # An unexpired lease already records this session's contact, possibly anchored at
                # an earlier host event.  Saving lineage metadata neither extends nor shortens it;
                # only a session entering ``active`` receives a fresh lease here (#837).
                current = self._rows(
                    "SELECT health, changed_at, lease_expires_at FROM task_sessions "
                    "WHERE task_id = ? AND session_id = ? LIMIT 2",
                    (task, route_session),
                )
                if (
                    len(current) == 1
                    and current[0][0] == SessionHealth.ACTIVE.value
                    and current[0][2] is not None
                    and _timestamp(current[0][2]) > now
                ):
                    lease = _text(current[0][2])
                    changed_wire = _text(current[0][1])
            self._db.execute(
                "INSERT INTO task_sessions(session_id, task_id, health, changed_at, created_at, ended_at, "
                "lease_expires_at, actor_id) VALUES (?, ?, ?, ?, ?, ?, ?, NULL) ON CONFLICT(session_id) DO UPDATE SET "
                "task_id = excluded.task_id, health = excluded.health, changed_at = excluded.changed_at, "
                "ended_at = excluded.ended_at, lease_expires_at = excluded.lease_expires_at",
                (
                    route_session,
                    task,
                    snapshot.session_health.value,
                    changed_wire,
                    now_wire,
                    now_wire if snapshot.session_health is SessionHealth.ENDED else None,
                    lease,
                ),
            )
        else:
            self._db.execute(
                "INSERT INTO task_sessions(session_id, task_id, health, changed_at, created_at, ended_at, "
                "lease_expires_at, actor_id) VALUES (?, ?, 'ended', ?, ?, ?, NULL, NULL) "
                "ON CONFLICT(session_id) DO UPDATE SET task_id = excluded.task_id, "
                "health = excluded.health, changed_at = excluded.changed_at, "
                "ended_at = excluded.ended_at, lease_expires_at = NULL",
                (route_session, task, now_wire, now_wire, now_wire),
            )
        self._db.execute(
            "INSERT INTO lineage_task_meta(task_id, lineage_authority_revision, contact_lost_at, "
            "abandonment_deadline, abandonment_reason, quiet_until) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(task_id) DO UPDATE SET lineage_authority_revision = excluded.lineage_authority_revision, "
            "contact_lost_at = excluded.contact_lost_at, abandonment_deadline = excluded.abandonment_deadline, "
            "abandonment_reason = excluded.abandonment_reason, quiet_until = excluded.quiet_until",
            (
                task,
                snapshot.lineage_authority_revision,
                None
                if snapshot.contact_lost_at is None
                else format_rfc3339_millis(snapshot.contact_lost_at),
                None
                if snapshot.abandonment_deadline is None
                else format_rfc3339_millis(snapshot.abandonment_deadline),
                snapshot.abandonment_reason,
                None
                if snapshot.quiet_until is None
                else format_rfc3339_millis(snapshot.quiet_until),
            ),
        )
        if snapshot.work_state in {
            WorkState.ABANDONED,
            WorkState.CANCELLED,
            WorkState.WRITTEN_OFF,
        }:
            # Keep lifecycle and capability revocation in the same catalog transaction.  The
            # coordinator also calls revoke_handles explicitly for the in-memory reference store;
            # this durable write closes the crash window between those two operations.
            self._db.execute(
                "UPDATE lineage_attach_handles SET revoked = 1 WHERE task_id = ? AND revoked = 0",
                (task,),
            )

    async def save_task(self, snapshot: LineageSnapshot) -> None:
        if type(snapshot) is not LineageSnapshot:
            raise TypeError("lineage_snapshot_invalid")
        with _Transaction(self._db):
            self._save_task_locked(snapshot)

    def _operation_row(self, operation_id: str) -> tuple[object, ...] | None:
        rows = self._rows(
            "SELECT operation_id, request_digest, parent_task_id, parent_session_id, child_task_id, depth, "
            "phase, state, handle_digest, owner_generation, lease_expires_at, terminal_at, "
            "project_id, membership_generation "
            "FROM lineage_operations WHERE installation_id = ? AND operation_id = ? LIMIT 2",
            (self._installation_id, operation_id),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage operation is inconsistent.")
        return None if not rows else rows[0]

    @staticmethod
    def _operation_value(row: tuple[object, ...]) -> DelegationOperation:
        if len(row) != 14:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The lineage operation is inconsistent.")
        try:
            project_value = None if row[12] is None else validate_id(IdKind.PROJECT, _text(row[12]))
            generation = None if row[13] is None else _integer(row[13])
            if (project_value is None) != (generation is None) or (
                generation is not None and generation < 1
            ):
                raise ValueError("lineage_project_admission_invalid")
            return DelegationOperation(
                operation_id=_text(row[0]),
                request_digest=_digest(row[1]),
                parent_task_id=validate_id(IdKind.TASK, _text(row[2])),
                parent_session_id=validate_id(IdKind.SESSION, _text(row[3])),
                child_task_id=validate_id(IdKind.TASK, _text(row[4])),
                depth=_integer(row[5]),
                phase=DelegationPhase(_text(row[6])),
                state=DelegationOperationState(_text(row[7])),
                handle_digest=_digest(row[8]),
                owner_generation=_integer(row[9]),
                lease_expires_at=_timestamp(row[10]),
                terminal_at=None if row[11] is None else _timestamp(row[11]),
                project_id=project_value,
                membership_generation=generation,
            )
        except (TypeError, ValueError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The lineage operation is inconsistent."
            ) from exc

    async def get_operation(self, operation_id: str) -> DelegationOperation | None:
        operation = validate_id(IdKind.REQUEST, operation_id)
        row = self._operation_row(operation)
        return None if row is None else self._operation_value(row)

    def _save_operation_locked(self, operation: DelegationOperation) -> None:
        existing = self._operation_row(operation.operation_id)
        if existing is not None:
            current = self._operation_value(existing)
            if (
                current.request_digest != operation.request_digest
                or current.parent_task_id != operation.parent_task_id
                or current.parent_session_id != operation.parent_session_id
                or current.child_task_id != operation.child_task_id
                or current.handle_digest != operation.handle_digest
                or current.project_id != operation.project_id
                or current.membership_generation != operation.membership_generation
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The lineage operation identity conflicts.",
                    reason="lineage_operation_conflict",
                )
            self._db.execute(
                "UPDATE lineage_operations SET depth = ?, phase = ?, state = ?, owner_generation = ?, "
                "lease_expires_at = ?, terminal_at = ? WHERE installation_id = ? AND operation_id = ?",
                (
                    operation.depth,
                    operation.phase.value,
                    operation.state.value,
                    operation.owner_generation,
                    format_rfc3339_millis(operation.lease_expires_at),
                    None
                    if operation.terminal_at is None
                    else format_rfc3339_millis(operation.terminal_at),
                    self._installation_id,
                    operation.operation_id,
                ),
            )
            return
        self._db.execute(
            "INSERT INTO lineage_operations(installation_id, operation_id, request_digest, parent_task_id, "
            "parent_session_id, child_task_id, depth, phase, state, handle_digest, owner_generation, "
            "lease_expires_at, terminal_at, project_id, membership_generation) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                self._installation_id,
                operation.operation_id,
                operation.request_digest,
                operation.parent_task_id,
                operation.parent_session_id,
                operation.child_task_id,
                operation.depth,
                operation.phase.value,
                operation.state.value,
                operation.handle_digest,
                operation.owner_generation,
                format_rfc3339_millis(operation.lease_expires_at),
                None
                if operation.terminal_at is None
                else format_rfc3339_millis(operation.terminal_at),
                operation.project_id,
                operation.membership_generation,
            ),
        )

    async def save_operation(self, operation: DelegationOperation) -> None:
        if type(operation) is not DelegationOperation:
            raise TypeError("lineage_operation_invalid")
        with _Transaction(self._db):
            self._save_operation_locked(operation)

    async def save_self_registration(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None:
        """Install a self-registered route and its terminal operation atomically.

        ``lineage_operations.child_task_id`` references ``task_routes``.  A self-registration is
        born without a handle reservation, so writing the operation first violates that foreign
        key; keeping both inserts in one catalog transaction also prevents an orphan route if the
        operation identity is rejected.
        """

        if (
            type(operation) is not DelegationOperation
            or type(child) is not LineageSnapshot
            or operation.child_task_id != child.task_id
        ):
            raise TypeError("lineage_self_registration_invalid")
        if (workspace_commitment is None) != (external_commitment is None):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child source identity is invalid.",
            )
        with _Transaction(self._db):
            existing = self._operation_row(operation.operation_id)
            if existing is not None:
                current = self._operation_value(existing)
                if current != operation:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The lineage operation identity conflicts.",
                        reason="lineage_operation_conflict",
                    )
                return
            if self._route(operation.child_task_id) is not None:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The self-registration child already exists.",
                    reason="lineage_task_conflict",
                )
            self._save_task_locked(
                child,
                workspace_commitment=workspace_commitment,
                external_commitment=external_commitment,
            )
            self._save_operation_locked(operation)

    async def list_operations(self) -> tuple[DelegationOperation, ...]:
        rows = self._rows(
            "SELECT operation_id, request_digest, parent_task_id, parent_session_id, child_task_id, depth, "
            "phase, state, handle_digest, owner_generation, lease_expires_at, terminal_at, "
            "project_id, membership_generation "
            "FROM lineage_operations WHERE installation_id = ? ORDER BY operation_id ASC",
            (self._installation_id,),
        )
        return tuple(self._operation_value(row) for row in rows)

    async def save_reservation(
        self,
        operation: DelegationOperation,
        child: LineageSnapshot,
        handle: AttachHandle,
        *,
        workspace_commitment: str | None = None,
        external_commitment: str | None = None,
    ) -> None:
        if (
            type(operation) is not DelegationOperation
            or type(child) is not LineageSnapshot
            or type(handle) is not AttachHandle
            or operation.child_task_id != child.task_id
            or operation.handle_digest != handle.digest
        ):
            raise TypeError("lineage_reservation_invalid")
        if (workspace_commitment is None) != (external_commitment is None):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "The child source identity is invalid.",
            )
        with _Transaction(self._db):
            if self._operation_row(operation.operation_id) is not None:
                current = self._operation_value(
                    cast(tuple[object, ...], self._operation_row(operation.operation_id))
                )
                if current != operation:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "The lineage operation identity conflicts.",
                        reason="lineage_operation_conflict",
                    )
                return
            self._save_task_locked(
                child,
                workspace_commitment=workspace_commitment,
                external_commitment=external_commitment,
            )
            self._save_operation_locked(operation)
            self._save_handle_locked(handle)

    def _handle_row(self, digest: str) -> tuple[object, ...] | None:
        rows = self._rows(
            "SELECT handle_digest, task_id, handle_value, expires_at, consumed_session_id, revoked "
            "FROM lineage_attach_handles WHERE handle_digest = ? LIMIT 2",
            (digest,),
        )
        if len(rows) > 1:
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The attach handle is inconsistent.")
        return None if not rows else rows[0]

    @staticmethod
    def _handle_value(row: tuple[object, ...]) -> AttachHandle:
        if len(row) != 6 or type(row[5]) is not int or row[5] not in (0, 1):
            raise _error(PublicErrorCode.STORAGE_CORRUPT, "The attach handle is inconsistent.")
        try:
            return AttachHandle(
                value=_text(row[2]),
                digest=_digest(row[0]),
                task_id=validate_id(IdKind.TASK, _text(row[1])),
                expires_at=_timestamp(row[3]),
                consumed_session_id=None
                if row[4] is None
                else validate_id(IdKind.SESSION, _text(row[4])),
                revoked=bool(row[5]),
            )
        except (TypeError, ValueError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The attach handle is inconsistent."
            ) from exc

    async def get_handle(self, digest: str) -> AttachHandle | None:
        if type(digest) is not str:
            raise TypeError("lineage_handle_digest_invalid")
        row = self._handle_row(_digest(digest))
        return None if row is None else self._handle_value(row)

    def _save_handle_locked(self, handle: AttachHandle) -> None:
        existing = self._handle_row(handle.digest)
        if existing is not None:
            current = self._handle_value(existing)
            if (
                current.task_id != handle.task_id
                or current.value != handle.value
                or current.expires_at != handle.expires_at
            ):
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The attach handle identity conflicts.",
                    reason="lineage_handle_conflict",
                )
            if (
                current.consumed_session_id is not None
                and current.consumed_session_id != handle.consumed_session_id
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The attach handle was already used.",
                    reason="attach_handle_reused",
                )
            if current.revoked and not handle.revoked:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "The attach handle has been revoked.",
                    reason="attach_handle_revoked",
                )
            self._db.execute(
                "UPDATE lineage_attach_handles SET consumed_session_id = ?, revoked = ? WHERE handle_digest = ?",
                (handle.consumed_session_id, 1 if handle.revoked else 0, handle.digest),
            )
            return
        self._db.execute(
            "INSERT INTO lineage_attach_handles(handle_digest, task_id, handle_value, expires_at, consumed_session_id, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                handle.digest,
                handle.task_id,
                handle.value,
                format_rfc3339_millis(handle.expires_at),
                handle.consumed_session_id,
                1 if handle.revoked else 0,
            ),
        )

    async def save_handle(self, handle: AttachHandle) -> None:
        if type(handle) is not AttachHandle:
            raise TypeError("lineage_handle_invalid")
        with _Transaction(self._db):
            self._save_handle_locked(handle)

    async def revoke_handles(self, task_id: str) -> None:
        task = validate_id(IdKind.TASK, task_id)
        with _Transaction(self._db):
            self._db.execute(
                "UPDATE lineage_attach_handles SET revoked = 1 WHERE task_id = ? AND revoked = 0",
                (task,),
            )

    async def get_manifest(
        self, parent_task_id: str, child_task_id: str
    ) -> DependencyManifest | None:
        parent = validate_id(IdKind.TASK, parent_task_id)
        child = validate_id(IdKind.TASK, child_task_id)
        rows = self._rows(
            "SELECT manifest_digest, canonical FROM lineage_manifests WHERE parent_task_id = ? AND child_task_id = ? LIMIT 2",
            (parent, child),
        )
        if len(rows) > 1:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest is inconsistent."
            )
        if not rows:
            return None
        row = rows[0]
        if type(row[1]) is not bytes:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest is inconsistent."
            )
        try:
            parsed = strict_json_parse(row[1])
            if canonical_encode(parsed) != row[1] or not isinstance(parsed, Mapping):
                raise ValueError("manifest_noncanonical")
            source = cast(Mapping[str, JsonValue], parsed)
            manifest = DependencyManifest(
                parent_task_id=parent,
                child_task_id=child,
                origin=LineageOrigin(cast(str, source["origin"])),
                acceptance=LineageAcceptance(cast(str, source["acceptance"])),
                child_frontier=frontier_from_json(source["child_frontier"]),
                child_check_id=cast(str | None, source.get("child_check_id")),
                child_receipt_id=cast(str | None, source.get("child_receipt_id")),
                coverage=cast(Mapping[str, JsonValue], source["coverage"]),
                findings_state=cast(Mapping[str, JsonValue], source["findings_state"]),
                lineage_authority_revision=cast(
                    int, _manifest_integer(source["lineage_authority_revision"])
                ),
                membership_generation=_manifest_integer(
                    source.get("membership_generation"), optional=True
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest is inconsistent."
            ) from exc
        if manifest.manifest_digest != _digest(row[0]):
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest digest is inconsistent."
            )
        if source.get("manifest_digest") != row[0]:
            raise _error(
                PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest digest is inconsistent."
            )
        return manifest

    async def save_manifest(self, manifest: DependencyManifest) -> None:
        if type(manifest) is not DependencyManifest:
            raise TypeError("lineage_manifest_invalid")
        payload = manifest.as_wire()
        # ``DependencyManifest`` uses integer authority/member values internally; its durable
        # wire representation keeps those fields as numbers, so round-trip decoding can remain
        # independent of Python's repr or enum classes.
        canonical = canonical_encode(cast(JsonValue, payload))
        with _Transaction(self._db):
            current_rows = self._rows(
                "SELECT manifest_digest, lineage_authority_revision FROM lineage_manifests "
                "WHERE parent_task_id = ? AND child_task_id = ? LIMIT 2",
                (manifest.parent_task_id, manifest.child_task_id),
            )
            if len(current_rows) > 1:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT, "The dependency manifest is inconsistent."
                )
            if current_rows:
                current_revision = _integer(current_rows[0][1])
                if (
                    current_rows[0][0] != manifest.manifest_digest
                    and manifest.lineage_authority_revision <= current_revision
                ):
                    raise _error(
                        PublicErrorCode.SESSION_CONFLICT,
                        "The dependency manifest is stale.",
                        reason="lineage_manifest_stale",
                    )
                self._db.execute(
                    "UPDATE lineage_manifests SET manifest_digest = ?, lineage_authority_revision = ?, "
                    "membership_generation = ?, canonical = ? WHERE parent_task_id = ? AND child_task_id = ?",
                    (
                        manifest.manifest_digest,
                        manifest.lineage_authority_revision,
                        manifest.membership_generation,
                        canonical,
                        manifest.parent_task_id,
                        manifest.child_task_id,
                    ),
                )
                return
            self._db.execute(
                "INSERT INTO lineage_manifests(parent_task_id, child_task_id, manifest_digest, lineage_authority_revision, "
                "membership_generation, canonical) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    manifest.parent_task_id,
                    manifest.child_task_id,
                    manifest.manifest_digest,
                    manifest.lineage_authority_revision,
                    manifest.membership_generation,
                    canonical,
                ),
            )
