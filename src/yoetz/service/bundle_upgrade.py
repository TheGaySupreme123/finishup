"""Automatic, backup-first bundle migration at the controlled READY boundary.

The service owns the lifecycle boundary and the evidence backend owns encrypted object and
projection facts.  This module owns the small amount of orchestration that must happen between
those boundaries: inspect a stale bundle read-only, claim one durable migration operation, obtain a
machine-bound backup, apply the numbered bundle migrations through a narrow writer, compare the
append-only history/object state, and require an injected projection replay proof before READY.

It is intentionally not called from lazy runtime opening.  A service composition must call
``BundleUpgradeCoordinator.run_before_ready`` after the catalog is current and before publishing a
READY context.  The exclusive-holder callback is required whenever work is found; a catalog CAS
row alone is not a cross-process bundle writer fence.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping, Sequence
from contextlib import AbstractAsyncContextManager
from dataclasses import dataclass, replace
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import Final, NoReturn, Protocol, cast

import apsw

from yoetz.adapters.sqlite.connection import (
    StorageUnsafeError,
    _open_bundle_migration_writer,  # pyright: ignore[reportPrivateUsage]
    open_read_only,
    verify_schema_identity,
)
from yoetz.adapters.sqlite.migrations import (
    BUNDLE_MIGRATIONS,
    MigrationReport,
    _validate_v10_bundle_layout,  # pyright: ignore[reportPrivateUsage]
    run_migrations,
)
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    JsonValue,
    TaskId,
    Timestamp,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    request_id,
    task_id,
    validate_sha256_digest,
)
from yoetz.ports.clock import ClockPort
from yoetz.ports.ids import IdPort
from yoetz.ports.maintenance import MigrationResult
from yoetz.protocol.canonical import canonical_digest, canonical_encode
from yoetz.protocol.ids import IdKind, new_id, validate_id

__all__ = [
    "BUNDLE_UPGRADE_SOURCE_VERSION",
    "BUNDLE_UPGRADE_SOURCE_VERSIONS",
    "BUNDLE_UPGRADE_TARGET_VERSION",
    "BackupEvidence",
    "BundleIntegrity",
    "BundleUpgradeCoordinator",
    "BundleUpgradeError",
    "BundleUpgradeOperation",
    "BundleUpgradePhase",
    "BundleUpgradeReason",
    "BundleUpgradeReport",
    "BundleUpgradeState",
    "BundleUpgradeTarget",
    "BundleUpgradeEffects",
    "SqliteBundleUpgradeJournal",
    "capture_sqlite_integrity",
    "migration_plan_digest",
    "migration_request_digest",
]

BUNDLE_UPGRADE_SOURCE_VERSION: Final = 12
BUNDLE_UPGRADE_TARGET_VERSION: Final = 16
# 0.3 development bundles already at v15 take only 0016 (review-input suspension, issue #951).
BUNDLE_UPGRADE_SOURCE_VERSIONS: Final = (12, 13, 14, 15)
_MAX_SAFE_INTEGER: Final = 2**53 - 1
_REQUIRED_MIGRATION_IDS: Final[tuple[str, ...]] = ("0013", "0014", "0015", "0016")
_LEASE_SECONDS: Final = 60
_MIGRATION_PHASE_ORDER: Final[tuple[str, ...]] = (
    "reserved",
    "backup_ready",
    "schema_applied",
    "replay_verified",
)
# Tables created by a migration inside the upgrade window (0015 semantic progress, #571 A2).
_MIGRATION_CREATED_TABLES: Final[frozenset[str]] = frozenset({"semantic_progress"})
_EPHEMERAL_PRESERVATION_TABLES: Final[frozenset[str]] = frozenset(
    {"bundle_meta", "maintenance_pins", "maintenance_operations"}
)
_PROJECTION_TABLES: Final[tuple[str, ...]] = (
    "projection_state",
    "p1_projection_state",
    "p1_query_snapshots",
    "p1_query_findings",
    "p1_query_finding_order",
    "p1_query_responses",
    "p1_coverage_gaps",
    "p2_query_snapshots",
    "p2_query_findings",
    "p2_query_finding_order",
    "p2_query_responses",
    "p2_coverage_gaps",
)


class BundleUpgradeReason(StrEnum):  # noqa: UP042 - closed internal error vocabulary
    HOLDER_REQUIRED = "holder_required"
    HOLDER_CONFLICT = "holder_conflict"
    BUNDLE_MISSING = "bundle_missing"
    SCHEMA_NEWER_THAN_BINARY = "schema_newer_than_binary"
    SCHEMA_METADATA_DISAGREES = "schema_metadata_disagrees"
    SCHEMA_UPGRADE_PATH_UNKNOWN = "schema_upgrade_path_unknown"
    MIGRATION_UNSUPPORTED = "migration_unsupported"
    PLAN_STALE = "plan_stale"
    MAINTENANCE_BUSY = "maintenance_busy"
    OPERATION_LOST = "operation_lost"
    BACKUP_FAILED = "backup_failed"
    MIGRATION_FAILED = "migration_failed"
    VERIFICATION_FAILED = "verification_failed"
    ROLLBACK_REQUIRED = "rollback_required"


class BundleUpgradeError(Exception):
    """Typed, payload-free upgrade failure suitable for the startup boundary."""

    __slots__ = ("reason", "retryable", "safe_details")

    reason: BundleUpgradeReason
    retryable: bool
    safe_details: Mapping[str, JsonValue]

    def __init__(
        self,
        reason: BundleUpgradeReason,
        retryable: bool,
        safe_details: Mapping[str, JsonValue] | None = None,
    ) -> None:
        if type(reason) is not BundleUpgradeReason or type(retryable) is not bool:
            raise TypeError("bundle_upgrade_error_invalid")
        details = JsonObject({} if safe_details is None else safe_details)
        if len(details) > 8 or len(canonical_encode(details)) > 2_048:
            raise ValueError("bundle_upgrade_error_details_invalid")
        self.reason = reason
        self.retryable = retryable
        self.safe_details = details
        super().__init__(reason.value)


@dataclass(frozen=True, slots=True)
class BundleUpgradeTarget:
    """Structural route facts captured by catalog composition before migration."""

    task_id: TaskId
    session_id: str
    bundle_path: Path
    route_generation: int
    route_identity_digest: str
    frontier: Frontier
    catalog_owner_generation: int
    privacy_root_generation: int = 0
    privacy_root_digest: str = "sha256:" + "0" * 64

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", task_id(self.task_id))
        if type(self.session_id) is not str or not self.session_id:
            raise ValueError("bundle_upgrade_target_invalid")
        if (
            not isinstance(  # pyright: ignore[reportUnnecessaryIsInstance]
                self.bundle_path, Path
            )
            or not self.bundle_path.is_absolute()
        ):
            raise ValueError("bundle_upgrade_target_invalid")
        if type(self.route_generation) is not int or self.route_generation <= 0:
            raise ValueError("bundle_upgrade_target_invalid")
        try:
            validate_sha256_digest(self.route_identity_digest)
        except ValueError as exc:
            raise ValueError("bundle_upgrade_target_invalid") from exc
        if type(self.frontier) is not Frontier:
            raise ValueError("bundle_upgrade_target_invalid")
        if type(self.catalog_owner_generation) is not int or self.catalog_owner_generation <= 0:
            raise ValueError("bundle_upgrade_target_invalid")
        if type(self.privacy_root_generation) is not int or self.privacy_root_generation < 0:
            raise ValueError("bundle_upgrade_target_invalid")
        try:
            validate_sha256_digest(self.privacy_root_digest)
        except ValueError as exc:
            raise ValueError("bundle_upgrade_target_invalid") from exc


@dataclass(frozen=True, slots=True)
class BundleIntegrity:
    """Digest-only preservation facts; no user content crosses this service boundary."""

    task_id: TaskId
    schema_version: int
    frontier: Frontier
    history_digest: str
    event_count: int
    object_digest: str
    object_count: int
    preserved_digest: str
    projection_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", task_id(self.task_id))
        if type(self.schema_version) is not int or self.schema_version <= 0:
            raise ValueError("bundle_integrity_invalid")
        if type(self.frontier) is not Frontier:
            raise ValueError("bundle_integrity_invalid")
        for digest in (
            self.history_digest,
            self.object_digest,
            self.preserved_digest,
            self.projection_digest,
        ):
            try:
                validate_sha256_digest(digest)
            except ValueError as exc:
                raise ValueError("bundle_integrity_invalid") from exc
        if type(self.event_count) is not int or self.event_count < 0:
            raise ValueError("bundle_integrity_invalid")
        if type(self.object_count) is not int or self.object_count < 0:
            raise ValueError("bundle_integrity_invalid")


@dataclass(frozen=True, slots=True)
class BackupEvidence:
    """The machine-bound backup identity and frontier used by one upgrade operation."""

    task_id: TaskId
    frontier: Frontier
    manifest_digest: str
    source_version: int = BUNDLE_UPGRADE_SOURCE_VERSION

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", task_id(self.task_id))
        if type(self.frontier) is not Frontier:
            raise ValueError("bundle_backup_evidence_invalid")
        if (
            type(self.source_version) is not int
            or self.source_version not in BUNDLE_UPGRADE_SOURCE_VERSIONS
        ):
            raise ValueError("bundle_backup_evidence_invalid")
        try:
            validate_sha256_digest(self.manifest_digest)
        except ValueError as exc:
            raise ValueError("bundle_backup_evidence_invalid") from exc


class BundleUpgradePhase(StrEnum):  # noqa: UP042 - frozen maintenance phase vocabulary
    RESERVED = "reserved"
    BACKUP_READY = "backup_ready"
    SCHEMA_APPLIED = "schema_applied"
    REPLAY_VERIFIED = "replay_verified"
    TERMINAL = "terminal"


class BundleUpgradeState(StrEnum):  # noqa: UP042 - frozen maintenance state vocabulary
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


@dataclass(frozen=True, slots=True)
class BundleUpgradeOperation:
    request_id: str
    task_id: TaskId
    route_identity_digest: str
    plan_digest: str
    phase: BundleUpgradePhase
    state: BundleUpgradeState
    backup_manifest_digest: str | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", str(request_id(self.request_id)))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        try:
            validate_sha256_digest(self.route_identity_digest)
            validate_sha256_digest(self.plan_digest)
            if self.backup_manifest_digest is not None:
                validate_sha256_digest(self.backup_manifest_digest)
        except ValueError as exc:
            raise ValueError("bundle_upgrade_operation_invalid") from exc
        if type(self.phase) is not BundleUpgradePhase or type(self.state) is not BundleUpgradeState:
            raise ValueError("bundle_upgrade_operation_invalid")


@dataclass(frozen=True, slots=True)
class BundleUpgradeReport:
    """Startup result containing only task identities and migration receipts."""

    migrated: tuple[MigrationResult, ...]
    already_current: tuple[TaskId, ...]

    def __post_init__(self) -> None:
        if type(self.migrated) is not tuple or type(self.already_current) is not tuple:
            raise ValueError("bundle_upgrade_report_invalid")
        if any(type(item) is not MigrationResult for item in self.migrated):
            raise ValueError("bundle_upgrade_report_invalid")
        normalized = tuple(task_id(item) for item in self.already_current)
        if normalized != self.already_current or len(set(normalized)) != len(normalized):
            raise ValueError("bundle_upgrade_report_invalid")


class BundleUpgradeEffects(Protocol):
    """Ready-composition backend for encrypted backup and projection replay evidence."""

    async def ensure_machine_backup(
        self,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
        before: BundleIntegrity,
        existing_manifest_digest: str | None,
    ) -> BackupEvidence:
        """Create or reopen the same verified backup for this operation."""
        ...

    async def verify_replay(
        self,
        target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        backup: BackupEvidence,
    ) -> str:
        """Replay projections and return the independently verified replay digest.

        ``before`` is ``None`` when a process restarted after the bundle DDL committed but before
        its phase CAS.  The implementation must then read the original integrity facts from the
        machine-bound backup identified by ``backup``; comparing the live target-version bundle to
        itself is not preservation evidence.
        """
        ...


def migration_request_digest(target: BundleUpgradeTarget) -> str:
    """Return the stable logical request identity for an automatic package upgrade."""

    return canonical_digest(
        {
            "kind": "package_upgrade_migration",
            "task_id": str(target.task_id),
            "target_storage_version": str(BUNDLE_UPGRADE_TARGET_VERSION),
        }
    )


def migration_plan_digest(target: BundleUpgradeTarget) -> str:
    """Bind the automatic operation to route, frontier, privacy roots, and migration bytes."""

    migration_digests = tuple(
        {
            "ddl_digest": "sha256:" + hashlib.sha256(migration.ddl).hexdigest(),
            "version": migration.version,
        }
        for migration in BUNDLE_MIGRATIONS
        if migration.version in _REQUIRED_MIGRATION_IDS
    )
    return canonical_digest(
        {
            "source_versions": tuple(str(version) for version in BUNDLE_UPGRADE_SOURCE_VERSIONS),
            "kind": "package_upgrade_migration",
            "migration_ids": _REQUIRED_MIGRATION_IDS,
            "migration_digests": migration_digests,
            "privacy_root_digest": target.privacy_root_digest,
            "privacy_root_generation": target.privacy_root_generation,
            "route_generation": target.route_generation,
            "route_identity_digest": target.route_identity_digest,
            "subject_frontier": target.frontier.as_wire(),
            "task_id": str(target.task_id),
            "to_version": str(BUNDLE_UPGRADE_TARGET_VERSION),
        }
    )


def _request_digest_for(target: BundleUpgradeTarget) -> str:
    return migration_request_digest(target)


def _safe_identifier(value: str) -> str:
    """Quote a catalog-derived SQLite identifier without accepting SQL syntax."""

    if type(value) is not str or not value or '"' in value or "\x00" in value:
        raise BundleUpgradeError(BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "table"})
    return '"' + value + '"'


def _cell_value(value: object) -> JsonValue:
    if value is None or type(value) is str or type(value) is int or type(value) is bool:
        return cast(JsonValue, value)
    if type(value) is bytes:
        return JsonObject(
            {
                "blob_digest": "sha256:" + hashlib.sha256(value).hexdigest(),
                "blob_size": len(value),
            }
        )
    raise BundleUpgradeError(BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "value"})


def _sorted_row_values(rows: Sequence[tuple[object, ...]]) -> tuple[tuple[JsonValue, ...], ...]:
    normalized = [tuple(_cell_value(value) for value in row) for row in rows]
    return tuple(sorted(normalized, key=canonical_encode))


def _table_exists(db: apsw.Connection, table: str) -> bool:
    return (
        db.execute(
            "SELECT 1 FROM sqlite_schema WHERE type='table' AND name = ? LIMIT 1", (table,)
        ).fetchone()
        is not None
    )


def _is_canonical_nonnegative_generation(value: object) -> bool:
    """Accept the fresh-bundle zero sentinel and bounded decimal generations only."""

    if type(value) is not str or not value.isdecimal():
        return False
    try:
        parsed = int(value, 10)
    except ValueError:
        return False
    return 0 <= parsed <= _MAX_SAFE_INTEGER and str(parsed) == value


def _stream_rows_digest(
    cursor: apsw.Cursor,
    *,
    table: str,
) -> tuple[str, int]:
    """Hash a deterministic row stream without retaining ledger rows in process memory."""

    digest = hashlib.sha256(b'{"rows":[')
    count = 0
    for raw_value in cursor:
        raw_row = cast(object, raw_value)
        if type(raw_row) is not tuple:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "row"}
            )
        row_values = cast(tuple[object, ...], raw_row)
        row = tuple(_cell_value(value) for value in row_values)
        if count:
            digest.update(b",")
        digest.update(canonical_encode(row))
        count += 1
    digest.update(b'],"table":')
    digest.update(canonical_encode(table))
    digest.update(b"}")
    return "sha256:" + digest.hexdigest(), count


def _stream_table_digest(
    db: apsw.Connection,
    table: str,
    *,
    order_by: str | None = None,
) -> tuple[str, int]:
    """Digest one table using a bounded cursor and explicit ordering where it matters.

    The only table rebuilt by 0014 (``events``) and the object inventory use their stable key
    ordering.  Other tables are unchanged by the migration and are scanned in SQLite's native
    b-tree order, so the digest does not retain their rows merely to sort them in Python.
    """

    projection = "*"
    if table == "semantic_attempts":
        columns = {row[1] for row in db.execute("PRAGMA table_info(semantic_attempts)")}
        usage_columns = (
            "usage_input_tokens",
            "usage_cached_input_tokens",
            "usage_cache_write_input_tokens",
            "usage_output_tokens",
            "usage_reasoning_output_tokens",
            "usage_total_tokens",
        )
        present = tuple(column in columns for column in usage_columns)
        if any(present) and not all(present):
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        if not any(present):
            projection += ", " + ", ".join("NULL" for _ in usage_columns)
    sql = f"SELECT {projection} FROM {_safe_identifier(table)}"
    if order_by is not None:
        sql += f" ORDER BY {_safe_identifier(order_by)}"
    cursor = db.execute(sql)
    return _stream_rows_digest(cursor, table=table)


def _read_event_frontier(db: apsw.Connection) -> Frontier:
    """Read only the append-only tail needed for a cheap bundle binding probe."""

    event_tail = db.execute(
        "SELECT ingestion_seq, entry_digest FROM events ORDER BY ingestion_seq DESC LIMIT 1"
    ).fetchone()
    if event_tail is None:
        return Frontier.genesis()
    if len(event_tail) != 2 or type(event_tail[0]) is not int or type(event_tail[1]) is not str:
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "frontier"}
        )
    try:
        return Frontier(event_tail[0], event_tail[1])
    except ValueError as exc:
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "frontier"}
        ) from exc


def _metadata_digest(db: apsw.Connection) -> str:
    if not _table_exists(db, "bundle_meta"):
        raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
    rows = cast(
        list[tuple[object, ...]],
        db.execute(
            "SELECT key, value FROM bundle_meta "
            "WHERE key NOT IN ('storage_schema_version','owner_generation','owner_nonce') "
            "ORDER BY key"
        ).fetchall(),
    )
    return canonical_digest(_sorted_row_values(rows))


def capture_sqlite_integrity(db: apsw.Connection) -> BundleIntegrity:
    """Capture bounded digest facts from an already-open bundle connection."""

    try:
        identity = verify_schema_identity(db)
        if (
            not _table_exists(db, "bundle_meta")
            or not _table_exists(db, "events")
            or not _table_exists(db, "objects")
        ):
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        task_row = db.execute("SELECT value FROM bundle_meta WHERE key='task_id'").fetchone()
        if task_row is None or type(task_row[0]) is not str:
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        history_digest, event_count = _stream_table_digest(db, "events", order_by="ingestion_seq")
        frontier = _read_event_frontier(db)
        object_digest, object_count = _stream_table_digest(db, "objects", order_by="object_id")
        table_rows: list[tuple[str, str, int]] = []
        table_names = cast(
            list[tuple[object, ...]],
            db.execute(
                "SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            ).fetchall(),
        )
        for row in table_names:
            if len(row) != 1 or type(row[0]) is not str:
                raise BundleUpgradeError(
                    BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "table"}
                )
            table = row[0]
            if table in _EPHEMERAL_PRESERVATION_TABLES:
                continue
            if table == "events":
                table_digest, table_count = history_digest, event_count
            elif table == "objects":
                table_digest, table_count = object_digest, object_count
            else:
                table_digest, table_count = _stream_table_digest(db, table)
            if table in _MIGRATION_CREATED_TABLES and table_count == 0:
                # A table the upgrade itself creates starts empty; its absence before and its
                # empty presence after are the same preserved content.
                continue
            table_rows.append((table, table_digest, table_count))
        table_rows.sort(key=lambda item: item[0].encode("utf-8"))
        projection_rows: list[tuple[str, str, int]] = []
        for table in _PROJECTION_TABLES:
            if _table_exists(db, table):
                projection_digest, projection_count = _stream_table_digest(db, table)
                projection_rows.append((table, projection_digest, projection_count))
        return BundleIntegrity(
            task_id=task_id(cast(str, task_row[0])),
            schema_version=identity.user_version,
            frontier=frontier,
            history_digest=history_digest,
            event_count=event_count,
            object_digest=object_digest,
            object_count=object_count,
            preserved_digest=canonical_digest(
                {
                    "metadata": _metadata_digest(db),
                    "tables": tuple(table_rows),
                }
            ),
            projection_digest=canonical_digest(tuple(projection_rows)),
        )
    except BundleUpgradeError:
        raise
    except (apsw.Error, ValueError, TypeError) as exc:
        raise BundleUpgradeError(
            BundleUpgradeReason.VERIFICATION_FAILED,
            False,
            {"check": "integrity"},
        ) from exc


class SqliteBundleUpgradeJournal:
    """Durable migration journal backed by the existing catalog maintenance table."""

    def __init__(
        self,
        catalog: apsw.Connection,
        *,
        installation_id: str,
        service_instance_id: str,
        clock: ClockPort,
        ids: IdPort | None = None,
        lease_seconds: int = _LEASE_SECONDS,
    ) -> None:
        if type(catalog) is not apsw.Connection:
            raise TypeError("bundle_upgrade_catalog_invalid")
        try:
            validate_id(IdKind.INSTALLATION, installation_id)
            validate_id(IdKind.SERVICE_INSTANCE, service_instance_id)
        except Exception as exc:
            raise ValueError("bundle_upgrade_journal_identity_invalid") from exc
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3_600:
            raise ValueError("bundle_upgrade_lease_invalid")
        self._catalog = catalog
        self._installation_id = installation_id
        self._service_instance_id = service_instance_id
        self._clock = clock
        self._ids = ids
        self._lease_seconds = lease_seconds

    def _now(self):
        return self._clock.now_utc()

    def _now_wire(self) -> str:
        return format_rfc3339_millis(self._now())

    def _expiry_wire(self) -> str:
        return format_rfc3339_millis(self._now() + timedelta(seconds=self._lease_seconds))

    def _catalog_owner_generation(self) -> int:
        rows = self._catalog.execute(
            "SELECT key, value FROM catalog_meta "
            "WHERE key IN ('installation_id','owner_generation')"
        ).fetchall()
        values = {
            row[0]: row[1]
            for row in rows
            if len(row) == 2 and type(row[0]) is str and type(row[1]) is str
        }
        if values.get("installation_id") != self._installation_id:
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        raw_generation = values.get("owner_generation")
        if raw_generation is None:
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        try:
            generation = int(raw_generation, 10)
        except ValueError as exc:
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False) from exc
        if generation <= 0:
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        return generation

    def _require_route(self, target: BundleUpgradeTarget) -> None:
        row = self._catalog.execute(
            "SELECT active_session_id, active_route_identity_digest, state, route_generation "
            "FROM task_routes WHERE task_id=?",
            (str(target.task_id),),
        ).fetchone()
        if row != (
            target.session_id,
            target.route_identity_digest,
            "active",
            target.route_generation,
        ):
            raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, False)

    def validate_target(self, target: BundleUpgradeTarget) -> None:
        """Validate the catalog generation and active route before a cheap bundle probe."""

        if self._catalog_owner_generation() != target.catalog_owner_generation:
            raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
        self._require_route(target)

    def has_unfinished(self, target: BundleUpgradeTarget) -> bool:
        """Return whether a target has a pending automatic migration operation."""

        rows = self._catalog.execute(
            "SELECT state, quarantine_code FROM maintenance_operations "
            "WHERE installation_id=? AND task_id=? AND kind='migration' "
            "AND requested_target_version=? ORDER BY created_at DESC LIMIT 2",
            (
                self._installation_id,
                str(target.task_id),
                str(BUNDLE_UPGRADE_TARGET_VERSION),
            ),
        ).fetchall()
        for row in rows:
            if row[0] == BundleUpgradeState.PENDING.value:
                return True
            if row[0] == BundleUpgradeState.QUARANTINED.value:
                raise BundleUpgradeError(
                    BundleUpgradeReason.ROLLBACK_REQUIRED,
                    False,
                    {"task_id": str(target.task_id)},
                )
        return False

    @staticmethod
    def _operation_from_row(row: tuple[object, ...]) -> BundleUpgradeOperation:
        if len(row) != 9:
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        operation_id, task_value, plan, state, phase, route, backup, _owner, _lease = row
        if any(
            type(value) is not str
            for value in (operation_id, task_value, plan, state, phase, route)
        ):
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        if backup is not None and type(backup) is not str:
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        try:
            return BundleUpgradeOperation(
                request_id=cast(str, operation_id),
                task_id=task_id(cast(str, task_value)),
                route_identity_digest=cast(str, route),
                plan_digest=cast(str, plan),
                phase=BundleUpgradePhase(cast(str, phase)),
                state=BundleUpgradeState(cast(str, state)),
                backup_manifest_digest=backup,
            )
        except (TypeError, ValueError) as exc:
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False) from exc

    def _load_operation(
        self, target: BundleUpgradeTarget, plan_digest: str
    ) -> tuple[tuple[object, ...] | None, bool]:
        rows = self._catalog.execute(
            "SELECT operation_id, task_id, plan_digest, state, phase, "
            "source_route_identity_digest, backup_manifest_digest, owner_generation, "
            "lease_owner_id, lease_generation, lease_expires_at "
            ", request_digest "
            "FROM maintenance_operations WHERE installation_id=? AND task_id=? "
            "AND kind='migration' AND requested_target_version=? ORDER BY created_at DESC LIMIT 2",
            (
                self._installation_id,
                str(target.task_id),
                str(BUNDLE_UPGRADE_TARGET_VERSION),
            ),
        ).fetchall()
        if not rows:
            return None, False
        for row in rows:
            if len(row) != 12:
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            if row[3] == BundleUpgradeState.PENDING.value:
                if (
                    row[2] != plan_digest
                    or row[5] != target.route_identity_digest
                    or row[11] != _request_digest_for(target)
                ):
                    raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, False)
                return cast(tuple[object, ...], row), True
        row = cast(tuple[object, ...], rows[0])
        if len(row) != 12:
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        if (
            row[2] != plan_digest
            or row[5] != target.route_identity_digest
            or row[11] != _request_digest_for(target)
        ):
            raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, False)
        return row, False

    def reserve(
        self,
        target: BundleUpgradeTarget,
        *,
        create_if_absent: bool,
    ) -> BundleUpgradeOperation | None:
        """Claim/resume one operation, optionally creating it for a stale v12 bundle."""

        plan_digest = migration_plan_digest(target)
        request_digest = _request_digest_for(target)
        catalog_generation = self._catalog_owner_generation()
        if catalog_generation != target.catalog_owner_generation:
            raise BundleUpgradeError(BundleUpgradeReason.PLAN_STALE, True)
        self._require_route(target)
        now = self._now()
        now_wire = format_rfc3339_millis(now)
        expires_wire = format_rfc3339_millis(now + timedelta(seconds=self._lease_seconds))
        try:
            self._catalog.execute("BEGIN IMMEDIATE")
            existing, pending = self._load_operation(target, plan_digest)
            if existing is None:
                if not create_if_absent:
                    self._catalog.execute("COMMIT")
                    return None
                competing = self._catalog.execute(
                    "SELECT kind FROM maintenance_operations WHERE task_id=? AND state='pending' LIMIT 2",
                    (str(target.task_id),),
                ).fetchall()
                if competing:
                    raise BundleUpgradeError(BundleUpgradeReason.MAINTENANCE_BUSY, True)
                operation_id = (
                    self._ids.new(IdKind.REQUEST)
                    if self._ids is not None
                    else new_id(IdKind.REQUEST)
                )
                operation_id = str(request_id(operation_id))
                self._catalog.execute(
                    "INSERT INTO maintenance_operations("
                    "installation_id, operation_id, task_id, kind, request_digest, plan_digest, "
                    "state, phase, subject_frontier_seq, subject_frontier_digest, "
                    "privacy_root_generation, privacy_root_digest, source_route_identity_digest, "
                    "target_route_identity_digest, source_location_commitment, target_location_commitment, "
                    "backup_mode, requested_target_version, owner_generation, lease_owner_id, "
                    "lease_generation, lease_expires_at, created_at, updated_at) "
                    "VALUES(?,?,?,'migration',?,?, 'pending','reserved',?,?,?,?,?,NULL,NULL,NULL,"
                    "'machine_bound',?,?,?,1,?,?,?)",
                    (
                        self._installation_id,
                        operation_id,
                        str(target.task_id),
                        request_digest,
                        plan_digest,
                        target.frontier.sequence,
                        target.frontier.head_digest,
                        target.privacy_root_generation,
                        target.privacy_root_digest,
                        target.route_identity_digest,
                        str(BUNDLE_UPGRADE_TARGET_VERSION),
                        str(catalog_generation),
                        self._service_instance_id,
                        expires_wire,
                        now_wire,
                        now_wire,
                    ),
                )
                self._catalog.execute("COMMIT")
                return BundleUpgradeOperation(
                    request_id=operation_id,
                    task_id=target.task_id,
                    route_identity_digest=target.route_identity_digest,
                    plan_digest=plan_digest,
                    phase=BundleUpgradePhase.RESERVED,
                    state=BundleUpgradeState.PENDING,
                    backup_manifest_digest=None,
                )

            operation = self._operation_from_row(
                (
                    existing[0],
                    existing[1],
                    existing[2],
                    existing[3],
                    existing[4],
                    existing[5],
                    existing[6],
                    existing[7],
                    existing[8],
                )
            )
            if operation.state is BundleUpgradeState.QUARANTINED:
                self._catalog.execute("ROLLBACK")
                raise BundleUpgradeError(
                    BundleUpgradeReason.ROLLBACK_REQUIRED,
                    False,
                    {"task_id": str(target.task_id)},
                )
            if operation.state is BundleUpgradeState.COMPLETE:
                self._catalog.execute("COMMIT")
                return operation
            if not pending:
                self._catalog.execute("ROLLBACK")
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            lease_generation = existing[9]
            owner_generation = existing[7]
            current_owner = existing[8]
            lease_expires_at = existing[10]
            if (
                type(owner_generation) is not str
                or type(current_owner) is not str
                or type(lease_generation) is not int
                or lease_generation <= 0
                or type(lease_expires_at) is not str
            ):
                self._catalog.execute("ROLLBACK")
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            try:
                lease_expired = parse_rfc3339_millis(lease_expires_at) <= now
            except (TypeError, ValueError) as exc:
                self._catalog.execute("ROLLBACK")
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False) from exc
            if owner_generation != str(catalog_generation):
                lease_expired = True
            if not lease_expired and current_owner != self._service_instance_id:
                self._catalog.execute("ROLLBACK")
                raise BundleUpgradeError(BundleUpgradeReason.HOLDER_CONFLICT, True)
            if lease_expired or current_owner != self._service_instance_id:
                lease_generation += 1
                self._catalog.execute(
                    "UPDATE maintenance_operations SET owner_generation=?, lease_owner_id=?, "
                    "lease_generation=?, lease_expires_at=?, updated_at=? "
                    "WHERE installation_id=? AND operation_id=? AND state='pending' "
                    "AND owner_generation IS ? AND lease_owner_id IS ? AND lease_generation=?",
                    (
                        str(catalog_generation),
                        self._service_instance_id,
                        lease_generation,
                        expires_wire,
                        now_wire,
                        self._installation_id,
                        operation.request_id,
                        owner_generation,
                        current_owner,
                        lease_generation - 1,
                    ),
                )
                if self._catalog.changes() != 1:
                    raise BundleUpgradeError(BundleUpgradeReason.MAINTENANCE_BUSY, True)
                operation = replace(operation, phase=operation.phase)
            self._catalog.execute("COMMIT")
            return operation
        except BundleUpgradeError:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise
        except apsw.ConstraintError as exc:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise BundleUpgradeError(BundleUpgradeReason.MAINTENANCE_BUSY, True) from exc
        except apsw.Error as exc:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, True) from exc

    def advance(
        self,
        operation: BundleUpgradeOperation,
        *,
        expected: tuple[BundleUpgradePhase, ...],
        next_phase: BundleUpgradePhase,
        backup_manifest_digest: str | None = None,
    ) -> BundleUpgradeOperation:
        if not expected or next_phase is BundleUpgradePhase.TERMINAL:
            raise ValueError("bundle_upgrade_phase_invalid")
        allowed = tuple(BundleUpgradePhase(value) for value in _MIGRATION_PHASE_ORDER)
        if any(item not in allowed for item in expected) or next_phase not in allowed:
            raise ValueError("bundle_upgrade_phase_invalid")
        if allowed.index(next_phase) < max(allowed.index(item) for item in expected):
            raise ValueError("bundle_upgrade_phase_invalid")
        if backup_manifest_digest is not None:
            validate_sha256_digest(backup_manifest_digest)
        try:
            self._catalog.execute("BEGIN IMMEDIATE")
            owner_generation, lease_generation = self._lease_facts(operation)
            self._catalog.execute(
                "UPDATE maintenance_operations SET phase=?, "
                "backup_manifest_digest=COALESCE(?,backup_manifest_digest), updated_at=? "
                "WHERE installation_id=? AND operation_id=? AND state='pending' "
                "AND owner_generation=? AND lease_owner_id=? AND lease_generation=? "
                "AND phase IN (" + ",".join("?" for _ in expected) + ")",
                (
                    next_phase.value,
                    backup_manifest_digest,
                    self._now_wire(),
                    self._installation_id,
                    operation.request_id,
                    owner_generation,
                    self._service_instance_id,
                    lease_generation,
                    *(item.value for item in expected),
                ),
            )
            if self._catalog.changes() != 1:
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            self._catalog.execute("COMMIT")
            return replace(
                operation,
                phase=next_phase,
                backup_manifest_digest=(
                    backup_manifest_digest
                    if backup_manifest_digest is not None
                    else operation.backup_manifest_digest
                ),
            )
        except BundleUpgradeError:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise
        except apsw.Error as exc:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, True) from exc

    def complete(
        self,
        operation: BundleUpgradeOperation,
        result: MigrationResult,
    ) -> None:
        if (
            str(result.request_id) != operation.request_id
            or result.task_id != operation.task_id
            or result.from_version
            not in tuple(str(version) for version in BUNDLE_UPGRADE_SOURCE_VERSIONS)
            or result.to_version != str(BUNDLE_UPGRADE_TARGET_VERSION)
            or operation.backup_manifest_digest is None
            or result.backup_manifest_digest != operation.backup_manifest_digest
        ):
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        value: dict[str, JsonValue] = {
            "kind": "migration",
            "request_id": str(result.request_id),
            "task_id": str(result.task_id),
            "from_version": result.from_version,
            "to_version": result.to_version,
            "backup_manifest_digest": result.backup_manifest_digest,
            "frontier_before": result.frontier_before.as_wire(),
            "frontier_after": result.frontier_after.as_wire(),
            "replay_digest": result.replay_digest,
            "completed_at": result.completed_at.wire,
        }
        canonical = canonical_encode(value)
        digest = canonical_digest(value)
        try:
            self._catalog.execute("BEGIN IMMEDIATE")
            owner_generation, lease_generation = self._lease_facts(operation)
            subject = self._catalog.execute(
                "SELECT subject_frontier_seq, subject_frontier_digest "
                "FROM maintenance_operations WHERE installation_id=? AND operation_id=?",
                (self._installation_id, operation.request_id),
            ).fetchone()
            if subject != (result.frontier_before.sequence, result.frontier_before.head_digest):
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            self._catalog.execute(
                "UPDATE maintenance_operations SET state='complete', phase='terminal', "
                "owner_generation=NULL, lease_owner_id=NULL, lease_generation=NULL, "
                "lease_expires_at=NULL, backup_manifest_digest=?, result_canonical=?, "
                "result_digest=?, terminal_at=?, updated_at=? WHERE installation_id=? "
                "AND operation_id=? AND state='pending' AND phase='replay_verified' "
                "AND owner_generation=? AND lease_owner_id=? AND lease_generation=?",
                (
                    result.backup_manifest_digest,
                    canonical,
                    digest,
                    result.completed_at.wire,
                    result.completed_at.wire,
                    self._installation_id,
                    operation.request_id,
                    owner_generation,
                    self._service_instance_id,
                    lease_generation,
                ),
            )
            if self._catalog.changes() != 1:
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            self._catalog.execute("COMMIT")
        except BundleUpgradeError:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise
        except apsw.Error as exc:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, True) from exc

    def quarantine(
        self,
        operation: BundleUpgradeOperation,
        *,
        code: str,
        backup_manifest_digest: str | None,
    ) -> None:
        if backup_manifest_digest is not None:
            validate_sha256_digest(backup_manifest_digest)
        value: dict[str, JsonValue] = {
            "kind": "migration",
            "request_id": operation.request_id,
            "task_id": str(operation.task_id),
            "outcome": "quarantined",
            "code": code,
        }
        try:
            self._catalog.execute("BEGIN IMMEDIATE")
            owner_generation, lease_generation = self._lease_facts(operation)
            self._catalog.execute(
                "UPDATE maintenance_operations SET state='quarantined', phase='terminal', "
                "owner_generation=NULL, lease_owner_id=NULL, lease_generation=NULL, "
                "lease_expires_at=NULL, backup_manifest_digest=COALESCE(?,backup_manifest_digest), "
                "result_canonical=?, result_digest=?, quarantine_code=?, terminal_at=?, updated_at=? "
                "WHERE installation_id=? AND operation_id=? AND state='pending' "
                "AND owner_generation=? AND lease_owner_id=? AND lease_generation=?",
                (
                    backup_manifest_digest,
                    canonical_encode(value),
                    canonical_digest(value),
                    code,
                    self._now_wire(),
                    self._now_wire(),
                    self._installation_id,
                    operation.request_id,
                    owner_generation,
                    self._service_instance_id,
                    lease_generation,
                ),
            )
            if self._catalog.changes() != 1:
                raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            self._catalog.execute("COMMIT")
        except BundleUpgradeError:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise
        except apsw.Error as exc:
            try:
                self._catalog.execute("ROLLBACK")
            except Exception:
                pass
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, True) from exc

    def _lease_facts(self, operation: BundleUpgradeOperation) -> tuple[str, int]:
        """Read the current lease token used by every terminal/phase CAS."""

        row = self._catalog.execute(
            "SELECT owner_generation, lease_owner_id, lease_generation, state "
            "FROM maintenance_operations WHERE installation_id=? AND operation_id=? "
            "AND kind='migration'",
            (self._installation_id, operation.request_id),
        ).fetchone()
        if (
            row is None
            or len(row) != 4
            or type(row[0]) is not str
            or type(row[1]) is not str
            or type(row[2]) is not int
            or row[3] != BundleUpgradeState.PENDING.value
            or row[1] != self._service_instance_id
            or row[2] <= 0
            or row[0] != str(self._catalog_owner_generation())
        ):
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        return cast(str, row[0]), cast(int, row[2])


type _HolderFactory = Callable[[tuple[BundleUpgradeTarget, ...]], AbstractAsyncContextManager[None]]
type _HolderAssertion = Callable[[], None]
type _OpenMigrationWriter = Callable[[Path], apsw.Connection]
type _RunMigration = Callable[..., MigrationReport]


class BundleUpgradeCoordinator:
    """Run all required bundle migrations before the service publishes READY."""

    def __init__(
        self,
        *,
        catalog: apsw.Connection,
        installation_id: str,
        service_instance_id: str,
        clock: ClockPort,
        effects: BundleUpgradeEffects,
        acquire_exclusive_holder: _HolderFactory | None,
        assert_exclusive_holder: _HolderAssertion | None = None,
        journal: SqliteBundleUpgradeJournal | None = None,
        ids: IdPort | None = None,
        open_migration_writer: _OpenMigrationWriter = _open_bundle_migration_writer,
        migration_runner: _RunMigration = run_migrations,
    ) -> None:
        # Protocols are structural and deliberately not runtime-checkable.  Validate only the
        # two callable seams so lightweight test doubles and the service backend remain valid.
        for name in ("ensure_machine_backup", "verify_replay"):
            if not callable(getattr(effects, name, None)):
                raise TypeError("bundle_upgrade_effects_invalid")
        self._clock = clock
        self._effects = effects
        self._acquire_holder = acquire_exclusive_holder
        self._assert_exclusive_holder = assert_exclusive_holder
        self._journal = journal or SqliteBundleUpgradeJournal(
            catalog,
            installation_id=installation_id,
            service_instance_id=service_instance_id,
            clock=clock,
            ids=ids,
        )
        self._open_migration_writer = open_migration_writer
        self._migration_runner = migration_runner

    def _assert_holder(self) -> None:
        """Prove the service still owns the singleton before or after each mutation phase."""

        assertion = self._assert_exclusive_holder
        if assertion is None:
            return
        try:
            assertion()
        except BundleUpgradeError:
            raise
        except Exception as exc:
            raise BundleUpgradeError(BundleUpgradeReason.HOLDER_CONFLICT, True) from exc

    @staticmethod
    def _close(db: apsw.Connection | None) -> None:
        if db is not None:
            try:
                db.close(force=True)
            except Exception:
                pass

    def _validate_bundle_binding(
        self,
        db: apsw.Connection,
        target: BundleUpgradeTarget,
        integrity: BundleIntegrity | None = None,
    ) -> None:
        """Check cheap task/generation/frontier facts before optionally hashing every row."""

        if not _table_exists(db, "objects"):
            raise BundleUpgradeError(BundleUpgradeReason.SCHEMA_METADATA_DISAGREES, False)
        task_row = db.execute("SELECT value FROM bundle_meta WHERE key='task_id'").fetchone()
        owner_row = db.execute(
            "SELECT value FROM bundle_meta WHERE key='owner_generation'"
        ).fetchone()
        if (
            task_row is None
            or type(task_row[0]) is not str
            or owner_row is None
            or len(owner_row) != 1
            or not _is_canonical_nonnegative_generation(owner_row[0])
            or task_row[0] != str(target.task_id)
        ):
            raise BundleUpgradeError(
                BundleUpgradeReason.SCHEMA_METADATA_DISAGREES,
                False,
                {"check": "bundle_binding"},
            )
        frontier = _read_event_frontier(db) if integrity is None else integrity.frontier
        if frontier != target.frontier:
            raise BundleUpgradeError(
                BundleUpgradeReason.PLAN_STALE,
                False,
                {"check": "bundle_binding"},
            )
        if integrity is not None and integrity.task_id != target.task_id:
            raise BundleUpgradeError(
                BundleUpgradeReason.PLAN_STALE,
                False,
                {"check": "bundle_binding"},
            )

    def _inspect(
        self,
        target: BundleUpgradeTarget,
        *,
        include_integrity: bool = True,
    ) -> tuple[int, BundleIntegrity | None]:
        db: apsw.Connection | None = None
        try:
            db = open_read_only(target.bundle_path)
            identity = verify_schema_identity(db)
            if identity.user_version in {10, *BUNDLE_UPGRADE_SOURCE_VERSIONS}:
                try:
                    _validate_v10_bundle_layout(
                        db,
                        identity.user_version,
                        tuple(
                            migration
                            for migration in BUNDLE_MIGRATIONS
                            if int(migration.version) > identity.user_version
                        ),
                    )
                except RuntimeError as exc:
                    if str(exc) == BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN.value:
                        raise BundleUpgradeError(
                            BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN,
                            False,
                            {"task_id": str(target.task_id)},
                        ) from None
                    raise
            if identity.user_version not in {
                *BUNDLE_UPGRADE_SOURCE_VERSIONS,
                BUNDLE_UPGRADE_TARGET_VERSION,
            }:
                raise BundleUpgradeError(
                    BundleUpgradeReason.MIGRATION_UNSUPPORTED,
                    False,
                    {"schema_version": identity.user_version},
                )
            if not include_integrity:
                self._validate_bundle_binding(db, target)
                return identity.user_version, None
            integrity = capture_sqlite_integrity(db)
            self._validate_bundle_binding(db, target, integrity)
            return identity.user_version, integrity
        except BundleUpgradeError:
            raise
        except StorageUnsafeError as exc:
            reason = {
                "database_missing": BundleUpgradeReason.BUNDLE_MISSING,
                "schema_newer_than_binary": BundleUpgradeReason.SCHEMA_NEWER_THAN_BINARY,
                "schema_metadata_disagrees": BundleUpgradeReason.SCHEMA_METADATA_DISAGREES,
            }.get(exc.reason_code, BundleUpgradeReason.SCHEMA_METADATA_DISAGREES)
            raise BundleUpgradeError(reason, False) from exc
        except (apsw.Error, OSError, ValueError, TypeError) as exc:
            raise BundleUpgradeError(BundleUpgradeReason.BUNDLE_MISSING, False) from exc
        finally:
            self._close(db)

    def _apply_schema(self, target: BundleUpgradeTarget) -> MigrationReport:
        db: apsw.Connection | None = None
        try:
            db = self._open_migration_writer(target.bundle_path)
            report = self._migration_runner(
                db,
                BUNDLE_MIGRATIONS,
                maintenance=None,
            )
            if (
                report.from_version not in BUNDLE_UPGRADE_SOURCE_VERSIONS
                or report.to_version != BUNDLE_UPGRADE_TARGET_VERSION
                or report.applied_versions
                != tuple(
                    m.version
                    for m in BUNDLE_MIGRATIONS
                    if report.from_version < int(m.version) <= BUNDLE_UPGRADE_TARGET_VERSION
                )
            ):
                raise BundleUpgradeError(
                    BundleUpgradeReason.MIGRATION_FAILED,
                    False,
                    {"check": "migration_sequence"},
                )
            return report
        except BundleUpgradeError:
            raise
        except RuntimeError as exc:
            reason = (
                BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN
                if str(exc) == BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN.value
                else BundleUpgradeReason.MIGRATION_FAILED
            )
            raise BundleUpgradeError(reason, False, {"check": "migration"}) from exc
        except (apsw.Error, OSError, ValueError, TypeError) as exc:
            raise BundleUpgradeError(
                BundleUpgradeReason.MIGRATION_FAILED,
                True,
                {"check": "migration"},
            ) from exc
        finally:
            self._close(db)

    @staticmethod
    def _compare_preservation(before: BundleIntegrity, after: BundleIntegrity) -> None:
        checks = (
            ("task", before.task_id == after.task_id),
            ("frontier", before.frontier == after.frontier),
            ("history", before.history_digest == after.history_digest),
            ("event_count", before.event_count == after.event_count),
            ("objects", before.object_digest == after.object_digest),
            ("object_count", before.object_count == after.object_count),
            ("preserved", before.preserved_digest == after.preserved_digest),
            ("projections", before.projection_digest == after.projection_digest),
        )
        for name, matches in checks:
            if not matches:
                raise BundleUpgradeError(
                    BundleUpgradeReason.VERIFICATION_FAILED,
                    False,
                    {"check": name},
                )

    def _raise_post_commit_failure(
        self,
        operation: BundleUpgradeOperation,
        backup: BackupEvidence,
        error: BaseException,
    ) -> NoReturn:
        """Quarantine any contradiction discovered after the target schema committed."""

        try:
            self._journal.quarantine(
                operation,
                code=BundleUpgradeReason.ROLLBACK_REQUIRED.value,
                backup_manifest_digest=backup.manifest_digest,
            )
        except BundleUpgradeError:
            # The lease may have been fenced by a recovery owner.  Preserve the original typed
            # failure; that owner will observe the terminal row or retry the durable operation.
            pass
        details: dict[str, JsonValue] = {
            "backup_manifest_digest": backup.manifest_digest,
        }
        if isinstance(error, BundleUpgradeError):
            check = error.safe_details.get("check")
            if type(check) is str:
                details["check"] = check
        raise BundleUpgradeError(BundleUpgradeReason.ROLLBACK_REQUIRED, False, details) from error

    def _quarantine_operation_contradiction(
        self,
        operation: BundleUpgradeOperation,
        *,
        code: str,
        backup_manifest_digest: str | None = None,
    ) -> None:
        """Terminalize a durable contradiction before it can strand the operation.

        Callers pass only bounded internal reason codes.  The journal mutation is best effort when
        a newer owner has already fenced this operation; in that case the original typed failure
        remains the useful result and the successor can inspect the row.
        """

        try:
            self._journal.quarantine(
                operation,
                code=code,
                backup_manifest_digest=(
                    operation.backup_manifest_digest
                    if backup_manifest_digest is None
                    else backup_manifest_digest
                ),
            )
        except BundleUpgradeError:
            # Preserve the original typed failure if the lease was fenced while terminalizing.
            pass

    def _quarantine_deterministic_backup_failure(
        self,
        operation: BundleUpgradeOperation,
        error: BundleUpgradeError,
    ) -> None:
        """Terminalize a known backup contradiction before it can strand the operation."""

        if error.retryable or error.reason not in {
            BundleUpgradeReason.BACKUP_FAILED,
            BundleUpgradeReason.VERIFICATION_FAILED,
        }:
            return
        self._quarantine_operation_contradiction(operation, code=error.reason.value)

    async def _migrate_one(
        self,
        target: BundleUpgradeTarget,
        current_version: int,
        before: BundleIntegrity,
        operation: BundleUpgradeOperation,
    ) -> MigrationResult:
        backup: BackupEvidence
        self._assert_holder()
        if current_version in BUNDLE_UPGRADE_SOURCE_VERSIONS and operation.phase not in {
            BundleUpgradePhase.RESERVED,
            BundleUpgradePhase.BACKUP_READY,
        }:
            error = BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
            self._quarantine_operation_contradiction(
                operation,
                code=BundleUpgradeReason.OPERATION_LOST.value,
            )
            raise error
        if (
            current_version == BUNDLE_UPGRADE_TARGET_VERSION
            and operation.phase is BundleUpgradePhase.RESERVED
        ):
            error = BundleUpgradeError(BundleUpgradeReason.ROLLBACK_REQUIRED, False)
            self._quarantine_operation_contradiction(
                operation,
                code=BundleUpgradeReason.ROLLBACK_REQUIRED.value,
            )
            raise error
        try:
            backup = await self._effects.ensure_machine_backup(
                target,
                operation,
                before,
                operation.backup_manifest_digest,
            )
        except BundleUpgradeError as exc:
            self._quarantine_deterministic_backup_failure(operation, exc)
            raise
        except Exception as exc:
            raise BundleUpgradeError(BundleUpgradeReason.BACKUP_FAILED, True) from exc
        self._assert_holder()
        if (
            type(backup) is not BackupEvidence
            or backup.task_id != target.task_id
            or backup.frontier != before.frontier
            or (
                current_version in BUNDLE_UPGRADE_SOURCE_VERSIONS
                and backup.source_version != current_version
            )
        ):
            error = BundleUpgradeError(
                BundleUpgradeReason.BACKUP_FAILED,
                False,
                {"check": "binding"},
            )
            self._quarantine_deterministic_backup_failure(operation, error)
            raise error

        if operation.phase is BundleUpgradePhase.RESERVED:
            self._assert_holder()
            operation = self._journal.advance(
                operation,
                expected=(BundleUpgradePhase.RESERVED,),
                next_phase=BundleUpgradePhase.BACKUP_READY,
                backup_manifest_digest=backup.manifest_digest,
            )
            self._assert_holder()
        elif operation.backup_manifest_digest != backup.manifest_digest:
            error = BundleUpgradeError(
                BundleUpgradeReason.BACKUP_FAILED,
                False,
                {"check": "identity"},
            )
            self._quarantine_deterministic_backup_failure(operation, error)
            raise error

        if current_version in BUNDLE_UPGRADE_SOURCE_VERSIONS:
            if operation.phase is not BundleUpgradePhase.BACKUP_READY:
                error = BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
                self._quarantine_operation_contradiction(
                    operation,
                    code=BundleUpgradeReason.OPERATION_LOST.value,
                )
                raise error
            self._assert_holder()
            try:
                self._apply_schema(target)
            except BundleUpgradeError:
                # A DDL failure is retryable only when the old schema is still provably present.
                try:
                    version_after, _ = self._inspect(target)
                except BundleUpgradeError:
                    version_after = -1
                if version_after == current_version:
                    raise
                if version_after == BUNDLE_UPGRADE_TARGET_VERSION:
                    try:
                        self._journal.quarantine(
                            operation,
                            code=BundleUpgradeReason.ROLLBACK_REQUIRED.value,
                            backup_manifest_digest=backup.manifest_digest,
                        )
                    except BundleUpgradeError:
                        pass
                    raise BundleUpgradeError(
                        BundleUpgradeReason.ROLLBACK_REQUIRED,
                        False,
                        {"backup_manifest_digest": backup.manifest_digest},
                    )
                try:
                    self._journal.quarantine(
                        operation,
                        code=BundleUpgradeReason.ROLLBACK_REQUIRED.value,
                        backup_manifest_digest=backup.manifest_digest,
                    )
                except BundleUpgradeError:
                    pass
                raise BundleUpgradeError(BundleUpgradeReason.ROLLBACK_REQUIRED, False) from None
            self._assert_holder()
            operation = self._journal.advance(
                operation,
                expected=(BundleUpgradePhase.BACKUP_READY,),
                next_phase=BundleUpgradePhase.SCHEMA_APPLIED,
                backup_manifest_digest=backup.manifest_digest,
            )
            self._assert_holder()
        elif current_version == BUNDLE_UPGRADE_TARGET_VERSION:
            if operation.phase is BundleUpgradePhase.BACKUP_READY:
                # The process may have committed DDL before losing the phase update.  Never run
                # the destructive rebuild twice; verify the target and advance conservatively.
                self._assert_holder()
                operation = self._journal.advance(
                    operation,
                    expected=(BundleUpgradePhase.BACKUP_READY,),
                    next_phase=BundleUpgradePhase.SCHEMA_APPLIED,
                    backup_manifest_digest=backup.manifest_digest,
                )
                self._assert_holder()
            elif operation.phase not in {
                BundleUpgradePhase.SCHEMA_APPLIED,
                BundleUpgradePhase.REPLAY_VERIFIED,
            }:
                error = BundleUpgradeError(BundleUpgradeReason.ROLLBACK_REQUIRED, False)
                self._quarantine_operation_contradiction(
                    operation,
                    code=BundleUpgradeReason.ROLLBACK_REQUIRED.value,
                )
                raise error
        else:
            raise BundleUpgradeError(BundleUpgradeReason.MIGRATION_UNSUPPORTED, False)

        try:
            self._assert_holder()
            _version_after, after = self._inspect(target)
            if after is None or after.schema_version != BUNDLE_UPGRADE_TARGET_VERSION:
                raise BundleUpgradeError(
                    BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "schema"}
                )
            # A restart after DDL may observe the target version while the durable operation is
            # still pending. The original source facts then live in the machine-bound backup;
            # passing the live target snapshot as ``before`` would compare the target to itself
            # and falsely prove preservation.  The effects backend must load and verify the original backup facts.
            preservation_before = (
                before if current_version in BUNDLE_UPGRADE_SOURCE_VERSIONS else None
            )
            if preservation_before is not None:
                self._compare_preservation(preservation_before, after)
            self._assert_holder()
            replay_digest = await self._effects.verify_replay(
                target, preservation_before, after, backup
            )
            self._assert_holder()
            validate_sha256_digest(replay_digest)
            if replay_digest != after.projection_digest:
                raise BundleUpgradeError(
                    BundleUpgradeReason.VERIFICATION_FAILED,
                    False,
                    {"check": "replay_digest"},
                )
        except BundleUpgradeError as exc:
            self._raise_post_commit_failure(operation, backup, exc)
        except Exception as exc:
            self._raise_post_commit_failure(operation, backup, exc)

        if operation.phase is BundleUpgradePhase.SCHEMA_APPLIED:
            self._assert_holder()
            operation = self._journal.advance(
                operation,
                expected=(BundleUpgradePhase.SCHEMA_APPLIED,),
                next_phase=BundleUpgradePhase.REPLAY_VERIFIED,
                backup_manifest_digest=backup.manifest_digest,
            )
            self._assert_holder()
        elif operation.phase is not BundleUpgradePhase.REPLAY_VERIFIED:
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)

        result = MigrationResult(
            request_id=request_id(operation.request_id),
            task_id=target.task_id,
            from_version=str(backup.source_version),
            to_version=str(BUNDLE_UPGRADE_TARGET_VERSION),
            backup_manifest_digest=backup.manifest_digest,
            frontier_before=before.frontier,
            frontier_after=after.frontier,
            replay_digest=replay_digest,
            completed_at=Timestamp(format_rfc3339_millis(self._clock.now_utc())),
        )
        self._assert_holder()
        self._journal.complete(operation, result)
        self._assert_holder()
        return result

    async def run_before_ready(
        self,
        targets: Sequence[BundleUpgradeTarget],
    ) -> BundleUpgradeReport:
        """Migrate stale v12-v15 targets before any READY work is admitted."""

        if type(targets) not in (tuple, list):
            raise TypeError("bundle_upgrade_targets_invalid")
        ordered = tuple(targets)
        if any(type(item) is not BundleUpgradeTarget for item in ordered):
            raise ValueError("bundle_upgrade_targets_invalid")
        if len({str(item.task_id) for item in ordered}) != len(ordered):
            raise ValueError("bundle_upgrade_targets_invalid")

        candidates: list[BundleUpgradeTarget] = []
        already_current: list[TaskId] = []
        for target in sorted(ordered, key=lambda item: str(item.task_id).encode("ascii")):
            self._assert_holder()
            self._journal.validate_target(target)
            current, _before = self._inspect(target, include_integrity=False)
            pending = self._journal.has_unfinished(target)
            if current == BUNDLE_UPGRADE_TARGET_VERSION and not pending:
                already_current.append(target.task_id)
            else:
                candidates.append(target)
        if not candidates:
            return BundleUpgradeReport((), tuple(already_current))
        if self._acquire_holder is None:
            raise BundleUpgradeError(BundleUpgradeReason.HOLDER_REQUIRED, False)

        migrated: list[MigrationResult] = []
        try:
            async with self._acquire_holder(tuple(candidates)):
                for target in candidates:
                    self._assert_holder()
                    current, before = self._inspect(target)
                    if before is None:
                        raise BundleUpgradeError(BundleUpgradeReason.VERIFICATION_FAILED, False)
                    self._assert_holder()
                    operation = self._journal.reserve(
                        target,
                        create_if_absent=current in BUNDLE_UPGRADE_SOURCE_VERSIONS,
                    )
                    self._assert_holder()
                    if operation is None:
                        already_current.append(target.task_id)
                        continue
                    if operation.state is BundleUpgradeState.COMPLETE:
                        if current != BUNDLE_UPGRADE_TARGET_VERSION:
                            # A terminal journal row paired with a restored/older bundle is a
                            # durable contradiction.  Do not report it as already current or
                            # silently create a second operation with a new backup identity.
                            raise BundleUpgradeError(
                                BundleUpgradeReason.ROLLBACK_REQUIRED,
                                False,
                                {"task_id": str(target.task_id)},
                            )
                        already_current.append(target.task_id)
                        continue
                    self._assert_holder()
                    migrated.append(await self._migrate_one(target, current, before, operation))
                    self._assert_holder()
        except BundleUpgradeError:
            raise
        except Exception as exc:
            raise BundleUpgradeError(BundleUpgradeReason.HOLDER_CONFLICT, True) from exc
        return BundleUpgradeReport(tuple(migrated), tuple(already_current))
