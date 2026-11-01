"""Backup, restore, and migration authority boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Literal, Never, Protocol, cast

from finishup.domain.values import (
    Frontier,
    JsonObject,
    JsonValue,
    RequestId,
    SessionId,
    TaskId,
    Timestamp,
    request_id,
    session_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.ports.keys import RecoverySecret
from finishup.ports.objects import ObjectKind, ObjectRef
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.errors import PROTOCOL_REASON_CODES, ProtocolValueError
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "BackupCommand",
    "BackupManifest",
    "BackupMode",
    "BackupObjectEntry",
    "BackupPlan",
    "BackupResult",
    "MaintenanceError",
    "MaintenanceHandle",
    "MaintenanceKind",
    "MaintenanceLocation",
    "MaintenancePin",
    "MaintenancePort",
    "MaintenanceReason",
    "MigrationCommand",
    "MigrationPlan",
    "MigrationResult",
    "PrivacyAuditBackupSnapshot",
    "RecoveryOperation",
    "RecoverySecretAcquirer",
    "RecoverySecretAcquisition",
    "RecoverySecret",
    "RestoreCommand",
    "RestorePlan",
    "RestoreResult",
]

type DestinationPolicy = Literal["new_route_only"]

_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_MAX_LOCATION_CHARS = 4_096
_MAX_WARNINGS = 64
_TOKEN_RE = re.compile(r"^[a-z0-9][a-z0-9._:/+-]{0,127}$", re.ASCII)
_LOGICAL_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", re.ASCII)


class MaintenanceKind(str, Enum):  # noqa: UP042 - exact durable wire enum
    BACKUP = "backup"
    RESTORE = "restore"
    MIGRATION = "migration"


class BackupMode(str, Enum):  # noqa: UP042 - exact durable wire enum
    MACHINE_BOUND = "machine_bound"
    PORTABLE_RECOVERY = "portable_recovery"


class RecoveryOperation(str, Enum):  # noqa: UP042 - exact durable wire enum
    CREATE = "create"
    RESTORE = "restore"


@dataclass(frozen=True, slots=True)
class RecoverySecretAcquisition:
    """Secret-free authority request for one confirmed portable operation."""

    request_id: RequestId
    confirmed_plan_digest: str
    service_generation: int
    operation: RecoveryOperation

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        _digest(self.confirmed_plan_digest)
        _positive_int(self.service_generation)
        if type(self.operation) is not RecoveryOperation:
            raise _invalid()


class MaintenanceReason(str, Enum):  # noqa: UP042 - exact durable wire enum
    PLAN_STALE = "plan_stale"
    CONFIRMATION_REQUIRED = "confirmation_required"
    TARGET_EXISTS = "target_exists"
    TARGET_UNSAFE = "target_unsafe"
    SOURCE_INVALID = "source_invalid"
    MANIFEST_INVALID = "manifest_invalid"
    MANIFEST_TAMPERED = "manifest_tampered"
    BACKUP_INCOMPLETE = "backup_incomplete"
    KEY_UNAVAILABLE = "key_unavailable"
    RECOVERY_SECRET_WRONG = "recovery_secret_wrong"
    RECOVERY_ARTIFACT_INVALID = "recovery_artifact_invalid"
    OBJECT_MISSING = "object_missing"
    OBJECT_TAMPERED = "object_tampered"
    DATABASE_INVALID = "database_invalid"
    REPLAY_MISMATCH = "replay_mismatch"
    CATALOG_ROUTE_CHANGED = "catalog_route_changed"
    MAINTENANCE_BUSY = "maintenance_busy"
    MIGRATION_UNSUPPORTED = "migration_unsupported"
    MIGRATION_FAILED = "migration_failed"
    ROLLBACK_REQUIRED = "rollback_required"
    GENERATION_LOST = "generation_lost"


def _invalid(reason: str = "maintenance_value_invalid") -> ProtocolValueError:
    if reason not in PROTOCOL_REASON_CODES:
        reason = "invalid_event_value_type"
    return ProtocolValueError(reason)


def _positive_int(value: object) -> int:
    if type(value) is not int or not 1 <= value <= _MAX_SAFE_INTEGER:
        raise _invalid()
    return value


def _nonnegative_int(value: object) -> int:
    if type(value) is not int or not 0 <= value <= _MAX_SAFE_INTEGER:
        raise _invalid()
    return value


def _token(value: object) -> str:
    if type(value) is not str or _TOKEN_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _positive_decimal(value: object) -> str:
    if type(value) is not str or not value.isascii() or not value.isdecimal():
        raise _invalid()
    parsed = int(value)
    if not 1 <= parsed <= _MAX_SAFE_INTEGER or str(parsed) != value:
        raise _invalid()
    return value


def _logical_name(value: object) -> str:
    if type(value) is not str or _LOGICAL_NAME_RE.fullmatch(value) is None:
        raise _invalid()
    return value


def _exact_tuple(value: object) -> tuple[object, ...]:
    if type(value) is not tuple:
        raise _invalid()
    return cast(tuple[object, ...], value)


def _sorted_tokens(value: object, *, allow_empty: bool = True) -> tuple[str, ...]:
    raw = _exact_tuple(value)
    if len(raw) > _MAX_WARNINGS or (not allow_empty and not raw):
        raise _invalid()
    result: list[str] = []
    previous: str | None = None
    for item in raw:
        member = _token(item)
        if previous is not None and member.encode("ascii") <= previous.encode("ascii"):
            raise _invalid("duplicate_set_member" if member == previous else "unsorted_set_field")
        result.append(member)
        previous = member
    return tuple(result)


def _ordered_unique_tokens(value: object) -> tuple[str, ...]:
    raw = _exact_tuple(value)
    if not 1 <= len(raw) <= 64:
        raise _invalid()
    result: list[str] = []
    seen: set[str] = set()
    for item in raw:
        member = _token(item)
        if member in seen:
            raise _invalid("duplicate_set_member")
        seen.add(member)
        result.append(member)
    return tuple(result)


def _json_rows(value: object) -> tuple[JsonObject, ...]:
    raw = _exact_tuple(value)
    result: list[JsonObject] = []
    previous: bytes | None = None
    for item in raw:
        row = item if type(item) is JsonObject else JsonObject(item)
        encoded = canonical_encode(row)
        if previous is not None and encoded <= previous:
            raise _invalid("duplicate_set_member" if encoded == previous else "unsorted_set_field")
        result.append(row)
        previous = encoded
    return tuple(result)


def _digest(value: object) -> str:
    if type(value) is not str:
        raise _invalid("invalid_digest")
    return validate_sha256_digest(value)


def _digest_or_none(value: object) -> str | None:
    if value is None:
        return None
    return _digest(value)


def _frontier(value: object) -> Frontier:
    if type(value) is not Frontier:
        raise _invalid("invalid_frontier")
    return value


def _timestamp(value: object) -> Timestamp:
    if type(value) is not Timestamp:
        raise _invalid("invalid_timestamp")
    return value


@dataclass(frozen=True, slots=True, repr=False)
class MaintenanceLocation:
    value: str

    def __post_init__(self) -> None:
        if (
            type(self.value) is not str
            or not 1 <= len(self.value) <= _MAX_LOCATION_CHARS
            or any(ord(char) < 32 or ord(char) == 127 for char in self.value)
        ):
            raise _invalid("maintenance_location_invalid")

    def __repr__(self) -> str:
        return "<MaintenanceLocation redacted>"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("maintenance_location_not_serializable")


@dataclass(frozen=True, slots=True, repr=False)
class MaintenanceHandle:
    task_id: TaskId
    kind: MaintenanceKind
    request_id: RequestId
    route_identity_digest: str
    owner_generation: int
    lease_generation: int
    confirmed_plan_digest: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "task_id", task_id(self.task_id))
        if type(self.kind) is not MaintenanceKind:
            raise _invalid()
        object.__setattr__(self, "request_id", request_id(self.request_id))
        _digest(self.route_identity_digest)
        _positive_int(self.owner_generation)
        _positive_int(self.lease_generation)
        _digest(self.confirmed_plan_digest)

    def __repr__(self) -> str:
        return "<MaintenanceHandle redacted>"

    __str__ = __repr__

    def __reduce__(self) -> Never:
        raise TypeError("maintenance_handle_not_serializable")


@dataclass(frozen=True, slots=True)
class MaintenanceError(Exception):
    reason: MaintenanceReason
    retryable: bool
    safe_details: Mapping[str, JsonValue]

    def __post_init__(self) -> None:
        if type(self.reason) is not MaintenanceReason or type(self.retryable) is not bool:
            raise _invalid("maintenance_error_invalid")
        try:
            details = JsonObject(self.safe_details)
        except ProtocolValueError as exc:
            raise _invalid("maintenance_error_invalid") from exc
        if (
            len(details) > 16
            or len(canonical_encode(details)) > 4_096
            or any(_TOKEN_RE.fullmatch(key) is None for key in details)
        ):
            raise _invalid("maintenance_error_invalid")
        object.__setattr__(self, "safe_details", details)
        Exception.__init__(self, self.reason.value)


@dataclass(frozen=True, slots=True)
class MaintenancePin:
    pin_id: str
    task_id: TaskId
    frontier: Frontier
    owner_generation: int
    privacy_root_generation: int
    privacy_root_digest: str
    expires_at: Timestamp

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.MAINTENANCE_PIN, self.pin_id)
        except ProtocolValueError as exc:
            raise _invalid() from exc
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.frontier)
        _positive_int(self.owner_generation)
        _nonnegative_int(self.privacy_root_generation)
        _digest(self.privacy_root_digest)
        _timestamp(self.expires_at)


@dataclass(frozen=True, slots=True)
class BackupObjectEntry:
    object_id: str
    kind: ObjectKind
    envelope_digest: str
    envelope_size: int

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.OBJECT, self.object_id)
        except ProtocolValueError as exc:
            raise _invalid() from exc
        if type(self.kind) is not ObjectKind or self.kind is ObjectKind.IMPORT_STDERR:
            raise _invalid()
        _digest(self.envelope_digest)
        _nonnegative_int(self.envelope_size)


@dataclass(frozen=True, slots=True)
class PrivacyAuditBackupSnapshot:
    origin_installation_id: str
    origin_task_id: TaskId
    catalog_version: str
    audit_store_version: str
    privacy_root_generation: int
    privacy_root_digest: str
    audit_rows: tuple[JsonObject, ...]
    terminal_receipts: tuple[JsonObject, ...]
    privacy_audit_objects: tuple[ObjectRef, ...]

    def __post_init__(self) -> None:
        try:
            validate_id(IdKind.INSTALLATION, self.origin_installation_id)
        except ProtocolValueError as exc:
            raise _invalid() from exc
        object.__setattr__(self, "origin_task_id", task_id(self.origin_task_id))
        object.__setattr__(self, "catalog_version", _positive_decimal(self.catalog_version))
        object.__setattr__(self, "audit_store_version", _positive_decimal(self.audit_store_version))
        _nonnegative_int(self.privacy_root_generation)
        _digest(self.privacy_root_digest)
        object.__setattr__(self, "audit_rows", _json_rows(self.audit_rows))
        object.__setattr__(self, "terminal_receipts", _json_rows(self.terminal_receipts))
        raw_objects = _exact_tuple(self.privacy_audit_objects)
        objects: list[ObjectRef] = []
        previous: str | None = None
        for item in raw_objects:
            if type(item) is not ObjectRef or item.metadata.kind is not ObjectKind.PRIVACY_AUDIT:
                raise _invalid()
            if previous is not None and item.object_id.encode("ascii") <= previous.encode("ascii"):
                raise _invalid(
                    "duplicate_set_member" if item.object_id == previous else "unsorted_set_field"
                )
            objects.append(item)
            previous = item.object_id
        object.__setattr__(self, "privacy_audit_objects", tuple(objects))


@dataclass(frozen=True, slots=True)
class BackupManifest:
    manifest_schema: Literal["yoetz.backup-manifest/1"]
    backup_format: str
    request_id: RequestId
    task_id: TaskId
    frontier: Frontier
    database_logical_name: str
    database_size: int
    database_digest: str
    objects: tuple[BackupObjectEntry, ...]
    object_set_digest: str
    version_manifest: JsonObject
    mode: BackupMode
    key_fingerprint: str
    key_locator_classification: str
    recovery_artifact_logical_name: str | None
    recovery_artifact_digest: str | None
    recovery_kdf_policy: JsonObject | None
    privacy_audit_snapshot_logical_name: Literal["privacy-audit-snapshot.json"]
    privacy_audit_snapshot_size: int
    privacy_audit_snapshot_digest: str
    privacy_root_generation: int
    privacy_root_digest: str
    audit_store_version: str
    privacy_audit_row_count: int
    privacy_audit_object_count: int
    created_at: Timestamp
    completed_at: Timestamp
    manifest_digest: str

    def __post_init__(self) -> None:
        if self.manifest_schema != "yoetz.backup-manifest/1":
            raise _invalid("maintenance_manifest_invalid")
        object.__setattr__(self, "backup_format", _token(self.backup_format))
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.frontier)
        object.__setattr__(self, "database_logical_name", _logical_name(self.database_logical_name))
        _nonnegative_int(self.database_size)
        _digest(self.database_digest)
        raw_objects = _exact_tuple(self.objects)
        objects: list[BackupObjectEntry] = []
        previous: str | None = None
        for item in raw_objects:
            if type(item) is not BackupObjectEntry:
                raise _invalid("maintenance_manifest_invalid")
            if previous is not None and item.object_id.encode("ascii") <= previous.encode("ascii"):
                raise _invalid(
                    "duplicate_set_member" if item.object_id == previous else "unsorted_set_field"
                )
            objects.append(item)
            previous = item.object_id
        object.__setattr__(self, "objects", tuple(objects))
        _digest(self.object_set_digest)
        if type(self.version_manifest) is not JsonObject:
            raise _invalid("maintenance_manifest_invalid")
        if type(self.mode) is not BackupMode:
            raise _invalid()
        object.__setattr__(self, "key_fingerprint", _token(self.key_fingerprint))
        object.__setattr__(
            self,
            "key_locator_classification",
            _token(self.key_locator_classification),
        )
        portable = self.mode is BackupMode.PORTABLE_RECOVERY
        if portable:
            if self.recovery_artifact_logical_name is None or self.recovery_kdf_policy is None:
                raise _invalid("maintenance_manifest_invalid")
            object.__setattr__(
                self,
                "recovery_artifact_logical_name",
                _logical_name(self.recovery_artifact_logical_name),
            )
            _digest(self.recovery_artifact_digest)
            if type(self.recovery_kdf_policy) is not JsonObject:
                raise _invalid("maintenance_manifest_invalid")
        elif any(
            value is not None
            for value in (
                self.recovery_artifact_logical_name,
                self.recovery_artifact_digest,
                self.recovery_kdf_policy,
            )
        ):
            raise _invalid("maintenance_manifest_invalid")
        if self.privacy_audit_snapshot_logical_name != "privacy-audit-snapshot.json":
            raise _invalid("maintenance_manifest_invalid")
        _nonnegative_int(self.privacy_audit_snapshot_size)
        _digest(self.privacy_audit_snapshot_digest)
        _nonnegative_int(self.privacy_root_generation)
        _digest(self.privacy_root_digest)
        object.__setattr__(self, "audit_store_version", _positive_decimal(self.audit_store_version))
        _nonnegative_int(self.privacy_audit_row_count)
        _nonnegative_int(self.privacy_audit_object_count)
        _timestamp(self.created_at)
        _timestamp(self.completed_at)
        if self.completed_at < self.created_at:
            raise _invalid("maintenance_manifest_invalid")
        _digest(self.manifest_digest)


@dataclass(frozen=True, slots=True)
class BackupCommand:
    request_id: RequestId
    session_id: SessionId
    destination: MaintenanceLocation
    mode: BackupMode
    expected_frontier: Frontier

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        if type(self.destination) is not MaintenanceLocation or type(self.mode) is not BackupMode:
            raise _invalid()
        _frontier(self.expected_frontier)


@dataclass(frozen=True, slots=True)
class BackupPlan:
    request_digest: str
    task_id: TaskId
    frontier: Frontier
    mode: BackupMode
    destination_commitment: str
    object_count: int
    estimated_ciphertext_bytes: int
    privacy_audit_object_count: int
    privacy_audit_snapshot_digest: str
    version_manifest: JsonObject
    warnings: tuple[str, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        _digest(self.request_digest)
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.frontier)
        if type(self.mode) is not BackupMode:
            raise _invalid()
        validate_commitment(self.destination_commitment)
        _nonnegative_int(self.object_count)
        _nonnegative_int(self.estimated_ciphertext_bytes)
        _nonnegative_int(self.privacy_audit_object_count)
        _digest(self.privacy_audit_snapshot_digest)
        if type(self.version_manifest) is not JsonObject:
            raise _invalid()
        object.__setattr__(self, "warnings", _sorted_tokens(self.warnings))
        _digest(self.plan_digest)


@dataclass(frozen=True, slots=True)
class BackupResult:
    request_id: RequestId
    task_id: TaskId
    frontier: Frontier
    mode: BackupMode
    backup_manifest_digest: str
    backup_set_digest: str
    object_count: int
    privacy_audit_object_count: int
    privacy_audit_snapshot_digest: str
    database_digest: str
    recovery_artifact_digest: str | None
    completed_at: Timestamp

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.frontier)
        if type(self.mode) is not BackupMode:
            raise _invalid()
        _digest(self.backup_manifest_digest)
        _digest(self.backup_set_digest)
        _nonnegative_int(self.object_count)
        _nonnegative_int(self.privacy_audit_object_count)
        _digest(self.privacy_audit_snapshot_digest)
        _digest(self.database_digest)
        recovery_digest = _digest_or_none(self.recovery_artifact_digest)
        if (self.mode is BackupMode.PORTABLE_RECOVERY) != (recovery_digest is not None):
            raise _invalid()
        object.__setattr__(self, "recovery_artifact_digest", recovery_digest)
        _timestamp(self.completed_at)


@dataclass(frozen=True, slots=True)
class RestoreCommand:
    request_id: RequestId
    source: MaintenanceLocation
    destination_policy: DestinationPolicy
    recovery_mode: BackupMode
    expected_task_id: TaskId | None
    expected_active_frontier: Frontier | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        if type(self.source) is not MaintenanceLocation:
            raise _invalid()
        if (
            self.destination_policy != "new_route_only"
            or type(self.recovery_mode) is not BackupMode
        ):
            raise _invalid()
        if self.expected_task_id is not None:
            object.__setattr__(self, "expected_task_id", task_id(self.expected_task_id))
        if self.expected_active_frontier is not None:
            _frontier(self.expected_active_frontier)


@dataclass(frozen=True, slots=True)
class RestorePlan:
    request_digest: str
    source_manifest_digest: str
    task_id: TaskId
    backup_frontier: Frontier
    active_frontier: Frontier | None
    new_route_identity_digest: str
    key_classification: BackupMode
    migration_needed: bool
    warnings: tuple[str, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        _digest(self.request_digest)
        _digest(self.source_manifest_digest)
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.backup_frontier)
        if self.active_frontier is not None:
            _frontier(self.active_frontier)
        _digest(self.new_route_identity_digest)
        if (
            type(self.key_classification) is not BackupMode
            or type(self.migration_needed) is not bool
        ):
            raise _invalid()
        object.__setattr__(self, "warnings", _sorted_tokens(self.warnings))
        _digest(self.plan_digest)


@dataclass(frozen=True, slots=True)
class RestoreResult:
    request_id: RequestId
    task_id: TaskId
    restored_frontier: Frontier
    prior_route_identity_digest: str | None
    active_route_identity_digest: str
    backup_manifest_digest: str
    replay_digest: str
    completed_at: Timestamp

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        _frontier(self.restored_frontier)
        object.__setattr__(
            self,
            "prior_route_identity_digest",
            _digest_or_none(self.prior_route_identity_digest),
        )
        _digest(self.active_route_identity_digest)
        _digest(self.backup_manifest_digest)
        _digest(self.replay_digest)
        _timestamp(self.completed_at)


@dataclass(frozen=True, slots=True)
class MigrationCommand:
    request_id: RequestId
    session_id: SessionId
    target_storage_version: str
    expected_frontier: Frontier

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "session_id", session_id(self.session_id))
        object.__setattr__(
            self,
            "target_storage_version",
            _positive_decimal(self.target_storage_version),
        )
        _frontier(self.expected_frontier)


@dataclass(frozen=True, slots=True)
class MigrationPlan:
    request_digest: str
    task_id: TaskId
    from_version: str
    to_version: str
    current_frontier: Frontier
    required_migration_ids: tuple[str, ...]
    preflight_backup_mode: BackupMode
    warnings: tuple[str, ...]
    plan_digest: str

    def __post_init__(self) -> None:
        _digest(self.request_digest)
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "from_version", _positive_decimal(self.from_version))
        object.__setattr__(self, "to_version", _positive_decimal(self.to_version))
        if int(self.to_version) <= int(self.from_version):
            raise _invalid()
        _frontier(self.current_frontier)
        object.__setattr__(
            self,
            "required_migration_ids",
            _ordered_unique_tokens(self.required_migration_ids),
        )
        if type(self.preflight_backup_mode) is not BackupMode:
            raise _invalid()
        object.__setattr__(self, "warnings", _sorted_tokens(self.warnings))
        _digest(self.plan_digest)


@dataclass(frozen=True, slots=True)
class MigrationResult:
    request_id: RequestId
    task_id: TaskId
    from_version: str
    to_version: str
    backup_manifest_digest: str
    frontier_before: Frontier
    frontier_after: Frontier
    replay_digest: str
    completed_at: Timestamp

    def __post_init__(self) -> None:
        object.__setattr__(self, "request_id", request_id(self.request_id))
        object.__setattr__(self, "task_id", task_id(self.task_id))
        object.__setattr__(self, "from_version", _positive_decimal(self.from_version))
        object.__setattr__(self, "to_version", _positive_decimal(self.to_version))
        if int(self.to_version) <= int(self.from_version):
            raise _invalid()
        _digest(self.backup_manifest_digest)
        _frontier(self.frontier_before)
        _frontier(self.frontier_after)
        if self.frontier_after != self.frontier_before:
            raise _invalid("maintenance_replay_frontier_changed")
        _digest(self.replay_digest)
        _timestamp(self.completed_at)


class MaintenancePort(Protocol):
    async def preview_backup(self, command: BackupCommand) -> BackupPlan: ...

    async def backup(
        self,
        command: BackupCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> BackupResult: ...

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan: ...

    async def restore(
        self,
        command: RestoreCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> RestoreResult: ...

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan: ...

    async def migrate(
        self,
        command: MigrationCommand,
        confirmed_plan_digest: str,
    ) -> MigrationResult: ...


class RecoverySecretAcquirer(Protocol):
    """Acquire one opaque recovery handle for one exact confirmed plan."""

    async def acquire_recovery_secret(
        self,
        acquisition: RecoverySecretAcquisition,
    ) -> RecoverySecret: ...
