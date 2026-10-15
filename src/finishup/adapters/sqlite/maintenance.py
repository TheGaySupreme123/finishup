"""Generation-fenced SQLite maintenance orchestration and backup-set codecs.

The procedure backend is deliberately narrow: it owns the repository, object-store,
privacy-catalog, and key-adapter evidence that cannot be reconstructed from structural
SQLite rows.  This module owns confirmation, catalog operation/lease state, bundle
frontier pins, canonical backup manifests, and complete read-only backup-set checks.
"""

from __future__ import annotations

import hashlib
import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Literal, Protocol, cast

import apsw

from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, current_schema_version
from finishup.domain.coordination import ProjectTextRef
from finishup.domain.values import (
    Frontier,
    JsonObject,
    JsonValue,
    Timestamp,
    format_rfc3339_millis,
    parse_rfc3339_millis,
    request_id,
    task_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.keys import RecoverySecret
from finishup.ports.maintenance import (
    BackupCommand,
    BackupManifest,
    BackupMode,
    BackupObjectEntry,
    BackupPlan,
    BackupResult,
    MaintenanceError,
    MaintenanceHandle,
    MaintenanceKind,
    MaintenancePin,
    MaintenanceReason,
    MigrationCommand,
    MigrationPlan,
    MigrationResult,
    RestoreCommand,
    RestorePlan,
    RestoreResult,
)
from finishup.ports.objects import ObjectKind
from finishup.ports.privacy import PrivacyAuditObjectRoots
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "RestoredTargetEvidence",
    "SqliteMaintenance",
    "VerifiedBackupSet",
    "build_backup_manifest",
    "verify_backup_set",
]

_MANIFEST_NAME = "backup-manifest.json"
_PRIVACY_SNAPSHOT_NAME = "privacy-audit-snapshot.json"
_DATABASE_NAME = "ledger.sqlite3"
_RECOVERY_NAME = "portable-recovery.json"
_COPY_CHUNK_BYTES = 1024 * 1024
_MAX_MANIFEST_BYTES = 1024 * 1024
_MAX_SIDECAR_BYTES = 4 * 1024 * 1024
_MAX_SAFE_INTEGER = 9_007_199_254_740_991
_FINISHUP_APPLICATION_ID = 0x594F4554
_CURRENT_BUNDLE_SCHEMA_VERSION = current_schema_version(BUNDLE_MIGRATIONS)


class _OperationState(StrEnum):
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"


class _PinContradiction(Exception):
    pass


@dataclass(frozen=True, slots=True)
class _AuthorityFacts:
    """Current authoritative facts required by the frozen catalog operation row."""

    task_id: str
    frontier: Frontier
    source_route_identity_digest: str
    owner_generation: int
    privacy_roots: PrivacyAuditObjectRoots
    backup_mode: BackupMode
    source_location_commitment: str | None = None
    target_location_commitment: str | None = None
    target_route_identity_digest: str | None = None
    requested_target_version: str | None = None

    def __post_init__(self) -> None:
        task_id(self.task_id)
        if type(self.frontier) is not Frontier:
            raise ValueError("maintenance_authority_facts_invalid")
        validate_sha256_digest(self.source_route_identity_digest)
        if type(self.owner_generation) is not int or self.owner_generation <= 0:
            raise ValueError("maintenance_authority_facts_invalid")
        if type(self.privacy_roots) is not PrivacyAuditObjectRoots:
            raise ValueError("maintenance_authority_facts_invalid")
        if (
            self.privacy_roots.task_id != self.task_id
            or self.privacy_roots.route_identity_digest != self.source_route_identity_digest
        ):
            raise ValueError("maintenance_authority_facts_invalid")
        if type(self.backup_mode) is not BackupMode:
            raise ValueError("maintenance_authority_facts_invalid")
        for value in (self.source_location_commitment, self.target_location_commitment):
            if value is not None:
                validate_commitment(value)
        if self.target_route_identity_digest is not None:
            validate_sha256_digest(self.target_route_identity_digest)
        if self.requested_target_version is not None and (
            not self.requested_target_version.isascii()
            or not self.requested_target_version.isdecimal()
        ):
            raise ValueError("maintenance_authority_facts_invalid")


class _MaintenanceProcedures(Protocol):
    """Composed evidence/effect seam; implementations remain inside the ready service."""

    async def preview_backup(self, command: BackupCommand) -> BackupPlan: ...

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan: ...

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan: ...

    async def authority_facts(
        self,
        command: BackupCommand | RestoreCommand | MigrationCommand,
        plan: BackupPlan | RestorePlan | MigrationPlan,
    ) -> _AuthorityFacts: ...

    async def current_privacy_roots(
        self, task_id: str, route_identity_digest: str
    ) -> PrivacyAuditObjectRoots: ...

    async def backup(
        self,
        handle: MaintenanceHandle,
        pin: MaintenancePin,
        command: BackupCommand,
        plan: BackupPlan,
        recovery_secret: RecoverySecret | None,
    ) -> BackupResult: ...

    async def restore(
        self,
        handle: MaintenanceHandle,
        command: RestoreCommand,
        plan: RestorePlan,
        recovery_secret: RecoverySecret | None,
    ) -> _RestoredTarget: ...

    async def migrate(
        self,
        handle: MaintenanceHandle,
        command: MigrationCommand,
        plan: MigrationPlan,
    ) -> MigrationResult: ...


@dataclass(frozen=True, slots=True)
class VerifiedBackupSet:
    """Opaque complete proof returned only after every named member verifies."""

    root: Path
    manifest: BackupManifest
    database_path: Path
    privacy_snapshot_path: Path
    object_paths: tuple[Path, ...]
    recovery_artifact_path: Path | None
    backup_set_digest: str


@dataclass(frozen=True, slots=True)
class RestoredTargetEvidence:
    """Path-free evidence that a quarantined target reproduced canonical truth."""

    task_id: str
    frontier: Frontier
    head_digest: str
    replay_digest: str
    object_set_digest: str
    key_fingerprint: str
    storage_version: str
    route_identity_digest: str
    owner_generation: int

    def __post_init__(self) -> None:
        task_id(self.task_id)
        if type(self.frontier) is not Frontier or self.head_digest != self.frontier.head_digest:
            raise ValueError("restored_target_evidence_invalid")
        for digest in (self.replay_digest, self.object_set_digest, self.route_identity_digest):
            validate_sha256_digest(digest)
        if type(self.key_fingerprint) is not str or not self.key_fingerprint:
            raise ValueError("restored_target_evidence_invalid")
        if (
            type(self.storage_version) is not str
            or not self.storage_version.isascii()
            or not self.storage_version.isdecimal()
        ):
            raise ValueError("restored_target_evidence_invalid")
        parsed_storage_version = int(self.storage_version, 10)
        if parsed_storage_version <= 0 or str(parsed_storage_version) != self.storage_version:
            raise ValueError("restored_target_evidence_invalid")
        if type(self.owner_generation) is not int or self.owner_generation <= 0:
            raise ValueError("restored_target_evidence_invalid")


@dataclass(frozen=True, slots=True)
class _RestoredTarget:
    """Backend result after quarantine verification and privacy reconciliation."""

    evidence: RestoredTargetEvidence
    result: RestoreResult
    bundle_relpath: str
    privacy_reconciled: bool

    def __post_init__(self) -> None:
        bundle_parts = self.bundle_relpath.split("/") if type(self.bundle_relpath) is str else ()
        staging_name = bundle_parts[1] if len(bundle_parts) == 2 else ""
        if (
            type(self.evidence) is not RestoredTargetEvidence
            or type(self.result) is not RestoreResult
            or self.result.task_id != self.evidence.task_id
            or self.result.restored_frontier != self.evidence.frontier
            or self.result.replay_digest != self.evidence.replay_digest
            or self.result.active_route_identity_digest != self.evidence.route_identity_digest
            or bundle_parts[:1] != ["tasks"]
            or len(bundle_parts) != 2
            or not staging_name.startswith("restore-")
            or not len("restore-") < len(staging_name) <= 128
            or any(
                character not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                for character in staging_name
            )
            or type(self.privacy_reconciled) is not bool
        ):
            raise ValueError("restored_target_invalid")


def _object_entry_value(entry: BackupObjectEntry) -> JsonObject:
    return JsonObject(
        {
            "object_id": entry.object_id,
            "kind": entry.kind.value,
            "envelope_digest": entry.envelope_digest,
            "envelope_size": entry.envelope_size,
        }
    )


def _manifest_value(manifest: BackupManifest, *, include_self_digest: bool) -> JsonObject:
    value: dict[str, JsonValue] = {
        "manifest_schema": manifest.manifest_schema,
        "backup_format": manifest.backup_format,
        "request_id": str(manifest.request_id),
        "task_id": str(manifest.task_id),
        "frontier": manifest.frontier.as_wire(),
        "database_logical_name": manifest.database_logical_name,
        "database_size": manifest.database_size,
        "database_digest": manifest.database_digest,
        "objects": tuple(_object_entry_value(entry) for entry in manifest.objects),
        "object_set_digest": manifest.object_set_digest,
        "version_manifest": manifest.version_manifest,
        "mode": manifest.mode.value,
        "key_fingerprint": manifest.key_fingerprint,
        "key_locator_classification": manifest.key_locator_classification,
        "recovery_artifact_logical_name": manifest.recovery_artifact_logical_name,
        "recovery_artifact_digest": manifest.recovery_artifact_digest,
        "recovery_kdf_policy": manifest.recovery_kdf_policy,
        "privacy_audit_snapshot_logical_name": manifest.privacy_audit_snapshot_logical_name,
        "privacy_audit_snapshot_size": manifest.privacy_audit_snapshot_size,
        "privacy_audit_snapshot_digest": manifest.privacy_audit_snapshot_digest,
        "privacy_root_generation": manifest.privacy_root_generation,
        "privacy_root_digest": manifest.privacy_root_digest,
        "audit_store_version": manifest.audit_store_version,
        "privacy_audit_row_count": manifest.privacy_audit_row_count,
        "privacy_audit_object_count": manifest.privacy_audit_object_count,
        "created_at": manifest.created_at.wire,
        "completed_at": manifest.completed_at.wire,
    }
    if include_self_digest:
        value["manifest_digest"] = manifest.manifest_digest
    return JsonObject(value)


def build_backup_manifest(
    *,
    backup_format: str,
    request_id_value: str,
    task_id_value: str,
    frontier: Frontier,
    database_size: int,
    database_digest: str,
    objects: tuple[BackupObjectEntry, ...],
    version_manifest: JsonObject,
    mode: BackupMode,
    key_fingerprint: str,
    key_locator_classification: str,
    recovery_artifact_digest: str | None,
    recovery_kdf_policy: JsonObject | None,
    privacy_audit_snapshot_size: int,
    privacy_audit_snapshot_digest: str,
    privacy_root_generation: int,
    privacy_root_digest: str,
    audit_store_version: str,
    privacy_audit_row_count: int,
    privacy_audit_object_count: int,
    created_at: Timestamp,
    completed_at: Timestamp,
) -> BackupManifest:
    """Build the one canonical manifest and derive both set and self identities."""

    object_set_digest = canonical_digest(tuple(_object_entry_value(entry) for entry in objects))
    portable = mode is BackupMode.PORTABLE_RECOVERY
    draft = BackupManifest(
        manifest_schema="yoetz.backup-manifest/1",
        backup_format=backup_format,
        request_id=request_id(request_id_value),
        task_id=task_id(task_id_value),
        frontier=frontier,
        database_logical_name=_DATABASE_NAME,
        database_size=database_size,
        database_digest=database_digest,
        objects=objects,
        object_set_digest=object_set_digest,
        version_manifest=version_manifest,
        mode=mode,
        key_fingerprint=key_fingerprint,
        key_locator_classification=key_locator_classification,
        recovery_artifact_logical_name=_RECOVERY_NAME if portable else None,
        recovery_artifact_digest=recovery_artifact_digest,
        recovery_kdf_policy=recovery_kdf_policy,
        privacy_audit_snapshot_logical_name=_PRIVACY_SNAPSHOT_NAME,
        privacy_audit_snapshot_size=privacy_audit_snapshot_size,
        privacy_audit_snapshot_digest=privacy_audit_snapshot_digest,
        privacy_root_generation=privacy_root_generation,
        privacy_root_digest=privacy_root_digest,
        audit_store_version=audit_store_version,
        privacy_audit_row_count=privacy_audit_row_count,
        privacy_audit_object_count=privacy_audit_object_count,
        created_at=created_at,
        completed_at=completed_at,
        manifest_digest="sha256:" + "0" * 64,
    )
    return BackupManifest(
        **{
            field: getattr(draft, field)
            for field in draft.__dataclass_fields__
            if field != "manifest_digest"
        },
        manifest_digest=canonical_digest(_manifest_value(draft, include_self_digest=False)),
    )


def _safe_regular(path: Path, *, max_bytes: int | None = None) -> os.stat_result:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {}) from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISREG(facts.st_mode)
        or facts.st_nlink != 1
        or stat.S_IMODE(facts.st_mode) & 0o077
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        or (max_bytes is not None and facts.st_size > max_bytes)
    ):
        raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
    return facts


def _safe_directory(path: Path) -> os.stat_result:
    if not path.is_absolute():
        raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
    try:
        facts = path.lstat()
    except OSError as exc:
        raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {}) from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or stat.S_IMODE(facts.st_mode) & 0o077
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
    ):
        raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
    return facts


def _read_bounded(path: Path, cap: int) -> bytes:
    facts = _safe_regular(path, max_bytes=cap)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            facts.st_dev,
            facts.st_ino,
            facts.st_size,
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        chunks: list[bytes] = []
        remaining = cap + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) > cap or len(data) != facts.st_size:
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        return data
    finally:
        os.close(descriptor)


def _sha256_file(path: Path, expected_size: int | None = None) -> str:
    facts = _safe_regular(path)
    if expected_size is not None and facts.st_size != expected_size:
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    digest = hashlib.sha256()
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        while True:
            chunk = os.read(descriptor, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (facts.st_dev, facts.st_ino, facts.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def _mapping(value: object) -> Mapping[str, object]:
    if type(value) is not dict:
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {})
    raw = cast(dict[object, object], value)
    if any(type(key) is not str for key in raw):
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {})
    return cast(dict[str, object], raw)


def _manifest_from_bytes(data: bytes) -> BackupManifest:
    try:
        parsed = strict_json_parse(data)
        value = _mapping(parsed)
        expected = set(BackupManifest.__dataclass_fields__)
        if set(value) != expected:
            raise ValueError("manifest_fields_invalid")
        frontier_value = _mapping(value["frontier"])
        sequence = frontier_value["sequence"]
        if type(sequence) is not str or not sequence.isdecimal():
            raise ValueError("manifest_frontier_invalid")
        objects_value = value["objects"]
        if type(objects_value) is not list:
            raise ValueError("manifest_objects_invalid")
        object_rows = cast(list[object], objects_value)
        entries: list[BackupObjectEntry] = []
        for raw_entry in object_rows:
            entry = _mapping(raw_entry)
            if set(entry) != {"object_id", "kind", "envelope_digest", "envelope_size"}:
                raise ValueError("manifest_object_invalid")
            entries.append(
                BackupObjectEntry(
                    object_id=cast(str, entry["object_id"]),
                    kind=ObjectKind(cast(str, entry["kind"])),
                    envelope_digest=cast(str, entry["envelope_digest"]),
                    envelope_size=cast(int, entry["envelope_size"]),
                )
            )
        manifest = BackupManifest(
            manifest_schema=cast("Literal['yoetz.backup-manifest/1']", value["manifest_schema"]),
            backup_format=cast(str, value["backup_format"]),
            request_id=request_id(cast(str, value["request_id"])),
            task_id=task_id(cast(str, value["task_id"])),
            frontier=Frontier(int(sequence, 10), cast(str, frontier_value["head_digest"])),
            database_logical_name=cast(str, value["database_logical_name"]),
            database_size=cast(int, value["database_size"]),
            database_digest=cast(str, value["database_digest"]),
            objects=tuple(entries),
            object_set_digest=cast(str, value["object_set_digest"]),
            version_manifest=JsonObject(value["version_manifest"]),
            mode=BackupMode(cast(str, value["mode"])),
            key_fingerprint=cast(str, value["key_fingerprint"]),
            key_locator_classification=cast(str, value["key_locator_classification"]),
            recovery_artifact_logical_name=cast(
                str | None, value["recovery_artifact_logical_name"]
            ),
            recovery_artifact_digest=cast(str | None, value["recovery_artifact_digest"]),
            recovery_kdf_policy=(
                None
                if value["recovery_kdf_policy"] is None
                else JsonObject(value["recovery_kdf_policy"])
            ),
            privacy_audit_snapshot_logical_name=cast(
                "Literal['privacy-audit-snapshot.json']",
                value["privacy_audit_snapshot_logical_name"],
            ),
            privacy_audit_snapshot_size=cast(int, value["privacy_audit_snapshot_size"]),
            privacy_audit_snapshot_digest=cast(str, value["privacy_audit_snapshot_digest"]),
            privacy_root_generation=cast(int, value["privacy_root_generation"]),
            privacy_root_digest=cast(str, value["privacy_root_digest"]),
            audit_store_version=cast(str, value["audit_store_version"]),
            privacy_audit_row_count=cast(int, value["privacy_audit_row_count"]),
            privacy_audit_object_count=cast(int, value["privacy_audit_object_count"]),
            created_at=Timestamp(cast(str, value["created_at"])),
            completed_at=Timestamp(cast(str, value["completed_at"])),
            manifest_digest=cast(str, value["manifest_digest"]),
        )
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {}) from exc
    if canonical_encode(parsed) != data:
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {})
    if manifest.manifest_digest != canonical_digest(
        _manifest_value(manifest, include_self_digest=False)
    ):
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    expected_object_set = canonical_digest(
        tuple(_object_entry_value(entry) for entry in manifest.objects)
    )
    if manifest.object_set_digest != expected_object_set:
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    return manifest


def _object_member_path(root: Path, object_id_value: str) -> Path:
    validate_id(IdKind.OBJECT, object_id_value)
    # Backup members are structural IDs, never user filenames.  A flat objects/
    # directory is the portable backup format; live bundle sharding is unrelated.
    objects_dir = root / "objects"
    _safe_directory(objects_dir)
    return objects_dir / object_id_value


def _sha256_object_member(root: Path, object_id_value: str, expected_size: int) -> str:
    """Hash one object through an opened, verified objects directory.

    Checking ``objects/<id>`` with a path alone leaves an intermediate ``objects`` symlink
    race.  Open the directory with ``O_NOFOLLOW`` and the member relative to that descriptor;
    the descriptor remains bound to the verified directory for the whole read.
    """

    validate_id(IdKind.OBJECT, object_id_value)
    if type(expected_size) is not int or expected_size < 0:
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    objects_dir = root / "objects"
    directory_facts = _safe_directory(objects_dir)
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    directory_fd: int | None = None
    member_fd: int | None = None
    try:
        try:
            directory_fd = os.open(objects_dir, flags)
            opened_directory = os.fstat(directory_fd)
        except OSError as exc:
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {}) from exc
        if (opened_directory.st_dev, opened_directory.st_ino, opened_directory.st_mode) != (
            directory_facts.st_dev,
            directory_facts.st_ino,
            directory_facts.st_mode,
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        try:
            member_facts = os.stat(
                object_id_value,
                dir_fd=directory_fd,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {}) from exc
        if (
            not stat.S_ISREG(member_facts.st_mode)
            or member_facts.st_nlink != 1
            or stat.S_IMODE(member_facts.st_mode) & 0o077
            or (hasattr(os, "geteuid") and member_facts.st_uid != os.geteuid())
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        if member_facts.st_size != expected_size:
            raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
        member_flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            member_flags |= os.O_NOFOLLOW
        try:
            member_fd = os.open(object_id_value, member_flags, dir_fd=directory_fd)
            opened_member = os.fstat(member_fd)
        except OSError as exc:
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {}) from exc
        if (opened_member.st_dev, opened_member.st_ino, opened_member.st_size) != (
            member_facts.st_dev,
            member_facts.st_ino,
            member_facts.st_size,
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        digest = hashlib.sha256()
        while True:
            chunk = os.read(member_fd, _COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(member_fd)
        if (after.st_dev, after.st_ino, after.st_size) != (
            member_facts.st_dev,
            member_facts.st_ino,
            member_facts.st_size,
        ):
            raise MaintenanceError(MaintenanceReason.SOURCE_INVALID, False, {})
        return "sha256:" + digest.hexdigest()
    finally:
        if member_fd is not None:
            os.close(member_fd)
        if directory_fd is not None:
            os.close(directory_fd)


def _verify_database_snapshot(path: Path, manifest: BackupManifest) -> None:
    database: apsw.Connection | None = None
    try:
        database = apsw.Connection(str(path), flags=apsw.SQLITE_OPEN_READONLY)
        database.pragma("query_only", 1)
        database.pragma("trusted_schema", 0)
        if database.pragma("application_id") != _FINISHUP_APPLICATION_ID:
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        version = database.pragma("user_version")
        if type(version) is not int or not 1 <= version <= _CURRENT_BUNDLE_SCHEMA_VERSION:
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        if database.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        if database.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        tables = {
            cast(str, row[0])
            for row in database.execute(
                "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
            )
        }
        if "bundle_meta" not in tables or "events" not in tables:
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        task_row = database.execute(
            "SELECT value FROM bundle_meta WHERE key = 'task_id'"
        ).fetchone()
        if task_row != (str(manifest.task_id),):
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
        event_tail = database.execute(
            "SELECT ingestion_seq, entry_digest FROM events ORDER BY ingestion_seq DESC LIMIT 1"
        ).fetchone()
        expected_tail: tuple[object, object] | None = (
            None
            if manifest.frontier.sequence == 0
            else (manifest.frontier.sequence, manifest.frontier.head_digest)
        )
        if event_tail != expected_tail:
            raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {})
    except MaintenanceError:
        raise
    except Exception as exc:
        raise MaintenanceError(MaintenanceReason.DATABASE_INVALID, False, {}) from exc
    finally:
        if database is not None:
            database.close(force=True)


def _verify_privacy_snapshot(data: bytes, manifest: BackupManifest) -> None:
    try:
        parsed = strict_json_parse(data)
        if canonical_encode(parsed) != data:
            raise ValueError("privacy_snapshot_not_canonical")
        value = _mapping(parsed)
        if set(value) != {
            "origin_installation_id",
            "origin_task_id",
            "catalog_version",
            "audit_store_version",
            "privacy_root_generation",
            "privacy_root_digest",
            "audit_rows",
            "terminal_receipts",
            "privacy_audit_objects",
        }:
            raise ValueError("privacy_snapshot_fields_invalid")
        rows = value["audit_rows"]
        receipts = value["terminal_receipts"]
        objects = value["privacy_audit_objects"]
        if type(rows) is not list or type(receipts) is not list or type(objects) is not list:
            raise ValueError("privacy_snapshot_rows_invalid")
        object_rows = cast(list[object], objects)
        object_ids: list[str] = []
        for raw in object_rows:
            row = _mapping(raw)
            if set(row) != {"object_id"}:
                raise ValueError("privacy_snapshot_object_shape_invalid")
            object_id_value = row.get("object_id")
            if type(object_id_value) is not str:
                raise ValueError("privacy_snapshot_object_invalid")
            validate_id(IdKind.OBJECT, object_id_value)
            object_ids.append(object_id_value)
        if object_ids != sorted(object_ids, key=lambda item: item.encode()) or len(
            set(object_ids)
        ) != len(object_ids):
            raise ValueError("privacy_snapshot_objects_invalid")
        if (
            value["origin_task_id"] != str(manifest.task_id)
            or value["audit_store_version"] != manifest.audit_store_version
            or value["privacy_root_generation"] != manifest.privacy_root_generation
            or value["privacy_root_digest"] != manifest.privacy_root_digest
            or len(cast(list[object], rows)) + len(cast(list[object], receipts))
            != manifest.privacy_audit_row_count
            or len(object_ids) != manifest.privacy_audit_object_count
            or object_ids
            != [
                entry.object_id
                for entry in manifest.objects
                if entry.kind is ObjectKind.PRIVACY_AUDIT
            ]
        ):
            raise ValueError("privacy_snapshot_binding_invalid")
    except Exception as exc:
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {}) from exc


def verify_backup_set(
    source: Path,
    expected_task_id: str | None = None,
) -> VerifiedBackupSet:
    """Read and verify one complete immutable backup set without mutation."""

    _safe_directory(source)
    manifest_bytes = _read_bounded(source / _MANIFEST_NAME, _MAX_MANIFEST_BYTES)
    manifest = _manifest_from_bytes(manifest_bytes)
    if expected_task_id is not None and manifest.task_id != task_id(expected_task_id):
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {})

    database_path = source / manifest.database_logical_name
    if _sha256_file(database_path, manifest.database_size) != manifest.database_digest:
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    if (source / f"{manifest.database_logical_name}-wal").exists() or (
        source / f"{manifest.database_logical_name}-shm"
    ).exists():
        raise MaintenanceError(MaintenanceReason.MANIFEST_INVALID, False, {})
    _verify_database_snapshot(database_path, manifest)

    privacy_path = source / manifest.privacy_audit_snapshot_logical_name
    privacy_bytes = _read_bounded(privacy_path, _MAX_SIDECAR_BYTES)
    if (
        len(privacy_bytes) != manifest.privacy_audit_snapshot_size
        or "sha256:" + hashlib.sha256(privacy_bytes).hexdigest()
        != manifest.privacy_audit_snapshot_digest
    ):
        raise MaintenanceError(MaintenanceReason.MANIFEST_TAMPERED, False, {})
    _verify_privacy_snapshot(privacy_bytes, manifest)

    object_paths: list[Path] = []
    set_members: list[JsonObject] = []
    for entry in manifest.objects:
        path = _object_member_path(source, entry.object_id)
        try:
            actual_object_digest = _sha256_object_member(
                source, entry.object_id, entry.envelope_size
            )
        except MaintenanceError as exc:
            if exc.reason is MaintenanceReason.MANIFEST_TAMPERED:
                raise MaintenanceError(MaintenanceReason.OBJECT_TAMPERED, False, {}) from exc
            raise
        if actual_object_digest != entry.envelope_digest:
            raise MaintenanceError(MaintenanceReason.OBJECT_TAMPERED, False, {})
        object_paths.append(path)
        set_members.append(
            JsonObject(
                {
                    "logical_name": f"objects/{entry.object_id}",
                    "size": entry.envelope_size,
                    "digest": entry.envelope_digest,
                }
            )
        )

    recovery_path: Path | None = None
    if manifest.mode is BackupMode.PORTABLE_RECOVERY:
        recovery_name = manifest.recovery_artifact_logical_name
        recovery_digest = manifest.recovery_artifact_digest
        if recovery_name is None or recovery_digest is None:
            raise MaintenanceError(MaintenanceReason.RECOVERY_ARTIFACT_INVALID, False, {})
        recovery_path = source / recovery_name
        if _sha256_file(recovery_path) != recovery_digest:
            raise MaintenanceError(MaintenanceReason.RECOVERY_ARTIFACT_INVALID, False, {})

    backup_set_digest = canonical_digest(
        JsonObject(
            {
                "manifest_digest": manifest.manifest_digest,
                "database_digest": manifest.database_digest,
                "privacy_audit_snapshot_digest": manifest.privacy_audit_snapshot_digest,
                "objects": tuple(set_members),
                "recovery_artifact_digest": manifest.recovery_artifact_digest,
            }
        )
    )
    return VerifiedBackupSet(
        root=source,
        manifest=manifest,
        database_path=database_path,
        privacy_snapshot_path=privacy_path,
        object_paths=tuple(object_paths),
        recovery_artifact_path=recovery_path,
        backup_set_digest=backup_set_digest,
    )


class SqliteMaintenance:
    """MaintenancePort implementation with catalog/bundle CAS owned here."""

    def __init__(
        self,
        catalog: apsw.Connection,
        bundle: apsw.Connection,
        *,
        installation_id: str,
        clock: ClockPort,
        ids: IdPort,
        procedures: _MaintenanceProcedures,
        lease_seconds: int = 60,
        pin_seconds: int = 3600,
    ) -> None:
        self._catalog = catalog
        self._bundle = bundle
        self._installation_id = validate_id(IdKind.INSTALLATION, installation_id)
        self._clock = clock
        self._ids = ids
        self._procedures = procedures
        self._lease_owner_id = ids.new(IdKind.SERVICE_INSTANCE)
        validate_id(IdKind.SERVICE_INSTANCE, self._lease_owner_id)
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 3600:
            raise ValueError("maintenance_lease_invalid")
        if type(pin_seconds) is not int or not 1 <= pin_seconds <= 86_400:
            raise ValueError("maintenance_pin_expiry_invalid")
        self._lease_seconds = lease_seconds
        self._pin_seconds = pin_seconds

    async def preview_backup(self, command: BackupCommand) -> BackupPlan:
        return await self._procedures.preview_backup(command)

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan:
        return await self._procedures.preview_restore(command)

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan:
        return await self._procedures.preview_migration(command)

    async def backup(
        self,
        command: BackupCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> BackupResult:
        plan = await self.preview_backup(command)
        acquired = await self._acquire_maintenance(command, plan, confirmed_plan_digest)
        if type(acquired) is BackupResult:
            return acquired
        if type(acquired) is not MaintenanceHandle:
            raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {})
        handle = acquired
        pin = await self.create_frontier_pin(
            handle,
            plan.frontier,
            Timestamp(format_rfc3339_millis(self._now() + timedelta(seconds=self._pin_seconds))),
        )
        result = await self._procedures.backup(handle, pin, command, plan, recovery_secret)
        self._complete(handle, result)
        await self.release_frontier_pin(handle, pin)
        return result

    async def restore(
        self,
        command: RestoreCommand,
        *,
        confirmed_plan_digest: str,
        recovery_secret: RecoverySecret | None,
    ) -> RestoreResult:
        plan = await self.preview_restore(command)
        acquired = await self._acquire_maintenance(command, plan, confirmed_plan_digest)
        if type(acquired) is RestoreResult:
            return acquired
        if type(acquired) is not MaintenanceHandle:
            raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {})
        handle = acquired
        target = await self._procedures.restore(handle, command, plan, recovery_secret)
        if not target.privacy_reconciled:
            raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
        await self._switch_restored_route(handle, target)
        self._complete(handle, target.result)
        return target.result

    async def migrate(
        self,
        command: MigrationCommand,
        confirmed_plan_digest: str,
    ) -> MigrationResult:
        plan = await self.preview_migration(command)
        acquired = await self._acquire_maintenance(command, plan, confirmed_plan_digest)
        if type(acquired) is MigrationResult:
            return acquired
        if type(acquired) is not MaintenanceHandle:
            raise MaintenanceError(MaintenanceReason.MIGRATION_FAILED, False, {})
        handle = acquired
        result = await self._procedures.migrate(handle, command, plan)
        self._complete(handle, result)
        return result

    async def _acquire_maintenance(
        self,
        command: BackupCommand | RestoreCommand | MigrationCommand,
        plan: BackupPlan | RestorePlan | MigrationPlan,
        confirmed_plan_digest: str,
    ) -> MaintenanceHandle | BackupResult | RestoreResult | MigrationResult:
        validate_sha256_digest(confirmed_plan_digest)
        if confirmed_plan_digest != plan.plan_digest:
            raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
        facts = await self._procedures.authority_facts(command, plan)
        if plan.task_id != facts.task_id:
            raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
        kind = _kind_for(command, plan)
        now = self._now()
        now_wire = format_rfc3339_millis(now)
        expires_wire = format_rfc3339_millis(now + timedelta(seconds=self._lease_seconds))
        operation_id = str(command.request_id)
        owner_generation = self._catalog_owner_generation()
        if owner_generation != facts.owner_generation:
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, True, {})
        self._require_current_route(facts)

        self._catalog.execute("BEGIN IMMEDIATE")
        try:
            existing = self._catalog.execute(
                "SELECT request_digest, plan_digest, state, owner_generation, "
                "lease_owner_id, lease_generation, source_route_identity_digest, "
                "subject_frontier_seq, subject_frontier_digest, privacy_root_generation, "
                "privacy_root_digest, quarantine_code, backup_manifest_digest "
                ", result_canonical, result_digest, lease_expires_at, phase, "
                "target_route_identity_digest "
                "FROM maintenance_operations "
                "WHERE installation_id = ? AND operation_id = ?",
                (self._installation_id, operation_id),
            ).fetchone()
            lease_generation = 1
            if existing is not None:
                if existing[0] != plan.request_digest or existing[1] != plan.plan_digest:
                    raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
                if existing[2] == _OperationState.QUARANTINED.value:
                    reason = (
                        MaintenanceReason.ROLLBACK_REQUIRED
                        if existing[11] == "rollback_required"
                        else MaintenanceReason.MIGRATION_FAILED
                    )
                    details: dict[str, JsonValue] = {}
                    if type(existing[12]) is str:
                        details["backup_manifest_digest"] = existing[12]
                    raise MaintenanceError(reason, False, details)
                if existing[2] == _OperationState.COMPLETE.value:
                    raw_result = existing[13]
                    stored_digest = existing[14]
                    if type(raw_result) is not bytes or type(stored_digest) is not str:
                        raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {})
                    replayed = _result_from_bytes(raw_result)
                    if canonical_digest(_result_value(replayed)) != stored_digest:
                        raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {})
                    self._catalog.execute("ROLLBACK")
                    return replayed
                if existing[2] != _OperationState.PENDING.value:
                    raise MaintenanceError(MaintenanceReason.MAINTENANCE_BUSY, False, {})
                route_switched_replay = (
                    kind is MaintenanceKind.RESTORE and existing[16] == "route_switched"
                )
                if route_switched_replay:
                    current_route = self._catalog.execute(
                        "SELECT active_route_identity_digest, state FROM task_routes "
                        "WHERE task_id = ?",
                        (facts.task_id,),
                    ).fetchone()
                    if (
                        current_route != (existing[17], "active")
                        or facts.source_route_identity_digest != existing[17]
                    ):
                        raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
                elif (
                    existing[6] != facts.source_route_identity_digest
                    or existing[7] != facts.frontier.sequence
                    or existing[8] != facts.frontier.head_digest
                    or existing[9] != facts.privacy_roots.privacy_root_generation
                    or existing[10] != facts.privacy_roots.root_set_digest
                ):
                    raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
                lease_expires_at = existing[15]
                if type(lease_expires_at) is not str:
                    raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {})
                try:
                    lease_expiry = parse_rfc3339_millis(lease_expires_at)
                except (TypeError, ValueError) as exc:
                    raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {}) from exc
                if lease_expiry > now:
                    raise MaintenanceError(MaintenanceReason.MAINTENANCE_BUSY, True, {})
                current_lease = cast(int, existing[5])
                lease_generation = current_lease + 1
                self._catalog.execute(
                    "UPDATE maintenance_operations SET owner_generation = ?, lease_owner_id = ?, "
                    "lease_generation = ?, lease_expires_at = ?, updated_at = ? "
                    "WHERE installation_id = ? AND operation_id = ? AND state = 'pending' "
                    "AND owner_generation IS ? AND lease_owner_id IS ? AND lease_generation = ?",
                    (
                        str(owner_generation),
                        self._lease_owner_id,
                        lease_generation,
                        expires_wire,
                        now_wire,
                        self._installation_id,
                        operation_id,
                        existing[3],
                        existing[4],
                        current_lease,
                    ),
                )
                if self._catalog.changes() != 1:
                    raise MaintenanceError(MaintenanceReason.MAINTENANCE_BUSY, True, {})
            else:
                self._catalog.execute(
                    "INSERT INTO maintenance_operations("
                    "installation_id, operation_id, task_id, kind, request_digest, plan_digest, "
                    "state, phase, subject_frontier_seq, subject_frontier_digest, "
                    "privacy_root_generation, privacy_root_digest, source_route_identity_digest, "
                    "target_route_identity_digest, source_location_commitment, "
                    "target_location_commitment, backup_mode, requested_target_version, "
                    "owner_generation, lease_owner_id, lease_generation, lease_expires_at, "
                    "created_at, updated_at) VALUES(?, ?, ?, ?, ?, ?, 'pending', 'reserved', "
                    "?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)",
                    (
                        self._installation_id,
                        operation_id,
                        facts.task_id,
                        kind.value,
                        plan.request_digest,
                        plan.plan_digest,
                        facts.frontier.sequence,
                        facts.frontier.head_digest,
                        facts.privacy_roots.privacy_root_generation,
                        facts.privacy_roots.root_set_digest,
                        facts.source_route_identity_digest,
                        facts.target_route_identity_digest,
                        facts.source_location_commitment,
                        facts.target_location_commitment,
                        facts.backup_mode.value,
                        facts.requested_target_version,
                        str(owner_generation),
                        self._lease_owner_id,
                        expires_wire,
                        now_wire,
                        now_wire,
                    ),
                )
            self._catalog.execute("COMMIT")
        except BaseException:
            self._catalog.execute("ROLLBACK")
            raise
        return MaintenanceHandle(
            task_id=task_id(facts.task_id),
            kind=kind,
            request_id=request_id(operation_id),
            route_identity_digest=facts.source_route_identity_digest,
            owner_generation=owner_generation,
            lease_generation=lease_generation,
            confirmed_plan_digest=plan.plan_digest,
        )

    async def create_frontier_pin(
        self,
        handle: MaintenanceHandle,
        frontier: Frontier,
        expires_at: Timestamp,
    ) -> MaintenancePin:
        self._require_handle(handle)
        roots = await self._procedures.current_privacy_roots(
            str(handle.task_id), handle.route_identity_digest
        )
        if (
            roots.task_id != handle.task_id
            or roots.route_identity_digest != handle.route_identity_digest
        ):
            raise MaintenanceError(MaintenanceReason.PLAN_STALE, False, {})
        pin_id = validate_id(IdKind.MAINTENANCE_PIN, self._new_pin_id())
        now_wire = format_rfc3339_millis(self._now())
        stored_expires_at = expires_at
        self._bundle.execute("BEGIN IMMEDIATE")
        try:
            self._require_bundle_generation(handle.owner_generation)
            existing = self._bundle.execute(
                "SELECT pin_id, task_id, kind, frontier_seq, frontier_digest, "
                "privacy_root_generation, privacy_root_digest, owner_generation, "
                "lease_generation, expires_at FROM maintenance_pins "
                "WHERE operation_id = ? AND state = 'active'",
                (str(handle.request_id),),
            ).fetchone()
            if existing is not None:
                expected = (
                    str(handle.task_id),
                    "backup",
                    frontier.sequence,
                    frontier.head_digest,
                    roots.privacy_root_generation,
                    roots.root_set_digest,
                    str(handle.owner_generation),
                )
                if existing[1:8] != expected:
                    raise _PinContradiction()
                pin_id = validate_id(IdKind.MAINTENANCE_PIN, cast(str, existing[0]))
                try:
                    existing_expiry = Timestamp(cast(str, existing[9]))
                    parsed_expiry = parse_rfc3339_millis(existing_expiry.wire)
                except Exception as exc:
                    raise _PinContradiction() from exc
                if parsed_expiry <= self._now():
                    raise _PinContradiction()
                stored_expires_at = existing_expiry
                self._bundle.execute(
                    "UPDATE maintenance_pins SET lease_generation = ? WHERE pin_id = ? "
                    "AND state = 'active' AND owner_generation = ? AND lease_generation = ?",
                    (
                        handle.lease_generation,
                        pin_id,
                        str(handle.owner_generation),
                        existing[8],
                    ),
                )
                if self._bundle.changes() != 1:
                    raise _PinContradiction()
            else:
                self._bundle.execute(
                    "INSERT INTO maintenance_pins("
                    "pin_id, task_id, operation_id, kind, frontier_seq, frontier_digest, "
                    "privacy_root_generation, privacy_root_digest, owner_generation, "
                    "lease_generation, expires_at, state, created_at) "
                    "VALUES(?, ?, ?, 'backup', ?, ?, ?, ?, ?, ?, ?, 'active', ?)",
                    (
                        pin_id,
                        str(handle.task_id),
                        str(handle.request_id),
                        frontier.sequence,
                        frontier.head_digest,
                        roots.privacy_root_generation,
                        roots.root_set_digest,
                        str(handle.owner_generation),
                        handle.lease_generation,
                        expires_at.wire,
                        now_wire,
                    ),
                )
            self._bundle.execute("COMMIT")
        except _PinContradiction:
            self._bundle.execute("ROLLBACK")
            self._quarantine(handle, "pin_identity_contradiction")
            raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {}) from None
        except BaseException:
            self._bundle.execute("ROLLBACK")
            raise
        self.advance_phase(handle, ("reserved", "pinned"), "pinned")
        return MaintenancePin(
            pin_id=pin_id,
            task_id=handle.task_id,
            frontier=frontier,
            owner_generation=handle.owner_generation,
            privacy_root_generation=roots.privacy_root_generation,
            privacy_root_digest=roots.root_set_digest,
            expires_at=stored_expires_at,
        )

    async def release_frontier_pin(self, handle: MaintenanceHandle, pin: MaintenancePin) -> None:
        if pin.task_id != handle.task_id or pin.owner_generation != handle.owner_generation:
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
        self._bundle.execute("BEGIN IMMEDIATE")
        try:
            self._require_bundle_generation(handle.owner_generation)
            self._bundle.execute(
                "UPDATE maintenance_pins SET state = 'released', released_at = ? "
                "WHERE pin_id = ? AND operation_id = ? AND state = 'active' "
                "AND owner_generation = ? AND lease_generation = ?",
                (
                    format_rfc3339_millis(self._now()),
                    pin.pin_id,
                    str(handle.request_id),
                    str(handle.owner_generation),
                    handle.lease_generation,
                ),
            )
            if self._bundle.changes() not in (0, 1):
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            self._bundle.execute("COMMIT")
        except BaseException:
            self._bundle.execute("ROLLBACK")
            raise

    def advance_phase(
        self,
        handle: MaintenanceHandle,
        expected_phases: tuple[str, ...],
        next_phase: str,
        *,
        backup_manifest_digest: str | None = None,
        target_route_identity_digest: str | None = None,
    ) -> None:
        """Advance one durable maintenance lower bound through the current lease CAS."""

        legal = {
            MaintenanceKind.BACKUP: (
                "reserved",
                "pinned",
                "database_ready",
                "objects_ready",
                "manifest_ready",
            ),
            MaintenanceKind.RESTORE: (
                "reserved",
                "source_verified",
                "target_ready",
                "target_verified",
                "route_switched",
            ),
            MaintenanceKind.MIGRATION: (
                "reserved",
                "backup_ready",
                "schema_applied",
                "replay_verified",
            ),
        }[handle.kind]
        if (
            type(expected_phases) is not tuple
            or not expected_phases
            or any(phase not in legal for phase in expected_phases)
            or next_phase not in legal
            or legal.index(next_phase) < max(legal.index(phase) for phase in expected_phases)
        ):
            raise ValueError("maintenance_phase_transition_invalid")
        if backup_manifest_digest is not None:
            validate_sha256_digest(backup_manifest_digest)
        if target_route_identity_digest is not None:
            validate_sha256_digest(target_route_identity_digest)
        self._catalog.execute("BEGIN IMMEDIATE")
        try:
            self._require_handle(handle)
            placeholders = ", ".join("?" for _ in expected_phases)
            bindings: tuple[apsw.Binding, ...] = (
                next_phase,
                backup_manifest_digest,
                target_route_identity_digest,
                format_rfc3339_millis(self._now()),
                self._installation_id,
                str(handle.request_id),
                str(handle.owner_generation),
                self._lease_owner_id,
                handle.lease_generation,
                *expected_phases,
            )
            self._catalog.execute(
                "UPDATE maintenance_operations SET phase = ?, "
                "backup_manifest_digest = COALESCE(?, backup_manifest_digest), "
                "target_route_identity_digest = COALESCE(?, target_route_identity_digest), "
                "updated_at = ? WHERE installation_id = ? AND operation_id = ? "
                "AND state = 'pending' AND owner_generation = ? AND lease_owner_id = ? "
                f"AND lease_generation = ? AND phase IN ({placeholders})",
                bindings,
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            self._catalog.execute("COMMIT")
        except BaseException:
            self._catalog.execute("ROLLBACK")
            raise

    @staticmethod
    def _project_text_ref(value: object) -> ProjectTextRef:
        """Decode a catalog pointer while keeping the encrypted object outside this boundary."""

        if type(value) is bytes:
            encoded = value
        elif type(value) is str:
            encoded = value.encode("utf-8")
        else:
            raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
        try:
            parsed = strict_json_parse(encoded)
            if not isinstance(parsed, Mapping) or canonical_encode(parsed) != encoded:
                raise ValueError("project_text_ref_noncanonical")
            required = {
                "object_id",
                "content_digest",
                "plaintext_size",
                "owner_task_id",
                "route_generation",
            }
            keys = set(parsed)
            if keys not in (required, required | {"envelope_digest"}):
                raise ValueError("project_text_ref_shape_invalid")
            route_generation = parsed["route_generation"]
            if type(route_generation) is not str:
                raise ValueError("project_text_ref_generation_invalid")
            generation = int(route_generation, 10)
            if str(generation) != route_generation:
                raise ValueError("project_text_ref_generation_invalid")
            reference = ProjectTextRef(
                object_id=cast(str, parsed["object_id"]),
                content_digest=cast(str, parsed["content_digest"]),
                plaintext_size=cast(int, parsed["plaintext_size"]),
                owner_task_id=cast(str, parsed["owner_task_id"]),
                route_generation=generation,
                envelope_digest=cast(str | None, parsed.get("envelope_digest")),
            )
        except (KeyError, TypeError, ValueError, OverflowError) as exc:
            raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {}) from exc
        # A pre-C6 reference without the envelope digest cannot be proven against the restored
        # object set.  Keeping it would allow a route switch to orphan plaintext under an
        # uncheckable pointer, so restore rejects the legacy form explicitly.
        if reference.envelope_digest is None:
            raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
        return reference

    @staticmethod
    def _project_text_ref_wire(reference: ProjectTextRef, original: object) -> bytes | str:
        encoded = canonical_encode(reference.as_wire())
        if type(original) is bytes:
            return encoded
        if type(original) is str:
            try:
                return encoded.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {}) from exc
        raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})

    def _catalog_table_exists_locked(self, name: str) -> bool:
        row = self._catalog.execute(
            "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ? LIMIT 1", (name,)
        ).fetchone()
        return row == (1,)

    def _validate_project_text_owner_locked(self, reference: ProjectTextRef) -> None:
        generations = {
            row[0]
            for row in self._catalog.execute(
                "SELECT route_generation FROM task_routes WHERE task_id = ? "
                "UNION ALL SELECT route_generation FROM retained_task_routes "
                "WHERE installation_id = ? AND task_id = ? AND state IN ('retained', 'quarantined')",
                (reference.owner_task_id, self._installation_id, reference.owner_task_id),
            ).fetchall()
            if len(row) == 1 and type(row[0]) is int
        }
        if reference.route_generation not in generations:
            raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})

    def _rebase_project_text_refs_locked(
        self, task_id_value: str, old_generation: int, new_generation: int
    ) -> None:
        """Validate every catalog pointer and rebase only the replaced route's current refs.

        The encrypted object bytes remain in their owning bundle.  Rebase changes only the
        structural route-generation field, and only when the pointer followed the active route
        being replaced.  Pointers to another task or to an explicitly retained generation stay
        untouched but are still checked for a live retention root.
        """

        if not self._catalog_table_exists_locked("projects"):
            return
        project_rows = self._catalog.execute(
            "SELECT project_id, title_ref_canonical, description_ref_canonical FROM projects"
        ).fetchall()
        for row in project_rows:
            if len(row) != 3 or type(row[0]) is not str:
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
            project_id_value = row[0]
            for column, encoded in (
                ("title_ref_canonical", row[1]),
                ("description_ref_canonical", row[2]),
            ):
                if encoded is None:
                    continue
                reference = self._project_text_ref(encoded)
                self._validate_project_text_owner_locked(reference)
                if (
                    reference.owner_task_id == task_id_value
                    and reference.route_generation == old_generation
                ):
                    rebased = replace(reference, route_generation=new_generation)
                    self._catalog.execute(
                        f"UPDATE projects SET {column} = ? WHERE project_id = ? AND {column} IS ?",
                        (
                            self._project_text_ref_wire(rebased, encoded),
                            project_id_value,
                            encoded,
                        ),
                    )
                    if self._catalog.changes() != 1:
                        raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})

        if not self._catalog_table_exists_locked("coordination_detections"):
            return
        detail_rows = self._catalog.execute(
            "SELECT detection_id, detail_ref_json FROM coordination_detections "
            "WHERE detail_ref_json IS NOT NULL"
        ).fetchall()
        for row in detail_rows:
            if len(row) != 2 or type(row[0]) is not str:
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
            encoded = row[1]
            reference = self._project_text_ref(encoded)
            self._validate_project_text_owner_locked(reference)
            if (
                reference.owner_task_id == task_id_value
                and reference.route_generation == old_generation
            ):
                rebased = replace(reference, route_generation=new_generation)
                self._catalog.execute(
                    "UPDATE coordination_detections SET detail_ref_json = ? "
                    "WHERE detection_id = ? AND detail_ref_json IS ?",
                    (self._project_text_ref_wire(rebased, encoded), row[0], encoded),
                )
                if self._catalog.changes() != 1:
                    raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})

    async def _switch_restored_route(
        self, handle: MaintenanceHandle, target: _RestoredTarget
    ) -> None:
        """Retain the old route and switch to one verified target in one catalog CAS."""

        if handle.kind is not MaintenanceKind.RESTORE:
            raise TypeError("maintenance_restore_handle_required")
        self._require_handle(handle)
        now_wire = format_rfc3339_millis(self._now())
        self._catalog.execute("BEGIN IMMEDIATE")
        try:
            self._require_handle(handle)
            route = self._catalog.execute(
                "SELECT active_session_id, bundle_relpath, route_generation, "
                "active_route_identity_digest, state FROM task_routes WHERE task_id = ?",
                (str(handle.task_id),),
            ).fetchone()
            if (
                route is None
                or route[3] != handle.route_identity_digest
                or route[4] != "active"
                or type(route[2]) is not int
            ):
                raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})
            operation = self._catalog.execute(
                "SELECT subject_frontier_seq, subject_frontier_digest, phase, "
                "target_route_identity_digest, backup_manifest_digest, "
                "privacy_root_generation, privacy_root_digest "
                "FROM maintenance_operations WHERE installation_id = ? AND operation_id = ? "
                "AND state = 'pending' AND phase IN ('reserved', 'source_verified', "
                "'target_ready', 'target_verified', 'route_switched')",
                (self._installation_id, str(handle.request_id)),
            ).fetchone()
            if operation is None:
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            if operation[2] == "route_switched":
                # The route switch is committed before the terminal result.  A retry must
                # re-prove the target privacy authority instead of treating the route and
                # retained-row shape as sufficient evidence.  The live roots provider binds
                # the digest to the current audit object set; the catalog row and object-bearing
                # audit rows then prove that authority was persisted on the target route.
                roots = await self._procedures.current_privacy_roots(
                    str(handle.task_id), handle.route_identity_digest
                )
                root_row = self._catalog.execute(
                    "SELECT route_identity_digest, root_generation, root_count, root_digest "
                    "FROM privacy_root_sets WHERE task_id = ?",
                    (str(handle.task_id),),
                ).fetchone()
                if root_row != (
                    handle.route_identity_digest,
                    roots.privacy_root_generation,
                    len(roots.object_refs),
                    roots.root_set_digest,
                ) or (
                    roots.privacy_root_generation != operation[5]
                    or roots.root_set_digest != operation[6]
                ):
                    raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
                audit_route_mismatch = self._catalog.execute(
                    "SELECT 1 FROM privacy_audit_records "
                    "WHERE task_id = ? AND content_object_id IS NOT NULL "
                    "AND (route_identity_digest IS NULL OR route_identity_digest <> ?) LIMIT 1",
                    (str(handle.task_id), handle.route_identity_digest),
                ).fetchone()
                if audit_route_mismatch is not None:
                    raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
                retained = self._catalog.execute(
                    "SELECT bundle_relpath, route_identity_digest, route_generation "
                    "FROM retained_task_routes WHERE installation_id = ? AND task_id = ? "
                    "AND retained_by_operation_id = ? AND state = 'retained'",
                    (
                        self._installation_id,
                        str(handle.task_id),
                        str(handle.request_id),
                    ),
                ).fetchone()
                if (
                    route[1] != target.bundle_relpath
                    or route[3] != operation[3]
                    or target.evidence.task_id != str(handle.task_id)
                    or target.evidence.owner_generation != handle.owner_generation
                    or target.evidence.route_identity_digest != route[3]
                    or target.result.active_route_identity_digest != route[3]
                    or target.result.prior_route_identity_digest is None
                    or retained is None
                    or retained[0] != f"tasks/{handle.task_id}"
                    or retained[1] != target.result.prior_route_identity_digest
                    or type(retained[2]) is not int
                    or retained[2] + 1 != route[2]
                    or target.result.backup_manifest_digest != operation[4]
                ):
                    raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
                self._catalog.execute("COMMIT")
                return
            roots = await self._procedures.current_privacy_roots(
                str(handle.task_id), handle.route_identity_digest
            )
            root_row = self._catalog.execute(
                "SELECT route_identity_digest, root_generation, root_digest "
                "FROM privacy_root_sets WHERE task_id = ?",
                (str(handle.task_id),),
            ).fetchone()
            if root_row != (
                handle.route_identity_digest,
                roots.privacy_root_generation,
                roots.root_set_digest,
            ):
                raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})
            old_generation = cast(int, route[2])
            if (
                target.evidence.task_id != str(handle.task_id)
                or target.evidence.owner_generation != handle.owner_generation
                or target.result.prior_route_identity_digest != handle.route_identity_digest
                or target.evidence.route_identity_digest == handle.route_identity_digest
            ):
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
            collision = self._catalog.execute(
                "SELECT 1 FROM task_routes WHERE bundle_relpath = ? OR "
                "active_route_identity_digest = ? LIMIT 1",
                (target.bundle_relpath, target.evidence.route_identity_digest),
            ).fetchone()
            if collision is not None:
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
            collision = self._catalog.execute(
                "SELECT 1 FROM retained_task_routes WHERE bundle_relpath = ? OR "
                "route_identity_digest = ? LIMIT 1",
                (target.bundle_relpath, target.evidence.route_identity_digest),
            ).fetchone()
            if collision is not None:
                raise MaintenanceError(MaintenanceReason.REPLAY_MISMATCH, False, {})
            self._rebase_project_text_refs_locked(
                str(handle.task_id), old_generation, old_generation + 1
            )
            self._catalog.execute(
                "INSERT INTO retained_task_routes("
                "installation_id, task_id, route_generation, bundle_relpath, "
                "route_identity_digest, retained_by_operation_id, retained_reason, state, "
                "frontier_seq, frontier_digest, retained_at) "
                "VALUES(?, ?, ?, ?, ?, ?, 'restore_replaced', 'retained', ?, ?, ?)",
                (
                    self._installation_id,
                    str(handle.task_id),
                    old_generation,
                    route[1],
                    handle.route_identity_digest,
                    str(handle.request_id),
                    operation[0],
                    operation[1],
                    now_wire,
                ),
            )
            self._catalog.execute(
                "UPDATE task_routes SET bundle_relpath = ?, route_generation = ?, "
                "active_route_identity_digest = ?, updated_at = ? WHERE task_id = ? "
                "AND route_generation = ? AND active_route_identity_digest = ? AND state = 'active'",
                (
                    target.bundle_relpath,
                    old_generation + 1,
                    target.evidence.route_identity_digest,
                    now_wire,
                    str(handle.task_id),
                    old_generation,
                    handle.route_identity_digest,
                ),
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})
            self._catalog.execute(
                "UPDATE privacy_root_sets SET route_identity_digest = ?, updated_at = ? "
                "WHERE task_id = ? AND route_identity_digest = ? AND root_generation = ? "
                "AND root_digest = ?",
                (
                    target.evidence.route_identity_digest,
                    now_wire,
                    str(handle.task_id),
                    handle.route_identity_digest,
                    roots.privacy_root_generation,
                    roots.root_set_digest,
                ),
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})
            self._catalog.execute(
                "UPDATE privacy_audit_records SET route_identity_digest = ?, updated_at = ? "
                "WHERE task_id = ? AND route_identity_digest = ?",
                (
                    target.evidence.route_identity_digest,
                    now_wire,
                    str(handle.task_id),
                    handle.route_identity_digest,
                ),
            )
            self._catalog.execute(
                "UPDATE maintenance_operations SET phase = 'route_switched', "
                "target_route_identity_digest = ?, backup_manifest_digest = ?, updated_at = ? "
                "WHERE installation_id = ? AND operation_id = ? AND state = 'pending' "
                "AND owner_generation = ? AND lease_owner_id = ? AND lease_generation = ?",
                (
                    target.evidence.route_identity_digest,
                    target.result.backup_manifest_digest,
                    now_wire,
                    self._installation_id,
                    str(handle.request_id),
                    str(handle.owner_generation),
                    self._lease_owner_id,
                    handle.lease_generation,
                ),
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            self._catalog.execute("COMMIT")
        except BaseException:
            self._catalog.execute("ROLLBACK")
            raise

    def _complete(
        self,
        handle: MaintenanceHandle,
        result: BackupResult | RestoreResult | MigrationResult,
    ) -> None:
        value = _result_value(result)
        canonical = canonical_encode(value)
        digest = canonical_digest(value)
        backup_digest = result.backup_manifest_digest
        self._catalog.execute("BEGIN IMMEDIATE")
        try:
            self._require_handle(handle)
            expected_terminal_phase = {
                MaintenanceKind.BACKUP: "manifest_ready",
                MaintenanceKind.RESTORE: "route_switched",
                MaintenanceKind.MIGRATION: "replay_verified",
            }[handle.kind]
            self._catalog.execute(
                "UPDATE maintenance_operations SET state = 'complete', phase = 'terminal', "
                "owner_generation = NULL, lease_owner_id = NULL, lease_generation = NULL, "
                "lease_expires_at = NULL, backup_manifest_digest = ?, result_canonical = ?, "
                "result_digest = ?, terminal_at = ?, updated_at = ? "
                "WHERE installation_id = ? AND operation_id = ? AND state = 'pending' "
                "AND owner_generation = ? AND lease_owner_id = ? AND lease_generation = ? "
                "AND phase = ?",
                (
                    backup_digest,
                    canonical,
                    digest,
                    format_rfc3339_millis(self._now()),
                    format_rfc3339_millis(self._now()),
                    self._installation_id,
                    str(handle.request_id),
                    str(handle.owner_generation),
                    self._lease_owner_id,
                    handle.lease_generation,
                    expected_terminal_phase,
                ),
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            self._catalog.execute("COMMIT")
        except BaseException:
            self._catalog.execute("ROLLBACK")
            raise

    def record_migration_failure(
        self,
        handle: MaintenanceHandle,
        *,
        backup_manifest_digest: str,
        original_verified: bool,
        outcome_ambiguous: bool,
    ) -> None:
        """Persist the fail-closed migration outcome, preserving the original and backup."""

        if handle.kind is not MaintenanceKind.MIGRATION:
            raise TypeError("maintenance_migration_handle_required")
        validate_sha256_digest(backup_manifest_digest)
        if type(original_verified) is not bool or type(outcome_ambiguous) is not bool:
            raise TypeError("maintenance_migration_failure_invalid")
        rollback_required = outcome_ambiguous or not original_verified
        self._quarantine(
            handle,
            "rollback_required" if rollback_required else "migration_failed_original_verified",
            backup_manifest_digest=backup_manifest_digest,
        )
        raise MaintenanceError(
            (
                MaintenanceReason.ROLLBACK_REQUIRED
                if rollback_required
                else MaintenanceReason.MIGRATION_FAILED
            ),
            False,
            {"backup_manifest_digest": backup_manifest_digest},
        )

    def _quarantine(
        self,
        handle: MaintenanceHandle,
        code: str,
        *,
        backup_manifest_digest: str | None = None,
    ) -> None:
        """Persist a bounded terminal contradiction without overwriting prior artifacts."""

        if backup_manifest_digest is not None:
            validate_sha256_digest(backup_manifest_digest)

        value = JsonObject(
            {
                "kind": handle.kind.value,
                "request_id": str(handle.request_id),
                "task_id": str(handle.task_id),
                "outcome": "quarantined",
                "code": code,
            }
        )
        canonical = canonical_encode(value)
        now_wire = format_rfc3339_millis(self._now())
        self._catalog.execute("BEGIN IMMEDIATE")
        try:
            self._require_handle(handle)
            self._catalog.execute(
                "UPDATE maintenance_operations SET state = 'quarantined', phase = 'terminal', "
                "owner_generation = NULL, lease_owner_id = NULL, lease_generation = NULL, "
                "lease_expires_at = NULL, result_canonical = ?, result_digest = ?, "
                "backup_manifest_digest = COALESCE(?, backup_manifest_digest), "
                "quarantine_code = ?, terminal_at = ?, updated_at = ? "
                "WHERE installation_id = ? AND operation_id = ? AND state = 'pending' "
                "AND owner_generation = ? AND lease_owner_id = ? AND lease_generation = ?",
                (
                    canonical,
                    canonical_digest(value),
                    backup_manifest_digest,
                    code,
                    now_wire,
                    now_wire,
                    self._installation_id,
                    str(handle.request_id),
                    str(handle.owner_generation),
                    self._lease_owner_id,
                    handle.lease_generation,
                ),
            )
            if self._catalog.changes() != 1:
                raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
            self._catalog.execute("COMMIT")
        except BaseException:
            self._catalog.execute("ROLLBACK")
            raise

    def _catalog_owner_generation(self) -> int:
        rows = self._catalog.execute(
            "SELECT key, value FROM catalog_meta WHERE key IN ('installation_id', 'owner_generation')"
        ).fetchall()
        values = {cast(str, key): cast(str, value) for key, value in rows}
        if values.get("installation_id") != self._installation_id:
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
        try:
            generation = int(values["owner_generation"], 10)
        except (KeyError, ValueError) as exc:
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {}) from exc
        if generation <= 0:
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
        return generation

    def _require_current_route(self, facts: _AuthorityFacts) -> None:
        row = self._catalog.execute(
            "SELECT active_route_identity_digest, state FROM task_routes WHERE task_id = ?",
            (facts.task_id,),
        ).fetchone()
        if row != (facts.source_route_identity_digest, "active"):
            raise MaintenanceError(MaintenanceReason.CATALOG_ROUTE_CHANGED, False, {})

    def _require_bundle_generation(self, owner_generation: int) -> None:
        row = self._bundle.execute(
            "SELECT value FROM bundle_meta WHERE key = 'owner_generation'"
        ).fetchone()
        if row != (str(owner_generation),):
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})

    def _require_handle(self, handle: MaintenanceHandle) -> None:
        if type(handle) is not MaintenanceHandle:
            raise TypeError("maintenance_handle_invalid")
        if handle.owner_generation != self._catalog_owner_generation():
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})
        row = self._catalog.execute(
            "SELECT task_id, kind, plan_digest, owner_generation, lease_owner_id, lease_generation "
            "FROM maintenance_operations WHERE installation_id = ? AND operation_id = ? "
            "AND state = 'pending'",
            (self._installation_id, str(handle.request_id)),
        ).fetchone()
        if row != (
            str(handle.task_id),
            handle.kind.value,
            handle.confirmed_plan_digest,
            str(handle.owner_generation),
            self._lease_owner_id,
            handle.lease_generation,
        ):
            raise MaintenanceError(MaintenanceReason.GENERATION_LOST, False, {})

    def _new_pin_id(self) -> str:
        return self._ids.new(IdKind.MAINTENANCE_PIN)

    def _now(self) -> datetime:
        value = self._clock.now_utc()
        if value.tzinfo is None or value.utcoffset() != timedelta(0):
            raise ValueError("maintenance_clock_invalid")
        return value.astimezone(UTC)


def _kind_for(
    command: BackupCommand | RestoreCommand | MigrationCommand,
    plan: BackupPlan | RestorePlan | MigrationPlan,
) -> MaintenanceKind:
    if type(command) is BackupCommand and type(plan) is BackupPlan:
        return MaintenanceKind.BACKUP
    if type(command) is RestoreCommand and type(plan) is RestorePlan:
        return MaintenanceKind.RESTORE
    if type(command) is MigrationCommand and type(plan) is MigrationPlan:
        return MaintenanceKind.MIGRATION
    raise TypeError("maintenance_command_plan_mismatch")


def _frontier_from_object(value: object) -> Frontier:
    row = _mapping(value)
    if set(row) != {"sequence", "head_digest"}:
        raise ValueError("maintenance_result_frontier_invalid")
    sequence = row["sequence"]
    head_digest = row["head_digest"]
    if type(sequence) is not str or not sequence.isdecimal() or type(head_digest) is not str:
        raise ValueError("maintenance_result_frontier_invalid")
    return Frontier(int(sequence, 10), head_digest)


def _result_from_bytes(
    data: bytes,
) -> BackupResult | RestoreResult | MigrationResult:
    try:
        parsed = strict_json_parse(data)
        if canonical_encode(parsed) != data:
            raise ValueError("maintenance_result_not_canonical")
        value = _mapping(parsed)
        kind = value.get("kind")
        if kind == "backup":
            if set(value) != {
                "kind",
                "request_id",
                "task_id",
                "frontier",
                "mode",
                "backup_manifest_digest",
                "backup_set_digest",
                "object_count",
                "privacy_audit_object_count",
                "privacy_audit_snapshot_digest",
                "database_digest",
                "recovery_artifact_digest",
                "completed_at",
            }:
                raise ValueError("maintenance_result_fields_invalid")
            return BackupResult(
                request_id(cast(str, value["request_id"])),
                task_id(cast(str, value["task_id"])),
                _frontier_from_object(value["frontier"]),
                BackupMode(cast(str, value["mode"])),
                cast(str, value["backup_manifest_digest"]),
                cast(str, value["backup_set_digest"]),
                cast(int, value["object_count"]),
                cast(int, value["privacy_audit_object_count"]),
                cast(str, value["privacy_audit_snapshot_digest"]),
                cast(str, value["database_digest"]),
                cast(str | None, value["recovery_artifact_digest"]),
                Timestamp(cast(str, value["completed_at"])),
            )
        if kind == "restore":
            if set(value) != {
                "kind",
                "request_id",
                "task_id",
                "restored_frontier",
                "prior_route_identity_digest",
                "active_route_identity_digest",
                "backup_manifest_digest",
                "replay_digest",
                "completed_at",
            }:
                raise ValueError("maintenance_result_fields_invalid")
            return RestoreResult(
                request_id(cast(str, value["request_id"])),
                task_id(cast(str, value["task_id"])),
                _frontier_from_object(value["restored_frontier"]),
                cast(str | None, value["prior_route_identity_digest"]),
                cast(str, value["active_route_identity_digest"]),
                cast(str, value["backup_manifest_digest"]),
                cast(str, value["replay_digest"]),
                Timestamp(cast(str, value["completed_at"])),
            )
        if kind == "migration":
            if set(value) != {
                "kind",
                "request_id",
                "task_id",
                "from_version",
                "to_version",
                "backup_manifest_digest",
                "frontier_before",
                "frontier_after",
                "replay_digest",
                "completed_at",
            }:
                raise ValueError("maintenance_result_fields_invalid")
            return MigrationResult(
                request_id(cast(str, value["request_id"])),
                task_id(cast(str, value["task_id"])),
                cast(str, value["from_version"]),
                cast(str, value["to_version"]),
                cast(str, value["backup_manifest_digest"]),
                _frontier_from_object(value["frontier_before"]),
                _frontier_from_object(value["frontier_after"]),
                cast(str, value["replay_digest"]),
                Timestamp(cast(str, value["completed_at"])),
            )
        raise ValueError("maintenance_result_kind_invalid")
    except Exception as exc:
        raise MaintenanceError(MaintenanceReason.BACKUP_INCOMPLETE, False, {}) from exc


def _result_value(result: BackupResult | RestoreResult | MigrationResult) -> JsonObject:
    if type(result) is BackupResult:
        return JsonObject(
            {
                "kind": "backup",
                "request_id": str(result.request_id),
                "task_id": str(result.task_id),
                "frontier": result.frontier.as_wire(),
                "mode": result.mode.value,
                "backup_manifest_digest": result.backup_manifest_digest,
                "backup_set_digest": result.backup_set_digest,
                "object_count": result.object_count,
                "privacy_audit_object_count": result.privacy_audit_object_count,
                "privacy_audit_snapshot_digest": result.privacy_audit_snapshot_digest,
                "database_digest": result.database_digest,
                "recovery_artifact_digest": result.recovery_artifact_digest,
                "completed_at": result.completed_at.wire,
            }
        )
    if type(result) is RestoreResult:
        return JsonObject(
            {
                "kind": "restore",
                "request_id": str(result.request_id),
                "task_id": str(result.task_id),
                "restored_frontier": result.restored_frontier.as_wire(),
                "prior_route_identity_digest": result.prior_route_identity_digest,
                "active_route_identity_digest": result.active_route_identity_digest,
                "backup_manifest_digest": result.backup_manifest_digest,
                "replay_digest": result.replay_digest,
                "completed_at": result.completed_at.wire,
            }
        )
    if type(result) is MigrationResult:
        return JsonObject(
            {
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
        )
    raise TypeError("maintenance_result_invalid")
