"""Production effects for the controlled 0.2-to-0.3 bundle upgrade.

The upgrade coordinator owns the durable operation state and the forward migration.  This module
owns the evidence that cannot be obtained from that state alone: a machine-bound, online SQLite
snapshot, authenticated copies of the encrypted object envelopes, the privacy audit sidecar, and
the post-migration replay call.  Route discovery and ownership remain service concerns and enter
through the typed ``TemporaryFencedLedgerFactory`` callback.

The backup format is deliberately the existing maintenance backup format.  Reusing its parser and
verifier keeps the automatic path subject to the same manifest-last, canonical JSON, digest, and
database checks as an explicitly requested backup.  The automatic path never creates a portable
recovery artifact and never copies vault material.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sqlite3
import stat
import urllib.parse
from collections.abc import Awaitable, Callable
from contextlib import AbstractAsyncContextManager
from pathlib import Path
from typing import Final, Protocol, cast

import apsw

from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.adapters.sqlite.connection import open_read_only
from finishup.adapters.sqlite.maintenance import (
    VerifiedBackupSet,
    build_backup_manifest,
    verify_backup_set,
)
from finishup.domain.values import (
    JsonObject,
    TaskId,
    Timestamp,
    format_rfc3339_millis,
    task_id,
    validate_commitment,
    validate_sha256_digest,
)
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.keys import BundleKeys, KeyStoreError
from finishup.ports.maintenance import (
    BackupManifest,
    BackupMode,
    BackupObjectEntry,
    MaintenanceError,
    PrivacyAuditBackupSnapshot,
)
from finishup.ports.objects import (
    MAX_OBJECT_HEADER_BYTES,
    ObjectKind,
    ObjectRef,
    ObjectRootSnapshot,
)
from finishup.ports.secret_memory import SecretMemoryPort
from finishup.protocol.canonical import canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_id
from finishup.protocol.models import MAX_OBJECT_PLAINTEXT_BYTES
from finishup.service.bundle_upgrade import (
    BackupEvidence,
    BundleIntegrity,
    BundleUpgradeError,
    BundleUpgradeOperation,
    BundleUpgradeReason,
    BundleUpgradeTarget,
)

__all__ = [
    "BundleKeysLoader",
    "BundleUpgradeFencedLedger",
    "PrivacySnapshotLoader",
    "ProductionBundleUpgradeEffects",
    "SqliteBundleUpgradeEffects",
    "TemporaryFencedLedgerFactory",
]


# The envelope reader has the same bound.  Keeping this limit here avoids importing private
# constants from the object adapter while ensuring a malformed object cannot allocate an
# unbounded staging buffer during backup.
_MAX_OBJECT_FRAME_BYTES: Final = (
    4 + 1 + 4 + MAX_OBJECT_HEADER_BYTES + 12 + MAX_OBJECT_PLAINTEXT_BYTES + 16
)
_MAX_BACKUP_SIDECAR_BYTES: Final = 4 * 1024 * 1024
_MAX_BACKUP_SETS_TO_SCAN: Final = 256
_BACKUP_FORMAT: Final = "yoetz.bundle-upgrade/1"
_DATABASE_NAME: Final = "ledger.sqlite3"
_MANIFEST_NAME: Final = "backup-manifest.json"
_PRIVACY_SNAPSHOT_NAME: Final = "privacy-audit-snapshot.json"
_OBJECT_COPY_CHUNK_BYTES: Final = 64 * 1024
# ``MacKeyHandle`` intentionally exposes no key bytes.  This object-domain operation gives the
# machine-bound manifest a stable, nonsecret identity for the actual bundle key material rather
# than pretending that the public key slot is a fingerprint.  Vault handles already permit this
# versioned object domain, and the domain separates the result from user object commitments.
_BUNDLE_KEY_FINGERPRINT_DOMAIN: Final = b"yoetz/object/bundle_key_fingerprint/v1\x00"
_BUNDLE_KEY_FINGERPRINT_MESSAGE: Final = b"machine-bound-backup\x00"


class BundleUpgradeFencedLedger(Protocol):
    """Service-owned temporary fence and replay facade.

    The service adapter enters this context only after it has quiesced all normal runtime
    writers.  The implementation normally wraps ``SqliteLedger`` plus its registered
    ``OwnershipFence``.  The effects adapter intentionally calls one narrow method instead of
    reaching into ledger or connection private state.
    """

    async def verify_replay(
        self,
        *,
        target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        backup: BackupEvidence,
    ) -> str:
        """Recover the projection under the fence and return its digest-only proof."""
        ...


type BundleKeysLoader = Callable[[str], Awaitable[BundleKeys]]
type PrivacySnapshotLoader = Callable[
    [BundleUpgradeTarget, BundleIntegrity], Awaitable[PrivacyAuditBackupSnapshot]
]
type TemporaryFencedLedgerFactory = Callable[
    [BundleUpgradeTarget], AbstractAsyncContextManager[BundleUpgradeFencedLedger]
]


def _backup_failure(
    check: str,
    *,
    retryable: bool,
    cause: BaseException | None = None,
) -> BundleUpgradeError:
    error = BundleUpgradeError(BundleUpgradeReason.BACKUP_FAILED, retryable, {"check": check})
    if cause is not None:
        error.__cause__ = cause
    return error


def _verification_failure(
    check: str,
    *,
    cause: BaseException | None = None,
) -> BundleUpgradeError:
    error = BundleUpgradeError(
        BundleUpgradeReason.VERIFICATION_FAILED,
        False,
        {"check": check},
    )
    if cause is not None:
        error.__cause__ = cause
    return error


def _private_facts(path: Path, *, max_bytes: int | None = None) -> os.stat_result:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise OSError("private_path_missing") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISREG(facts.st_mode)
        or facts.st_nlink != 1
        or stat.S_IMODE(facts.st_mode) & 0o077
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        or (max_bytes is not None and facts.st_size > max_bytes)
    ):
        raise OSError("private_file_unsafe")
    return facts


def _private_directory(path: Path) -> os.stat_result:
    try:
        facts = path.lstat()
    except OSError as exc:
        raise OSError("private_directory_missing") from exc
    if (
        stat.S_ISLNK(facts.st_mode)
        or not stat.S_ISDIR(facts.st_mode)
        or stat.S_IMODE(facts.st_mode) & 0o077
        or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
    ):
        raise OSError("private_directory_unsafe")
    return facts


def _ensure_private_directory(path: Path) -> None:
    """Create a private directory without following a pre-existing symlink component."""

    if not path.is_absolute():
        raise ValueError("backup_root_invalid")
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, component in enumerate(components):
        current /= component
        try:
            facts = current.lstat()
        except FileNotFoundError:
            current.mkdir(mode=0o700)
            facts = current.lstat()
        if (
            stat.S_ISLNK(facts.st_mode)
            or not stat.S_ISDIR(facts.st_mode)
            or (
                index == len(components) - 1
                and (
                    stat.S_IMODE(facts.st_mode) & 0o077
                    or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
                )
            )
        ):
            raise ValueError("backup_root_invalid")
    _private_directory(path)


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        facts = os.fstat(descriptor)
        if (
            not stat.S_ISREG(facts.st_mode)
            or facts.st_nlink != 1
            or stat.S_IMODE(facts.st_mode) & 0o077
            or (hasattr(os, "geteuid") and facts.st_uid != os.geteuid())
        ):
            raise OSError("private_file_unsafe")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        _private_directory(path)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_exclusive(path: Path, data: bytes) -> None:
    if type(data) is not bytes:
        raise TypeError("backup_bytes_invalid")
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        view = memoryview(data)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count <= 0:
                raise OSError("backup_write_incomplete")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _sha256_private_file(path: Path, *, expected_size: int | None = None) -> str:
    facts = _private_facts(path)
    if expected_size is not None and facts.st_size != expected_size:
        raise OSError("private_file_changed")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            facts.st_dev,
            facts.st_ino,
            facts.st_size,
        ):
            raise OSError("private_file_changed")
        while True:
            chunk = os.read(descriptor, _OBJECT_COPY_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (after.st_dev, after.st_ino, after.st_size) != (
            facts.st_dev,
            facts.st_ino,
            facts.st_size,
        ):
            raise OSError("private_file_changed")
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest()


def _read_private_file(path: Path, *, max_bytes: int) -> bytes:
    facts = _private_facts(path, max_bytes=max_bytes)
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            facts.st_dev,
            facts.st_ino,
            facts.st_size,
        ):
            raise OSError("private_file_changed")
        chunks: list[bytes] = []
        remaining = max_bytes + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(_OBJECT_COPY_CHUNK_BYTES, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        data = b"".join(chunks)
        if len(data) != facts.st_size or len(data) > max_bytes:
            raise OSError("private_file_changed")
        return data
    finally:
        os.close(descriptor)


def _copy_private_file(source: Path, destination: Path, *, max_bytes: int) -> int:
    """Copy one exact owner-only file and return the copied byte count."""

    source_descriptor = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    destination_descriptor = -1
    try:
        source_facts = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_facts.st_mode)
            or source_facts.st_nlink != 1
            or source_facts.st_size > max_bytes
            or stat.S_IMODE(source_facts.st_mode) & 0o077
            or (hasattr(os, "geteuid") and source_facts.st_uid != os.geteuid())
        ):
            raise OSError("private_file_unsafe")
        destination_descriptor = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        copied = 0
        while copied < source_facts.st_size:
            chunk = os.read(
                source_descriptor,
                min(_OBJECT_COPY_CHUNK_BYTES, source_facts.st_size - copied),
            )
            if not chunk:
                raise OSError("private_file_truncated")
            view = memoryview(chunk)
            written = 0
            while written < len(view):
                count = os.write(destination_descriptor, view[written:])
                if count <= 0:
                    raise OSError("backup_write_incomplete")
                written += count
            copied += len(chunk)
        if copied != source_facts.st_size:
            raise OSError("private_file_changed")
        os.fsync(destination_descriptor)
        destination_facts = os.fstat(destination_descriptor)
        if (
            destination_facts.st_size != source_facts.st_size
            or destination_facts.st_nlink != 1
            or stat.S_IMODE(destination_facts.st_mode) & 0o077
        ):
            raise OSError("private_file_changed")
        return copied
    finally:
        os.close(source_descriptor)
        if destination_descriptor >= 0:
            os.close(destination_descriptor)


def _backup_sqlite(source: Path, destination: Path) -> None:
    """Take a consistent online snapshot, including any committed source WAL pages."""

    source_uri = "file:" + urllib.parse.quote(source.as_posix(), safe="/:@") + "?mode=ro"
    source_connection: sqlite3.Connection | None = None
    destination_connection: sqlite3.Connection | None = None
    try:
        source_connection = sqlite3.connect(source_uri, uri=True, timeout=30.0)
        destination_connection = sqlite3.connect(str(destination), timeout=30.0)
        source_connection.backup(destination_connection)
        if destination_connection.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise OSError("backup_database_invalid")
        if destination_connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
            raise OSError("backup_database_invalid")
        destination_connection.commit()
        checkpoint = cast(
            tuple[object, ...] | None,
            destination_connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone(),
        )
        if type(checkpoint) is not tuple or len(checkpoint) != 3 or checkpoint[0] != 0:
            raise OSError("backup_database_checkpoint")
        journal_mode = destination_connection.execute("PRAGMA journal_mode=DELETE").fetchone()
        if journal_mode != ("delete",):
            raise OSError("backup_database_journal_mode")
        destination_connection.commit()
    except (OSError, sqlite3.Error):
        raise
    finally:
        if destination_connection is not None:
            destination_connection.close()
        if source_connection is not None:
            source_connection.close()
    destination.chmod(0o600)
    _fsync_file(destination)
    if _path_exists(destination.with_name(destination.name + "-wal")) or _path_exists(
        destination.with_name(destination.name + "-shm")
    ):
        raise OSError("backup_database_sidecar")


def _path_exists(path: Path) -> bool:
    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


def _manifest_value(manifest: BackupManifest) -> JsonObject:
    return JsonObject(
        {
            "manifest_schema": manifest.manifest_schema,
            "backup_format": manifest.backup_format,
            "request_id": str(manifest.request_id),
            "task_id": str(manifest.task_id),
            "frontier": manifest.frontier.as_wire(),
            "database_logical_name": manifest.database_logical_name,
            "database_size": manifest.database_size,
            "database_digest": manifest.database_digest,
            "objects": tuple(
                JsonObject(
                    {
                        "object_id": entry.object_id,
                        "kind": entry.kind.value,
                        "envelope_digest": entry.envelope_digest,
                        "envelope_size": entry.envelope_size,
                    }
                )
                for entry in manifest.objects
            ),
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
            "manifest_digest": manifest.manifest_digest,
        }
    )


def _privacy_snapshot_value(snapshot: PrivacyAuditBackupSnapshot) -> JsonObject:
    return JsonObject(
        {
            "origin_installation_id": snapshot.origin_installation_id,
            "origin_task_id": str(snapshot.origin_task_id),
            "catalog_version": snapshot.catalog_version,
            "audit_store_version": snapshot.audit_store_version,
            "privacy_root_generation": snapshot.privacy_root_generation,
            "privacy_root_digest": snapshot.privacy_root_digest,
            "audit_rows": snapshot.audit_rows,
            "terminal_receipts": snapshot.terminal_receipts,
            "privacy_audit_objects": tuple(
                JsonObject({"object_id": ref.object_id}) for ref in snapshot.privacy_audit_objects
            ),
        }
    )


def _integrity_matches(left: BundleIntegrity, right: BundleIntegrity, *, projection: bool) -> bool:
    checks = (
        left.task_id == right.task_id,
        left.frontier == right.frontier,
        left.history_digest == right.history_digest,
        left.event_count == right.event_count,
        left.object_digest == right.object_digest,
        left.object_count == right.object_count,
        left.preserved_digest == right.preserved_digest,
    )
    if projection:
        return all(checks) and left.projection_digest == right.projection_digest
    return all(checks)


def _close_read_only(db: apsw.Connection | None) -> None:
    if db is not None:
        try:
            db.close(force=True)
        except Exception:
            pass


async def _run_blocking_joined[ResultT](call: Callable[[], ResultT]) -> ResultT:
    """Join a file/SQLite worker before cancellation can release the bundle fence."""

    worker = asyncio.create_task(asyncio.to_thread(call))
    try:
        await asyncio.wait((worker,))
        return worker.result()
    except asyncio.CancelledError:
        while not worker.done():
            try:
                await asyncio.wait((worker,))
            except asyncio.CancelledError:
                continue
        try:
            worker.result()
        except BaseException:
            # The caller's cancellation remains the public outcome.  The worker is joined so it
            # cannot continue mutating the backup after the service-owned fence is released.
            pass
        raise


class SqliteBundleUpgradeEffects:
    """Backup and replay effects backed by the existing SQLite/object contracts."""

    def __init__(
        self,
        *,
        backup_root: Path,
        installation_id: str,
        load_bundle_keys: BundleKeysLoader,
        secret_memory: SecretMemoryPort,
        ids: IdPort,
        open_temporary_fenced_ledger: TemporaryFencedLedgerFactory,
        load_privacy_snapshot: PrivacySnapshotLoader,
        clock: ClockPort,
        version_manifest: JsonObject | None = None,
    ) -> None:
        _ensure_private_directory(backup_root)
        try:
            validated_installation = validate_id(IdKind.INSTALLATION, installation_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("bundle_upgrade_effects_invalid") from exc
        if not callable(load_bundle_keys) or not callable(open_temporary_fenced_ledger):
            raise TypeError("bundle_upgrade_effects_invalid")
        if not callable(load_privacy_snapshot):
            raise TypeError("bundle_upgrade_effects_invalid")
        if version_manifest is not None and type(version_manifest) is not JsonObject:
            raise TypeError("bundle_upgrade_effects_invalid")
        self._backup_root = backup_root
        self._installation_id = validated_installation
        self._load_bundle_keys = load_bundle_keys
        self._secret_memory = secret_memory
        self._ids = ids
        self._open_temporary_fenced_ledger = open_temporary_fenced_ledger
        self._load_privacy_snapshot = load_privacy_snapshot
        self._clock = clock
        self._version_manifest = version_manifest

    async def ensure_machine_backup(
        self,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
        before: BundleIntegrity,
        existing_manifest_digest: str | None,
    ) -> BackupEvidence:
        self._validate_operation_binding(target, operation, before)
        if existing_manifest_digest is not None:
            try:
                validate_sha256_digest(existing_manifest_digest)
            except ValueError as exc:
                raise _backup_failure("manifest_digest", retryable=False, cause=exc)

        final = self._operation_directory(target, operation)
        task_dir = final.parent
        _ensure_private_directory(task_dir)
        if _path_exists(final):
            verified = self._try_verify_set(final)
            if verified is not None:
                return await self._evidence_for(
                    verified,
                    target=target,
                    operation=operation,
                    before=before,
                    expected_manifest_digest=existing_manifest_digest,
                )
            if existing_manifest_digest is not None:
                raise _backup_failure("existing_set", retryable=False)
            self._quarantine_existing(final)
        elif existing_manifest_digest is not None:
            found = self._find_verified_set(target, existing_manifest_digest)
            if found is not None:
                return await self._evidence_for(
                    found,
                    target=target,
                    operation=operation,
                    before=before,
                    expected_manifest_digest=existing_manifest_digest,
                )
            raise _backup_failure("existing_set", retryable=False)

        stage = task_dir / f".{final.name}.{secrets.token_hex(16)}.tmp"
        _ensure_private_directory(stage)
        try:
            async with self._open_temporary_fenced_ledger(target):
                await self._create_backup_stage(
                    stage,
                    target=target,
                    operation=operation,
                    before=before,
                )
        except BundleUpgradeError:
            raise
        except (
            KeyStoreError,
            apsw.Error,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
            sqlite3.Error,
        ) as exc:
            raise _backup_failure("create", retryable=True, cause=exc)

        try:
            os.replace(stage, final)
            _fsync_directory(task_dir)
        except OSError as exc:
            # The complete stage intentionally remains discoverable if publication is interrupted.
            raise _backup_failure("publish", retryable=True, cause=exc)

        verified = self._try_verify_set(final)
        if verified is None:
            raise _backup_failure("published_set", retryable=False)
        return await self._evidence_for(
            verified,
            target=target,
            operation=operation,
            before=before,
            expected_manifest_digest=existing_manifest_digest,
        )

    async def verify_replay(
        self,
        target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        backup: BackupEvidence,
    ) -> str:
        if after.task_id != target.task_id or after.schema_version <= 0:
            raise _verification_failure("replay_binding")
        try:
            validate_sha256_digest(backup.manifest_digest)
        except ValueError as exc:
            raise _verification_failure("backup_digest", cause=exc)
        verified = self._find_verified_set(target, backup.manifest_digest)
        if verified is None:
            raise _verification_failure("backup_set")
        manifest = verified.manifest
        if manifest.task_id != target.task_id or manifest.frontier != after.frontier:
            raise _verification_failure("backup_frontier")
        self._validate_privacy_sidecar(verified, target)
        backup_integrity = self._capture_path_integrity(verified.database_path)
        if before is not None:
            if not _integrity_matches(before, backup_integrity, projection=True):
                raise _verification_failure("backup_preservation")
        # A restart after the DDL commit intentionally passes ``before=None``.  The immutable
        # machine-bound backup is then the only source of the original v12 facts; comparing the
        # live v14 bundle to itself would make preservation vacuous.
        if not _integrity_matches(backup_integrity, after, projection=True):
            raise _verification_failure("backup_preservation")

        try:
            await self._verify_live_objects(target, manifest)
        except BundleUpgradeError:
            raise
        except (
            KeyStoreError,
            OSError,
            RuntimeError,
            TypeError,
            ValueError,
        ) as exc:
            raise _verification_failure("bundle_key", cause=exc)
        try:
            async with self._open_temporary_fenced_ledger(target) as fenced:
                replay_digest = await fenced.verify_replay(
                    target=target,
                    before=before,
                    after=after,
                    backup=backup,
                )
        except BundleUpgradeError:
            raise
        except (apsw.Error, OSError, RuntimeError, TypeError, ValueError, sqlite3.Error) as exc:
            raise _verification_failure("replay", cause=exc)
        try:
            validate_sha256_digest(replay_digest)
        except ValueError as exc:
            raise _verification_failure("replay_digest", cause=exc)

        current = self._capture_path_integrity(target.bundle_path)
        if not _integrity_matches(after, current, projection=False):
            raise _verification_failure("post_replay_preservation")
        if current.projection_digest != replay_digest:
            raise _verification_failure("post_replay_projection")
        return replay_digest

    async def _create_backup_stage(
        self,
        stage: Path,
        *,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
        before: BundleIntegrity,
    ) -> None:
        _private_directory(stage)
        bundle_root = target.bundle_path.parent
        _private_directory(bundle_root)
        source_integrity = self._capture_path_integrity(target.bundle_path)
        if not _integrity_matches(before, source_integrity, projection=True):
            raise _backup_failure("source_changed", retryable=True)

        source_db = target.bundle_path
        database_path = stage / _DATABASE_NAME
        await _run_blocking_joined(lambda: _backup_sqlite(source_db, database_path))
        copied_integrity = self._capture_path_integrity(database_path)
        if not _integrity_matches(before, copied_integrity, projection=True):
            raise _backup_failure("database_snapshot", retryable=False)

        rows = self._present_object_rows(source_db)
        try:
            keys = await self._load_bundle_keys(str(target.task_id))
        except KeyStoreError:
            raise
        except (OSError, RuntimeError, TypeError, ValueError):
            raise
        if type(keys) is not BundleKeys:
            raise _backup_failure("bundle_keys", retryable=False)
        key_fingerprint = _bundle_key_fingerprint(keys)
        store: EncryptedFilesObjectStore | None = None
        if rows:
            store = self._object_store(bundle_root, keys)

        objects_directory = stage / "objects"
        _ensure_private_directory(objects_directory)
        entries: list[BackupObjectEntry] = []
        for object_id_value, kind, envelope_digest in rows:
            assert store is not None
            resolved = await self._resolve_live_object(
                store,
                object_id_value,
                envelope_digest,
                expected_kind=kind,
                expected_task=target.task_id,
            )
            source_object = self._live_object_path(bundle_root, object_id_value)
            destination_object = objects_directory / object_id_value
            envelope_size = await _run_blocking_joined(
                lambda: _copy_private_file(
                    source_object,
                    destination_object,
                    max_bytes=_MAX_OBJECT_FRAME_BYTES,
                )
            )
            copied_digest = await _run_blocking_joined(
                lambda: _sha256_private_file(
                    destination_object,
                    expected_size=envelope_size,
                )
            )
            if copied_digest != envelope_digest or resolved.envelope_digest != envelope_digest:
                raise _backup_failure("object_copy", retryable=False)
            entries.append(
                BackupObjectEntry(
                    object_id=object_id_value,
                    kind=kind,
                    envelope_digest=envelope_digest,
                    envelope_size=envelope_size,
                )
            )

        entries_tuple = tuple(sorted(entries, key=lambda item: item.object_id.encode("ascii")))
        snapshot = await self._load_privacy_snapshot(target, before)
        if type(snapshot) is not PrivacyAuditBackupSnapshot:
            raise _backup_failure("privacy_snapshot", retryable=False)
        self._validate_privacy_snapshot(snapshot, target, entries_tuple)
        snapshot_bytes = canonical_encode(_privacy_snapshot_value(snapshot))
        if len(snapshot_bytes) > _MAX_BACKUP_SIDECAR_BYTES:
            raise _backup_failure("privacy_snapshot_size", retryable=False)
        privacy_path = stage / _PRIVACY_SNAPSHOT_NAME
        _write_exclusive(privacy_path, snapshot_bytes)
        _fsync_directory(objects_directory)
        _fsync_directory(stage)

        now = Timestamp(format_rfc3339_millis(self._clock.now_utc()))
        manifest = build_backup_manifest(
            backup_format=_BACKUP_FORMAT,
            request_id_value=operation.request_id,
            task_id_value=str(target.task_id),
            frontier=before.frontier,
            database_size=_private_facts(database_path).st_size,
            database_digest=_sha256_private_file(database_path),
            objects=entries_tuple,
            version_manifest=self._version_manifest
            or JsonObject(
                {
                    "kind": "yoetz.bundle-upgrade/1",
                    "from_version": str(before.schema_version),
                    "to_version": "14",
                    "migration_ids": tuple(
                        f"{version:04d}" for version in range(before.schema_version + 1, 15)
                    ),
                }
            ),
            mode=BackupMode.MACHINE_BOUND,
            key_fingerprint=key_fingerprint,
            key_locator_classification="machine_bound",
            recovery_artifact_digest=None,
            recovery_kdf_policy=None,
            privacy_audit_snapshot_size=len(snapshot_bytes),
            privacy_audit_snapshot_digest="sha256:" + hashlib.sha256(snapshot_bytes).hexdigest(),
            privacy_root_generation=snapshot.privacy_root_generation,
            privacy_root_digest=snapshot.privacy_root_digest,
            audit_store_version=snapshot.audit_store_version,
            privacy_audit_row_count=len(snapshot.audit_rows) + len(snapshot.terminal_receipts),
            privacy_audit_object_count=len(snapshot.privacy_audit_objects),
            created_at=now,
            completed_at=now,
        )
        _write_exclusive(stage / _MANIFEST_NAME, canonical_encode(_manifest_value(manifest)))
        _fsync_file(stage / _MANIFEST_NAME)
        _fsync_directory(stage)

    def _validate_operation_binding(
        self,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
        before: BundleIntegrity,
    ) -> None:
        if (
            operation.task_id != target.task_id
            or before.task_id != target.task_id
            or before.frontier != target.frontier
        ):
            raise _backup_failure("binding", retryable=False)

    def _operation_directory(
        self,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
    ) -> Path:
        validate_id(IdKind.TASK, str(target.task_id))
        validate_id(IdKind.REQUEST, operation.request_id)
        return self._backup_root / str(target.task_id) / operation.request_id

    async def _evidence_for(
        self,
        verified: VerifiedBackupSet,
        *,
        target: BundleUpgradeTarget,
        operation: BundleUpgradeOperation,
        before: BundleIntegrity,
        expected_manifest_digest: str | None,
    ) -> BackupEvidence:
        manifest = verified.manifest
        if (
            manifest.request_id != operation.request_id
            or manifest.task_id != target.task_id
            or manifest.frontier != before.frontier
            or manifest.mode is not BackupMode.MACHINE_BOUND
            or manifest.privacy_root_generation != target.privacy_root_generation
            or manifest.privacy_root_digest != target.privacy_root_digest
        ):
            raise _backup_failure("manifest_binding", retryable=False)
        if (
            expected_manifest_digest is not None
            and manifest.manifest_digest != expected_manifest_digest
        ):
            raise _backup_failure("manifest_identity", retryable=False)
        self._validate_privacy_sidecar(verified, target)
        backup_integrity = self._capture_path_integrity(verified.database_path)
        if not _integrity_matches(before, backup_integrity, projection=True):
            raise _backup_failure("backup_preservation", retryable=False)
        try:
            keys = await self._load_bundle_keys(str(target.task_id))
            if type(keys) is not BundleKeys:
                raise _backup_failure("bundle_keys", retryable=False)
            if _bundle_key_fingerprint(keys) != manifest.key_fingerprint:
                raise _backup_failure("key_fingerprint", retryable=False)
        except BundleUpgradeError:
            raise
        except (KeyStoreError, OSError, RuntimeError, TypeError, ValueError) as exc:
            raise _backup_failure("bundle_keys", retryable=False, cause=exc)
        return BackupEvidence(
            target.task_id,
            before.frontier,
            manifest.manifest_digest,
            backup_integrity.schema_version,
        )

    def _try_verify_set(self, path: Path) -> VerifiedBackupSet | None:
        try:
            return verify_backup_set(path)
        except (MaintenanceError, OSError, TypeError, ValueError):
            return None

    def _find_verified_set(
        self,
        target: BundleUpgradeTarget,
        manifest_digest: str,
    ) -> VerifiedBackupSet | None:
        try:
            validate_sha256_digest(manifest_digest)
            task_dir = self._backup_root / str(task_id(target.task_id))
            _private_directory(task_dir)
            candidates = sorted(task_dir.iterdir(), key=lambda item: item.name.encode("utf-8"))
        except (OSError, TypeError, ValueError):
            return None
        if len(candidates) > _MAX_BACKUP_SETS_TO_SCAN:
            return None
        for candidate in candidates:
            try:
                if not candidate.is_dir() or candidate.is_symlink():
                    continue
                verified = verify_backup_set(candidate, expected_task_id=str(target.task_id))
            except (MaintenanceError, OSError, TypeError, ValueError):
                continue
            if (
                verified.manifest.manifest_digest == manifest_digest
                and verified.manifest.frontier == target.frontier
            ):
                return verified
        return None

    def _quarantine_existing(self, path: Path) -> None:
        quarantine = path.parent / f".{path.name}.invalid.{secrets.token_hex(16)}"
        try:
            os.replace(path, quarantine)
            _fsync_directory(path.parent)
        except OSError as exc:
            raise _backup_failure("existing_set", retryable=True, cause=exc)

    def _capture_path_integrity(self, path: Path) -> BundleIntegrity:
        db: apsw.Connection | None = None
        try:
            db = open_read_only(path)
            from finishup.service.bundle_upgrade import capture_sqlite_integrity

            return capture_sqlite_integrity(db)
        except BundleUpgradeError:
            raise
        except (apsw.Error, OSError, TypeError, ValueError) as exc:
            raise _verification_failure("integrity", cause=exc)
        finally:
            _close_read_only(db)

    @staticmethod
    def _present_object_rows(
        path: Path,
    ) -> tuple[tuple[str, ObjectKind, str], ...]:
        db: apsw.Connection | None = None
        try:
            db = open_read_only(path)
            rows = db.execute(
                "SELECT object_id,kind,envelope_digest,state FROM objects ORDER BY object_id"
            ).fetchall()
            result: list[tuple[str, ObjectKind, str]] = []
            for row in rows:
                if len(row) != 4 or type(row[0]) is not str or type(row[1]) is not str:
                    raise _verification_failure("object_inventory")
                state = row[3]
                if type(state) is not str or state not in {
                    "present",
                    "redacted",
                    "missing",
                    "quarantined",
                }:
                    raise _verification_failure("object_inventory")
                if state != "present":
                    continue
                try:
                    object_kind = ObjectKind(row[1])
                    validate_id(IdKind.OBJECT, row[0])
                    validate_sha256_digest(cast(str, row[2]))
                except (TypeError, ValueError) as exc:
                    raise _verification_failure("object_inventory", cause=exc)
                if object_kind is ObjectKind.IMPORT_STDERR:
                    raise _verification_failure("object_kind")
                result.append((row[0], object_kind, cast(str, row[2])))
            return tuple(result)
        except BundleUpgradeError:
            raise
        except apsw.Error as exc:
            raise _verification_failure("object_inventory", cause=exc)
        finally:
            _close_read_only(db)

    async def _verify_live_objects(
        self,
        target: BundleUpgradeTarget,
        manifest: BackupManifest,
    ) -> None:
        rows = self._present_object_rows(target.bundle_path)
        expected = tuple(
            (entry.object_id, entry.kind, entry.envelope_digest) for entry in manifest.objects
        )
        observed = tuple((object_id_value, kind, digest) for object_id_value, kind, digest in rows)
        if observed != expected:
            raise _verification_failure("object_inventory")
        keys = await self._load_bundle_keys(str(target.task_id))
        if type(keys) is not BundleKeys:
            raise _verification_failure("bundle_keys")
        if _bundle_key_fingerprint(keys) != manifest.key_fingerprint:
            raise _verification_failure("key_fingerprint")
        if not rows:
            return
        store = self._object_store(target.bundle_path.parent, keys)
        for object_id_value, kind, digest in rows:
            await self._resolve_live_object(
                store,
                object_id_value,
                digest,
                expected_kind=kind,
                expected_task=target.task_id,
            )

    async def _resolve_live_object(
        self,
        store: EncryptedFilesObjectStore,
        object_id_value: str,
        envelope_digest: str,
        *,
        expected_kind: ObjectKind,
        expected_task: TaskId,
    ) -> ObjectRef:
        try:
            resolved = await store.resolve_verified(object_id_value, envelope_digest)
        except (OSError, TypeError, ValueError) as exc:
            raise _verification_failure("object_authentication", cause=exc)
        if (
            type(resolved) is not ObjectRef
            or resolved.object_id != object_id_value
            or resolved.envelope_digest != envelope_digest
            or resolved.metadata.kind is not expected_kind
            or resolved.metadata.task_id != str(expected_task)
        ):
            raise _verification_failure("object_binding")
        return resolved

    @staticmethod
    def _live_object_path(bundle_root: Path, object_id_value: str) -> Path:
        try:
            validate_id(IdKind.OBJECT, object_id_value)
            _private_directory(bundle_root)
            objects_root = bundle_root / "objects"
            _private_directory(objects_root)
            shard = objects_root / object_id_value[4:6]
            _private_directory(shard)
            path = shard / object_id_value
            _private_facts(path, max_bytes=_MAX_OBJECT_FRAME_BYTES)
            return path
        except (OSError, TypeError, ValueError) as exc:
            raise _verification_failure("object_path", cause=exc)

    def _object_store(
        self,
        bundle_root: Path,
        keys: BundleKeys,
    ) -> EncryptedFilesObjectStore:
        return EncryptedFilesObjectStore(
            bundle_root=bundle_root,
            bundle_keys=keys,
            secret_memory=self._secret_memory,
            id_port=self._ids,
            current_root_snapshot=_unavailable_root_snapshot,
        )

    def _validate_privacy_snapshot(
        self,
        snapshot: PrivacyAuditBackupSnapshot,
        target: BundleUpgradeTarget,
        entries: tuple[BackupObjectEntry, ...],
    ) -> None:
        privacy_ids = tuple(ref.object_id for ref in snapshot.privacy_audit_objects)
        manifest_privacy_ids = tuple(
            entry.object_id for entry in entries if entry.kind is ObjectKind.PRIVACY_AUDIT
        )
        if (
            snapshot.origin_installation_id != self._installation_id
            or snapshot.origin_task_id != target.task_id
            or snapshot.privacy_root_generation != target.privacy_root_generation
            or snapshot.privacy_root_digest != target.privacy_root_digest
            or privacy_ids != manifest_privacy_ids
        ):
            raise _backup_failure("privacy_binding", retryable=False)

    def _validate_privacy_sidecar(
        self,
        verified: VerifiedBackupSet,
        target: BundleUpgradeTarget,
    ) -> None:
        try:
            data = _read_private_file(
                verified.privacy_snapshot_path,
                max_bytes=_MAX_BACKUP_SIDECAR_BYTES,
            )
            parsed = strict_json_parse(data)
            if canonical_encode(parsed) != data or type(parsed) is not dict:
                raise ValueError("privacy_snapshot_invalid")
            value = cast(dict[str, object], parsed)
            if (
                value.get("origin_installation_id") != self._installation_id
                or value.get("origin_task_id") != str(target.task_id)
                or value.get("privacy_root_generation") != target.privacy_root_generation
                or value.get("privacy_root_digest") != target.privacy_root_digest
            ):
                raise ValueError("privacy_snapshot_binding_invalid")
        except (OSError, TypeError, ValueError) as exc:
            raise _verification_failure("privacy_snapshot", cause=exc)


async def _unavailable_root_snapshot() -> ObjectRootSnapshot:
    raise RuntimeError("upgrade_object_snapshot_unavailable")


def _bundle_key_fingerprint(keys: BundleKeys) -> str:
    """Return the opaque, stable identity of the loaded bundle key material."""

    if type(keys) is not BundleKeys:
        raise TypeError("bundle_keys_invalid")
    try:
        fingerprint = keys.commitment_key.mac(
            _BUNDLE_KEY_FINGERPRINT_DOMAIN,
            _BUNDLE_KEY_FINGERPRINT_MESSAGE,
        )
        validate_commitment(fingerprint)
    except (KeyStoreError, TypeError, ValueError, RuntimeError) as exc:
        raise ValueError("bundle_key_fingerprint_invalid") from exc
    return fingerprint


# Keep a descriptive production name available to ready-composition code while preserving the
# concrete adapter name used by focused tests and adapters.
ProductionBundleUpgradeEffects = SqliteBundleUpgradeEffects
