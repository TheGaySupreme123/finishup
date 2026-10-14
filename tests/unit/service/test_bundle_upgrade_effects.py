"""Focused tests for the automatic upgrade's bounded backup effects."""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import AsyncGenerator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import apsw
import pytest
from cryptography.hazmat.primitives.keywrap import aes_key_unwrap, aes_key_wrap

import finishup.adapters.sqlite.connection as connection_module
from finishup.adapters.objects.encrypted_files import EncryptedFilesObjectStore
from finishup.adapters.sqlite.maintenance import verify_backup_set
from finishup.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, run_migrations
from finishup.domain.values import Frontier, format_rfc3339_millis, task_id
from finishup.ports.ids import IdPort
from finishup.ports.keys import BundleKeys, WrappedDek
from finishup.ports.maintenance import PrivacyAuditBackupSnapshot
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRootSnapshot, ObjectSource
from finishup.ports.secret_memory import (
    SecretConsumer,
    SecretHandle,
    SecretMemoryCapability,
    SecretMemoryPort,
    SecretPurpose,
)
from finishup.protocol.ids import IdKind
from finishup.service.bundle_upgrade import (
    BundleIntegrity,
    BundleUpgradeOperation,
    BundleUpgradePhase,
    BundleUpgradeState,
    BundleUpgradeTarget,
    capture_sqlite_integrity,
)
from finishup.service.bundle_upgrade_effects import (
    BundleUpgradeFencedLedger,
    SqliteBundleUpgradeEffects,
)

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000004"
_SESSION_ID = "ses_00000000-0000-4000-8000-000000000005"
_REQUEST_ID = "req_00000000-0000-4000-8000-000000000006"
_ROUTE_DIGEST = "sha256:" + "a" * 64
_PLAN_DIGEST = "sha256:" + "b" * 64
_ZERO_DIGEST = "sha256:" + "0" * 64
_NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class _Clock:
    def now_utc(self) -> datetime:
        return _NOW

    def monotonic_seconds(self) -> float:
        return 1.0


@dataclass(slots=True)
class _FencedLedger:
    calls: int = 0
    replay_digest: str | None = None

    async def verify_replay(self, **kwargs: object) -> str:
        self.calls += 1
        digest = self.replay_digest
        if digest is None:
            raise AssertionError("replay_not_used_by_backup")
        after = cast(BundleIntegrity, kwargs["after"])
        assert digest == after.projection_digest
        return digest


class _Secret:
    def __init__(self, value: bytes | bytearray) -> None:
        self._value = bytearray(value)
        self._consumed = False

    @property
    def purpose(self) -> SecretPurpose:
        return SecretPurpose.OBJECT_PAYLOAD

    def consume[T](self, consumer: SecretConsumer, fn: Callable[[memoryview], T]) -> T:
        if consumer is not SecretConsumer.OBJECT_CRYPTO or self._consumed:
            raise ValueError("secret_handle_invalid")
        self._consumed = True
        try:
            return fn(memoryview(self._value))
        finally:
            self._value[:] = b"\0" * len(self._value)


class _SecretMemory:
    def capability(self) -> SecretMemoryCapability:
        return SecretMemoryCapability("active", "unavailable", "unavailable", "active", "active")

    def capture(self, purpose: SecretPurpose, source: bytearray) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        result = _Secret(source)
        source[:] = b"\0" * len(source)
        return result

    def allocate(self, purpose: SecretPurpose, size: int) -> _Secret:
        assert purpose is SecretPurpose.OBJECT_PAYLOAD
        return _Secret(bytes(size))

    def close(self) -> None:
        return None


class _WrapKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def wrap_dek(self, dek: SecretHandle) -> WrappedDek:
        wrapped = dek.consume(
            SecretConsumer.OBJECT_CRYPTO,
            lambda value: aes_key_wrap(self._key, bytes(value)),
        )
        return WrappedDek("aes-256-kw-rfc3394", wrapped)

    def unwrap_dek(self, wrapped: WrappedDek) -> _Secret:
        return _Secret(aes_key_unwrap(self._key, wrapped.wrapped))


class _MacKey:
    def __init__(self, key: bytes) -> None:
        self._key = key

    def mac(self, domain: bytes, message: bytes) -> str:
        return "hmac-sha256:" + hmac.new(self._key, domain + message, hashlib.sha256).hexdigest()


class _Ids:
    def __init__(self) -> None:
        self._next = 1

    def new(self, kind: IdKind) -> str:
        assert kind is IdKind.OBJECT
        value = f"obj_{self._next:08x}-0000-4000-8000-000000000001"
        self._next += 1
        return value


def _build_bundle(path: Path) -> None:
    database = apsw.Connection(str(path))
    database.execute("PRAGMA foreign_keys = ON")
    database.execute("PRAGMA trusted_schema = OFF")
    with database:
        for migration in BUNDLE_MIGRATIONS[:12]:
            database.execute(migration.ddl.decode("utf-8"))
        database.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),"
            "('storage_schema_version','12'),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID,),
        )
        database.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    database.close()
    path.chmod(0o600)


def _target(path: Path) -> BundleUpgradeTarget:
    return BundleUpgradeTarget(
        task_id=task_id(_TASK_ID),
        session_id=_SESSION_ID,
        bundle_path=path,
        route_generation=1,
        route_identity_digest=_ROUTE_DIGEST,
        frontier=Frontier.genesis(),
        catalog_owner_generation=1,
    )


def _operation() -> BundleUpgradeOperation:
    return BundleUpgradeOperation(
        request_id=_REQUEST_ID,
        task_id=task_id(_TASK_ID),
        route_identity_digest=_ROUTE_DIGEST,
        plan_digest=_PLAN_DIGEST,
        phase=BundleUpgradePhase.RESERVED,
        state=BundleUpgradeState.PENDING,
        backup_manifest_digest=None,
    )


def _snapshot() -> PrivacyAuditBackupSnapshot:
    return PrivacyAuditBackupSnapshot(
        origin_installation_id=_INSTALLATION_ID,
        origin_task_id=task_id(_TASK_ID),
        catalog_version="1",
        audit_store_version="1",
        privacy_root_generation=0,
        privacy_root_digest=_ZERO_DIGEST,
        audit_rows=(),
        terminal_receipts=(),
        privacy_audit_objects=(),
    )


def _before(path: Path) -> BundleIntegrity:
    database = apsw.Connection(str(path), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        return capture_sqlite_integrity(database)
    finally:
        database.close(force=True)


def _keys() -> BundleKeys:
    return BundleKeys(
        "bmk-1",
        _WrapKey(bytes(range(32))),
        _MacKey(bytes(range(32, 64))),
    )


def _allow_private_local_bundle(_path: Path) -> None:
    return None


async def _unused_root_snapshot() -> ObjectRootSnapshot:
    raise RuntimeError("root_snapshot_not_used")


@pytest.mark.anyio
async def test_machine_backup_is_online_manifest_last_and_reopenable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connection_module, "verify_private_local_bundle", _allow_private_local_bundle
    )
    bundle = tmp_path / "ledger.sqlite3"
    backup_root = tmp_path / "upgrade-backups"
    _build_bundle(bundle)
    target = _target(bundle)
    operation = _operation()
    before = _before(bundle)

    fenced = _FencedLedger()
    entered: list[str] = []

    @asynccontextmanager
    async def open_fenced(
        _target: BundleUpgradeTarget,
    ) -> AsyncGenerator[BundleUpgradeFencedLedger]:
        entered.append("entered")
        yield fenced

    async def load_privacy(
        _target: BundleUpgradeTarget, _before: object
    ) -> PrivacyAuditBackupSnapshot:
        return _snapshot()

    async def load_keys(_task: str) -> BundleKeys:
        return _keys()

    effects = SqliteBundleUpgradeEffects(
        backup_root=backup_root,
        installation_id=_INSTALLATION_ID,
        load_bundle_keys=load_keys,
        secret_memory=cast(SecretMemoryPort, object()),
        ids=cast(IdPort, object()),
        open_temporary_fenced_ledger=open_fenced,
        load_privacy_snapshot=load_privacy,
        clock=_Clock(),
    )

    evidence = await effects.ensure_machine_backup(target, operation, before, None)
    assert evidence.task_id == target.task_id
    assert evidence.frontier == before.frontier
    assert entered == ["entered"]
    final = backup_root / _TASK_ID / _REQUEST_ID
    assert (final / "backup-manifest.json").is_file()
    assert not (final / "ledger.sqlite3-wal").exists()
    assert not (final / "ledger.sqlite3-shm").exists()
    manifest = verify_backup_set(final).manifest
    expected_fingerprint = (
        "hmac-sha256:"
        + hmac.new(
            bytes(range(32, 64)),
            b"yoetz/object/bundle_key_fingerprint/v1\x00machine-bound-backup\x00",
            hashlib.sha256,
        ).hexdigest()
    )
    assert manifest.key_fingerprint == expected_fingerprint

    reopened = await effects.ensure_machine_backup(
        target,
        operation,
        before,
        evidence.manifest_digest,
    )
    assert reopened == evidence
    assert entered == ["entered"]


@pytest.mark.anyio
async def test_wal_source_backup_has_no_owned_sidecars_after_integrity_probe(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The owned snapshot is checkpointed before its manifest becomes publishable."""

    monkeypatch.setattr(
        connection_module, "verify_private_local_bundle", _allow_private_local_bundle
    )
    bundle = tmp_path / "ledger.sqlite3"
    backup_root = tmp_path / "upgrade-backups"
    _build_bundle(bundle)
    source_writer = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READWRITE)
    try:
        assert source_writer.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        with source_writer:
            source_writer.execute("INSERT INTO counters(name,next_value) VALUES('wal_probe', 2)")
        source_wal = bundle.with_name(bundle.name + "-wal")
        assert source_wal.is_file()

        target = _target(bundle)
        operation = _operation()
        before = _before(bundle)

        @asynccontextmanager
        async def open_fenced(
            _target: BundleUpgradeTarget,
        ) -> AsyncGenerator[BundleUpgradeFencedLedger]:
            yield _FencedLedger()

        async def load_privacy(
            _target: BundleUpgradeTarget, _before: BundleIntegrity
        ) -> PrivacyAuditBackupSnapshot:
            return _snapshot()

        async def load_keys(_task: str) -> BundleKeys:
            return _keys()

        effects = SqliteBundleUpgradeEffects(
            backup_root=backup_root,
            installation_id=_INSTALLATION_ID,
            load_bundle_keys=load_keys,
            secret_memory=cast(SecretMemoryPort, object()),
            ids=cast(IdPort, object()),
            open_temporary_fenced_ledger=open_fenced,
            load_privacy_snapshot=load_privacy,
            clock=_Clock(),
        )

        evidence = await effects.ensure_machine_backup(target, operation, before, None)
        final = backup_root / _TASK_ID / _REQUEST_ID
        assert verify_backup_set(final).manifest.manifest_digest == evidence.manifest_digest
        assert not (final / "ledger.sqlite3-wal").exists()
        assert not (final / "ledger.sqlite3-shm").exists()
        assert source_wal.is_file()
    finally:
        source_writer.close(force=True)


@pytest.mark.anyio
async def test_incomplete_previous_set_is_retained_before_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connection_module, "verify_private_local_bundle", _allow_private_local_bundle
    )
    bundle = tmp_path / "ledger.sqlite3"
    backup_root = tmp_path / "upgrade-backups"
    _build_bundle(bundle)
    target = _target(bundle)
    operation = _operation()
    before = _before(bundle)

    final = backup_root / _TASK_ID / _REQUEST_ID
    final.mkdir(parents=True, mode=0o700)
    backup_root.chmod(0o700)
    final.parent.chmod(0o700)
    (final / "partial").write_bytes(b"partial")
    (final / "partial").chmod(0o600)

    @asynccontextmanager
    async def open_fenced(
        _target: BundleUpgradeTarget,
    ) -> AsyncGenerator[BundleUpgradeFencedLedger]:
        yield _FencedLedger()

    async def load_privacy(
        _target: BundleUpgradeTarget, _before: object
    ) -> PrivacyAuditBackupSnapshot:
        return _snapshot()

    async def load_keys(_task: str) -> BundleKeys:
        return _keys()

    effects = SqliteBundleUpgradeEffects(
        backup_root=backup_root,
        installation_id=_INSTALLATION_ID,
        load_bundle_keys=load_keys,
        secret_memory=cast(SecretMemoryPort, object()),
        ids=cast(IdPort, object()),
        open_temporary_fenced_ledger=open_fenced,
        load_privacy_snapshot=load_privacy,
        clock=_Clock(),
    )

    evidence = await effects.ensure_machine_backup(target, operation, before, None)
    assert evidence.manifest_digest.startswith("sha256:")
    retained = tuple(path for path in final.parent.iterdir() if ".invalid." in path.name)
    assert len(retained) == 1


@pytest.mark.anyio
async def test_backup_authenticates_and_copies_present_encrypted_objects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        connection_module, "verify_private_local_bundle", _allow_private_local_bundle
    )
    bundle = tmp_path / "ledger.sqlite3"
    backup_root = tmp_path / "upgrade-backups"
    _build_bundle(bundle)

    ids = _Ids()
    keys = _keys()
    object_store = EncryptedFilesObjectStore(
        bundle_root=tmp_path,
        bundle_keys=keys,
        secret_memory=_SecretMemory(),
        id_port=ids,
        current_root_snapshot=_unused_root_snapshot,
    )
    metadata = ObjectMetadata(
        ObjectKind.CAPTURED_CONTENT,
        "application/octet-stream",
        _TASK_ID,
        _NOW,
    )
    reference = await object_store.finalize(
        await object_store.stage(ObjectSource(data=b"captured"), metadata)
    )
    database = apsw.Connection(str(bundle))
    try:
        database.execute(
            "INSERT INTO objects(object_id,kind,plaintext_size,commitment,envelope_digest,"
            "encryption_format,key_slot,state,durable_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (
                reference.object_id,
                reference.metadata.kind.value,
                reference.plaintext_size,
                reference.commitment,
                reference.envelope_digest,
                reference.encryption_format,
                reference.key_slot,
                "present",
                format_rfc3339_millis(_NOW),
            ),
        )
    finally:
        database.close()

    target = _target(bundle)
    operation = _operation()
    before = _before(bundle)
    fenced = _FencedLedger(replay_digest=before.projection_digest)

    @asynccontextmanager
    async def open_fenced(
        _target: BundleUpgradeTarget,
    ) -> AsyncGenerator[BundleUpgradeFencedLedger]:
        yield fenced

    async def load_privacy(
        _target: BundleUpgradeTarget, _before: BundleIntegrity
    ) -> PrivacyAuditBackupSnapshot:
        return _snapshot()

    async def load_keys(_task: str) -> BundleKeys:
        return keys

    effects = SqliteBundleUpgradeEffects(
        backup_root=backup_root,
        installation_id=_INSTALLATION_ID,
        load_bundle_keys=load_keys,
        secret_memory=_SecretMemory(),
        ids=ids,
        open_temporary_fenced_ledger=open_fenced,
        load_privacy_snapshot=load_privacy,
        clock=_Clock(),
    )

    evidence = await effects.ensure_machine_backup(target, operation, before, None)
    final = backup_root / _TASK_ID / _REQUEST_ID
    manifest = verify_backup_set(final).manifest
    assert manifest.objects[0].object_id == reference.object_id
    verified = await effects.ensure_machine_backup(
        target, operation, before, evidence.manifest_digest
    )
    assert verified == evidence
    replay_digest = await effects.verify_replay(target, before, before, evidence)
    assert replay_digest == before.projection_digest
    assert fenced.calls == 1
    assert (final / "objects" / reference.object_id).is_file()

    database = apsw.Connection(str(bundle))
    try:
        run_migrations(database, BUNDLE_MIGRATIONS, maintenance=None)
    finally:
        database.close(force=True)
    after = _before(bundle)
    fenced.replay_digest = after.projection_digest

    # A process restart after the 0014 DDL leaves no in-memory v12 facts.  The effects layer must
    # still compare the immutable backup to the post-DDL snapshot before accepting replay.
    replay_after_restart = await effects.verify_replay(target, None, after, evidence)
    assert replay_after_restart == before.projection_digest
    assert fenced.calls == 2
