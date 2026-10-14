"""Automatic bundle-upgrade orchestration over isolated v0.2-style bundle files."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import apsw
import pytest

import yoetz.adapters.sqlite.connection as connection_module
import yoetz.service.bundle_upgrade as bundle_upgrade_module
from yoetz.adapters.sqlite.migrations import BUNDLE_MIGRATIONS, initialize_catalog
from yoetz.domain.values import Frontier, task_id
from yoetz.service.bundle_upgrade import (
    BUNDLE_UPGRADE_TARGET_VERSION,
    BackupEvidence,
    BundleIntegrity,
    BundleUpgradeCoordinator,
    BundleUpgradeError,
    BundleUpgradeOperation,
    BundleUpgradePhase,
    BundleUpgradeReason,
    BundleUpgradeTarget,
    SqliteBundleUpgradeJournal,
)

_INSTALLATION_ID = "ins_00000000-0000-4000-8000-000000000001"
_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000002"
_OTHER_SERVICE_ID = "svc_00000000-0000-4000-8000-000000000003"
_TASK_ID = "tsk_00000000-0000-4000-8000-000000000004"
_SESSION_ID = "ses_00000000-0000-4000-8000-000000000005"
_ROUTE_DIGEST = "sha256:" + "a" * 64
_BACKUP_DIGEST = "sha256:" + "b" * 64
_NOW = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)


@dataclass(slots=True)
class _Clock:
    current: datetime = _NOW

    def now_utc(self) -> datetime:
        return self.current

    def monotonic_seconds(self) -> float:
        return 1.0


@dataclass(slots=True)
class _Effects:
    source_version: int = 12
    fail_replay: bool = False
    backup_error: BundleUpgradeError | None = None
    backups: list[tuple[str | None, BundleIntegrity]] = field(
        default_factory=lambda: cast(list[tuple[str | None, BundleIntegrity]], [])
    )
    replays: list[BundleIntegrity | None] = field(
        default_factory=lambda: cast(list[BundleIntegrity | None], [])
    )

    async def ensure_machine_backup(
        self,
        target: BundleUpgradeTarget,
        _operation: object,
        before: BundleIntegrity,
        existing_manifest_digest: str | None,
    ) -> BackupEvidence:
        if self.backup_error is not None:
            raise self.backup_error
        if existing_manifest_digest is not None:
            assert existing_manifest_digest == _BACKUP_DIGEST
        self.backups.append((existing_manifest_digest, before))
        return BackupEvidence(target.task_id, before.frontier, _BACKUP_DIGEST, self.source_version)

    async def verify_replay(
        self,
        _target: BundleUpgradeTarget,
        before: BundleIntegrity | None,
        after: BundleIntegrity,
        _backup: BackupEvidence,
    ) -> str:
        self.replays.append(before)
        if self.fail_replay:
            raise BundleUpgradeError(
                BundleUpgradeReason.VERIFICATION_FAILED, False, {"check": "replay"}
            )
        return after.projection_digest


@dataclass(slots=True)
class _SuspendingBackupEffects(_Effects):
    started: asyncio.Event = field(default_factory=asyncio.Event)
    release: asyncio.Event = field(default_factory=asyncio.Event)

    async def ensure_machine_backup(
        self,
        target: BundleUpgradeTarget,
        operation: object,
        before: BundleIntegrity,
        existing_manifest_digest: str | None,
    ) -> BackupEvidence:
        self.started.set()
        await self.release.wait()
        return await super().ensure_machine_backup(
            target, operation, before, existing_manifest_digest
        )


def _open_writer(path: Path) -> apsw.Connection:
    database = apsw.Connection(str(path), flags=apsw.SQLITE_OPEN_READWRITE)
    connection_module._configure_writer(database)  # pyright: ignore[reportPrivateUsage]
    database.set_authorizer(connection_module._writer_authorizer)  # pyright: ignore[reportPrivateUsage]
    return database


def _allow_isolated_path(_path: Path) -> None:
    return None


def _build_bundle(path: Path, *, version: int, owner_generation: str = "1") -> None:
    database = apsw.Connection(str(path))
    database.execute("PRAGMA foreign_keys = ON")
    database.execute("PRAGMA trusted_schema = OFF")
    with database:
        for migration in BUNDLE_MIGRATIONS[:version]:
            database.execute(migration.ddl.decode("utf-8"))
        database.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation',?),"
            "('storage_schema_version',?),('protocol_version','0.1'),"
            "('import_schema_version','1')",
            (_TASK_ID, owner_generation, str(version)),
        )
        database.execute("INSERT INTO counters(name,next_value) VALUES('ingestion_sequence',1)")
    database.close()
    path.chmod(0o600)


def _build_legacy_v10(path: Path) -> None:
    database = apsw.Connection(str(path))
    database.execute("PRAGMA foreign_keys = OFF")
    database.execute("PRAGMA trusted_schema = OFF")
    with database:
        for migration in BUNDLE_MIGRATIONS[:9]:
            database.execute(migration.ddl.decode("utf-8"))
        database.execute("DROP TABLE events")
        database.execute(
            "CREATE TABLE events(summary_code TEXT NOT NULL "
            "CHECK(summary_code IN ('delegation_declared'))) STRICT"
        )
        database.execute(
            "INSERT INTO bundle_meta(key,value) VALUES"
            "('task_id',?),('owner_generation','1'),('storage_schema_version','10'),"
            "('protocol_version','0.1'),('import_schema_version','1')",
            (_TASK_ID,),
        )
        database.execute("PRAGMA user_version = 10")
    database.execute("PRAGMA foreign_keys = ON")
    database.close()
    path.chmod(0o600)


def _catalog(bundle_path: Path, *, generation: int = 1) -> apsw.Connection:
    catalog = apsw.Connection(":memory:")
    initialize_catalog(catalog)
    catalog.execute(
        "INSERT OR REPLACE INTO catalog_meta(key,value) VALUES"
        "('installation_id',?),('owner_generation',?)",
        (_INSTALLATION_ID, str(generation)),
    )
    catalog.execute(
        "INSERT INTO task_routes(task_id,active_session_id,bundle_relpath,route_generation,"
        "active_route_identity_digest,state,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
        (
            _TASK_ID,
            _SESSION_ID,
            f"tasks/{_TASK_ID}",
            1,
            _ROUTE_DIGEST,
            "active",
            _NOW.isoformat(),
            _NOW.isoformat(),
        ),
    )
    return catalog


def _target(path: Path, *, catalog_owner_generation: int = 1) -> BundleUpgradeTarget:
    return BundleUpgradeTarget(
        task_id=task_id(_TASK_ID),
        session_id=_SESSION_ID,
        bundle_path=path,
        route_generation=1,
        route_identity_digest=_ROUTE_DIGEST,
        frontier=Frontier.genesis(),
        catalog_owner_generation=catalog_owner_generation,
    )


def _coordinator(
    catalog: apsw.Connection,
    *,
    clock: _Clock,
    effects: _Effects,
    service_id: str = _SERVICE_ID,
    runner: Callable[..., object] | None = None,
    holder_calls: list[tuple[str, ...]] | None = None,
    holder_assertion: Callable[[], None] | None = None,
) -> BundleUpgradeCoordinator:
    calls = [] if holder_calls is None else holder_calls

    @asynccontextmanager
    async def holder(targets: tuple[BundleUpgradeTarget, ...]):
        calls.append(tuple(str(item.task_id) for item in targets))
        yield

    kwargs: dict[str, object] = {
        "catalog": catalog,
        "installation_id": _INSTALLATION_ID,
        "service_instance_id": service_id,
        "clock": clock,
        "effects": effects,
        "acquire_exclusive_holder": holder,
        "open_migration_writer": _open_writer,
    }
    if runner is not None:
        kwargs["migration_runner"] = runner
    if holder_assertion is not None:
        kwargs["assert_exclusive_holder"] = holder_assertion
    return BundleUpgradeCoordinator(**kwargs)  # type: ignore[arg-type]


@pytest.mark.anyio
@pytest.mark.parametrize("source_version", [12, 13, 14, 15])
async def test_supported_upgrade_is_backup_first_idempotent_and_fenced(
    source_version: int,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=source_version)
    catalog = _catalog(bundle)
    target = _target(bundle)
    clock = _Clock()
    effects = _Effects(source_version=source_version)
    holder_calls: list[tuple[str, ...]] = []

    report = await _coordinator(
        catalog,
        clock=clock,
        effects=effects,
        holder_calls=holder_calls,
    ).run_before_ready((target,))

    assert len(report.migrated) == 1
    assert report.migrated[0].from_version == str(source_version)
    assert report.migrated[0].to_version == str(BUNDLE_UPGRADE_TARGET_VERSION)
    assert report.already_current == ()
    assert len(effects.backups) == 1
    assert effects.replays == [effects.backups[0][1]]
    assert holder_calls == [(_TASK_ID,)]
    inspection = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert inspection.execute("PRAGMA user_version").fetchone() == (
            BUNDLE_UPGRADE_TARGET_VERSION,
        )
    finally:
        inspection.close()
    assert catalog.execute(
        "SELECT state,phase,backup_manifest_digest FROM maintenance_operations"
    ).fetchone() == ("complete", "terminal", _BACKUP_DIGEST)

    second = await _coordinator(
        catalog,
        clock=clock,
        effects=effects,
        holder_calls=holder_calls,
    ).run_before_ready((target,))
    assert second.migrated == ()
    assert second.already_current == (_TASK_ID,)
    assert len(effects.backups) == 1
    assert holder_calls == [(_TASK_ID,)]


@pytest.mark.anyio
async def test_unknown_and_future_bundle_versions_still_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    catalog = _catalog(tmp_path / "unknown.sqlite3")

    unknown = tmp_path / "unknown.sqlite3"
    _build_bundle(unknown, version=11)
    with pytest.raises(BundleUpgradeError) as unknown_error:
        await _coordinator(catalog, clock=_Clock(), effects=_Effects()).run_before_ready(
            (_target(unknown),)
        )
    assert unknown_error.value.reason is BundleUpgradeReason.MIGRATION_UNSUPPORTED
    assert not unknown_error.value.retryable

    future = tmp_path / "future.sqlite3"
    _build_bundle(future, version=BUNDLE_UPGRADE_TARGET_VERSION)
    database = _open_writer(future)
    try:
        database.execute("PRAGMA user_version = 17")
        database.execute("UPDATE bundle_meta SET value='17' WHERE key='storage_schema_version'")
    finally:
        database.close(force=True)
    with pytest.raises(BundleUpgradeError) as future_error:
        await _coordinator(catalog, clock=_Clock(), effects=_Effects()).run_before_ready(
            (_target(future),)
        )
    assert future_error.value.reason is BundleUpgradeReason.SCHEMA_NEWER_THAN_BINARY
    assert not future_error.value.retryable


@pytest.mark.anyio
async def test_current_bundle_selection_uses_tail_probe_without_full_hashing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "current.sqlite3"
    _build_bundle(bundle, version=BUNDLE_UPGRADE_TARGET_VERSION)
    catalog = _catalog(bundle)
    target = _target(bundle)

    def unexpected_full_capture(_database: apsw.Connection) -> BundleIntegrity:
        raise AssertionError("full_integrity_capture_on_current_bundle")

    monkeypatch.setattr(bundle_upgrade_module, "capture_sqlite_integrity", unexpected_full_capture)
    report = await _coordinator(catalog, clock=_Clock(), effects=_Effects()).run_before_ready(
        (target,)
    )
    assert report.migrated == ()
    assert report.already_current == (_TASK_ID,)


@pytest.mark.anyio
async def test_fresh_bundle_generation_zero_is_accepted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "fresh.sqlite3"
    _build_bundle(bundle, version=BUNDLE_UPGRADE_TARGET_VERSION, owner_generation="0")
    catalog = _catalog(bundle, generation=3)
    target = _target(bundle, catalog_owner_generation=3)

    report = await _coordinator(catalog, clock=_Clock(), effects=_Effects()).run_before_ready(
        (target,)
    )

    assert report.migrated == ()
    assert report.already_current == (_TASK_ID,)


@pytest.mark.parametrize("owner_generation", ("-1", "01", str(2**53)))
@pytest.mark.anyio
async def test_invalid_bundle_generations_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    owner_generation: str,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / f"invalid-generation-{owner_generation}.sqlite3"
    _build_bundle(bundle, version=BUNDLE_UPGRADE_TARGET_VERSION, owner_generation=owner_generation)
    catalog = _catalog(bundle, generation=3)
    target = _target(bundle, catalog_owner_generation=3)

    with pytest.raises(BundleUpgradeError) as error:
        await _coordinator(catalog, clock=_Clock(), effects=_Effects()).run_before_ready((target,))

    assert error.value.reason is BundleUpgradeReason.SCHEMA_METADATA_DISAGREES
    assert not error.value.retryable


@pytest.mark.anyio
async def test_interrupted_schema_phase_resumes_same_operation_and_backup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    clock = _Clock()
    effects = _Effects()
    attempts = 0

    def fail_once(*_args: object, **_kwargs: object) -> object:
        nonlocal attempts
        attempts += 1
        raise RuntimeError("synthetic_interruption")

    with pytest.raises(BundleUpgradeError) as first_error:
        await _coordinator(
            catalog,
            clock=clock,
            effects=effects,
            runner=fail_once,
        ).run_before_ready((target,))
    assert first_error.value.reason is BundleUpgradeReason.MIGRATION_FAILED
    assert catalog.execute(
        "SELECT state,phase,backup_manifest_digest FROM maintenance_operations"
    ).fetchone() == ("pending", "backup_ready", _BACKUP_DIGEST)
    assert attempts == 1

    report = await _coordinator(catalog, clock=clock, effects=effects).run_before_ready((target,))
    assert len(report.migrated) == 1
    assert effects.backups[1][0] == _BACKUP_DIGEST
    assert catalog.execute("SELECT state,phase FROM maintenance_operations").fetchone() == (
        "complete",
        "terminal",
    )


@pytest.mark.anyio
async def test_committed_schema_with_lost_phase_uses_backup_facts_on_resume(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    # Bundle ownership is a per-bundle monotonic fence.  It is intentionally independent from
    # the catalog/service generation used by the migration journal, including across restart.
    _build_bundle(bundle, version=12, owner_generation="7")
    catalog = _catalog(bundle, generation=3)
    target = _target(bundle, catalog_owner_generation=3)
    clock = _Clock()
    effects = _Effects()
    original_advance = SqliteBundleUpgradeJournal.advance
    failed = False

    def fail_after_schema(
        journal: SqliteBundleUpgradeJournal,
        operation: BundleUpgradeOperation,
        *,
        expected: tuple[BundleUpgradePhase, ...],
        next_phase: BundleUpgradePhase,
        backup_manifest_digest: str | None = None,
    ) -> BundleUpgradeOperation:
        nonlocal failed
        if not failed and next_phase is BundleUpgradePhase.SCHEMA_APPLIED:
            failed = True
            raise BundleUpgradeError(BundleUpgradeReason.OPERATION_LOST, False)
        return original_advance(
            journal,
            operation,
            expected=expected,
            next_phase=next_phase,
            backup_manifest_digest=backup_manifest_digest,
        )

    monkeypatch.setattr(SqliteBundleUpgradeJournal, "advance", fail_after_schema)
    with pytest.raises(BundleUpgradeError) as interruption:
        await _coordinator(catalog, clock=clock, effects=effects).run_before_ready((target,))
    assert interruption.value.reason is BundleUpgradeReason.OPERATION_LOST
    assert catalog.execute("SELECT state,phase FROM maintenance_operations").fetchone() == (
        "pending",
        "backup_ready",
    )

    monkeypatch.setattr(SqliteBundleUpgradeJournal, "advance", original_advance)
    report = await _coordinator(catalog, clock=clock, effects=effects).run_before_ready((target,))
    assert len(report.migrated) == 1
    assert effects.replays[-1] is None


@pytest.mark.anyio
async def test_deterministic_backup_contradiction_is_quarantined_before_ddl(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    effects = _Effects(
        backup_error=BundleUpgradeError(
            BundleUpgradeReason.BACKUP_FAILED,
            False,
            {"check": "manifest_identity"},
        )
    )

    with pytest.raises(BundleUpgradeError) as error:
        await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready((target,))

    assert error.value.reason is BundleUpgradeReason.BACKUP_FAILED
    assert not error.value.retryable
    assert catalog.execute(
        "SELECT state,phase,quarantine_code FROM maintenance_operations"
    ).fetchone() == ("quarantined", "terminal", "backup_failed")
    inspection = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert inspection.execute("PRAGMA user_version").fetchone() == (12,)
    finally:
        inspection.close(force=True)

    with pytest.raises(BundleUpgradeError) as retry:
        await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready((target,))
    assert retry.value.reason is BundleUpgradeReason.ROLLBACK_REQUIRED


@pytest.mark.anyio
async def test_retryable_backup_failure_keeps_pending_operation_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    effects = _Effects(
        backup_error=BundleUpgradeError(
            BundleUpgradeReason.BACKUP_FAILED,
            True,
            {"check": "create"},
        )
    )

    with pytest.raises(BundleUpgradeError) as error:
        await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready((target,))
    assert error.value.reason is BundleUpgradeReason.BACKUP_FAILED
    assert error.value.retryable
    assert catalog.execute(
        "SELECT state,phase,quarantine_code FROM maintenance_operations"
    ).fetchone() == ("pending", "reserved", None)

    effects.backup_error = None
    report = await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready(
        (target,)
    )
    assert len(report.migrated) == 1


@pytest.mark.parametrize(
    ("version", "phase", "expected_reason", "quarantine_code"),
    (
        (
            12,
            BundleUpgradePhase.SCHEMA_APPLIED,
            BundleUpgradeReason.OPERATION_LOST,
            "operation_lost",
        ),
        (
            12,
            BundleUpgradePhase.REPLAY_VERIFIED,
            BundleUpgradeReason.OPERATION_LOST,
            "operation_lost",
        ),
        (
            BUNDLE_UPGRADE_TARGET_VERSION,
            BundleUpgradePhase.RESERVED,
            BundleUpgradeReason.ROLLBACK_REQUIRED,
            "rollback_required",
        ),
    ),
)
@pytest.mark.anyio
async def test_impossible_phase_and_schema_pairs_are_quarantined(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    version: int,
    phase: BundleUpgradePhase,
    expected_reason: BundleUpgradeReason,
    quarantine_code: str,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / f"impossible-{version}-{phase.value}.sqlite3"
    _build_bundle(bundle, version=version)
    catalog = _catalog(bundle)
    target = _target(bundle)
    effects = _Effects()
    coordinator = _coordinator(catalog, clock=_Clock(), effects=effects)
    operation = coordinator._journal.reserve(  # pyright: ignore[reportPrivateUsage]
        target, create_if_absent=True
    )
    assert operation is not None
    backup_manifest_digest = _BACKUP_DIGEST if version == 12 else None
    catalog.execute(
        "UPDATE maintenance_operations SET phase=?, backup_manifest_digest=? "
        "WHERE installation_id=? AND operation_id=?",
        (phase.value, backup_manifest_digest, _INSTALLATION_ID, operation.request_id),
    )

    with pytest.raises(BundleUpgradeError) as error:
        await coordinator.run_before_ready((target,))

    assert error.value.reason is expected_reason
    assert not error.value.retryable
    assert catalog.execute(
        "SELECT state,phase,quarantine_code FROM maintenance_operations"
    ).fetchone() == ("quarantined", "terminal", quarantine_code)
    assert effects.backups == []
    inspection = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert inspection.execute("PRAGMA user_version").fetchone() == (version,)
    finally:
        inspection.close(force=True)


@pytest.mark.anyio
async def test_holder_loss_during_backup_blocks_following_journal_and_ddl_phases(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A singleton release while an effect awaits cannot advance the migration or run DDL."""

    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    effects = _SuspendingBackupEffects()
    holder_lost = False

    def assert_holder() -> None:
        if holder_lost:
            raise RuntimeError("singleton_released")

    upgrade = asyncio.create_task(
        _coordinator(
            catalog,
            clock=_Clock(),
            effects=effects,
            holder_assertion=assert_holder,
        ).run_before_ready((target,))
    )
    await effects.started.wait()
    holder_lost = True
    effects.release.set()
    with pytest.raises(BundleUpgradeError) as error:
        await upgrade

    assert error.value.reason is BundleUpgradeReason.HOLDER_CONFLICT
    assert catalog.execute("SELECT state,phase FROM maintenance_operations").fetchone() == (
        "pending",
        "reserved",
    )
    assert effects.replays == []
    inspection = apsw.Connection(str(bundle), flags=apsw.SQLITE_OPEN_READONLY)
    try:
        assert inspection.execute("PRAGMA user_version").fetchone() == (12,)
    finally:
        inspection.close(force=True)


@pytest.mark.anyio
async def test_live_holder_and_expired_holder_are_distinguished(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    _build_bundle(bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    clock = _Clock()
    effects = _Effects()
    first = _coordinator(catalog, clock=clock, effects=effects)
    operation = first._journal.reserve(target, create_if_absent=True)  # pyright: ignore[reportPrivateUsage]
    assert operation is not None

    with pytest.raises(BundleUpgradeError) as live_error:
        await _coordinator(
            catalog,
            clock=clock,
            effects=effects,
            service_id=_OTHER_SERVICE_ID,
        ).run_before_ready((target,))
    assert live_error.value.reason is BundleUpgradeReason.HOLDER_CONFLICT

    clock.current += timedelta(seconds=61)
    resumed = await _coordinator(
        catalog,
        clock=clock,
        effects=effects,
        service_id=_OTHER_SERVICE_ID,
    ).run_before_ready((target,))
    assert len(resumed.migrated) == 1


@pytest.mark.anyio
async def test_v10_development_shape_fails_closed_before_journal_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "legacy.sqlite3"
    _build_legacy_v10(bundle)
    catalog = _catalog(bundle)
    effects = _Effects()

    with pytest.raises(BundleUpgradeError) as error:
        await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready(
            (_target(bundle),)
        )
    assert error.value.reason is BundleUpgradeReason.SCHEMA_UPGRADE_PATH_UNKNOWN
    assert catalog.execute("SELECT count(*) FROM maintenance_operations").fetchone() == (0,)
    assert effects.backups == []


@pytest.mark.anyio
async def test_post_commit_replay_failure_quarantines_and_restored_v12_is_not_current(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(connection_module, "verify_private_local_bundle", _allow_isolated_path)
    bundle = tmp_path / "ledger.sqlite3"
    old_bundle = tmp_path / "old-v12.sqlite3"
    _build_bundle(bundle, version=12)
    _build_bundle(old_bundle, version=12)
    catalog = _catalog(bundle)
    target = _target(bundle)
    effects = _Effects(fail_replay=True)

    with pytest.raises(BundleUpgradeError) as replay_error:
        await _coordinator(catalog, clock=_Clock(), effects=effects).run_before_ready((target,))
    assert replay_error.value.reason is BundleUpgradeReason.ROLLBACK_REQUIRED
    assert catalog.execute(
        "SELECT state,phase,quarantine_code FROM maintenance_operations"
    ).fetchone() == (
        "quarantined",
        "terminal",
        "rollback_required",
    )

    complete_bundle = tmp_path / "complete.sqlite3"
    complete_old_bundle = tmp_path / "complete-old-v12.sqlite3"
    _build_bundle(complete_bundle, version=12)
    _build_bundle(complete_old_bundle, version=12)
    complete_catalog = _catalog(complete_bundle)
    complete_target = _target(complete_bundle)
    await _coordinator(
        complete_catalog,
        clock=_Clock(),
        effects=_Effects(),
    ).run_before_ready((complete_target,))
    assert complete_catalog.execute(
        "SELECT state,phase FROM maintenance_operations"
    ).fetchone() == (
        "complete",
        "terminal",
    )
    # A terminal completion paired with a restored old file is a durable contradiction.
    # Replacing the isolated test file also exercises the same path a recovery restore uses.
    complete_bundle.write_bytes(complete_old_bundle.read_bytes())
    complete_bundle.chmod(0o600)
    with pytest.raises(BundleUpgradeError) as restored_error:
        await _coordinator(
            complete_catalog,
            clock=_Clock(),
            effects=_Effects(),
        ).run_before_ready((complete_target,))
    assert restored_error.value.reason is BundleUpgradeReason.ROLLBACK_REQUIRED


def test_usage_preservation_digest_normalizes_legacy_nulls_and_detects_counter_changes() -> None:
    from yoetz.service.bundle_upgrade import (
        _stream_table_digest,  # pyright: ignore[reportPrivateUsage]
    )

    db = apsw.Connection(":memory:")
    db.execute("CREATE TABLE semantic_attempts (attempt_id TEXT PRIMARY KEY)")
    db.execute("INSERT INTO semantic_attempts VALUES ('attempt-1')")
    before = _stream_table_digest(db, "semantic_attempts")
    for column in (
        "input_tokens",
        "cached_input_tokens",
        "cache_write_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
    ):
        db.execute(f"ALTER TABLE semantic_attempts ADD COLUMN usage_{column} INTEGER")
    assert _stream_table_digest(db, "semantic_attempts") == before
    db.execute("UPDATE semantic_attempts SET usage_input_tokens=100, usage_total_tokens=100")
    assert _stream_table_digest(db, "semantic_attempts") != before
    db.close()
