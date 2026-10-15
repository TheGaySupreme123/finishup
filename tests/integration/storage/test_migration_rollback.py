"""Migration failure persistence and retry semantics."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import UTC, datetime

import apsw
import pytest

from finishup.adapters.sqlite.maintenance import (
    SqliteMaintenance,
    _AuthorityFacts,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.sqlite.migrations import initialize_bundle, initialize_catalog
from finishup.domain.values import Frontier, request_id, session_id, task_id
from finishup.ports.keys import RecoverySecret
from finishup.ports.maintenance import (
    BackupCommand,
    BackupMode,
    BackupPlan,
    BackupResult,
    MaintenanceError,
    MaintenanceHandle,
    MaintenanceReason,
    MigrationCommand,
    MigrationPlan,
    MigrationResult,
    RestoreCommand,
    RestorePlan,
)
from finishup.ports.privacy import PrivacyAuditObjectRoots
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _id(kind: IdKind, value: int) -> str:
    raw = bytearray(value.to_bytes(16, "big"))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


@dataclass(slots=True)
class _Clock:
    def now_utc(self) -> datetime:
        return datetime(2026, 7, 19, 9, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 0.0


class _Ids:
    def __init__(self) -> None:
        self._next = 900

    def new(self, kind: IdKind) -> str:
        self._next += 1
        return _id(kind, self._next)


@dataclass(slots=True)
class _Procedures:
    plan: MigrationPlan
    facts: _AuthorityFacts

    async def preview_backup(self, command: BackupCommand) -> BackupPlan:
        del command
        raise AssertionError("not used")

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan:
        del command
        raise AssertionError("not used")

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan:
        del command
        return self.plan

    async def authority_facts(
        self,
        command: BackupCommand | RestoreCommand | MigrationCommand,
        plan: BackupPlan | RestorePlan | MigrationPlan,
    ) -> _AuthorityFacts:
        del command, plan
        return self.facts

    async def current_privacy_roots(
        self, task_id: str, route_identity_digest: str
    ) -> PrivacyAuditObjectRoots:
        assert task_id == self.facts.privacy_roots.task_id
        assert route_identity_digest == self.facts.privacy_roots.route_identity_digest
        return self.facts.privacy_roots

    async def backup(
        self,
        handle: object,
        pin: object,
        command: BackupCommand,
        plan: BackupPlan,
        recovery_secret: RecoverySecret | None,
    ) -> BackupResult:
        del handle, pin, command, plan, recovery_secret
        raise AssertionError("not used")

    async def restore(
        self,
        handle: object,
        command: RestoreCommand,
        plan: RestorePlan,
        recovery_secret: RecoverySecret | None,
    ) -> object:
        del handle, command, plan, recovery_secret
        raise AssertionError("not used")

    async def migrate(
        self,
        handle: object,
        command: MigrationCommand,
        plan: MigrationPlan,
    ) -> MigrationResult:
        del handle, command, plan
        raise AssertionError("not used")


@dataclass(slots=True)
class _Harness:
    adapter: SqliteMaintenance
    catalog: apsw.Connection
    procedures: _Procedures
    command: MigrationCommand


def _harness() -> _Harness:
    installation = _id(IdKind.INSTALLATION, 700)
    task = _id(IdKind.TASK, 701)
    session = _id(IdKind.SESSION, 702)
    route_digest = canonical_digest({"route": "active"})
    roots = PrivacyAuditObjectRoots(task, route_digest, 0, (), canonical_digest(()))
    catalog = apsw.Connection(":memory:")
    initialize_catalog(catalog)
    catalog.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation), ("owner_generation", "1")),
    )
    now = "2026-07-19T09:00:00.000Z"
    catalog.execute(
        "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, route_generation, "
        "active_route_identity_digest, state, created_at, updated_at) "
        "VALUES(?, ?, ?, 1, ?, 'active', ?, ?)",
        (task, session, f"tasks/{task}", route_digest, now, now),
    )
    bundle = apsw.Connection(":memory:")
    initialize_bundle(
        bundle,
        {
            "task_id": task,
            "owner_generation": "1",
            "storage_schema_version": "1",
            "protocol_version": "0.1",
        },
    )
    command = MigrationCommand(
        request_id(_id(IdKind.REQUEST, 703)),
        session_id(session),
        "2",
        Frontier.genesis(),
    )
    plan = MigrationPlan(
        canonical_digest({"request": "migration"}),
        task_id(task),
        "1",
        "2",
        Frontier.genesis(),
        ("0002",),
        BackupMode.MACHINE_BOUND,
        (),
        canonical_digest({"plan": "migration"}),
    )
    facts = _AuthorityFacts(
        task_id=task,
        frontier=Frontier.genesis(),
        source_route_identity_digest=route_digest,
        owner_generation=1,
        privacy_roots=roots,
        backup_mode=BackupMode.MACHINE_BOUND,
        requested_target_version="2",
    )
    procedures = _Procedures(plan, facts)
    adapter = SqliteMaintenance(
        catalog,
        bundle,
        installation_id=installation,
        clock=_Clock(),
        ids=_Ids(),
        procedures=procedures,  # pyright: ignore[reportArgumentType]
    )
    return _Harness(adapter, catalog, procedures, command)


async def _acquire(harness: _Harness) -> MaintenanceHandle:
    acquired = await harness.adapter._acquire_maintenance(  # pyright: ignore[reportPrivateUsage]
        harness.command,
        harness.procedures.plan,
        harness.procedures.plan.plan_digest,
    )
    assert type(acquired) is MaintenanceHandle
    return acquired


@pytest.mark.anyio
async def test_failure_before_commit_leaves_original_intact() -> None:
    harness = _harness()
    handle = await _acquire(harness)
    backup_digest = canonical_digest({"backup": 1})

    with pytest.raises(MaintenanceError) as captured:
        harness.adapter.record_migration_failure(
            handle,
            backup_manifest_digest=backup_digest,
            original_verified=True,
            outcome_ambiguous=False,
        )

    assert captured.value.reason is MaintenanceReason.MIGRATION_FAILED
    assert harness.catalog.execute("SELECT bundle_relpath FROM task_routes").fetchone() == (
        f"tasks/{harness.procedures.facts.task_id}",
    )


@pytest.mark.anyio
async def test_failure_after_commit_is_quarantined_not_corrupted() -> None:
    harness = _harness()
    handle = await _acquire(harness)
    backup_digest = canonical_digest({"backup": 2})

    with pytest.raises(MaintenanceError) as captured:
        harness.adapter.record_migration_failure(
            handle,
            backup_manifest_digest=backup_digest,
            original_verified=False,
            outcome_ambiguous=True,
        )

    assert captured.value.reason is MaintenanceReason.ROLLBACK_REQUIRED
    assert harness.catalog.execute(
        "SELECT state, quarantine_code, backup_manifest_digest FROM maintenance_operations"
    ).fetchone() == ("quarantined", "rollback_required", backup_digest)


@pytest.mark.anyio
async def test_retry_is_idempotent_after_rollback() -> None:
    harness = _harness()
    handle = await _acquire(harness)
    backup_digest = canonical_digest({"backup": 3})
    with pytest.raises(MaintenanceError):
        harness.adapter.record_migration_failure(
            handle,
            backup_manifest_digest=backup_digest,
            original_verified=False,
            outcome_ambiguous=True,
        )

    with pytest.raises(MaintenanceError) as replayed:
        await _acquire(harness)

    assert replayed.value.reason is MaintenanceReason.ROLLBACK_REQUIRED
    assert replayed.value.safe_details["backup_manifest_digest"] == backup_digest
    assert harness.catalog.execute("SELECT COUNT(*) FROM maintenance_operations").fetchone() == (1,)
