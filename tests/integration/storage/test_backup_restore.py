"""Focused backup-set, pin fault-boundary, and route-switch integration tests."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import apsw
import pytest

from finishup.adapters.sqlite.maintenance import (
    RestoredTargetEvidence,
    SqliteMaintenance,
    _AuthorityFacts,  # pyright: ignore[reportPrivateUsage]
    _manifest_value,  # pyright: ignore[reportPrivateUsage]
    _RestoredTarget,  # pyright: ignore[reportPrivateUsage]
    build_backup_manifest,
    verify_backup_set,
)
from finishup.adapters.sqlite.migrations import initialize_bundle, initialize_catalog
from finishup.domain.coordination import ProjectTextRef
from finishup.domain.values import (
    Frontier,
    JsonObject,
    Timestamp,
    request_id,
    session_id,
    task_id,
)
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
    MaintenanceLocation,
    MaintenanceReason,
    MigrationCommand,
    MigrationPlan,
    MigrationResult,
    RestoreCommand,
    RestorePlan,
    RestoreResult,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.privacy import PrivacyAuditObjectRoots
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.ids import PREFIX_BY_KIND, IdKind


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _id(kind: IdKind, value: int) -> str:
    raw = bytearray(value.to_bytes(16, "big"))
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return PREFIX_BY_KIND[kind] + str(uuid.UUID(bytes=bytes(raw)))


def _digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _commitment(seed: int) -> str:
    return "hmac-sha256:" + f"{seed:064x}"


@dataclass(slots=True)
class _Clock:
    current: datetime

    def now_utc(self) -> datetime:
        return self.current

    def monotonic_seconds(self) -> float:
        return 0.0


class _Ids:
    def __init__(self) -> None:
        self._next = 900

    def new(self, kind: IdKind) -> str:
        self._next += 1
        return _id(kind, self._next)


def _privacy_ref(task: str, seed: int) -> ObjectRef:
    object_id = _id(IdKind.OBJECT, seed)
    return ObjectRef(
        object_id=object_id,
        metadata=ObjectMetadata(
            task_id=task,
            kind=ObjectKind.PRIVACY_AUDIT,
            media_type="application/vnd.yoetz.privacy-audit+json",
            created_at=datetime(2026, 7, 19, 9, 0, tzinfo=UTC),
        ),
        plaintext_size=8,
        commitment=_commitment(seed),
        envelope_digest=_digest(f"privacy-{seed}".encode()),
        encryption_format="yoetz-object/1",
        key_slot="bundle-key-1",
    )


def _roots(task: str, route_digest: str, *, generation: int = 3) -> PrivacyAuditObjectRoots:
    refs = (_privacy_ref(task, 401),)
    return PrivacyAuditObjectRoots(
        task_id=task,
        route_identity_digest=route_digest,
        privacy_root_generation=generation,
        object_refs=refs,
        root_set_digest=canonical_digest(
            tuple(
                {
                    "object_id": ref.object_id,
                    "envelope_digest": ref.envelope_digest,
                }
                for ref in refs
            )
        ),
    )


def _owner_only_file(path: Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(0o600)


def _backup_set(tmp_path: Path) -> tuple[Path, BackupManifest, BackupObjectEntry]:
    root = tmp_path / "backup"
    root.mkdir(mode=0o700)
    objects_dir = root / "objects"
    objects_dir.mkdir(mode=0o700)
    task = _id(IdKind.TASK, 10)

    database_path = root / "ledger.sqlite3"
    database = apsw.Connection(str(database_path))
    initialize_bundle(
        database,
        {
            "task_id": task,
            "owner_generation": "1",
            "storage_schema_version": "2",
            "protocol_version": "0.1",
        },
    )
    database.close(force=True)
    database_path.chmod(0o600)
    database_bytes = database_path.read_bytes()

    object_id = _id(IdKind.OBJECT, 401)
    object_bytes = b"ciphertext-envelope"
    _owner_only_file(objects_dir / object_id, object_bytes)
    entry = BackupObjectEntry(
        object_id=object_id,
        kind=ObjectKind.PRIVACY_AUDIT,
        envelope_digest=_digest(object_bytes),
        envelope_size=len(object_bytes),
    )
    root_digest = canonical_digest(
        ({"object_id": object_id, "envelope_digest": entry.envelope_digest},)
    )
    sidecar = canonical_encode(
        {
            "origin_installation_id": _id(IdKind.INSTALLATION, 11),
            "origin_task_id": task,
            "catalog_version": "1",
            "audit_store_version": "1",
            "privacy_root_generation": 3,
            "privacy_root_digest": root_digest,
            "audit_rows": (),
            "terminal_receipts": (),
            "privacy_audit_objects": ({"object_id": object_id},),
        }
    )
    _owner_only_file(root / "privacy-audit-snapshot.json", sidecar)
    timestamp = Timestamp("2026-07-19T09:00:00.000Z")
    manifest = build_backup_manifest(
        backup_format="1",
        request_id_value=_id(IdKind.REQUEST, 12),
        task_id_value=task,
        frontier=Frontier.genesis(),
        database_size=len(database_bytes),
        database_digest=_digest(database_bytes),
        objects=(entry,),
        version_manifest=JsonObject({"protocol": "0.1", "storage": "2"}),
        mode=BackupMode.MACHINE_BOUND,
        key_fingerprint="key.test",
        key_locator_classification="machine_bound",
        recovery_artifact_digest=None,
        recovery_kdf_policy=None,
        privacy_audit_snapshot_size=len(sidecar),
        privacy_audit_snapshot_digest=_digest(sidecar),
        privacy_root_generation=3,
        privacy_root_digest=root_digest,
        audit_store_version="1",
        privacy_audit_row_count=0,
        privacy_audit_object_count=1,
        created_at=timestamp,
        completed_at=timestamp,
    )
    _owner_only_file(
        root / "backup-manifest.json",
        canonical_encode(_manifest_value(manifest, include_self_digest=True)),
    )
    return root, manifest, entry


def test_backup_pins_and_captures_manifest(tmp_path: Path) -> None:
    root, manifest, entry = _backup_set(tmp_path)

    verified = verify_backup_set(root, str(manifest.task_id))

    assert verified.manifest == manifest
    assert verified.manifest.objects == (entry,)
    assert verified.backup_set_digest.startswith("sha256:")


def test_restore_verifies_manifest_keys_and_objects(tmp_path: Path) -> None:
    root, manifest, entry = _backup_set(tmp_path)
    object_path = root / "objects" / entry.object_id
    object_path.write_bytes(b"tampered")
    object_path.chmod(0o600)

    with pytest.raises(MaintenanceError) as captured:
        verify_backup_set(root, str(manifest.task_id))

    assert captured.value.reason is MaintenanceReason.OBJECT_TAMPERED


@pytest.mark.anyio
async def test_active_maintenance_lease_is_not_stolen() -> None:
    harness = _harness()
    harness.procedures.facts = _AuthorityFacts(
        task_id=harness.procedures.facts.task_id,
        frontier=Frontier.genesis(),
        source_route_identity_digest=harness.procedures.facts.source_route_identity_digest,
        owner_generation=1,
        privacy_roots=harness.procedures.roots,
        backup_mode=BackupMode.MACHINE_BOUND,
        target_location_commitment=harness.procedures.backup_plan.destination_commitment,
    )
    acquired = await harness.adapter._acquire_maintenance(  # pyright: ignore[reportPrivateUsage]
        harness.backup_command,
        harness.procedures.backup_plan,
        harness.procedures.backup_plan.plan_digest,
    )
    assert type(acquired) is MaintenanceHandle

    with pytest.raises(MaintenanceError) as captured:
        await harness.adapter._acquire_maintenance(  # pyright: ignore[reportPrivateUsage]
            harness.backup_command,
            harness.procedures.backup_plan,
            harness.procedures.backup_plan.plan_digest,
        )

    assert captured.value.reason is MaintenanceReason.MAINTENANCE_BUSY
    assert captured.value.retryable is True
    assert harness.catalog.execute(
        "SELECT lease_generation FROM maintenance_operations"
    ).fetchone() == (1,)


def test_backup_rejects_objects_directory_symlink(tmp_path: Path) -> None:
    root, manifest, _entry = _backup_set(tmp_path)
    objects = root / "objects"
    outside = tmp_path / "outside-objects"
    objects.rename(outside)
    objects.symlink_to(outside, target_is_directory=True)

    with pytest.raises(MaintenanceError) as captured:
        verify_backup_set(root, str(manifest.task_id))

    assert captured.value.reason is MaintenanceReason.SOURCE_INVALID


def test_backup_rejects_privacy_snapshot_object_not_in_manifest(tmp_path: Path) -> None:
    root, manifest, _entry = _backup_set(tmp_path)
    sidecar_path = root / "privacy-audit-snapshot.json"
    sidecar = {
        "origin_installation_id": _id(IdKind.INSTALLATION, 11),
        "origin_task_id": str(manifest.task_id),
        "catalog_version": "1",
        "audit_store_version": "1",
        "privacy_root_generation": 3,
        "privacy_root_digest": manifest.privacy_root_digest,
        "audit_rows": (),
        "terminal_receipts": (),
        "privacy_audit_objects": ({"object_id": _id(IdKind.OBJECT, 402)},),
    }
    sidecar_bytes = canonical_encode(sidecar)
    _owner_only_file(sidecar_path, sidecar_bytes)
    rewritten = replace(
        manifest,
        privacy_audit_snapshot_size=len(sidecar_bytes),
        privacy_audit_snapshot_digest=_digest(sidecar_bytes),
        manifest_digest="sha256:" + "0" * 64,
    )
    rewritten = replace(
        rewritten,
        manifest_digest=canonical_digest(_manifest_value(rewritten, include_self_digest=False)),
    )
    _owner_only_file(
        root / "backup-manifest.json",
        canonical_encode(_manifest_value(rewritten, include_self_digest=True)),
    )

    with pytest.raises(MaintenanceError) as captured:
        verify_backup_set(root, str(manifest.task_id))

    assert captured.value.reason is MaintenanceReason.MANIFEST_INVALID


def test_backup_includes_privacy_catalog_roots_and_sidecar(tmp_path: Path) -> None:
    root, _manifest, entry = _backup_set(tmp_path)

    verified = verify_backup_set(root)

    assert entry.kind is ObjectKind.PRIVACY_AUDIT
    assert verified.manifest.privacy_audit_object_count == 1
    assert verified.privacy_snapshot_path.name == "privacy-audit-snapshot.json"


def test_restored_target_rejects_unscoped_staging_paths() -> None:
    harness = _harness()
    restored = harness.procedures.restored
    for path in (
        "tasks/../outside",
        "tasks/restore-a/b",
        "tasks/restore-",
        "tasks/restore-\\windows",
    ):
        with pytest.raises(ValueError, match="restored_target_invalid"):
            _RestoredTarget(
                restored.evidence,
                restored.result,
                path,
                restored.privacy_reconciled,
            )


@pytest.mark.anyio
async def test_restore_rejects_target_from_another_owner_generation() -> None:
    harness = _harness()
    current = harness.procedures.restored
    harness.procedures.restored = _RestoredTarget(
        replace(current.evidence, owner_generation=current.evidence.owner_generation + 1),
        current.result,
        current.bundle_relpath,
        current.privacy_reconciled,
    )

    with pytest.raises(MaintenanceError) as captured:
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )

    assert captured.value.reason is MaintenanceReason.REPLAY_MISMATCH
    assert harness.catalog.execute(
        "SELECT route_generation FROM task_routes WHERE task_id = ?",
        (harness.procedures.facts.task_id,),
    ).fetchone() == (1,)


@dataclass(slots=True)
class _Procedures:
    backup_plan: BackupPlan
    restore_plan: RestorePlan
    migration_plan: MigrationPlan
    facts: _AuthorityFacts
    roots: PrivacyAuditObjectRoots
    restored: _RestoredTarget

    async def preview_backup(self, command: BackupCommand) -> BackupPlan:
        del command
        return self.backup_plan

    async def preview_restore(self, command: RestoreCommand) -> RestorePlan:
        del command
        return self.restore_plan

    async def preview_migration(self, command: MigrationCommand) -> MigrationPlan:
        del command
        return self.migration_plan

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
        assert task_id == self.roots.task_id
        assert route_identity_digest == self.roots.route_identity_digest
        return self.roots

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
    ) -> _RestoredTarget:
        del handle, command, plan, recovery_secret
        return self.restored

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
    bundle: apsw.Connection
    procedures: _Procedures
    restore_command: RestoreCommand
    backup_command: BackupCommand


def _harness() -> _Harness:
    installation = _id(IdKind.INSTALLATION, 200)
    task = _id(IdKind.TASK, 201)
    session = _id(IdKind.SESSION, 202)
    old_route = canonical_digest({"route": "old"})
    new_route = canonical_digest({"route": "new"})
    roots = _roots(task, old_route)
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
        (task, session, f"tasks/{task}", old_route, now, now),
    )
    catalog.execute(
        "INSERT INTO privacy_root_sets(task_id, route_identity_digest, root_generation, "
        "root_count, root_digest, updated_at) VALUES(?, ?, ?, ?, ?, ?)",
        (task, old_route, roots.privacy_root_generation, 1, roots.root_set_digest, now),
    )
    bundle = apsw.Connection(":memory:")
    initialize_bundle(
        bundle,
        {
            "task_id": task,
            "owner_generation": "1",
            "storage_schema_version": "2",
            "protocol_version": "0.1",
        },
    )
    backup_request = _id(IdKind.REQUEST, 203)
    backup_request_digest = canonical_digest({"request": "backup"})
    backup_plan_digest = canonical_digest({"plan": "backup"})
    backup_command = BackupCommand(
        request_id(backup_request),
        session_id(session),
        MaintenanceLocation("/private/tmp/finishup-backup-test"),
        BackupMode.MACHINE_BOUND,
        Frontier.genesis(),
    )
    backup_plan = BackupPlan(
        backup_request_digest,
        task_id(task),
        Frontier.genesis(),
        BackupMode.MACHINE_BOUND,
        _commitment(301),
        1,
        8,
        1,
        canonical_digest({"sidecar": 1}),
        JsonObject({"protocol": "0.1"}),
        (),
        backup_plan_digest,
    )
    restore_request = _id(IdKind.REQUEST, 204)
    restore_request_digest = canonical_digest({"request": "restore"})
    restore_plan_digest = canonical_digest({"plan": "restore"})
    restore_command = RestoreCommand(
        request_id(restore_request),
        MaintenanceLocation("/private/tmp/finishup-restore-source"),
        "new_route_only",
        BackupMode.MACHINE_BOUND,
        task_id(task),
        Frontier.genesis(),
    )
    restore_plan = RestorePlan(
        restore_request_digest,
        canonical_digest({"manifest": 1}),
        task_id(task),
        Frontier.genesis(),
        Frontier.genesis(),
        new_route,
        BackupMode.MACHINE_BOUND,
        False,
        (),
        restore_plan_digest,
    )
    migration_plan = MigrationPlan(
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
    completed = Timestamp(now)
    restore_result = RestoreResult(
        request_id(restore_request),
        task_id(task),
        Frontier.genesis(),
        old_route,
        new_route,
        restore_plan.source_manifest_digest,
        canonical_digest({"replay": 1}),
        completed,
    )
    restored = _RestoredTarget(
        evidence=RestoredTargetEvidence(
            task_id=task,
            frontier=Frontier.genesis(),
            head_digest="genesis",
            replay_digest=restore_result.replay_digest,
            object_set_digest=canonical_digest({"objects": 1}),
            key_fingerprint="key.test",
            storage_version="1",
            route_identity_digest=new_route,
            owner_generation=1,
        ),
        result=restore_result,
        bundle_relpath="tasks/restore-verified-target",
        privacy_reconciled=True,
    )
    facts = _AuthorityFacts(
        task_id=task,
        frontier=Frontier.genesis(),
        source_route_identity_digest=old_route,
        owner_generation=1,
        privacy_roots=roots,
        backup_mode=BackupMode.MACHINE_BOUND,
        source_location_commitment=_commitment(302),
        target_route_identity_digest=new_route,
    )
    procedures = _Procedures(backup_plan, restore_plan, migration_plan, facts, roots, restored)
    adapter = SqliteMaintenance(
        catalog,
        bundle,
        installation_id=installation,
        clock=_Clock(datetime(2026, 7, 19, 9, 0, tzinfo=UTC)),
        ids=_Ids(),
        procedures=procedures,
    )
    return _Harness(adapter, catalog, bundle, procedures, restore_command, backup_command)


@pytest.mark.anyio
async def test_restore_switches_routes_atomically() -> None:
    harness = _harness()

    result = await harness.adapter.restore(
        harness.restore_command,
        confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
        recovery_secret=None,
    )

    route = harness.catalog.execute(
        "SELECT bundle_relpath, active_route_identity_digest FROM task_routes"
    ).fetchone()
    retained = harness.catalog.execute(
        "SELECT bundle_relpath, state FROM retained_task_routes"
    ).fetchone()
    assert route == ("tasks/restore-verified-target", result.active_route_identity_digest)
    assert retained == (f"tasks/{result.task_id}", "retained")


@pytest.mark.anyio
async def test_restore_route_switch_replay_completes_after_crash() -> None:
    harness = _harness()
    original_complete = harness.adapter._complete  # pyright: ignore[reportPrivateUsage]

    def crash_after_route_switch(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("fault_after_route_switch")

    harness.adapter._complete = crash_after_route_switch  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="fault_after_route_switch"):
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )
    assert harness.catalog.execute(
        "SELECT state, phase FROM maintenance_operations"
    ).fetchone() == ("pending", "route_switched")

    target_route = harness.procedures.restored.evidence.route_identity_digest
    target_roots = _roots(str(harness.procedures.facts.task_id), target_route)
    harness.procedures.roots = target_roots
    harness.procedures.facts = replace(
        harness.procedures.facts,
        source_route_identity_digest=target_route,
        privacy_roots=target_roots,
    )
    harness.catalog.execute(
        "UPDATE maintenance_operations SET lease_expires_at = ?",
        ("2026-07-19T08:59:59.000Z",),
    )
    harness.adapter._complete = original_complete  # type: ignore[method-assign]

    result = await harness.adapter.restore(
        harness.restore_command,
        confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
        recovery_secret=None,
    )

    assert result.active_route_identity_digest == target_route
    assert harness.catalog.execute(
        "SELECT state, phase FROM maintenance_operations"
    ).fetchone() == ("complete", "terminal")
    assert harness.catalog.execute(
        "SELECT COUNT(*) FROM retained_task_routes WHERE retained_by_operation_id = ?",
        (str(harness.restore_command.request_id),),
    ).fetchone() == (1,)


@pytest.mark.anyio
async def test_restore_route_switch_replay_rejects_deleted_privacy_root() -> None:
    harness = _harness()
    original_complete = harness.adapter._complete  # pyright: ignore[reportPrivateUsage]

    def crash_after_route_switch(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("fault_after_route_switch")

    harness.adapter._complete = crash_after_route_switch  # type: ignore[method-assign]
    with pytest.raises(RuntimeError, match="fault_after_route_switch"):
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )

    target_route = harness.procedures.restored.evidence.route_identity_digest
    target_roots = _roots(str(harness.procedures.facts.task_id), target_route)
    harness.procedures.roots = target_roots
    harness.procedures.facts = replace(
        harness.procedures.facts,
        source_route_identity_digest=target_route,
        privacy_roots=target_roots,
    )
    harness.catalog.execute(
        "DELETE FROM privacy_root_sets WHERE task_id = ?", (str(target_roots.task_id),)
    )
    harness.catalog.execute(
        "UPDATE maintenance_operations SET lease_expires_at = ?",
        ("2026-07-19T08:59:59.000Z",),
    )
    harness.adapter._complete = original_complete  # type: ignore[method-assign]

    with pytest.raises(MaintenanceError) as captured:
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )

    assert captured.value.reason is MaintenanceReason.REPLAY_MISMATCH
    assert harness.catalog.execute(
        "SELECT state, phase FROM maintenance_operations"
    ).fetchone() == ("pending", "route_switched")

    harness.catalog.execute(
        "INSERT INTO privacy_root_sets(task_id, route_identity_digest, root_generation, "
        "root_count, root_digest, updated_at) VALUES (?, ?, ?, ?, ?, ?)",
        (
            str(target_roots.task_id),
            target_roots.route_identity_digest,
            target_roots.privacy_root_generation,
            len(target_roots.object_refs),
            target_roots.root_set_digest,
            "2026-07-19T09:00:00.000Z",
        ),
    )
    harness.catalog.execute(
        "UPDATE maintenance_operations SET lease_expires_at = ?",
        ("2026-07-19T08:59:59.000Z",),
    )
    result = await harness.adapter.restore(
        harness.restore_command,
        confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
        recovery_secret=None,
    )
    assert result.active_route_identity_digest == target_route
    assert harness.catalog.execute(
        "SELECT state, phase FROM maintenance_operations"
    ).fetchone() == ("complete", "terminal")


@pytest.mark.anyio
async def test_restore_invalidates_nonterminal_privacy_authority() -> None:
    harness = _harness()
    harness.procedures.restored = _RestoredTarget(
        harness.procedures.restored.evidence,
        harness.procedures.restored.result,
        harness.procedures.restored.bundle_relpath,
        False,
    )

    with pytest.raises(MaintenanceError) as captured:
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )

    assert captured.value.reason is MaintenanceReason.REPLAY_MISMATCH
    assert harness.catalog.execute("SELECT bundle_relpath FROM task_routes").fetchone() == (
        f"tasks/{harness.procedures.facts.task_id}",
    )


@pytest.mark.anyio
async def test_restore_rebases_owned_project_refs_and_preserves_other_route_generation() -> None:
    harness = _harness()
    task = str(harness.procedures.facts.task_id)
    other_task = _id(IdKind.TASK, 205)
    other_session = _id(IdKind.SESSION, 206)
    now = "2026-07-19T09:00:00.000Z"
    harness.catalog.execute(
        "INSERT INTO task_routes(task_id, active_session_id, bundle_relpath, route_generation, "
        "active_route_identity_digest, state, created_at, updated_at) "
        "VALUES(?, ?, ?, 1, ?, 'active', ?, ?)",
        (
            other_task,
            other_session,
            f"tasks/{other_task}",
            canonical_digest({"route": "other"}),
            now,
            now,
        ),
    )
    project = _id(IdKind.PROJECT, 207)
    owned = ProjectTextRef(
        _id(IdKind.OBJECT, 208),
        _digest(b"owned-content"),
        13,
        task,
        1,
        _digest(b"owned-envelope"),
    )
    foreign = ProjectTextRef(
        _id(IdKind.OBJECT, 209),
        _digest(b"foreign-content"),
        15,
        other_task,
        1,
        _digest(b"foreign-envelope"),
    )
    harness.catalog.execute(
        "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
        "membership_generation, created_at, dissolved_at, title_ref_canonical, "
        "description_ref_canonical) VALUES(?, 'general', NULL, 1, 1, ?, NULL, ?, ?)",
        (project, now, canonical_encode(owned.as_wire()), canonical_encode(foreign.as_wire())),
    )
    detection = _id(IdKind.EVENT, 212)
    harness.catalog.execute(
        "INSERT INTO coordination_detections("
        "detection_id, project_id, membership_generation, left_task_id, right_task_id, "
        "overlap_kind, resource_identities_json, counterpart_task_id, advice_only, "
        "obligation_declared, addressed, generation_valid, detail_ref_json, resolved) "
        "VALUES(?, ?, 1, ?, ?, 'integration', ?, ?, 1, 0, 0, 1, ?, 0)",
        (
            detection,
            project,
            task,
            other_task,
            canonical_encode([canonical_digest({"resource": "src/a.py"})]).decode("utf-8"),
            other_task,
            canonical_encode(owned.as_wire()).decode("utf-8"),
        ),
    )

    await harness.adapter.restore(
        harness.restore_command,
        confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
        recovery_secret=None,
    )

    project_row = harness.catalog.execute(
        "SELECT title_ref_canonical, description_ref_canonical FROM projects WHERE project_id = ?",
        (project,),
    ).fetchone()
    assert project_row is not None
    title, description = cast(tuple[object, object], project_row)
    assert title == canonical_encode(
        ProjectTextRef(
            owned.object_id,
            owned.content_digest,
            owned.plaintext_size,
            owned.owner_task_id,
            2,
            owned.envelope_digest,
        ).as_wire()
    )
    assert description == canonical_encode(foreign.as_wire())
    detail = harness.catalog.execute(
        "SELECT detail_ref_json FROM coordination_detections WHERE detection_id = ?",
        (detection,),
    ).fetchone()
    assert detail == (
        canonical_encode(
            ProjectTextRef(
                owned.object_id,
                owned.content_digest,
                owned.plaintext_size,
                owned.owner_task_id,
                2,
                owned.envelope_digest,
            ).as_wire()
        ).decode("utf-8"),
    )
    assert harness.catalog.execute(
        "SELECT route_generation FROM task_routes WHERE task_id = ?", (task,)
    ).fetchone() == (2,)
    assert harness.catalog.execute(
        "SELECT route_generation FROM retained_task_routes WHERE task_id = ?", (task,)
    ).fetchone() == (1,)


@pytest.mark.anyio
async def test_restore_fails_closed_for_legacy_project_ref_and_rolls_back_route() -> None:
    harness = _harness()
    task = str(harness.procedures.facts.task_id)
    project = _id(IdKind.PROJECT, 210)
    legacy = ProjectTextRef(
        _id(IdKind.OBJECT, 211),
        _digest(b"legacy-content"),
        14,
        task,
        1,
    )
    now = "2026-07-19T09:00:00.000Z"
    encoded = canonical_encode(legacy.as_wire())
    harness.catalog.execute(
        "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
        "membership_generation, created_at, dissolved_at, title_ref_canonical, "
        "description_ref_canonical) VALUES(?, 'general', NULL, 1, 1, ?, NULL, ?, NULL)",
        (project, now, encoded),
    )

    with pytest.raises(MaintenanceError) as captured:
        await harness.adapter.restore(
            harness.restore_command,
            confirmed_plan_digest=harness.procedures.restore_plan.plan_digest,
            recovery_secret=None,
        )

    assert captured.value.reason is MaintenanceReason.REPLAY_MISMATCH
    assert harness.catalog.execute(
        "SELECT bundle_relpath, route_generation FROM task_routes WHERE task_id = ?", (task,)
    ).fetchone() == (f"tasks/{task}", 1)
    assert harness.catalog.execute(
        "SELECT COUNT(*) FROM retained_task_routes WHERE task_id = ?", (task,)
    ).fetchone() == (0,)
    assert harness.catalog.execute(
        "SELECT title_ref_canonical FROM projects WHERE project_id = ?", (project,)
    ).fetchone() == (encoded,)


@pytest.mark.anyio
async def test_backup_recovers_pin_after_bundle_commit_before_catalog_phase() -> None:
    harness = _harness()
    harness.procedures.facts = _AuthorityFacts(
        task_id=harness.procedures.facts.task_id,
        frontier=Frontier.genesis(),
        source_route_identity_digest=harness.procedures.facts.source_route_identity_digest,
        owner_generation=1,
        privacy_roots=harness.procedures.roots,
        backup_mode=BackupMode.MACHINE_BOUND,
        target_location_commitment=harness.procedures.backup_plan.destination_commitment,
    )
    handle = await harness.adapter._acquire_maintenance(  # pyright: ignore[reportPrivateUsage]
        harness.backup_command,
        harness.procedures.backup_plan,
        harness.procedures.backup_plan.plan_digest,
    )
    assert type(handle) is MaintenanceHandle
    original_advance = harness.adapter.advance_phase

    def crash_after_bundle_commit(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise RuntimeError("fault_after_bundle_pin_commit")

    harness.adapter.advance_phase = crash_after_bundle_commit  # type: ignore[method-assign]
    expiry = Timestamp("2026-07-19T10:00:00.000Z")
    with pytest.raises(RuntimeError, match="fault_after_bundle_pin_commit"):
        await harness.adapter.create_frontier_pin(handle, Frontier.genesis(), expiry)
    stored_pin_row = harness.bundle.execute(
        "SELECT pin_id FROM maintenance_pins WHERE state = 'active'"
    ).fetchone()
    assert stored_pin_row is not None and type(stored_pin_row[0]) is str
    stored_pin_id = stored_pin_row[0]

    harness.adapter.advance_phase = original_advance  # type: ignore[method-assign]
    # A crashed owner may be reclaimed only after its durable lease expires.
    harness.catalog.execute(
        "UPDATE maintenance_operations SET lease_expires_at = ?",
        ("2026-07-19T08:59:59.000Z",),
    )
    resumed_handle = await harness.adapter._acquire_maintenance(  # pyright: ignore[reportPrivateUsage]
        harness.backup_command,
        harness.procedures.backup_plan,
        harness.procedures.backup_plan.plan_digest,
    )
    assert type(resumed_handle) is MaintenanceHandle
    resumed_pin = await harness.adapter.create_frontier_pin(
        resumed_handle, Frontier.genesis(), Timestamp("2026-07-19T10:30:00.000Z")
    )

    assert resumed_pin.pin_id == stored_pin_id
    assert resumed_pin.expires_at == expiry
    assert harness.bundle.execute(
        "SELECT COUNT(*) FROM maintenance_pins WHERE state = 'active'"
    ).fetchone() == (1,)
    assert harness.catalog.execute("SELECT phase FROM maintenance_operations").fetchone() == (
        "pinned",
    )
