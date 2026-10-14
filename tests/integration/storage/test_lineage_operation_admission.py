"""Durable cross-repository lineage admission persistence and CAS checks."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.lineage_catalog import SqliteLineageStore
from finishup.adapters.sqlite.migrations import initialize_catalog
from finishup.application.lineage import (
    DelegationRequest,
    LineageCoordinator,
    LineageProjectAdmission,
)
from finishup.ports.clock import ClockPort
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind, new_id


class _Clock(ClockPort):
    def now_utc(self) -> datetime:
        return datetime(2026, 9, 6, 12, 0, tzinfo=UTC)

    def monotonic_seconds(self) -> float:
        return 0.0


def _commitment(seed: str) -> str:
    return "hmac-sha256:" + seed * 64


@pytest.mark.anyio
async def test_cross_repository_admission_survives_sqlite_restart_and_identity_cas(
    tmp_path: Path,
) -> None:
    path = tmp_path / "catalog.sqlite3"
    installation = new_id(IdKind.INSTALLATION)
    parent_task = new_id(IdKind.TASK)
    parent_session = new_id(IdKind.SESSION)
    project = new_id(IdKind.PROJECT)
    operation_id = new_id(IdKind.REQUEST)
    parent_repository = _commitment("a")
    child_repository = _commitment("b")
    workspace = _commitment("c")
    external = _commitment("d")
    request_digest = "sha256:" + "1" * 64

    db = apsw.Connection(str(path))
    initialize_catalog(db)
    db.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation), ("owner_generation", "1")),
    )
    db.execute(
        "INSERT INTO projects(project_id, kind, repository_commitment, auto_grouping, "
        "membership_generation, created_at, dissolved_at) VALUES (?, 'general', NULL, 1, 4, ?, NULL)",
        (project, "2026-09-06T12:00:00.000Z"),
    )
    store = SqliteLineageStore(db, installation_id=installation, clock=_Clock())

    async def resolve(_parent: str, _child: str) -> LineageProjectAdmission:
        return LineageProjectAdmission(project, 4)

    coordinator = LineageCoordinator(
        store=store,
        clock=_Clock(),
        handle_key=b"lineage-admission-storage-test-key",
        project_admission_resolver=resolve,
    )
    await coordinator.register_root(
        task_id=parent_task,
        session_id=parent_session,
        repository_commitment=parent_repository,
    )
    request = DelegationRequest(
        operation_id=operation_id,
        request_digest=request_digest,
        parent_task_id=parent_task,
        parent_session_id=parent_session,
        repository_commitment=child_repository,
        workspace_commitment=workspace,
        external_commitment=external,
    )
    reserved = await coordinator.reserve_delegation(request)
    assert reserved.operation.project_id == project
    assert reserved.operation.membership_generation == 4
    db.close()

    reopened = apsw.Connection(str(path))
    restarted_store = SqliteLineageStore(
        reopened,
        installation_id=installation,
        clock=_Clock(),
    )
    stored = await restarted_store.get_operation(operation_id)
    assert stored is not None
    assert stored.project_id == project
    assert stored.membership_generation == 4

    async def revoked_resolver(_parent: str, _child: str) -> None:
        raise AssertionError("a replay must use the stored admission")

    restarted = LineageCoordinator(
        store=restarted_store,
        clock=_Clock(),
        handle_key=b"lineage-admission-storage-test-key",
        owner_generation=2,
        project_admission_resolver=revoked_resolver,
    )
    replay = await restarted.reserve_delegation(request)
    assert replay.operation.project_id == project
    assert replay.operation.membership_generation == 4

    with pytest.raises(PublicOperationError) as error:
        await restarted_store.save_operation(
            replace(stored, project_id=new_id(IdKind.PROJECT), membership_generation=5)
        )
    assert error.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert error.value.safe_details["reason_code"] == "lineage_operation_conflict"
    reopened.close()
