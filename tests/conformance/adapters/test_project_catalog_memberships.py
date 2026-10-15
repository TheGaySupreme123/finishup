"""Parity for repository/workspace project membership expansion."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import apsw
import pytest

from conformance.adapters.test_start_catalog_port import (  # pyright: ignore[reportPrivateUsage]
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _command,  # pyright: ignore[reportPrivateUsage]
    _id,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _Lookup,  # pyright: ignore[reportPrivateUsage]
    _memory_catalog,  # pyright: ignore[reportPrivateUsage]
)
from finishup.adapters.sqlite.start_catalog import SqliteStartCatalog
from finishup.domain.coordination import MemberKind
from finishup.protocol.ids import IdKind


def _sqlite_catalog_v4(installation_id: str, clock: _Clock) -> SqliteStartCatalog:
    db = apsw.Connection(":memory:")
    root = Path(__file__).resolve().parents[3]
    for version in ("0001", "0002", "0003", "0004"):
        db.execute((root / f"migrations/catalog/{version}.sql").read_text(encoding="utf-8"))
    db.executemany(
        "INSERT INTO catalog_meta(key, value) VALUES(?, ?)",
        (("installation_id", installation_id), ("owner_generation", "1")),
    )
    return SqliteStartCatalog(
        db,
        installation_id=installation_id,
        lookup=_Lookup(),
        clock=clock,
        ids=_Ids(),
    )


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("member_kind", [MemberKind.REPOSITORY, MemberKind.WORKSPACE])
async def test_project_membership_expansion_is_parity_for_memory_and_sqlite(
    member_kind: MemberKind,
) -> None:
    installation_id = _id(IdKind.INSTALLATION, 900)
    now = datetime(2026, 9, 6, 10, 0, tzinfo=UTC)
    memory, _ = _memory_catalog(installation_id, _Clock(now))
    sqlite = _sqlite_catalog_v4(installation_id, _Clock(now))
    repository_a = "hmac-sha256:" + "a" * 64
    repository_b = "hmac-sha256:" + "b" * 64
    project_id = _id(
        IdKind.PROJECT,
        901 if member_kind is MemberKind.REPOSITORY else 902,
    )

    for catalog in (memory, sqlite):
        first = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 910),
                title="First project task",
                workspace_ref="project-workspace-a",
                external_ref="project-external-a",
                repository_privacy_commitment=repository_a,
            )
        )
        second = await catalog.reserve_or_resume(
            await _command(
                catalog,
                operation_id=_id(IdKind.REQUEST, 911),
                title="Second project task",
                workspace_ref="project-workspace-b",
                external_ref="project-external-b",
                repository_privacy_commitment=repository_b,
            )
        )
        await catalog.create_general_project(project_id)

        if member_kind is MemberKind.REPOSITORY:
            members = (repository_a, repository_b)
        else:
            first_source = await catalog.task_source_provenance(first.task_id)
            second_source = await catalog.task_source_provenance(second.task_id)
            assert first_source is not None and second_source is not None
            assert (
                first_source.workspace_ref_commitment is not None
                and second_source.workspace_ref_commitment is not None
            )
            members = (
                first_source.workspace_ref_commitment,
                second_source.workspace_ref_commitment,
            )

        for member in members:
            await catalog.record_project_membership(
                project_id,
                member_kind=member_kind,
                member_commitment_or_id=member,
            )

        expected_tasks = tuple(sorted((first.task_id, second.task_id)))
        assert await catalog.list_project_task_ids(project_id) == expected_tasks
        assert await catalog.list_task_project_ids(first.task_id) == (project_id,)
        assert await catalog.list_task_project_ids(second.task_id) == (project_id,)
