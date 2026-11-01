"""Focused project-operation journal contract tests."""

from __future__ import annotations

from pathlib import Path

import apsw
import pytest

from finishup.adapters.sqlite.project_operations import SqliteProjectOperationJournal
from finishup.domain.coordination import ProjectTextRef
from finishup.domain.values import JsonObject
from finishup.protocol.canonical import canonical_encode
from finishup.protocol.ids import IdKind, new_id

_INSTALLATION = "ins_70000000-0000-4000-8000-000000000001"


def _catalog() -> apsw.Connection:
    db = apsw.Connection(":memory:")
    root = Path(__file__).resolve().parents[3]
    for version in range(1, 6):
        db.execute((root / "migrations" / "catalog" / f"{version:04d}.sql").read_text())
    db.execute(
        "INSERT INTO catalog_meta(key, value) VALUES ('installation_id', ?), ('owner_generation', '1')",
        (_INSTALLATION,),
    )
    return db


@pytest.mark.anyio
async def test_sqlite_journal_reserves_replays_and_conflicts_without_plaintext() -> None:
    db = _catalog()
    journal = SqliteProjectOperationJournal(db, installation_id=_INSTALLATION)
    request = new_id(IdKind.REQUEST)
    project = new_id(IdKind.PROJECT)
    object_id = new_id(IdKind.OBJECT)
    digest = "hmac-sha256:" + "a" * 64

    reserved = await journal.reserve(
        request,
        digest,
        "create",
        owner_task_id="tsk_70000000-0000-4000-8000-000000000002",
        owner_route_generation=1,
        reserved_project_id=project,
        reserved_title_object_id=object_id,
    )
    assert reserved.phase == "reserved"
    assert reserved.owner_task_id == "tsk_70000000-0000-4000-8000-000000000002"
    assert reserved.owner_route_generation == 1
    row = db.execute(
        "SELECT request_digest, result_canonical FROM project_operations WHERE request_id = ?",
        (request,),
    ).fetchone()
    assert row == (digest, None)
    assert db.execute(
        "SELECT COUNT(*) FROM project_operations WHERE request_id = ?", (request,)
    ).fetchone() == (1,)

    reference = ProjectTextRef(
        object_id,
        "sha256:" + "1" * 64,
        12,
        "tsk_70000000-0000-4000-8000-000000000002",
        1,
        "sha256:" + "2" * 64,
    )
    await journal.advance(request, digest, phase="text_ready", title_ref=reference)
    response = canonical_encode(
        JsonObject({"project_id": project, "title_ref": reference.as_wire()})
    )
    completed = await journal.complete(request, digest, response)
    replay = await journal.reserve(
        request,
        digest,
        "create",
        reserved_project_id=project,
        reserved_title_object_id=object_id,
    )

    assert completed.completed
    assert replay.result_canonical == response
    assert b"private title" not in response

    with pytest.raises(ValueError, match="project_operation_request_conflict"):
        await journal.reserve(
            request,
            "hmac-sha256:" + "b" * 64,
            "create",
            reserved_project_id=project,
            reserved_title_object_id=object_id,
        )


@pytest.mark.anyio
async def test_sqlite_journal_persists_amendment_pre_effect_refs() -> None:
    db = _catalog()
    journal = SqliteProjectOperationJournal(db, installation_id=_INSTALLATION)
    request = new_id(IdKind.REQUEST)
    project = new_id(IdKind.PROJECT)
    prior = ProjectTextRef(
        new_id(IdKind.OBJECT),
        "sha256:" + "3" * 64,
        4,
        "tsk_70000000-0000-4000-8000-000000000002",
        1,
        "sha256:" + "4" * 64,
    )
    digest = "hmac-sha256:" + "c" * 64

    reserved = await journal.reserve(
        request,
        digest,
        "amend",
        project_id=project,
        prior_title_ref=prior,
    )

    assert reserved.prior_title_ref == prior
    row = db.execute(
        "SELECT prior_title_ref_canonical, prior_description_ref_canonical "
        "FROM project_operations WHERE request_id = ?",
        (request,),
    ).fetchone()
    assert row is not None
    assert row[0] == canonical_encode(prior.as_wire())
    assert row[1] is None
