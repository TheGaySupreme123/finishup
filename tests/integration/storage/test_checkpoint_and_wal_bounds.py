"""Owner-fenced PASSIVE checkpoint and real-WAL degradation acceptance."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import apsw
import pytest

from builders.ledger_adapters import MemoryObjects
from builders.replay import replay_records
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.values import event_id, object_id
from finishup.ports.ledger import AppendCommand
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from integration.storage.test_append_and_replay import (
    command_from_records,
    sqlite_for,
    uuid_id,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _wal_ledger(
    path: Path,
) -> tuple[AppendCommand, MemoryObjects, SqliteLedger, apsw.Connection]:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    db = apsw.Connection(str(path))
    assert db.pragma("journal_mode", "WAL") == "wal"
    db.pragma("wal_autocheckpoint", 0)
    db.set_busy_timeout(25)
    return command, objects, sqlite_for(command, objects, db), db


def _successor(command: AppendCommand, objects: MemoryObjects, *, ordinal: int) -> AppendCommand:
    entry = replace(
        command.entries[0],
        draft=replace(
            command.entries[0].draft,
            event_id=event_id(uuid_id("evt", 40_000 + ordinal)),
            causal_parents=(),
        ),
        payload_object=replace(
            command.entries[0].payload_object,
            object_id=object_id(uuid_id("obj", 50_000 + ordinal)),
        ),
    )
    objects._data[entry.payload_object.object_id] = (  # pyright: ignore[reportPrivateUsage]
        b"checkpoint-successor"
    )
    return replace(
        command,
        operation_id=uuid_id("req", 60_000 + ordinal),
        request_digest="sha256:" + f"{ordinal:064x}",
        expected_frontier=ordinal,
        entries=(entry,),
    )


@pytest.mark.anyio
async def test_owner_only_passive_checkpoint(tmp_path: Path) -> None:
    command, _, ledger, db = _wal_ledger(tmp_path / "owner.sqlite3")
    await ledger.append_batch(command)
    before = tuple(
        db.execute(
            "SELECT ingestion_seq,event_id,entry_digest,canonical_entry FROM events ORDER BY ingestion_seq"
        ).fetchall()
    )
    report = await ledger.run_passive_checkpoint(1)
    after = tuple(
        db.execute(
            "SELECT ingestion_seq,event_id,entry_digest,canonical_entry FROM events ORDER BY ingestion_seq"
        ).fetchall()
    )
    assert 0 <= report.checkpointed <= report.log
    assert after == before

    db.execute("UPDATE bundle_meta SET value='2' WHERE key='owner_generation'")
    with pytest.raises(PublicOperationError) as stale:
        await ledger.run_passive_checkpoint(1)
    assert stale.value.code is PublicErrorCode.STORAGE_UNSAFE
    assert (
        tuple(db.execute("SELECT ingestion_seq,event_id,entry_digest,canonical_entry FROM events"))
        == before
    )
    db.close()


@pytest.mark.anyio
async def test_wal_thresholds_emit_diagnostics(tmp_path: Path) -> None:
    path = tmp_path / "threshold.sqlite3"
    command, objects, ledger, db = _wal_ledger(path)
    await ledger.run_passive_checkpoint(1)
    await ledger.append_batch(command)

    wal_path = Path(f"{path}-wal")
    assert wal_path.stat().st_size > 0
    skipped = await ledger.run_passive_checkpoint(2**31)
    assert skipped.busy == 0
    assert skipped.log > 0
    assert skipped.checkpointed == 0

    reader = apsw.Connection(str(path))
    reader.execute("BEGIN")
    assert reader.execute("SELECT count(*) FROM events").fetchone() == (1,)
    second = _successor(command, objects, ordinal=1)
    await ledger.append_batch(second)
    degraded = await ledger.run_passive_checkpoint(1)
    assert degraded.log > 0
    assert degraded.checkpointed < degraded.log
    assert db.execute("SELECT count(*) FROM events").fetchone() == (2,)

    reader.execute("ROLLBACK")
    reader.close()
    recovered = await ledger.run_passive_checkpoint(1)
    assert recovered.busy == 0
    assert recovered.checkpointed == recovered.log
    assert db.execute("SELECT count(*) FROM events").fetchone() == (2,)
    db.close()


@pytest.mark.anyio
async def test_busy_timeout_and_io_faults_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "faults.sqlite3"
    command, objects, ledger, db = _wal_ledger(path)
    accepted = await ledger.append_batch(command)
    second = _successor(command, objects, ordinal=1)

    blocker = apsw.Connection(str(path))
    blocker.set_busy_timeout(25)
    blocker.execute("BEGIN IMMEDIATE")
    with pytest.raises(apsw.BusyError):
        await ledger.append_batch(second)
    blocker.execute("ROLLBACK")
    blocker.close()
    assert db.execute("SELECT count(*) FROM events").fetchone() == (1,)
    assert db.execute(
        "SELECT count(*) FROM operations WHERE operation_id=?", (second.operation_id,)
    ).fetchone() == (0,)

    page_count = db.pragma("page_count")
    assert type(page_count) is int and page_count > 0
    db.pragma("max_page_count", page_count)
    with pytest.raises(apsw.FullError):
        await ledger.append_batch(second)
    assert db.execute("SELECT count(*) FROM events").fetchone() == (1,)
    assert db.execute(
        "SELECT count(*) FROM operations WHERE operation_id=?", (second.operation_id,)
    ).fetchone() == (0,)
    assert tuple([row async for row in ledger.load_events(command.session_id)])
    assert accepted.result_frontier.sequence == 1

    db.close()
    with pytest.raises(apsw.ConnectionClosedError):
        await ledger.run_passive_checkpoint(1)
