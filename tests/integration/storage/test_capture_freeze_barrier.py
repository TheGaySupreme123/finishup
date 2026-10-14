"""Freeze admission must coordinate with durable native-content handoffs."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest

from builders.ledger_adapters import MemoryObjects
from builders.replay import replay_records
from finishup.adapters.memory.ledger import MemoryLedgerAdapter
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.findings import CheckVerdict, RankedFindings
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationSource,
)
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.domain.values import Timestamp
from finishup.ports.ledger import (
    AppendCommand,
    CheckCommitResult,
    CheckPhase,
    CheckPolicyExecution,
    FrozenCase,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.coverage import PublicationChannel, coverage_for_channel
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import SemanticReason, SemanticStatus
from integration.storage.test_append_and_replay import (
    command_from_records,
    deterministic_result_ref,
    file_sqlite_for,
    uuid_id,
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _ticket(
    command: AppendCommand,
    *,
    logical_identity: str,
    state: Literal["staging", "pending", "revoked"] = "staging",
) -> ObservationCaptureTicket:
    # The handoff is metadata-only in this test.  A staging row deliberately
    # has no object IDs; the repository barrier must still see it before a
    # structural freeze can advance the ledger.
    return ObservationCaptureTicket(
        workspace_commitment="hmac-sha256:" + "1" * 64,
        task_id=command.task_id,
        yoetz_session_id=command.session_id,
        session_commitment="hmac-sha256:" + "2" * 64,
        source=ObservationSource.CLAUDE_HOOK,
        source_identity="hook:freeze-barrier",
        cursor=ObservationCursor(
            source_generation=1,
            byte_position=10,
            event_position=1,
            last_source_commitment="hmac-sha256:" + "3" * 64,
            mapping_version="claude-observation-1",
        ),
        logical_identity=logical_identity,
        content_capture_profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
        authority_generation="sha256:" + "4" * 64,
        object_ids=(),
        captured_at=Timestamp("2026-07-19T12:00:00.000Z"),
        state=state,
    )


async def _complete_check(
    ledger: SqliteLedger, command: AppendCommand, objects: MemoryObjects
) -> tuple[str, str]:
    request_id = uuid_id("req", 91_001)
    request_digest = "sha256:" + "5" * 64
    frozen = await ledger.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        request_id,
        request_digest,
    )
    assert type(frozen) is FrozenCase
    operation = await ledger.lookup_operation(command.writer_id, request_id)
    assert operation is not None and operation.resume_object_ref is not None
    local = await deterministic_result_ref(
        command,
        objects,
        frozen,
        operation.resume_object_ref,
        request_digest,
    )
    lease = await ledger.advance_check_phase(
        frozen.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        local,
    )
    lease = await ledger.advance_check_phase(
        lease,
        CheckPhase.LOCAL_READY,
        CheckPhase.READY_TO_FINALIZE,
    )
    committed = await ledger.commit_check_if_current(
        FrozenCase(frozen.case, lease),
        RankedFindings(
            (),
            0,
            CheckVerdict.NO_ISSUE_DETECTED,
            coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
        ),
        (CheckPolicyExecution("work-integrity", "0.1.0", "run", "completed"),),
        SemanticStatus.NOT_REQUESTED,
        SemanticReason.DETERMINISTIC_MODE,
        None,
        request_id,
    )
    assert committed.outcome == "committed"
    return request_id, request_digest


@pytest.mark.anyio
async def test_freeze_waits_for_capture_ticket_and_revoked_ticket_is_ignored(
    tmp_path: Path,
) -> None:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "capture-freeze.sqlite3")
    await ledger.append_batch(command)
    store = ledger.open_observation_store()
    ticket = _ticket(
        command,
        logical_identity="sha256:" + "a" * 64,
    )
    store.record_capture_ticket(ticket)
    operation_count = db.execute("SELECT count(*) FROM operations").fetchone()

    with pytest.raises(PublicOperationError) as blocked:
        await asyncio.wait_for(
            ledger.freeze_case(
                command.session_id,
                command.writer_id,
                1,
                uuid_id("req", 91_002),
                "sha256:" + "6" * 64,
            ),
            timeout=1,
        )
    assert blocked.value.code is PublicErrorCode.OPERATION_PENDING
    assert blocked.value.retryable is True
    assert db.execute("SELECT count(*) FROM operations").fetchone() == operation_count

    captured = await objects.stage(
        ObjectSource(data=b"encrypted-capture", declared_size=17),
        ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "text/plain",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    captured_ref = await objects.finalize(captured)
    correlation_identity = "hook:freeze-barrier:tool-output"
    store.record_content_manifest(
        workspace=ticket.workspace_commitment,
        logical_identity=ticket.logical_identity,
        chunk=ObservationContentChunk(
            content_kind=ObservationContentKind.TOOL_OUTPUT,
            correlation_identity=correlation_identity,
            source_commitment=ticket.cursor.last_source_commitment,
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=b"encrypted-capture",
        ),
        ref=captured_ref,
        content_digest=canonical_digest({"content": "encrypted-capture"}),
        content_bytes=17,
        recorded_at=ticket.captured_at,
    )
    pending = replace(
        ticket,
        object_ids=(captured_ref.object_id,),
        state="pending",
        expected_parts=(
            (
                ObservationContentKind.TOOL_OUTPUT.value,
                correlation_identity,
                ticket.cursor.last_source_commitment,
                0,
                1,
            ),
        ),
    )
    store.finalize_capture_ticket(ticket, pending)

    with pytest.raises(PublicOperationError) as pending_failure:
        await ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_003),
            "sha256:" + "7" * 64,
        )
    assert pending_failure.value.code is PublicErrorCode.OPERATION_PENDING

    store.tombstone_capture_ticket(pending)
    resumed = await asyncio.wait_for(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_004),
            "sha256:" + "8" * 64,
        ),
        timeout=1,
    )
    assert type(resumed) is FrozenCase
    db.close()


@pytest.mark.anyio
async def test_freeze_blocks_predecessor_ticket_for_same_task_successor(
    tmp_path: Path,
) -> None:
    """A successor check cannot outrun a predecessor handoff in the same task."""

    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "capture-freeze-successor.sqlite3")
    await ledger.append_batch(command)
    store = ledger.open_observation_store()
    ticket = _ticket(
        command,
        logical_identity="sha256:" + "d" * 64,
    )
    store.record_capture_ticket(ticket)

    successor_session = uuid_id("ses", 91_010)
    successor_writer = uuid_id("wri", 91_011)
    with pytest.raises(PublicOperationError) as blocked:
        await ledger.freeze_case(
            successor_session,
            successor_writer,
            1,
            uuid_id("req", 91_012),
            "sha256:" + "e" * 64,
        )
    assert blocked.value.code is PublicErrorCode.OPERATION_PENDING
    assert blocked.value.retryable is True
    assert db.execute("SELECT count(*) FROM operations").fetchone() == (1,)

    store.tombstone_capture_ticket(ticket)
    db.close()


@pytest.mark.anyio
async def test_completed_same_id_replay_bypasses_unrelated_capture_ticket(
    tmp_path: Path,
) -> None:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "capture-replay.sqlite3")
    await ledger.append_batch(command)
    request_id, request_digest = await _complete_check(ledger, command, objects)
    store = ledger.open_observation_store()
    store.record_capture_ticket(
        _ticket(
            command,
            logical_identity="sha256:" + "b" * 64,
        )
    )

    replayed = await asyncio.wait_for(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            request_digest,
        ),
        timeout=1,
    )
    assert type(replayed) is CheckCommitResult

    with pytest.raises(PublicOperationError) as blocked:
        await ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_005),
            "sha256:" + "9" * 64,
        )
    assert blocked.value.code is PublicErrorCode.OPERATION_PENDING
    db.close()


@pytest.mark.anyio
async def test_capture_ticket_inserted_during_freeze_is_caught_at_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "capture-race.sqlite3")
    await ledger.append_batch(command)
    store = ledger.open_observation_store()
    ticket = _ticket(
        command,
        logical_identity="sha256:" + "c" * 64,
    )
    entered = asyncio.Event()
    release = asyncio.Event()
    original = MemoryLedgerAdapter.freeze_case

    async def pause_after_oracle(
        adapter: MemoryLedgerAdapter,
        session_id: str,
        writer_id: str,
        expected_frontier: int | None,
        request_id: str,
        request_digest: str,
    ) -> FrozenCase | CheckCommitResult:
        result = await original(
            adapter,
            session_id,
            writer_id,
            expected_frontier,
            request_id,
            request_digest,
        )
        entered.set()
        await release.wait()
        return result

    monkeypatch.setattr(MemoryLedgerAdapter, "freeze_case", pause_after_oracle)
    operation_count = db.execute("SELECT count(*) FROM operations").fetchone()
    freezing = asyncio.create_task(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_007),
            "sha256:" + "b" * 64,
        )
    )
    await asyncio.wait_for(entered.wait(), timeout=1)
    # The oracle has staged a candidate, but the repository has not opened its
    # final transaction yet.  This ticket must be visible to that transaction.
    store.record_capture_ticket(ticket)
    release.set()
    with pytest.raises(PublicOperationError) as blocked:
        await asyncio.wait_for(freezing, timeout=1)
    assert blocked.value.code is PublicErrorCode.OPERATION_PENDING
    assert db.execute("SELECT count(*) FROM operations").fetchone() == operation_count
    db.close()


@pytest.mark.anyio
async def test_schema_claiming_capture_tickets_but_missing_table_fails_closed(
    tmp_path: Path,
) -> None:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "missing-capture-table.sqlite3")
    await ledger.append_batch(command)
    db.execute("DROP TABLE observation_capture_tickets")

    with pytest.raises(PublicOperationError) as failure:
        await ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_008),
            "sha256:" + "a" * 64,
        )
    assert failure.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert failure.value.retryable is False
    db.close()


@pytest.mark.anyio
async def test_malformed_pending_capture_ticket_fails_closed_without_freeze(
    tmp_path: Path,
) -> None:
    command, objects = command_from_records(replay_records("projection-rebuild")[:1])
    ledger, db = file_sqlite_for(command, objects, tmp_path / "malformed-capture-ticket.sqlite3")
    await ledger.append_batch(command)
    store = ledger.open_observation_store()
    ticket = _ticket(
        command,
        logical_identity="sha256:" + "b" * 64,
    )
    store.record_capture_ticket(ticket)
    db.execute(
        "UPDATE observation_capture_tickets SET expected_parts_json=? "
        "WHERE workspace_commitment=? AND logical_identity=?",
        (b'{"malformed":true}', ticket.workspace_commitment, ticket.logical_identity),
    )
    # The ticket identity remains valid; only its durable structural codec is
    # corrupt.  A freeze must report storage corruption rather than retrying
    # forever behind a generic OPERATION_PENDING barrier.
    with pytest.raises(PublicOperationError) as failure:
        await ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            uuid_id("req", 91_009),
            "sha256:" + "b" * 64,
        )
    assert failure.value.code is PublicErrorCode.STORAGE_CORRUPT
    assert failure.value.retryable is False
    assert db.execute("SELECT count(*) FROM operations").fetchone() == (1,)
    db.close()
