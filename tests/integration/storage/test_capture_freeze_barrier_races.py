"""Bounded race coverage for SQLite's two-phase check acquisition barrier."""

from __future__ import annotations

import asyncio
from typing import Any

import apsw
import pytest

from conformance.adapters.test_ledger_port import (
    _Clock,  # pyright: ignore[reportPrivateUsage]
    _fence,  # pyright: ignore[reportPrivateUsage]
    _GatedObjects,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _local_result_ref,  # pyright: ignore[reportPrivateUsage]
    ledger_command,
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.ports.ledger import CheckAdmissionStage, CheckPhase, FrozenCase, check_admission_stage
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from integration.storage.test_append_and_replay import uuid_id
from integration.storage.test_capture_freeze_barrier import (
    _ticket,  # pyright: ignore[reportPrivateUsage]
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _gated_sqlite(command: Any) -> tuple[SqliteLedger, _GatedObjects, apsw.Connection]:
    db = apsw.Connection(":memory:")
    initialize_bundle(
        db,
        {
            "task_id": command.task_id,
            "owner_generation": "1",
            "owner_nonce": "ledger-test-nonce",
        },
    )
    ids = _Ids()
    gate = _GatedObjects(ids)
    return (
        SqliteLedger(
            db=db,
            task_id=command.task_id,
            ownership_fence=_fence(),
            clock=_Clock(),
            ids=ids,
            objects=gate,
        ),
        gate,
        db,
    )


class _ObservedLock:
    """Expose the final acquisition attempt without changing asyncio.Lock semantics."""

    def __init__(self, inner: asyncio.Lock) -> None:
        self.inner = inner
        self.waiting = asyncio.Event()

    async def acquire(self) -> bool:
        if self.inner.locked():
            self.waiting.set()
        return await self.inner.acquire()

    def release(self) -> None:
        self.inner.release()

    async def __aenter__(self) -> _ObservedLock:
        await self.acquire()
        return self

    async def __aexit__(self, *exc: object) -> None:
        self.release()


@pytest.mark.anyio
async def test_cancelled_final_lock_wait_releases_freeze_reservation() -> None:
    command = ledger_command(unknown=True)
    ledger, gate, db = _gated_sqlite(command)
    await ledger.append_batch(command)
    observed = _ObservedLock(ledger._lock)  # pyright: ignore[reportPrivateUsage]
    ledger._lock = observed  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
    request_id = "req_00000000-0000-4000-8000-0000000000c1"
    freeze = asyncio.create_task(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            "sha256:" + "c" * 64,
        )
    )
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)

    await observed.acquire()
    gate.release_freeze.set()
    await asyncio.wait_for(observed.waiting.wait(), timeout=1)
    freeze.cancel()
    observed.release()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(freeze, timeout=1)

    assert (command.writer_id, request_id) not in ledger._state.check_reservations  # pyright: ignore[reportPrivateUsage]
    db.close()


@pytest.mark.anyio
async def test_capture_ticket_sync_failure_releases_freeze_reservation() -> None:
    command = ledger_command(unknown=True)
    ledger, gate, db = _gated_sqlite(command)
    await ledger.append_batch(command)
    store = ledger.open_observation_store()
    request_id = uuid_id("req", 92_002)
    ticket = _ticket(  # pyright: ignore[reportPrivateUsage]
        command,
        logical_identity="sha256:" + "c" * 64,
    )
    freeze = asyncio.create_task(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            "sha256:" + "d" * 64,
        )
    )
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    store.record_capture_ticket(ticket)
    gate.release_freeze.set()

    with pytest.raises(PublicOperationError) as caught:
        await asyncio.wait_for(freeze, timeout=1)
    assert caught.value.code is PublicErrorCode.OPERATION_PENDING
    # The handoff that landed mid-staging is named precisely, not as a stranded operation.
    assert check_admission_stage(caught.value) is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING
    assert (command.writer_id, request_id) not in ledger._state.check_reservations  # pyright: ignore[reportPrivateUsage]
    admission = await ledger.lookup_check_admission(command.writer_id, request_id)
    assert admission is not None
    assert admission.stage is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING

    store.tombstone_capture_ticket(ticket)
    resumed = await asyncio.wait_for(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            request_id,
            "sha256:" + "d" * 64,
        ),
        timeout=1,
    )
    assert isinstance(resumed, FrozenCase)
    db.close()


@pytest.mark.anyio
async def test_freeze_does_not_overwrite_concurrent_non_record_state() -> None:
    command = ledger_command(unknown=True)
    ledger, gate, db = _gated_sqlite(command)
    await ledger.append_batch(command)
    gate.release_freeze.set()
    first_request = uuid_id("req", 92_003)
    first = await ledger.freeze_case(
        command.session_id,
        command.writer_id,
        1,
        first_request,
        "sha256:" + "e" * 64,
    )
    assert isinstance(first, FrozenCase)

    deterministic_ref = await _local_result_ref(ledger, command)  # pyright: ignore[reportPrivateUsage]
    gate.freeze_entered.clear()
    gate.release_freeze.clear()
    second_request = uuid_id("req", 92_004)
    second = asyncio.create_task(
        ledger.freeze_case(
            command.session_id,
            command.writer_id,
            1,
            second_request,
            "sha256:" + "f" * 64,
        )
    )
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    await ledger.advance_check_phase(
        first.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        deterministic_ref,
    )
    gate.release_freeze.set()

    # Lifecycle motion that moved no record cannot change the staged case, so the admission is
    # carried over it instead of surfacing a no-record OPERATION_PENDING (issue #838).
    result = await asyncio.wait_for(second, timeout=1)
    assert isinstance(result, FrozenCase)
    operation = await ledger.lookup_operation(command.writer_id, first_request)
    assert operation is not None
    assert operation.phase is CheckPhase.LOCAL_READY
    assert await ledger.lookup_operation(command.writer_id, second_request) is not None
    db.close()
