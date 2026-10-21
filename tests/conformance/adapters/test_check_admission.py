"""Pre-admission check refusals are typed, journaled, and converge on replay (issue #838).

Every branch that answers a new check with ``OPERATION_PENDING`` before an operation record
exists must name its stage, carry the same-identity continuation, stay visible to operation
recovery, and let the exact replay converge. An abandoned frozen check must stop deferring the
observation drain that later checks are waiting on. Memory and SQLite share one oracle, so each
stage is driven through both adapters with deterministic barriers and no sleeps.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import apsw
import pytest

import finishup.adapters.objects.check_resume as resume_module
from conformance.adapters.test_ledger_port import (
    _fence,  # pyright: ignore[reportPrivateUsage]
    _GatedObjects,  # pyright: ignore[reportPrivateUsage]
    _grant_park_observation,  # pyright: ignore[reportPrivateUsage]
    _Ids,  # pyright: ignore[reportPrivateUsage]
    _local_result_ref,  # pyright: ignore[reportPrivateUsage]
    _Objects,  # pyright: ignore[reportPrivateUsage]
    ledger_command,
)
from finishup.adapters.memory.importer import MemoryImportState
from finishup.adapters.memory.ledger import (
    MemoryLedgerAdapter,
    MemoryLedgerState,
    check_admission_record,
    note_check_admission_refusal,
)
from finishup.adapters.sqlite.migrations import initialize_bundle
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.findings import CheckVerdict, RankedFindings
from finishup.ports.ledger import (
    CHECK_ADMISSION_REASON_CODES,
    CHECK_ADMISSION_RETRY_AFTER_MS,
    AppendCommand,
    CheckAdmissionStage,
    CheckPhase,
    CheckPolicyExecution,
    FrozenCase,
    check_admission_refused,
    check_admission_stage,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource, StagedObject
from finishup.ports.runtime import OwnershipFence
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import SemanticReason, SemanticStatus

type _Adapter = MemoryLedgerAdapter | SqliteLedger
type _Kind = Literal["memory", "sqlite"]

_KINDS: tuple[_Kind, ...] = ("memory", "sqlite")
_DIGEST = "sha256:" + "8" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _SteppingClock:
    """A service clock a test moves explicitly, so lease expiry needs no sleep."""

    def __init__(self) -> None:
        self.now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)

    def now_utc(self) -> datetime:
        return self.now

    def monotonic_seconds(self) -> float:
        return 1.0

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


class _CountingGate(_GatedObjects):
    """Signal when a second check-resume staging call has reached the shared gate."""

    def __init__(self, ids: _Ids) -> None:
        super().__init__(ids)
        self.entries = 0
        self.second_entered = asyncio.Event()

    async def stage(
        self, source: ObjectSource, metadata: ObjectMetadata, *, object_id: str | None = None
    ) -> StagedObject:
        if metadata.kind is ObjectKind.CHECK_RESUME:
            self.entries += 1
            if self.entries >= 2:
                self.second_entered.set()
        return await super().stage(source, metadata, object_id=object_id)


class _ImportGate:
    """Minimal import state whose pending flag the test controls."""

    def __init__(self) -> None:
        self.pending = False

    def has_pending_import(self, session_id: str) -> bool:
        del session_id
        return self.pending

    def publication_reservation(self, writer_id: str, request_id: str) -> None:
        del writer_id, request_id
        return None


def _adapter(
    kind: _Kind,
    command: AppendCommand,
    clock: _SteppingClock,
    *,
    gated: bool = False,
    fence: OwnershipFence | None = None,
) -> tuple[_Adapter, _CountingGate | None]:
    ids = _Ids()
    objects = _CountingGate(ids) if gated else _Objects(ids)
    if kind == "memory":
        adapter: _Adapter = MemoryLedgerAdapter(
            task_id=command.task_id,
            ownership_fence=_fence() if fence is None else fence,
            state=MemoryLedgerState(),
            import_state=MemoryImportState(),
            transaction_lock=asyncio.Lock(),
            clock=clock,
            ids=ids,
            objects=objects,
        )
    else:
        db = apsw.Connection(":memory:")
        initialize_bundle(
            db,
            {
                "task_id": command.task_id,
                "owner_generation": "1",
                "owner_nonce": "ledger-test-nonce",
            },
        )
        adapter = SqliteLedger(
            db=db,
            task_id=command.task_id,
            ownership_fence=_fence() if fence is None else fence,
            clock=clock,
            ids=ids,
            objects=objects,
        )
    return adapter, objects if isinstance(objects, _CountingGate) else None


async def _freeze(adapter: _Adapter, command: AppendCommand, request_id: str) -> object:
    return await adapter.freeze_case(command.session_id, command.writer_id, 1, request_id, _DIGEST)


def _assert_typed_refusal(exc: PublicOperationError, stage: CheckAdmissionStage) -> None:
    assert exc.code is PublicErrorCode.OPERATION_PENDING
    assert exc.retryable is True
    assert check_admission_stage(exc) is stage
    assert exc.safe_details["reason_code"] == CHECK_ADMISSION_REASON_CODES[stage]
    assert exc.safe_details["retry_after_ms"] == CHECK_ADMISSION_RETRY_AFTER_MS[stage]
    # The same-identity continuation attaches at construction: a pre-admission refusal can never
    # read as the stranded-operation directive that told agents to stop (issue #838).
    assert exc.safe_details["continuation"] == "check_admission_same_identity"


def test_every_stage_has_a_distinct_registered_reason_and_bounded_wait() -> None:
    reasons = tuple(CHECK_ADMISSION_REASON_CODES[stage] for stage in CheckAdmissionStage)
    assert len(set(reasons)) == len(CheckAdmissionStage)
    for stage in CheckAdmissionStage:
        refusal = check_admission_refused(stage)
        _assert_typed_refusal(refusal, stage)
        assert 0 < CHECK_ADMISSION_RETRY_AFTER_MS[stage] <= 10_000
    untyped = PublicOperationError(PublicErrorCode.OPERATION_PENDING, "pending", True)
    assert check_admission_stage(untyped) is None
    terminal = PublicOperationError(
        PublicErrorCode.OPERATION_PENDING,
        "pending",
        False,
        safe_details={"reason_code": "check_admission_capture_pending"},
    )
    assert check_admission_stage(terminal) is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", _KINDS)
async def test_abandoned_check_lease_stops_deferring_observation(kind: _Kind) -> None:
    """An expired pending check is no barrier; its exact replay reclaims and still commits."""

    command = ledger_command(request_suffix="d")
    operation_id = "req_00000000-0000-4000-8000-000000000838"
    observation = _grant_park_observation("e", "e1")
    clock = _SteppingClock()
    adapter, _ = _adapter(kind, command, clock)
    await adapter.append_batch(command)
    frozen = await _freeze(adapter, command, operation_id)
    assert type(frozen) is FrozenCase

    assert await adapter.has_active_frozen_case(command.session_id)
    with pytest.raises(PublicOperationError) as deferred:
        await adapter.append_batch(observation)
    assert deferred.value.code is PublicErrorCode.OPERATION_PENDING

    # The invocation that froze the case went away and renews nothing.
    clock.advance(61)
    assert not await adapter.has_active_frozen_case(command.session_id)
    drained = await adapter.append_batch(observation)
    assert drained.result_frontier.sequence == 2

    reclaimed = await _freeze(adapter, command, operation_id)
    assert type(reclaimed) is FrozenCase
    assert reclaimed.case.frontier.sequence == 1
    assert await adapter.has_active_frozen_case(command.session_id)

    local = await adapter.advance_check_phase(
        reclaimed.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        await _local_result_ref(adapter, command),
    )
    ready = await adapter.advance_check_phase(
        local, CheckPhase.LOCAL_READY, CheckPhase.READY_TO_FINALIZE
    )
    committed = await adapter.commit_check_if_current(
        FrozenCase(reclaimed.case, ready),
        RankedFindings((), 0, CheckVerdict.NO_ISSUE_DETECTED, command.entries[0].coverage),
        (CheckPolicyExecution("research-evidence", "0.1.0", "run", "completed"),),
        SemanticStatus.NOT_REQUESTED,
        SemanticReason.DETERMINISTIC_MODE,
        None,
        operation_id,
    )
    assert committed.outcome == "committed"
    assert committed.subject_frontier.sequence == 1
    assert committed.result_frontier.sequence > drained.result_frontier.sequence


@pytest.mark.anyio
async def test_pending_check_of_a_dead_owner_generation_is_no_barrier() -> None:
    """A successor service must not inherit a dead generation's frozen case as a barrier."""

    command = ledger_command(request_suffix="e")
    observation = _grant_park_observation("f", "f1")
    clock = _SteppingClock()
    previous, _ = _adapter("memory", command, clock)
    assert isinstance(previous, MemoryLedgerAdapter)
    await previous.append_batch(command)
    frozen = await _freeze(previous, command, "req_00000000-0000-4000-8000-000000000839")
    assert type(frozen) is FrozenCase
    assert await previous.has_active_frozen_case(command.session_id)

    successor = MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=OwnershipFence(
            "svc_00000000-0000-4000-8000-000000000002", 2, 2, "ledger-test-nonce"
        ),
        state=previous._state,  # pyright: ignore[reportPrivateUsage]
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=clock,
        ids=_Ids(),
        objects=previous._objects,  # pyright: ignore[reportPrivateUsage]
    )
    # The lease has not expired on the clock, but no live owner can renew it.
    assert not await successor.has_active_frozen_case(command.session_id)
    assert (await successor.append_batch(observation)).result_frontier.sequence == 2


@pytest.mark.anyio
@pytest.mark.parametrize("kind", _KINDS)
async def test_same_request_in_flight_is_typed_acquiring_and_visible(kind: _Kind) -> None:
    command = ledger_command(unknown=True)
    clock = _SteppingClock()
    adapter, gate = _adapter(kind, command, clock, gated=True)
    assert gate is not None
    await adapter.append_batch(command)
    request_id = "req_00000000-0000-4000-8000-0000000008a1"
    assert await adapter.lookup_check_admission(command.writer_id, request_id) is None

    first = asyncio.create_task(_freeze(adapter, command, request_id))
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    acquiring = await adapter.lookup_check_admission(command.writer_id, request_id)
    assert acquiring is not None
    assert acquiring.stage is CheckAdmissionStage.ACQUIRING
    assert acquiring.refusal_count == 0

    with pytest.raises(PublicOperationError) as refused:
        await _freeze(adapter, command, request_id)
    _assert_typed_refusal(refused.value, CheckAdmissionStage.ACQUIRING)
    seen = await adapter.lookup_check_admission(command.writer_id, request_id)
    assert seen is not None and seen.stage is CheckAdmissionStage.ACQUIRING
    assert seen.refusal_count == 1
    # Another writer's view of the same request id learns nothing about this key.
    other_writer = "wri_00000000-0000-4000-8000-0000000008ff"
    assert await adapter.lookup_check_admission(other_writer, request_id) is None

    gate.release_freeze.set()
    assert type(await asyncio.wait_for(first, timeout=1)) is FrozenCase
    # Admission replaces the journal: the operation page is authoritative from here on.
    assert await adapter.lookup_check_admission(command.writer_id, request_id) is None
    assert await adapter.lookup_operation(command.writer_id, request_id) is not None


@pytest.mark.anyio
async def test_pending_import_refusal_is_typed_counted_and_clears_on_admission() -> None:
    command = ledger_command(unknown=True)
    clock = _SteppingClock()
    imports = _ImportGate()
    ids = _Ids()
    adapter = MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=_fence(),
        state=MemoryLedgerState(),
        import_state=imports,
        transaction_lock=asyncio.Lock(),
        clock=clock,
        ids=ids,
        objects=_Objects(ids),
    )
    await adapter.append_batch(command)
    request_id = "req_00000000-0000-4000-8000-0000000008a2"
    imports.pending = True
    for expected_count in (1, 2):
        with pytest.raises(PublicOperationError) as refused:
            await _freeze(adapter, command, request_id)
        _assert_typed_refusal(refused.value, CheckAdmissionStage.IMPORT_PENDING)
        record = await adapter.lookup_check_admission(command.writer_id, request_id)
        assert record is not None
        assert record.stage is CheckAdmissionStage.IMPORT_PENDING
        assert record.refusal_count == expected_count
        clock.advance(5)
    record = await adapter.lookup_check_admission(command.writer_id, request_id)
    assert record is not None
    assert record.first_observed_at == datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    assert record.last_observed_at == datetime(2026, 7, 19, 12, 0, 5, tzinfo=UTC)

    imports.pending = False
    assert type(await _freeze(adapter, command, request_id)) is FrozenCase
    assert await adapter.lookup_check_admission(command.writer_id, request_id) is None


@pytest.mark.anyio
@pytest.mark.parametrize("paged", (False, True))
async def test_sqlite_freeze_merges_over_concurrent_lifecycle_motion(
    monkeypatch: pytest.MonkeyPatch, paged: bool
) -> None:
    """Another check's phase write during staging no longer discards this admission."""

    command = ledger_command(unknown=True)
    if paged:
        monkeypatch.setattr(resume_module, "MAX_OBJECT_PLAINTEXT_BYTES", 512)
    clock = _SteppingClock()
    adapter, gate = _adapter("sqlite", command, clock, gated=True)
    assert isinstance(adapter, SqliteLedger) and gate is not None
    await adapter.append_batch(command)
    gate.release_freeze.set()
    first_request = "req_00000000-0000-4000-8000-0000000008b1"
    first = await _freeze(adapter, command, first_request)
    assert type(first) is FrozenCase

    gate.freeze_entered.clear()
    gate.release_freeze.clear()
    second_request = "req_00000000-0000-4000-8000-0000000008b2"
    second = asyncio.create_task(_freeze(adapter, command, second_request))
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    await adapter.advance_check_phase(
        first.lease,
        CheckPhase.RESERVED,
        CheckPhase.LOCAL_READY,
        await _local_result_ref(adapter, command),
    )
    gate.release_freeze.set()

    admitted = await asyncio.wait_for(second, timeout=1)
    assert type(admitted) is FrozenCase
    kept = await adapter.lookup_operation(command.writer_id, first_request)
    assert kept is not None and kept.phase is CheckPhase.LOCAL_READY
    merged = await adapter.lookup_operation(command.writer_id, second_request)
    assert merged is not None and merged.phase is CheckPhase.RESERVED
    db = adapter._db  # pyright: ignore[reportPrivateUsage]
    durable = dict(
        cast(
            list[tuple[str, str]],
            db.execute(
                "SELECT operation_id, phase FROM operations WHERE operation_id IN (?, ?)",
                (first_request, second_request),
            ).fetchall(),
        )
    )
    assert durable == {first_request: "local_ready", second_request: "reserved"}
    if paged:
        page_ids = {
            row[0] for row in db.execute("SELECT object_id FROM objects WHERE kind='check_resume'")
        }
        assert len(page_ids) > 2
        staged_pages = {
            ref.object_id
            for ref in gate._refs.values()  # pyright: ignore[reportPrivateUsage]
            if ref.metadata.media_type == resume_module.CHECK_RESUME_PAGE_MEDIA_TYPE
        }
        assert staged_pages <= page_ids
    assert (command.writer_id, second_request) not in (
        adapter._state.check_reservations  # pyright: ignore[reportPrivateUsage]
    )


@pytest.mark.anyio
@pytest.mark.parametrize("kind", _KINDS)
async def test_freeze_refuses_as_contended_when_case_inputs_move(kind: _Kind) -> None:
    """Motion in the case's own inputs refuses precisely, releases, and the replay admits."""

    command = ledger_command(unknown=True)
    clock = _SteppingClock()
    adapter, gate = _adapter(kind, command, clock, gated=True)
    assert gate is not None
    await adapter.append_batch(command)
    request_id = "req_00000000-0000-4000-8000-0000000008b3"
    frozen = asyncio.create_task(_freeze(adapter, command, request_id))
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    # A concurrent inventory refresh changed which objects the case may call available.
    unrelated = await _local_result_ref(adapter, command)
    adapter._state.object_refs[unrelated.object_id] = unrelated  # pyright: ignore[reportPrivateUsage]
    gate.release_freeze.set()

    with pytest.raises(PublicOperationError) as refused:
        await asyncio.wait_for(frozen, timeout=1)
    _assert_typed_refusal(refused.value, CheckAdmissionStage.ACQUISITION_CONTENDED)
    assert await adapter.lookup_operation(command.writer_id, request_id) is None
    state = adapter._state  # pyright: ignore[reportPrivateUsage]
    assert (command.writer_id, request_id) not in state.check_reservations
    record = await adapter.lookup_check_admission(command.writer_id, request_id)
    assert record is not None
    assert record.stage is CheckAdmissionStage.ACQUISITION_CONTENDED
    assert record.refusal_count == 1

    assert type(await _freeze(adapter, command, request_id)) is FrozenCase
    assert await adapter.lookup_check_admission(command.writer_id, request_id) is None


@pytest.mark.anyio
@pytest.mark.parametrize("kind", _KINDS)
async def test_stalled_acquisition_yields_to_its_successor(kind: _Kind) -> None:
    """A reservation that lapsed mid-staging names the live successor, which then admits."""

    command = ledger_command(unknown=True)
    clock = _SteppingClock()
    adapter, gate = _adapter(kind, command, clock, gated=True)
    assert gate is not None
    await adapter.append_batch(command)
    request_id = "req_00000000-0000-4000-8000-0000000008b4"
    stalled = asyncio.create_task(_freeze(adapter, command, request_id))
    await asyncio.wait_for(gate.freeze_entered.wait(), timeout=1)
    clock.advance(61)
    successor = asyncio.create_task(_freeze(adapter, command, request_id))
    await asyncio.wait_for(gate.second_entered.wait(), timeout=1)
    live = await adapter.lookup_check_admission(command.writer_id, request_id)
    assert live is not None and live.stage is CheckAdmissionStage.ACQUIRING
    gate.release_freeze.set()

    with pytest.raises(PublicOperationError) as refused:
        await asyncio.wait_for(stalled, timeout=1)
    _assert_typed_refusal(refused.value, CheckAdmissionStage.ACQUIRING)
    assert type(await asyncio.wait_for(successor, timeout=1)) is FrozenCase
    assert await adapter.lookup_check_admission(command.writer_id, request_id) is None
    assert await adapter.lookup_operation(command.writer_id, request_id) is not None


def test_admission_journal_is_bounded_by_count_and_age() -> None:
    state = MemoryLedgerState()
    now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    writer = "wri_00000000-0000-4000-8000-0000000008c0"
    keys = [(writer, f"req_00000000-0000-4000-8000-{index:012x}") for index in range(70)]
    for offset, key in enumerate(keys):
        note_check_admission_refusal(
            state,
            key,
            CheckAdmissionStage.CAPTURE_HANDOFF_PENDING,
            now + timedelta(milliseconds=offset),
        )
    assert len(state.check_admissions) == 64
    assert keys[0] not in state.check_admissions
    assert keys[-1] in state.check_admissions

    # A repeat refusal keeps the first observation and moves the key to the newest slot.
    later = now + timedelta(seconds=30)
    note_check_admission_refusal(state, keys[10], CheckAdmissionStage.ACQUISITION_CONTENDED, later)
    record = check_admission_record(state, keys[10], later)
    assert record is not None
    assert record.stage is CheckAdmissionStage.ACQUISITION_CONTENDED
    assert record.refusal_count == 2
    assert record.first_observed_at == now + timedelta(milliseconds=10)
    assert record.last_observed_at == later
    assert next(reversed(state.check_admissions)) == keys[10]

    # Stale entries disappear; the journal never outlives its bounded window.
    expired = later + timedelta(minutes=16)
    assert check_admission_record(state, keys[10], expired) is None
    assert state.check_admissions == {}


def test_admission_record_yields_to_an_admitted_operation() -> None:
    state = MemoryLedgerState()
    now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    key = ("wri_00000000-0000-4000-8000-0000000008c1", "req_00000000-0000-4000-8000-0000000008c1")
    note_check_admission_refusal(state, key, CheckAdmissionStage.CAPTURE_HANDOFF_PENDING, now)
    assert check_admission_record(state, key, now) is not None
    operations = cast(dict[tuple[str, str], object], state.operations)
    operations[key] = object()
    assert check_admission_record(state, key, now) is None


def test_refusal_count_zero_is_only_valid_while_acquiring() -> None:
    from finishup.ports.ledger import CheckAdmissionRecord

    now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    base = CheckAdmissionRecord(
        "wri_00000000-0000-4000-8000-0000000008c2",
        "req_00000000-0000-4000-8000-0000000008c2",
        CheckAdmissionStage.ACQUIRING,
        0,
        now,
        now,
        2_000,
    )
    with pytest.raises(ValueError):
        replace(base, stage=CheckAdmissionStage.CAPTURE_HANDOFF_PENDING)
    with pytest.raises(ValueError):
        replace(base, last_observed_at=now - timedelta(seconds=1))
