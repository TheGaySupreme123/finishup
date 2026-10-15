"""A material append between closure-basis reads is re-read, not guessed (F03, ADR-046).

The ledger still refuses a torn snapshot. An unpinned status read re-reads the whole basis at
the latest frontier, immediately, at most twice. A pinned frontier is not moved. An extension
the suffix check already accepts does not move the prediction.
"""

# The race is inside private status helpers; the tests call them directly.
# pyright: reportPrivateUsage=false

from __future__ import annotations

import asyncio
import inspect
import uuid
from dataclasses import replace
from typing import cast

import pytest

import finishup.application.status as status_module
from builders.ledger_adapters import FixedClock, FixedIds, MemoryObjects, ownership_fence
from builders.replay import replay_records
from finishup.adapters.memory.importer import MemoryImportState
from finishup.adapters.memory.ledger import MemoryLedgerAdapter, MemoryLedgerState
from finishup.application.closure_basis import clear_closure_basis_memo, load_closure_basis
from finishup.application.status import (
    _CLOSURE_BASIS_HEAD_RETRIES,
    Application,
    StatusInternalResult,
    _closure_basis_or_none,
    _closure_readiness,
    _status_closure_follows_head,
    execute_status,
)
from finishup.domain.events import (
    OBSERVATION_COORDINATOR_ACTOR_ID,
    AcceptedEvent,
    EventDraft,
    LedgerRecord,
    encode_payload,
)
from finishup.domain.values import Actor, ActorType, Frontier, actor_id, parse_rfc3339_millis
from finishup.kernel.receipt_prediction import predict_receipt_conclusion
from finishup.ports.diagnostics import RuntimeCapability
from finishup.ports.ledger import AppendCommand, AppendEntry, OperationKind
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef, ObjectStorePort
from finishup.ports.runtime import ImporterPort, TaskRuntime
from finishup.protocol.canonical import canonical_digest, canonical_encode
from finishup.protocol.coverage import (
    AuthorshipAssurance,
    PublicationChannel,
    coverage_for_channel,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.models import StatusImportStatusModel, StatusRequest

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _digest(sequence: int) -> str:
    return "sha256:" + f"{sequence:064x}"


def _frontier(sequence: int) -> Frontier:
    return Frontier(sequence, _digest(sequence))


def _uuid(prefix: str, number: int) -> str:
    return f"{prefix}_{uuid.UUID(int=number, version=4)}"


def _ignore_diagnostic(*_args: object, **_kwargs: object) -> None:
    return None


def _entry(record: LedgerRecord, objects: MemoryObjects) -> AppendEntry:
    assert isinstance(record, AcceptedEvent)
    payload = record.payload
    assert payload is not None
    metadata = ObjectMetadata(
        ObjectKind.EVENT_PAYLOAD,
        record.payload_ref.media_type,
        record.task_id,
        parse_rfc3339_millis(record.ledger.accepted_at.wire),
    )
    ref = ObjectRef(
        record.payload_ref.object_id,
        record.payload_ref.plaintext_size,
        record.payload_ref.commitment,
        "sha256:" + "1" * 64,
        "yoetz-object/1",
        "slot-1",
        metadata,
    )
    objects._data[ref.object_id] = canonical_encode(encode_payload(payload))
    draft = EventDraft(
        record.event_id,
        record.schema,
        record.occurred_at,
        record.causal_parents,
        payload,
        record.artifact_refs,
        record.evidence_refs,
    )
    return AppendEntry(
        draft,
        record.author,
        ref,
        ref.commitment,
        metadata.media_type,
        ref.plaintext_size,
        record.publication_channel,
        record.coverage,
        "projected",
    )


def _command(
    record: LedgerRecord, objects: MemoryObjects, expected: int, number: int
) -> AppendCommand:
    entries = (_entry(record, objects),)
    operation_id = _uuid("req", number)
    return AppendCommand(
        record.task_id,
        record.session_id,
        record.writer.writer_id,
        operation_id,
        OperationKind.PUBLISH_WORK,
        canonical_digest({"event_ids": (entries[0].draft.event_id,), "operation_id": operation_id}),
        expected,
        entries,
    )


def _ledger(command: AppendCommand, objects: MemoryObjects) -> MemoryLedgerAdapter:
    return MemoryLedgerAdapter(
        task_id=command.task_id,
        ownership_fence=ownership_fence(),
        state=MemoryLedgerState(),
        import_state=MemoryImportState(),
        transaction_lock=asyncio.Lock(),
        clock=FixedClock(),
        ids=FixedIds(),
        objects=objects,
    )


def _runtime(
    ledger: MemoryLedgerAdapter, command: AppendCommand, objects: MemoryObjects
) -> TaskRuntime:
    return TaskRuntime(
        task_id=command.task_id,
        session_id=command.session_id,
        writer_id=command.writer_id,
        capabilities=frozenset({RuntimeCapability.STRUCTURAL_READ}),
        ledger=ledger,
        objects=cast(ObjectStorePort, objects),
        importer=cast(ImporterPort, object()),
        projection_version="1.0.0",
        engine_version="1.0.0",
        protocol_version="0.1",
        bundle_schema_version="1.0.0",
        fence=ownership_fence(),
    )


class _Head:
    def __init__(self, frontier: Frontier) -> None:
        self.frontier = frontier
        self.calls = 0

    async def load_frontier(self) -> Frontier:
        self.calls += 1
        return self.frontier


def _conflict() -> PublicOperationError:
    return PublicOperationError(
        PublicErrorCode.FRONTIER_CONFLICT,
        "frontier_conflict",
        True,
        safe_details={"reason_code": "frontier_changed", "sequence": 2, "head_digest": _digest(2)},
    )


def test_a_pinned_status_read_does_not_follow_the_head() -> None:
    assert _status_closure_follows_head(cursor_bound=False, at_frontier=None) is True
    assert _status_closure_follows_head(cursor_bound=True, at_frontier=None) is False
    assert _status_closure_follows_head(cursor_bound=False, at_frontier="3") is False
    assert "_status_closure_follows_head" in inspect.getsource(execute_status)


def test_the_re_read_does_not_sleep() -> None:
    source = inspect.getsource(_closure_basis_or_none) + inspect.getsource(_closure_readiness)
    assert "asyncio.sleep" not in source
    assert "time.sleep" not in source


async def test_a_same_sequence_conflict_is_not_treated_as_a_newer_head(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    frontier = _frontier(4)
    head = _Head(frontier)
    calls: list[Frontier] = []

    async def boom(_runtime: object, asked: Frontier) -> object:
        calls.append(asked)
        raise status_module.ClosureBasisUnavailable("frontier_changed")

    diagnostics: list[BaseException] = []

    def record(exc: BaseException, **_kwargs: object) -> None:
        diagnostics.append(exc)

    monkeypatch.setattr(status_module, "load_closure_basis", boom)
    monkeypatch.setattr(status_module, "record_unexpected_exception_without_raising", record)
    runtime = cast(TaskRuntime, type("Runtime", (), {"ledger": head})())

    loaded = await _closure_basis_or_none(runtime, frontier, "req_test", follow_head=True)

    assert loaded is None
    assert calls == [frontier]
    assert head.calls == 1
    assert len(diagnostics) == 1


async def test_a_non_race_failure_is_not_retried(monkeypatch: pytest.MonkeyPatch) -> None:
    frontier = _frontier(1)
    head = _Head(_frontier(9))
    calls: list[Frontier] = []

    async def boom(_runtime: object, asked: Frontier) -> object:
        calls.append(asked)
        raise status_module.ClosureBasisUnavailable("projection_replay_failed")

    monkeypatch.setattr(status_module, "load_closure_basis", boom)
    monkeypatch.setattr(
        status_module, "record_unexpected_exception_without_raising", _ignore_diagnostic
    )
    runtime = cast(TaskRuntime, type("Runtime", (), {"ledger": head})())

    loaded = await _closure_basis_or_none(runtime, frontier, None, follow_head=True)

    assert loaded is None
    assert calls == [frontier]
    assert head.calls == 0


async def test_retries_stop_at_the_bound_when_every_read_is_torn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    async def boom(_runtime: object, asked: Frontier) -> object:
        calls.append(asked.sequence)
        raise _conflict()

    class _Moving:
        async def load_frontier(self) -> Frontier:
            return _frontier(calls[-1] + 1)

    diagnostics: list[str] = []

    def record(exc: BaseException, **kwargs: object) -> None:
        diagnostics.append(str(kwargs.get("operation")))

    monkeypatch.setattr(status_module, "load_closure_basis", boom)
    monkeypatch.setattr(status_module, "record_unexpected_exception_without_raising", record)
    runtime = cast(TaskRuntime, type("Runtime", (), {"ledger": _Moving()})())

    loaded = await _closure_basis_or_none(runtime, _frontier(1), "req_test", follow_head=True)

    assert loaded is None
    assert calls == list(range(1, 2 + _CLOSURE_BASIS_HEAD_RETRIES))
    assert diagnostics == ["status_closure_prediction_unavailable"]


async def test_a_pinned_caller_is_not_advanced_past_one_conflict(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[int] = []

    async def boom(_runtime: object, asked: Frontier) -> object:
        calls.append(asked.sequence)
        raise _conflict()

    class _Moving:
        async def load_frontier(self) -> Frontier:
            raise AssertionError("pinned read must not ask for a newer frontier")

    monkeypatch.setattr(status_module, "load_closure_basis", boom)
    monkeypatch.setattr(
        status_module, "record_unexpected_exception_without_raising", _ignore_diagnostic
    )
    runtime = cast(TaskRuntime, type("Runtime", (), {"ledger": _Moving()})())

    loaded = await _closure_basis_or_none(runtime, _frontier(5), None, follow_head=False)

    assert loaded is None
    assert calls == [5]


def _arm(
    ledger: MemoryLedgerAdapter, commands: tuple[AppendCommand, ...], *, every: bool
) -> list[int]:
    original = ledger.load_case_availability
    seen: list[int] = []
    appended = 0

    async def wrapped(session_id: str, frontier: Frontier, projection: object) -> object:
        nonlocal appended
        if appended < len(commands) and (every or appended == 0):
            await ledger.append_batch(commands[appended])
            appended += 1
        seen.append(frontier.sequence)
        return await original(session_id, frontier, projection)  # type: ignore[arg-type]

    ledger.load_case_availability = wrapped  # type: ignore[method-assign]
    return seen


async def _opened_ledger() -> tuple[
    MemoryLedgerAdapter, TaskRuntime, Frontier, tuple[LedgerRecord, ...], MemoryObjects
]:
    records = replay_records("projection-rebuild")
    objects = MemoryObjects(FixedIds())
    first = _command(records[0], objects, 0, 1)
    ledger = _ledger(first, objects)
    appended = await ledger.append_batch(first)
    clear_closure_basis_memo()
    return ledger, _runtime(ledger, first, objects), appended.result_frontier, records, objects


async def test_a_material_write_between_reads_yields_the_newer_frontier() -> None:
    ledger, runtime, opened, records, objects = await _opened_ledger()
    later = _command(records[1], objects, opened.sequence, 2)
    seen = _arm(ledger, (later,), every=False)

    loaded = await _closure_basis_or_none(runtime, opened, "req_race", follow_head=True)

    assert loaded is not None
    assert loaded.basis.frontier.sequence == opened.sequence + 1
    assert any(record.schema.name == "obligation_published" for record in loaded.records)
    assert seen[0] == opened.sequence
    clear_closure_basis_memo()
    again = await load_closure_basis(runtime, loaded.basis.frontier)
    assert predict_receipt_conclusion(again.basis) == predict_receipt_conclusion(loaded.basis)

    clear_closure_basis_memo()
    readiness = await _closure_readiness(runtime, opened, None, "req_race", follow_head=True)
    prediction = readiness.model.predicted_receipt
    assert prediction is not None
    assert prediction.basis_frontier == str(opened.sequence + 1)
    assert readiness.frontier == loaded.basis.frontier
    assert readiness.compact_page is not None
    assert readiness.compact_page.effective_frontier == loaded.basis.frontier
    quiet = await _closure_readiness(
        runtime, loaded.basis.frontier, None, "req_quiet", follow_head=False
    )
    assert quiet.model.predicted_receipt == prediction


async def test_a_pinned_frontier_stays_unavailable_when_a_material_write_lands() -> None:
    ledger, runtime, opened, records, objects = await _opened_ledger()
    later = _command(records[1], objects, opened.sequence, 2)
    seen = _arm(ledger, (later,), every=False)
    diagnostics: list[str] = []

    def record(exc: BaseException, **kwargs: object) -> None:
        del exc
        diagnostics.append(str(kwargs.get("operation")))

    original = status_module.record_unexpected_exception_without_raising
    status_module.record_unexpected_exception_without_raising = record
    try:
        readiness = await _closure_readiness(runtime, opened, None, "req_pin", follow_head=False)
    finally:
        status_module.record_unexpected_exception_without_raising = original

    assert readiness.model.predicted_receipt is None
    assert readiness.frontier == opened
    assert seen == [opened.sequence]
    assert diagnostics == ["status_closure_prediction_unavailable"]
    assert (await ledger.load_frontier()).sequence == opened.sequence + 1


async def test_interleaving_past_the_retry_bound_omits_the_prediction() -> None:
    ledger, runtime, opened, records, objects = await _opened_ledger()
    commands = tuple(
        _command(records[index], objects, index, 10 + index)
        for index in range(1, 2 + _CLOSURE_BASIS_HEAD_RETRIES)
    )
    seen = _arm(ledger, commands, every=True)
    diagnostics: list[str] = []

    def record(exc: BaseException, **kwargs: object) -> None:
        del exc
        diagnostics.append(str(kwargs.get("operation")))

    original = status_module.record_unexpected_exception_without_raising
    status_module.record_unexpected_exception_without_raising = record
    try:
        loaded = await _closure_basis_or_none(runtime, opened, "req_burst", follow_head=True)
    finally:
        status_module.record_unexpected_exception_without_raising = original

    assert loaded is None
    assert seen == list(range(opened.sequence, opened.sequence + 1 + _CLOSURE_BASIS_HEAD_RETRIES))
    assert diagnostics == ["status_closure_prediction_unavailable"]
    assert (await ledger.load_frontier()).sequence == opened.sequence + len(commands)


async def test_a_suffix_safe_observation_does_not_move_the_prediction() -> None:
    ledger, runtime, opened, records, objects = await _opened_ledger()
    material = _command(records[1], objects, opened.sequence, 2)
    entry = material.entries[0]
    observed = replace(
        material,
        entries=(
            replace(
                entry,
                author=Actor(
                    actor_id(OBSERVATION_COORDINATOR_ACTOR_ID),
                    ActorType.HARNESS,
                    AuthorshipAssurance.HARNESS_OBSERVED,
                ),
                publication_channel=PublicationChannel.HOOK_OBSERVED,
                coverage=coverage_for_channel(PublicationChannel.HOOK_OBSERVED),
            ),
        ),
    )
    seen = _arm(ledger, (observed,), every=False)
    diagnostics: list[str] = []

    def record(exc: BaseException, **kwargs: object) -> None:
        del exc
        diagnostics.append(str(kwargs.get("operation")))

    original = status_module.record_unexpected_exception_without_raising
    status_module.record_unexpected_exception_without_raising = record
    try:
        loaded = await _closure_basis_or_none(runtime, opened, "req_obs", follow_head=True)
    finally:
        status_module.record_unexpected_exception_without_raising = original

    assert loaded is not None
    assert loaded.basis.frontier == opened
    assert seen == [opened.sequence]
    assert diagnostics == []
    assert (await ledger.load_frontier()).sequence == opened.sequence + 1
    assert all(record.ledger.ingestion_sequence <= opened.sequence for record in loaded.records)


_LINEAGE_TOKEN = "lineage_manifest_not_recorded"


def _status_request(runtime: TaskRuntime, view: str) -> StatusRequest:
    return StatusRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": "req_00000000-0000-4000-8000-0000000000a8",
            "session_id": runtime.session_id,
            "writer_id": runtime.writer_id,
            "view": view,
            "limit": "10",
            "actor": {"actor_id": "harness:test", "actor_type": "harness"},
            "client": {
                "kind": "test_client",
                "version": "0.1.0",
                "integration": "cooperative_mcp",
            },
        }
    )


class _RoutedRuntime:
    def __init__(self, runtime: TaskRuntime) -> None:
        self._runtime = runtime

    async def route(self, _command: object) -> TaskRuntime:
        return self._runtime

    async def release(self, runtime: TaskRuntime) -> None:
        assert runtime is self._runtime


class _StatusApp:
    def __init__(self, runtime: TaskRuntime) -> None:
        self.runtime = _RoutedRuntime(runtime)
        self.status_cursor_key = b"k" * 32
        self.start_catalog = object()
        self.project_application = None
        self.host_lineage_registry = None


async def _quiet_import(_runtime: object) -> StatusImportStatusModel:
    return StatusImportStatusModel(
        pending_count="0",
        terminal_count="0",
        phase=None,
        report_evidence_id=None,
        source_identity_digest=None,
    )


async def _race_lineage_status(
    monkeypatch: pytest.MonkeyPatch, view: str
) -> tuple[StatusInternalResult, list[int], Frontier]:
    """Append, during the basis read, the event that records the lineage the first gaps name."""

    ledger, runtime, opened, records, objects = await _opened_ledger()
    later = _command(records[1], objects, opened.sequence, 2)
    landed_event = later.entries[0].draft.event_id
    _arm(ledger, (later,), every=False)
    asked: list[int] = []

    async def gaps(
        _app: object, bound: TaskRuntime, frontier: Frontier, _request_id: str
    ) -> tuple[tuple[str, ...], bool]:
        asked.append(frontier.sequence)
        visible = False
        async for record in bound.ledger.load_events(bound.session_id, through=frontier.sequence):
            if getattr(record, "event_id", None) == landed_event:
                visible = True
                break
        if visible:
            return (), False
        return (_LINEAGE_TOKEN,), False

    monkeypatch.setattr(status_module, "_lineage_readiness_gaps", gaps)
    monkeypatch.setattr(status_module, "_import_status", _quiet_import)
    result = await execute_status(
        cast(Application, _StatusApp(runtime)), _status_request(runtime, view)
    )
    clear_closure_basis_memo()
    return result, asked, opened


async def test_compact_status_drops_a_lineage_gap_the_landed_frontier_recorded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, asked, opened = await _race_lineage_status(monkeypatch, "compact")

    assert asked == [opened.sequence, opened.sequence + 1]
    assert result.requested_frontier.sequence == opened.sequence + 1
    assert _LINEAGE_TOKEN not in result.gaps
    assert _LINEAGE_TOKEN not in result.coverage.known_gaps
    assert _LINEAGE_TOKEN not in (result.closure_readiness.agent_actionable or ())


async def test_advice_status_keeps_the_first_lineage_gap_off_the_advanced_readiness(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, asked, opened = await _race_lineage_status(monkeypatch, "advice")

    assert asked == [opened.sequence, opened.sequence + 1]
    assert result.requested_frontier == opened
    assert result.head_frontier.sequence == opened.sequence + 1
    assert _LINEAGE_TOKEN in result.gaps
    assert _LINEAGE_TOKEN not in (result.closure_readiness.agent_actionable or ())
