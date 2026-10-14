"""Focused contract tests for the bounded unit-of-work seam."""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import FrozenInstanceError, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest

from builders.replay import replay_records
from finishup.application.unit_of_work import (
    CatalogCompletion,
    CatalogPhaseAdvance,
    CatalogQuarantine,
    CommitResolution,
    PreparedMutation,
    PreSubmissionCancelled,
    resolve_ambiguous_operation,
    resolve_ambiguous_start,
    run_catalog_transition,
    run_prepared_append,
    run_publish_response_commit,
)
from finishup.domain.events import EventDraft, EventPayload
from finishup.domain.privacy import LocalDisclosureSink
from finishup.domain.values import Frontier, parse_rfc3339_millis
from finishup.ports.ledger import (
    AcceptedEventSummary,
    AppendCommand,
    AppendEntry,
    AppendResult,
    CheckPhase,
    LedgerPort,
    OperationKind,
    OperationQuarantineCode,
    OperationRecord,
    OperationState,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.ports.publish_response_catalog import (
    PublishResponseCatalogPort,
    PublishResponseKey,
    StoredPublishResponse,
)
from finishup.ports.runtime import StartCompletionEvidence, StartMilestone
from finishup.ports.start_catalog import (
    EncryptedResultRef,
    SafeReason,
    StartAllocation,
    StartCatalogPort,
    StartCommand,
    StartIdentityCommitments,
    StartIdentityInput,
    StartMode,
    StartOperationLease,
    StartPhase,
)
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import PublicErrorCode, PublicOperationError


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _append_command() -> AppendCommand:
    record = replay_records("projection-rebuild")[0]
    assert record.payload is not None
    draft = EventDraft(
        record.event_id,
        record.schema,
        record.occurred_at,
        record.causal_parents,
        cast(EventPayload, record.payload),
        record.artifact_refs,
        record.evidence_refs,
    )
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
    entry = AppendEntry(
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
    return AppendCommand(
        record.task_id,
        record.session_id,
        record.writer.writer_id,
        "req_00000000-0000-4000-8000-000000000001",
        OperationKind.PUBLISH_WORK,
        "sha256:" + "2" * 64,
        0,
        (entry,),
    )


def _prepared(command: AppendCommand | None = None) -> PreparedMutation:
    value = _append_command() if command is None else command
    return PreparedMutation(
        value.writer_id,
        value.operation_id,
        value.request_digest,
        value.expected_frontier,
        tuple(entry.payload_object for entry in value.entries),
        value,
    )


def _append_result(
    command: AppendCommand, outcome: Literal["accepted", "replayed"] = "accepted"
) -> AppendResult:
    head = Frontier(1, "sha256:" + "3" * 64)
    summary = AcceptedEventSummary(
        command.entries[0].draft.event_id, 1, 1, "sha256:" + "4" * 64, "projected"
    )
    return AppendResult(outcome, (summary,), Frontier.genesis(), head, ())


class _LedgerDouble:
    def __init__(self, command: AppendCommand) -> None:
        self.command = command
        self.calls = 0
        self.events: list[str] = []
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.release.set()
        self.record: OperationRecord | None = None
        self.lookup_error: PublicOperationError | None = None
        self.commit_error: BaseException | None = None
        self.committed = False
        self.current_frontier = command.expected_frontier
        self.owner_current = True
        self.generation_current = True

    async def append_batch(self, command: AppendCommand) -> AppendResult:
        self.calls += 1
        self.events.append("port_commit_begin")
        self.entered.set()
        await self.release.wait()
        if not self.owner_current or not self.generation_current:
            self.events.append("port_rollback")
            raise PublicOperationError(PublicErrorCode.STORAGE_UNSAFE, "Storage fence lost.", False)
        if command.expected_frontier != self.current_frontier:
            self.events.append("port_rollback")
            raise PublicOperationError(
                PublicErrorCode.FRONTIER_CONFLICT, "Frontier changed.", False
            )
        if self.commit_error is not None:
            self.events.append("port_rollback")
            raise self.commit_error
        self.committed = True
        self.events.append("port_commit_done")
        return _append_result(command, "accepted" if self.calls == 1 else "replayed")

    async def lookup_operation(self, writer_id: str, operation_id: str) -> OperationRecord | None:
        assert writer_id == self.command.writer_id
        assert operation_id == self.command.operation_id
        if self.lookup_error is not None:
            raise self.lookup_error
        return self.record

    async def lookup_task_operation(
        self, writer_id: str, operation_id: str
    ) -> OperationRecord | None:
        return await self.lookup_operation(writer_id, operation_id)


def _ledger(value: _LedgerDouble) -> LedgerPort:
    return cast(LedgerPort, value)


def _operation_record(
    command: AppendCommand,
    state: OperationState,
    *,
    digest: str | None = None,
) -> OperationRecord:
    now = datetime(2026, 7, 19, 12, 0, tzinfo=UTC)
    result = b'{"outcome":"accepted"}'
    if state is OperationState.PENDING:
        metadata = ObjectMetadata(
            ObjectKind.CHECK_RESUME,
            "application/json",
            command.task_id,
            now,
        )
        resume = ObjectRef(
            "obj_00000000-0000-4000-8000-000000000008",
            2,
            "hmac-sha256:" + "5" * 64,
            "sha256:" + "6" * 64,
            "yoetz-object/1",
            "slot-1",
            metadata,
        )
        return OperationRecord(
            command.writer_id,
            command.operation_id,
            OperationKind.CHECK,
            command.request_digest if digest is None else digest,
            state,
            CheckPhase.RESERVED,
            "owner-1",
            "lease-1",
            1,
            now + timedelta(minutes=1),
            resume,
            None,
            None,
            None,
            None,
            None,
        )
    quarantine = (
        OperationQuarantineCode.OPERATION_KIND_STATE_CONTRADICTION
        if state is OperationState.QUARANTINED
        else None
    )
    return OperationRecord(
        command.writer_id,
        command.operation_id,
        command.operation_kind,
        command.request_digest if digest is None else digest,
        state,
        CheckPhase.TERMINAL,
        None,
        None,
        None,
        None,
        None,
        result,
        "sha256:" + hashlib.sha256(result).hexdigest(),
        None,
        quarantine,
        now,
    )


def _start_command() -> StartCommand:
    return StartCommand(
        "req_00000000-0000-4000-8000-000000000011",
        "sha256:" + "7" * 64,
        StartMode.CREATE,
        StartIdentityInput("A task"),
        StartIdentityCommitments("hmac-sha256:" + "8" * 64, None, None),
    )


def _start_allocation(
    outcome: Literal["reserved", "resumed", "replayed"],
) -> StartAllocation:
    task_id = "tsk_00000000-0000-4000-8000-000000000012"
    route_digest = canonical_digest(
        {
            "task_id": task_id,
            "bundle_relpath": f"tasks/{task_id}",
            "route_generation": 1,
        }
    )
    replayed = outcome == "replayed"
    lease = None
    if not replayed:
        lease = StartOperationLease(
            1,
            "service-owner",
            1,
            datetime(2026, 7, 19, 12, 1, tzinfo=UTC),
        )
    return StartAllocation(
        outcome,
        "created",
        task_id,
        "ses_00000000-0000-4000-8000-000000000013",
        "wri_00000000-0000-4000-8000-000000000014",
        "evt_00000000-0000-4000-8000-000000000015",
        f"tasks/{task_id}",
        1,
        route_digest,
        StartPhase.TERMINAL if replayed else StartPhase.ROUTE_RESERVED,
        None,
        None,
        None,
        None,
        lease,
        b'{"outcome":"started"}' if replayed else None,
    )


class _CatalogDouble:
    def __init__(self, allocation: StartAllocation) -> None:
        self.allocation = allocation
        self.calls = 0
        self.error: PublicOperationError | None = None
        self.events: list[str] = []

    async def reserve_or_resume(self, request: StartCommand) -> StartAllocation:
        del request
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.allocation

    async def advance_phase(
        self,
        allocation: StartAllocation,
        phase: StartPhase,
        result: EncryptedResultRef | None = None,
    ) -> StartAllocation:
        del result
        self.events.append(f"advance:{phase.value}")
        return replace(allocation, phase=phase)

    async def complete(
        self,
        allocation: StartAllocation,
        result: EncryptedResultRef,
        evidence: StartCompletionEvidence,
    ) -> None:
        del allocation, result, evidence
        self.events.append("complete")

    async def quarantine(self, allocation: StartAllocation, reason: SafeReason) -> None:
        del allocation
        self.events.append(f"quarantine:{reason.code}")


def _catalog(value: _CatalogDouble) -> StartCatalogPort:
    return cast(StartCatalogPort, value)


class _PublishResponseCatalogDouble:
    def __init__(self) -> None:
        self.entered = asyncio.Event()
        self.release = asyncio.Event()
        self.calls = 0
        self.winner: StoredPublishResponse | None = None

    async def lookup(self, key: PublishResponseKey) -> StoredPublishResponse | None:
        del key
        return self.winner

    async def put_if_absent(self, response: StoredPublishResponse) -> StoredPublishResponse:
        self.calls += 1
        self.entered.set()
        await self.release.wait()
        if self.winner is None:
            self.winner = response
        return self.winner


def _stored_publish_response() -> StoredPublishResponse:
    canonical = b'{"ok":true}'
    return StoredPublishResponse(
        PublishResponseKey(
            "tsk_00000000-0000-4000-8000-000000000019",
            "ses_00000000-0000-4000-8000-000000000020",
            "wri_00000000-0000-4000-8000-000000000021",
            "req_00000000-0000-4000-8000-000000000022",
            "sha256:" + "d" * 64,
            LocalDisclosureSink.AGENT_CONTEXT,
        ),
        canonical,
        "sha256:" + hashlib.sha256(canonical).hexdigest(),
    )


def test_prepared_mutation_is_immutable_and_mirrors_the_exact_command() -> None:
    prepared = _prepared()
    with pytest.raises(FrozenInstanceError):
        prepared.expected_frontier = 9  # pyright: ignore[reportAttributeAccessIssue]
    with pytest.raises(ValueError, match="invalid_unit_of_work_value"):
        replace(prepared, request_digest="sha256:" + "9" * 64)
    with pytest.raises(ValueError, match="invalid_unit_of_work_value"):
        replace(prepared, finalized_object_refs=())


def test_commit_resolution_allows_only_outcome_specific_bounded_evidence() -> None:
    with pytest.raises(ValueError, match="invalid_unit_of_work_value"):
        CommitResolution("pending", stored_result=b"not-applicable")
    with pytest.raises(ValueError, match="invalid_unit_of_work_value"):
        CommitResolution("quarantined", safe_reason="raw adapter exception")
    with pytest.raises(ValueError, match="invalid_unit_of_work_value"):
        CommitResolution(
            "unknown",
            failure=PublicOperationError(
                PublicErrorCode.IDEMPOTENCY_CONFLICT,
                "The request ID was already used.",
                False,
            ),
        )


@pytest.mark.anyio
async def test_port_owns_commit_and_rollback_ordering_without_helper_retry() -> None:
    prepared = _prepared()
    adapter = _LedgerDouble(prepared.command)
    adapter.commit_error = RuntimeError("adapter rolled back")
    with pytest.raises(RuntimeError, match="adapter rolled back"):
        await run_prepared_append(_ledger(adapter), prepared)
    assert adapter.calls == 1
    assert adapter.events == ["port_commit_begin", "port_rollback"]


@pytest.mark.anyio
async def test_cancellation_during_commit_waits_for_definite_outcome_then_reraises() -> None:
    prepared = _prepared()
    adapter = _LedgerDouble(prepared.command)
    adapter.release.clear()
    task = asyncio.create_task(run_prepared_append(_ledger(adapter), prepared))
    await adapter.entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    adapter.release.set()
    with pytest.raises(asyncio.CancelledError) as caught:
        await task
    assert adapter.committed
    assert adapter.calls == 1
    assert adapter.events == ["port_commit_begin", "port_commit_done"]
    # A submitted commit is ambiguous, so it must never carry the pre-submission certificate that
    # licenses a caller to abandon its finalized objects.
    assert not isinstance(caught.value, PreSubmissionCancelled)


@pytest.mark.anyio
async def test_cancellation_pending_before_submission_never_calls_port() -> None:
    prepared = _prepared()
    adapter = _LedgerDouble(prepared.command)

    async def cancelled_caller() -> None:
        current = asyncio.current_task()
        assert current is not None
        current.cancel()
        await run_prepared_append(_ledger(adapter), prepared)

    with pytest.raises(PreSubmissionCancelled):
        await cancelled_caller()
    assert adapter.calls == 0
    assert issubclass(PreSubmissionCancelled, asyncio.CancelledError)


@pytest.mark.anyio
async def test_publish_response_commit_is_shielded_and_returns_the_persisted_winner() -> None:
    adapter = _PublishResponseCatalogDouble()
    response = _stored_publish_response()
    task = asyncio.create_task(
        run_publish_response_commit(cast(PublishResponseCatalogPort, adapter), response)
    )
    await adapter.entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    adapter.release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert adapter.winner is response
    assert adapter.calls == 1


@pytest.mark.anyio
async def test_same_prepared_retry_delegates_idempotency_and_never_caches() -> None:
    prepared = _prepared()
    adapter = _LedgerDouble(prepared.command)
    first = await run_prepared_append(_ledger(adapter), prepared)
    second = await run_prepared_append(_ledger(adapter), prepared)
    assert first.outcome == "accepted"
    assert second.outcome == "replayed"
    assert adapter.calls == 2


@pytest.mark.anyio
@pytest.mark.parametrize("fence", ["ownership", "generation", "frontier"])
async def test_port_fences_are_propagated_without_retry_or_adapter_bypass(fence: str) -> None:
    prepared = _prepared()
    adapter = _LedgerDouble(prepared.command)
    if fence == "ownership":
        adapter.owner_current = False
    elif fence == "generation":
        adapter.generation_current = False
    else:
        adapter.current_frontier = 9
    expected = (
        PublicErrorCode.FRONTIER_CONFLICT if fence == "frontier" else PublicErrorCode.STORAGE_UNSAFE
    )
    with pytest.raises(PublicOperationError) as caught:
        await run_prepared_append(_ledger(adapter), prepared)
    assert caught.value.code is expected
    assert adapter.calls == 1


@pytest.mark.anyio
async def test_ledger_resolution_table_and_digest_conflict() -> None:
    command = _append_command()
    adapter = _LedgerDouble(command)
    assert (
        await resolve_ambiguous_operation(
            _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
        )
    ).outcome == "not_committed"

    adapter.record = _operation_record(command, OperationState.COMPLETE)
    committed = await resolve_ambiguous_operation(
        _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
    )
    assert committed == CommitResolution("committed", stored_result=b'{"outcome":"accepted"}')

    adapter.record = _operation_record(command, OperationState.PENDING)
    assert (
        await resolve_ambiguous_operation(
            _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
        )
    ).outcome == "pending"

    adapter.record = _operation_record(command, OperationState.QUARANTINED)
    quarantined = await resolve_ambiguous_operation(
        _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
    )
    assert quarantined == CommitResolution(
        "quarantined", safe_reason="operation_kind_state_contradiction"
    )

    adapter.record = _operation_record(
        command, OperationState.COMPLETE, digest="sha256:" + "9" * 64
    )
    with pytest.raises(PublicOperationError) as caught:
        await resolve_ambiguous_operation(
            _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
        )
    assert caught.value.code is PublicErrorCode.IDEMPOTENCY_CONFLICT


@pytest.mark.anyio
async def test_unverified_storage_is_unknown_and_nonstorage_failure_propagates() -> None:
    command = _append_command()
    adapter = _LedgerDouble(command)
    storage = PublicOperationError(PublicErrorCode.STORAGE_UNSAFE, "Storage unverified.", False)
    adapter.lookup_error = storage
    assert await resolve_ambiguous_operation(
        _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
    ) == CommitResolution("unknown", failure=storage)

    conflict = PublicOperationError(
        PublicErrorCode.IDEMPOTENCY_CONFLICT, "The request ID was already used.", False
    )
    adapter.lookup_error = conflict
    with pytest.raises(PublicOperationError) as caught:
        await resolve_ambiguous_operation(
            _ledger(adapter), command.writer_id, command.operation_id, command.request_digest
        )
    assert caught.value is conflict


@pytest.mark.anyio
async def test_start_resolution_uses_catalog_scope_and_closed_transition() -> None:
    command = _start_command()
    reserved = _CatalogDouble(_start_allocation("reserved"))
    assert await run_catalog_transition(_catalog(reserved), command) == reserved.allocation
    assert reserved.calls == 1

    replayed = _CatalogDouble(_start_allocation("replayed"))
    resolution = await resolve_ambiguous_start(_catalog(replayed), command)
    assert resolution == CommitResolution("committed", stored_result=b'{"outcome":"started"}')
    assert replayed.calls == 1


@pytest.mark.anyio
async def test_closed_catalog_transition_values_dispatch_exactly_once() -> None:
    allocation = _start_allocation("reserved")
    adapter = _CatalogDouble(allocation)
    advanced = await run_catalog_transition(
        _catalog(adapter), CatalogPhaseAdvance(allocation, StartPhase.BUNDLE_READY)
    )
    assert advanced.phase is StartPhase.BUNDLE_READY

    result_bytes = b'{"outcome":"started"}'
    result = EncryptedResultRef(
        "obj_00000000-0000-4000-8000-000000000016",
        "sha256:" + "a" * 64,
        result_bytes,
        "sha256:" + hashlib.sha256(result_bytes).hexdigest(),
    )
    evidence = StartCompletionEvidence(
        StartMilestone.RESULT_PUBLISHED,
        allocation.task_id,
        allocation.session_id,
        allocation.writer_id,
        allocation.lifecycle_event_id,
        allocation.route_generation,
        allocation.route_identity_digest,
        1,
        Frontier(1, "sha256:" + "b" * 64),
        result.response_object_id,
        result.envelope_digest,
        result.result_digest,
        "sha256:" + "c" * 64,
    )
    assert (
        await run_catalog_transition(
            _catalog(adapter), CatalogCompletion(advanced, result, evidence)
        )
        is None
    )
    assert (
        await run_catalog_transition(
            _catalog(adapter),
            CatalogQuarantine(advanced, SafeReason("start_lifecycle_contradiction")),
        )
        is None
    )
    assert adapter.events == [
        "advance:bundle_ready",
        "complete",
        "quarantine:start_lifecycle_contradiction",
    ]


def test_unit_of_work_has_no_concrete_adapter_or_transaction_dependency() -> None:
    source = Path(__file__).parents[3] / "src/finishup/application/unit_of_work.py"
    text = source.read_text(encoding="utf-8")
    assert "finishup.adapters" not in text
    assert "sqlite" not in text.lower()
    assert "connection" not in text.lower()
    assert "rollback(" not in text
