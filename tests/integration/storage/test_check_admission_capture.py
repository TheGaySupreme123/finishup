"""A check refused behind a native capture handoff converges once the handoff drains (#838).

The native failure was a deterministic check that returned retryable ``OPERATION_PENDING`` twice
while ``status view=operation`` reported ``absent``. The storage-level shape of that failure: a
pending check that nobody renews keeps deferring the observation append that would consume the
task's capture handoff, and every new check on the task waits on that handoff. These tests drive
that interleaving with explicit clock steps and ticket transitions, never sleeps.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime

import pytest

from conformance.adapters.test_check_admission import (
    _adapter,  # pyright: ignore[reportPrivateUsage]
    _SteppingClock,  # pyright: ignore[reportPrivateUsage]
)
from conformance.adapters.test_ledger_port import (
    _observation_command,  # pyright: ignore[reportPrivateUsage]
    ledger_command,
)
from finishup.adapters.sqlite.repository import SqliteLedger
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
)
from finishup.ports.ledger import (
    AppendCommand,
    CheckAdmissionStage,
    FrozenCase,
    check_admission_stage,
)
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectSource
from finishup.protocol.canonical import canonical_digest
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from integration.storage.test_capture_freeze_barrier import (
    _ticket,  # pyright: ignore[reportPrivateUsage]
)

_DIGEST = "sha256:" + "9" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _pending_handoff(
    ledger: SqliteLedger, command: AppendCommand, logical_identity: str
) -> ObservationCaptureTicket:
    """Stage, manifest, and finalize one complete native handoff exactly as capture-only does."""

    store = ledger.open_observation_store()
    staging = _ticket(command, logical_identity=logical_identity)
    store.record_capture_ticket(staging)
    objects = ledger._objects  # pyright: ignore[reportPrivateUsage]
    assert objects is not None
    staged = await objects.stage(
        ObjectSource(data=b"encrypted-capture", declared_size=17),
        ObjectMetadata(
            ObjectKind.CAPTURED_CONTENT,
            "text/plain",
            command.task_id,
            datetime(2026, 7, 19, 12, 0, tzinfo=UTC),
        ),
    )
    captured = await objects.finalize(staged)
    correlation = "hook:freeze-barrier:tool-output"
    store.record_content_manifest(
        workspace=staging.workspace_commitment,
        logical_identity=staging.logical_identity,
        chunk=ObservationContentChunk(
            content_kind=ObservationContentKind.TOOL_OUTPUT,
            correlation_identity=correlation,
            source_commitment=staging.cursor.last_source_commitment,
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=b"encrypted-capture",
        ),
        ref=captured,
        content_digest=canonical_digest({"content": "encrypted-capture"}),
        content_bytes=17,
        recorded_at=staging.captured_at,
    )
    pending = replace(
        staging,
        object_ids=(captured.object_id,),
        state="pending",
        expected_parts=(
            (
                ObservationContentKind.TOOL_OUTPUT.value,
                correlation,
                staging.cursor.last_source_commitment,
                0,
                1,
            ),
        ),
    )
    store.finalize_capture_ticket(staging, pending)
    return pending


async def _refused(ledger: SqliteLedger, command: AppendCommand, request_id: str) -> None:
    with pytest.raises(PublicOperationError) as refused:
        await ledger.freeze_case(command.session_id, command.writer_id, 1, request_id, _DIGEST)
    assert refused.value.code is PublicErrorCode.OPERATION_PENDING
    assert refused.value.retryable is True
    assert check_admission_stage(refused.value) is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING
    assert refused.value.safe_details["continuation"] == "check_admission_same_identity"


@pytest.mark.anyio
async def test_capture_refusal_is_visible_and_the_exact_replay_admits_after_delivery() -> None:
    command = ledger_command(unknown=True)
    clock = _SteppingClock()
    ledger, _ = _adapter("sqlite", command, clock)
    assert isinstance(ledger, SqliteLedger)
    await ledger.append_batch(command)
    handoff = await _pending_handoff(ledger, command, "sha256:" + "a" * 64)
    request_id = "req_00000000-0000-4000-8000-0000000008d1"

    await _refused(ledger, command, request_id)
    clock.advance(14)
    await _refused(ledger, command, request_id)
    # Operation recovery now distinguishes this from a request the service never saw.
    assert await ledger.lookup_operation(command.writer_id, request_id) is None
    admission = await ledger.lookup_check_admission(command.writer_id, request_id)
    assert admission is not None
    assert admission.stage is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING
    assert admission.refusal_count == 2
    assert (admission.last_observed_at - admission.first_observed_at).total_seconds() == 14

    # The structural delivery consumes the handoff; the unchanged request then admits.
    ledger.open_observation_store().delete_capture_ticket(handoff)
    admitted = await ledger.freeze_case(
        command.session_id, command.writer_id, 1, request_id, _DIGEST
    )
    assert type(admitted) is FrozenCase
    assert await ledger.lookup_check_admission(command.writer_id, request_id) is None
    operation = await ledger.lookup_operation(command.writer_id, request_id)
    assert operation is not None and operation.operation_id == request_id


@pytest.mark.anyio
async def test_abandoned_check_no_longer_strands_the_handoff_every_new_check_waits_on() -> None:
    """Reproduce the native stall end to end, then show both requests converge."""

    command = ledger_command(unknown=True)
    delivery = _observation_command(request_suffix="3", expected_frontier=1, seed="f")
    clock = _SteppingClock()
    ledger, _ = _adapter("sqlite", command, clock)
    assert isinstance(ledger, SqliteLedger)
    await ledger.append_batch(command)
    abandoned_request = "req_00000000-0000-4000-8000-0000000008d2"
    abandoned = await ledger.freeze_case(
        command.session_id, command.writer_id, 1, abandoned_request, _DIGEST
    )
    assert type(abandoned) is FrozenCase
    handoff = await _pending_handoff(ledger, command, "sha256:" + "b" * 64)

    new_request = "req_00000000-0000-4000-8000-0000000008d3"
    await _refused(ledger, command, new_request)
    # While the earlier check's lease is live its barrier is real, so the handoff's structural
    # delivery defers and the exact replay is refused at the same stage.
    with pytest.raises(PublicOperationError) as deferred:
        await ledger.append_batch(delivery)
    assert deferred.value.code is PublicErrorCode.OPERATION_PENDING
    await _refused(ledger, command, new_request)

    # Its invocation went away. Before issue #838 the barrier outlived the lease forever, so the
    # delivery, the handoff, and every new check on the task stayed blocked together.
    clock.advance(61)
    drained = await ledger.append_batch(delivery)
    assert drained.result_frontier.sequence == 2
    ledger.open_observation_store().delete_capture_ticket(handoff)

    admitted = await ledger.freeze_case(
        command.session_id, command.writer_id, 2, new_request, _DIGEST
    )
    assert type(admitted) is FrozenCase
    assert admitted.case.frontier.sequence == 2
    assert await ledger.lookup_check_admission(command.writer_id, new_request) is None

    # The abandoned request still converges on its own operation and original frontier.
    reclaimed = await ledger.freeze_case(
        command.session_id, command.writer_id, 1, abandoned_request, _DIGEST
    )
    assert type(reclaimed) is FrozenCase
    assert reclaimed.case.frontier.sequence == 1
