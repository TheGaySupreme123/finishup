"""Admission-independent loss reporting uses only the original task attribution."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
)
from finishup.application.observation_drain import ObservationOutboxSweeper
from finishup.domain.observation import ObservationCursor, ObservationEnvelope, ObservationSource
from finishup.domain.observation_budget import LARGEST_CAPACITY
from finishup.domain.observation_settings import ObservationDetailProfile, ObservationSelection
from finishup.domain.values import JsonObject, Timestamp
from finishup.ports.ledger import FrozenCase
from finishup.protocol.ids import IdKind
from integration.application.test_check import (  # pyright: ignore[reportPrivateUsage]
    _App,  # pyright: ignore[reportPrivateUsage]
    _request,  # pyright: ignore[reportPrivateUsage]
    execute_check_commit,
)
from integration.application.test_native_capture_pipeline import (
    _ids,  # pyright: ignore[reportPrivateUsage]
)
from integration.service.test_capture_inventory_recovery import (  # pyright: ignore[reportPrivateUsage]
    _native_failed_command,  # pyright: ignore[reportPrivateUsage]
    _World,  # pyright: ignore[reportPrivateUsage]
    _world,  # pyright: ignore[reportPrivateUsage]
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
@pytest.mark.parametrize("host", ("claude", "cursor", "codex"))
async def test_loss_reaches_task_and_frozen_check_without_new_event(
    tmp_path: Path, host: str
) -> None:
    world = await _world(tmp_path, host=host)
    sweeper = world.sweep()
    try:
        await asyncio.to_thread(_native_failed_command, world, host, "lost", "not-retained")
        before = world.local.selection_accounting(world.workspace)
        assert before["unrecoverable_input_count"] == 1
        assert world.local.pending_selection_losses(world.workspace)
        await sweeper.sweep()
        assert world.requests == []
        assert not world.local.pending_selection_losses(world.workspace)
        after = world.local.selection_accounting(world.workspace)
        assert after["unrecoverable_input_count"] == 1
        assert after["loss_identity_commitment"] == before["loss_identity_commitment"]
        history = world.observation.list_envelopes_for_session(world.workspace, world.session)
        assert len(history) == 1
        assert history[0].event_kind == "observation_gap"
        assert history[0].gap_codes == ("observation_input_loss",)
        assert world.sibling_observation.list_envelopes(world.workspace) == ()
        frontier = await world.runtime.ledger.load_frontier()
        assert frontier.sequence > 0
        frozen = await world.runtime.ledger.freeze_case(
            world.runtime.session_id,
            cast(str, world.runtime.writer_id),
            frontier.sequence,
            _ids(IdKind.REQUEST, 9201),
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        assert any(
            "observation_input_loss" in coverage.known_gaps
            for coverage in frozen.case.coverage_by_ref.values()
        )
    finally:
        sweeper.close()
        world.coordinator.close()


@pytest.mark.anyio
async def test_retry_after_ledger_commit_and_restart_does_not_duplicate_loss(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        original = world.local.acknowledge_selection_loss

        def failed_ack(_workspace: str, _lane: str) -> None:
            raise OSError("synthetic acknowledgement failure")

        monkeypatch.setattr(world.local, "acknowledge_selection_loss", failed_ack)
        with pytest.raises(OSError):
            await world.coordinator.reconcile_task_selection_losses(world.runtime)
        before = await world.runtime.ledger.load_frontier()
        assert world.local.pending_selection_losses(world.workspace)
        reopened = LocalObservationStore(_state=tmp_path / "state")
        world.local = reopened
        world.wire()
        await world.coordinator.reconcile_task_selection_losses(world.runtime)
        assert (await world.runtime.ledger.load_frontier()).sequence == before.sequence
        assert not reopened.pending_selection_losses(world.workspace)
        assert len(world.observation.list_envelopes(world.workspace)) == 1
        # Durable acknowledgement avoids a new report after another restart.
        assert not LocalObservationStore(_state=tmp_path / "state").pending_selection_losses(
            world.workspace
        )
        del original
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_new_check_reconciles_losses_and_completed_replay_skips_new_history() -> None:
    app = _App()
    calls: list[object] = []

    async def reconcile(runtime: object) -> None:
        assert app.ledger.operation is None
        calls.append(runtime)

    setattr(app, "reconcile_observation_losses", reconcile)
    first = await execute_check_commit(app, _request())
    assert len(calls) == 1

    async def fail_if_called(_runtime: object) -> None:
        raise AssertionError("a completed check must preserve its frozen inputs")

    setattr(app, "reconcile_observation_losses", fail_if_called)
    app.ledger.replay = first
    assert await execute_check_commit(app, _request()) is first


@pytest.mark.anyio
async def test_real_check_imports_loss_before_freezing_and_preserves_replay(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        app = _App()
        app.runtime = cast(object, world.routes)  # pyright: ignore[reportAttributeAccessIssue]
        setattr(
            app, "reconcile_observation_losses", world.coordinator.reconcile_task_selection_losses
        )
        frontier = await world.runtime.ledger.load_frontier()
        request = _request().model_copy(
            update={
                "session_id": world.runtime.session_id,
                "writer_id": world.runtime.writer_id,
                "request_id": _ids(IdKind.REQUEST, 9300),
                "expected_frontier": _request().expected_frontier.model_copy(
                    update={
                        "sequence": str(frontier.sequence),
                        "head_digest": frontier.head_digest,
                    }
                ),
            }
        )
        first = await execute_check_commit(app, request)
        assert "observation_input_loss" in first.coverage.known_gaps
        assert not world.local.pending_selection_losses(world.workspace)

        # A later lost lane cannot change this check's already frozen result.
        async def fail_if_called(_runtime: object) -> None:
            raise AssertionError("replay inspected mutable loss history")

        setattr(app, "reconcile_observation_losses", fail_if_called)
        replay = await execute_check_commit(app, request)
        assert replay.coverage == first.coverage

        from dataclasses import replace

        from finishup.application.receipt import execute_receipt
        from finishup.ports.importer import ImporterPort
        from finishup.ports.runtime import BundleRuntimePort
        from finishup.protocol.models import ReceiptRequest
        from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
            _build_app,  # pyright: ignore[reportPrivateUsage]
            _IdleImporter,  # pyright: ignore[reportPrivateUsage]
            _receipt_wire,  # pyright: ignore[reportPrivateUsage]
        )

        current = replace(world.runtime, importer=cast(ImporterPort, _IdleImporter()))
        world.routes.runtimes[current.session_id] = current
        receipt_app, _, _ = _build_app()
        receipt_app = replace(receipt_app, runtime=cast(BundleRuntimePort, world.routes))
        receipt = await execute_receipt(
            receipt_app,  # pyright: ignore[reportArgumentType]
            ReceiptRequest.model_validate(
                _receipt_wire(
                    9399,
                    task_id=current.task_id,
                    session=current.session_id,
                    writer=cast(str, current.writer_id),
                    frontier=replay.result_frontier,
                )
            ),
        )
        assert "observation_input_loss" in receipt.coverage.known_gaps
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_unrouted_loss_stays_local_and_new_task_binding_cannot_claim_it(
    tmp_path: Path,
) -> None:
    from finishup.domain.observation import (
        ObservationCursor,
        ObservationEnvelope,
        ObservationSource,
    )
    from finishup.domain.values import JsonObject, timestamp_from_datetime

    world = await _world(tmp_path)
    try:
        envelope = ObservationEnvelope(
            world.session,
            "PostToolUse",
            "unrouted-failure",
            ObservationSource.CLAUDE_HOOK,
            ObservationCursor(1, 0, 1, "hmac-sha256:" + "2" * 64, "test/1"),
            timestamp_from_datetime(world.coordinator.clock.now_utc()),
            JsonObject({"tool_name": "Bash", "exit_status": 1}),
            (),
            (),
        )
        world.local.record_admission_loss(world.workspace, envelope)
        assert world.local.selection_accounting(world.workspace)["unrecoverable_input_count"] == 1
        assert not world.local.pending_selection_losses(world.workspace)
        assert not world.local.selection_loss_workspaces()
        await world.coordinator.reconcile_task_selection_losses(world.runtime)
        assert (await world.runtime.ledger.load_frontier()).sequence == 0
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_healthy_capture_inventory_still_reports_loss_and_preserves_native_cursor(
    tmp_path: Path,
) -> None:
    world = await _world(tmp_path)
    sweeper = world.sweep()
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        # A separate successful inventory proof must not remove loss demand.
        from finishup.domain.observation import ObservationCaptureBacklog

        world.local.bootstrap_capture_reservations(
            world.workspace,
            {
                world.runtime.task_id: ObservationCaptureBacklog(0, 0, None),
                world.sibling.task_id: ObservationCaptureBacklog(0, 0, None),
            },
            complete=True,
        )
        assert world.local.capture_reservation_bootstrap_ready(world.workspace)
        assert world.workspace in world.local.pending_workspaces()
        await sweeper.sweep()
        assert not world.local.pending_selection_losses(world.workspace)
        assert (await world.runtime.ledger.load_frontier()).sequence > 0
        # The first actual host event is still admissible: the loss marker must
        # not move the task's native cursor or consume its source identity.
        await asyncio.to_thread(_native_failed_command, world, "claude", "next", "retained")
        assert world.requests
        assert world.local.selection_accounting(world.workspace)["unrecoverable_input_count"] == 1
    finally:
        sweeper.close()
        world.coordinator.close()


@pytest.mark.anyio
async def test_failed_loss_reconciliation_prevents_new_check_freeze() -> None:
    app = _App()

    async def unavailable(_runtime: object) -> None:
        raise OSError("synthetic loss read failure")

    setattr(app, "reconcile_observation_losses", unavailable)
    from finishup.protocol.errors import PublicErrorCode, PublicOperationError

    with pytest.raises(PublicOperationError) as caught:
        await execute_check_commit(app, _request())
    assert caught.value.code is PublicErrorCode.INTERNAL_ERROR
    assert app.ledger.operation is None


@pytest.mark.anyio
async def test_store_contention_during_loss_reconciliation_is_a_retryable_refusal() -> None:
    """#689: a contended local store is not an internal failure of the child recheck."""

    from finishup.ports.ledger import CheckAdmissionStage, check_admission_stage
    from finishup.ports.observation import ObservationStoreLockTimeout
    from finishup.protocol.errors import PublicErrorCode, PublicOperationError

    app = _App()

    async def contended(_runtime: object) -> None:
        raise ObservationStoreLockTimeout(
            scope="thread",
            waited_ms=2_000,
            holder_role="sweep",
            holder_phase="bump_outbox_row_attempt",
            holder_held_ms=2_300,
            holder_waiting=True,
        )

    setattr(app, "reconcile_observation_losses", contended)
    with pytest.raises(PublicOperationError) as caught:
        await execute_check_commit(app, _request())
    assert caught.value.code is PublicErrorCode.OPERATION_PENDING
    assert caught.value.retryable
    assert check_admission_stage(caught.value) is CheckAdmissionStage.ACQUISITION_CONTENDED
    assert caught.value.safe_details["reason_code"] == "check_admission_contended"
    # Nothing was admitted, so the exact replay converges once the store is free.
    assert app.ledger.operation is None

    async def reconciled(_runtime: object) -> None:
        return None

    setattr(app, "reconcile_observation_losses", reconciled)
    assert await execute_check_commit(app, _request()) is not None


@pytest.mark.anyio
async def test_wrong_runtime_cannot_retarget_a_loss(tmp_path: Path) -> None:
    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        world.routes.runtimes[world.runtime.session_id] = world.sibling
        await world.coordinator.reconcile_task_selection_losses(world.runtime)
        assert not world.local.pending_selection_losses(world.workspace)
        assert (await world.runtime.ledger.load_frontier()).sequence > 0
        assert len(world.observation.list_envelopes(world.workspace)) == 1
        assert world.sibling_observation.list_envelopes(world.workspace) == ()
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_quarantined_loss_marker_uses_one_recovery_operation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from hashlib import sha256

    from finishup.ports.ledger import (
        CheckPhase,
        OperationKind,
        OperationQuarantineCode,
        OperationRecord,
        OperationState,
    )

    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        report = world.local.pending_selection_losses(world.workspace)[0]
        from finishup.domain.observation_loss import ObservationSelectionLoss
        from finishup.protocol.canonical import canonical_digest

        loss = ObservationSelectionLoss.from_local_range(report)
        digest = canonical_digest(
            {
                "format": "yoetz.selection-loss-report/1",
                "task_id": loss.task_id,
                "lane": loss.lane,
            }
        )
        operation_id = world.coordinator._stable_operation_id(digest)  # pyright: ignore[reportPrivateUsage]
        terminal = world.coordinator.clock.now_utc()
        result = b"{}"
        quarantined = OperationRecord(
            cast(str, world.runtime.writer_id),
            operation_id,
            OperationKind.PUBLISH_WORK,
            digest,
            OperationState.QUARANTINED,
            CheckPhase.TERMINAL,
            None,
            None,
            None,
            None,
            None,
            result,
            "sha256:" + sha256(result).hexdigest(),
            None,
            OperationQuarantineCode.OPERATION_KIND_STATE_CONTRADICTION,
            terminal,
        )
        original_lookup = world.runtime.ledger.lookup_task_operation

        async def lookup(writer_id: str, candidate_id: str) -> OperationRecord | None:
            if candidate_id == operation_id:
                return quarantined
            return await original_lookup(writer_id, candidate_id)

        monkeypatch.setattr(world.runtime.ledger, "lookup_task_operation", lookup)
        await world.coordinator.reconcile_task_selection_losses(world.runtime)

        assert not world.local.pending_selection_losses(world.workspace)
        reopened = LocalObservationStore(_state=tmp_path / "state")
        assert not reopened.pending_selection_losses(world.workspace)
        assert len(world.observation.list_envelopes(world.workspace)) == 1
        assert (await world.runtime.ledger.load_frontier()).sequence > 0
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_route_valid_malformed_lane_keeps_explicit_loss_coverage(tmp_path: Path) -> None:
    from finishup.domain.observation_loss import ObservationSelectionLoss
    from finishup.domain.values import JsonObject

    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")
        state = world.local._load(world.workspace)  # pyright: ignore[reportPrivateUsage]
        entry = dict(state.selection_loss_ranges[0])
        entry["lane"] = "sha256:" + "0" * 64
        state.selection_loss_ranges = (JsonObject(entry),)
        world.local._save(world.workspace, state)  # pyright: ignore[reportPrivateUsage]

        await world.coordinator.reconcile_task_selection_losses(world.runtime)

        assert not world.local.pending_selection_losses(world.workspace)
        normalized = ObservationSelectionLoss.from_local_range_for_recovery(JsonObject(entry))
        state = world.local._load(world.workspace)  # pyright: ignore[reportPrivateUsage]
        state.selection_reported_loss_lanes = tuple(
            [f"sha256:{index:064x}" for index in range(64)] + [normalized.lane]
        )
        world.local._save(world.workspace, state)  # pyright: ignore[reportPrivateUsage]
        reopened = LocalObservationStore(_state=tmp_path / "state")
        assert not reopened.pending_selection_losses(world.workspace)
        assert len(world.observation.list_envelopes(world.workspace)) == 1
        frontier = await world.runtime.ledger.load_frontier()
        frozen = await world.runtime.ledger.freeze_case(
            world.runtime.session_id,
            cast(str, world.runtime.writer_id),
            frontier.sequence,
            _ids(IdKind.REQUEST, 9251),
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        assert any(
            "observation_input_loss" in coverage.known_gaps
            for coverage in frozen.case.coverage_by_ref.values()
        )
    finally:
        world.coordinator.close()


@pytest.mark.anyio
async def test_loss_reporting_does_not_require_retained_host_mapping(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = await _world(tmp_path)
    try:
        await asyncio.to_thread(_native_failed_command, world, "claude", "lost", "not-retained")

        # Lifecycle pruning and a unavailable future hook must not hide an
        # already authenticated loss route. No new mapping is created.
        def no_sessions(_workspace: str) -> tuple[str, ...]:
            return ()

        def no_mapping(_host: str, *, _state: Path | None = None) -> None:
            return None

        monkeypatch.setattr(world.local, "unambiguous_codex_sessions_for_workspace", no_sessions)
        monkeypatch.setattr(world.coordinator, "mapping_loader", no_mapping)
        await world.coordinator.reconcile_task_selection_losses(world.runtime)
        assert not world.local.pending_selection_losses(world.workspace)
        assert (await world.runtime.ledger.load_frontier()).sequence > 0
    finally:
        world.coordinator.close()


# --- #843: a refusal after lowering above the 1 MiB fallback stays visible ---

_HOST_SOURCES = {
    "claude": ObservationSource.CLAUDE_HOOK,
    "cursor": ObservationSource.CURSOR_HOOK,
    "codex": ObservationSource.CODEX_HOOK,
}


def _lower_after_accepting_backlog(world: _World, host: str, count: int = 1_700) -> None:
    """Accept host rows under Largest in one save, then revoke to the fallback."""

    local = world.local
    local.set_workspace_selection(
        world.workspace,
        ObservationSelection(detail=ObservationDetailProfile.FOCUSED, capacity=LARGEST_CAPACITY),
    )
    with local._lock:  # pyright: ignore[reportPrivateUsage]
        state = local._load(world.workspace)  # pyright: ignore[reportPrivateUsage]
        assert state.pending_outbox is not None
        state.pending_outbox.extend(
            ObservationOutboxRow(
                codex_session_id=world.host_session,
                envelope=ObservationEnvelope(
                    session_commitment=world.session,
                    event_kind="PostToolUse",
                    source_identity=f"backlog:{index}",
                    source=_HOST_SOURCES[host],
                    cursor=ObservationCursor(
                        source_generation=1,
                        byte_position=0,
                        event_position=10_000 + index,
                        last_source_commitment="hmac-sha256:" + "a" * 64,
                        mapping_version="codex-obs-hook/1.0.0",
                    ),
                    receipt_time=Timestamp("2026-09-10T00:01:00.000Z"),
                    structural_payload=JsonObject({"tool_name": "shell", "exit_status": 1}),
                    content_object_refs=(),
                    gap_codes=(),
                ),
            )
            for index in range(count)
        )
        local._save(world.workspace, state)  # pyright: ignore[reportPrivateUsage]
    path = local._workspace_path(world.workspace)  # pyright: ignore[reportPrivateUsage]
    assert path.stat().st_size > 1_048_576
    local.clear_workspace_selection(world.workspace)


@pytest.mark.anyio
@pytest.mark.parametrize("host", ("claude", "cursor", "codex"))
async def test_refusal_after_lowering_above_the_byte_ceiling_reaches_check_and_receipt(
    tmp_path: Path, host: str
) -> None:
    world = await _world(tmp_path, host=host)
    sweeper = world.sweep()
    try:
        # Recover capture inventory first so only the lowered capacity refuses.
        assert (await sweeper.sweep()).reasons == (("capture_inventory_recovered", 1),)
        _lower_after_accepting_backlog(world, host)

        assert (
            await asyncio.to_thread(_native_failed_command, world, host, "over-target", "refused")
            == 0
        )
        accounting = world.local.selection_accounting(world.workspace)
        assert accounting["unrecoverable_input_count"] == 1
        assert world.local.pending_selection_losses(world.workspace)
        backlog = world.local.pending_outbox_count(world.workspace)
        # The refused hook may already deliver and acknowledge accepted rows. A
        # committed row can also remain queued for an idempotent retry when the
        # hook budget ends, so pending and delivered identities may overlap.
        expected_sources = {f"backlog:{index}" for index in range(1_700)}
        pending_sources = {
            row.envelope.source_identity
            for row in world.local.list_pending_outbox_rows(world.workspace)
        }
        before_history = world.observation.list_envelopes_for_session(
            world.workspace, world.session
        )
        delivered_sources = {
            item.source_identity for item in before_history if item.event_kind == "PostToolUse"
        }
        assert pending_sources | delivered_sources == expected_sources

        # A bounded real drain at the byte boundary: deliveries acknowledge and
        # the loss reaches task history without any new host event.
        drain = ObservationOutboxSweeper(
            world.local,
            world.coordinator,
            capture_recovery=world.coordinator.recover_capture_inventory,
            limit=2,
        )
        try:
            await drain.sweep()
        finally:
            drain.close()
        assert world.local.pending_outbox_count(world.workspace) == backlog - 2
        assert not world.local.pending_selection_losses(world.workspace)
        history = world.observation.list_envelopes_for_session(world.workspace, world.session)
        assert [item.gap_codes for item in history if item.event_kind == "observation_gap"] == [
            ("observation_input_loss",)
        ]
        pending_sources = {
            row.envelope.source_identity
            for row in world.local.list_pending_outbox_rows(world.workspace)
        }
        delivered_sources = {
            item.source_identity for item in history if item.event_kind == "PostToolUse"
        }
        assert pending_sources | delivered_sources == expected_sources

        # The frozen check input and the receipt carry the loss.
        frontier = await world.runtime.ledger.load_frontier()
        frozen = await world.runtime.ledger.freeze_case(
            world.runtime.session_id,
            cast(str, world.runtime.writer_id),
            frontier.sequence,
            _ids(IdKind.REQUEST, 9401),
            "sha256:" + "0" * 64,
        )
        assert isinstance(frozen, FrozenCase)
        assert any(
            "observation_input_loss" in coverage.known_gaps
            for coverage in frozen.case.coverage_by_ref.values()
        )
        check_gaps, receipt_gaps = await _check_and_receipt_known_gaps(world, seed=9402)
        assert "observation_input_loss" in check_gaps
        assert "observation_input_loss" in receipt_gaps
    finally:
        sweeper.close()
        world.coordinator.close()


async def _check_and_receipt_known_gaps(
    world: _World, *, seed: int
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Run the real check commit and receipt against the world's task route."""

    from dataclasses import replace

    from finishup.application.receipt import execute_receipt
    from finishup.ports.importer import ImporterPort
    from finishup.ports.runtime import BundleRuntimePort
    from finishup.protocol.models import ReceiptRequest
    from integration.application.test_respond_status_receipt import (  # pyright: ignore[reportPrivateUsage]
        _build_app,  # pyright: ignore[reportPrivateUsage]
        _IdleImporter,  # pyright: ignore[reportPrivateUsage]
        _receipt_wire,  # pyright: ignore[reportPrivateUsage]
    )

    app = _App()
    app.runtime = cast(object, world.routes)  # pyright: ignore[reportAttributeAccessIssue]
    setattr(app, "reconcile_observation_losses", world.coordinator.reconcile_task_selection_losses)
    frontier = await world.runtime.ledger.load_frontier()
    request = _request().model_copy(
        update={
            "session_id": world.runtime.session_id,
            "writer_id": world.runtime.writer_id,
            "request_id": _ids(IdKind.REQUEST, seed),
            "expected_frontier": _request().expected_frontier.model_copy(
                update={"sequence": str(frontier.sequence), "head_digest": frontier.head_digest}
            ),
        }
    )
    checked = await execute_check_commit(app, request)
    current = replace(world.runtime, importer=cast(ImporterPort, _IdleImporter()))
    world.routes.runtimes[current.session_id] = current
    receipt_app, _, _ = _build_app()
    receipt_app = replace(receipt_app, runtime=cast(BundleRuntimePort, world.routes))
    receipt = await execute_receipt(
        receipt_app,  # pyright: ignore[reportArgumentType]
        ReceiptRequest.model_validate(
            _receipt_wire(
                seed + 1,
                task_id=current.task_id,
                session=current.session_id,
                writer=cast(str, current.writer_id),
                frontier=checked.result_frontier,
            )
        ),
    )
    return tuple(checked.coverage.known_gaps), tuple(receipt.coverage.known_gaps)
