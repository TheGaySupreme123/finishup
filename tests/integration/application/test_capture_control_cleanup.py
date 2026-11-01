"""Runtime admission cleanup for durable native capture handoffs."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from finishup.application.observation_drain import ObservationOutboxSweeper
from finishup.application.observation_materialize import observation_content_identity
from finishup.cli.observe_hooks import map_hook_payload_to_envelope
from finishup.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationRevokeCommand,
    ObservationSource,
)
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.ports.ledger import (
    CheckAdmissionStage,
    FrozenCase,
    check_admission_refused,
    check_admission_stage,
)
from finishup.protocol.errors import PublicErrorCode, PublicOperationError
from finishup.protocol.ids import IdKind
from integration.application.test_check import (
    _App as _CheckApp,  # pyright: ignore[reportPrivateUsage]
)
from integration.application.test_check import (
    _request as _check_request,  # pyright: ignore[reportPrivateUsage]
)
from integration.application.test_check import (
    execute_check_commit as _execute_check_commit,  # pyright: ignore[reportPrivateUsage]
)
from integration.application.test_native_capture_pipeline import (
    _ZERO_DIGEST,  # pyright: ignore[reportPrivateUsage]
    _capture_claude_post_requests,  # pyright: ignore[reportPrivateUsage]
    _claude_hook_runner,  # pyright: ignore[reportPrivateUsage]
    _ids,  # pyright: ignore[reportPrivateUsage]
    _pipeline,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.anyio
async def test_disabled_runtime_sweeper_revokes_native_ticket_before_successor_freeze(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A READY replay retires the exact native handoff before returning disabled."""

    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        _session_commitment,
        local,
        observation,
        ledger,
        runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id="claude:disabled-sweep", profile=profile)
    run_hook = _claude_hook_runner(
        project=project,
        state=tmp_path / "state",
        connect=connect,
        profile=profile,
    )

    assert (
        await asyncio.to_thread(
            run_hook,
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "disabled-sweep",
                "tool_name": "Bash",
                "tool_use_id": "disabled-sweep-tool",
            },
        )
        == 0
    )
    captured = await _capture_claude_post_requests(
        client=client,
        monkeypatch=monkeypatch,
        run_hook=run_hook,
        session_id="disabled-sweep",
        tool_use_id="disabled-sweep-tool",
        marker=b"disabled-runtime-marker",
    )
    capture = next(item for item in captured if item.capture_only)
    structural = next(item for item in captured if not item.capture_only)
    staged = await coordinator.ingest_request(capture)
    assert staged.disposition is ObservationIngestDisposition.REJECTED
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(structural.envelope)
    pending = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert pending is not None and pending.state == "pending"

    # The structural arm is the durable local outbox row that READY will replay.
    local.enqueue_outbox(workspace, "claude:disabled-sweep", structural.envelope)
    coordinator.observation_enabled = False
    summary = await ObservationOutboxSweeper(local, coordinator).sweep()
    assert summary.attempted == 1
    assert summary.retry_pending == 1

    retired = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert retired is not None and retired.state == "revoked"
    frontier = await ledger.load_frontier()
    frozen = await ledger.freeze_case(
        runtime.session_id,
        cast(str, runtime.writer_id),
        frontier.sequence,
        _ids(IdKind.REQUEST, 9_801),
        _ZERO_DIGEST,
    )
    assert isinstance(frozen, FrozenCase)


@pytest.mark.anyio
async def test_global_disable_retires_profileless_codex_ticket_idempotently(
    tmp_path: Path,
) -> None:
    codex_session = "codex-disabled-ticket"
    (
        _project,
        workspace,
        session_commitment,
        local,
        observation,
        _ledger,
        _runtime,
        coordinator,
        _client,
        _connect,
    ) = await _pipeline(tmp_path, codex_session_id=codex_session, profile=None)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {"tool_name": "shell", "tool_call_id": "disabled-ticket-tool"},
        session_commitment=session_commitment,
        event_ordinal=1,
        key_material=local.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    capture = ObservationIngestRequest(
        codex_session_id=codex_session,
        envelope=envelope,
        content_chunks=(
            ObservationContentChunk(
                content_kind=ObservationContentKind.TOOL_OUTPUT,
                correlation_identity=f"{envelope.source_identity}:tool-output",
                source_commitment=envelope.cursor.last_source_commitment,
                media_type="text/plain",
                part_index=0,
                part_count=1,
                content=b"disabled-codex-ticket-marker",
            ),
        ),
        capture_only=True,
    )
    staged = await coordinator.ingest_request(capture)
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(envelope)
    pending = observation.load_capture_ticket(
        workspace=workspace, logical_identity=logical_identity
    )
    assert pending is not None and pending.state == "pending"
    assert pending.object_ids

    structural = ObservationIngestRequest(codex_session_id=codex_session, envelope=envelope)
    coordinator.observation_enabled = False
    for _ in range(2):
        rejected = await coordinator.ingest_request(structural)
        assert rejected.reason == "observation_disabled"
        retired = observation.load_capture_ticket(
            workspace=workspace,
            logical_identity=logical_identity,
        )
        assert retired is not None and retired.state == "revoked"
        assert retired.object_ids == pending.object_ids

    # A later generation cannot resurrect the retired handoff.
    # Consent revocation now crosses the coordinator's project-generation fence.  Exercise the
    # public coordinator operation so the standalone pipeline can complete its local fence before
    # the successor consent is granted; mutating the local store directly intentionally leaves
    # that durable revocation ceremony pending.
    await coordinator.revoke(ObservationRevokeCommand(workspace))
    local.grant_consent(workspace)
    coordinator.observation_enabled = True
    resumed = await coordinator.ingest_request(structural)
    # Structural history may still be recorded under the new grant, but the old
    # content must not follow it into the ledger.
    assert resumed.disposition is ObservationIngestDisposition.ACCEPTED
    recorded = observation.list_envelopes(workspace)
    assert recorded and all(not item.content_object_refs for item in recorded)
    retired = observation.load_capture_ticket(
        workspace=workspace, logical_identity=logical_identity
    )
    assert retired is not None and retired.state == "revoked"


@pytest.mark.anyio
async def test_disabled_runtime_does_not_cleanup_wrong_session_commitment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Admission cleanup never turns an invalid session request into authority."""

    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        _session_commitment,
        _local,
        observation,
        _ledger,
        _runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id="claude:disabled-auth", profile=profile)
    run_hook = _claude_hook_runner(
        project=project,
        state=tmp_path / "state",
        connect=connect,
        profile=profile,
    )
    assert (
        await asyncio.to_thread(
            run_hook,
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "disabled-auth",
                "tool_name": "Bash",
                "tool_use_id": "disabled-auth-tool",
            },
        )
        == 0
    )
    captured = await _capture_claude_post_requests(
        client=client,
        monkeypatch=monkeypatch,
        run_hook=run_hook,
        session_id="disabled-auth",
        tool_use_id="disabled-auth-tool",
        marker=b"disabled-auth-marker",
    )
    capture = next(item for item in captured if item.capture_only)
    staged = await coordinator.ingest_request(capture)
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(capture.envelope)
    coordinator.observation_enabled = False

    invalid = replace(
        capture,
        envelope=replace(
            capture.envelope,
            session_commitment="hmac-sha256:" + "f" * 64,
        ),
    )
    rejected = await coordinator.ingest_request(invalid)
    assert rejected.reason == "consent_missing"
    still_pending = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert still_pending is not None and still_pending.state == "pending"


@pytest.mark.anyio
async def test_check_preflight_retires_disabled_ticket_without_structural_outbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The task-local CHECK preflight closes a ticket after a public local disable."""

    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        _session_commitment,
        local,
        observation,
        ledger,
        runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id="claude:disabled-check", profile=profile)
    run_hook = _claude_hook_runner(
        project=project,
        state=tmp_path / "state",
        connect=connect,
        profile=profile,
    )
    assert (
        await asyncio.to_thread(
            run_hook,
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "disabled-check",
                "tool_name": "Bash",
                "tool_use_id": "disabled-check-tool",
            },
        )
        == 0
    )
    captured = await _capture_claude_post_requests(
        client=client,
        monkeypatch=monkeypatch,
        run_hook=run_hook,
        session_id="disabled-check",
        tool_use_id="disabled-check-tool",
        marker=b"disabled-check-marker",
    )
    capture = next(item for item in captured if item.capture_only)
    staged = await coordinator.ingest_request(capture)
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(capture.envelope)
    local.disable_content_capture(workspace, profile)
    # The hook helper deliberately exercised the structural delivery attempt as well. Remove
    # those delivery rows through the public acknowledgement API so this fixture isolates the
    # durable ticket with no structural outbox successor.
    pending_rows = local.list_pending_outbox_rows(
        workspace,
        codex_session_id="claude:disabled-check",
    )
    for row in pending_rows:
        assert local.acknowledge_outbox_row(workspace, row)
    assert local.pending_outbox_count(workspace) == 0
    pending = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert pending is not None and pending.state == "pending"

    # READY's CHECK preflight is the coordinator's exact-task handoff pass.
    assert await coordinator.reconcile_task_capture_handoffs(runtime) == 1
    retired = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert retired is not None and retired.state == "revoked"
    frontier = await ledger.load_frontier()
    frozen = await ledger.freeze_case(
        runtime.session_id,
        cast(str, runtime.writer_id),
        frontier.sequence,
        _ids(IdKind.REQUEST, 9_802),
        _ZERO_DIGEST,
    )
    assert isinstance(frozen, FrozenCase)


@pytest.mark.anyio
async def test_check_reconciliation_keeps_profileless_codex_ticket_active(
    tmp_path: Path,
) -> None:
    """READY cleanup does not treat the Codex structural grant as a profile arm."""

    codex_session = "codex:profileless-check"
    (
        _project,
        workspace,
        session_commitment,
        local,
        observation,
        _ledger,
        runtime,
        coordinator,
        _client,
        _connect,
    ) = await _pipeline(tmp_path, codex_session_id=codex_session, profile=None)
    envelope = map_hook_payload_to_envelope(
        "PostToolUse",
        {
            "hook_event_name": "PostToolUse",
            "session_id": codex_session,
            "tool_name": "Bash",
            "tool_use_id": "profileless-check-tool",
            "tool_response": "profileless-check-marker",
        },
        session_commitment=session_commitment,
        event_ordinal=1,
        key_material=local.key_material(),
        source=ObservationSource.CODEX_HOOK,
    )
    request = ObservationIngestRequest(
        codex_session_id=codex_session,
        envelope=envelope,
        content_chunks=(
            ObservationContentChunk(
                content_kind=ObservationContentKind.TOOL_OUTPUT,
                correlation_identity=f"{envelope.source_identity}:tool-output",
                source_commitment=envelope.cursor.last_source_commitment,
                media_type="text/plain",
                part_index=0,
                part_count=1,
                content=b"profileless-check-marker",
            ),
        ),
        capture_only=True,
    )
    staged = await coordinator.ingest_request(request)
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(envelope)
    pending = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert pending is not None and pending.state == "pending"

    # A fresh profileless handoff with current authority is not stranded, even
    # though this direct capture-only request left no structural outbox row.
    assert await coordinator.reconcile_task_capture_handoffs(runtime) == 0

    retained = observation.load_capture_ticket(
        workspace=workspace,
        logical_identity=logical_identity,
    )
    assert retained is not None and retained.state == "pending"


@pytest.mark.anyio
async def test_check_reconciles_once_after_capture_barrier_before_retrying_freeze() -> None:
    """A new CHECK retries its exact freeze once after the bounded capture fence runs."""

    app = _CheckApp()
    original_freeze = app.ledger.freeze_case
    first = True
    calls: list[object] = []

    async def freeze_once(*args: object) -> object:
        nonlocal first
        if first:
            first = False
            raise PublicOperationError(
                PublicErrorCode.OPERATION_PENDING,
                "capture pending",
                True,
            )
        return await original_freeze(*args)

    async def reconcile(runtime: object) -> None:
        assert app.ledger.operation is None
        calls.append(runtime)

    app.ledger.freeze_case = freeze_once  # type: ignore[method-assign]
    setattr(app, "reconcile_observation_capture", reconcile)
    result = await _execute_check_commit(app, _check_request())

    assert result.outcome == "committed"
    assert len(calls) == 1


@pytest.mark.anyio
async def test_store_contention_during_capture_reconciliation_keeps_the_typed_refusal() -> None:
    """#689: a contended local store leaves the capture barrier's own retryable refusal."""

    from finishup.ports.ledger import CheckAdmissionStage, check_admission_refused
    from finishup.ports.observation import ObservationStoreLockTimeout

    app = _CheckApp()
    refusal = check_admission_refused(CheckAdmissionStage.CAPTURE_HANDOFF_PENDING)
    freezes = 0

    async def refused(*args: object) -> object:
        nonlocal freezes
        del args
        freezes += 1
        raise refusal

    async def contended(_runtime: object) -> None:
        raise ObservationStoreLockTimeout(
            scope="process",
            waited_ms=2_000,
            holder_role="hook",
            holder_phase="handle_observe",
            holder_held_ms=2_400,
        )

    app.ledger.freeze_case = refused  # type: ignore[method-assign]
    setattr(app, "reconcile_observation_capture", contended)
    with pytest.raises(PublicOperationError) as caught:
        await _execute_check_commit(app, _check_request())
    assert caught.value is refusal
    assert caught.value.retryable
    assert freezes == 1
    assert app.ledger.operation is None


@pytest.mark.anyio
async def test_completed_check_replay_skips_capture_reconciliation() -> None:
    """An idempotent replay returns before inspecting newer capture tickets."""

    app = _CheckApp()
    first = await _execute_check_commit(app, _check_request())

    async def fail_if_called(_runtime: object) -> None:
        raise AssertionError("capture reconciliation must not run for a completed replay")

    setattr(app, "reconcile_observation_capture", fail_if_called)
    app.ledger.replay = first
    replayed = await _execute_check_commit(app, _check_request())

    assert replayed is first


class _At:
    """A reconciliation clock pinned to one instant."""

    def __init__(self, now: datetime) -> None:
        self.now = now

    def now_utc(self) -> datetime:
        return self.now

    def monotonic_seconds(self) -> float:
        return 1.0


@pytest.mark.anyio
async def test_check_preflight_retires_an_orphaned_live_authority_ticket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A handoff no structural row can ever consume no longer blocks the task (issue #838).

    Authority stays active throughout. The ticket is kept while it is young and while its
    structural row is still pending; only once that row is gone and the grace window has passed
    is it retired, after which the check admits.
    """

    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        _session_commitment,
        local,
        observation,
        ledger,
        runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(tmp_path, codex_session_id="claude:orphan-check", profile=profile)
    run_hook = _claude_hook_runner(
        project=project,
        state=tmp_path / "state",
        connect=connect,
        profile=profile,
    )
    assert (
        await asyncio.to_thread(
            run_hook,
            "PreToolUse",
            {
                "hook_event_name": "PreToolUse",
                "session_id": "orphan-check",
                "tool_name": "Bash",
                "tool_use_id": "orphan-check-tool",
            },
        )
        == 0
    )
    captured = await _capture_claude_post_requests(
        client=client,
        monkeypatch=monkeypatch,
        run_hook=run_hook,
        session_id="orphan-check",
        tool_use_id="orphan-check-tool",
        marker=b"orphan-check-marker",
    )
    capture = next(item for item in captured if item.capture_only)
    staged = await coordinator.ingest_request(capture)
    assert staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON
    logical_identity = observation_content_identity(capture.envelope)
    pending = observation.load_capture_ticket(
        workspace=workspace, logical_identity=logical_identity
    )
    assert pending is not None and pending.state == "pending"
    after_grace = _At(pending.captured_at.as_datetime() + timedelta(seconds=121))
    reconcile = coordinator.reconcile_task_capture_handoffs
    original_clock = coordinator.clock

    # The structural row that will consume this handoff is still queued: keep it.
    rows = local.list_pending_outbox_rows(workspace, codex_session_id="claude:orphan-check")
    assert rows
    monkeypatch.setattr(coordinator, "clock", after_grace)
    await reconcile(runtime)
    kept = observation.load_capture_ticket(workspace=workspace, logical_identity=logical_identity)
    assert kept is not None and kept.state == "pending"

    # The row leaves without consuming the handoff (delivered or quarantined elsewhere).
    for row in rows:
        assert local.acknowledge_outbox_row(workspace, row)
    young = _At(pending.captured_at.as_datetime() + timedelta(seconds=29))
    monkeypatch.setattr(coordinator, "clock", young)
    await reconcile(runtime)
    kept = observation.load_capture_ticket(workspace=workspace, logical_identity=logical_identity)
    assert kept is not None and kept.state == "pending"
    monkeypatch.setattr(coordinator, "clock", original_clock)
    await reconcile(runtime)
    kept = observation.load_capture_ticket(workspace=workspace, logical_identity=logical_identity)
    assert kept is not None and kept.state == "pending"

    monkeypatch.setattr(coordinator, "clock", after_grace)
    await reconcile(runtime)
    retired = observation.load_capture_ticket(
        workspace=workspace, logical_identity=logical_identity
    )
    assert retired is not None and retired.state == "revoked"
    frontier = await ledger.load_frontier()
    frozen = await ledger.freeze_case(
        runtime.session_id,
        cast(str, runtime.writer_id),
        frontier.sequence,
        _ids(IdKind.REQUEST, 9_838),
        _ZERO_DIGEST,
    )
    assert isinstance(frozen, FrozenCase)


def _refuse_first(app: _CheckApp, stage: CheckAdmissionStage) -> list[str]:
    original_freeze = app.ledger.freeze_case
    calls: list[str] = []

    async def freeze(*args: object) -> object:
        calls.append("freeze")
        if len(calls) == 1:
            raise check_admission_refused(stage)
        return await original_freeze(*args)

    async def reconcile(_runtime: object) -> None:
        calls.append("reconcile")

    app.ledger.freeze_case = freeze  # type: ignore[method-assign]
    setattr(app, "reconcile_observation_capture", reconcile)
    return calls


@pytest.mark.anyio
async def test_typed_capture_refusal_reconciles_then_retries_the_exact_freeze() -> None:
    app = _CheckApp()
    calls = _refuse_first(app, CheckAdmissionStage.CAPTURE_HANDOFF_PENDING)
    result = await _execute_check_commit(app, _check_request())
    assert result.outcome == "committed"
    assert calls == ["freeze", "reconcile", "freeze"]


@pytest.mark.anyio
async def test_lost_acquisition_race_retries_once_without_capture_reconciliation() -> None:
    app = _CheckApp()
    calls = _refuse_first(app, CheckAdmissionStage.ACQUISITION_CONTENDED)
    result = await _execute_check_commit(app, _check_request())
    assert result.outcome == "committed"
    assert calls == ["freeze", "freeze"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    "stage", (CheckAdmissionStage.ACQUIRING, CheckAdmissionStage.IMPORT_PENDING)
)
async def test_in_flight_or_import_refusal_returns_its_typed_stage_unretried(
    stage: CheckAdmissionStage,
) -> None:
    """A retry inside the call cannot help, so the caller gets the typed same-identity path."""

    app = _CheckApp()
    calls = _refuse_first(app, stage)
    with pytest.raises(PublicOperationError) as refused:
        await _execute_check_commit(app, _check_request())
    assert check_admission_stage(refused.value) is stage
    assert refused.value.safe_details["continuation"] == "check_admission_same_identity"
    assert calls == ["freeze"]
