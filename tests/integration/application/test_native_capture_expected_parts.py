"""Exercise complete-set binding for interrupted native capture handoffs."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from finishup.application.observation_materialize import observation_content_identity
from finishup.domain.observation import (
    ObservationCaptureTicket,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationIngestDisposition,
    ObservationSource,
    ObservationStatusQuery,
    observation_capture_part_descriptors,
)
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from integration.application.test_native_capture_pipeline import (
    _claude_hook_runner,  # pyright: ignore[reportPrivateUsage]
    _pending_structural_request,  # pyright: ignore[reportPrivateUsage]
    _pipeline,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.anyio
async def test_interrupted_handoff_cannot_finalize_missing_content_group(tmp_path: Path) -> None:
    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        session_commitment,
        local,
        observation,
        _ledger,
        runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(
        tmp_path,
        codex_session_id="claude:expected-parts-crash",
        profile=profile,
    )
    run_hook = _claude_hook_runner(
        project=project,
        state=tmp_path / "state",
        connect=connect,
        profile=profile,
    )
    try:
        assert (
            await asyncio.to_thread(
                run_hook,
                "PreToolUse",
                {
                    "hook_event_name": "PreToolUse",
                    "session_id": "expected-parts-crash",
                    "tool_name": "Bash",
                    "tool_use_id": "expected-parts-tool-1",
                },
            )
            == 0
        )
        # Ordinary-native structural rows stay in the local outbox when the
        # hook has no transient content.  Exercise the same service-shaped
        # request without requiring a foreground drain just to obtain it.
        request = _pending_structural_request(
            local,
            workspace,
            codex_session_id="claude:expected-parts-crash",
            event_kind="PreToolUse",
        )
        # The hook intentionally deferred this structural row to its local outbox.  Reproduce
        # the old service-accepted prefix explicitly before installing the interrupted ticket;
        # the final retry must then exercise duplicate reconciliation rather than a first append.
        initial = await coordinator.ingest_request(request)
        assert initial.disposition is ObservationIngestDisposition.ACCEPTED
        assert client.requests == []
        source_commitment = request.envelope.cursor.last_source_commitment
        first_group = ObservationContentChunk(
            content_kind=ObservationContentKind.TOOL_INPUT,
            correlation_identity=f"{request.envelope.source_identity}:tool-input",
            source_commitment=source_commitment,
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=b"first-group",
        )
        missing_group = ObservationContentChunk(
            content_kind=ObservationContentKind.TOOL_OUTPUT,
            correlation_identity=f"{request.envelope.source_identity}:tool-output",
            source_commitment=source_commitment,
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=b"missing-group",
        )
        authority = local.content_capture_authority(workspace)
        assert authority is not None
        ticket = ObservationCaptureTicket(
            workspace_commitment=workspace,
            task_id=runtime.task_id,
            finishup_session_id=runtime.session_id,
            session_commitment=session_commitment,
            source=ObservationSource.CLAUDE_HOOK,
            source_identity=request.envelope.source_identity,
            cursor=request.envelope.cursor,
            logical_identity=observation_content_identity(request.envelope),
            content_capture_profile=profile,
            authority_generation=authority.generation,
            object_ids=(),
            captured_at=request.envelope.receipt_time,
            state="staging",
            expected_parts=observation_capture_part_descriptors((first_group, missing_group)),
        )
        observation.record_capture_ticket(ticket)

        changed_group = ObservationContentChunk(
            content_kind=ObservationContentKind.TOOL_OUTPUT,
            correlation_identity=f"{request.envelope.source_identity}:changed-output",
            source_commitment=source_commitment,
            media_type="text/plain",
            part_index=0,
            part_count=1,
            content=b"changed-set-must-be-refused",
        )
        changed_retry = await coordinator.ingest_request(
            replace(
                request,
                capture_only=True,
                content_chunks=(changed_group,),
                content_capture_profile=profile,
            )
        )
        assert changed_retry.reason == "content_capture_unavailable"
        assert not observation.content_manifests_for_logical_identity(
            workspace=workspace,
            logical_identity=ticket.logical_identity,
        )

        # Simulate a crash after the first complete group was inventoried but
        # before the ticket could bind the complete expected set.
        captured, _replay, _redacted, unavailable = await coordinator._capture_content(  # pyright: ignore[reportPrivateUsage]
            runtime,
            observation,
            workspace=workspace,
            envelope=request.envelope,
            chunks=(first_group,),
        )
        assert len(captured) == 1
        assert unavailable is False
        assert observation.content_manifests_for_logical_identity(
            workspace=workspace,
            logical_identity=ticket.logical_identity,
        )

        retry = await coordinator.ingest_request(
            replace(request, content_chunks=(), capture_only=False)
        )
        assert retry.disposition is ObservationIngestDisposition.DUPLICATE
        revoked = observation.load_capture_ticket(
            workspace=workspace,
            logical_identity=ticket.logical_identity,
        )
        assert revoked is not None
        assert revoked.state == "revoked"
        status = local.status(ObservationStatusQuery(workspace))
        assert "content_capture_unavailable" in status.gaps
    finally:
        coordinator.close()
