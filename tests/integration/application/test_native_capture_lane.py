"""Bound the native capture handoff independently of structural ledger replay."""

from __future__ import annotations

import asyncio
from dataclasses import replace
from pathlib import Path

import pytest

from finishup.domain.observation import ObservationContentChunk, ObservationContentKind
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from integration.application.test_native_capture_pipeline import (
    _claude_hook_runner,  # pyright: ignore[reportPrivateUsage]
    _pending_structural_request,  # pyright: ignore[reportPrivateUsage]
    _pipeline,  # pyright: ignore[reportPrivateUsage]
)


@pytest.mark.anyio
async def test_capture_only_stages_while_structural_append_is_blocked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A structural append gate must not consume the native staging budget."""

    profile = CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    (
        project,
        workspace,
        _session_commitment,
        _local,
        _observation,
        _ledger,
        _runtime,
        coordinator,
        client,
        connect,
    ) = await _pipeline(
        tmp_path,
        codex_session_id="claude:capture-lane-gate",
        profile=profile,
    )
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
                "session_id": "capture-lane-gate",
                "tool_name": "Bash",
                "tool_use_id": "capture-lane-tool-1",
            },
        )
        == 0
    )
    structural_request = _pending_structural_request(
        _local,
        workspace,
        codex_session_id="claude:capture-lane-gate",
        event_kind="PreToolUse",
    )
    assert client.requests == []
    append_entered = asyncio.Event()

    async def blocked_append(*args: object, **kwargs: object) -> object:
        del args, kwargs
        append_entered.set()
        await asyncio.Future()
        return None

    monkeypatch.setattr(coordinator, "_append_materialized", blocked_append)
    structural_task = asyncio.create_task(coordinator.ingest_request(structural_request))
    await asyncio.wait_for(append_entered.wait(), timeout=1.0)

    capture_request = replace(
        structural_request,
        capture_only=True,
        content_capture_profile=profile,
        content_chunks=(
            ObservationContentChunk(
                content_kind=ObservationContentKind.TOOL_INPUT,
                correlation_identity=(f"{structural_request.envelope.source_identity}:tool-input"),
                source_commitment=structural_request.envelope.cursor.last_source_commitment,
                media_type="text/plain",
                part_index=0,
                part_count=1,
                content=b"capture-lane-marker",
                redacted=False,
            ),
        ),
    )
    result = await asyncio.wait_for(
        client.coordinator.ingest_request(capture_request),
        timeout=1.0,
    )
    assert result.reason == "content_capture_pending"

    structural_task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await structural_task
