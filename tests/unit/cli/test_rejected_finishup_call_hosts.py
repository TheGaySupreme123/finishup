"""A FinishUP call FinishUP rejected closes as rejected on Claude Code and Cursor too (tb4n5 fix review).

Both host adapters normalize the hook body to a structural envelope that drops ``tool_input``
before the shared ingress, so the first cut of the rejected-call record computed no commitment
there and an absent post on the paired ordinary profiles still expired after ten minutes. Each
adapter now commits to the call from the payload the host sent and passes only that commitment.
These drive the real ``handle_claude_observe`` and ``handle_cursor_observe`` with an absent post
and a matching bridge rejection.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import io
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations import finishup_call_rejections as rejections
from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks
from finishup.domain.observation import ObservationSource, ObservationStatusQuery
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)
from finishup.domain.values import JsonValue
from finishup.protocol.canonical import canonical_encode

_ARGUMENTS: dict[str, JsonValue] = {
    "request_id": "req_4a3b2c1d-0e9f-4a8b-9c7d-6e5f4a3b2c1d",
    "session_id": "ses_1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    "writer_id": "wri_6f5e4d3c-2b1a-4c9d-8e7f-6a5b4c3d2e1f",
    "mode": "semantic_required",
}
# PR #1088 round 3: an id-less publish (the default shape since issue #1084) commits to its body.
_IDLESS_PUBLISH: dict[str, object] = {
    "session_id": "ses_1c2d3e4f-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
    "writer_id": "wri_6f5e4d3c-2b1a-4c9d-8e7f-6a5b4c3d2e1f",
    "event_drafts": [
        {
            "schema": {"name": "decision_recorded", "version": "1.0.0"},
            "payload": {"statement": "Keep it.", "rationale": "Covers it.", "authority": "a"},
        }
    ],
}
_CALLS: dict[str, tuple[str, Mapping[str, object]]] = {
    "check": ("check", _ARGUMENTS),
    "idless_publish": ("publish_work", _IDLESS_PUBLISH),
}


def _host(
    host: str, basename: str = "check"
) -> tuple[Callable[..., int], str, str, str, ObservationSource]:
    if host == "claude":
        return (
            observe_hooks.handle_claude_observe,
            "PreToolUse",
            f"mcp__plugin_yoetz_yoetz__{basename}",
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            ObservationSource.CLAUDE_HOOK,
        )
    return (
        observe_hooks.handle_cursor_observe,
        "preToolUse",
        f"yoetz:{basename}",
        CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
        ObservationSource.CURSOR_HOOK,
    )


@pytest.mark.parametrize("call", sorted(_CALLS))
@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_an_ordinary_host_attempt_finishup_rejected_closes_as_rejected(
    host: str, call: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    basename, arguments = _CALLS[call]
    handler, event, tool, profile, source = _host(host, basename)
    state = tmp_path / "state"
    store = LocalObservationStore(_state=state)
    workspace = store.workspace_commitment(str(tmp_path.resolve()))
    store.grant_consent(workspace)
    store.enable_content_capture(workspace, profile)
    # Hook receipts use the real clock; the store's deadlines follow an adjustable copy of it.
    offset = [0.0]

    def wall_now(_self: LocalObservationStore) -> float:
        return time.time() + offset[0]

    monkeypatch.setattr(LocalObservationStore, "_wall_now", wall_now)
    payload: dict[str, object] = {
        "hook_event_name": event,
        "session_id": f"{host}-rejected-call",
        "conversation_id": f"{host}-rejected-conversation",
        "tool_name": tool,
        "tool_use_id": f"{host}-call-{basename}",
        "tool_input": arguments,
        "workspace_roots": [str(tmp_path)],
    }
    assert (
        handler(
            event_name=event,
            stdin_bytes=canonical_encode(cast(JsonValue, payload)),
            stdout=io.BytesIO(),
            workspace=str(tmp_path),
            _state=state,
            skip_service=True,
            observation_profile=profile,
        )
        == 0
    )
    pending = [
        entry
        for entry in (store._load(workspace).open_pre or {}).values()
        if entry.source is source
    ]
    assert len(pending) == 1
    commitment = rejections.rejected_call_commitment(basename, arguments)
    assert commitment is not None
    assert pending[0].request_commitment == commitment

    # What the bridge records when it answers that call with an error; no post follows.
    assert rejections.record_rejected_finishup_call(
        basename, arguments, state_root=state, now_ms=int(time.time() * 1000) + 200
    )
    offset[0] = 10.0
    # The next pairing read (any later hook of the session) reconciles the attempt.
    assert not store.has_open_pre(
        workspace,
        "probe",
        source=source,
        session_commitment=cast(str, pending[0].session_commitment),
        source_generation=cast(int, pending[0].source_generation),
    )
    endings = store.pending_attempt_endings(workspace)
    assert cast(Mapping[str, int], endings["counts"]) == {"rejected_by_yoetz": 1}
    offset[0] = 700.0
    assert "pending_attempt_expired" not in store.status(ObservationStatusQuery(workspace)).gaps
