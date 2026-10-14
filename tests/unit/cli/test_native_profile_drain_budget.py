"""Native ordinary-profile drain selection without transient content."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.observe_hooks import handle_observe
from finishup.domain.observation import ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)


@pytest.mark.parametrize(
    ("source", "profile", "session_id", "expected_budget"),
    (
        (
            ObservationSource.CLAUDE_HOOK,
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            "claude:budget-native",
            None,
        ),
        (
            ObservationSource.CURSOR_HOOK,
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            "cursor:budget-native",
            None,
        ),
        (ObservationSource.CODEX_HOOK, None, "codex-budget-native", 0.2),
    ),
)
def test_contentless_native_rows_defer_service_drain(
    tmp_path: Path,
    source: ObservationSource,
    profile: str | None,
    session_id: str,
    expected_budget: float | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Native structural rows stay durable locally when there are no transient chunks."""

    store = LocalObservationStore(_state=tmp_path)
    workspace_locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(workspace_locator)
    store.grant_consent(
        workspace,
        content_capture_profiles=() if profile is None else (profile,),
    )
    observed: list[dict[str, object]] = []
    timing_flags: list[object] = []

    async def capture_drain(*args: object, **kwargs: object) -> None:
        del args
        observed.append(dict(kwargs))

    def capture_timing(*args: object, **kwargs: object) -> None:
        del args
        timing_flags.append(kwargs.get("native_content"))

    def run_async(factory: object) -> object:
        return asyncio.run(factory())  # type: ignore[operator, arg-type]

    monkeypatch.setattr(observe_hooks_module, "_drain_outbox", capture_drain)
    monkeypatch.setattr(observe_hooks_module, "_record_pass_timing", capture_timing)

    payload = {
        "session_id": session_id,
        "tool_name": "publish_work",
        "tool_call_id": "native-structural-only",
        "tool_response": "Already recorded by the FinishUP service; do not recapture this output",
        "success": True,
    }
    code = handle_observe(
        event_name="PostToolUse",
        stdin_bytes=json.dumps(payload).encode(),
        stdout=io.BytesIO(),
        workspace=workspace_locator,
        _state=tmp_path,
        source=source,
        connect=None,
        run_async=run_async,  # type: ignore[arg-type]
        _content_capture_profile=profile,
        _content_payload=payload,
    )

    assert code == 0
    if expected_budget is None:
        assert observed == []
        assert LocalObservationStore(_state=tmp_path).list_pending_outbox_rows(workspace)
    else:
        assert len(observed) == 1
        assert observed[0]["budget_seconds"] == expected_budget
        assert observed[0]["priority_source_identity"] is None
        assert observed[0]["content_by_source_identity"] is None
    assert timing_flags == [False]
