"""Host teardown records lifecycle intent without constructing undeliverable advice."""

from __future__ import annotations

import asyncio
import io
import json
from collections.abc import Callable, Coroutine
from pathlib import Path
from typing import cast

import pytest

from finishup.adapters.integrations.observation_local import LocalObservationStore
from finishup.cli import observe_hooks
from finishup.domain.observation import ObservationSource
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
)


@pytest.mark.parametrize(
    ("source", "profile", "session_id"),
    (
        (
            ObservationSource.CLAUDE_HOOK,
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
            "claude:teardown-budget",
        ),
        (
            ObservationSource.CURSOR_HOOK,
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
            "cursor:teardown-budget",
        ),
        (ObservationSource.CODEX_HOOK, None, "codex-teardown-budget"),
    ),
)
def test_native_teardown_persists_end_and_outbox_without_advice_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    source: ObservationSource,
    profile: str | None,
    session_id: str,
) -> None:
    store = LocalObservationStore(_state=tmp_path)
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir(mode=0o700)
    monkeypatch.setenv("CODEX_HOME", str(codex_home))
    locator = str(tmp_path.resolve())
    workspace = store.workspace_commitment(locator)
    store.grant_consent(workspace, content_capture_profiles=() if profile is None else (profile,))
    store.bind_codex_session(workspace, session_id)
    drains: list[dict[str, object]] = []

    def forbidden_advice(*args: object, **kwargs: object) -> None:
        del args, kwargs
        pytest.fail("SessionEnd must not construct advice the host cannot consume")

    async def defer_drain(*args: object, **kwargs: object) -> None:
        del args
        drains.append(kwargs)

    def run_async(factory: object) -> object:
        return asyncio.run(cast(Callable[[], Coroutine[object, object, object]], factory)())

    monkeypatch.setattr(LocalObservationStore, "refresh_advice", forbidden_advice)
    monkeypatch.setattr(observe_hooks, "_drain_outbox", defer_drain)
    output = io.BytesIO()
    assert (
        observe_hooks.handle_observe(
            event_name="SessionEnd",
            stdin_bytes=json.dumps({"session_id": session_id}).encode(),
            stdout=output,
            workspace=locator,
            _state=tmp_path,
            source=source,
            run_async=run_async,
            _content_capture_profile=profile,
        )
        == 0
    )

    reopened = LocalObservationStore(_state=tmp_path)
    assert reopened.codex_session_ended(workspace, session_id)
    pending = reopened.list_pending_outbox_rows(workspace)
    assert len(pending) == 1
    assert pending[0].envelope.event_kind == "SessionEnd"
    assert drains == []
    assert json.loads(output.getvalue()) == {}
