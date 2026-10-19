"""Setup finishes as local only only once that choice is recorded (review of #1067/#1068)."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from types import SimpleNamespace
from typing import Any

import pytest

from finishup.tui.app import FinishUpTui


@pytest.mark.anyio
@pytest.mark.parametrize(("outcome", "finished"), [("configured", True), ("failed", False)])
async def test_local_only_finishes_setup_only_when_recorded(
    monkeypatch: pytest.MonkeyPatch, outcome: str, finished: bool
) -> None:
    app = FinishUpTui()
    finishes: list[bool] = []

    async def privacy(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(outcome=outcome)

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    async def finish(*, connected: bool) -> None:
        finishes.append(connected)

    def say(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(app.runtime, "run_privacy_setup", privacy)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(app, "_finish_setup", finish)
    monkeypatch.setattr(app, "say", say)

    await app._run_initial_review("local_only", connected=True)  # pyright: ignore[reportPrivateUsage]

    assert finishes == ([True] if finished else [])
