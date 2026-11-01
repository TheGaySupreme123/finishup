"""Shared harness for driving the FinishUP terminal UI in tests."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from builders.tui_runtime import FakeRuntime
from finishup.tui.app import FinishUpTui


@pytest.fixture
def make_app(monkeypatch: pytest.MonkeyPatch) -> Callable[..., FinishUpTui]:
    """Build a ``FinishUpTui`` over a fake runtime, with the marker write stubbed.

    Completing setup writes a first-run marker into the real state directory;
    tests must never do that, so the write is replaced with a recorded no-op.
    """

    import finishup.cli.setup as setup_module

    written: list[str] = []

    def record(outcome: str) -> bool:
        written.append(outcome)
        return True

    monkeypatch.setattr(setup_module, "write_setup_marker", record)

    def build(
        *,
        first_run: bool = False,
        runtime: FakeRuntime | None = None,
        suspendable: bool = True,
        prompt_codex_home: bool = False,
    ) -> FinishUpTui:
        app = FinishUpTui(cast(Any, runtime or FakeRuntime()), first_run=first_run)
        if not prompt_codex_home:

            async def selected_codex_home(_option: object) -> Path:
                return Path("/tmp/codex-explicit-test-home")

            monkeypatch.setattr(app, "_choose_codex_home", selected_codex_home)
        app.markers_written = written  # type: ignore[attr-defined]
        if suspendable:
            # A headless test driver cannot suspend a real terminal. Substituting
            # the handoff models "the ceremony ran on the controlling TTY" while
            # keeping every other step — including the consent screen — real.
            async def handoff(operation: Any) -> Any:
                return await operation()

            monkeypatch.setattr(app, "hand_over_terminal", handoff)
        return app

    return build
