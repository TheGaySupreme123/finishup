"""Issue #855: the terminal interface repairs and inspects the Codex evaluator runtime."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

import pytest

from builders.tui_runtime import FakeRuntime
from finishup.tui.app import FinishUpTui
from finishup.tui.runtime import RuntimeError_

pytestmark = pytest.mark.anyio

WIDE = (100, 34)
MakeApp = Callable[..., FinishUpTui]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def transcript(app: FinishUpTui) -> str:
    return "\n".join(
        "\n".join((event.title, *event.body, *event.details)) for event in app.transcript.events
    )


async def run_command(pilot: object, app: FinishUpTui, command: str) -> None:
    app.composer.focus_input()
    app.composer.text = command
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]


@dataclass
class _RepairRuntime(FakeRuntime):
    repair_refusal: RuntimeError_ | None = None
    repairs: list[str] = field(default_factory=lambda: [])

    def codex_subscription_repair_plan(self) -> dict[str, object]:
        if self.repair_refusal is not None:
            raise self.repair_refusal
        return {
            "state_before": "codex_runtime_executable_changed",
            "source_path": "/opt/evaluator/codex",
            "runtime_version_before": "0.157.1",
            "runtime_version_after": "0.162.1",
            "candidates": [
                {"source": "discovered", "path": "/opt/evaluator/codex", "runtime_version": v}
                for v in ("0.162.1", "0.159.0")
            ],
            "executable_path_after": "/var/lib/finishup/external-runtimes/codex-evaluator/x/codex",
            "capability_profile_before": "codex-evaluator/0.157.1/v2",
            "capability_profile_after": "codex-evaluator/capability/v4",
        }

    async def repair_codex_subscription(self) -> dict[str, object]:
        self.repairs.append("repair")
        return {
            "executable_path": "/var/lib/finishup/external-runtimes/codex-evaluator/x/codex",
            "model_available": True,
            "process_cleanup": "terminated",
            "login_reused": True,
        }

    def codex_evaluator_runtime_status(self) -> dict[str, object]:
        return {
            "platform": "linux-x64",
            "runtime_floor": "0.157.1",
            "retained_runtimes": [
                {"runtime_version": "0.159.0", "state": "verified"},
                {"runtime_version": "0.157.1", "state": "unchecked"},
            ],
            "binding": {
                "state": "codex_runtime_executable_changed",
                "runtime_version": "0.157.1",
            },
            "next_command": "finishup provider codex-subscription repair",
        }


async def _choose(pilot: object, app: FinishUpTui, text: str) -> None:
    await run_command(pilot, app, "/provider")
    # #1119: /provider first asks how to reach a reviewer; the Codex maintenance actions stay on
    # the API provider picker behind "Use an API key".
    connection = app.open_view
    assert connection is not None
    assert getattr(connection, "view_name", None) == "reviewer-connection"
    await pilot.press("down")  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    view = app.open_view
    assert view is not None
    assert getattr(view, "view_name", None) == "provider"
    view.filter(text)  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]


async def test_repair_shows_what_changes_and_runs_only_after_approval(
    make_app: MakeApp,
) -> None:
    runtime = _RepairRuntime()
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await _choose(pilot, app, "repair codex")
        view = app.open_view
        assert view is not None
        body = " ".join(getattr(view, "body", ()) or getattr(view, "_body", ()))
        assert "codex_runtime_executable_changed" in body
        assert "codex-evaluator/0.157.1/v2 -> codex-evaluator/capability/v4" in body
        assert "(Codex 0.162.1)" in body
        assert "1 older release(s) remain as fallbacks" in body
        assert "never signs in" in body
        # The safe default declines.
        await pilot.press("enter")
        await pilot.pause()
        assert runtime.repairs == []
        assert "Codex evaluator repair was cancelled." in transcript(app)

        await _choose(pilot, app, "repair codex")
        await pilot.press("up")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        assert runtime.repairs == ["repair"]
        assert "Codex evaluator binding repaired" in transcript(app)


async def test_a_refused_repair_names_its_next_step(make_app: MakeApp) -> None:
    runtime = _RepairRuntime(
        repair_refusal=RuntimeError_(
            "codex_runtime_config_changed",
            "The Codex evaluator binding cannot be repaired",
            details=("restore it or remove only that file, then run repair",),
        )
    )
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await _choose(pilot, app, "repair codex")
        text = transcript(app)
        assert "Reason: codex_runtime_config_changed" in text
        assert "restore it or remove only that file" in text
        assert runtime.repairs == []


async def test_runtime_status_reports_structure_without_a_sign_in_check(
    make_app: MakeApp,
) -> None:
    app = make_app(runtime=_RepairRuntime())
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await _choose(pilot, app, "evaluator runtime status")
        text = transcript(app)
        assert "Binding: codex_runtime_executable_changed (Codex 0.157.1)" in text
        assert "Retained Codex 0.159.0: verified" in text
        assert "Retained Codex 0.157.1: unchecked" in text
        assert "Minimum Codex: 0.157.1" in text
        assert "Next: finishup provider codex-subscription repair" in text
        assert "Sign-in was not checked" in text


async def test_setup_preselects_the_existing_reasoning_effort(make_app: MakeApp) -> None:
    runtime = _RepairRuntime()
    runtime.codex_subscription_defaults = lambda: (  # type: ignore[method-assign]
        "/var/lib/finishup/external-runtimes/codex-evaluator/x/codex",
        "/var/lib/finishup/codex-home",
        "gpt-5.6-sol",
        "xhigh",
    )
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await _choose(pilot, app, "switch")
        # Accept every preselected default until the sign-in approval opens; the number of
        # effort prompts differs between release lines.
        for _ in range(8):
            view = app.open_view
            if (
                view is not None
                and getattr(view, "view_name", None) == "codex-subscription-confirm"
            ):
                break
            await pilot.press("enter")
            await pilot.pause()
        await pilot.press("up")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()

    assert runtime.subscription_setups == [
        (
            "/var/lib/finishup/external-runtimes/codex-evaluator/x/codex",
            "/var/lib/finishup/codex-home",
            "gpt-5.6-sol",
            "xhigh",
            True,
        )
    ]


async def test_setup_without_a_runtime_shows_the_consented_download_command(
    make_app: MakeApp,
) -> None:
    runtime = _RepairRuntime()
    runtime.codex_subscription_defaults = lambda: (  # type: ignore[method-assign]
        "",
        "/var/lib/finishup/codex-home",
        "gpt-5.6-sol",
        "high",
    )
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await _choose(pilot, app, "switch")
        assert "finishup provider codex-subscription runtime install --download" in transcript(app)
        assert "asks before downloading" in transcript(app)
        assert getattr(app.open_view, "view_name", None) == "codex-subscription-executable"
        assert runtime.subscription_setups == []
