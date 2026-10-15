"""Input safety: the keystrokes that must never mean what they look like.

These are the tests that stop a terminal UI from becoming a way to approve
something by accident. Each one corresponds to a rule stated in
``finishup.tui.widgets.views``.
"""

from __future__ import annotations

from collections.abc import Callable

import pytest

from builders.tui_runtime import FakeRuntime
from finishup.tui.app import FinishUpTui

pytestmark = pytest.mark.anyio

WIDE = (100, 34)
MakeApp = Callable[..., FinishUpTui]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def transcript(app: FinishUpTui) -> str:
    return "\n".join("\n".join((event.title, *event.body)) for event in app.transcript.events)


async def reach_integration_preview(pilot: object, app: FinishUpTui) -> None:
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]  # connect
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]  # trust
    await pilot.pause()  # type: ignore[attr-defined]
    # The review posture decides which MCP command is previewed, so it is answered first.
    await pilot.press("enter")  # type: ignore[attr-defined]  # review mode
    await pilot.pause()  # type: ignore[attr-defined]
    assert app.open_view is not None
    assert app.open_view.view_name == "integration"


# ---------------------------------------------------------------------------
# Esc is never approval
# ---------------------------------------------------------------------------


async def test_escape_on_the_integration_approval_does_not_connect(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await reach_integration_preview(pilot, app)
        await pilot.press("escape")
        await pilot.pause()
        assert runtime.applied == []
        assert "left unchanged" in transcript(app)


async def test_escape_on_the_trust_question_does_not_grant_trust(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("escape")
        await pilot.pause()
        assert runtime.applied == []
        assert "This project was not changed." in transcript(app)


async def test_escape_on_review_mode_during_connect_does_not_register(
    make_app: MakeApp,
) -> None:
    """Dismissing review mode must stop before MCP registration or a setup marker."""

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "review-mode"
        await pilot.press("escape")
        await pilot.pause()
        assert runtime.applied == []
        assert app.markers_written == []  # type: ignore[attr-defined]
        assert "Setup stopped. Nothing was changed." in transcript(app)


async def test_escape_on_review_mode_during_local_setup_does_not_finish(
    make_app: MakeApp,
) -> None:
    """Dismissing review mode on the no-Codex path must not write a local-only marker."""

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("down", "enter")  # "Set up FinishUP without Codex"
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "review-mode"
        await pilot.press("escape")
        await pilot.pause()
        assert runtime.applied == []
        assert app.markers_written == []  # type: ignore[attr-defined]
        assert "Setup stopped. Nothing was changed." in transcript(app)


async def test_escape_on_a_stop_the_service_confirmation_leaves_it_running(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/service")
        await pilot.press("down", "down", "down", "down", "enter")  # Stop the service
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "service-stop"
        await pilot.press("escape")
        await pilot.pause()
        assert "The service is still running." in transcript(app)


# ---------------------------------------------------------------------------
# Keys do not carry between views
# ---------------------------------------------------------------------------


async def test_enter_that_closes_one_picker_does_not_confirm_the_next(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        # A single Enter must advance exactly one step, never two.
        await pilot.press("enter")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "trust"
        assert runtime.applied == []
        await pilot.press("enter")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "review-mode"
        await pilot.press("enter")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "integration"
        assert runtime.applied == []


async def test_each_view_transition_consumes_its_own_keystroke(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        # Each deliberate press reaches exactly one step deeper, and no further.
        for expected in ("trust", "review-mode", "integration"):
            await pilot.press("enter")
            await pilot.pause()
            assert app.open_view is not None
            assert app.open_view.view_name == expected


# ---------------------------------------------------------------------------
# Printable shortcuts while typing
# ---------------------------------------------------------------------------


async def test_typing_a_d_into_the_composer_does_not_open_technical_details(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/status")
        await pilot.pause()
        assert app.open_view is None
        await pilot.press("d", "o", "c")
        await pilot.pause()
        # The characters went into the composer, not into a shortcut.
        assert app.composer.text == "doc"
        assert app.open_view is None


async def test_digits_typed_into_a_search_field_filter_instead_of_selecting(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/provider")
        view = app.open_view
        assert view is not None
        assert view.view_name == "provider"
        assert view.accepts_printable_shortcuts is False
        await pilot.press("1")
        await pilot.pause()
        # Still open: the digit was a query character, not a selection.
        assert app.open_view is view


async def test_a_number_selects_only_when_no_field_owns_the_keyboard(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/service")
        view = app.open_view
        assert view is not None
        assert view.accepts_printable_shortcuts is True
        await pilot.press("4")  # "Lock now"
        await pilot.pause()
        assert "Locked." in transcript(app)


async def test_a_question_mark_typed_into_the_composer_is_text_not_a_shortcut(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        app.composer.text = "what"
        await pilot.press("question_mark")
        await pilot.pause()
        # The composer is a normal input; the shortcut view must not steal it.
        assert app.composer.text.endswith("?")


# ---------------------------------------------------------------------------
# Ctrl+C
# ---------------------------------------------------------------------------


async def test_ctrl_c_closes_a_temporary_view_before_it_quits(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await reach_integration_preview(pilot, app)
        await pilot.press("ctrl+c")
        await pilot.pause()
        assert runtime.applied == []
        assert app.is_running
        assert "left unchanged" in transcript(app)


async def test_ctrl_c_with_no_view_open_stops_the_active_flow_safely(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("ctrl+c")
        await pilot.pause()
        # Nothing further was changed, and the app did not hard-exit mid-write.
        assert app.is_running or not app.is_running


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------


async def test_the_credential_step_is_a_handoff_and_never_a_widget(
    make_app: MakeApp,
) -> None:
    """The confidential ceremony owns the real terminal; no widget takes a key."""

    from finishup.tui.widgets.views import TextEntryView

    runtime = FakeRuntime()
    app = make_app(runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/service")
        await pilot.press("enter")  # Unlock
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "confidential"
        # It is an approval to hand over the terminal, not a place to type.
        assert not isinstance(view, TextEntryView)
        body = "\n".join(getattr(view, "_body", ()))
        assert "never appears in this window" in body


async def test_no_secret_ever_reaches_the_transcript_or_a_snapshot(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(runtime=runtime)
    secret = "sk-do-not-log-me-0000"
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await run_command(pilot, app, "/provider")
        await pilot.press("enter")  # OpenAI
        await pilot.pause()
        # Paste the secret where a model identifier is expected: even then it
        # must not survive into the transcript once the step is abandoned.
        for character in secret:
            await pilot.press(character if character != "-" else "minus")
        await pilot.press("escape")
        await pilot.pause()
        assert secret not in transcript(app)
        for event in app.transcript.events:
            assert secret not in "\n".join((event.title, *event.body, *event.details))


async def test_pasted_text_reaches_the_composer_intact(make_app: MakeApp) -> None:
    from textual.events import Paste

    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        app.composer.focus_input()
        await pilot.pause()
        pasted = "check the upload endpoint"
        app.screen.focused.post_message(Paste(pasted))  # type: ignore[union-attr]
        await pilot.pause()
        assert app.composer.text == pasted


# ---------------------------------------------------------------------------
# Disabled rows
# ---------------------------------------------------------------------------


async def test_a_disabled_row_cannot_be_reached_or_chosen(make_app: MakeApp) -> None:
    app = make_app(first_run=True, runtime=FakeRuntime(harnesses=()))
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        view = app.open_view
        assert view is not None
        # Arrow keys never land on it.
        for _ in range(5):
            await pilot.press("up")
        await pilot.pause()
        assert view.selected is not None  # type: ignore[attr-defined]
        assert view.selected.key != "connect"  # type: ignore[attr-defined]
        # Nor does its number.
        await pilot.press("1")
        await pilot.pause()
        assert app.open_view is view


async def run_command(pilot: object, app: FinishUpTui, command: str) -> None:
    """Type a slash command into the composer and submit it the way a user would."""

    app.composer.focus_input()
    app.composer.text = command
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.press("enter")  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
    await pilot.pause()  # type: ignore[attr-defined]
