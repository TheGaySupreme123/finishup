"""The first-run flow, driven by real keystrokes through the Textual pilot."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest
from textual.widgets import Input, Static

from builders.tui_runtime import CLI, DESKTOP, FakeRuntime
from finishup.tui.app import FinishUpTui
from finishup.tui.models import IntegrationOutcome, LayerState, ReadinessLayer, VaultPosture
from finishup.tui.runtime import RuntimeError_
from finishup.tui.widgets.views import Option, SelectionView

pytestmark = pytest.mark.anyio

WIDE = (100, 34)
SMALL = (60, 18)
NARROW = (42, 24)

MakeApp = Callable[..., FinishUpTui]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _options(view: object) -> tuple[Option, ...]:
    assert isinstance(view, SelectionView)
    return view.options


def _selected(view: object) -> Option:
    assert isinstance(view, SelectionView)
    option = view.selected
    assert option is not None
    return option


def transcript(app: FinishUpTui) -> str:
    return "\n".join("\n".join((event.title, *event.body)) for event in app.transcript.events)


async def answer_review(pilot: object, mode: str = "local") -> None:
    """Answer the review-mode question, which now precedes any registration.

    Kept in one place because it encodes the option order: moving the recommendation changes
    which keystroke means which posture, and every caller should follow automatically.
    """

    press = getattr(pilot, "press")
    if mode == "semantic":
        await press("enter")  # first row, where the cursor rests
    else:
        await press("down", "enter")
    await getattr(pilot, "pause")()


async def test_welcome_shows_detection_and_offers_the_recommended_path(
    make_app: MakeApp,
) -> None:
    app = make_app(first_run=True)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        assert "Welcome to FinishUP" in transcript(app)
        assert "Codex Desktop 0.44" in transcript(app)
        view = app.open_view
        assert view is not None
        assert view.view_name == "welcome"
        labels = [option.label for option in _options(view)]
        assert labels == [
            "Connect FinishUP to an agent",
            "Set up FinishUP without an agent",
            "Exit",
        ]


async def test_without_a_codex_installation_the_connect_option_is_disabled(
    make_app: MakeApp,
) -> None:
    app = make_app(first_run=True, runtime=FakeRuntime(harnesses=()))
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        view = app.open_view
        assert view is not None
        options = _options(view)
        assert options[0].disabled is True
        # The cursor must not rest on a row that cannot be chosen.
        assert _selected(view).key == "local"


async def test_the_layout_still_renders_on_a_small_or_narrow_terminal(
    make_app: MakeApp,
) -> None:
    for size in (SMALL, NARROW):
        app = make_app(first_run=True)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            view = app.open_view
            assert view is not None
            assert isinstance(view, SelectionView)
            assert "Welcome to FinishUP" in transcript(app)
            # Nothing rendered may be wider than the terminal.
            for event in app.transcript.events:
                for line in event.body:
                    assert len(line) <= size[0]
            option_lines = view._option_lines().plain.splitlines()  # pyright: ignore[reportPrivateUsage]
            assert all(len(line) <= size[0] for line in option_lines)


async def test_multiple_installations_ask_which_one_before_previewing(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime(harnesses=(DESKTOP, CLI))
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "harness"
        labels = [option.label for option in _options(view)]
        assert labels == ["Codex Desktop 0.44", "Codex CLI 0.44", "Choose another executable"]
        await pilot.press("2")  # Codex CLI
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        view = app.open_view
        assert view is not None
        assert view.view_name == "integration"
        technical = "\n".join(view.technical_details)
        assert CLI.executable_path in technical
        assert DESKTOP.executable_path not in technical


async def test_exact_codex_home_is_entered_separately_and_bound_to_the_plan(
    make_app: MakeApp,
    tmp_path: Path,
) -> None:
    codex_home = tmp_path / "selected-codex-home"
    codex_home.mkdir()
    runtime = FakeRuntime(harnesses=(CLI,))
    app = make_app(first_run=True, runtime=runtime, prompt_codex_home=True)

    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect using the sole discovered executable
        await pilot.pause()

        view = app.open_view
        assert view is not None
        assert view.view_name == "codex-home-path"
        label = view.query_one(".entry-label", Static).render()
        assert CLI.executable_path in str(label)
        view.query_one("#view-entry", Input).value = str(codex_home)
        await pilot.press("enter")
        await pilot.pause()

        assert app.open_view is not None
        assert app.open_view.view_name == "trust"
        await pilot.press("enter")
        await pilot.pause()
        await answer_review(pilot)

        preview = app.open_view
        assert preview is not None
        assert preview.view_name == "integration"
        technical = "\n".join(preview.technical_details)
        assert CLI.executable_path in technical
        assert "Explicit Codex home" in technical
        assert str(codex_home) in "".join(line.strip() for line in preview.technical_details)
        for disclosed_effect in (
            "Probed activation version",
            "Executable digest",
            "Plugin cache/install target",
            "Marketplace preimage digest",
            "Config preimage digest",
            "Forced activation environment",
            "Exact activation command argv",
            "Plugin cache mutation planned",
        ):
            assert disclosed_effect in technical
        assert runtime.planned_codex_homes == [codex_home]

        await pilot.press("enter")  # approve the exact paired plan
        await pilot.pause()
        assert runtime.applied_codex_homes == [codex_home]


async def test_a_tilde_codex_home_is_expanded_before_validation(
    make_app: MakeApp,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("HOME", str(tmp_path))
    codex_home = tmp_path / "tilde-codex-home"
    codex_home.mkdir()
    runtime = FakeRuntime(harnesses=(CLI,))
    app = make_app(first_run=True, runtime=runtime, prompt_codex_home=True)

    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect using the sole discovered executable
        await pilot.pause()

        view = app.open_view
        assert view is not None
        assert view.view_name == "codex-home-path"
        view.query_one("#view-entry", Input).value = "~/tilde-codex-home"
        await pilot.press("enter")
        await pilot.pause()

        # The default-home spelling is accepted, not rejected as non-absolute.
        assert app.open_view is not None
        assert app.open_view.view_name == "trust"
        await pilot.press("enter")
        await pilot.pause()
        await answer_review(pilot)

        assert runtime.planned_codex_homes == [codex_home]


async def test_an_empty_manual_executable_path_is_rejected_in_place(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime(harnesses=(DESKTOP, CLI))
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("3")  # Choose another executable
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "harness-path"
        await pilot.press("enter")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "harness-path"
        assert "not an executable file" in transcript(app)
        assert runtime.applied == []


async def test_project_trust_precedes_any_integration_preview(make_app: MakeApp) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "trust"
        assert runtime.applied == []


async def test_b_on_the_review_question_returns_to_project_trust(make_app: MakeApp) -> None:
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
        await pilot.press("b")
        await pilot.pause()
        # Back re-asks the previous question rather than cancelling the run.
        assert app.open_view is not None
        assert app.open_view.view_name == "trust"
        assert "Setup stopped" not in transcript(app)
        assert runtime.applied == []


async def test_b_on_the_local_review_question_reasks_it_without_cancelling(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("down", "enter")  # set up without Codex
        await pilot.pause()
        review_view = app.open_view
        assert review_view is not None
        assert review_view.view_name == "review-mode"
        await pilot.press("b")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view is not review_view
        assert app.open_view.view_name == "review-mode"
        assert "Setup stopped" not in transcript(app)
        assert runtime.applied == []


async def test_b_on_project_trust_returns_to_the_installation_picker(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime(harnesses=(DESKTOP, CLI))
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("2")  # Codex CLI
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "trust"
        await pilot.press("b")
        await pilot.pause()
        assert app.open_view is not None
        assert app.open_view.view_name == "harness"
        assert runtime.applied == []


async def test_back_never_reaches_a_step_that_already_changed_the_project(
    make_app: MakeApp,
) -> None:
    """Back is offered only on questions; the approval that applies a change is not one."""

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        view = app.open_view
        assert view is not None
        assert view.view_name == "integration"
        await pilot.press("b")
        await pilot.pause()
        # 'b' is inert here: the integration approval stays open and nothing was applied.
        assert app.open_view is view
        assert runtime.applied == []


async def test_b_typed_into_a_searchable_picker_filters_and_does_not_go_back(
    make_app: MakeApp,
) -> None:
    app = make_app()
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        app.composer.focus_input()
        app.composer.text = "/provider"
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "provider"
        assert view.accepts_printable_shortcuts is False
        await pilot.press("b")
        await pilot.pause()
        # The letter belonged to the query, so the view is still open.
        assert app.open_view is view
        assert view.query_one("#view-search", Input).value == "b"


async def test_declining_project_trust_changes_nothing(make_app: MakeApp) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("down", "enter")  # "No, quit"
        await pilot.pause()
        assert runtime.applied == []
        assert "This project was not changed." in transcript(app)


async def test_the_integration_preview_is_shown_before_anything_is_applied(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        view = app.open_view
        assert view is not None
        assert view.view_name == "integration"
        assert runtime.applied == []


async def test_approving_the_preview_applies_exactly_the_digests_that_were_shown(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("enter")  # approve the preview
        await pilot.pause()
        assert runtime.applied == [("sha256:abc123", "7f8a92bd")]


async def test_declining_the_preview_leaves_the_project_unchanged(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("down", "enter")  # "No, keep this project unchanged"
        await pilot.pause()
        assert runtime.applied == []
        assert "left unchanged" in transcript(app)


async def test_a_foreign_mcp_entry_blocks_and_never_offers_to_replace_it(
    make_app: MakeApp,
) -> None:
    import dataclasses

    from builders.tui_runtime import PLAN

    runtime = FakeRuntime(plan=dataclasses.replace(PLAN, foreign_entry=True))
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        assert runtime.applied == []
        assert "Could not register FinishUP with Codex" in transcript(app)
        view = app.open_view
        assert view is not None
        assert view.view_name == "foreign"
        labels = [option.label.lower() for option in _options(view)]
        assert not any("replace" in label or "force" in label for label in labels)
        assert "Nothing was replaced or removed." in transcript(app)


async def test_a_failed_registration_is_reported_as_a_failure(make_app: MakeApp) -> None:
    runtime = FakeRuntime(
        apply_result=IntegrationOutcome(
            outcome="failed",
            reason="mcp_verification_failed",
            layers=(
                ReadinessLayer("mcp_registered", "MCP registered", LayerState.BLOCKED),
                ReadinessLayer("mcp_verified", "MCP verified", LayerState.UNPROVEN),
            ),
        )
    )
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("enter")
        await pilot.pause()
        text = transcript(app)
        assert "could not finish connecting" in text
        assert "FinishUP is connected to this project" not in text


async def test_a_preview_failure_reports_the_reason_and_stops(make_app: MakeApp) -> None:
    runtime = FakeRuntime(
        plan_error=RuntimeError_("codex_unavailable", "the Codex registration could not be read")
    )
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await pilot.press("enter")
        await pilot.pause()
        await answer_review(pilot)
        assert runtime.applied == []
        assert "codex_unavailable" in transcript(app)


async def test_keychain_unavailable_disables_system_storage_but_offers_a_passphrase(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime(secure_storage=False)
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("enter")  # approve
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "storage"
        options = _options(view)
        assert options[0].disabled is True
        # The disabled row states the reason, never a bare "not available" (issue #721).
        assert options[0].disabled_reason == (
            "no credential store is loaded; FinishUP needs a test"
        )
        assert options[1].disabled is False
        assert _selected(view).key == "passphrase"


async def test_system_storage_selection_initializes_keyring_not_passphrase(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime(
        vault=VaultPosture(reachable=True, state="locked", vault_mode="uninitialized")
    )
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("enter")  # approve
        await pilot.pause()
        await pilot.press("enter")  # system secure storage
        await pilot.pause()
        await pilot.press("enter")  # approve terminal handoff
        await pilot.pause()
        assert "initialize_keyring" in runtime.ceremonies
        assert "initialize_vault" not in runtime.ceremonies


async def test_setup_finishes_with_an_honest_summary_and_records_the_marker(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("enter")  # approve
        await pilot.pause()
        await pilot.press("escape")  # skip storage
        await pilot.pause()
        text = transcript(app)
        assert "FinishUP is ready" in text
        assert "Nothing is being sent to an external review model." in text
        assert app.markers_written == ["registered"]  # type: ignore[attr-defined]


async def test_semantic_review_is_the_recommended_answer_and_where_the_cursor_rests(
    make_app: MakeApp,
) -> None:
    """The recommendation is a property of this question, not of what an install seeds.

    Pressing enter here chooses a wizard branch. It binds no provider, stores no credential,
    and commits no policy -- each of those is a separate step with its own gate -- so the
    seeded zero-egress ``local_only`` policy is unaffected by which row the cursor starts on.
    """

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "review-mode"
        assert [option.label for option in _options(view)] == [
            "Add AI-powered review",
            "Local only",
        ]
        assert _selected(view).key == "semantic"
        assert "Recommended." in _selected(view).description


async def test_the_review_answer_decides_the_route_and_both_halves_use_it(
    make_app: MakeApp,
) -> None:
    """Preview and apply must ask for the same route, and it must be the one chosen.

    The serve command is inside the preview digest, so a preview on one route and an apply on
    another is refused as stale -- first run's very first action failing. Asserting the two
    halves agree is what keeps the question and the registration connected.
    """

    for mode, expected in (("semantic", "policy"), ("local", "strict")):
        runtime = FakeRuntime()
        app = make_app(first_run=True, runtime=runtime)
        async with app.run_test(size=WIDE) as pilot:
            await pilot.pause()
            await pilot.press("enter")  # connect
            await pilot.pause()
            await pilot.press("enter")  # trust
            await pilot.pause()
            await answer_review(pilot, mode)
            view = app.open_view
            assert view is not None
            assert view.view_name == "integration"
            # The approval screen names the argv that will actually be registered.
            assert runtime.planned_routes == [expected]
            await pilot.press("enter")  # approve
            await pilot.pause()
            assert runtime.applied_routes == [expected]


async def test_abandoning_semantic_setup_offers_a_coherent_local_only_finish(
    make_app: MakeApp,
) -> None:
    """Backing out of the provider step must not leave a half-configured install.

    AI-powered review was chosen, so the policy route is already registered. Without this the flow
    returns with that route in place, no provider behind it, and no marker written -- an
    install that is neither local-only nor AI-powered, and says so nowhere.
    """

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot, "semantic")
        await pilot.press("enter")  # approve the policy-route registration
        await pilot.pause()
        await pilot.press("escape")  # skip storage
        await pilot.pause()
        await pilot.press("escape")  # abandon the provider choice
        await pilot.pause()
        view = app.open_view
        assert view is not None
        assert view.view_name == "semantic-incomplete"
        await pilot.press("enter")  # "Yes, finish as local only"
        await pilot.pause()
        await pilot.press("enter")  # approve the strict re-registration
        await pilot.pause()
        # The install ends on the route it actually has, and setup is marked complete.
        assert runtime.applied_routes == ["policy", "strict"]
        assert app.markers_written == ["registered"]  # type: ignore[attr-defined]


async def test_declining_the_local_only_finish_says_setup_is_unfinished(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot, "semantic")
        await pilot.press("enter")  # approve
        await pilot.pause()
        await pilot.press("escape")  # skip storage
        await pilot.pause()
        await pilot.press("escape")  # abandon the provider choice
        await pilot.pause()
        await pilot.press("down", "enter")  # "No, leave setup unfinished"
        await pilot.pause()
        assert app.markers_written == []  # type: ignore[attr-defined]
        assert "Setup was not completed." in transcript(app)


async def test_the_approval_screen_shows_the_local_only_serve_command(
    make_app: MakeApp,
) -> None:
    """Choosing local only must not show the command that permits AI-powered review."""

    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("enter")  # connect
        await pilot.pause()
        await pilot.press("enter")  # trust
        await pilot.pause()
        await answer_review(pilot, "local")
        view = app.open_view
        assert view is not None
        details = "\n".join(view.technical_details)
        assert "finishup mcp serve --semantic off" in details


async def test_choosing_local_only_setup_never_touches_the_project(
    make_app: MakeApp,
) -> None:
    runtime = FakeRuntime()
    app = make_app(first_run=True, runtime=runtime)
    async with app.run_test(size=WIDE) as pilot:
        await pilot.pause()
        await pilot.press("down", "enter")  # "Set up FinishUP without Codex"
        await pilot.pause()
        await answer_review(pilot)
        await pilot.press("escape")  # skip storage
        await pilot.pause()
        assert runtime.applied == []
        assert app.markers_written == ["local_only"]  # type: ignore[attr-defined]
        assert "FinishUP is ready" in transcript(app)
