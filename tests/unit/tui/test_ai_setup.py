"""The full-screen interface uses the same optional-review choices as the wizard."""

from __future__ import annotations

from collections.abc import Sequence
from types import SimpleNamespace

import pytest

from finishup.tui.app import FinishUpTui
from finishup.tui.widgets.views import BaseView, SelectionView


@pytest.mark.anyio
async def test_not_now_records_local_review_in_the_interface() -> None:
    app = FinishUpTui(SimpleNamespace())  # pyright: ignore[reportArgumentType]
    views: list[BaseView] = []
    recorded: list[bool] = []

    async def ask(view: BaseView) -> str:
        views.append(view)
        return "local_only"

    async def local() -> bool:
        recorded.append(True)
        return True

    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    app._record_local_only = local  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]
    assert await app.command_provider("local_agent_opt_in") == "local_only"
    assert recorded == [True]
    view = views[0]
    assert isinstance(view, SelectionView)
    assert view.title_text == "How should FinishUP reach an AI reviewer?"
    assert [option.key for option in view.options] == [
        "codex_subscription",
        "api_key",
        "local_only",
    ]


@pytest.mark.anyio
async def test_model_picker_offers_reviewed_models_and_a_custom_escape() -> None:
    from finishup.tui.ai_setup import choose_model

    seen: list[BaseView] = []
    replies = iter(["2"])

    async def ask(view: BaseView) -> str:
        seen.append(view)
        return next(replies)

    models: Sequence[str] = ("gpt-6.1-sol", "gpt-6-astra", "gpt-6-luna")
    assert await choose_model(ask, "OpenAI", models) == "gpt-6-astra"
    view = seen[0]
    assert isinstance(view, SelectionView)
    assert "recommended" in view.options[0].label
    assert view.options[-1].key == "custom"


@pytest.mark.anyio
async def test_api_selection_approves_privacy_before_hidden_key_entry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from collections.abc import Awaitable, Callable

    from finishup.tui.runtime import FinishUpRuntime

    events: list[str] = []

    class Runtime(FinishUpRuntime):
        def save_provider_binding(self, *args: object, **kwargs: object) -> None:
            events.append("binding")

        async def run_privacy_setup(self, *args: object, **kwargs: object) -> object:
            assert kwargs["credential_probe"] is True
            events.append("privacy")
            return SimpleNamespace(outcome="configured", grant_state="granted")

        async def store_provider_credential(self) -> str:
            events.append("hidden-key")
            return "stored"

    app = FinishUpTui(Runtime())
    replies = iter(["api_key", "official_openai", "1", "approve"])

    async def ask(_view: BaseView) -> str:
        return next(replies)

    async def handover(operation: Callable[[], Awaitable[object]]) -> object:
        return await operation()

    async def confidential(*_args: object, **_kwargs: object) -> str:
        await app.runtime.store_provider_credential()
        return "stored"

    async def posture() -> object:
        return SimpleNamespace()

    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    app.hand_over_terminal = handover  # pyright: ignore[reportAttributeAccessIssue]

    def silent(*_args: object, **_kwargs: object) -> None:
        return None

    app.say = silent  # pyright: ignore[reportAttributeAccessIssue]
    app._run_confidential = confidential  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]
    app.runtime.provider_posture = posture  # pyright: ignore[reportAttributeAccessIssue]
    # Rendering the stored-provider snapshot is outside this transition-order test.
    import finishup.tui.app as app_module

    def rendered(*_args: object) -> tuple[str, ...]:
        return ()

    monkeypatch.setattr(app_module, "render_provider_stored", rendered)
    await app.command_provider("local_agent_opt_in")
    assert events == ["binding", "privacy", "hidden-key"]


@pytest.mark.anyio
@pytest.mark.parametrize("probe", [True, False])
async def test_trusted_privacy_handoff_asks_probe_consent_only_for_api_key(
    monkeypatch: pytest.MonkeyPatch,
    probe: bool,
) -> None:
    from pathlib import Path

    from finishup.cli import privacy_setup, setup
    from finishup.tui.runtime import FinishUpRuntime

    questions: list[bool] = []
    calls: list[dict[str, object]] = []

    def authorize() -> bool:
        questions.append(True)
        return True

    async def privacy(**kwargs: object) -> object:
        calls.append(kwargs)
        return SimpleNamespace(outcome="configured")

    monkeypatch.setattr(setup, "prompt_credential_probe_authorization", authorize)
    monkeypatch.setattr(privacy_setup, "run_privacy_setup", privacy)
    runtime = FinishUpRuntime(cwd=Path.cwd())
    await runtime.run_privacy_setup(None, credential_probe=probe)
    assert questions == ([True] if probe else [])
    assert calls[0]["credential_probe_authorized"] is probe


@pytest.mark.anyio
async def test_an_unrecorded_not_now_never_finishes_setup() -> None:
    """Review of #1119: a failed local-only recording must not finish over the old policy."""

    app = FinishUpTui(SimpleNamespace())  # pyright: ignore[reportArgumentType]
    finished: list[bool] = []

    async def ask(_view: BaseView) -> str:
        return "local_only"

    async def unrecorded() -> bool:
        return False

    async def finish(*, connected: bool) -> None:
        finished.append(connected)

    async def ready_reviewer() -> object:
        raise AssertionError("an unrecorded answer must not fall through to reviewer readiness")

    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    app._record_local_only = unrecorded  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]
    app._finish_setup = finish  # pyright: ignore[reportAttributeAccessIssue, reportPrivateUsage]
    app.runtime.provider_posture = ready_reviewer  # pyright: ignore[reportAttributeAccessIssue]

    assert await app.command_provider("local_agent_opt_in") == "local_only_unrecorded"
    await app._run_initial_review("agent_opt_in", connected=True)  # pyright: ignore[reportPrivateUsage]
    await app._run_initial_review("local_only", connected=True)  # pyright: ignore[reportPrivateUsage]
    assert finished == []


@pytest.mark.anyio
@pytest.mark.parametrize("outcome", ["removed", "removed_not_ready", "cancelled", "unknown"])
async def test_provider_menu_offers_remove_and_hands_terminal_back(outcome: str) -> None:
    from collections.abc import Awaitable, Callable

    from finishup.tui.runtime import FinishUpRuntime

    events: list[str] = []
    messages: list[str] = []
    views: list[BaseView] = []

    class Runtime(FinishUpRuntime):
        async def remove_provider_credential(self) -> str:
            events.append("remove")
            return outcome

    app = FinishUpTui(Runtime())
    replies = iter(["api_key", "remove_key"])

    async def ask(view: BaseView) -> str:
        views.append(view)
        return next(replies)

    async def handover(operation: Callable[[], Awaitable[object]]) -> object:
        events.append("handover")
        return await operation()

    def silent(*args: object, **_kwargs: object) -> None:
        messages.append(str(args))

    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    app.hand_over_terminal = handover  # pyright: ignore[reportAttributeAccessIssue]
    app.say = silent  # pyright: ignore[reportAttributeAccessIssue]
    await app.command_provider()
    assert events == ["handover", "remove"]
    menu = views[1]
    assert isinstance(menu, SelectionView)
    assert any(option.label == "Remove the stored key" for option in menu.options)
    if outcome in {"removed", "removed_not_ready"}:
        assert any(
            "was removed" in message and "finishup ai key" in message for message in messages
        )
    else:
        assert all("was removed" not in message for message in messages)
