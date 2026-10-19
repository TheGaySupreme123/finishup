"""First run offers all agents, a real subset, and one batch approval."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from dataclasses import asdict
from pathlib import Path
from typing import Any

import pytest

import builders.tui as build
from finishup.tui.app import FinishUpTui
from finishup.tui.models import HarnessOption
from finishup.tui.widgets.views import ApprovalView, BaseView, SelectionView


@pytest.mark.anyio
async def test_all_agents_is_the_first_default_choice(monkeypatch: pytest.MonkeyPatch) -> None:
    app = FinishUpTui()
    options = (
        HarnessOption("/opt/claude", "2.1.0", "Claude Code", "", host="claude"),
        HarnessOption("/opt/agent", "1.0.0", "Cursor Agent CLI", "", host="cursor-cli"),
    )
    views: list[BaseView] = []

    async def ask(view: BaseView) -> str:
        views.append(view)
        return "all"

    monkeypatch.setattr(app, "ask", ask)
    selected = await app._choose_harnesses(options)  # pyright: ignore[reportPrivateUsage]
    assert selected == options
    assert isinstance(views[0], SelectionView)
    assert views[0].options[0].key == "all"
    assert views[0].options[0].label == "All 2 agents (recommended)"


@pytest.mark.anyio
async def test_choose_which_opens_multiselect(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.tui.widgets.views import MultiSelectionView

    app = FinishUpTui()
    options = (
        HarnessOption("/opt/claude", "2.1.0", "Claude Code", "", host="claude"),
        HarnessOption("/opt/agent", "1.0.0", "Cursor Agent CLI", "", host="cursor-cli"),
    )

    async def ask(view: BaseView) -> str:
        if isinstance(view, MultiSelectionView):
            view.toggle("1")
            return "submit"
        return "choose"

    monkeypatch.setattr(app, "ask", ask)
    assert await app._choose_harnesses(options) == (options[1],)  # pyright: ignore[reportPrivateUsage]


def test_multiselect_does_not_submit_empty_or_accept_escape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.tui.widgets.views import MultiSelectionView, Option

    view = MultiSelectionView(name="agents", options=[Option("a", "Claude Code")])
    dismissed: list[str | None] = []
    monkeypatch.setattr(view, "dismiss", dismissed.append)
    from textual.events import Key

    view.on_key(Key("enter", None))
    assert dismissed == []
    view.on_key(Key("space", " "))
    assert view.selected_keys == ("a",)
    view.on_key(Key("enter", None))
    view.on_key(Key("escape", None))
    assert dismissed == ["submit", None]


@pytest.mark.anyio
async def test_first_run_keeps_codex_home_and_trust_and_asks_review_once(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from finishup.tui.models import Detection

    app = FinishUpTui()
    options = (build.CLI, HarnessOption("/opt/claude", "2.1.0", "Claude Code", "", host="claude"))
    detected = build.detection(harnesses=options)
    steps: list[str] = []

    async def detect() -> Detection:
        return detected

    async def ask(view: BaseView) -> str:
        return "connect" if view.view_name == "welcome" else "all"

    async def home(option: HarnessOption) -> Path:
        assert option == build.CLI
        steps.append("codex-home")
        return tmp_path

    async def trust(detection: Detection, **kwargs: Any) -> bool:
        assert detection == detected
        steps.append("trust")
        return True

    async def review(**kwargs: Any) -> str:
        steps.append("review")
        return "local_only"

    async def connect(selected: Sequence[HarnessOption], **kwargs: Any) -> bool:
        assert len(selected) == 2
        assert selected[0].config_root == str(tmp_path)
        assert kwargs["route"] == "policy"
        steps.append("connect")
        return True

    async def storage(detection: Detection) -> None:
        steps.append("storage")

    async def initial_review(choice: str, **kwargs: Any) -> None:
        assert choice == "local_only" and kwargs["connected"]
        steps.append("initial-review")

    async def refresh() -> None:
        pass

    monkeypatch.setattr(app.runtime, "detect", detect)
    monkeypatch.setattr(app, "ask", ask)

    def say(*args: object, **kwargs: object) -> None:
        pass

    monkeypatch.setattr(app, "say", say)
    monkeypatch.setattr(app, "_refresh_header", refresh)
    monkeypatch.setattr(app, "_choose_codex_home", home)
    monkeypatch.setattr(app, "_confirm_project_trust", trust)
    monkeypatch.setattr(app, "_ask_review_mode", review)
    monkeypatch.setattr(app, "_connect_host_batch", connect)
    monkeypatch.setattr(app, "_choose_storage", storage)
    monkeypatch.setattr(app, "_run_initial_review", initial_review)
    await app._first_run_flow()  # pyright: ignore[reportPrivateUsage]
    assert steps == ["codex-home", "trust", "review", "connect", "storage", "initial-review"]


@pytest.mark.anyio
@pytest.mark.parametrize("approval", ["approve", None])
async def test_combined_tui_preview_preserves_codex_activation_and_one_approval(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    approval: str | None,
) -> None:
    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.application.host_connection import ConnectionPlan
    from finishup.cli import host_batch, host_connection
    from finishup.protocol.canonical import JsonValue

    app = FinishUpTui()
    options = (build.CLI, HarnessOption("/opt/claude", "2.1.0", "Claude Code", "", host="claude"))
    views: list[BaseView] = []
    applied: list[str] = []

    def select(
        host: str, executable: Path, config_root: Path | None, **kwargs: object
    ) -> HostInstallation:
        if host == "codex":
            assert kwargs["preserve_visible_name"] is True
        return HostInstallation(host, executable, "1.0.0", config_root or tmp_path, host)  # pyright: ignore[reportArgumentType]

    async def prepare(
        installations: Sequence[HostInstallation], project: Path, **kwargs: Any
    ) -> tuple[host_batch.BatchMember, ...]:
        members: list[host_batch.BatchMember] = []
        for item in installations:
            body: dict[str, JsonValue] = {
                "host": item.host,
                "executable": str(item.executable),
                "config_root": str(item.config_root),
                "project_root": str(project),
                "route_profile": "policy",
                "changes": ["install_plugin"],
                "request_id": kwargs["request_value"],
                "preview_digest": "sha256:" + "a" * 64,
                "action": "connect",
            }
            if item.host == "codex":
                body["codex_plan"] = asdict(build.plan())
            plan = ConnectionPlan(body, lambda: {}, lambda: None)
            members.append(host_batch.BatchMember(item, plan, lambda plan=plan: plan))
        return tuple(members)

    async def ask(view: BaseView) -> str | None:
        views.append(view)
        return approval

    async def apply(members: Sequence[host_batch.BatchMember]) -> list[dict[str, JsonValue]]:
        applied.extend(member.installation.host for member in members)
        return [host_batch.member_report(member, "completed") for member in members]

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    monkeypatch.setattr(app.runtime, "project_root", lambda: tmp_path)
    monkeypatch.setattr(app, "ask", ask)

    def say(*args: object, **kwargs: object) -> None:
        pass

    monkeypatch.setattr(app, "say", say)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(host_connection, "refuse_unservable_runtime", lambda: None)
    monkeypatch.setattr(host_connection, "select_installation", select)
    monkeypatch.setattr(host_batch, "prepare_batch", prepare)
    monkeypatch.setattr(host_batch, "apply_batch", apply)
    assert await app._connect_host_batch(options, route="policy") is (approval == "approve")  # pyright: ignore[reportPrivateUsage]
    assert len(views) == 1 and isinstance(views[0], ApprovalView)
    details = "\n".join(views[0].technical_details)
    assert build.plan().activation_preview_digest in details
    assert build.plan().skill_preview_digest in details
    assert "Combined preview:" in details
    assert applied == (["codex", "claude"] if approval == "approve" else [])


@pytest.mark.anyio
async def test_a_stale_batch_shows_each_outcome_and_a_fresh_preview(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Review of #1119: a change during approval keeps the outcomes and offers a fresh preview."""

    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.application.host_connection import ConnectionError, ConnectionPlan
    from finishup.cli import host_batch, host_connection
    from finishup.protocol.canonical import JsonValue

    app = FinishUpTui()
    options = (
        HarnessOption("/opt/claude", "2.1.0", "Claude Code", "", host="claude"),
        HarnessOption("/opt/agent", "1.0.0", "Cursor Agent CLI", "", host="cursor-cli"),
    )
    said: list[tuple[str, tuple[str, ...]]] = []

    def select(
        host: str, executable: Path, config_root: Path | None, **_: object
    ) -> HostInstallation:
        return HostInstallation(host, executable, "1.0.0", config_root or tmp_path, host)  # pyright: ignore[reportArgumentType]

    async def prepare(
        installations: Sequence[HostInstallation], project: Path, **kwargs: Any
    ) -> tuple[host_batch.BatchMember, ...]:
        members: list[host_batch.BatchMember] = []
        for item in installations:
            body: dict[str, JsonValue] = {
                "host": item.host,
                "executable": str(item.executable),
                "config_root": str(item.config_root),
                "project_root": str(project),
                "route_profile": "policy",
                "changes": ["install_plugin"],
                "request_id": kwargs["request_value"],
                "preview_digest": "sha256:" + "a" * 64,
                "action": "connect",
            }
            plan = ConnectionPlan(body, lambda: {}, lambda: None)
            members.append(host_batch.BatchMember(item, plan, lambda plan=plan: plan))
        return tuple(members)

    async def ask(_view: BaseView) -> str:
        return "approve"

    async def stale(members: Sequence[host_batch.BatchMember]) -> list[dict[str, JsonValue]]:
        reports = [host_batch.member_report(member, "not_attempted") for member in members]
        reports[1].update({"outcome": "incomplete", "reason": "connection_preview_stale"})
        raise host_batch.BatchPreparationError(reports, ConnectionError("connection_preview_stale"))

    async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
        return await operation()

    def say(_level: object, title: str, body: Sequence[str] = ()) -> None:
        said.append((title, tuple(body)))

    monkeypatch.setattr(app.runtime, "project_root", lambda: tmp_path)
    monkeypatch.setattr(app, "ask", ask)
    monkeypatch.setattr(app, "say", say)
    monkeypatch.setattr(app, "hand_over_terminal", hand_over)
    monkeypatch.setattr(host_connection, "refuse_unservable_runtime", lambda: None)
    monkeypatch.setattr(host_connection, "select_installation", select)
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: (str(launcher),))
    monkeypatch.setattr(host_batch, "prepare_batch", prepare)
    monkeypatch.setattr(host_batch, "apply_batch", stale)

    assert await app._connect_host_batch(options, route="policy") is False  # pyright: ignore[reportPrivateUsage]
    titles = [title for title, _body in said]
    assert "claude: not_attempted" in titles
    assert "cursor-cli: incomplete" in titles
    fresh = said[-1]
    assert fresh[0] == "An agent changed before the connection was applied"
    assert "--accept" not in fresh[1][-1] and "--host claude" in fresh[1][-1]
