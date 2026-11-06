"""``/server`` lists server targets, shows status, and switches with the CLI's confirmation.

ADR-051: the header names a selected target by kind and id only; the everyday server leaves the
header exactly as before. Switching to a remote target hands the terminal to the same trusted
console confirmation ``finishup server use`` uses; ``add``, ``remove`` and ``login`` belong on the
command line, so ``/server`` prints those commands. Server-host commands refuse a remote target.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

import pytest

from builders.tui_runtime import FakeRuntime
from finishup.cli.command_scope import ServerHostRequired
from finishup.tui.app import FinishUpTui
from finishup.tui.commands import command_named
from finishup.tui.models import ServerRow
from finishup.tui.render import render_session_header
from finishup.tui.runtime import RuntimeError_
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import ApprovalView, BaseView, SelectionView

pytestmark = pytest.mark.anyio

_ROWS = (
    ServerRow("local", "local", None, None, True),
    ServerRow("work", "local", "t_1a2b3c4d", None, False),
    ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", False),
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Harness:
    def __init__(self, runtime: FakeRuntime, answers: Sequence[str | None]) -> None:
        self.runtime = runtime
        self.app = FinishUpTui(runtime)  # pyright: ignore[reportArgumentType]
        self.said: list[tuple[Level, str, tuple[str, ...]]] = []
        self.views: list[BaseView] = []
        self.answers = list(answers)
        self.handed_over = 0
        self.header_refreshes = 0

        def say(
            level: Level, title: str, body: Sequence[str] = (), *, details: Sequence[str] = ()
        ) -> None:
            del details
            self.said.append((level, title, tuple(body)))

        async def ask(view: BaseView) -> str | None:
            self.views.append(view)
            return self.answers.pop(0)

        async def hand_over(operation: Callable[[], Awaitable[Any]]) -> Any:
            self.handed_over += 1
            return await operation()

        async def refresh_header() -> None:
            self.header_refreshes += 1

        self.app.say = say  # pyright: ignore[reportAttributeAccessIssue]
        self.app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
        self.app.hand_over_terminal = hand_over  # pyright: ignore[reportAttributeAccessIssue]
        self.app._refresh_header = refresh_header  # pyright: ignore[reportAttributeAccessIssue,reportPrivateUsage]

    @property
    def titles(self) -> list[str]:
        return [title for _level, title, _body in self.said]


async def test_switching_to_a_named_local_server_needs_no_terminal_handoff() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["use:work"])

    await harness.app.command_server()

    assert runtime.server_uses == ["work"]
    assert harness.handed_over == 0
    assert harness.header_refreshes == 1
    assert runtime.server_indicator() == "local t_1a2b3c4d"
    assert "Using the server work" in harness.titles
    selection = harness.views[0]
    assert isinstance(selection, SelectionView)


async def test_switching_to_a_remote_server_hands_over_for_the_typed_confirmation() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["use:lab", "approve"])

    await harness.app.command_server()

    assert isinstance(harness.views[1], ApprovalView)
    assert harness.handed_over == 1
    assert runtime.server_uses == ["lab"]
    assert runtime.server_indicator() == "ssh t_9f8e7d6c"


async def test_declining_the_remote_switch_changes_nothing() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["use:lab", "decline"])

    await harness.app.command_server()

    assert runtime.server_uses == []
    assert harness.handed_over == 0
    assert "The selected server is unchanged." in harness.titles


@pytest.mark.parametrize(
    ("choice", "command"),
    [
        ("add", "finishup server add NAME --local"),
        ("remove", "finishup server remove NAME"),
        ("login", "finishup server login NAME"),
        ("folders", "finishup server folders add NAME"),
    ],
)
async def test_registry_changes_print_the_cli_command(choice: str, command: str) -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, [choice])

    await harness.app.command_server()

    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    assert any(command in line for line in body)
    assert runtime.server_uses == []


async def test_status_shows_the_probe_lines() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["status"])

    await harness.app.command_server()

    assert harness.said[-1][1] == "Server status"


async def test_a_refusal_is_reported_with_its_reason() -> None:
    runtime = FakeRuntime(
        servers=_ROWS,
        server_error=RuntimeError_("selection_overridden", "the selection is not used here"),
    )
    harness = _Harness(runtime, [])

    await harness.app._dispatch("server")  # pyright: ignore[reportPrivateUsage]

    assert any("selection is not used here" in title for title in harness.titles)


async def test_server_host_commands_refuse_a_remote_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(command: str) -> None:
        if command in {"/privacy", "/provider", "/service"}:
            raise ServerHostRequired("t_9f8e7d6c", "ssh")

    monkeypatch.setattr("finishup.cli.command_scope.require_server_host", refuse)
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, [])

    await harness.app._dispatch("service")  # pyright: ignore[reportPrivateUsage]

    level, title, body = harness.said[-1]
    assert level is Level.BLOCKED
    assert title == "/service runs on the FinishUP server host"
    assert "requires_server_host" in body[0]
    assert "t_9f8e7d6c" in body[0]
    assert "lab" not in body[0].replace("t_9f8e7d6c", "")


def test_the_header_is_unchanged_without_a_selected_target() -> None:
    plain = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
    )
    with_none = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
        server=None,
    )
    selected = render_session_header(
        version="1.2.3",
        project_root="/srv/p",
        harness_state="connected",
        privacy_summary="local only",
        width=72,
        server="ssh t_9f8e7d6c",
    )
    assert plain == with_none
    assert len(selected) == len(plain) + 1
    assert selected[-1].split() == ["server:", "ssh", "t_9f8e7d6c", "/server", "to", "change"]


def test_server_is_a_slash_command() -> None:
    command = command_named("/server")
    assert command is not None and command.name == "server"


async def test_the_real_runtime_lists_switches_and_names_the_header(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from builders.server_targets import ambient_home
    from finishup.client import targets
    from finishup.config.paths import reset_selection_memo
    from finishup.tui.runtime import FinishUpRuntime

    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, _root = targets.new_local_target("work")
        runtime = FinishUpRuntime(cwd=home)
        assert runtime.server_indicator() is None

        rows, lines = await runtime.server_rows()
        assert [(row.name, row.selected) for row in rows] == [("local", True), ("work", False)]
        assert any(record.target_id in line for line in lines)

        assert await runtime.use_server("work") == f"local {record.target_id}"
        reset_selection_memo()
        assert runtime.server_indicator() == f"local {record.target_id}"

        assert await runtime.use_server("local") == "everyday"
        reset_selection_memo()
        assert runtime.server_indicator() is None

        with pytest.raises(RuntimeError_) as raised:
            await runtime.use_server("nowhere")
        assert raised.value.reason == "target_unknown"
        assert "nowhere" not in raised.value.message
