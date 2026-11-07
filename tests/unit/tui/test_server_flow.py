"""``/server`` lists server targets, shows status, and switches with the CLI's confirmation.

ADR-051: the header names a selected target by kind and id only; the everyday server leaves the
header exactly as before. Switching to a remote target hands the terminal to the same trusted
console confirmation ``finishup server use`` uses; ``add``, ``remove`` and ``login`` belong on the
command line, so ``/server`` prints those commands. Server-host commands refuse a remote target.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any

import pytest

from builders.tui_runtime import FakeRuntime
from finishup.cli.command_scope import ServerHostRequired
from finishup.tui.app import FinishUpTui
from finishup.tui.commands import command_named
from finishup.tui.models import ServerRow, ServerSwitch
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


_LEFT = (
    "Closed this computer's connection to the server t_9f8e7d6c (ssh): it no longer answers "
    "that server's requests for your files.",
)


async def test_switching_away_from_a_remote_server_says_its_connection_closed() -> None:
    """ADR-051 decision 8: ``/server`` "Use local" is the way out, and it stops the traffic."""

    rows = (
        ServerRow("local", "local", None, None, False),
        ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
    )
    runtime = FakeRuntime(servers=rows, server_selected="ssh t_9f8e7d6c", server_left_lines=_LEFT)
    harness = _Harness(runtime, ["use:local"])

    await harness.app.command_server()

    assert runtime.server_uses == ["local"]
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.VERIFIED, "Using this computer's everyday server")
    assert body[0] == _LEFT[0]
    assert "Restart open agent sessions: a running" in body[1]


async def test_a_left_connection_that_did_not_close_is_not_shown_as_done() -> None:
    rows = (
        ServerRow("local", "local", None, None, False),
        ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
    )
    still = ("The connection to the server t_9f8e7d6c (ssh) did not close in time, ...",)
    runtime = FakeRuntime(
        servers=rows,
        server_selected="ssh t_9f8e7d6c",
        server_left_lines=still,
        server_left_open=True,
    )
    harness = _Harness(runtime, ["use:local"])

    await harness.app.command_server()

    verified = [entry for entry in harness.said if entry[0] is Level.VERIFIED]
    assert len(verified) == 1 and still[0] not in verified[0][2]
    assert harness.said[-1] == (
        Level.UNPROVEN,
        "The connection to the server you left did not close",
        still,
    )


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
        ("remove", "finishup server remove NAME"),
        ("login", "finishup server login NAME"),
        ("folders", "finishup server folders add NAME"),
        ("folders", "finishup server folders mode NAME local"),
        ("folders", "finishup server folders mode NAME listed"),
        # The repair of a damaged record, which '/server' status names (refusal-guide review).
        ("folders", "finishup server folders remove NAME --all"),
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


async def test_adding_a_server_on_this_computer_prints_its_command() -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", "add:local"])

    await harness.app.command_server()

    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    assert "    finishup server add NAME --local" in body
    assert not any("--outside-reads" in line for line in body)
    assert len(harness.views) == 2  # no outside-read question for a server on this computer


@pytest.mark.parametrize("answer", ["local", "listed"])
async def test_adding_a_remote_server_asks_what_it_may_read_outside_your_projects(
    answer: str,
) -> None:
    """D2b: ``/server`` asks the question ``finishup server add`` asks, in the same words, and
    the printed command carries the answer for every remote kind."""

    from finishup.client.server_folders import OUTSIDE_READ_MODE_LINES, OUTSIDE_READ_QUESTION

    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", "add:remote", answer])

    await harness.app.command_server()

    question = harness.views[2]
    assert isinstance(question, SelectionView)
    assert question.title_text == OUTSIDE_READ_QUESTION
    options = {option.key: option.description for option in question._all_options}  # pyright: ignore[reportPrivateUsage]
    assert options == dict(OUTSIDE_READ_MODE_LINES)
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    for address in ("ssh://user@host", "--port PORT", "https://host"):
        assert f"    finishup server add NAME {address} --outside-reads {answer}" in body
    assert any("type its name" in line for line in body)
    assert runtime.server_uses == []


async def test_no_official_service_is_offered_while_none_is_reviewed() -> None:
    """``OFFICIAL_ENDPOINT_HOSTS`` is empty: the add flow offers no official service, and the
    question names none."""

    from finishup.client.server_folders import OFFICIAL_ENDPOINT_HOSTS

    assert OFFICIAL_ENDPOINT_HOSTS == frozenset()
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", "add:remote", "listed"])

    await harness.app.command_server()

    where, question = harness.views[1], harness.views[2]
    assert isinstance(where, SelectionView) and isinstance(question, SelectionView)
    keys = [option.key for option in where._all_options]  # pyright: ignore[reportPrivateUsage]
    assert keys == ["add:local", "add:remote"]
    assert not any("official" in line for line in question._body)  # pyright: ignore[reportPrivateUsage]


async def test_an_official_service_is_not_asked_and_its_command_carries_no_mode(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ADR-051 decision 5: ``server add`` never asks an official FinishUP service and leaves its
    ``local`` unrecorded, following the reviewed list; ``/server`` does the same, so it never
    turns that into the owner's own recorded choice with ``--outside-reads``."""

    from finishup.client import server_folders

    monkeypatch.setattr(
        server_folders, "OFFICIAL_ENDPOINT_HOSTS", frozenset({"fu.example", "api.fu.example"})
    )
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, ["add", "add:official"])

    await harness.app.command_server()

    where = harness.views[1]
    assert isinstance(where, SelectionView)
    keys = [option.key for option in where._all_options]  # pyright: ignore[reportPrivateUsage]
    assert keys == ["add:local", "add:official", "add:remote"]
    assert len(harness.views) == 2  # no outside-read question
    level, title, body = harness.said[-1]
    assert (level, title) == (Level.OPTIONAL, "Run this in your shell")
    assert body[:2] == (
        "    finishup server add NAME https://api.fu.example",
        "    finishup server add NAME https://fu.example",
    )
    assert not any("--outside-reads" in line for line in body)
    assert any("mode local" in line for line in body)
    assert runtime.server_uses == []

    # The question for any other server says an official one is not asked.
    asked = _Harness(FakeRuntime(servers=_ROWS), ["add", "add:remote", "listed"])
    await asked.app.command_server()
    question = asked.views[2]
    assert isinstance(question, SelectionView)
    assert any(
        "An official FinishUP service is not asked" in line
        for line in question._body  # pyright: ignore[reportPrivateUsage]
    )


@pytest.mark.parametrize("answers", [["add", None], ["add", "add:remote", None]])
async def test_going_back_from_the_add_flow_adds_nothing(answers: list[str | None]) -> None:
    runtime = FakeRuntime(servers=_ROWS)
    harness = _Harness(runtime, answers)

    await harness.app.command_server()

    assert harness.said[-1][1] == "No server was added."
    assert not any(title == "Run this in your shell" for title in harness.titles)


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

        assert await runtime.use_server("work") == ServerSwitch(f"local {record.target_id}")
        reset_selection_memo()
        assert runtime.server_indicator() == f"local {record.target_id}"

        assert await runtime.use_server("local") == ServerSwitch("everyday")
        reset_selection_memo()
        assert runtime.server_indicator() is None

        with pytest.raises(RuntimeError_) as raised:
            await runtime.use_server("nowhere")
        assert raised.value.reason == "target_unknown"
        assert "nowhere" not in raised.value.message


async def test_the_real_runtime_stops_the_remote_server_it_switches_away_from(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``/server`` "Use local" runs ``finishup server use local``: what this client ran for the
    remote server it leaves is stopped through that target's runtime, never by pattern."""

    from builders.server_targets import ambient_home
    from finishup.client import targets
    from finishup.client.rest_runtime import RestTargetRuntime
    from finishup.config.paths import reset_selection_memo
    from finishup.tui.runtime import FinishUpRuntime

    stops: list[Path | None] = []

    def stop(_self: object, target: Path | None) -> None:
        stops.append(target)

    monkeypatch.setattr(RestTargetRuntime, "stop", stop)
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "lab", "ssh", user="owner", host="lab.example", port=22
            )
            targets.write_selection(record)
        reset_selection_memo()
        runtime = FinishUpRuntime(cwd=home)

        switch = await runtime.use_server("local")

        assert stops == [root]
        assert switch == ServerSwitch(
            "everyday",
            (
                f"Closed this computer's connection to the server {record.target_id} (ssh): it "
                "no longer answers that server's requests for your files.",
            ),
        )
        assert targets.read_selected_target_id() is None


async def test_the_real_runtime_status_shows_what_a_remote_server_may_read_outside(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-051 decision 5: ``/server`` status shows the outside-read mode, where it came from,
    and the folders listed for that server, as ``finishup server status`` does."""

    from builders.server_targets import ambient_home
    from finishup.cli import server as server_cli
    from finishup.client import targets
    from finishup.client.server_folders import add_folder, set_mode
    from finishup.client.target_runtime import ProbeResult
    from finishup.tui.runtime import FinishUpRuntime

    def unreachable(_record: object, _root: object) -> ProbeResult:
        return ProbeResult("unavailable", reason="remote_unreachable")

    monkeypatch.setattr(server_cli, "_probe", unreachable)
    with ambient_home(monkeypatch) as home:
        with targets.registry_lock():
            record, root = targets.new_remote_target(
                "devbox", "ssh", host="devbox.example", port=22
            )
        shared = (tmp_path / "shared").resolve()
        shared.mkdir()
        with targets.registry_lock():
            add_folder(root, record.target_id, str(shared))
        runtime = FinishUpRuntime(cwd=home)
        lines = await runtime.server_status_lines("devbox")
        # No mode chosen: listed, and how to choose, as 'finishup server status' says.
        assert (
            "Outside your projects: reads only folders you list (mode listed, not chosen yet)"
        ) in lines
        assert any("'finishup server folders mode devbox local'" in line for line in lines)
        with targets.registry_lock():
            set_mode(root, record.target_id, "local")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads what FinishUP on this computer would read (mode local, "
            "set by you)"
        ) in lines
        assert f"  {shared}" in lines
        with targets.registry_lock():
            set_mode(root, record.target_id, "listed")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads only folders you list (mode listed, set by you)" in lines
        )
        at = lines.index("Folders it may read outside your projects:")
        assert lines[at + 1] == f"  {shared}"
        # A damaged record: say so, with the one repair, where to run it, and its full name.
        from finishup.client.server_folders import folders_path

        folders_path(root).write_text("{damaged\n")
        lines = await runtime.server_status_lines("devbox")
        assert (
            "Outside your projects: reads only folders you list (mode listed, because its record "
            "cannot be read)"
        ) in lines
        assert any(
            "Repair it on this computer with 'finishup server folders remove devbox --all'" in line
            for line in lines
        )
