"""The terminal interface shows a remote server refused under zero-network (ADR-051).

Maintainer decision of 2026-11-07 (decision 8): this computer's zero-network policy and a server
on another machine, a port or the web are never in force together. While the selection still
names one (a process that resolved it earlier, a change made elsewhere), the header and
``/server`` say that connections to it are refused, from the live policy or, when this
computer's service cannot be asked, from what it last reported; ``/server`` keeps "Use local" as
the owner's way out, and the header drops the item once the selection changes. The item is read
when the interface starts, before any command, and again after a privacy ceremony and on
``/server``.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.cli.zero_network_selection as zero_network
import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from builders.tui_runtime import FakeRuntime
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.tui.app import FinishUpTui
from finishup.tui.models import ServerRow
from finishup.tui.symbols import Level
from finishup.tui.widgets.views import BaseView, SelectionView

pytestmark = pytest.mark.anyio

_ROWS = (
    ServerRow("local", "local", None, None, False),
    ServerRow("lab", "ssh", "t_9f8e7d6c", "ssh://owner@lab.example:22", True),
)
_ITEM_LINES = (
    "This computer's privacy policy forbids all network use, and the selected FinishUP server "
    "t_9f8e7d6c (ssh) is on another machine, reached over SSH.",
    "To keep working, run 'finishup server use local', then restart open agent sessions.",
)
_TITLE = "This computer is zero-network: the selected server is refused"


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


def _harness(
    runtime: FakeRuntime, answers: Sequence[str | None]
) -> tuple[FinishUpTui, list[tuple[Level, str, tuple[str, ...]]], list[BaseView]]:
    app = FinishUpTui(cast(Any, runtime))
    said: list[tuple[Level, str, tuple[str, ...]]] = []
    views: list[BaseView] = []
    pending = list(answers)

    def say(
        level: Level, title: str, body: Sequence[str] = (), *, details: Sequence[str] = ()
    ) -> None:
        del details
        said.append((level, title, tuple(body)))

    async def ask(view: BaseView) -> str | None:
        views.append(view)
        return pending.pop(0)

    async def refresh_header() -> None:
        return None

    app.say = say  # pyright: ignore[reportAttributeAccessIssue]
    app.ask = ask  # pyright: ignore[reportAttributeAccessIssue]
    app._refresh_header = refresh_header  # pyright: ignore[reportAttributeAccessIssue,reportPrivateUsage]
    return app, said, views


async def test_server_shows_the_item_and_keeps_use_local_as_the_way_out() -> None:
    runtime = FakeRuntime(servers=_ROWS, server_selected="ssh t_9f8e7d6c", zero_network=_ITEM_LINES)
    app, said, views = _harness(runtime, [None])

    await app.command_server()

    item = [entry for entry in said if entry[1] == _TITLE]
    assert item == [(Level.UNPROVEN, _TITLE, _ITEM_LINES)]
    selection = views[0]
    assert isinstance(selection, SelectionView)
    assert "use:local" in [option.key for option in selection.options]
    # Showing the item switched nothing.
    assert runtime.server_uses == []


async def test_server_says_nothing_more_without_the_item() -> None:
    runtime = FakeRuntime(servers=_ROWS, server_selected="ssh t_9f8e7d6c")
    app, said, _views = _harness(runtime, [None])

    await app.command_server()

    assert [title for _level, title, _body in said] == ["FinishUP servers"]
    assert runtime.zero_network_reads == 1


async def test_the_item_is_read_when_the_interface_starts() -> None:
    runtime = FakeRuntime(zero_network=_ITEM_LINES)
    app = FinishUpTui(cast(Any, runtime))

    async with app.run_test(size=(100, 34)) as pilot:
        await pilot.pause()
        assert runtime.zero_network_reads >= 1


def _remote_selected() -> targets.ServerTarget:
    with targets.registry_lock():
        record, _root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=22
        )
        targets.write_selection(record)
    reset_selection_memo()
    return record


async def test_the_header_names_the_item_until_the_selection_changes(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected()
    monkeypatch.setattr(zero_network, "everyday_network_state", lambda: "zero_network")
    runtime = FinishUpRuntime(cwd=home)
    assert runtime.server_indicator() == f"ssh {record.target_id}"

    lines = await runtime.refresh_zero_network_item()

    assert any("refused before anything is sent" in line for line in lines)
    indicator = runtime.server_indicator()
    assert indicator == f"ssh {record.target_id} · refused: zero-network here"
    assert "lab" not in str(indicator).replace(record.target_id, "")
    assert runtime.zero_network_heading() == _TITLE

    with targets.registry_lock():
        targets.clear_selection()
    assert runtime.server_indicator() is None


async def test_a_privacy_ceremony_refreshes_the_item(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected()
    state = ["network_permitted"]
    monkeypatch.setattr(zero_network, "everyday_network_state", lambda: state[0])
    runtime = FinishUpRuntime(cwd=home)
    await runtime.refresh_zero_network_item()
    assert runtime.server_indicator() == f"ssh {record.target_id}"

    async def ceremony(**_kwargs: object) -> object:
        # Another terminal made this computer zero-network while the ceremony ran.
        state[0] = "zero_network"
        return SimpleNamespace(outcome="configured")

    monkeypatch.setattr("finishup.cli.privacy_setup.run_privacy_setup", ceremony)

    report = await runtime.run_privacy_setup("private")

    assert getattr(report, "outcome", None) == "configured"
    assert runtime.server_indicator() == f"ssh {record.target_id} · refused: zero-network here"


async def test_the_header_and_server_say_what_this_computer_last_reported(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """This computer's service is stopped or locked, the normal case while a remote server is
    used: what it last reported decides, worded as such."""

    from finishup.tui.runtime import FinishUpRuntime

    record = _remote_selected()
    monkeypatch.setattr(zero_network, "everyday_network_state", lambda: "unreadable")
    everyday_policy.record_reported_policy(
        zero_network=True, now=datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
    )
    runtime = FinishUpRuntime(cwd=home)

    lines = await runtime.refresh_zero_network_item()

    assert lines[0].startswith(
        "This computer last reported, at 2026-11-07T09:30:00.000Z, that its privacy policy"
    )
    assert runtime.server_indicator() == (
        f"ssh {record.target_id} · refused: last reported zero-network here"
    )
    assert runtime.zero_network_heading() == (
        "This computer last reported zero-network: the selected server is refused"
    )


async def test_server_titles_the_item_as_last_reported() -> None:
    title = "This computer last reported zero-network: the selected server is refused"
    runtime = FakeRuntime(
        servers=_ROWS,
        server_selected="ssh t_9f8e7d6c",
        zero_network=_ITEM_LINES,
        zero_network_title=title,
    )
    app, said, _views = _harness(runtime, [None])

    await app.command_server()

    assert (Level.UNPROVEN, title, _ITEM_LINES) in said


async def test_server_status_reuses_the_item_server_read_and_asks_no_service_again(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``/server`` reads the item (one policy read) before its status view; the status lines
    never show it, so building them does not ask this computer's service for its policy again.
    A selection switched meanwhile drops the cached item rather than reusing a stale one."""

    from finishup.client.target_runtime import ProbeResult
    from finishup.tui.runtime import FinishUpRuntime

    def unreachable(_self: object, _root: Path | None) -> ProbeResult:
        return ProbeResult("unavailable", reason="remote_unreachable")

    monkeypatch.setattr(
        "finishup.client.connector_runtime.ConnectorTargetRuntime.probe", unreachable
    )
    record = _remote_selected()
    reads: list[int] = []

    def zero_network_state() -> str:
        reads.append(1)
        return "zero_network"

    monkeypatch.setattr(zero_network, "everyday_network_state", zero_network_state)
    built: list[object] = []
    from finishup.cli import server as server_cli

    real_build = server_cli.build_status_document

    def build(name: str | None, **kwargs: Any) -> dict[str, Any]:
        document = real_build(name, **kwargs)
        built.append(document["zero_network_selection"])
        return document

    monkeypatch.setattr(server_cli, "build_status_document", build)
    runtime = FinishUpRuntime(cwd=home)

    assert await runtime.refresh_zero_network_item()
    lines = await runtime.server_status_lines()

    assert any(record.target_id in line for line in lines)
    assert reads == [1]
    assert built == [
        {
            "reason": "zero_network_remote_selected",
            "target_id": record.target_id,
            "kind": "ssh",
            "detail": None,
            "policy_read": "live",
            "last_reported_at": None,
        }
    ]

    with targets.registry_lock():
        targets.clear_selection()
    reset_selection_memo()
    await runtime.server_status_lines("lab")
    assert reads == [1]
    assert built[-1] is None


@pytest.mark.parametrize("selected", [True, False])
async def test_server_status_of_a_named_server_probes_nothing_and_names_its_fix(
    home: Path, monkeypatch: pytest.MonkeyPatch, selected: bool
) -> None:
    """``/server`` status of one server while this computer last reported zero-network: nothing
    is sent to probe it, and the fix is the one for that server ('finishup server use local' for
    the selected one; this computer's privacy policy for one nothing uses)."""

    from finishup.cli import server as server_cli
    from finishup.tui.runtime import FinishUpRuntime

    def never(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("nothing is probed or sent")

    monkeypatch.setattr(server_cli, "_probe", never)
    monkeypatch.setattr(zero_network, "everyday_network_state", lambda: "unreadable")
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", "ssh", host="lab.example", port=22)
        if selected:
            targets.write_selection(record)
    reset_selection_memo()
    everyday_policy.record_reported_policy(
        zero_network=True, now=datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
    )

    lines = await FinishUpRuntime(cwd=home).server_status_lines("lab")

    token = "zero_network_remote_selected" if selected else "zero_network_in_force"
    assert f"State: not probed, nothing was sent ({token})" in lines
    text = "\n".join(lines)
    assert "did not answer" not in text
    if selected:
        assert "'finishup server use local'" in text
    else:
        assert "'finishup privacy setup'" in text
        assert "server use local" not in text
