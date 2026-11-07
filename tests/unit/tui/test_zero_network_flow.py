"""The terminal interface shows a remote server still selected under zero-network (ADR-051).

Maintainer decision of 2026-11-06 (decision 8): the header and ``/server`` say so while this
computer's privacy policy forbids network use and the selection names a server on another
machine, a port or the web; ``/server`` keeps "Use local" as the owner's way to switch, and the
header drops the item once the selection changes. The item is read when the interface starts,
before any command, and again after a privacy ceremony and on ``/server``.
"""

from __future__ import annotations

from collections.abc import Iterator, Sequence
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import finishup.cli.zero_network_selection as zero_network
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
    "This computer's privacy policy forbids all network use, but the selected FinishUP server "
    "t_9f8e7d6c (ssh) is on another machine, reached over SSH.",
    "To stop, run 'finishup server use local', then restart open agent sessions.",
)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(zero_network, "_selection_on_disk", zero_network.read_selection_on_disk)
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

    item = [entry for entry in said if entry[1] == "Zero-network does not stop the selected server"]
    assert item == [(Level.UNPROVEN, "Zero-network does not stop the selected server", _ITEM_LINES)]
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

    assert any("does not stop traffic" in line for line in lines)
    indicator = runtime.server_indicator()
    assert indicator == f"ssh {record.target_id} · zero-network here does not stop it"
    assert "lab" not in str(indicator).replace(record.target_id, "")

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
        # The owner chose zero-network and kept the server when the ceremony asked.
        state[0] = "zero_network"
        return SimpleNamespace(outcome="configured")

    monkeypatch.setattr("finishup.cli.privacy_setup.run_privacy_setup", ceremony)

    report = await runtime.run_privacy_setup("private")

    assert getattr(report, "outcome", None) == "configured"
    assert runtime.server_indicator() == (
        f"ssh {record.target_id} · zero-network here does not stop it"
    )
