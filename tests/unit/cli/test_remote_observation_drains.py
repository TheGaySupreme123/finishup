"""Hook and ``observe drain`` deliveries are claim-bound on a remote root (ADR-051, approach C).

A server on another machine accepts an observation row only when it is attested over a connection
that claims the row's workspace (decision 12); an unattested row would be refused and quarantined.
So on a remote root a hook pass's drains, and ``finishup observe drain``, name their workspace on
the connection (the connect seam claims it; the path is never sent). On every other root they
connect exactly as before, naming no workspace.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import cast

import pytest

from builders.server_targets import ambient_home
from finishup.cli import observe as observe_module
from finishup.cli import observe_hooks
from finishup.client import targets
from finishup.client.remote_remedy import remote_root_selected
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def __call__(self, kind: ControlClientKind, **options: object) -> object:
        self.calls.append({"kind": kind, **options})
        return object()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


def _select_remote() -> None:
    with targets.registry_lock():
        record, _root = targets.new_remote_target("lab", "https", base_url="https://lab.example")
        targets.write_selection(record)
    reset_selection_memo()


@pytest.mark.anyio
async def test_a_local_root_drains_exactly_as_before(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home
    recorder = _Recorder()
    monkeypatch.setattr(observe_hooks, "connect_service", recorder, raising=False)
    assert remote_root_selected() is False
    connect = observe_hooks._claim_bound_drain_connector("/home/me/repo")  # pyright: ignore[reportPrivateUsage]
    await connect(ControlClientKind.CLI)
    assert recorder.calls == [{"kind": ControlClientKind.CLI}]


@pytest.mark.anyio
async def test_a_remote_root_drains_over_a_connection_that_names_the_workspace(
    home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    del home
    _select_remote()
    recorder = _Recorder()
    monkeypatch.setattr(observe_hooks, "connect_service", recorder, raising=False)
    assert remote_root_selected() is True
    connect = observe_hooks._claim_bound_drain_connector("/home/me/repo")  # pyright: ignore[reportPrivateUsage]
    await connect(ControlClientKind.CLI)
    assert recorder.calls == [
        {"kind": ControlClientKind.CLI, "workspace_locator": WorkspaceLocator("/home/me/repo")}
    ]
    # Without a workspace nothing is sent there; the rows stay for the workspace agent.
    unbound = observe_hooks._claim_bound_drain_connector(None)  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(ControlError) as raised:
        await unbound(ControlClientKind.CLI)
    assert raised.value.reason == "service_unavailable"
    assert len(recorder.calls) == 1


def test_a_callers_connector_and_a_local_only_pass_are_kept() -> None:
    choose = observe_hooks._drain_connector  # pyright: ignore[reportPrivateUsage]
    recorder = _Recorder()
    assert choose(recorder, "/home/me/repo", skip_service=False) is recorder
    assert choose(None, "/home/me/repo", skip_service=True) is None
    assert callable(choose(None, "/home/me/repo", skip_service=False))


@pytest.mark.anyio
async def test_observe_drain_covers_one_named_workspace_on_a_remote_root(
    home: Path, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    del home
    recorder = _Recorder()
    drain_connector = cast(observe_module.DrainConnector, recorder)
    claim_bound = observe_module._claim_bound_drain  # pyright: ignore[reportPrivateUsage]
    # A local root: every pending workspace, connected as before.
    workspace, connect = claim_bound(None, drain_connector)
    assert workspace is None and connect is drain_connector
    _select_remote()
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.chdir(repo)
    workspace, connect = claim_bound(None, drain_connector)
    assert workspace == "."
    await connect(ControlClientKind.CLI)
    assert recorder.calls == [
        {"kind": ControlClientKind.CLI, "workspace_locator": WorkspaceLocator(str(repo.resolve()))}
    ]
