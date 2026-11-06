"""Observation drains claim their workspace on a server on another machine (ADR-051).

Found in the real-environment runs of all three approaches: a hook pass's own outbox drain, and
``finishup observe drain``, connected without a workspace. A server on another machine accepts a
row only attested over a connection that claims the row's workspace (decision 12), so an HTTPS
gateway refused ``observation_ingest`` (``method_forbidden``) and an SSH server quarantined the
rows as ``consent_missing``. On a remote root (or one whose record cannot be read) the drain now
names the workspace, which the connect seam turns into its claim; the path is never sent. Every
local root connects exactly as before.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from builders.server_targets import ambient_home
from finishup.adapters.workspace_binding import canonical_workspace_locator
from finishup.cli import observe, observe_hooks
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator

_drain_connector: Any = getattr(observe_hooks, "_drain_connector")
_claim_bound_drain: Any = getattr(observe, "_claim_bound_drain")
_PATH = "/srv/dev/private-project"


class _Recorder:
    """A connect seam that records how it was asked to connect."""

    def __init__(self) -> None:
        self.calls: list[tuple[ControlClientKind, dict[str, object]]] = []

    async def __call__(self, kind: ControlClientKind, **kwargs: object) -> object:
        self.calls.append((kind, kwargs))
        return object()


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        yield root


@pytest.fixture
def seam(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    """The hook module's service connector, replaced through its module-attribute override."""

    recorder = _Recorder()
    monkeypatch.setattr(observe_hooks, "connect_service", recorder, raising=False)
    return recorder


def _select_remote() -> Path:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", user="owner", host="lab.example", port=22
        )
    targets.write_selection(record)
    return root / "target.json"


def _select_local() -> None:
    with targets.registry_lock():
        record, _root = targets.new_local_target("work")
    targets.write_selection(record)


def _shared_mode(record: Path) -> None:
    record.chmod(0o644)


def _newer_release_field(record: Path) -> None:
    record.write_bytes(record.read_bytes().replace(b'{"', b'{"added_later":1,"', 1))


def test_the_predicate_names_remote_and_unreadable_roots_only(home: Path) -> None:
    assert targets.active_root_may_be_remote() is False  # the everyday installation
    _select_local()
    assert targets.active_root_may_be_remote() is False  # a named local server
    record = _select_remote()
    assert targets.active_root_may_be_remote() is True
    _shared_mode(record)
    reset_selection_memo()
    assert targets.active_root_may_be_remote() is True  # unreadable: it may be remote


def test_a_root_that_cannot_be_resolved_keeps_its_own_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unresolvable() -> None:
        raise targets.TargetError("target_root_unsafe")

    monkeypatch.setattr(targets, "active_target_record", unresolvable)
    assert targets.active_root_may_be_remote() is False


def test_an_injected_hook_drain_connector_is_used_as_given() -> None:
    injected = _Recorder()
    assert _drain_connector(injected, _PATH) is injected


@pytest.mark.parametrize("select", [lambda: None, _select_local], ids=["everyday", "named_local"])
def test_a_local_root_keeps_the_unbound_hook_drain(
    home: Path, seam: _Recorder, select: Callable[[], None]
) -> None:
    select()
    for locator in (_PATH, None):
        asyncio.run(_drain_connector(None, locator)(ControlClientKind.CLI))
    assert seam.calls == [(ControlClientKind.CLI, {}), (ControlClientKind.CLI, {})]


@pytest.mark.parametrize(
    "damage", [None, _shared_mode, _newer_release_field], ids=["remote", "shared", "newer"]
)
def test_a_remote_root_drains_over_a_connection_that_claims_the_workspace(
    home: Path, seam: _Recorder, damage: Callable[[Path], None] | None
) -> None:
    record = _select_remote()
    if damage is not None:
        damage(record)
        reset_selection_memo()
    asyncio.run(_drain_connector(None, _PATH)(ControlClientKind.CLI))
    # The seam turns the locator into a claim on a remote root and refuses an unreadable one;
    # an unbound connection, which would send unattested rows, is never opened.
    assert seam.calls == [(ControlClientKind.CLI, {"workspace_locator": WorkspaceLocator(_PATH)})]


def test_a_remote_hook_pass_without_a_workspace_sends_nothing(home: Path, seam: _Recorder) -> None:
    _select_remote()
    with pytest.raises(ControlError) as refused:
        asyncio.run(_drain_connector(None, None)(ControlClientKind.CLI))
    # A failed connect keeps the rows pending for the background drain, never quarantined.
    assert (refused.value.reason, refused.value.retryable) == ("service_unavailable", True)
    assert seam.calls == []


def test_a_local_observe_drain_is_unchanged(home: Path) -> None:
    connect = _Recorder()
    for workspace in (None, _PATH):
        assert _claim_bound_drain(workspace, connect) == (workspace, connect)


def test_a_remote_observe_drain_covers_one_workspace_over_its_claim(
    home: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _select_remote()
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    canonical = canonical_workspace_locator(str(project))
    assert canonical is not None
    for workspace, expected in ((None, "."), (str(project), str(project))):
        connect = _Recorder()
        covered, bound = _claim_bound_drain(workspace, connect)
        assert covered == expected
        asyncio.run(bound(ControlClientKind.CLI))
        assert connect.calls == [
            (ControlClientKind.CLI, {"workspace_locator": WorkspaceLocator(canonical)})
        ]


def test_the_observe_drain_decides_its_connection_before_it_connects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    seen: list[tuple[str | None, object]] = []
    connect = _Recorder()

    def spy(workspace: str | None, given: object) -> tuple[str | None, object]:
        seen.append((workspace, given))
        return workspace, given

    monkeypatch.setattr(observe, "_claim_bound_drain", spy)
    state = tmp_path / "state"
    state.mkdir(mode=0o700)
    drain: Any = getattr(observe, "_drain_observation_async")
    code, _summary = asyncio.run(drain(workspace=None, _state=state, connect=connect))
    assert code == 0
    assert seen == [(None, connect)]
