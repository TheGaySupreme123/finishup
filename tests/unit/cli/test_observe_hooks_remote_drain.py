"""A hook's own outbox drain claims its workspace on a server on another machine (ADR-051).

Found in the real-environment run of approach A: the drain connected unbound, so an HTTPS
gateway refused ``observation_ingest`` (``method_forbidden``) and an SSH server, which keeps no
observation consent for a client's workspace, quarantined the rows as ``consent_missing``. On a
remote root the drain connection now carries the workspace claim (never the path); a local root
keeps today's unbound connection.
"""

from __future__ import annotations

import asyncio

import pytest

import finishup.client.targets as targets
from finishup.cli import observe_hooks
from finishup.ports.control import ControlClientKind, WorkspaceLocator

_drain_connector = getattr(observe_hooks, "_drain_connector")
_PATH = "/home/dev/private-project"


class _Recorder:
    def __init__(self) -> None:
        self.calls: list[tuple[ControlClientKind, dict[str, object]]] = []

    async def __call__(self, kind: ControlClientKind, **kwargs: object) -> object:
        self.calls.append((kind, kwargs))
        return object()


def test_an_injected_connector_is_used_as_given() -> None:
    injected = _Recorder()
    assert _drain_connector(injected, _PATH) is injected


def test_a_local_root_keeps_the_unbound_drain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(targets, "active_target_is_remote", lambda: False)
    assert _drain_connector(None, _PATH) is None
    assert _drain_connector(None, None) is None


def test_a_pass_without_a_workspace_keeps_the_unbound_drain(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(targets, "active_target_is_remote", lambda: True)
    assert _drain_connector(None, None) is None


def test_a_remote_root_drains_over_a_connection_that_claims_the_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(targets, "active_target_is_remote", lambda: True)
    recorder = _Recorder()
    monkeypatch.setattr(observe_hooks, "connect_service", recorder, raising=False)
    connect = _drain_connector(None, _PATH)
    assert connect is not None
    asyncio.run(connect(ControlClientKind.CLI))
    ((kind, kwargs),) = recorder.calls
    assert kind is ControlClientKind.CLI
    # The seam turns the locator into a claim for a remote root; the path never leaves here.
    assert kwargs == {"workspace_locator": WorkspaceLocator(_PATH)}
