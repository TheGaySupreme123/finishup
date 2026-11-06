"""Which surfaces serve the workspace on a remote target (ADR-051, approach B: direct dial).

A process whose calls need the workspace while they run claims it and offers the workspace agent
on its own connection: the CLI (and the terminal interface, through the same connect helper) and
the MCP bridge. Everything else that names a workspace to a remote server is claim-bound without
an agent (``service.client``'s seam). For a local root every surface connects exactly as before,
with the locator.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path
from typing import Any, cast

import pytest

import finishup.mcp.server as bridge
from builders.server_targets import ambient_home
from finishup.cli import app as cli_app
from finishup.client import targets
from finishup.config.paths import reset_selection_memo
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.service.client import ClientWorkspaceBinding


@pytest.fixture
def remote(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    with ambient_home(monkeypatch):
        with targets.registry_lock():
            record, _root = targets.new_remote_target(
                "lab",
                "ssh",
                user="owner",
                host="lab.example",
                port=22,
                remote_root="/srv/fu",
                remote_launcher="/opt/fu/bin/finishup",
            )
            targets.write_selection(record)
        reset_selection_memo()
        yield


class _Recorded(Exception):
    pass


def _recorder(calls: list[dict[str, Any]]) -> Any:  # noqa: ANN401
    async def connect(kind: ControlClientKind, **kwargs: Any) -> object:  # noqa: ANN401
        calls.append({"kind": kind, **kwargs})
        raise _Recorded

    return connect


def test_the_cli_connection_serves_the_workspace_on_a_remote_root(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    del remote
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(cli_app, "connect_service", _recorder(calls))
    with pytest.raises(_Recorded):
        asyncio.run(cli_app.build_service_client(workspace_locator=WorkspaceLocator(str(tmp_path))))
    (call,) = calls
    assert "workspace_locator" not in call
    binding = call["workspace_binding"]
    assert type(binding) is ClientWorkspaceBinding and binding.agent is not None


def test_the_cli_connection_sends_its_locator_on_a_local_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls: list[dict[str, Any]] = []
    with ambient_home(monkeypatch):
        monkeypatch.setattr(cli_app, "connect_service", _recorder(calls))
        locator = WorkspaceLocator(str(tmp_path))
        with pytest.raises(_Recorded):
            asyncio.run(cli_app.build_service_client(workspace_locator=locator))
    (call,) = calls
    assert call["workspace_locator"] == locator
    assert "workspace_binding" not in call


def test_the_bridge_connection_serves_the_workspace_on_a_remote_root(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    del remote
    calls: list[dict[str, Any]] = []

    async def on_demand(kind: ControlClientKind, **kwargs: Any) -> object:  # noqa: ANN401
        calls.append({"kind": kind, **kwargs})
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")

    monkeypatch.setattr(bridge, "connect_service_on_demand", on_demand)
    monkeypatch.chdir(tmp_path)
    runtime = bridge.build_bridge_runtime()

    async def exercise() -> None:
        await bridge.dispatch_start(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000071",
                "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.1.0",
                    "integration": "cooperative_mcp",
                },
                "mode": "create",
                "task_title": "Remote task",
                "requested_view": "compact",
            },
            runtime,
        )

    asyncio.run(exercise())
    assert calls, "the bridge never dialled"
    call = calls[0]
    assert call["kind"] is ControlClientKind.MCP_BRIDGE
    assert "workspace_locator" not in call
    binding = call["workspace_binding"]
    assert type(binding) is ClientWorkspaceBinding and binding.agent is not None


def test_server_connect_agent_serves_the_named_remote_target(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from typer.testing import CliRunner

    from finishup.cli import server as server_cli
    from finishup.client import agent_session

    del remote
    served: list[tuple[Path, WorkspaceLocator]] = []

    async def serve(root: Path, locator: WorkspaceLocator) -> None:
        served.append((root, locator))

    def ready(_name: str | None, _action: str) -> str:
        return "lab (t_x)"

    monkeypatch.setattr(server_cli, "_runtime_call", ready)
    monkeypatch.setattr(agent_session, "run_foreground_agent", serve)
    monkeypatch.chdir(tmp_path)
    reset_selection_memo()
    result = CliRunner().invoke(cli_app.app, ["server", "connect", "lab", "--agent"])
    assert result.exit_code == 0, result.output
    ((root, locator),) = served
    record = targets.find_target("lab")
    assert root == targets.target_root(record.target_id)
    assert locator.path == str(tmp_path.resolve())
    assert "Ctrl-C" in result.stdout and "lab.example" not in result.output


def test_server_connect_agent_refuses_the_everyday_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from typer.testing import CliRunner

    with ambient_home(monkeypatch):
        reset_selection_memo()
        result = CliRunner().invoke(cli_app.app, ["server", "connect", "local", "--agent"])
    assert result.exit_code != 0
    assert "only a remote server target needs a workspace agent" in result.stderr


def test_each_bridge_service_call_renews_the_background_lease(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    del remote
    noted: list[WorkspaceLocator | None] = []

    class _Work:
        def note_activity(self, workspace: WorkspaceLocator | None) -> None:
            noted.append(workspace)

    async def on_demand(_kind: ControlClientKind, **_kwargs: Any) -> object:  # noqa: ANN401
        raise ControlError("service_unavailable", retryable=True, phase="remote_unreachable")

    monkeypatch.setattr(bridge, "connect_service_on_demand", on_demand)
    monkeypatch.chdir(tmp_path)
    runtime = bridge.build_bridge_runtime()
    runtime._slot.remote_background = _Work()  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage, reportAttributeAccessIssue]
    asyncio.run(
        bridge.dispatch_start(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": "req_00000000-0000-4000-8000-000000000072",
                "actor": {"actor_id": "harness:mcp", "actor_type": "harness"},
                "client": {
                    "kind": "cooperative_agent",
                    "version": "0.1.0",
                    "integration": "cooperative_mcp",
                },
                "mode": "create",
                "task_title": "Remote task",
                "requested_view": "compact",
            },
            runtime,
        )
    )
    assert noted and noted[0] == WorkspaceLocator(str(tmp_path.resolve()))


def _recording_connect(calls: list[dict[str, Any]]) -> Any:  # noqa: ANN401
    async def connect(kind: ControlClientKind, **kwargs: Any) -> object:  # noqa: ANN401
        calls.append({"kind": kind, **kwargs})
        return object()

    return connect


def test_hook_drains_claim_the_hooks_workspace_on_a_remote_root(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.cli import observe_hooks

    del remote
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(observe_hooks, "connect_service", _recording_connect(calls), raising=False)
    connector = observe_hooks._drain_connector(None, str(tmp_path))  # pyright: ignore[reportPrivateUsage]
    assert connector is not None
    asyncio.run(connector(ControlClientKind.CLI))  # type: ignore[arg-type]
    assert calls == [
        {"kind": ControlClientKind.CLI, "workspace_locator": WorkspaceLocator(str(tmp_path))}
    ]


def test_hook_drains_connect_as_before_on_a_local_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.cli import observe_hooks

    calls: list[dict[str, Any]] = []
    with ambient_home(monkeypatch):
        monkeypatch.setattr(
            observe_hooks, "connect_service", _recording_connect(calls), raising=False
        )
        connector = observe_hooks._drain_connector(None, str(tmp_path))  # pyright: ignore[reportPrivateUsage]
        assert connector is not None
        asyncio.run(connector(ControlClientKind.CLI))  # type: ignore[arg-type]
        # An injected connector is used exactly as given.
        injected = _recording_connect(calls)
        assert observe_hooks._drain_connector(injected, str(tmp_path)) is injected  # pyright: ignore[reportPrivateUsage]
    assert calls == [{"kind": ControlClientKind.CLI}]


def test_observe_drain_claims_this_folder_on_a_remote_root(
    remote: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.cli import observe

    del remote
    calls: list[dict[str, Any]] = []
    workspace, connect = observe._claim_bound_drain(str(tmp_path), _recording_connect(calls))  # pyright: ignore[reportPrivateUsage]
    assert workspace == str(tmp_path.resolve())
    asyncio.run(cast(Any, connect(ControlClientKind.CLI)))
    assert calls == [
        {
            "kind": ControlClientKind.CLI,
            "workspace_locator": WorkspaceLocator(str(tmp_path.resolve())),
        }
    ]
