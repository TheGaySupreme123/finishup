"""Approach A (edge relay): nothing reaches a remote target while this computer is zero-network.

ADR-051 decision 8, maintainer decision of 2026-11-07: this computer's zero-network policy and a
server on another machine, a port or the web are never in force together. The last line of
defence is the connection check every hop decision calls (``targets.require_current_authorization``,
reading what this computer last reported). Here it is driven through approach A's own seams: both
connect paths of ``service.client``, the connector's background workspace agent, the connector
runtime's probe behind ``server status`` and ``server test``, and the CLI and MCP renderings. A
process whose selection predates the change (its memo still names the remote root) sends nothing,
starts no connector, records no claim, and every surface says why and ``finishup server use
local``.
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

import finishup.client.everyday_policy as everyday_policy
from builders.server_targets import ambient_home
from finishup.client import targets
from finishup.config.paths import active_root, reset_selection_memo, selection_override
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.protocol.canonical import JsonValue
from finishup.service import client as service_client

_AT = datetime(2026, 11, 7, 9, 30, tzinfo=UTC)
_PHASE = "zero_network_remote_selected"


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    with ambient_home(monkeypatch) as root:
        monkeypatch.setattr(
            everyday_policy,
            "_location",
            everyday_policy._ambient_marker_path,  # pyright: ignore[reportPrivateUsage]
        )
        yield root


@pytest.fixture
def remote(home: Path) -> Path:
    with targets.registry_lock():
        record, root = targets.new_remote_target(
            "lab", "ssh", host="lab.example", port=22, remote_launcher="/opt/fu/bin/finishup"
        )
        targets.write_selection(record)
    reset_selection_memo()
    assert active_root() == root
    return root


@pytest.fixture
def nothing_dialled(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    started: list[str] = []

    def spawn(_root: Path) -> None:
        started.append("connector")

    def refuse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("a remote root never starts or supersedes a local service")

    async def dial() -> object:
        started.append("dial")
        raise OSError("never dialled")

    monkeypatch.setattr("finishup.client.connector_status.spawn_connector", spawn)
    monkeypatch.setattr(service_client, "connect_control", dial)
    monkeypatch.setattr(service_client, "_spawn_service_process", refuse)
    monkeypatch.setattr(service_client, "supersede_incompatible_service", refuse)
    return started


@pytest.mark.parametrize("with_workspace", [True, False])
def test_a_process_whose_selection_predates_zero_network_sends_nothing(
    remote: Path, nothing_dialled: list[str], with_workspace: bool
) -> None:
    # This process resolved the remote root; then this computer was made zero-network and the
    # owner switched in another terminal, which reset only its own memo.
    everyday_policy.record_reported_policy(zero_network=True, now=_AT)
    with targets.registry_lock():
        path = targets.selection_path()
        path.unlink()
    assert active_root() == remote
    locator = WorkspaceLocator(path=str(remote.parent / "repo")) if with_workspace else None

    async def exercise() -> None:
        for connect in (service_client.connect_service, service_client.connect_service_on_demand):
            with pytest.raises(ControlError) as refused:
                await connect(ControlClientKind.CLI, workspace_locator=locator)
            error = refused.value
            assert (error.reason, error.phase, error.retryable) == (
                "service_unavailable",
                _PHASE,
                True,
            )

    asyncio.run(exercise())
    assert nothing_dialled == []
    assert not (remote / "state" / "claimed-workspaces").exists()


def test_a_report_that_permits_network_lets_the_connection_proceed(
    remote: Path, nothing_dialled: list[str]
) -> None:
    everyday_policy.record_reported_policy(zero_network=False, now=_AT)

    async def exercise() -> None:
        # The stand-in endpoint fails the dial itself: reaching it is the point.
        with pytest.raises(OSError, match="never dialled"):
            await service_client.connect_service(ControlClientKind.CLI)

    asyncio.run(exercise())
    # It dialled: the zero-network refusal did not apply.
    assert "dial" in nothing_dialled


def test_the_connector_opens_no_background_agent_while_zero_network(remote: Path) -> None:
    from finishup.client.claimed_workspaces import record_claimed_workspace
    from finishup.client.connector_agent import open_connector_agent
    from finishup.client.remote_binding import binding_for_active_root

    workspace_dir = (remote.parent / "repo").resolve()
    workspace_dir.mkdir()
    workspace = WorkspaceLocator(str(workspace_dir))

    async def claim() -> object:
        with selection_override(remote):
            return await binding_for_active_root(workspace, serve_workspace=False)

    claimed = asyncio.run(claim())
    assert claimed is not None
    assert record_claimed_workspace(remote, claimed.claim, workspace) is True  # type: ignore[attr-defined]
    everyday_policy.record_reported_policy(zero_network=True, now=_AT)

    async def dial() -> object:
        raise AssertionError("never dialled")

    async def open_agent() -> object:
        with selection_override(remote):
            return await open_connector_agent(remote, claimed.claim, dial)  # type: ignore[attr-defined, arg-type]

    assert asyncio.run(open_agent()) is None


def test_server_status_and_test_probe_send_nothing_and_name_the_refusal(
    remote: Path, nothing_dialled: list[str]
) -> None:
    from finishup.client.connector_runtime import ConnectorTargetRuntime

    everyday_policy.record_reported_policy(zero_network=True, now=_AT)

    result = ConnectorTargetRuntime().probe(remote)

    assert (result.outcome, result.reason) == ("unavailable", _PHASE)
    assert nothing_dialled == []


def test_server_connect_is_refused_with_the_remedy(
    remote: Path, nothing_dialled: list[str]
) -> None:
    from typer.testing import CliRunner

    from finishup.cli import app as cli

    everyday_policy.record_reported_policy(zero_network=True, now=_AT)
    reset_selection_memo()

    result = CliRunner().invoke(cli.app, ["server", "connect", "lab"])

    assert result.exit_code == 2, result.output
    assert result.stderr.startswith(f"{_PHASE}: ")
    assert "'finishup server use local'" in result.stderr
    assert nothing_dialled == []


def test_cli_mcp_hooks_and_terminal_say_why_and_the_one_remedy(remote: Path) -> None:
    from finishup.cli.bootstrap import control_failure
    from finishup.cli.hooks import unavailable_context
    from finishup.mcp import server as bridge
    from finishup.protocol.recovery import RECOVERY_DIRECTIVES
    from finishup.tui.runtime import _connect_failure  # pyright: ignore[reportPrivateUsage]

    error = ControlError("service_unavailable", retryable=True, phase=_PHASE)
    directive = RECOVERY_DIRECTIVES["zero_network_local_server_required"]

    lines: list[str] = []
    documents: list[JsonValue] = []
    control_failure(
        error, json_output=True, stderr_writer=lines.append, stdout_writer=documents.append
    )
    text = "\n".join(lines)
    assert text.splitlines()[0] == (
        f"service_unavailable: {_PHASE}: this computer's FinishUP is set to make no network "
        "connections, so nothing was sent to the selected FinishUP server"
    )
    assert directive.directive in text
    assert "'finishup server use local'" in text
    (document,) = documents
    assert cast(dict[str, JsonValue], document)["phase"] == _PHASE

    result = bridge._control_error_result(  # pyright: ignore[reportPrivateUsage]
        error, request_id=None, operation="start"
    )
    public = cast(dict[str, object], cast(dict[str, object], result.structuredContent)["error"])
    assert public["message"] == directive.directive
    details = cast(dict[str, object], public["safe_details"])
    assert details["reason_code"] == _PHASE
    assert details["continuation"] == "zero_network_local_server_required"

    context = unavailable_context(_PHASE)
    assert f"({_PHASE})" in context
    assert context.endswith(" Continuation: zero_network_local_server_required.")

    failure = _connect_failure(error)
    assert failure.reason == _PHASE
    assert failure.message == (
        "this computer's FinishUP is set to make no network connections, so nothing was sent "
        "to the selected FinishUP server"
    )
    assert failure.details == (directive.directive,)
    for shown in (text, cast(str, public["message"]), context, failure.message):
        assert "lab.example" not in shown and " lab " not in f" {shown} "
