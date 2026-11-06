"""The CLI and the SessionStart auto-attach send a claim-bound connection's handle, never a path."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.cli import app as app_module
from finishup.cli import observe_hooks as observe_hooks_module
from finishup.cli.render import render_error_recovery_lines
from finishup.ports.control import ControlError
from finishup.protocol.errors import PublicErrorCode
from finishup.protocol.models import StartRequest

_HANDLE = "client:0123456789abcdef"
_PATH = "/home/dev/private-project"
_START = json.dumps(
    {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": "req_00000000-0000-4000-8000-000000000061",
        "actor": {"actor_id": "harness:cli", "actor_type": "harness"},
        "client": {"kind": "yoetz_cli", "version": "0.1.0", "integration": "local_cli"},
        "mode": "create_or_attach",
        "task_title": "Remote task",
        "requested_view": "compact",
        "workspace_ref": _PATH,
        "external_ref": "host-session:1",
    }
)


class _Client:
    def __init__(self, binding: str, handle: str | None) -> None:
        self.workspace_binding = binding
        self.workspace_handle = handle
        self.sent: list[StartRequest] = []
        self.closed = False

    async def start(self, request: StartRequest, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        self.sent.append(request)
        raise ControlError("invalid_request")

    async def close(self) -> None:
        self.closed = True


def _run_cli_start(monkeypatch: pytest.MonkeyPatch, client: _Client) -> int:
    async def build(*_args: object, **_kwargs: object) -> object:
        return client

    monkeypatch.setattr(app_module, "build_service_client", build)
    return asyncio.run(
        app_module._call_workflow("start", StartRequest, None, _START, True, None)  # pyright: ignore[reportPrivateUsage]
    )


def test_the_cli_sends_the_handle_on_a_claim_bound_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _Client("client_claim", _HANDLE)
    _run_cli_start(monkeypatch, client)
    (sent,) = client.sent
    assert sent.workspace_ref == _HANDLE


def test_the_cli_sends_a_local_start_as_written(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _Client("local_path", None)
    _run_cli_start(monkeypatch, client)
    (sent,) = client.sent
    assert sent.workspace_ref == _PATH


def test_the_cli_sends_nothing_without_a_handle(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _Client("client_claim", None)
    code = _run_cli_start(monkeypatch, client)
    captured = capsys.readouterr()
    assert client.sent == [] and client.closed
    assert code == app_module.exit_code_for(PublicErrorCode.INVALID_REQUEST)
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert lines[0].startswith("The selected FinishUP server is on another machine")
    assert lines[1:] == render_error_recovery_lines(
        {"reason_code": "workspace_ref_not_portable", "continuation": "workspace_handle_required"}
    )
    assert "private-project" not in captured.err


def _auto_start(tmp_path: Path, client: _Client) -> observe_hooks_module.AutoAttachOutcome:
    async def connect(_kind: object) -> object:
        return client

    return asyncio.run(
        observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            "claude:remote-1",
            _state=tmp_path,
            harness_id="claude",
            workspace_locator=_PATH,
            connect=cast(observe_hooks_module.HookStartConnector, connect),
        )
    )


def test_auto_attach_sends_the_handle_on_a_claim_bound_connection(tmp_path: Path) -> None:
    client = _Client("client_claim", _HANDLE)
    outcome = _auto_start(tmp_path, client)
    (sent,) = client.sent
    assert sent.workspace_ref == _HANDLE
    assert outcome.mapping is None  # the stand-in answered with a control error


def test_auto_attach_keeps_the_locator_on_a_local_connection(tmp_path: Path) -> None:
    client = _Client("local_path", None)
    _auto_start(tmp_path, client)
    (sent,) = client.sent
    assert sent.workspace_ref == _PATH


def test_auto_attach_sends_nothing_without_a_handle(tmp_path: Path) -> None:
    client = _Client("client_claim", None)
    outcome = _auto_start(tmp_path, client)
    assert client.sent == [] and client.closed
    assert outcome == observe_hooks_module.AutoAttachOutcome(None, "auto_attach_refused")


def test_a_stand_in_connection_without_binding_facts_is_unchanged(tmp_path: Path) -> None:
    sent: list[StartRequest] = []

    async def start(request: StartRequest, *, deadline_ms: int | None = None) -> object:
        del deadline_ms
        sent.append(request)
        raise ControlError("invalid_request")

    async def close() -> None:
        return None

    async def connect(_kind: object) -> object:
        return SimpleNamespace(start=start, close=close)

    asyncio.run(
        observe_hooks_module._try_auto_start(  # pyright: ignore[reportPrivateUsage]
            "claude:remote-2",
            _state=tmp_path,
            harness_id="claude",
            workspace_locator=_PATH,
            connect=cast(observe_hooks_module.HookStartConnector, connect),
        )
    )
    (request,) = sent
    assert request.workspace_ref == _PATH
