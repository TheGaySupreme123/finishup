"""Native Cursor workspace binding over the real daemon/control transport (#596)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import cast
from unittest.mock import patch

import pytest
from mcp import types
from pydantic import FileUrl

import finishup.cli.app as cli_app
import finishup.mcp.server as bridge
from finishup.cli import elevated
from finishup.protocol.canonical import JsonValue, canonical_encode
from finishup.protocol.models import StatusRequest
from finishup.service.elevated_bootstrap import load_pending
from integration.service.test_consent_vault_initialize_composition import (
    _approve_attestation,  # pyright: ignore[reportPrivateUsage]
    _approved_store,  # pyright: ignore[reportPrivateUsage]
    _MemoryKeyring,  # pyright: ignore[reportPrivateUsage]
    _production_daemon,  # pyright: ignore[reportPrivateUsage]
    runtime_directory,  # noqa: F401 - imported pytest fixture  # pyright: ignore[reportUnusedImport]
)


class _RootsSession:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.calls = 0

    async def list_roots(self) -> types.ListRootsResult:
        self.calls += 1
        return types.ListRootsResult(roots=[types.Root(uri=FileUrl(self.path.as_uri()))])


def _root_body(request_id: str, *, workspace: Path) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "actor": {"actor_id": "harness:cursor", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
        "mode": "create",
        "task_title": "Cursor native workspace binding",
        "requested_view": "compact",
        "external_ref": "cursor-workspace-596",
        "workspace_ref": str(workspace),
    }


def _status_body(request_id: str, start: dict[str, object]) -> dict[str, JsonValue]:
    return {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "request_id": request_id,
        "session_id": cast(str, start["session_id"]),
        "writer_id": cast(str, start["writer_id"]),
        "view": "compact",
        "limit": "10",
        "actor": {"actor_id": "harness:cursor", "actor_type": "harness"},
        "client": {
            "kind": "cooperative_agent",
            "version": "0.1.0",
            "integration": "cooperative_mcp",
        },
    }


def _error(result: object) -> dict[str, object]:
    structured = cast(dict[str, object], getattr(result, "structuredContent"))
    assert getattr(result, "isError") is True
    return cast(dict[str, object], structured["error"])


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.mark.anyio
async def test_cursor_root_binding_reaches_real_service_and_refuses_root_switch(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    runtime_directory: Path,  # noqa: F811 - imported pytest fixture
) -> None:
    """A home-CWD bridge sends the root-bound locator through hello and the repository fence."""

    monkeypatch.chdir(Path.home())
    tmp_path.chmod(0o700)
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    consent_state = tmp_path / "consent"
    consent_state.mkdir(mode=0o700)
    backend = _MemoryKeyring()
    store = _approved_store(tmp_path / "data", backend)

    daemon = await _production_daemon(tmp_path, pristine=True)
    await daemon.start()
    serving = asyncio.create_task(daemon.serve())
    runtime = bridge.build_bridge_runtime(host_profile="cursor")
    roots = _RootsSession(project)
    try:
        with (
            patch("finishup.service.elevated_bootstrap.state_dir", return_value=consent_state),
            patch("finishup.cli.elevated._auto_unlock_store", return_value=store),
        ):
            elevated.prepare_elevated("vault_initialize")
            pending = load_pending(_state=consent_state)
            assert pending is not None
            initialized = await asyncio.wait_for(
                elevated.authorize_elevated(_approve_attestation(pending)), timeout=30
            )
            assert initialized["outcome"] == "completed"

        start_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="start",
                # The public ref is deliberately the other directory. It remains the agent's
                # task-attachment selector, while the native Cursor roots response is the trusted
                # repository authority for this MCP session.
                arguments=_root_body("req_00000000-0000-4000-8000-000000000596", workspace=other),
            )
        )
        start_response = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
            start_request, runtime, session=roots
        )
        start_result = start_response.root
        assert isinstance(start_result, types.CallToolResult)
        assert start_result.isError is False
        start = cast(dict[str, object], start_result.structuredContent)
        assert start["ok"] is True
        assert roots.calls == 1

        status_request = types.CallToolRequest(
            params=types.CallToolRequestParams(
                name="status",
                arguments=_status_body("req_00000000-0000-4000-8000-000000000597", start),
            )
        )
        status_response = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
            status_request, runtime, session=roots
        )
        status_result = status_response.root
        assert isinstance(status_result, types.CallToolResult)
        assert status_result.isError is False
        status = cast(dict[str, object], status_result.structuredContent)
        assert status["ok"] is True
        assert status["task_id"] == start["task_id"]
        assert roots.calls == 2

        # The CLI's ordinary cwd binding confirms the service route is A-bound even though the
        # start request carried public workspace_ref B. B cannot use that session through status.
        status_input = canonical_encode(cast(JsonValue, status_request.params.arguments)).decode(
            "utf-8"
        )
        monkeypatch.chdir(project)
        matching_cli_exit = await cli_app._call_workflow(  # pyright: ignore[reportPrivateUsage]
            "status", StatusRequest, None, status_input, True, None
        )
        assert matching_cli_exit == 0
        monkeypatch.chdir(other)
        foreign_cli_exit = await cli_app._call_workflow(  # pyright: ignore[reportPrivateUsage]
            "status", StatusRequest, None, status_input, True, None
        )
        assert foreign_cli_exit != 0
        monkeypatch.chdir(Path.home())

        # Cursor 3.19.7 does not promise roots/list_changed. A changed root on the next workflow
        # call must retire the existing client before it can dispatch against the wrong route.
        roots.path = other
        switched_response = await bridge._handle_call_tool_request(  # pyright: ignore[reportPrivateUsage]
            status_request, runtime, session=roots
        )
        switched_result = switched_response.root
        assert isinstance(switched_result, types.CallToolResult)
        switched_error = _error(switched_result)
        assert switched_error["code"] == "SESSION_CONFLICT"
        assert cast(dict[str, object], switched_error["safe_details"])["reason_code"] == (
            "repository_identity_required"
        )
        rendered_error = json.dumps(switched_result.structuredContent)
        assert str(project) not in rendered_error
        assert str(other) not in rendered_error
        assert roots.calls == 3
    finally:
        await bridge.close_bridge_runtime(runtime)
        await daemon.stop()
        await asyncio.wait_for(serving, timeout=10)
