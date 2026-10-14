"""Cursor MCP root binding accepts the observed wire shape and stays fail closed."""

# pyright: reportPrivateUsage=false

from __future__ import annotations

import json
from pathlib import Path

import pytest
from mcp import types

import finishup.mcp.server as server
from finishup.ports.control import WorkspaceLocator

_LAUNCHER = ("/opt/finishup/bin/finishup",)


def _directory(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    path.chmod(0o700)
    return path


def _raw_roots(*paths: Path) -> dict[str, object]:
    return {
        "roots": [{"uri": str(path), "name": f"root-{index}"} for index, path in enumerate(paths)]
    }


def _write_project_registration(
    project: Path,
    *,
    launcher: tuple[str, ...] = _LAUNCHER,
    isolation_root: Path | None = None,
) -> Path:
    config = _directory(project / ".cursor") / "mcp.json"
    entry: dict[str, object] = {
        "type": "stdio",
        "command": launcher[0],
        "args": [
            *launcher[1:],
            "mcp",
            "serve",
            "--host",
            "cursor",
            "--project-root",
            "${workspaceFolder}",
        ],
    }
    if isolation_root is not None:
        entry["env"] = {"FINISHUP_ISOLATED_ROOT": str(isolation_root)}
    config.write_text(json.dumps({"mcpServers": {"finishup": entry}}) + "\n", encoding="utf-8")
    config.chmod(0o600)
    return config


def test_cursor_accepts_raw_absolute_posix_roots_and_typed_file_uri(tmp_path: Path) -> None:
    project = _directory(tmp_path / "project")
    raw = server._cursor_workspace_binding(_raw_roots(project))
    assert raw == (WorkspaceLocator(str(project)), str(project))

    typed_root = types.Root.model_validate({"uri": f"file://{project}", "name": "project"})
    typed = types.ListRootsResult(roots=[typed_root])
    assert server._cursor_workspace_locator(typed) == WorkspaceLocator(str(project))


def test_selector_only_disambiguates_roots_that_cursor_already_reported(tmp_path: Path) -> None:
    project = _directory(tmp_path / "project")
    other = _directory(tmp_path / "other")
    result = _raw_roots(project, other)

    assert server._cursor_workspace_binding(result) is None
    assert server._cursor_workspace_binding(result, str(project)) == (
        WorkspaceLocator(str(project)),
        str(project),
    )
    assert server._cursor_workspace_binding(result, str(tmp_path / "missing")) is None


def test_selector_and_project_root_may_be_a_safe_git_subdirectory(tmp_path: Path) -> None:
    repository = _directory(tmp_path / "repository")
    _directory(repository / ".git")
    project = _directory(repository / "workspace")

    binding = server._cursor_workspace_binding(
        _raw_roots(project),
        str(repository),
    )
    assert binding == (WorkspaceLocator(str(repository)), str(repository))
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    assert runtime.cursor_project_root == str(repository)


@pytest.mark.parametrize(
    "uri",
    [
        "relative/project",
        "//remote/project",
        "file://remote/project",
        "/absolute/project?query",
        "/absolute/project#fragment",
        "/absolute/project\nwith-control",
        "/" + ("x" * (server._MAX_CURSOR_ROOT_URI_BYTES + 1)),
    ],
)
def test_cursor_rejects_unsafe_root_uri_forms(uri: str) -> None:
    assert server._cursor_root_path({"uri": uri}) is None
    assert server._cursor_workspace_binding({"roots": [{"uri": uri}]}) is None


@pytest.mark.anyio
async def test_cursor_uses_raw_result_model_for_the_production_roots_request(
    tmp_path: Path,
) -> None:
    project = _directory(tmp_path / "project")
    calls: list[tuple[object, object]] = []

    class Session:
        async def send_request(self, request: object, result_type: object) -> object:
            calls.append((request, result_type))
            return _raw_roots(project)

        async def list_roots(self) -> types.ListRootsResult:
            raise AssertionError("raw Cursor roots must not go through FileUrl validation")

    result = await server._cursor_list_roots(Session())
    assert result == _raw_roots(project)
    assert len(calls) == 1
    request, result_type = calls[0]
    assert isinstance(request, types.ServerRequest)
    assert isinstance(request.root, types.ListRootsRequest)
    assert result_type is server._RawListRootsResult


def test_cursor_project_selector_is_validated_at_runtime_construction(tmp_path: Path) -> None:
    project = _directory(tmp_path / "project")
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    assert runtime.cursor_project_root == str(project)

    with pytest.raises(ValueError, match="mcp_project_root_host_invalid"):
        server.build_bridge_runtime(host_profile="generic", project_root=project)
    with pytest.raises(ValueError, match="mcp_project_root_invalid"):
        server.build_bridge_runtime(host_profile="cursor", project_root=tmp_path / "missing")
    with pytest.raises(ValueError, match="mcp_project_launcher_invalid"):
        server.build_bridge_runtime(host_profile="cursor", project_root=project)


def test_runtime_recovers_exact_console_or_module_launcher_prefix(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import sys

    monkeypatch.setattr(
        server.sys,
        "argv",
        [sys.executable, "--entrypoint", "mcp", "serve", "--host", "cursor"],
    )
    executable = str(Path(sys.executable).resolve(strict=True))
    assert server._runtime_launcher_from_argv() == (executable, "--entrypoint")

    package_main = Path(server.__file__).resolve().parents[1] / "__main__.py"
    monkeypatch.setattr(
        server.sys,
        "argv",
        [str(package_main), "--entrypoint", "mcp", "serve", "--host", "cursor"],
    )
    assert server._runtime_launcher_from_argv() == (
        executable,
        "-m",
        "finishup",
        "--entrypoint",
    )


def test_symlinked_console_launcher_is_normalized_like_the_project_writer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from finishup.adapters.integrations.launcher import resolve_finishup_launcher

    real = tmp_path / "finishup"
    real.write_text("#!/bin/sh\n", encoding="utf-8")
    real.chmod(0o700)
    linked = tmp_path / "cursor-finishup"
    linked.symlink_to(real)
    monkeypatch.setattr(
        server.sys,
        "argv",
        [str(linked), "mcp", "serve", "--host", "cursor"],
    )

    expected = (str(real),)
    assert server._runtime_launcher_from_argv() == expected
    assert resolve_finishup_launcher(linked) == expected


@pytest.mark.anyio
async def test_project_registration_binds_the_exact_isolation_root(
    tmp_path: Path,
) -> None:
    project = _directory(tmp_path / "project")
    configured_root = _directory(tmp_path / "configured-root")
    wrong_root = _directory(tmp_path / "wrong-root")
    _write_project_registration(project, isolation_root=configured_root)

    runtime = server.build_bridge_runtime(
        host_profile="cursor",
        project_root=project,
        launcher=_LAUNCHER,
        isolation_root=str(configured_root),
    )
    session = _ProjectRootsSession(project)
    assert await server._ensure_cursor_workspace_binding(runtime, session, None, "start") is None

    wrong_runtime = server.build_bridge_runtime(
        host_profile="cursor",
        project_root=project,
        launcher=_LAUNCHER,
        isolation_root=str(wrong_root),
    )
    error = await server._ensure_cursor_workspace_binding(
        wrong_runtime, _ProjectRootsSession(project), None, "start"
    )
    assert error is not None
    assert wrong_runtime._slot.workspace_binding_state == "failed"


@pytest.mark.anyio
async def test_cursor_revalidates_selected_directory_identity_but_ignores_other_root_changes(
    tmp_path: Path,
) -> None:
    project = _directory(tmp_path / "project")
    other = _directory(tmp_path / "other")
    _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )

    class Session:
        roots = _raw_roots(project, other)

        async def send_request(self, _request: object, _result_type: object) -> object:
            return self.roots

        async def list_roots(self) -> types.ListRootsResult:
            raise AssertionError("the raw Cursor request path should be used")

    session = Session()
    assert await server._ensure_cursor_workspace_binding(runtime, session, None, "start") is None
    assert runtime._slot.workspace_locator == WorkspaceLocator(str(project))

    replacement = _directory(tmp_path / "replacement")
    session.roots = _raw_roots(project, replacement)
    assert await server._ensure_cursor_workspace_binding(runtime, session, None, "status") is None

    (project / ".cursor" / "mcp.json").unlink()
    (project / ".cursor").rmdir()
    project.rmdir()
    project.mkdir(mode=0o700)
    session.roots = _raw_roots(project, replacement)
    error = await server._ensure_cursor_workspace_binding(runtime, session, None, "check")
    assert error is not None
    assert runtime._slot.workspace_binding_state == "failed"
    assert runtime._slot.workspace_locator is None
    assert error.content and isinstance(error.content[0], types.TextContent)
    assert "registered project or selected repository changed" in error.content[0].text
    assert str(project) not in error.content[0].text


@pytest.mark.anyio
async def test_cursor_selector_mismatch_uses_bounded_operator_wording(tmp_path: Path) -> None:
    project = _directory(tmp_path / "project")
    other = _directory(tmp_path / "other")
    _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )

    class Session:
        async def send_request(self, _request: object, _result_type: object) -> object:
            return _raw_roots(other)

        async def list_roots(self) -> types.ListRootsResult:
            raise AssertionError("the raw Cursor request path should be used")

    error = await server._ensure_cursor_workspace_binding(runtime, Session(), None, "start")
    assert error is not None
    assert error.content and isinstance(error.content[0], types.TextContent)
    assert "matching the registered project selector" in error.content[0].text
    assert str(project) not in error.content[0].text


def _status_request() -> types.CallToolRequest:
    return types.CallToolRequest(params=types.CallToolRequestParams(name="status", arguments={}))


class _ProjectRootsSession:
    def __init__(self, project: Path) -> None:
        self.project = project
        self.calls = 0

    async def send_request(self, _request: object, _result_type: object) -> object:
        self.calls += 1
        return _raw_roots(self.project)

    async def list_roots(self) -> types.ListRootsResult:
        raise AssertionError("the raw Cursor request path should be used")


@pytest.mark.anyio
@pytest.mark.parametrize("mode", ["missing", "foreign", "mismatched"])
async def test_project_registration_must_be_exact_before_roots_or_service(
    tmp_path: Path, mode: str
) -> None:
    project = _directory(tmp_path / "project")
    if mode != "missing":
        config = _write_project_registration(project)
        document = json.loads(config.read_text(encoding="utf-8"))
        entry = document["mcpServers"]["finishup"]
        if mode == "foreign":
            entry["command"] = "/foreign/finishup"
        else:
            entry["args"].append("--semantic")
            entry["args"].append("off")
        config.write_text(json.dumps(document) + "\n", encoding="utf-8")
        config.chmod(0o600)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    session = _ProjectRootsSession(project)

    error = await server._ensure_cursor_workspace_binding(runtime, session, None, "start")
    assert error is not None
    assert error.content and isinstance(error.content[0], types.TextContent)
    assert "project MCP registration is missing or does not match" in error.content[0].text
    assert session.calls == 0
    assert runtime._slot.workspace_binding_state == "failed"


@pytest.mark.anyio
async def test_project_registration_edit_retires_binding_before_second_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    dispatches: list[str] = []

    async def fake_call_tool(
        name: str, _arguments: dict[str, object], _runtime: server.BridgeRuntime
    ) -> types.CallToolResult:
        dispatches.append(name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            structuredContent={"ok": True},
            isError=False,
        )

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    session = _ProjectRootsSession(project)
    request = _status_request()
    first = await server._handle_call_tool_request(request, runtime, session=session)
    assert isinstance(first.root, types.CallToolResult)
    assert first.root.isError is False
    assert dispatches == ["status"]

    config.write_text(
        config.read_text(encoding="utf-8").replace(_LAUNCHER[0], "/other/finishup"),
        encoding="utf-8",
    )
    config.chmod(0o600)
    second = await server._handle_call_tool_request(request, runtime, session=session)
    assert isinstance(second.root, types.CallToolResult)
    assert second.root.isError is True
    assert dispatches == ["status"]
    assert session.calls == 1
    assert runtime._slot.workspace_binding_state == "failed"


@pytest.mark.anyio
async def test_same_bytes_atomic_registration_replacement_skips_second_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    dispatches: list[str] = []

    async def fake_call_tool(
        name: str, _arguments: dict[str, object], _runtime: server.BridgeRuntime
    ) -> types.CallToolResult:
        dispatches.append(name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            structuredContent={"ok": True},
            isError=False,
        )

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    session = _ProjectRootsSession(project)
    request = _status_request()
    first = await server._handle_call_tool_request(request, runtime, session=session)
    assert isinstance(first.root, types.CallToolResult)
    assert first.root.isError is False
    assert dispatches == ["status"]

    original = config.read_bytes()
    config.unlink()
    config.write_bytes(original)
    config.chmod(0o600)
    second = await server._handle_call_tool_request(request, runtime, session=session)
    assert isinstance(second.root, types.CallToolResult)
    assert second.root.isError is True
    assert dispatches == ["status"]
    assert session.calls == 1
    assert runtime._slot.workspace_binding_state == "failed"


@pytest.mark.anyio
async def test_registration_is_rechecked_after_roots_exchange_before_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    dispatches: list[str] = []

    async def fake_call_tool(
        name: str, _arguments: dict[str, object], _runtime: server.BridgeRuntime
    ) -> types.CallToolResult:
        dispatches.append(name)
        return types.CallToolResult(
            content=[types.TextContent(type="text", text="ok")],
            structuredContent={"ok": True},
            isError=False,
        )

    class InterleavingSession(_ProjectRootsSession):
        async def send_request(self, _request: object, _result_type: object) -> object:
            self.calls += 1
            original = config.read_bytes()
            config.unlink()
            config.write_bytes(original)
            config.chmod(0o600)
            return _raw_roots(project)

    monkeypatch.setattr(server, "call_tool", fake_call_tool)
    session = InterleavingSession(project)
    response = await server._handle_call_tool_request(_status_request(), runtime, session=session)
    assert isinstance(response.root, types.CallToolResult)
    assert response.root.isError is True
    assert dispatches == []
    assert session.calls == 1
    assert runtime._slot.workspace_binding_state == "failed"


@pytest.mark.anyio
async def test_project_registration_removal_retires_an_existing_binding(
    tmp_path: Path,
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_project_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    session = _ProjectRootsSession(project)
    assert await server._ensure_cursor_workspace_binding(runtime, session, None, "start") is None

    config.unlink()
    error = await server._ensure_cursor_workspace_binding(runtime, session, None, "status")
    assert error is not None
    assert session.calls == 1
    assert runtime._slot.workspace_binding_state == "failed"


def _write_cli_registration(project: Path) -> Path:
    config = _write_project_registration(project)
    document = json.loads(config.read_text())
    entry = document["mcpServers"]["finishup"]
    entry["args"][-1] = str(project)
    entry["args"].extend(["--project-binding", "registered-project"])
    config.write_text(json.dumps(document))
    return config


@pytest.mark.anyio
async def test_explicit_cli_binding_uses_only_approved_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _directory(tmp_path / "project")
    unrelated = _directory(tmp_path / "unrelated")
    _write_cli_registration(project)
    monkeypatch.chdir(unrelated)
    runtime = server.build_bridge_runtime(
        host_profile="cursor",
        project_root=project,
        launcher=_LAUNCHER,
        project_binding="registered-project",
    )
    # The Agent CLI has no roots capability. CWD and client claims cannot select a root.
    assert await server._ensure_cursor_workspace_binding(runtime, None, None, "start") is None
    assert runtime._slot.workspace_locator == WorkspaceLocator(str(project))
    assert runtime._slot.workspace_binding_source == "registered_project"
    desktop = server.build_bridge_runtime(
        host_profile="cursor", project_root=project, launcher=_LAUNCHER
    )
    assert await server._ensure_cursor_workspace_binding(desktop, None, None, "start") is not None


@pytest.mark.anyio
@pytest.mark.parametrize(
    "mutation",
    ["missing", "foreign_launcher", "mode_removed", "root_mismatch", "symlink", "replacement"],
)
async def test_cli_binding_retires_on_registration_or_directory_changes(
    tmp_path: Path, mutation: str
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_cli_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor",
        project_root=project,
        launcher=_LAUNCHER,
        project_binding="registered-project",
    )
    assert await server._ensure_cursor_workspace_binding(runtime, None, None, "start") is None
    document = json.loads(config.read_text())
    if mutation == "missing":
        config.unlink()
    elif mutation == "foreign_launcher":
        document["mcpServers"]["finishup"]["command"] = "/foreign/finishup"
        config.write_text(json.dumps(document))
    elif mutation == "mode_removed":
        document["mcpServers"]["finishup"]["args"] = document["mcpServers"]["finishup"]["args"][:-2]
        config.write_text(json.dumps(document))
    elif mutation == "root_mismatch":
        document["mcpServers"]["finishup"]["args"][-3] = str(tmp_path)
        config.write_text(json.dumps(document))
    elif mutation == "symlink":
        moved = tmp_path / "moved"
        project.rename(moved)
        project.symlink_to(moved, target_is_directory=True)
    else:
        new_file = config.with_suffix(".new")
        new_file.write_bytes(config.read_bytes())
        new_file.replace(config)
    error = await server._ensure_cursor_workspace_binding(runtime, None, None, "check")
    assert error is not None
    assert runtime._slot.workspace_binding_state == "failed"
    assert runtime._slot.workspace_locator is None


@pytest.mark.parametrize(
    "host,project", [("generic", True), ("codex", True), ("claude", True), ("cursor", False)]
)
def test_cli_binding_requires_an_explicit_cursor_project(
    tmp_path: Path, host: str, project: bool
) -> None:
    from typing import cast

    from finishup.ports.control import McpHostProfile

    root = _directory(tmp_path / "project")
    with pytest.raises(ValueError, match="mcp_project_binding_invalid"):
        server.build_bridge_runtime(
            host_profile=cast(McpHostProfile, host),
            project_root=root if project else None,
            launcher=_LAUNCHER,
            project_binding="registered-project",
        )


@pytest.mark.anyio
async def test_cli_registration_is_rechecked_before_binding(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = _directory(tmp_path / "project")
    config = _write_cli_registration(project)
    runtime = server.build_bridge_runtime(
        host_profile="cursor",
        project_root=project,
        launcher=_LAUNCHER,
        project_binding="registered-project",
    )
    identity = server._cursor_workspace_identity

    def replace_registration(path: str) -> tuple[int, int] | None:
        result = identity(path)
        config.write_text('{"mcpServers":{}}')
        return result

    monkeypatch.setattr(server, "_cursor_workspace_identity", replace_registration)
    error = await server._ensure_cursor_workspace_binding(runtime, None, None, "start")
    assert error is not None
    assert runtime._slot.workspace_locator is None
    assert runtime._slot.workspace_binding_state == "failed"
