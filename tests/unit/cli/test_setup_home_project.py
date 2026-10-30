"""Explicit home-project opt-in, native propagation, and the disconnect reverse path (#1154)."""

from __future__ import annotations

import json
import shlex
from pathlib import Path
from typing import Any, Literal

import anyio
import pytest
from typer.testing import CliRunner

from finishup.adapters.integrations import codex_mcp, codex_plugin
from finishup.adapters.integrations.claude_code_integration import render_claude_code_plugin
from finishup.adapters.integrations.cursor_integration import render_cursor_plugin
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.adapters.integrations.launcher import resolve_finishup_launcher
from finishup.adapters.integrations.legacy_launchers import launcher_aliases, recorded_launcher
from finishup.adapters.workspace_binding import (
    canonical_workspace_locator,
    resolve_workspace_locator,
)
from finishup.application.host_connection import ConnectionPlan, apply_connection
from finishup.cli import host_connection
from finishup.cli.app import app
from finishup.config.home_project import home_project_scope
from finishup.ports.harness_mcp import MCP_SERVE_COMMAND, mcp_command_profile
from finishup.ports.plugin_artifacts import ArtifactAuthority, McpOwnership, PluginFormatProfile
from finishup.protocol.host_connection import HostConnectionBatchReport, HostConnectionReport


@pytest.fixture
def home(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    result = tmp_path / "home with spaces"
    result.mkdir(mode=0o700)
    monkeypatch.setenv("HOME", str(result))
    monkeypatch.chdir(result)
    return result


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-ide", "cursor-cli", "all"])
@pytest.mark.parametrize("allow", [False, True])
def test_unattended_setup_requires_the_explicit_flag(
    monkeypatch: pytest.MonkeyPatch, home: Path, host: str, allow: bool
) -> None:
    seen: list[Path] = []

    def connect(**kwargs: Any) -> int:
        seen.append(kwargs["project"])
        assert canonical_workspace_locator(home) == str(home)
        return 0

    async def batch(**kwargs: Any) -> int:
        return connect(**kwargs)

    monkeypatch.setattr(host_connection, "run_host_connection", connect)
    monkeypatch.setattr("finishup.cli.host_batch.run_host_batch", batch)
    arguments = [
        "setup",
        "run",
        "--host",
        host,
        "--project",
        str(home),
        "--non-interactive",
        "--json",
        "--accept",
    ]
    if allow:
        arguments.append("--allow-home-project")
    # Even a native launcher's inherited permission is not setup opt-in.
    with home_project_scope(home):
        result = CliRunner().invoke(app, arguments)
    assert result.exit_code == (0 if allow else 1), result.output
    assert seen == ([home] if allow else [])
    if not allow:
        report = json.loads(result.stdout)
        HostConnectionReport.model_validate(report)
        assert report["reason"] == "workspace_locator_invalid"
        assert report["status"]["home_project_allowed"] is False
        assert "--allow-home-project" in report["next_step"]
    assert canonical_workspace_locator(home) is None


@pytest.mark.parametrize("project", ["/", "home-is-root", "symlink", "writable"])
def test_opt_in_keeps_root_symlink_and_ownership_guards(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, project: str
) -> None:
    if project == "symlink":
        selected = tmp_path / "linked-home"
        selected.symlink_to(home, target_is_directory=True)
    elif project == "writable":
        selected = home
        selected.chmod(0o777)
    else:
        selected = Path("/")
        if project == "home-is-root":
            monkeypatch.setenv("HOME", "/")

    def forbidden(**_kwargs: Any) -> int:
        raise AssertionError("unsafe project reached connection planning")

    monkeypatch.setattr(host_connection, "run_host_connection", forbidden)
    result = CliRunner().invoke(
        app,
        [
            "setup",
            "run",
            "--host",
            "claude",
            "--project",
            str(selected),
            "--allow-home-project",
            "--non-interactive",
            "--json",
        ],
    )
    assert result.exit_code == 1, result.output
    assert json.loads(result.stdout)["reason"] == "workspace_locator_invalid"


def test_runtime_opt_in_is_exact_scoped_and_keeps_root_refused(home: Path, tmp_path: Path) -> None:
    assert canonical_workspace_locator(home) is None
    with home_project_scope(home):
        assert canonical_workspace_locator(home) == str(home)
        assert resolve_workspace_locator(payload={"workspace_roots": [str(home)]}) == str(home)
        assert resolve_workspace_locator(explicit=home) == str(home)
        assert canonical_workspace_locator("/") is None
        assert resolve_workspace_locator(explicit="/") is None
    with home_project_scope(tmp_path):
        assert canonical_workspace_locator(home) is None
    assert canonical_workspace_locator(home) is None


def test_home_opt_in_keeps_the_git_marker_safety_boundary(home: Path, tmp_path: Path) -> None:
    git = home / ".git"
    git.mkdir()
    nested = home / "src"
    nested.mkdir()
    with home_project_scope(home):
        assert canonical_workspace_locator(nested) == str(home)
        git.rmdir()
        git.symlink_to(tmp_path, target_is_directory=True)
        assert canonical_workspace_locator(home) is None
        assert canonical_workspace_locator(nested) is None


def test_bound_native_launcher_and_codex_hooks_keep_the_exact_opt_in(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path
) -> None:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    monkeypatch.setattr(
        codex_mcp, "installed_launcher", lambda: (str(launcher), "sha256:" + "a" * 64)
    )
    with home_project_scope(home):
        resolved = resolve_finishup_launcher(launcher)
        assert resolved == (str(launcher), "--home-project", str(home))
        assert resolve_finishup_launcher(resolved) == resolved
        command, _ = codex_mcp.proven_serve_command(MCP_SERVE_COMMAND)
        assert command[1:3] == ("--home-project", str(home))
        assert mcp_command_profile(command) == "policy"
        members = codex_plugin.render_plugin_install_tree(codex_version="0.162.1")
    hooks = json.loads(members["hooks/hooks.json"])["hooks"]
    for entries in hooks.values():
        for entry in entries:
            for handler in entry["hooks"]:
                assert shlex.split(handler["command"])[1:3] == ["--home-project", str(home)]
    assert "--home-project" not in resolve_finishup_launcher(launcher)
    assert (
        mcp_command_profile((str(launcher), "--home-project", "/", *MCP_SERVE_COMMAND[1:])) is None
    )


def test_claude_and_cursor_native_artifacts_carry_home_permission(home: Path) -> None:
    with home_project_scope(home):
        claude = render_claude_code_plugin(
            finishup_launcher="/bin/echo",
            mcp_ownership=McpOwnership.PLUGIN_MANAGED,
            route_profile="strict",
        )
        cursor = render_cursor_plugin(
            PluginFormatProfile.CURSOR_PLUGIN_NATIVE, finishup_launcher="/bin/echo"
        )
    assert claude.finishup_launcher[1:3] == ("--home-project", str(home))
    mcp = json.loads(claude.members[".mcp.json"])["mcpServers"]["finishup"]
    assert mcp["args"][:2] == ["--home-project", str(home)]
    for artifact in (claude, cursor):
        hooks = json.loads(artifact.members["hooks/hooks.json"])["hooks"]
        for entries in hooks.values():
            for entry in entries:
                for handler in entry.get("hooks", [entry]):
                    assert shlex.split(handler["command"])[1:3] == ["--home-project", str(home)]


def test_codex_skill_home_opt_in_is_required(home: Path) -> None:
    from finishup.cli import setup
    from finishup.ports.integrations import IntegrationError

    with pytest.raises((ValueError, IntegrationError)):
        anyio.run(setup.project_skill_preview, home)
    with home_project_scope(home):
        preview = anyio.run(setup.project_skill_preview, home)
    assert preview.preview_digest.startswith("sha256:")
    assert preview.file_changes


def _cursor_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    host: Literal["cursor-ide", "cursor-cli"],
) -> tuple[CliRunner, Path, Path]:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation(
        host, launcher, "2026.09.19", tmp_path / "cursor-config", "Cursor"
    )

    def select(*_args: object, **_kwargs: object) -> HostInstallation:
        return installation

    monkeypatch.setattr(host_connection, "select_installation", select)
    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: str(launcher))
    monkeypatch.setattr(host_connection, "refuse_unservable_runtime", lambda: None)
    monkeypatch.setattr(
        "finishup.adapters.integrations.host_discovery.discover_hosts", lambda: (installation,)
    )

    class Review:
        def consume_artifact_review(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            assert authority.target_digest == preview_digest

        def consume_setup_authority(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise AssertionError("only the complete plan is reviewed")

    def apply(plan: ConnectionPlan, refresh: Any) -> dict[str, Any]:
        return apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=refresh,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=Review(),
        )

    monkeypatch.setattr(host_connection, "apply_selected", apply)
    return CliRunner(), launcher, installation.config_root


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
@pytest.mark.parametrize("batch", [False, True])
def test_home_connection_preview_apply_and_disconnect(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    host: Literal["cursor-ide", "cursor-cli"],
    batch: bool,
) -> None:
    runner, _, _ = _cursor_runner(monkeypatch, tmp_path, host)
    arguments = [
        "setup",
        "run",
        "--host",
        host,
        "--project",
        str(home),
        "--allow-home-project",
        "--non-interactive",
        "--json",
    ]
    if batch:
        arguments.append("--batch")
    preview = runner.invoke(app, arguments)
    assert preview.exit_code == 0, preview.output
    report = json.loads(preview.stdout)
    (HostConnectionBatchReport if batch else HostConnectionReport).model_validate(report)
    row = report["members"][0] if batch else report
    assert row["status"]["home_project_allowed"] is True
    assert "--allow-home-project" in report["next_step"]
    # No project or config writes on preview.
    assert not (home / ".cursor").exists()
    accepted = shlex.split(report["next_step"])[1:]
    if "--json" not in accepted:
        accepted.append("--json")
    connected = runner.invoke(app, accepted)
    assert connected.exit_code == 0, connected.output
    report = json.loads(connected.stdout)
    row = report["members"][0] if batch else report
    assert row["status"]["configured"] is True
    assert row["status"]["home_project_allowed"] is True
    mcp = json.loads((home / ".cursor/mcp.json").read_text())["mcpServers"]["finishup"]
    assert mcp["args"][:2] == ["--home-project", str(home)]
    # The hidden native flag alone must never authorize a new setup attempt.
    refused = runner.invoke(
        app,
        ["--home-project", str(home), *[arg for arg in arguments if arg != "--allow-home-project"]],
    )
    assert refused.exit_code == 1
    assert json.loads(refused.stdout)["reason"] == "workspace_locator_invalid"
    arguments = [
        "setup",
        "disconnect",
        "--host",
        host,
        "--project",
        str(home),
        "--non-interactive",
        "--json",
    ]
    if batch:
        arguments.append("--batch")
    preview = runner.invoke(app, arguments)
    assert preview.exit_code == 0, preview.output
    report = json.loads(preview.stdout)
    accepted = shlex.split(report["next_step"])[1:]
    if "--json" not in accepted:
        accepted.append("--json")
    disconnected = runner.invoke(app, accepted)
    assert disconnected.exit_code == 0, disconnected.output
    report = json.loads(disconnected.stdout)
    row = report["members"][0] if batch else report
    assert row["status"]["configured"] is False
    assert "finishup" not in (home / ".cursor/mcp.json").read_text()


def _cursor_setup(
    runner: CliRunner,
    host: Literal["cursor-ide", "cursor-cli"],
    project: Path,
    *,
    disconnect: bool = False,
    allow_home: bool = False,
) -> dict[str, Any]:
    arguments = [
        "setup",
        "disconnect" if disconnect else "run",
        "--host",
        host,
        "--project",
        str(project),
        "--non-interactive",
        "--json",
    ]
    if allow_home:
        arguments.append("--allow-home-project")
    preview = runner.invoke(app, arguments)
    assert preview.exit_code == 0, preview.output
    report = json.loads(preview.stdout)
    if report["outcome"] == "unchanged":
        return report
    accepted = shlex.split(report["next_step"])[1:]
    if "--json" not in accepted:
        accepted.append("--json")
    connected = runner.invoke(app, accepted)
    assert connected.exit_code == 0, connected.output
    return json.loads(connected.stdout)


def _cursor_hook_commands(config: Path) -> list[list[str]]:
    hooks = json.loads((config / "plugins/local/finishup/hooks/hooks.json").read_text())["hooks"]
    return [
        shlex.split(handler["command"])
        for entries in hooks.values()
        for entry in entries
        for handler in entry.get("hooks", [entry])
    ]


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_cursor_shared_hooks_keep_only_the_still_connected_home_permission(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    host: Literal["cursor-ide", "cursor-cli"],
) -> None:
    runner, _, config = _cursor_runner(monkeypatch, tmp_path, host)
    project = tmp_path / "ordinary-project"
    project.mkdir(mode=0o700)
    _cursor_setup(runner, host, home, allow_home=True)
    home_mcp = (home / ".cursor/mcp.json").read_bytes()

    connected = _cursor_setup(runner, host, project)
    assert connected["status"].get("home_project_allowed") is not True
    assert str(home) in connected["status"]["connected_projects_observed"]
    assert all(
        command[1:3] == ["--home-project", str(home)] for command in _cursor_hook_commands(config)
    )
    ordinary_mcp = (project / ".cursor/mcp.json").read_bytes()
    assert "--home-project" not in ordinary_mcp.decode()
    assert (home / ".cursor/mcp.json").read_bytes() == home_mcp
    assert canonical_workspace_locator(home) is None

    # Rebuilding and disconnecting another project's pieces keep the exact HOME permission.
    _cursor_setup(runner, host, project)
    _cursor_setup(runner, host, project, disconnect=True)
    assert all("--home-project" in command for command in _cursor_hook_commands(config))
    _cursor_setup(runner, host, project)
    removed = _cursor_setup(runner, host, home, disconnect=True)
    assert "update_shared_plugin" in removed["plan"]["changes"]
    assert str(project) in removed["status"]["connected_projects_observed"]
    assert all("--home-project" not in command for command in _cursor_hook_commands(config))
    assert (project / ".cursor/mcp.json").read_bytes() == ordinary_mcp
    _cursor_setup(runner, host, project)
    assert all("--home-project" not in command for command in _cursor_hook_commands(config))
    # A prior connection never authorizes a fresh HOME setup without its explicit flag.
    refused = runner.invoke(
        app, ["setup", "run", "--host", host, "--project", str(home), "--non-interactive", "--json"]
    )
    assert refused.exit_code == 1
    assert json.loads(refused.stdout)["reason"] == "workspace_locator_invalid"


@pytest.mark.parametrize("evidence", ["none", "missing", "foreign", "unflagged", "unrecorded"])
def test_cursor_shared_hooks_do_not_infer_home_permission(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    evidence: str,
) -> None:
    from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    runner, _, config = _cursor_runner(monkeypatch, tmp_path, "cursor-cli")
    if evidence != "none":
        _cursor_setup(runner, "cursor-cli", home, allow_home=True)
        path = home / ".cursor/mcp.json"
        if evidence == "missing":
            path.unlink()
        elif evidence == "unrecorded":
            (config / CONNECTED_PROJECTS_FILE).write_text('{"projects": []}')
        else:
            document = json.loads(path.read_text())
            entry = document["mcpServers"]["finishup"]
            if evidence == "foreign":
                entry["command"] = str(tmp_path / "unrelated")
            else:
                del entry["args"][:2]
            path.write_text(json.dumps(document))
    project = tmp_path / "ordinary-project"
    project.mkdir(mode=0o700)
    _cursor_setup(runner, "cursor-cli", project)
    assert all("--home-project" not in command for command in _cursor_hook_commands(config))
    assert canonical_workspace_locator(home) is None


@pytest.mark.parametrize("host", ["cursor-ide", "cursor-cli"])
def test_cursor_home_permission_survives_consecutive_launcher_updates(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
    host: Literal["cursor-ide", "cursor-cli"],
) -> None:
    runner, launcher, config = _cursor_runner(monkeypatch, tmp_path, host)
    _cursor_setup(runner, host, home, allow_home=True)
    home_mcp = (home / ".cursor/mcp.json").read_bytes()
    for number in range(2):
        runtime = tmp_path / f"runtime-{number}"
        runtime.mkdir(mode=0o700)
        updated = runtime / "finishup"
        updated.write_bytes(launcher.read_bytes())
        updated.chmod(0o700)
        monkeypatch.setattr(host_connection, "invoking_launcher", lambda: str(updated))
        project = tmp_path / f"project-{number}"
        project.mkdir(mode=0o700)
        connected = _cursor_setup(runner, host, project)
        assert str(home) in connected["status"]["connected_projects_observed"]
        assert all(
            command[:3] == [str(updated), "--home-project", str(home)]
            for command in _cursor_hook_commands(config)
        )
        assert "--home-project" not in (project / ".cursor/mcp.json").read_text()
    assert (home / ".cursor/mcp.json").read_bytes() == home_mcp
    # The original HOME launcher is still the ownership proof for its reverse path.
    removed = _cursor_setup(runner, host, home, disconnect=True)
    assert removed["status"]["configured"] is False
    assert all("--home-project" not in command for command in _cursor_hook_commands(config))


def test_cursor_home_permission_change_invalidates_the_ordinary_project_preview(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    tmp_path: Path,
) -> None:
    runner, _, config = _cursor_runner(monkeypatch, tmp_path, "cursor-cli")
    _cursor_setup(runner, "cursor-cli", home, allow_home=True)
    project = tmp_path / "ordinary-project"
    project.mkdir(mode=0o700)
    preview = runner.invoke(
        app,
        [
            "setup",
            "run",
            "--host",
            "cursor-cli",
            "--project",
            str(project),
            "--non-interactive",
            "--json",
        ],
    )
    assert preview.exit_code == 0, preview.output
    report = json.loads(preview.stdout)
    assert report["status"]["shared_home_project"] == str(home)
    path = home / ".cursor/mcp.json"
    document = json.loads(path.read_text())
    document["mcpServers"]["finishup"]["args"].extend(["--semantic", "off"])
    path.write_text(json.dumps(document))
    accepted = shlex.split(report["next_step"])[1:]
    if "--json" not in accepted:
        accepted.append("--json")
    stale = runner.invoke(app, accepted)
    assert stale.exit_code == 1, stale.output
    assert json.loads(stale.stdout)["reason"] == "connection_preview_stale"
    assert not (project / ".cursor").exists()
    assert all("--home-project" in command for command in _cursor_hook_commands(config))


@pytest.mark.parametrize("unsafe", ["symlink", "writable"])
def test_cursor_unreadable_home_permission_stops_before_shared_hooks_change(
    monkeypatch: pytest.MonkeyPatch, home: Path, tmp_path: Path, unsafe: str
) -> None:
    runner, _, config = _cursor_runner(monkeypatch, tmp_path, "cursor-cli")
    _cursor_setup(runner, "cursor-cli", home, allow_home=True)
    path = home / ".cursor/mcp.json"
    if unsafe == "symlink":
        saved = home / ".cursor/saved-mcp.json"
        path.rename(saved)
        path.symlink_to(saved)
    else:
        path.chmod(0o666)
    project = tmp_path / "ordinary-project"
    project.mkdir(mode=0o700)
    refused = runner.invoke(
        app,
        [
            "setup",
            "run",
            "--host",
            "cursor-cli",
            "--project",
            str(project),
            "--non-interactive",
            "--json",
        ],
    )
    assert refused.exit_code == 1, refused.output
    assert json.loads(refused.stdout)["reason"] == "connection_home_project_permission_unknown"
    assert not (project / ".cursor").exists()
    assert all("--home-project" in command for command in _cursor_hook_commands(config))


@pytest.mark.parametrize("base", [("/opt/bin/finishup",), ("/opt/bin/python", "-m", "finishup")])
def test_recorded_home_launchers_keep_exact_permission_and_rename_aliases(
    home: Path, base: tuple[str, ...]
) -> None:
    launcher = (*base, "--home-project", str(home))
    assert recorded_launcher(list(launcher)) == launcher
    alias = ("/opt/bin/yoetz",) if len(base) == 1 else (base[0], "-m", "yoetz")
    assert launcher_aliases(launcher) == (launcher, (*alias, "--home-project", str(home)))
    for suffix in (
        ("--home-project", "/"),
        ("--home-project", str(home / "other")),
        ("--home-project", str(home), "--unexpected"),
    ):
        assert recorded_launcher([*base, *suffix]) is None


def test_setup_help_explains_the_opt_in() -> None:
    # GitHub Actions makes Typer force a styled terminal; a dumb, wide one keeps option names
    # whole and unstyled, as the other help tests do.
    result = CliRunner().invoke(
        app, ["setup", "run", "--help"], color=False, env={"COLUMNS": "300", "TERM": "dumb"}
    )
    assert result.exit_code == 0
    assert "--allow-home-project" in result.output
