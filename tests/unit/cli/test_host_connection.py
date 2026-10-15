import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import ConnectionPlan
from finishup.cli import host_connection as cli
from finishup.protocol.canonical import JsonValue
from finishup.protocol.host_connection import HostConnectionReport
from finishup.service.elevated_bootstrap import ElevatedBootstrapError

REQUEST = "req_cc8c2c7e-1246-4ed2-9e48-05a69fbb1d90"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ConnectionPlan:
    launcher = tmp_path / "finishup"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    monkeypatch.setattr(cli, "invoking_launcher", lambda: (str(launcher),))
    installation = HostInstallation(
        "claude", Path("/opt/claude"), "2.1.241", Path("/workspace/example/.claude"), "Claude Code"
    )
    plan = ConnectionPlan(
        {
            "schema": "yoetz.host-connection-plan/1",
            "request_id": REQUEST,
            "host": "claude",
            "host_version": "2.1.241",
            "executable": "/opt/claude",
            "config_root": "/workspace/example/.claude",
            "project_root": "/workspace/example/project",
            "action": "connect",
            "route_profile": "strict",
            "preview_digest": DIGEST,
            "connection_observed": False,
            "changes": ["install_plugin", "enable_plugin"],
        },
        lambda: {"configured": False, "connection_observed": False},
        lambda: None,
    )

    def selected(*_args: object) -> HostInstallation:
        return installation

    def prepared_plan(*_args: object, **_kwargs: object) -> ConnectionPlan:
        return plan

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "prepare_selected", prepared_plan)
    return plan


def test_agent_acceptance_requires_exact_preview_and_request(
    prepared: ConnectionPlan, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_args: object, **_kwargs: object):
        raise AssertionError("bare accept must never reach authorization or mutation")

    monkeypatch.setattr(cli, "apply_selected", forbidden)
    code = cli.run_host_connection(
        host="claude",
        executable=None,
        config_root=None,
        project=Path("/workspace/example/project"),
        accept=True,
        json_output=True,
    )
    assert code == 3
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert report["outcome"] == "preview"
    assert "--preview-digest " + prepared.digest in report["next_step"]
    assert "--request-id" in report["next_step"]


def test_pending_approval_is_an_actionable_report_not_a_traceback(
    prepared: ConnectionPlan, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def pending(*_args: object, **_kwargs: object):
        raise ElevatedBootstrapError("pending_already_active")

    monkeypatch.setattr(cli, "apply_selected", pending)
    code = cli.run_host_connection(
        host="claude",
        executable=None,
        config_root=None,
        project=Path("/workspace/example/project"),
        accept=True,
        request_value=REQUEST,
        preview_digest=prepared.digest,
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert report["reason"] == "pending_already_active"


def test_status_never_consumes_approval(
    prepared: ConnectionPlan, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def forbidden(*_args: object, **_kwargs: object):
        raise AssertionError("status must be read only")

    monkeypatch.setattr(cli, "apply_selected", forbidden)
    assert (
        cli.run_host_connection(
            host="claude",
            executable=None,
            config_root=None,
            project=Path("/workspace/example/project"),
            status_only=True,
            json_output=True,
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == "status"
    assert report["connection_observed"] is False


def test_launch_preserves_the_selected_finishup_runtime_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.cli import host_connection

    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: "/opt/instance/bin/finishup")

    def resolve(_value: object) -> tuple[str, ...]:
        return ("/opt/instance/bin/finishup",)

    monkeypatch.setattr(host_connection, "resolve_finishup_launcher", resolve)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    selected = HostInstallation(
        "codex", Path("/opt/codex"), "0.153.4", Path("/workspace/profile"), "Codex"
    )
    launch = host_connection.launch_details(selected, Path("/workspace/project"))
    environment = launch["environment"]
    assert isinstance(environment, dict)
    assert environment["PATH"] == "/opt/instance/bin:/usr/bin:/bin"


def test_launch_names_the_isolated_root_under_both_spellings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A host that resolves an older ``yoetz`` launcher still stays isolated (ADR-048, #604)."""

    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.cli import host_connection

    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: None)
    monkeypatch.setattr(host_connection, "isolated_root", lambda: Path("/opt/instance/state"))
    selected = HostInstallation(
        "claude", Path("/opt/claude"), "2.1.0", Path("/workspace/profile"), "Claude Code"
    )
    launch = host_connection.launch_details(selected, Path("/workspace/project"))
    environment = launch["environment"]
    assert isinstance(environment, dict)
    assert environment["FINISHUP_ISOLATED_ROOT"] == "/opt/instance/state"
    assert environment["YOETZ_ISOLATED_ROOT"] == "/opt/instance/state"
    shell_command = launch["shell_command"]
    assert isinstance(shell_command, str)
    assert "FINISHUP_ISOLATED_ROOT=/opt/instance/state" in shell_command
    assert "YOETZ_ISOLATED_ROOT=/opt/instance/state" in shell_command


@pytest.mark.parametrize("host", ["claude", "cursor-ide", "cursor-cli", "codex"])
def test_setup_keeps_os_password_ceremony_on_main_thread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: str
) -> None:
    import threading

    import anyio

    from finishup.cli.setup import run_setup_wizard

    main_thread = threading.get_ident()

    def connect(**_kwargs: object) -> int:
        assert (threading.get_ident() == main_thread) is (host != "codex")
        return 0

    monkeypatch.setattr(cli, "run_host_connection", connect)

    async def run() -> int:
        return await run_setup_wizard(
            non_interactive=True,
            codex_path=None,
            codex_home=None,
            accept=False,
            json_output=True,
            host=host,
            project=tmp_path,
        )

    assert anyio.run(run) == 0


def test_claude_and_cursor_plans_describe_changes_in_plain_words(
    prepared: ConnectionPlan,
) -> None:
    lines = cli.connection_summary(prepared)

    changes = next(line for line in lines if line.startswith("Changes: "))
    assert changes == "Changes: Install the FinishUP plugin, Enable the FinishUP plugin"
    assert prepared.body["changes"] == ["install_plugin", "enable_plugin"]


def test_an_ambiguous_installation_names_the_paths_to_choose_from(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    older = HostInstallation("codex", Path("/opt/a/codex"), "0.153.4", tmp_path, "Codex")
    newer = HostInstallation("codex", Path("/opt/b/codex"), "0.162.1", tmp_path, "Codex")

    def discovered() -> tuple[HostInstallation, ...]:
        return (older, newer)

    monkeypatch.setattr(cli, "discover_hosts", discovered)

    code = cli.run_host_connection(
        host="codex", executable=None, config_root=None, project=tmp_path, action="disconnect"
    )

    assert code == 1
    out = capsys.readouterr().out
    assert "connection_executable_required" in out
    assert "--host-path" in out
    assert "/opt/a/codex, /opt/b/codex" in out
    assert "trusted local terminal" not in out


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-cli"])
def test_failed_connection_names_a_runtime_another_account_can_write(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    import finishup.cli.runtime_refusal as refusal
    from finishup.ports.plugin_artifacts import PluginArtifactError, PluginArtifactReason

    def unsafe(*_args: object, **_kwargs: object) -> ConnectionPlan:
        raise PluginArtifactError(PluginArtifactReason.TARGET_UNSAFE, {})

    monkeypatch.setattr(cli, "prepare_selected", unsafe)
    monkeypatch.setattr(
        refusal,
        "installed_runtime_refusal_text",
        lambda: (
            "release_runtime_group_writable",
            "release_runtime_group_writable: Another account ... retry:\n  chmod -R go-w /x\n",
        ),
    )
    code = cli.run_host_connection(
        host=host,
        executable=None,
        config_root=None,
        project=Path("/workspace/example/project"),
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert report["reason"] == "release_runtime_group_writable"
    assert "chmod -R go-w /x" in report["next_step"]


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-cli"])
def test_connect_preflight_names_a_runtime_another_account_installed(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    """Every host would launch a runtime that cannot serve this account: refuse by name."""

    from finishup.adapters import release_runtime

    monkeypatch.setattr(
        release_runtime,
        "installed_runtime_refusal",
        lambda: release_runtime.ReleaseRuntimeError("release_runtime_not_owned"),
    )
    code = cli.run_host_connection(
        host=host,
        executable=None,
        config_root=None,
        project=Path("/workspace/example/project"),
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert (report["outcome"], report["reason"]) == ("incomplete", "release_runtime_not_owned")
    assert "must belong to the account running FinishUP" in report["next_step"]
    assert "plan" not in report


def test_connect_preflight_refuses_but_disconnect_and_status_proceed(
    prepared: ConnectionPlan, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.cli.runtime_refusal as refusal

    monkeypatch.setattr(
        refusal,
        "installed_runtime_refusal_text",
        lambda: ("release_runtime_world_writable", "release_runtime_world_writable: repair\n"),
    )
    project = Path("/workspace/example/project")
    assert (
        cli.run_host_connection(
            project=project, json_output=True, host="claude", executable=None, config_root=None
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert (report["outcome"], report["reason"]) == ("incomplete", "release_runtime_world_writable")
    assert "plan" not in report
    # The way out and the read-only view stay available.
    assert (
        cli.run_host_connection(
            project=project,
            json_output=True,
            status_only=True,
            host="claude",
            executable=None,
            config_root=None,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["outcome"] == "status"
    assert (
        cli.run_host_connection(
            project=project,
            json_output=True,
            action="disconnect",
            host="claude",
            executable=None,
            config_root=None,
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["outcome"] == "preview"


# --- Every connect path refuses a runtime that cannot serve this account -------------------


def _runtime_cannot_serve(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.adapters import release_runtime

    monkeypatch.setattr(
        release_runtime,
        "installed_runtime_refusal",
        lambda: release_runtime.ReleaseRuntimeError("release_runtime_not_owned"),
    )


def test_bare_setup_run_registers_nothing_for_a_runtime_that_cannot_serve(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    """``setup run`` without ``--host`` (the Codex wizard) used to register Codex anyway."""

    import anyio

    import finishup.cli.setup as setup
    from finishup.adapters.integrations import host_discovery

    _runtime_cannot_serve(monkeypatch)
    monkeypatch.setattr(host_discovery, "discover_hosts", lambda: ())
    from finishup.ports.harness_mcp import HarnessBinary, HarnessId

    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n")
    executable.chmod(0o700)
    binary = HarnessBinary(HarnessId.CODEX, str(executable), "0.162.1", "untested")
    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: (binary,))

    def no_registration(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("the Codex integration went past the runtime refusal")

    monkeypatch.setattr(setup, "CodexPluginService", no_registration)
    monkeypatch.setattr(setup, "resolve_codex_home_for_binary", no_registration)

    async def unreachable(**_kwargs: object) -> dict[str, object]:
        return {"reachable": False, "state": None, "vault_mode": None}

    monkeypatch.setattr(setup, "_service_reachability", unreachable)

    def marker_written(*_args: object) -> bool:
        return True

    monkeypatch.setattr(setup, "_write_setup_marker", marker_written)

    async def run() -> int:
        return await setup.run_setup_wizard(
            non_interactive=True,
            codex_path=None,
            codex_home=tmp_path / "codex-home",
            accept=True,
            json_output=True,
            project=tmp_path,
        )

    anyio.run(run)
    report = json.loads(capsys.readouterr().out)
    registration = report["registration"]
    assert (registration["outcome"], registration["reason"]) == (
        "failed",
        "release_runtime_not_owned",
    )
    assert any(
        "must belong to the account running FinishUP" in str(step) for step in report["next_steps"]
    )


def test_apply_selected_refuses_a_connect_but_never_a_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard every front end's connect passes through, the TUI's included."""

    from types import SimpleNamespace

    from finishup.application.host_connection import ConnectionError

    _runtime_cannot_serve(monkeypatch)
    applied: list[str] = []

    def apply(plan: object, **_kwargs: object) -> dict[str, object]:
        applied.append(cast_action(plan))
        return {}

    def cast_action(plan: object) -> str:
        return str(getattr(plan, "body")["action"])

    monkeypatch.setattr(cli, "apply_connection", apply)
    connect = SimpleNamespace(
        body={"action": "connect", "requires_os_presence": False, "changes": []},
        unchanged=True,
        digest="sha256:" + "0" * 64,
    )
    with pytest.raises(ConnectionError) as refused:
        cli.apply_selected(connect, lambda: connect)  # type: ignore[arg-type]
    assert str(refused.value) == "release_runtime_refused"
    disconnect = SimpleNamespace(
        body={"action": "disconnect", "requires_os_presence": False, "changes": []},
        unchanged=True,
        digest="sha256:" + "0" * 64,
    )
    cli.apply_selected(disconnect, lambda: disconnect)  # type: ignore[arg-type]
    assert applied == ["disconnect"]


# The documented direct commands (and the prompt-loop menu, which calls ``integrate_mcp``).


@pytest.mark.parametrize("action", ["install", "preview"])
def test_integrate_codex_mcp_refuses_a_runtime_that_cannot_serve(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], action: str
) -> None:
    import anyio

    import finishup.cli.setup as setup

    _runtime_cannot_serve(monkeypatch)

    def no_discovery() -> tuple[object, ...]:
        raise AssertionError("the registration went past the runtime refusal")

    monkeypatch.setattr(setup, "discover_codex_binaries", no_discovery)

    async def run() -> int:
        return await setup.integrate_mcp(
            action, "codex", codex_path=None, accept=True, preview_digest=None, json_output=True
        )

    assert anyio.run(run) == 20
    assert capsys.readouterr().err.startswith("release_runtime_not_owned: ")


@pytest.mark.parametrize("action", ["status", "preview-remove", "remove"])
def test_integrate_codex_mcp_status_and_removal_stay_open(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], action: str
) -> None:
    import anyio

    import finishup.cli.setup as setup

    _runtime_cannot_serve(monkeypatch)
    reached: list[bool] = []

    def discovery() -> tuple[object, ...]:
        reached.append(True)
        return ()

    monkeypatch.setattr(setup, "discover_codex_binaries", discovery)

    async def run() -> int:
        return await setup.integrate_mcp(
            action, "codex", codex_path=None, accept=True, preview_digest=None, json_output=True
        )

    anyio.run(run)
    assert reached == [True]
    assert "release_runtime_not_owned" not in capsys.readouterr().err


@pytest.mark.parametrize(
    ("command", "requested", "refused"),
    [
        ("install", None, True),
        ("update", None, True),
        ("enable", None, True),
        ("preview", None, True),
        ("preview", "connect", True),
        ("preview", "remove", False),
        ("remove", None, False),
        ("disable", None, False),
        ("status", None, False),
    ],
)
def test_integrate_claude_plugin_refuses_only_connects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    requested: str | None,
    refused: bool,
) -> None:
    from finishup.cli.claude_code_integration import run_claude_code_plugin_command

    _runtime_cannot_serve(monkeypatch)
    code = run_claude_code_plugin_command(
        command,
        harness="claude",
        claude_path=tmp_path / "no-claude",
        claude_config_root=tmp_path / "config",
        cache_root=tmp_path / "config" / "plugins" / "cache",
        marketplace_root=tmp_path / "marketplace",
        project_root=tmp_path,
        format_name="native",
        ownership_name="plugin",
        route_profile=None,
        requested_action=requested,
        request_value=None,
        preview_digest=None,
        accept=False,
        json_output=True,
    )
    err = capsys.readouterr().err
    assert (code == 20 and err.startswith("release_runtime_not_owned: ")) is refused
    if not refused:
        assert "release_runtime_not_owned" not in err


@pytest.mark.parametrize(
    ("command", "requested", "refused"),
    [
        ("install", None, True),
        ("preview", None, True),
        ("preview", "replace", True),
        ("preview", "remove", False),
        ("remove", None, False),
        ("status", None, False),
    ],
)
def test_integrate_cursor_plugin_refuses_only_connects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    command: str,
    requested: str | None,
    refused: bool,
) -> None:
    from finishup.cli.cursor_integration import run_cursor_plugin_command

    _runtime_cannot_serve(monkeypatch)
    config = tmp_path / "cursor"
    config.mkdir(mode=0o700)
    code = run_cursor_plugin_command(
        command,
        harness="cursor",
        cursor_config_root=config,
        project_root=None,
        format_name="native",
        ownership_name="plugin",
        route_profile=None,
        requested_action=requested,
        request_value=None,
        preview_digest=None,
        accept=False,
        json_output=True,
    )
    err = capsys.readouterr().err
    assert (code == 20 and err.startswith("release_runtime_not_owned: ")) is refused
    if not refused:
        assert "release_runtime_not_owned" not in err


@pytest.mark.parametrize(
    ("action", "refused"),
    [("install", True), ("preview", True), ("preview-remove", False), ("status", False)],
)
def test_integrate_cursor_project_mcp_refuses_only_connects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    refused: bool,
) -> None:
    from finishup.cli.cursor_project_mcp import run_cursor_project_mcp_command

    _runtime_cannot_serve(monkeypatch)
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    code = run_cursor_project_mcp_command(
        action,
        "cursor",
        project_root=project,
        cursor_config_root=tmp_path / "cursor",
        route_profile=None,
        accept=False,
        preview_digest=None,
        json_output=True,
    )
    body = json.loads(capsys.readouterr().out)
    assert (code == 20 and body.get("reason_code") == "release_runtime_not_owned") is refused
    if refused:
        assert "must belong to the account running FinishUP" in body["next_step"]
    else:
        assert body.get("reason_code") != "release_runtime_not_owned"


def test_recommend_accept_codex_activation_refuses_a_runtime_that_cannot_serve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``finishup recommend accept codex-plugin-activation`` (setup's next command) enables the
    Codex plugin and its hooks: it is a connect, refused before refreshing or previewing."""

    from typer.testing import CliRunner

    from finishup.cli import recommend

    _runtime_cannot_serve(monkeypatch)

    async def no_refresh(**_kwargs: object) -> object:
        raise AssertionError("the activation went past the runtime refusal")

    monkeypatch.setattr(recommend, "refresh_pending", no_refresh)
    result = CliRunner().invoke(
        recommend.recommend_app,
        [
            "accept",
            "codex-plugin-activation",
            "--codex-path",
            str(tmp_path / "codex"),
            "--codex-home",
            str(tmp_path / "codex-home"),
        ],
    )
    assert result.exit_code == 20
    assert result.stderr.startswith("release_runtime_not_owned: ")


def test_lock_unavailable_says_nothing_changed_and_names_the_lock_folder(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """#1058: a setup lock that cannot be taken is not a partial connection."""

    from finishup.adapters.integrations import host_projects
    from finishup.application.host_connection import ConnectionError as SetupConnectionError

    def unavailable(*_args: object, **_kwargs: object):
        raise SetupConnectionError("connection_lock_unavailable")

    monkeypatch.setattr(cli, "apply_selected", unavailable)
    code = cli.run_host_connection(
        host="claude",
        executable=None,
        config_root=tmp_path / "claude",
        project=Path("/workspace/example/project"),
        accept=True,
        request_value=REQUEST,
        preview_digest=prepared.digest,
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert report["reason"] == "connection_lock_unavailable"
    step = report["next_step"]
    assert step.startswith("Nothing was changed.")
    assert str(host_projects.lock_path_for(tmp_path / "claude").parent) in step
    assert "partial connection" not in step


def _select(monkeypatch: pytest.MonkeyPatch, host: str, root: Path) -> None:
    from typing import cast

    from finishup.adapters.integrations.host_discovery import SetupHost

    installation = HostInstallation(cast(SetupHost, host), Path("/opt/host"), "1.0.0", root, "Host")

    def selected(*_args: object) -> HostInstallation:
        return installation

    def no_leftover(*_args: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "_codex_leftover", no_leftover)


def _damaged_record(root: Path) -> Path:
    from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    root.mkdir(mode=0o700)
    record = root / CONNECTED_PROJECTS_FILE
    record.write_text('{"projects":["/work/a"]}\n')
    record.chmod(0o644)  # readable by others: refused
    return record


@pytest.mark.parametrize(
    ("host", "action", "status_only"),
    [
        ("codex", "connect", False),
        ("codex", "connect", True),
        ("codex", "disconnect", False),
        ("cursor-ide", "disconnect", False),
    ],
)
def test_a_damaged_record_gets_its_own_continuation_on_every_command(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    host: str,
    action: str,
    status_only: bool,
) -> None:
    """#1058 review P2-6: `setup run` and `setup status` reach Codex through a wrapper that keeps
    only `source_invalid`; the record itself is asked, so every command names the file."""

    from typing import Literal, cast

    from finishup.application.host_connection import ConnectionError as SetupConnectionError
    from finishup.ports.integrations import IntegrationError, IntegrationReason
    from finishup.tui.runtime import RuntimeError_

    root = tmp_path / "config"
    record = _damaged_record(root)
    _select(monkeypatch, host, root)

    def invalid(*_args: object, **_kwargs: object):
        if host != "codex":
            raise SetupConnectionError("connection_projects_record_invalid")
        if action == "disconnect":
            raise IntegrationError(
                IntegrationReason.SOURCE_INVALID, {"conflict": "connected_projects"}
            )
        # What `setup run|status --host codex` sees: the TUI runtime keeps only the reason.
        raise RuntimeError_("source_invalid", "the Codex activation could not be previewed")

    monkeypatch.setattr(cli, "prepare_selected", invalid)
    code = cli.run_host_connection(
        host=host,
        executable=None,
        config_root=root,
        project=Path("/workspace/example/project"),
        action=cast(Literal["connect", "disconnect"], action),
        status_only=status_only,
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    assert report["reason"] == "connection_projects_record_invalid"
    step = report["next_step"]
    assert step.startswith("Nothing was changed.")
    assert f"chmod 600 {record}" in step
    if host == "codex":
        # Codex only detects its own earlier members and trusted checkouts: never "just delete".
        assert "run setup again for every project" in step
        assert "membership_unverified" in step
    else:
        assert "unknown" in step


def test_source_invalid_with_a_valid_record_keeps_the_generic_continuation(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE
    from finishup.tui.runtime import RuntimeError_

    root = tmp_path / "config"
    root.mkdir(mode=0o700)
    record = root / CONNECTED_PROJECTS_FILE
    record.write_text('{"projects":["/work/a"]}\n')
    record.chmod(0o600)
    _select(monkeypatch, "codex", root)

    def invalid(*_args: object, **_kwargs: object):
        raise RuntimeError_("source_invalid", "the Codex activation could not be previewed")

    monkeypatch.setattr(cli, "prepare_selected", invalid)
    cli.run_host_connection(
        host="codex",
        executable=None,
        config_root=root,
        project=Path("/workspace/example/project"),
        json_output=True,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "source_invalid"
    assert "connected" not in report["next_step"]


def test_summary_names_projects_whose_shared_review_mode_changes() -> None:
    """#1058 review P2-3: connecting on another review mode changes it for other projects."""

    lines = cli._shared_summary(  # pyright: ignore[reportPrivateUsage]
        {
            "action": "connect",
            "route_profile": "policy",
            "route_profile_before": "strict",
            "route_changes_for": ["/work/a"],
            "shared_with": ["/work/a"],
        }
    )
    assert any(
        "from local only to AI-powered review" in line and "/work/a" in line for line in lines
    )


def test_text_preview_prints_what_the_plan_does_to_other_projects(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from dataclasses import replace

    disclosed = replace(
        prepared,
        body={**prepared.body, "route_profile": "policy"},
        disclosure={
            "shared_with": ["/work/a"],
            "route_profile_before": "strict",
            "route_changes_for": ["/work/a"],
        },
    )

    def prepared_plan(*_args: object, **_kwargs: object) -> ConnectionPlan:
        return disclosed

    monkeypatch.setattr(cli, "prepare_selected", prepared_plan)
    cli.run_host_connection(
        host="claude",
        executable=None,
        config_root=None,
        project=Path("/workspace/example/project"),
        route="policy",
    )
    out = capsys.readouterr().out
    assert "claude: preview" in out
    assert "keep working: /work/a" in out
    assert "from local only to AI-powered review" in out


def test_codex_home_that_does_not_exist_names_the_mkdir(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """#1058 review P3: Codex needs an existing home; say so instead of generic advice."""

    from finishup.tui.runtime import RuntimeError_

    home = tmp_path / "nested" / "codex"
    _select(monkeypatch, "codex", home)

    def untrusted(*_args: object, **_kwargs: object):
        raise RuntimeError_("target_untrusted", "the Codex activation could not be previewed")

    monkeypatch.setattr(cli, "prepare_selected", untrusted)
    cli.run_host_connection(
        host="codex",
        executable=None,
        config_root=home,
        project=Path("/workspace/example/project"),
        json_output=True,
    )
    report = json.loads(capsys.readouterr().out)
    assert report["reason"] == "target_untrusted"
    assert report["next_step"].startswith("Nothing was changed.")
    assert f"mkdir -p -m 700 {home}" in report["next_step"]


def test_unverified_step_names_the_selected_codex_and_keeps_the_review_mode(
    tmp_path: Path,
) -> None:
    """#1058 review round 2 P3: the continuation works when Codex is not on PATH and the
    reconnect keeps the home's shared review mode."""

    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text(
        '[mcp_servers.finishup]\ncommand = "finishup"\n'
        'args = ["mcp", "serve", "--host", "codex", "--semantic", "off"]\n'
    )
    installation = HostInstallation("codex", Path("/opt/codex/bin/codex"), "0.144.6", home, "Codex")
    step = cli._codex_unverified_step(  # pyright: ignore[reportPrivateUsage]
        None, tmp_path / "a", installation
    )
    assert step.count("--host-path /opt/codex/bin/codex") == 2
    assert "--route-profile strict" in step


def test_summary_names_unserved_members_rebind_and_possible_route_changes() -> None:
    lines = cli._shared_summary(  # pyright: ignore[reportPrivateUsage]
        {
            "action": "connect",
            "route_profile": "policy",
            "route_profile_before": "strict",
            "route_changes_for": [],
            "route_changes_possible_for": ["/work/maybe"],
            "members_not_serving": ["/work/away"],
            "rebind_to": "/work/next",
        }
    )
    joined = "\n".join(lines)
    assert "/work/maybe (may use FinishUP)" in joined
    assert "missing right now" in joined and "/work/away" in joined
    assert "binding moves to /work/next" in joined


def test_an_unchanged_disconnect_names_who_keeps_the_shared_pieces(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A re-run or never-connected disconnect changes nothing; text mode says who keeps them."""

    installation = HostInstallation(
        "codex", Path("/opt/codex"), "0.162.1", Path("/workspace/home"), "Codex"
    )
    plan = ConnectionPlan(
        {
            "schema": "yoetz.host-connection-plan/1",
            "request_id": REQUEST,
            "host": "codex",
            "host_version": "0.162.1",
            "executable": "/opt/codex",
            "config_root": "/workspace/home",
            "project_root": "/workspace/b",
            "action": "disconnect",
            "route_profile": "strict",
            "preview_digest": DIGEST,
            "connection_observed": False,
            "changes": [],
        },
        lambda: {"configured": False, "shared_with": ["/workspace/a"]},
        lambda: None,
    )

    def selected(*_args: object) -> HostInstallation:
        return installation

    def prepared_plan(*_args: object, **_kwargs: object) -> ConnectionPlan:
        return plan

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "prepare_selected", prepared_plan)
    code = cli.run_host_connection(
        host="codex",
        executable=None,
        config_root=None,
        project=Path("/workspace/b"),
        action="disconnect",
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "codex: unchanged" in out
    assert "stay for the other projects using this configuration: /workspace/a" in out


def test_shared_pieces_kept_only_for_a_missing_directory_name_the_way_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """#1058 triage: nothing live keeps them, so name the project and the home-wide preview."""

    installation = HostInstallation(
        "codex", Path("/opt/codex"), "0.162.1", Path("/workspace/home"), "Codex"
    )
    plan = ConnectionPlan(
        {
            "schema": "yoetz.host-connection-plan/1",
            "request_id": REQUEST,
            "host": "codex",
            "host_version": "0.162.1",
            "executable": "/opt/codex",
            "config_root": "/workspace/home",
            "project_root": "/workspace/c",
            "action": "disconnect",
            "route_profile": "strict",
            "preview_digest": DIGEST,
            "connection_observed": False,
            "changes": [],
        },
        lambda: {
            "configured": False,
            "shared_with": ["/workspace/a"],
            "members_missing": ["/workspace/a"],
        },
        lambda: None,
    )

    def selected(*_args: object) -> HostInstallation:
        return installation

    def prepared_plan(*_args: object, **_kwargs: object) -> ConnectionPlan:
        return plan

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "prepare_selected", prepared_plan)
    code = cli.run_host_connection(
        host="codex",
        executable=None,
        config_root=None,
        project=Path("/workspace/c"),
        action="disconnect",
    )
    assert code == 0
    out = capsys.readouterr().out
    assert "/workspace/a (directory missing right now)" in out
    assert "whose directory is missing right now" in out
    assert "setup disconnect --host codex --host-path /opt/codex" in out
    assert "--project /workspace/c --remove-shared" in out

    code = cli.run_host_connection(
        host="codex",
        executable=None,
        config_root=None,
        project=Path("/workspace/c"),
        action="disconnect",
        json_output=True,
    )
    report = json.loads(capsys.readouterr().out)
    assert "--remove-shared" in report["next_step"]


@pytest.mark.parametrize("completed", [False, True], ids=["unchanged", "completed"])
def test_a_disconnect_that_keeps_unconfirmed_shared_pieces_names_the_home_wide_way_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], completed: bool
) -> None:
    """A Yoetz-era Cursor plugin folder found without a record stays on an ordinary disconnect
    (membership unknown). The completed and the repeated disconnect both say how to remove it,
    as `setup status` does (#1073)."""

    installation = HostInstallation(
        "cursor-ide", Path("/opt/cursor"), "3.17.8", Path("/workspace/.cursor"), "Cursor"
    )
    final: dict[str, JsonValue] = {
        "configured": False,
        "membership_unknown": True,
        "connected_projects": [],
    }
    plan = ConnectionPlan(
        {
            "schema": "yoetz.host-connection-plan/1",
            "request_id": REQUEST,
            "host": "cursor-ide",
            "host_version": "3.17.8",
            "executable": "/opt/cursor",
            "config_root": "/workspace/.cursor",
            "project_root": "/workspace/a",
            "action": "disconnect",
            "route_profile": "strict",
            "preview_digest": DIGEST,
            "connection_observed": False,
            "changes": ["remove_project_mcp"] if completed else [],
        },
        lambda: final,
        lambda: None,
    )

    def selected(*_args: object) -> HostInstallation:
        return installation

    def prepared_plan(*_args: object, **_kwargs: object) -> ConnectionPlan:
        return plan

    def applied(*_args: object, **_kwargs: object) -> dict[str, JsonValue]:
        return final

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "prepare_selected", prepared_plan)
    monkeypatch.setattr(cli, "apply_selected", applied)
    code = cli.run_host_connection(
        host="cursor-ide",
        executable=None,
        config_root=None,
        project=Path("/workspace/a"),
        action="disconnect",
        accept=completed,
        request_value=REQUEST if completed else None,
        preview_digest=plan.digest if completed else None,
        json_output=True,
    )
    assert code == 0
    report = json.loads(capsys.readouterr().out)
    assert report["outcome"] == ("completed" if completed else "unchanged")
    assert report["next_step"].startswith("Restart the selected host.")
    assert (
        "setup disconnect --host cursor-ide --host-path /opt/cursor --host-config-root "
        "/workspace/.cursor --project /workspace/a --remove-shared"
    ) in report["next_step"]


def test_a_removed_plugin_with_only_the_registration_kept_says_so() -> None:
    """A+B+C: A is Yoetz-era (keeps the MCP registration), B anchors the binding, C is a FinishUP
    member whose plugin files are missing. B's disconnect removes the shared plugin, so C loses
    it and only the registration stays for A (#1073)."""

    lines = cli._shared_summary(  # pyright: ignore[reportPrivateUsage]
        {
            "action": "disconnect",
            "shared_with": ["/w/a"],
            "shared_plugin_removed": True,
            "members_not_serving": ["/w/c"],
        }
    )
    text = "\n".join(lines)
    assert (
        "The shared FinishUP plugin is removed from this home; only the MCP registration stays "
        "for: /w/a"
    ) in text
    assert "Connected projects whose FinishUP plugin files are missing right now" in text
    assert "/w/c" in text
    assert "Other connected projects keep using the shared FinishUP pieces" not in text


def test_a_mixed_leftover_names_each_key_and_keeps_the_revoke(tmp_path: Path) -> None:
    """An exact FinishUP approval table beside an edited Yoetz-era one: the step names which is
    which, and the revoke that removes the exact one (#1073)."""

    from finishup.adapters.integrations.host_admission import CODEX_EXTERNAL_ADMISSION_TABLE
    from finishup.cli.codex_connection import project_mcp_leftover_status

    home, project = tmp_path / "home", tmp_path / "project"
    (project / ".codex").mkdir(parents=True, mode=0o700)
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text("")
    edited_yoetz = '[mcp_servers.yoetz.tools.check]\napproval_mode = "prompt"\n'
    (project / ".codex" / "config.toml").write_text(
        CODEX_EXTERNAL_ADMISSION_TABLE + "\n" + edited_yoetz
    )

    status = project_mcp_leftover_status(home, project)

    assert status["project_mcp_leftover"] == "retained_tables"
    assert status["project_mcp_leftover_retained_servers"] == ["yoetz"]
    assert status["project_mcp_leftover_tools_only_servers"] == ["finishup"]
    step = cli._leftover_next_step(  # pyright: ignore[reportPrivateUsage]
        cli._rendered_status(status)  # pyright: ignore[reportPrivateUsage]
    )
    assert step is not None
    assert "[mcp_servers.yoetz] tables that FinishUP did not write" in step
    assert "[mcp_servers.finishup]" in step
    assert "--action revoke" in step
    assert "[mcp_servers.finishup] and [mcp_servers.yoetz]" not in step


def test_an_edited_finishup_table_beside_an_exact_yoetz_one_gives_no_wrong_command(
    tmp_path: Path,
) -> None:
    """The reverse mix: the revoke cannot edit a file holding edited FinishUP tables (so neither
    key's tables are its to remove), and connecting again restores only ``finishup``; the step
    names both keys and offers no command."""

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES
    from finishup.cli.codex_connection import project_mcp_leftover_status

    home, project = tmp_path / "home", tmp_path / "project"
    (project / ".codex").mkdir(parents=True, mode=0o700)
    home.mkdir(mode=0o700)
    (home / "config.toml").write_text("")
    edited_finishup = '[mcp_servers.finishup.tools.check]\napproval_mode = "prompt"\n'
    (project / ".codex" / "config.toml").write_text(
        edited_finishup + "\n" + CODEX_LEGACY_ADMISSION_TABLES[0]
    )

    status = project_mcp_leftover_status(home, project)

    assert status["project_mcp_leftover_retained_servers"] == ["finishup", "yoetz"]
    assert status["project_mcp_leftover_tools_only_servers"] == []
    assert "next_arguments" not in status
    step = cli._leftover_next_step(  # pyright: ignore[reportPrivateUsage]
        cli._rendered_status(status)  # pyright: ignore[reportPrivateUsage]
    )
    assert step is not None
    assert "[mcp_servers.finishup] and [mcp_servers.yoetz] tables" in step
    assert "Remove those tables from that file yourself" in step
    assert "None" not in step


def test_a_disconnect_kept_by_an_unread_input_says_why_and_names_the_way_out() -> None:
    """The disconnect keeps the registration when an input cannot be read (round 3); the plan
    says which, what makes it readable, and the explicit low-level removal."""

    lines = "\n".join(
        cli._admission_summary(  # pyright: ignore[reportPrivateUsage]
            {
                "action": "disconnect",
                "executable": "/opt/codex",
                "config_root": "/workspace/home",
                "admission_other_projects_unread": ["connected_projects_unreadable"],
                "mcp_removal_preview_arguments": [
                    "integrate",
                    "codex",
                    "mcp",
                    "preview-remove",
                    "--codex-path",
                    "/opt/codex",
                    "--codex-home",
                    "/workspace/home",
                ],
            }
        )
    )
    assert "could not read which projects it connected to this Codex home" in lines
    assert "/workspace/home/.yoetz-connected-projects.json" in lines
    assert "integrate codex mcp preview-remove --codex-path /opt/codex" in lines
    assert "your explicit choice" in lines
