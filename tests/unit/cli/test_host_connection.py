import json
from pathlib import Path

import pytest

from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.application.host_connection import ConnectionPlan
from yoetz.cli import host_connection as cli
from yoetz.protocol.host_connection import HostConnectionReport
from yoetz.service.elevated_bootstrap import ElevatedBootstrapError

REQUEST = "req_cc8c2c7e-1246-4ed2-9e48-05a69fbb1d90"
DIGEST = "sha256:" + "a" * 64


@pytest.fixture
def prepared(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ConnectionPlan:
    launcher = tmp_path / "yoetz"
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


def test_launch_preserves_the_selected_yoetz_runtime_on_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from yoetz.adapters.integrations.host_discovery import HostInstallation
    from yoetz.cli import host_connection

    monkeypatch.setattr(host_connection, "invoking_launcher", lambda: "/opt/instance/bin/yoetz")

    def resolve(_value: object) -> tuple[str, ...]:
        return ("/opt/instance/bin/yoetz",)

    monkeypatch.setattr(host_connection, "resolve_yoetz_launcher", resolve)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    selected = HostInstallation(
        "codex", Path("/opt/codex"), "0.153.4", Path("/workspace/profile"), "Codex"
    )
    launch = host_connection.launch_details(selected, Path("/workspace/project"))
    environment = launch["environment"]
    assert isinstance(environment, dict)
    assert environment["PATH"] == "/opt/instance/bin:/usr/bin:/bin"


@pytest.mark.parametrize("host", ["claude", "cursor-ide", "cursor-cli", "codex"])
def test_setup_keeps_os_password_ceremony_on_main_thread(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, host: str
) -> None:
    import threading

    import anyio

    from yoetz.cli.setup import run_setup_wizard

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


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-cli"])
def test_failed_connection_names_a_runtime_another_account_can_write(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    import yoetz.cli.runtime_refusal as refusal
    from yoetz.ports.plugin_artifacts import PluginArtifactError, PluginArtifactReason

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


def test_connect_preflight_refuses_but_disconnect_and_status_proceed(
    prepared: ConnectionPlan, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import yoetz.cli.runtime_refusal as refusal

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


def test_lock_unavailable_says_nothing_changed_and_names_the_lock_folder(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """#1058: a setup lock that cannot be taken is not a partial connection."""

    from yoetz.adapters.integrations import host_projects
    from yoetz.application.host_connection import ConnectionError as SetupConnectionError

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


@pytest.mark.parametrize("host", ["cursor-ide", "codex"])
def test_invalid_projects_record_names_the_file_and_the_way_out(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    host: str,
) -> None:
    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE
    from yoetz.application.host_connection import ConnectionError as SetupConnectionError
    from yoetz.ports.integrations import IntegrationError, IntegrationReason

    def invalid(*_args: object, **_kwargs: object):
        if host == "codex":
            raise IntegrationError(
                IntegrationReason.SOURCE_INVALID, {"conflict": "connected_projects"}
            )
        raise SetupConnectionError("connection_projects_record_invalid")

    monkeypatch.setattr(cli, "prepare_selected", invalid)

    def no_leftover(*_args: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr(cli, "_codex_leftover", no_leftover)
    root = tmp_path / "config"
    code = cli.run_host_connection(
        host=host,
        executable=None,
        config_root=root,
        project=Path("/workspace/example/project"),
        action="disconnect",
        json_output=True,
    )
    assert code == 1
    report = json.loads(capsys.readouterr().out)
    HostConnectionReport.model_validate(report)
    step = report["next_step"]
    assert step.startswith("Nothing was changed.")
    assert str(root / CONNECTED_PROJECTS_FILE) in step
    assert "remove" in step and "unknown" in step
