import json
from pathlib import Path

import pytest

from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import ConnectionPlan
from finishup.cli import host_connection as cli
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
