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


@pytest.mark.parametrize("host", ["codex", "claude", "cursor-cli"])
def test_connect_preflight_names_a_runtime_another_account_installed(
    prepared: ConnectionPlan,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    """Every host would launch a runtime that cannot serve this account: refuse by name."""

    from yoetz.adapters import release_runtime

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
    assert "must belong to the account running Yoetz" in report["next_step"]
    assert "plan" not in report


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


# --- Every connect path refuses a runtime that cannot serve this account -------------------


def _runtime_cannot_serve(monkeypatch: pytest.MonkeyPatch) -> None:
    from yoetz.adapters import release_runtime

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

    import yoetz.cli.setup as setup
    from yoetz.adapters.integrations import host_discovery

    _runtime_cannot_serve(monkeypatch)
    monkeypatch.setattr(host_discovery, "discover_hosts", lambda: ())
    from yoetz.ports.harness_mcp import HarnessBinary, HarnessId

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
        "must belong to the account running Yoetz" in str(step) for step in report["next_steps"]
    )


def test_apply_selected_refuses_a_connect_but_never_a_disconnect(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The guard every front end's connect passes through, the TUI's included."""

    from types import SimpleNamespace

    from yoetz.application.host_connection import ConnectionError

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
