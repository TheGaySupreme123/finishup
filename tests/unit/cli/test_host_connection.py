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


def _select(monkeypatch: pytest.MonkeyPatch, host: str, root: Path) -> None:
    from typing import cast

    from yoetz.adapters.integrations.host_discovery import SetupHost

    installation = HostInstallation(cast(SetupHost, host), Path("/opt/host"), "1.0.0", root, "Host")

    def selected(*_args: object) -> HostInstallation:
        return installation

    def no_leftover(*_args: object) -> dict[str, object]:
        return {}

    monkeypatch.setattr(cli, "select_installation", selected)
    monkeypatch.setattr(cli, "_codex_leftover", no_leftover)


def _damaged_record(root: Path) -> Path:
    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

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

    from yoetz.application.host_connection import ConnectionError as SetupConnectionError
    from yoetz.ports.integrations import IntegrationError, IntegrationReason
    from yoetz.tui.runtime import RuntimeError_

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
    from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE
    from yoetz.tui.runtime import RuntimeError_

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

    from yoetz.tui.runtime import RuntimeError_

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
        '[mcp_servers.yoetz]\ncommand = "yoetz"\n'
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
    assert "/work/maybe (may use Yoetz)" in joined
    assert "missing right now" in joined and "/work/away" in joined
    assert "binding moves to /work/next" in joined
