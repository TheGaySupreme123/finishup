from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from finishup.adapters import package_upgrade as package_adapter
from finishup.application import upgrade
from finishup.cli.app import app

_RUNNER = CliRunner()


def test_plan_does_not_execute_package_or_infer_host_roots(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected() -> str:
        raise AssertionError("package execution without acceptance")

    monkeypatch.setattr("finishup.cli.upgrade.execute_package_upgrade", unexpected)
    result = _RUNNER.invoke(app, ["upgrade"])
    assert result.exit_code == 0, result.output
    assert "Plan only" in result.output
    for host in upgrade.HOSTS:
        assert f"{host}: select existing target" in result.output
    assert "Expanded review" in result.output


@pytest.mark.parametrize("legacy_flag", [False, True])
def test_acceptance_runs_while_sessions_keep_working(
    monkeypatch: pytest.MonkeyPatch, legacy_flag: bool
) -> None:
    """Nothing has to be stopped first; open sessions switch when they are reopened (#820)."""

    calls: list[bool] = []

    def execute() -> str:
        calls.append(True)
        return "package_command_succeeded"

    monkeypatch.setattr("finishup.cli.upgrade.execute_package_upgrade", execute)
    argv = ["upgrade", "--accept"] + (["--writers-stopped"] if legacy_flag else [])
    result = _RUNNER.invoke(app, argv)
    assert result.exit_code == 0, result.output
    assert calls == [True]
    assert "upgrade_writers_must_be_stopped" not in result.output
    assert "Open sessions keep working on the previous version" in result.output
    assert "retires the previous service automatically" in result.output


def test_plan_never_asks_to_stop_hosts_or_service() -> None:
    steps = upgrade.build_upgrade_plan(["codex"], {})
    text = "\n".join(step.detail for step in steps)
    assert "Nothing needs to be stopped" in text
    assert "--writers-stopped" not in text
    assert "stop the service" not in text
    replace = next(step for step in steps if step.title == "Replace the package")
    assert replace.commands == (("finishup", "upgrade", "--accept"),)
    assert "finishup upgrade --accept only" in replace.detail
    help_result = _RUNNER.invoke(app, ["upgrade", "--help"])
    assert help_result.exit_code == 0
    assert "--writers-stopped" not in help_result.output


@pytest.mark.parametrize(
    "outcome, code",
    [("package_command_succeeded", 0), ("package_command_failed", 2), ("outcome_unknown", 2)],
)
def test_package_result_never_claims_host_or_data_upgrade(
    monkeypatch: pytest.MonkeyPatch, outcome: str, code: int
) -> None:
    calls: list[bool] = []

    def execute() -> str:
        calls.append(True)
        return outcome

    monkeypatch.setattr("finishup.cli.upgrade.execute_package_upgrade", execute)
    result = _RUNNER.invoke(app, ["upgrade", "--accept"])
    assert result.exit_code == code
    assert calls == [True]
    assert outcome in result.output
    if code == 0:
        assert "Host refresh, migration and activation remain unverified" in result.output


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_native_plan_preserves_explicit_paths_and_profiles(host: str) -> None:
    options = {
        "project-root": "/project with spaces",
        "claude-path": "/bin/claude",
        "claude-config-root": "/fixture/claude-home",
        "cache-root": "/cache/claude",
        "marketplace-root": "/market/claude",
        "cursor-config-root": "/fixture/cursor-home",
        "mcp-ownership": "plugin-managed",
        "route-profile": "strict",
        "observation-profile": "ordinary",
    }
    steps = upgrade.build_upgrade_plan([host], options)
    stage = next(step for step in steps if step.title == f"{host}: refresh installed plugin")
    assert stage.cwd == "/project with spaces"
    for command in stage.commands:
        assert command[command.index("--project-root") + 1] == "/project with spaces"
        assert command[command.index("--route-profile") + 1] == "strict"
        assert command[command.index("--observation-profile") + 1] == "ordinary"
        assert "--accept" not in command
        assert "<preview_digest>" not in command
        result = _RUNNER.invoke(app, [*command[1:], "--help"])
        assert result.exit_code == 0, result.output
    assert stage.commands[1][-3:-1] == ("--action", "update" if host == "claude" else "replace")


def test_codex_plan_has_no_invented_plugin_update_or_general_setup() -> None:
    steps = upgrade.build_upgrade_plan(
        ["codex"],
        {
            "project-root": "/project",
            "codex-path": "/bin/codex",
            "codex-home": "/fixture/codex-home",
        },
    )
    stage = next(step for step in steps if step.title.startswith("codex: refresh"))
    assert stage.environment == (
        ("CODEX_HOME", "/fixture/codex-home"),
        ("CODEX_TESTING_HOME", "/fixture/codex-home"),
    )
    assert stage.commands[-1][-2:] == ("--codex-home", "/fixture/codex-home")
    for command in stage.commands:
        assert "setup" not in command
        assert "update" not in command
        assert _RUNNER.invoke(app, [*command[1:], "--help"]).exit_code == 0


def test_existing_task_upgrade_uses_normal_startup_and_status() -> None:
    steps = upgrade.build_upgrade_plan(["codex"], {})
    data_step = next(step for step in steps if step.title == "Data and service")
    assert data_step.commands == (("finishup", "service", "status", "--json"),)
    assert "upgrade automatically" in data_step.detail
    assert "Existing tasks, settings and permissions are retained" in data_step.detail
    assert "resumes the recorded upgrade" in data_step.detail


def test_invalid_targets_fail_before_execution() -> None:
    with pytest.raises(ValueError, match="upgrade_target_must_be_absolute"):
        upgrade.build_upgrade_plan(["cursor"], {"project-root": "relative"})
    with pytest.raises(ValueError, match="upgrade_option_invalid"):
        upgrade.build_upgrade_plan(["cursor"], {"project-root": "/safe\ninjected"})


def test_isolated_runtime_cannot_upgrade_ambient_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("finishup.config.paths.isolated_root", lambda: tmp_path)

    def unexpected(*args: object, **kwargs: object) -> object:
        raise AssertionError("uv must not run from isolated runtime")

    monkeypatch.setattr(package_adapter.subprocess, "run", unexpected)
    assert package_adapter.execute_package_upgrade() == "refused_isolated_runtime"


@pytest.mark.parametrize("matched", [False, True])
def test_package_execution_binds_invoking_uv_tool(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, matched: bool
) -> None:
    root = tmp_path / "tools"
    (root / "finishup").mkdir(parents=True)
    (root / "finishup/uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup",specifier="==0.2.1"}]\n'
    )
    monkeypatch.setattr("finishup.config.paths.isolated_root", lambda: None)
    monkeypatch.setattr(
        package_adapter,
        "installation_prefix",
        lambda: root / "finishup" if matched else tmp_path / "source",
    )
    calls: list[tuple[str, ...]] = []

    def run(argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        assert kwargs["stdin"] == subprocess.DEVNULL
        if argv == ("uv", "tool", "dir"):
            return SimpleNamespace(returncode=0, stdout=str(root).encode())
        if argv == (str(root / "finishup/bin/finishup"), "--version"):
            return SimpleNamespace(returncode=0, stdout=b"99.0.0\n")
        assert argv == package_adapter.PACKAGE_UPGRADE_ARGV
        assert kwargs["stdout"] == subprocess.DEVNULL
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(package_adapter.subprocess, "run", run)
    assert package_adapter.execute_package_upgrade() == (
        "package_command_succeeded" if matched else "refused_non_uv_tool_runtime"
    )
    assert len(calls) == (3 if matched else 1)


def test_package_timeout_reports_unknown_without_retry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr("finishup.config.paths.isolated_root", lambda: None)
    monkeypatch.setattr(package_adapter, "installation_prefix", lambda: tmp_path / "finishup")
    (tmp_path / "finishup").mkdir()
    (tmp_path / "finishup/uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\n'
    )
    calls: list[tuple[str, ...]] = []

    def run(argv: tuple[str, ...], **kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        if argv == ("uv", "tool", "dir"):
            return SimpleNamespace(returncode=0, stdout=str(tmp_path).encode())
        raise subprocess.TimeoutExpired(argv, 120)

    monkeypatch.setattr(package_adapter.subprocess, "run", run)
    assert package_adapter.execute_package_upgrade() == "outcome_unknown"
    assert calls == [("uv", "tool", "dir"), package_adapter.PACKAGE_UPGRADE_ARGV]


def test_upgrade_replaces_exact_pin_and_preserves_supported_extras(tmp_path: Path) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup",specifier="==0.2.1",extras=["semantic-openai"]}]\n'
    )
    command = package_adapter._upgrade_command(tmp_path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command is not None
    assert command[:4] == ("uv", "tool", "install", "--upgrade")
    assert command[-1].startswith("finishup[semantic-openai]>=")
    assert "0.2.1" not in command[-1]


def test_custom_resolution_is_not_silently_replaced(tmp_path: Path) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\n[tool.options]\nno-index = true\n'
    )
    assert package_adapter._upgrade_command(tmp_path) is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_same_version_is_not_reported_as_an_installed_update(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "finishup.cli.upgrade.execute_package_upgrade", lambda: "package_already_current"
    )
    result = _RUNNER.invoke(app, ["upgrade", "--accept"])
    assert result.exit_code == 0
    assert "No newer version was installed" in result.output
    assert "Package step: package_command_succeeded" not in result.output


def test_cleanup_never_executes_a_package_upgrade(monkeypatch: pytest.MonkeyPatch) -> None:
    def prune(_prefix: Path) -> tuple[int, int]:
        return (2, 1)

    monkeypatch.setattr("finishup.cli.upgrade.prune_release_runtimes", prune)

    def unexpected() -> str:
        raise AssertionError("cleanup is not an installation")

    monkeypatch.setattr("finishup.cli.upgrade.execute_package_upgrade", unexpected)
    result = _RUNNER.invoke(app, ["upgrade", "--prune-runtimes"])
    assert result.exit_code == 0
    assert "Removed 2 unused runtime copies; kept 1 in use" in result.output
    result = _RUNNER.invoke(app, ["upgrade", "--prune-runtimes", "--accept"])
    assert result.exit_code == 2


def test_upgrade_preserves_recorded_python_selection(tmp_path: Path) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\npython = "3.14.6"\n'
    )
    command = package_adapter._upgrade_command(tmp_path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command is not None
    assert command[4:6] == ("--python", "3.14.6")
