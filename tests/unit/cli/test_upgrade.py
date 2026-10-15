from __future__ import annotations

import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest
from typer.testing import CliRunner

from finishup.adapters import package_upgrade as package_adapter
from finishup.application import upgrade
from finishup.application.package_update import PACKAGE_INSTALL_COMMAND
from finishup.cli.app import app

_RUNNER = CliRunner()
# ``[tool]`` lines uv records for --constraints, --overrides, --build-constraints, an index or
# find-links option, and a key this boundary does not know: each is a choice a rebuilt command
# would lose, so the receipt is not plain.
_RECORDED_RESOLUTION = (
    'constraints = [{name="openai",specifier="<2"}]',
    'overrides = [{name="openai",specifier="<2"}]',
    'build-constraint-dependencies = [{name="setuptools",specifier="<80"}]',
    'options = {index=["https://example.invalid/simple"]}',
    'excludes = ["openai"]',
    "constraints = []\nfuture-choice = true",
)
# Resolution keys present but empty record no choice.
_EMPTY_RESOLUTION = (
    "constraints = []",
    "overrides = []",
    "build-constraint-dependencies = []",
    "options = {}",
)
# The shape ``uv tool install --managed-python --python 3.14 '<name>[semantic-openai]'`` writes.
_REAL_RECEIPT = (
    '[tool]\nrequirements = [{{ name = "{name}", extras = ["semantic-openai"] }}]\n'
    'python = "3.14"\nentrypoints = [\n'
    '    {{ name = "{name}", install-path = "/var/home/u/.local/bin/{name}", from = "{name}" }},\n]\n'
)


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
        # A umask 0002 shell must not leave the replacement writable by the group.
        assert kwargs["umask"] == 0o022
        # Checked-hash bytecode the sealed generation can reuse; set for the child only.
        env = kwargs["env"]
        assert isinstance(env, dict)
        assert cast(dict[str, str], env).get("SOURCE_DATE_EPOCH")
        assert "SOURCE_DATE_EPOCH" not in os.environ
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


def test_cleanup_names_a_runtime_another_account_installed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from finishup.adapters.release_runtime import ReleaseRuntimeError

    def prune(_prefix: Path) -> tuple[int, int]:
        raise ReleaseRuntimeError("release_runtime_not_owned")

    monkeypatch.setattr("finishup.cli.upgrade.prune_release_runtimes", prune)
    result = _RUNNER.invoke(app, ["upgrade", "--prune-runtimes"])
    assert result.exit_code == 2
    assert result.stderr.startswith("release_runtime_not_owned: ")
    assert "could not safely complete" not in result.stderr


def test_upgrade_preserves_recorded_python_selection(tmp_path: Path) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\npython = "3.14.6"\n'
    )
    command = package_adapter._upgrade_command(tmp_path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command is not None
    assert command[4:7] == ("--compile-bytecode", "--python", "3.14.6")


def _uv_tool(root: Path, tool: str, requirement: str, extras: str = "") -> Path:
    prefix = root / tool
    prefix.mkdir(parents=True)
    (prefix / "uv-receipt.toml").write_text(
        f'[tool]\nrequirements = [{{name="{requirement}",specifier="==0.2.5"{extras}}}]\n'
    )
    return prefix


def _run_upgrade(
    monkeypatch: pytest.MonkeyPatch, root: Path, prefix: Path, reported: bytes = b"99.0.0\n"
) -> tuple[str, list[tuple[str, ...]]]:
    monkeypatch.setattr("finishup.config.paths.isolated_root", lambda: None)
    monkeypatch.setattr(package_adapter, "installation_prefix", lambda: prefix)
    calls: list[tuple[str, ...]] = []

    def run(argv: tuple[str, ...], **_kwargs: object) -> SimpleNamespace:
        calls.append(argv)
        if argv == ("uv", "tool", "dir"):
            return SimpleNamespace(returncode=0, stdout=str(root).encode())
        if argv[-1] == "--version":
            return SimpleNamespace(returncode=0, stdout=reported)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(package_adapter.subprocess, "run", run)
    return package_adapter.execute_package_upgrade(), calls


def test_legacy_yoetz_uv_tool_upgrades_in_place_through_its_own_name(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A tool installed before the rename keeps its name and launcher (ADR-048)."""

    root = tmp_path / "tools"
    prefix = _uv_tool(root, "yoetz", "yoetz", ',extras=["semantic-openai"]')

    outcome, calls = _run_upgrade(monkeypatch, root, prefix)

    assert outcome == "package_command_succeeded"
    install, verify = calls[1], calls[2]
    assert install[:4] == ("uv", "tool", "install", "--upgrade")
    assert install[-1] == f"yoetz[semantic-openai]>={package_adapter.__version__}"
    assert verify == (str(prefix / "bin/yoetz"), "--version")


def test_finishup_uv_tool_still_upgrades_through_finishup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "tools"
    prefix = _uv_tool(root, "finishup", "finishup")

    outcome, calls = _run_upgrade(monkeypatch, root, prefix)

    assert outcome == "package_command_succeeded"
    assert calls[1] == package_adapter.PACKAGE_UPGRADE_ARGV
    assert calls[2] == (str(prefix / "bin/finishup"), "--version")


@pytest.mark.parametrize(("tool", "requirement"), [("yoetz", "finishup"), ("finishup", "yoetz")])
def test_a_tool_whose_receipt_names_the_other_package_is_never_renamed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, tool: str, requirement: str
) -> None:
    root = tmp_path / "tools"
    prefix = _uv_tool(root, tool, requirement)

    outcome, calls = _run_upgrade(monkeypatch, root, prefix)

    assert outcome == "refused_custom_uv_installation"
    assert calls == [("uv", "tool", "dir")]


def test_a_tool_directory_with_another_name_is_not_a_supported_runtime(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "tools"
    prefix = _uv_tool(root, "yoetz-dev", "yoetz")

    outcome, calls = _run_upgrade(monkeypatch, root, prefix)

    assert outcome == "refused_non_uv_tool_runtime"
    assert calls == [("uv", "tool", "dir")]


def test_legacy_tool_with_an_unparsable_alias_version_is_unverified(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    root = tmp_path / "tools"
    prefix = _uv_tool(root, "yoetz", "yoetz")

    outcome, _calls = _run_upgrade(monkeypatch, root, prefix, reported=b"notice: renamed\n")

    assert outcome == "package_version_unverified"


def test_alias_plan_names_the_alias_and_the_way_off_it() -> None:
    steps = upgrade.build_upgrade_plan(["codex"], {}, launcher="yoetz")

    commands = [argv for step in steps for argv in step.commands]
    assert commands and all(argv[0] == "yoetz" for argv in commands)
    assert "Run yoetz upgrade --accept" in steps[1].detail
    move = steps[-1]
    assert move.title == "Move from the yoetz name"
    assert move.commands == ()
    assert (
        f"install the new name: {PACKAGE_INSTALL_COMMAND}. Its extras could not be confirmed"
        in (move.detail)
    )
    assert "for example 'finishup[semantic-openai]'." in move.detail
    assert "also works as yoetz with the same subcommand" in move.detail
    assert "uv tool uninstall yoetz" in move.detail
    # A Codex registration kept under the earlier name still starts the old tool, so the move
    # names the status check before the uninstall.
    status_check = move.detail.index("finishup setup status --host codex")
    assert status_check < move.detail.index("uv tool uninstall yoetz")


@pytest.mark.parametrize(
    ("extras", "package"),
    [
        ((), "finishup"),
        (("semantic-openai",), "'finishup[semantic-openai]'"),
        (
            ("portable-recovery", "semantic-openai"),
            "'finishup[portable-recovery,semantic-openai]'",
        ),
    ],
)
def test_alias_move_step_installs_the_managed_python_pin_with_recorded_extras(
    extras: tuple[str, ...], package: str
) -> None:
    steps = upgrade.build_upgrade_plan(["codex"], {}, launcher="yoetz", legacy_extras=extras)

    move = steps[-1]
    assert (
        "install the new name: uv tool install --compile-bytecode --managed-python --python 3.14.6 "
        + package
        + "."
    ) in move.detail
    assert "could not be confirmed" not in move.detail


def test_alias_move_step_refuses_unknown_extras() -> None:
    with pytest.raises(ValueError, match="upgrade_extras_invalid"):
        upgrade.build_upgrade_plan(["codex"], {}, launcher="yoetz", legacy_extras=("dev",))


@pytest.mark.parametrize(
    ("receipt", "expected"),
    [
        ('[tool]\nrequirements = [{name="yoetz"}]\n', ()),
        ('[tool]\nrequirements = [{name="yoetz",specifier=">=0.3.0"}]\n', ()),
        (
            '[tool]\nrequirements = [{name="yoetz",extras=["semantic-openai",'
            '"portable-recovery","semantic-openai"]}]\n',
            ("portable-recovery", "semantic-openai"),
        ),
        ('[tool]\nrequirements = [{name="finishup"}]\n', None),
        ('[tool]\nrequirements = [{name="yoetz",extras=["dev"]}]\n', None),
        ('[tool]\nrequirements = [{name="yoetz",extras="semantic-openai"}]\n', None),
        ('[tool]\nrequirements = [{name="yoetz",editable="."}]\n', None),
        ('[tool]\nrequirements = [{name="yoetz"},{name="openai"}]\n', None),
        ('[tool]\nrequirements = [{name="yoetz"}]\noptions = {index=["x"]}\n', None),
        *(
            (f'[tool]\nrequirements = [{{name="yoetz"}}]\n{line}\n', None)
            for line in _RECORDED_RESOLUTION
        ),
        *(
            (
                f'[tool]\nrequirements = [{{name="yoetz",extras=["semantic-openai"]}}]\n{line}\n',
                ("semantic-openai",),
            )
            for line in _EMPTY_RESOLUTION
        ),
        (_REAL_RECEIPT.format(name="yoetz"), ("semantic-openai",)),
        (_REAL_RECEIPT.format(name="yoetz") + '[tool.options]\nfind-links = ["file:///x"]\n', None),
        ('[tool]\nrequirements = ["yoetz"]\n', None),
        ('[tool]\nrequirements = "yoetz"\n', None),
        ('tool = "yoetz"\n', None),
        ("[tool\n", None),
        ("", None),
    ],
)
def test_legacy_tool_extras_reads_only_a_plain_yoetz_receipt(
    receipt: str, expected: tuple[str, ...] | None
) -> None:
    assert upgrade.legacy_tool_extras(receipt) == expected


def test_finishup_plan_has_no_migration_step_and_rejects_other_launchers() -> None:
    steps = upgrade.build_upgrade_plan(["codex"], {})
    assert all(step.title != "Move from the yoetz name" for step in steps)
    assert "Run finishup upgrade --accept" in steps[1].detail
    with pytest.raises(ValueError, match="upgrade_launcher_invalid"):
        upgrade.build_upgrade_plan(["codex"], {}, launcher="python")


def test_upgrade_run_through_the_alias_plans_with_the_alias(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An upgraded ``yoetz`` tool has no ``finishup`` on PATH, so its plan names ``yoetz``."""

    monkeypatch.setattr("sys.argv", ["/var/home/user/.local/bin/yoetz", "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    assert "  yoetz upgrade --accept" in result.output
    assert "  finishup " not in result.output
    assert "Move from the yoetz name" in result.output
    assert PACKAGE_INSTALL_COMMAND in result.output


def test_alias_upgrade_carries_the_yoetz_tool_extras_into_the_move(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prefix = _uv_tool(tmp_path / "tools", "yoetz", "yoetz", ',extras=["semantic-openai"]')
    monkeypatch.setattr("finishup.cli.upgrade.installation_prefix", lambda: prefix)
    monkeypatch.setattr("sys.argv", [str(prefix / "bin/yoetz"), "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    assert "--python 3.14.6 'finishup[semantic-openai]'." in " ".join(result.output.split())
    assert "could not be confirmed" not in result.output


def test_alias_upgrade_with_an_unreadable_receipt_says_to_re_add_extras(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    prefix = _uv_tool(tmp_path / "tools", "yoetz", "yoetz", ',editable="."')
    monkeypatch.setattr("finishup.cli.upgrade.installation_prefix", lambda: prefix)
    monkeypatch.setattr("sys.argv", [str(prefix / "bin/yoetz"), "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert (
        f"install the new name: {PACKAGE_INSTALL_COMMAND}. Its extras could not be confirmed"
        in output
    )
    assert "for example 'finishup[semantic-openai]'." in output


def test_finishup_upgrade_never_reads_a_tool_receipt(monkeypatch: pytest.MonkeyPatch) -> None:
    def unexpected() -> Path:
        raise AssertionError("receipt read for a finishup run")

    monkeypatch.setattr("finishup.cli.upgrade.installation_prefix", unexpected)
    monkeypatch.setattr("sys.argv", ["/var/home/user/.local/bin/finishup", "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output


def test_accepted_alias_upgrade_continues_with_the_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["/var/home/user/.local/bin/yoetz", "upgrade", "--accept"])
    monkeypatch.setattr(
        "finishup.cli.upgrade.execute_package_upgrade", lambda: "package_command_succeeded"
    )
    result = _RUNNER.invoke(app, ["upgrade", "--accept"])

    assert result.exit_code == 0, result.output
    assert "Re-run yoetz upgrade with the same target options" in result.output


def test_upgrade_run_through_finishup_plans_with_finishup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.argv", ["/var/home/user/.local/bin/finishup", "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    assert "  finishup upgrade --accept" in result.output
    assert "  yoetz " not in result.output
    assert "Move from the yoetz name" not in result.output


@pytest.mark.parametrize("line", _RECORDED_RESOLUTION)
def test_in_place_upgrade_refuses_any_recorded_resolution_choice(tmp_path: Path, line: str) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        f'[tool]\nrequirements = [{{name="finishup",extras=["semantic-openai"]}}]\n{line}\n'
    )
    assert package_adapter._upgrade_command(tmp_path) is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize("line", _EMPTY_RESOLUTION)
def test_in_place_upgrade_accepts_empty_resolution_keys(tmp_path: Path, line: str) -> None:
    (tmp_path / "uv-receipt.toml").write_text(
        f'[tool]\nrequirements = [{{name="finishup",extras=["semantic-openai"]}}]\n{line}\n'
    )
    command = package_adapter._upgrade_command(tmp_path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command is not None
    assert command[-1] == f"finishup[semantic-openai]>={package_adapter.__version__}"


@pytest.mark.parametrize("name", ["finishup", "yoetz"])
def test_in_place_upgrade_reads_a_real_uv_receipt(tmp_path: Path, name: str) -> None:
    (tmp_path / "uv-receipt.toml").write_text(_REAL_RECEIPT.format(name=name))
    command = package_adapter._upgrade_command(tmp_path, name)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command == (
        "uv",
        "tool",
        "install",
        "--upgrade",
        "--compile-bytecode",
        "--python",
        "3.14",
        f"{name}[semantic-openai]>={package_adapter.__version__}",
    )


def test_receipt_extras_are_one_shared_set() -> None:
    """Planning the move and upgrading in place accept exactly the same extras."""

    assert frozenset({"semantic-openai", "portable-recovery"}) == package_adapter.PACKAGE_EXTRAS
    assert upgrade.PACKAGE_EXTRAS is package_adapter.PACKAGE_EXTRAS


def _unsafe_receipt(prefix: Path, kind: str) -> None:
    receipt = prefix / "uv-receipt.toml"
    if kind == "symlink":
        target = prefix / "elsewhere.toml"
        target.write_text('[tool]\nrequirements = [{name="yoetz",extras=["semantic-openai"]}]\n')
        receipt.symlink_to(target)
    elif kind == "fifo":
        os.mkfifo(receipt)
    elif kind == "directory":
        receipt.mkdir()
    elif kind == "oversized":
        body = '[tool]\nrequirements = [{name="yoetz",extras=["semantic-openai"]}]\n'
        receipt.write_text(body + "#" * (package_adapter.UV_RECEIPT_MAX_BYTES + 1 - len(body)))
    elif kind == "not_utf8":
        receipt.write_bytes(b'[tool]\nrequirements = [{name="yoetz"}]\n# \xff\n')
    elif kind == "missing":
        pass
    else:  # pragma: no cover - parametrize guard
        raise AssertionError(kind)


_UNSAFE_RECEIPTS = ("symlink", "fifo", "directory", "oversized", "not_utf8", "missing")


@pytest.mark.parametrize("kind", _UNSAFE_RECEIPTS)
def test_receipt_read_refuses_anything_but_a_bounded_regular_file(
    tmp_path: Path, kind: str
) -> None:
    _unsafe_receipt(tmp_path, kind)
    with pytest.raises((OSError, ValueError)):
        package_adapter.read_uv_receipt(tmp_path)
    assert package_adapter._upgrade_command(tmp_path, "yoetz") is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]


def test_receipt_read_accepts_a_receipt_at_the_size_limit(tmp_path: Path) -> None:
    body = '[tool]\nrequirements = [{name="yoetz",extras=["semantic-openai"]}]\n'
    padded = body + "#" * (package_adapter.UV_RECEIPT_MAX_BYTES - len(body))
    (tmp_path / "uv-receipt.toml").write_text(padded)
    assert package_adapter.read_uv_receipt(tmp_path) == padded


@pytest.mark.parametrize("kind", _UNSAFE_RECEIPTS)
def test_alias_plan_with_an_unsafe_receipt_falls_back_without_blocking(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, kind: str
) -> None:
    prefix = tmp_path / "tools" / "yoetz"
    prefix.mkdir(parents=True)
    _unsafe_receipt(prefix, kind)
    monkeypatch.setattr("finishup.cli.upgrade.installation_prefix", lambda: prefix)
    monkeypatch.setattr("sys.argv", [str(prefix / "bin/yoetz"), "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert f"install the new name: {PACKAGE_INSTALL_COMMAND}. Its extras could not be" in output
    assert "for example 'finishup[semantic-openai]'." in output


@pytest.mark.parametrize("line", _RECORDED_RESOLUTION)
def test_alias_plan_with_recorded_resolution_says_to_re_add_choices(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, line: str
) -> None:
    prefix = tmp_path / "tools" / "yoetz"
    prefix.mkdir(parents=True)
    (prefix / "uv-receipt.toml").write_text(
        f'[tool]\nrequirements = [{{name="yoetz",extras=["semantic-openai"]}}]\n{line}\n'
    )
    monkeypatch.setattr("finishup.cli.upgrade.installation_prefix", lambda: prefix)
    monkeypatch.setattr("sys.argv", [str(prefix / "bin/yoetz"), "upgrade"])
    result = _RUNNER.invoke(app, ["upgrade"])

    assert result.exit_code == 0, result.output
    output = " ".join(result.output.split())
    assert "Its extras could not be confirmed" in output
    assert f"install the new name: {PACKAGE_INSTALL_COMMAND}." in output


def test_documented_compile_bytecode_install_upgrades_and_keeps_bytecode(tmp_path: Path) -> None:
    # `uv tool install --compile-bytecode` records the option in the receipt; it is the
    # documented install, not a custom resolution to refuse.
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\npython = "3.14.6"\n'
        "[tool.options]\ncompile-bytecode = true\n"
    )
    command = package_adapter._upgrade_command(tmp_path)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
    assert command is not None
    assert "--compile-bytecode" in command
    (tmp_path / "uv-receipt.toml").write_text(
        '[tool]\nrequirements = [{name="finishup"}]\n'
        '[tool.options]\ncompile-bytecode = true\nindex-url = "https://example.invalid"\n'
    )
    assert package_adapter._upgrade_command(tmp_path) is None  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
