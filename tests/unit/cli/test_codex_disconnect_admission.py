"""Guided disconnect sweeps the project's host admission before the registration goes.

Regression for the macOS Codex 0.162.1 finding: ``setup disconnect --host codex --project P``
removed the user-level ``[mcp_servers.yoetz]`` transport but left P's
``[mcp_servers.yoetz.tools.check]`` admission table, after which Codex refused to load its
configuration inside P (``invalid transport in `mcp_servers.yoetz```), the removal verification
failed as ``connection_outcome_unknown`` and the planned project-skill removal never ran.
"""

from __future__ import annotations

import subprocess
import tomllib
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from yoetz.adapters.integrations import codex_mcp
from yoetz.adapters.integrations.codex_marketplace import RemovalOutcome
from yoetz.adapters.integrations.codex_mcp import (
    CodexMcpAdapter,
    CommandOutput,
    codex_project_mcp_leftover,
    probe_project_config_load,
)
from yoetz.adapters.integrations.host_admission import (
    CODEX_EXTERNAL_ADMISSION_TABLE,
    CODEX_PLUGIN_ADMISSION_TABLE,
    HostAdmissionAction,
    apply_host_admission,
    preview_host_admission,
)
from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.application.host_connection import (
    AdmissionCleanupStep,
    ConnectionError,
    apply_connection,
    prepare_connection,
)
from yoetz.cli import codex_connection
from yoetz.cli.host_connection import connection_summary
from yoetz.domain.values import request_id
from yoetz.ports.integrations import IntegrationState
from yoetz.ports.plugin_artifacts import ArtifactAuthority
from yoetz.protocol.schemas import validate_schema_instance

REQUEST = "req_52e989dd-b118-4f49-a359-707a6b32bfa4"
DIGEST = "sha256:" + "a" * 64
ENTRY = b'{"command":"yoetz","args":["mcp","serve","--host","codex"]}'


class FakeCodex:
    """Models Codex's merged config load: a transport-less project table fails every command."""

    def __init__(self, home: Path, project: Path, *, registered: bool = True) -> None:
        self.home = home
        self.project = project
        self.registered = registered
        self.calls: list[tuple[str, ...]] = []

    def loads(self) -> bool:
        path = self.project / ".codex" / "config.toml"
        if self.registered or not path.exists():
            return True
        servers = tomllib.loads(path.read_text()).get("mcp_servers", {})
        return "yoetz" not in servers

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        if not self.loads():
            # The shell that runs `yoetz setup disconnect` usually sits inside the project.
            return CommandOutput(1, b"")
        if argv[1:3] == ("mcp", "remove"):
            self.registered = False
            return CommandOutput(0, b"")
        if argv[1:3] == ("mcp", "get"):
            return CommandOutput(0, ENTRY) if self.registered else CommandOutput(1, b"")
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return CommandOutput(1, b"")


def _items(value: object) -> list[Any]:
    assert isinstance(value, list)
    return cast(list[Any], value)


def _grant(project: Path) -> None:
    preview = preview_host_admission(
        "codex",
        project,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
    )
    apply_host_admission(preview, project, accepted_preview_digest=preview.preview_digest)
    assert (project / ".codex" / "config.toml").read_text() == CODEX_EXTERNAL_ADMISSION_TABLE


def _wire(
    monkeypatch: pytest.MonkeyPatch,
    fake: FakeCodex,
    cleanup: list[str],
    *,
    plugin: RemovalOutcome = RemovalOutcome.ALREADY_ABSENT,
    skill: IntegrationState = IntegrationState.INSTALLED_EXACT,
) -> None:
    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(fake)

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(preview_digest=DIGEST, outcome=plugin)

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(preview_digest=DIGEST, state_before=skill)

        async def remove_skill(self, *_args: object) -> None:
            cleanup.append("skill")

    def probe(_executable: str, _home: Path | None, _project: Path) -> str:
        return "loads" if fake.loads() else "fails"

    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "probe_project_config_load", probe)


def _layout(tmp_path: Path) -> tuple[Path, Path, HostInstallation]:
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.162.1", home, "Codex Testing"
    )
    return home, project, installation


def _plan(installation: HostInstallation, project: Path):
    return codex_connection.prepare_codex_connection(
        installation, project, action="disconnect", route="strict", request_value=REQUEST
    )


def test_disconnect_sweeps_admission_before_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    _grant(project)
    fake, cleanup = FakeCodex(home, project), list[str]()
    _wire(monkeypatch, fake, cleanup)

    plan = _plan(installation, project)
    assert plan.body["changes"] == [
        "remove_mcp_registration",
        "remove_project_skill",
        "remove_project_admission",
    ]
    cleanup_plan = plan.disclosure["admission_cleanup"]
    assert isinstance(cleanup_plan, dict) and cleanup_plan["state"] == "present"
    assert any("removed first" in line for line in connection_summary(plan))
    # The released plan schema stays closed; the cleanup is digest-bound disclosure.
    validate_schema_instance("host-connection", "1.0.0", plan.body)

    plan.apply_reviewed_steps()
    status = plan.status()
    assert status["admission_cleanup"] == {
        "host": "codex",
        "outcome": "removed",
        "surfaces_changed": [".codex/config.toml"],
    }
    removal = status["mcp_removal"]
    assert isinstance(removal, dict) and removal["outcome"] == "completed"
    assert status["project_config_load"] == "loads"
    assert cleanup == ["skill"]
    assert not (project / ".codex" / "config.toml").exists()
    assert fake.loads()


def test_repeat_disconnect_repairs_tools_only_leftover(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    _grant(project)
    fake, cleanup = FakeCodex(home, project, registered=False), list[str]()
    assert not fake.loads()
    assert codex_project_mcp_leftover(home, project) == "tools_only"
    # User-scope probes run from the Codex home, so the leftover cannot fail the preview.
    fake_neutral = FakeCodex(home, tmp_path / "elsewhere", registered=False)
    _wire(monkeypatch, fake_neutral, cleanup, skill=IntegrationState.ABSENT)

    plan = _plan(installation, project)
    assert plan.body["changes"] == ["remove_project_admission"]
    plan.apply_reviewed_steps()
    assert plan.status()["admission_cleanup"] == {
        "host": "codex",
        "outcome": "removed",
        "surfaces_changed": [".codex/config.toml"],
    }
    assert fake.loads()
    assert codex_project_mcp_leftover(home, project) is None


def test_retained_foreign_table_refuses_before_any_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CHECK_DISCONNECT_R1 P2-b: a retained table that needs the transport stops the plan."""

    home, project, installation = _layout(tmp_path)
    (project / ".codex").mkdir(mode=0o700)
    # A non-exact (foreign) table Yoetz does not own and therefore retains.
    (project / ".codex" / "config.toml").write_text(
        '[mcp_servers.yoetz.tools.status]\napproval_mode = "approve"\n'
    )
    cleanup = list[str]()
    fake = FakeCodex(home, tmp_path / "elsewhere")
    _wire(monkeypatch, fake, cleanup, skill=IntegrationState.ABSENT)

    with pytest.raises(ConnectionError, match="connection_project_mcp_tables_retained") as caught:
        _plan(installation, project)

    status = caught.value.status
    assert status is not None
    assert status["project_mcp_retained"] == str(project / ".codex" / "config.toml")
    assert fake.registered
    assert not any(call[1:3] == ("mcp", "remove") for call in fake.calls)
    # Status keeps naming the conflict while the project still loads (the user-level
    # registration is still present).
    (home / "config.toml").write_text('[mcp_servers.yoetz]\ncommand = "yoetz"\n')
    assert codex_connection.project_mcp_leftover_status(home, project) == {
        "project_mcp_needs_registration": True
    }


@pytest.mark.parametrize(
    "content",
    [
        # A comment inside the generated table makes it the owner's (retained, not swept).
        CODEX_EXTERNAL_ADMISSION_TABLE + "# user comment\n",
        # An exact generated table plus a user-owned sibling tools table.
        CODEX_EXTERNAL_ADMISSION_TABLE
        + '\n[mcp_servers.yoetz.tools.status]\napproval_mode = "prompt"\n',
    ],
)
def test_edited_or_sibling_admission_refuses_before_unregistering(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, content: str
) -> None:
    home, project, installation = _layout(tmp_path)
    (project / ".codex").mkdir(mode=0o700)
    (project / ".codex" / "config.toml").write_text(content)
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    with pytest.raises(ConnectionError, match="connection_project_mcp_tables_retained"):
        _plan(installation, project)

    assert fake.registered and fake.loads()
    assert (project / ".codex" / "config.toml").read_text() == content


def test_unknown_admission_surface_refuses_before_any_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CHECK_DISCONNECT_R1 P2-a: a symlinked approval file is never skipped."""

    home, project, installation = _layout(tmp_path)
    real = tmp_path / "real-config.toml"
    real.write_text(CODEX_EXTERNAL_ADMISSION_TABLE)
    (project / ".codex").mkdir(mode=0o700)
    (project / ".codex" / "config.toml").symlink_to(real)
    fake = FakeCodex(home, tmp_path / "elsewhere")
    _wire(monkeypatch, fake, list[str]())

    with pytest.raises(ConnectionError, match="connection_admission_cleanup_failed") as caught:
        _plan(installation, project)

    assert caught.value.status is not None
    assert caught.value.status["admission_unreadable_surfaces"] == [".codex/config.toml"]
    assert fake.registered
    assert real.read_text() == CODEX_EXTERNAL_ADMISSION_TABLE


@pytest.mark.parametrize("host", ["claude", "cursor"])
def test_unknown_admission_surface_refuses_for_every_host(tmp_path: Path, host: str) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    surface = ".claude/settings.local.json" if host == "claude" else ".cursor/permissions.json"
    real = tmp_path / "real.json"
    real.write_text("{}")
    (project / surface).parent.mkdir(mode=0o700)
    (project / surface).symlink_to(real)

    with pytest.raises(ConnectionError, match="connection_admission_cleanup_failed"):
        AdmissionCleanupStep(project).plan({"changes": []}, host, "disconnect")  # type: ignore[arg-type]


def test_admission_turning_unreadable_after_preview_stops_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())
    plan = _plan(installation, project)
    real = tmp_path / "real-config.toml"
    real.write_text(CODEX_EXTERNAL_ADMISSION_TABLE)
    (project / ".codex").mkdir(mode=0o700)
    (project / ".codex" / "config.toml").symlink_to(real)

    with pytest.raises(ConnectionError, match="connection_admission_cleanup_failed"):
        plan.apply_reviewed_steps()

    assert fake.registered


def test_disconnect_keeps_registration_another_project_uses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The multi-project risk in CHECK_DISCONNECT_R1: B's approval table needs the transport."""

    home, project, installation = _layout(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    _grant(other)
    (home / "config.toml").write_text(
        f'[projects."{project}"]\ntrust_level = "trusted"\n\n'
        f'[projects."{other}"]\ntrust_level = "trusted"\n'
    )
    fake, cleanup = FakeCodex(home, project), list[str]()
    _wire(monkeypatch, fake, cleanup)
    plan = _plan(installation, project)
    assert "remove_mcp_registration" not in _items(plan.body["changes"])
    assert "mcp_registration_kept_for_other_projects" in _items(plan.body["warnings"])
    others = plan.disclosure["admission_other_projects"]
    assert isinstance(others, list) and len(others) == 1
    assert isinstance(others[0], dict) and others[0]["project_root"] == str(other)
    assert others[0]["dependence"] == "depends"
    assert any("registration stays" in line for line in connection_summary(plan))
    validate_schema_instance("host-connection", "1.0.0", plan.body)

    plan.apply_reviewed_steps()

    assert fake.registered
    assert not any(call[1:3] == ("mcp", "remove") for call in fake.calls)


def test_plugin_only_or_own_transport_projects_do_not_hold_the_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """P3: projects that load without the home transport are not listed as dependent."""

    home, project, installation = _layout(tmp_path)
    plugin_only, own = tmp_path / "plugin-only", tmp_path / "own"
    for root in (plugin_only, own):
        (root / ".codex").mkdir(parents=True, mode=0o700)
    (plugin_only / ".codex" / "config.toml").write_text(CODEX_PLUGIN_ADMISSION_TABLE)
    (own / ".codex" / "config.toml").write_text(
        '[mcp_servers.yoetz]\ncommand = "yoetz"\n\n' + CODEX_EXTERNAL_ADMISSION_TABLE
    )
    (home / "config.toml").write_text(
        f'[projects."{plugin_only}"]\ntrust_level = "trusted"\n\n'
        f'[projects."{own}"]\ntrust_level = "trusted"\n'
    )
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    plan = _plan(installation, project)

    assert "remove_mcp_registration" in _items(plan.body["changes"])
    assert "admission_other_projects" not in plan.disclosure


def _crowded_home(tmp_path: Path, home: Path, *, stale: int, live: int) -> Path:
    """A home whose trust list has stale and live entries sorting before a dependent project."""

    dependent = tmp_path / "zz-dependent"
    dependent.mkdir(mode=0o700)
    _grant(dependent)
    live_roots = [tmp_path / f"live{index:02d}" for index in range(live)]
    for root in live_roots:
        root.mkdir(mode=0o700)
    stale_roots = [tmp_path / f"gone{index:02d}" for index in range(stale)]
    (home / "config.toml").write_text(
        "".join(
            f'[projects."{root}"]\ntrust_level = "trusted"\n\n'
            for root in [*stale_roots, *live_roots, dependent]
        )
    )
    return dependent


def test_incomplete_scan_keeps_the_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """CHECK_MULTIPROJ_R1 P2-3: an unread project may depend; an incomplete scan is no proof."""

    home, project, installation = _layout(tmp_path)
    _crowded_home(tmp_path, home, stale=0, live=40)
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    plan = _plan(installation, project)

    assert "remove_mcp_registration" not in _items(plan.body["changes"])
    assert plan.disclosure["admission_other_projects_known"] == 41
    assert plan.disclosure["admission_other_projects_inspected"] == 32
    assert "other_projects_partially_checked" in _items(plan.body["warnings"])
    assert any("so it stays" in line for line in connection_summary(plan))
    plan.apply_reviewed_steps()
    assert fake.registered
    assert not any(call[1:3] == ("mcp", "remove") for call in fake.calls)

    with pytest.raises(ConnectionError, match="connection_other_projects_need_registration"):
        codex_connection.prepare_codex_connection(
            installation,
            project,
            action="disconnect",
            route="strict",
            request_value=REQUEST,
            remove_shared=True,
        )


def test_stale_trust_entries_do_not_use_up_the_read_window(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    dependent = _crowded_home(tmp_path, home, stale=40, live=0)
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    plan = _plan(installation, project)

    others = _items(plan.disclosure["admission_other_projects"])
    assert [item["project_root"] for item in others] == [str(dependent)]
    assert "admission_other_projects_known" not in plan.disclosure


def test_remove_shared_refuses_while_another_project_needs_the_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    other = tmp_path / "other"
    other.mkdir(mode=0o700)
    _grant(other)
    (home / "config.toml").write_text(f'[projects."{other}"]\ntrust_level = "trusted"\n')
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    with pytest.raises(ConnectionError, match="connection_other_projects_need_registration"):
        codex_connection.prepare_codex_connection(
            installation,
            project,
            action="disconnect",
            route="strict",
            request_value=REQUEST,
            remove_shared=True,
        )
    assert fake.registered


def test_leftover_detector_respects_user_transport(tmp_path: Path) -> None:
    home, project = tmp_path / "home", tmp_path / "project"
    (project / ".codex").mkdir(parents=True)
    home.mkdir()
    (project / ".codex" / "config.toml").write_text(CODEX_EXTERNAL_ADMISSION_TABLE)
    assert codex_project_mcp_leftover(home, project) == "tools_only"
    (home / "config.toml").write_text('[mcp_servers.yoetz]\ncommand = "yoetz"\n')
    assert codex_project_mcp_leftover(home, project) is None
    (project / ".codex" / "config.toml").write_text('model = "x"\n')
    assert codex_project_mcp_leftover(home, tmp_path / "missing") is None


def test_config_load_probe_runs_in_project(tmp_path: Path) -> None:
    seen: list[tuple[tuple[str, ...], str]] = []

    def runner(argv: tuple[str, ...], cwd: str) -> CommandOutput:
        seen.append((argv, cwd))
        return CommandOutput(1, b"secret")

    assert probe_project_config_load("/opt/codex", tmp_path, tmp_path, runner=runner) == "fails"
    assert seen == [(("/opt/codex", "mcp", "list", "--json"), str(tmp_path))]


def test_registration_commands_run_from_codex_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def run(argv: tuple[str, ...], **kwargs: Any) -> SimpleNamespace:
        captured.update(kwargs)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(subprocess, "run", run)
    codex_mcp._default_runner(("/opt/codex", "mcp", "list", "--json"), codex_home=tmp_path)  # pyright: ignore[reportPrivateUsage]
    assert captured["cwd"] == str(tmp_path)


def test_cursor_disconnect_sweeps_project_admission(tmp_path: Path) -> None:
    project, config = tmp_path / "project", tmp_path / "cursor"
    project.mkdir(mode=0o700)
    launcher = tmp_path / "yoetz"
    launcher.write_text("#!/bin/sh\nexit 0\n")
    launcher.chmod(0o700)
    installation = HostInstallation("cursor-cli", launcher, "2026.09.19", config, "Cursor")
    review_digests: list[str] = []

    class Review:
        def consume_artifact_review(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            review_digests.append(preview_digest)

        def consume_setup_authority(
            self, authority: ArtifactAuthority, preview_digest: str
        ) -> None:
            raise AssertionError

    def run(action: str) -> dict[str, Any]:
        def prepare():
            return prepare_connection(
                request_id(REQUEST),
                installation,
                project,
                action=action,  # pyright: ignore[reportArgumentType]
                route="strict",
                launcher=(str(launcher),),
            )

        plan = prepare()
        if action == "disconnect":
            assert "remove_project_admission" in _items(plan.body["changes"])
        return apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=ArtifactAuthority("review_only", plan.digest, "test"),
            review=Review(),
        )

    run("connect")
    preview = preview_host_admission(
        "cursor",
        project,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
    )
    apply_host_admission(preview, project, accepted_preview_digest=preview.preview_digest)
    result = run("disconnect")
    cleanup = result["admission_cleanup"]
    assert cleanup["outcome"] == "removed"
    assert not (project / ".cursor" / "permissions.json").exists()
    assert not (project / ".cursor" / "cli.json").exists()


def test_claude_cleanup_step_plans_and_sweeps(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    preview = preview_host_admission(
        "claude",
        project,
        HostAdmissionAction.GRANT,
        route_profile="policy",
        grant_permits=True,
        owner="external",
    )
    apply_host_admission(preview, project, accepted_preview_digest=preview.preview_digest)
    step = AdmissionCleanupStep(project)
    body: dict[str, Any] = {"changes": []}
    assert step.plan(body, "claude", "disconnect") is True
    assert body["changes"] == ["remove_project_admission"]
    step.apply(True)
    assert step.status()["admission_cleanup"] == {
        "host": "claude",
        "outcome": "removed",
        "surfaces_changed": [".claude/settings.local.json"],
    }
    assert AdmissionCleanupStep(project).plan({"changes": []}, "claude", "connect") is False


def test_admission_change_after_preview_makes_plan_stale(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, project, installation = _layout(tmp_path)
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())
    before = _plan(installation, project)
    assert "remove_project_admission" not in _items(before.body["changes"])
    _grant(project)
    after = _plan(installation, project)
    assert after.digest != before.digest


def test_preview_disclosure_renders_pinned_continuations() -> None:
    from yoetz.cli import host_connection

    rendered = host_connection._rendered_disclosure(  # pyright: ignore[reportPrivateUsage]
        {
            "admission_other_projects": [
                {
                    "project_root": "/work/q",
                    "next_arguments": ["integrate", "codex", "admission", "status"],
                }
            ]
        }
    )
    (item,) = _items(rendered["admission_other_projects"])
    assert "next_arguments" not in item
    assert str(item["next_command"]).endswith("integrate codex admission status")
    status = host_connection._rendered_status(  # pyright: ignore[reportPrivateUsage]
        {"project_mcp_leftover": "tools_only", "next_arguments": ["integrate"]}
    )
    step = host_connection._leftover_next_step(status)  # pyright: ignore[reportPrivateUsage]
    assert step is not None and "Codex cannot load its configuration here" in step


def test_detaching_disconnect_keeps_the_shared_mcp_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """#1058: other connected projects keep using the home's user-level MCP server."""

    home, project, installation = _layout(tmp_path)
    _grant(project)
    fake, cleanup = FakeCodex(home, project), list[str]()
    _wire(monkeypatch, fake, cleanup)
    other = str(tmp_path / "other")

    def detach_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            preview_digest=DIGEST, outcome=RemovalOutcome.DETACH, shared_with=(other,)
        )

    monkeypatch.setattr(codex_connection, "preview_removal", detach_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", detach_preview)

    plan = _plan(installation, project)
    assert plan.body["changes"] == [
        "detach_project",
        "remove_project_skill",
        "remove_project_admission",
    ]
    assert plan.body["mcp_preview_digest"] is None
    assert plan.disclosure["shared_with"] == [other]
    assert "admission_other_projects" not in plan.disclosure
    validate_schema_instance("host-connection", "1.0.0", plan.body)

    plan.apply_reviewed_steps()

    assert fake.registered
    assert not any(call[1:3] == ("mcp", "remove") for call in fake.calls)
    status = plan.status()
    assert status["mcp_removal"] is None
    assert status["enabled"] is False
    assert cleanup == ["skill"]


def test_an_alias_of_the_same_project_does_not_hold_the_registration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Found natively: a moved project's old trusted path is this project, not another one."""

    home, project, installation = _layout(tmp_path)
    _grant(project)
    alias = tmp_path / "old-path"
    alias.symlink_to(project, target_is_directory=True)
    (home / "config.toml").write_text(f'[projects."{alias}"]\ntrust_level = "trusted"\n')
    fake = FakeCodex(home, project)
    _wire(monkeypatch, fake, list[str]())

    plan = _plan(installation, project)

    assert "remove_mcp_registration" in _items(plan.body["changes"])
    assert "admission_other_projects" not in plan.disclosure
