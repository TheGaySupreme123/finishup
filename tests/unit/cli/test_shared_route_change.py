"""A review-mode change of a shared registration names the other projects (#1058 review r2).

The Codex `[mcp_servers.finishup]` registration is user-level and the Claude Code marketplace source
serves every project's install, so rewriting either on another review mode changes the other
projects' sessions too. Every path that can do it says so and cannot apply it on a bare --accept.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE, encode_projects
from finishup.cli import setup as setup_cli
from finishup.ports.harness_mcp import (
    MCP_LEGACY_STRICT_SERVE_COMMAND,
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationObservation,
    McpRegistrationPreview,
    McpRegistrationState,
    mcp_command_profile,
)
from finishup.ports.integrations import HarnessId, IntegrationScope, IntegrationTarget

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "b" * 64
_BINARY = HarnessBinary(
    harness_id=HarnessId.CODEX,
    executable_path="/opt/harness/bin/codex",
    reported_version=None,
    compatibility="untested",
)


def _serving_member(tmp_path: Path, name: str) -> Path:
    from tests.unit.adapters.test_codex_marketplace import (
        _install,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.codex_marketplace import (
        _canonical_marketplace_bytes,  # pyright: ignore[reportPrivateUsage]
    )

    root = tmp_path / name
    root.mkdir(mode=0o700)
    _install(IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(root)))
    (root / ".agents/plugins/marketplace.json").write_bytes(_canonical_marketplace_bytes())
    return root


def _collector(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
    emitted: list[dict[str, object]] = []

    def emit(value: Mapping[str, object], *, json_output: bool) -> None:
        del json_output
        emitted.append(dict(value))

    monkeypatch.setattr(setup_cli, "_emit", emit)
    return emitted


def _home_with_member(tmp_path: Path) -> tuple[Path, Path]:
    home = tmp_path / "codex"
    home.mkdir(mode=0o700)
    member = _serving_member(tmp_path, "a")
    record = home / CONNECTED_PROJECTS_FILE
    record.write_bytes(encode_projects((str(member),)))
    record.chmod(0o600)
    return home, member


def _rewrite_to_policy(
    monkeypatch: pytest.MonkeyPatch,
    registered_command: tuple[str, ...] = MCP_STRICT_SERVE_COMMAND,
) -> list[str]:
    """The home's registration is FinishUP's (strict by default); a policy preview rewrites it.

    The preview follows the previewing route like the Codex adapter: ``reregister`` whenever the
    registered command differs, which a launcher-only difference (a legacy bare `yoetz` entry)
    also causes. ``observe`` reads the registered command's own mode.
    """

    registered: list[str] = []

    async def fake_preview(self: Any, _binary: object) -> McpRegistrationPreview:
        route = self._port._route_profile  # pyright: ignore[reportPrivateUsage]
        command = MCP_SERVE_COMMAND if route == "policy" else MCP_STRICT_SERVE_COMMAND
        return McpRegistrationPreview(
            HarnessId.CODEX,
            McpRegistrationAction.NOOP
            if command == registered_command
            else McpRegistrationAction.REREGISTER,
            McpRegistrationState.FINISHUP_OWNED,
            (),
            _DIGEST if route == "policy" else "sha256:" + "c" * 64,
            command,
            route,
        )

    async def fake_observe(self: object, _binary: object) -> McpRegistrationObservation:
        return McpRegistrationObservation(
            HarnessId.CODEX,
            McpRegistrationState.FINISHUP_OWNED,
            mcp_command_profile(registered_command),
            "ambient",
            registered_command,
        )

    async def fake_register(self: object, _binary: object, confirmation: Any, **_: object):
        registered.append(confirmation.preview_digest)
        raise AssertionError("registered")

    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))
    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.preview", fake_preview)
    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.observe", fake_observe)
    monkeypatch.setattr(
        "finishup.application.harness_mcp.HarnessMcpService.register", fake_register
    )
    return registered


async def test_integrate_codex_mcp_preview_names_and_binds_the_other_projects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, member = _home_with_member(tmp_path)
    _rewrite_to_policy(monkeypatch)
    emitted = _collector(monkeypatch)

    code = await setup_cli.integrate_mcp(
        "preview",
        "codex",
        codex_path=None,
        codex_home=home,
        accept=False,
        preview_digest=None,
        json_output=True,
        route_profile="policy",
    )

    assert code == 0
    body = emitted[-1]
    assert body["route_profile_before"] == "strict"
    assert body["route_changes_for"] == [str(member)]
    # The digest the owner echoes binds the named projects, not only the registration.
    assert body["preview_digest"] != _DIGEST


async def test_integrate_codex_mcp_install_refuses_a_bare_accept_that_changes_others(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    home, _member = _home_with_member(tmp_path)
    registered = _rewrite_to_policy(monkeypatch)
    emitted = _collector(monkeypatch)

    code = await setup_cli.integrate_mcp(
        "install",
        "codex",
        codex_path=None,
        codex_home=home,
        accept=True,
        preview_digest=None,
        json_output=True,
        route_profile="policy",
    )
    assert code == 2
    assert registered == []

    # The registration's own digest is stale now: only the bound preview digest applies.
    stale = await setup_cli.integrate_mcp(
        "install",
        "codex",
        codex_path=None,
        codex_home=home,
        accept=True,
        preview_digest=_DIGEST,
        json_output=True,
        route_profile="policy",
    )
    assert stale == 2
    assert registered == []

    # With the exact preview digest the change applies, on the registration's own digest.
    await setup_cli.integrate_mcp(
        "preview",
        "codex",
        codex_path=None,
        codex_home=home,
        accept=False,
        preview_digest=None,
        json_output=True,
        route_profile="policy",
    )
    shown = str(emitted[-1]["preview_digest"])
    with pytest.raises(AssertionError, match="registered"):
        await setup_cli.integrate_mcp(
            "install",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=True,
            preview_digest=shown,
            json_output=True,
            route_profile="policy",
        )
    assert registered == [_DIGEST]


async def test_wizard_refuses_a_bare_accept_that_changes_other_projects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`setup run --codex-path ... --non-interactive --accept` (the historical wizard)."""

    home, member = _home_with_member(tmp_path)
    _rewrite_to_policy(monkeypatch)
    monkeypatch.setenv("CODEX_HOME", str(home))
    project = tmp_path / "b"
    project.mkdir(mode=0o700)

    report = await setup_cli._codex_integration_step(  # pyright: ignore[reportPrivateUsage]
        _BINARY,
        interactive=False,
        accept=True,
        route_profile="policy",
        workspace=project,
    )

    assert report["outcome"] == "failed"
    assert report["reason"] == "route_change_affects_other_projects"
    assert report["route_changes_for"] == [str(member)]
    assert "setup run --host codex" in str(report["next_step"])
    assert not (project / ".agents").exists()


async def test_a_launcher_only_reregistration_keeps_the_legacy_strict_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A legacy bare `yoetz ... --semantic off` entry stays local only without --route-profile.

    The re-registration changes only the launcher; reading the mode from the preview's action
    took ``reregister`` for "the other mode" and flipped every project to AI-powered review
    without a disclosure (#1058 review round 3).
    """

    home, member = _home_with_member(tmp_path)
    _rewrite_to_policy(monkeypatch, MCP_LEGACY_STRICT_SERVE_COMMAND)
    emitted = _collector(monkeypatch)

    assert (
        await setup_cli.integrate_mcp(
            "preview",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=False,
            preview_digest=None,
            json_output=True,
        )
        == 0
    )
    body = emitted[-1]
    assert body["route_profile_before"] == "strict"
    assert body["route_profile"] == "strict"
    assert "route_changes_for" not in body

    # The historical wizard keeps the mode too.
    monkeypatch.setenv("CODEX_HOME", str(home))
    project = tmp_path / "b"
    project.mkdir(mode=0o700)
    captured: dict[str, object] = {}

    def capture(_binary: object, preview: McpRegistrationPreview, *_a: object, **kw: object):
        captured["route_profile"] = preview.route_profile
        captured.update(kw)
        raise AssertionError("previewed")

    monkeypatch.setattr(setup_cli, "_emit_registration_preview", capture)
    monkeypatch.setattr(setup_cli, "_preview_project_skill", _fake_skill_plan)
    with pytest.raises(AssertionError, match="previewed"):
        await setup_cli._codex_integration_step(  # pyright: ignore[reportPrivateUsage]
            _BINARY, interactive=True, accept=False, route_profile=None, workspace=project
        )
    assert captured["route_profile"] == "strict"
    assert captured["route_profile_before"] == "strict"
    assert captured["route_change"] == {}

    # Asking for policy on that legacy entry is a real change, and it names the other project.
    assert (
        await setup_cli.integrate_mcp(
            "preview",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=False,
            preview_digest=None,
            json_output=True,
            route_profile="policy",
        )
        == 0
    )
    body = emitted[-1]
    assert body["route_profile_before"] == "strict"
    assert body["route_changes_for"] == [str(member)]


async def _fake_skill_plan(_project: object) -> Any:
    from types import SimpleNamespace

    return SimpleNamespace(
        preview=SimpleNamespace(
            preview_digest="sha256:" + "d" * 64,
            state_before=SimpleNamespace(value="absent"),
        )
    )


def _damaged_record(home: Path) -> None:
    """A connected-projects record another account could edit: never trusted, never empty."""

    (home / CONNECTED_PROJECTS_FILE).chmod(0o644)


def _symlinked_home(tmp_path: Path, home: Path) -> Path:
    link = tmp_path / "codex-link"
    link.symlink_to(home, target_is_directory=True)
    return link


@pytest.mark.parametrize("damage", ["record", "symlink"])
async def test_unknown_membership_refuses_a_bare_accept_that_changes_the_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str
) -> None:
    """Membership that cannot be read is unknown, not "no other projects" (round 3)."""

    home, _member = _home_with_member(tmp_path)
    if damage == "record":
        _damaged_record(home)
    else:
        home = _symlinked_home(tmp_path, home)
    registered = _rewrite_to_policy(monkeypatch)
    emitted = _collector(monkeypatch)

    code = await setup_cli.integrate_mcp(
        "preview",
        "codex",
        codex_path=None,
        codex_home=home,
        accept=False,
        preview_digest=None,
        json_output=True,
        route_profile="policy",
    )
    assert code == 0
    body = emitted[-1]
    assert body["membership_unknown"] is True
    assert body["route_profile_before"] == "strict"
    # The unknown membership is part of what the owner approves.
    assert body["preview_digest"] != _DIGEST
    shown = str(body["preview_digest"])

    assert (
        await setup_cli.integrate_mcp(
            "install",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=True,
            preview_digest=None,
            json_output=True,
            route_profile="policy",
        )
        == 2
    )
    assert registered == []
    with pytest.raises(AssertionError, match="registered"):
        await setup_cli.integrate_mcp(
            "install",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=True,
            preview_digest=shown,
            json_output=True,
            route_profile="policy",
        )

    # The historical wizard refuses a bare --accept the same way.
    monkeypatch.setenv("CODEX_HOME", str(home))
    project = tmp_path / "b"
    project.mkdir(mode=0o700)
    report = await setup_cli._codex_integration_step(  # pyright: ignore[reportPrivateUsage]
        _BINARY, interactive=False, accept=True, route_profile="policy", workspace=project
    )
    assert report["reason"] == "route_change_affects_other_projects"
    assert report["membership_unknown"] is True


@pytest.mark.parametrize("damage", ["record", "symlink"])
async def test_setup_run_host_codex_stops_on_unknown_membership(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str
) -> None:
    """`setup run --host codex` and the terminal interface stop before a mode change."""

    from finishup.application.harness_mcp import HarnessMcpService
    from finishup.tui import runtime as tui_runtime

    home, member = _home_with_member(tmp_path)
    if damage == "record":
        _damaged_record(home)
    else:
        home = _symlinked_home(tmp_path, home)
    _rewrite_to_policy(monkeypatch)
    service = HarnessMcpService(cast(Any, SimpleNamespace(_route_profile="policy")))
    preview = await service.preview(_BINARY)
    with pytest.raises(tui_runtime.RuntimeError_) as raised:
        await tui_runtime._shared_route_change(  # pyright: ignore[reportPrivateUsage]
            service, _BINARY, preview, "policy", home, tmp_path / "b"
        )
    assert raised.value.reason == "source_invalid"
    assert member.exists()


def test_the_route_change_refusal_names_the_exact_preview(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Followed literally, the refusal's preview command must not end in preview_stale."""

    command = "finishup integrate codex mcp preview --route-profile policy"
    setup_cli._mcp_error_exit(  # pyright: ignore[reportPrivateUsage]
        "route_change_affects_other_projects", preview_command=command
    )
    err = capsys.readouterr().err
    assert command in err
    assert "same --route-profile" in err


@pytest.mark.parametrize("damage", ["record", "symlink"])
async def test_unknown_membership_is_named_and_bound_by_the_low_level_remove(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, damage: str
) -> None:
    home, _member = _home_with_member(tmp_path)
    if damage == "record":
        _damaged_record(home)
    else:
        home = _symlinked_home(tmp_path, home)
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.UNREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        (),
        _DIGEST,
    )

    async def fake_preview(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    async def forbidden(self: object, *_args: object, **_kwargs: object):
        raise AssertionError("unregistered")

    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))
    monkeypatch.setattr(
        "finishup.application.harness_mcp.HarnessMcpService.preview_unregistration", fake_preview
    )
    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.unregister", forbidden)
    emitted = _collector(monkeypatch)

    assert (
        await setup_cli.integrate_mcp(
            "preview-remove",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=False,
            preview_digest=None,
            json_output=True,
        )
        == 0
    )
    body = emitted[-1]
    assert body["membership_unknown"] is True
    assert "mcp_registration_shared_with_other_projects" in cast_list(body["warnings"])
    assert body["preview_digest"] != _DIGEST
    assert (
        await setup_cli.integrate_mcp(
            "remove",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=True,
            preview_digest=_DIGEST,
            json_output=True,
        )
        == 2
    )


def test_wizard_preview_names_the_projects_whose_mode_changes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        (),
        _DIGEST,
        MCP_SERVE_COMMAND,
        "policy",
    )
    setup_cli._emit_registration_preview(  # pyright: ignore[reportPrivateUsage]
        _BINARY,
        preview,
        route_profile_before="strict",
        route_change={"route_profile_before": "strict", "route_changes_for": ["/work/a"]},
    )
    out = capsys.readouterr().out
    assert "from local only to AI-powered review" in out
    assert "/work/a" in out


def test_claude_plugin_preview_names_live_projects_whose_mode_changes(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`integrate claude plugin preview|install|update` re-renders the shared source."""

    from finishup.adapters.integrations.claude_code_integration import (
        ClaudeCodePluginAction,
        render_claude_code_plugin,
    )
    from finishup.cli import claude_code_integration as claude_cli
    from finishup.ports.plugin_artifacts import McpOwnership

    other = tmp_path / "other"
    other.mkdir()

    def installed(_target: object) -> str:
        return "strict"

    def others(_target: object) -> tuple[str, ...]:
        return (str(other), str(tmp_path / "deleted"))

    monkeypatch.setattr(claude_cli, "installed_claude_route_profile", installed)
    monkeypatch.setattr(claude_cli, "claude_code_other_projects", others)
    policy = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="policy"
    )
    change = claude_cli._shared_route_change(  # pyright: ignore[reportPrivateUsage]
        cast(Any, None), policy, ClaudeCodePluginAction.UPDATE, tmp_path / "project"
    )
    assert change == {"route_profile_before": "strict", "route_changes_for": [str(other)]}
    strict = render_claude_code_plugin(
        mcp_ownership=McpOwnership.PLUGIN_MANAGED, route_profile="strict"
    )
    assert (
        claude_cli._shared_route_change(  # pyright: ignore[reportPrivateUsage]
            cast(Any, None), strict, ClaudeCodePluginAction.UPDATE, tmp_path / "project"
        )
        == {}
    )


async def test_integrate_codex_mcp_remove_names_and_binds_the_projects_it_affects(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The low-level remove takes the registration away from every project of the home."""

    home, member = _home_with_member(tmp_path)
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.UNREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        (),
        _DIGEST,
    )

    async def fake_preview(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    async def forbidden(self: object, *_args: object, **_kwargs: object):
        raise AssertionError("unregistered")

    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))
    monkeypatch.setattr(
        "finishup.application.harness_mcp.HarnessMcpService.preview_unregistration", fake_preview
    )
    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.unregister", forbidden)
    emitted = _collector(monkeypatch)

    assert (
        await setup_cli.integrate_mcp(
            "preview-remove",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=False,
            preview_digest=None,
            json_output=True,
        )
        == 0
    )
    body = emitted[-1]
    assert body["shared_with"] == [str(member)]
    assert "mcp_registration_shared_with_other_projects" in cast_list(body["warnings"])
    assert body["preview_digest"] != _DIGEST
    # The registration's own digest no longer approves it: the named projects are bound.
    assert (
        await setup_cli.integrate_mcp(
            "remove",
            "codex",
            codex_path=None,
            codex_home=home,
            accept=True,
            preview_digest=_DIGEST,
            json_output=True,
        )
        == 2
    )


def cast_list(value: object) -> list[object]:
    assert isinstance(value, list)
    return list(value)  # pyright: ignore[reportUnknownArgumentType]


def test_cursor_plugin_remove_preview_names_the_projects_using_the_plugin(tmp_path: Path) -> None:
    from finishup.cli import cursor_integration as cursor_cli

    config = tmp_path / "cursor"
    config.mkdir(mode=0o700)
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    record = config / CONNECTED_PROJECTS_FILE
    record.write_bytes(encode_projects((str(a), str(b))))
    record.chmod(0o600)

    sharing = cursor_cli._plugin_sharing(config, a, plugin_present=True)  # pyright: ignore[reportPrivateUsage]
    assert sharing == {"shared_with": [str(b)], "shared_removed_for_every_project": True}
    record.unlink()
    assert cursor_cli._plugin_sharing(config, a, plugin_present=True) == {  # pyright: ignore[reportPrivateUsage]
        "membership_unknown": True,
        "shared_removed_for_every_project": True,
    }
    assert cursor_cli._plugin_sharing(config, a, plugin_present=False) == {}  # pyright: ignore[reportPrivateUsage]


@pytest.mark.parametrize(
    "arguments",
    [
        ["setup", "run", "--host", "codex", "--non-interactive"],
        ["setup", "status", "--host", "codex"],
        ["setup", "disconnect", "--host", "codex", "--non-interactive"],
    ],
)
def test_setup_without_a_route_profile_leaves_the_mode_to_the_home(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, arguments: list[str]
) -> None:
    """No --route-profile is "keep the home's current review mode", not strict (round 3 T4)."""

    from typer.testing import CliRunner

    from finishup.cli.app import app

    captured: dict[str, object] = {}

    def connection(**kwargs: object) -> int:
        captured.update(kwargs)
        return 0

    monkeypatch.setattr("finishup.cli.host_connection.run_host_connection", connection)
    result = CliRunner().invoke(app, [*arguments, "--project", str(tmp_path), "--json"])
    assert result.exit_code == 0, result.output
    assert captured["route"] is None

    explicit = CliRunner().invoke(
        app, [*arguments, "--project", str(tmp_path), "--route-profile", "policy", "--json"]
    )
    assert explicit.exit_code == 0, explicit.output
    assert captured["route"] == "policy"


@pytest.mark.parametrize(
    ("registered", "expected"),
    [("policy", "policy"), ("strict", "strict"), (None, "strict"), ("unreadable", "strict")],
)
def test_a_codex_connection_without_a_route_uses_the_registered_mode(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, registered: str | None, expected: str
) -> None:
    """The home's FinishUP registration names the mode; a fresh home stays strict (local only)."""

    from finishup.cli import codex_connection
    from finishup.ports.harness_mcp import McpRegistrationError, McpRegistrationReason

    async def observe(self: object, _binary: object) -> McpRegistrationObservation:
        if registered == "unreadable":
            raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})
        if registered is None:
            return McpRegistrationObservation(
                HarnessId.CODEX, McpRegistrationState.ABSENT, None, None, None
            )
        command = MCP_SERVE_COMMAND if registered == "policy" else MCP_LEGACY_STRICT_SERVE_COMMAND
        return McpRegistrationObservation(
            HarnessId.CODEX,
            McpRegistrationState.FINISHUP_OWNED,
            mcp_command_profile(command),
            "ambient",
            command,
        )

    monkeypatch.setattr("finishup.application.harness_mcp.HarnessMcpService.observe", observe)
    assert (
        codex_connection._current_route(_BINARY, tmp_path)  # pyright: ignore[reportPrivateUsage]
        == expected
    )
