"""A review-mode change of a shared registration names the other projects (#1058 review r2).

The Codex `[mcp_servers.yoetz]` registration is user-level and the Claude Code marketplace source
serves every project's install, so rewriting either on another review mode changes the other
projects' sessions too. Every path that can do it says so and cannot apply it on a bare --accept.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from yoetz.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE, encode_projects
from yoetz.cli import setup as setup_cli
from yoetz.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationAction,
    McpRegistrationPreview,
    McpRegistrationState,
)
from yoetz.ports.integrations import HarnessId, IntegrationScope, IntegrationTarget

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

    from yoetz.adapters.integrations.codex_marketplace import (
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


def _rewrite_to_policy(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """The home's registration is Yoetz's on strict; this preview rewrites it to policy."""

    registered: list[str] = []
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.YOETZ_OWNED,
        (),
        _DIGEST,
        MCP_SERVE_COMMAND,
        "policy",
    )

    async def fake_preview(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    async def fake_register(self: object, _binary: object, confirmation: Any, **_: object):
        registered.append(confirmation.preview_digest)
        raise AssertionError("registered")

    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))
    monkeypatch.setattr("yoetz.application.harness_mcp.HarnessMcpService.preview", fake_preview)
    monkeypatch.setattr("yoetz.application.harness_mcp.HarnessMcpService.register", fake_register)
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


def test_wizard_preview_names_the_projects_whose_mode_changes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.YOETZ_OWNED,
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

    from typing import cast

    from yoetz.adapters.integrations.claude_code_integration import (
        ClaudeCodePluginAction,
        render_claude_code_plugin,
    )
    from yoetz.cli import claude_code_integration as claude_cli
    from yoetz.ports.plugin_artifacts import McpOwnership

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
        McpRegistrationState.YOETZ_OWNED,
        (),
        _DIGEST,
    )

    async def fake_preview(self: object, _binary: object) -> McpRegistrationPreview:
        return preview

    async def forbidden(self: object, *_args: object, **_kwargs: object):
        raise AssertionError("unregistered")

    monkeypatch.setattr(setup_cli, "discover_codex_binaries", lambda: (_BINARY,))
    monkeypatch.setattr(
        "yoetz.application.harness_mcp.HarnessMcpService.preview_unregistration", fake_preview
    )
    monkeypatch.setattr("yoetz.application.harness_mcp.HarnessMcpService.unregister", forbidden)
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
    from yoetz.cli import cursor_integration as cursor_cli

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
