"""The composed disconnect preserves MCP outcome and stops later cleanup on uncertainty."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from finishup.adapters.integrations.codex_marketplace import RemovalOutcome
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import ConnectionError
from finishup.cli import codex_connection
from finishup.cli.host_connection import connection_summary
from finishup.ports.integrations import IntegrationState
from finishup.protocol.schemas import validate_schema_instance


def _plugin_removal(digest: str) -> SimpleNamespace:
    return SimpleNamespace(
        preview_digest=digest,
        outcome=RemovalOutcome.ALREADY_ABSENT,
        legacy_removed_block="",
        legacy_cache_versions=(),
        possible_users=(),
        shared_with=(),
        rebind_to=None,
        unserved_members=(),
        keeps_shared=False,
        missing_members=(),
    )


@pytest.mark.parametrize("verified_absent", [True, False])
def test_disconnect_keeps_removal_outcome(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, verified_absent: bool
) -> None:
    digest = "sha256:" + "a" * 64
    removed = False
    cleanup: list[str] = []
    host_calls: list[tuple[str, ...]] = []

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        nonlocal removed
        host_calls.append(argv)
        if argv[1:3] == ("mcp", "remove"):
            removed = True
            return CommandOutput(1, b"private host payload")
        if removed:
            return (
                CommandOutput(0, b"[]")
                if argv[1:3] == ("mcp", "list") and verified_absent
                else CommandOutput(1, b"")
            )
        if argv[1:3] == ("mcp", "list"):
            # No legacy ``yoetz`` key entry (ADR-048).
            return CommandOutput(0, b"[]")
        return CommandOutput(0, b'{"command":"finishup","args":["mcp","serve","--host","codex"]}')

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return _plugin_removal(digest)

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=digest,
                state_before=IntegrationState.INSTALLED_EXACT,
                warnings=(),
            )

        async def remove_skill(self, *_args: object) -> None:
            cleanup.append("skill")

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", plugin_preview)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.153.4", tmp_path / "home", "Codex Testing"
    )
    plan = codex_connection.prepare_codex_connection(
        installation,
        tmp_path,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )
    assert plan.body["warnings"] == ["host_remove_not_compare_and_swap"]
    assert any("host_remove_not_compare_and_swap" in line for line in connection_summary(plan))
    if verified_absent:
        plan.apply_reviewed_steps()
        removal = plan.status()["mcp_removal"]
        assert cleanup == ["skill"]
        assert isinstance(removal, dict) and removal["outcome"] == "completed"
    else:
        with pytest.raises(ConnectionError, match="connection_outcome_unknown") as caught:
            plan.apply_reviewed_steps()
        assert cleanup == []
        assert caught.value.status is not None
        removal = caught.value.status["mcp_removal"]
        assert "--codex-path /opt/codex-testing" in str(caught.value.status["next_command"])
        assert isinstance(removal, dict) and removal["outcome"] == "unverified"
    assert removal["warnings"] == ["host_remove_returned_nonzero"]
    validate_schema_instance("mcp-removal", "1.0.0", removal)
    assert sum(argv[1:3] == ("mcp", "remove") for argv in host_calls) == 1


def test_disconnect_removes_a_legacy_only_owned_skill_tree(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A marker-consistent ``.agents/skills/yoetz`` alone is still removed (ADR-048)."""

    digest = "sha256:" + "b" * 64
    cleanup: list[str] = []

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return CommandOutput(1, b"")

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return _plugin_removal(digest)

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=digest,
                state_before=IntegrationState.ABSENT,
                warnings=("legacy_skill_tree_owned",),
            )

        async def remove_skill(self, *_args: object) -> None:
            cleanup.append("legacy_skill")

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", plugin_preview)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.153.4", tmp_path / "home", "Codex Testing"
    )
    plan = codex_connection.prepare_codex_connection(
        installation,
        tmp_path,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )
    assert plan.body["changes"] == ["remove_legacy_project_skill"]
    plan.apply_reviewed_steps()
    assert cleanup == ["legacy_skill"]


def test_a_retained_legacy_skill_tree_is_never_removed_on_disconnect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    digest = "sha256:" + "c" * 64
    cleanup: list[str] = []

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return CommandOutput(1, b"")

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return _plugin_removal(digest)

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=digest,
                state_before=IntegrationState.ABSENT,
                warnings=("legacy_skill_tree_retained",),
            )

        async def remove_skill(self, *_args: object) -> None:
            cleanup.append("legacy_skill")

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", plugin_preview)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.153.4", tmp_path / "home", "Codex Testing"
    )
    plan = codex_connection.prepare_codex_connection(
        installation,
        tmp_path,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )
    assert plan.body["changes"] == []
    plan.apply_reviewed_steps()
    assert cleanup == []


@pytest.mark.parametrize("shape", ["policy-only", "strict-direct", "legacy-both", "foreign-race"])
def test_disconnect_plugin_carried_registration_in_one_apply(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, shape: str
) -> None:
    from typing import cast

    import anyio

    from finishup.adapters.integrations.codex_skill import CodexSkillIntegration
    from finishup.application.host_connection import apply_connection
    from finishup.domain.values import request_id
    from finishup.ports.harness_mcp import McpRegistrationError, McpRegistrationReason
    from finishup.ports.integrations import (
        HarnessId,
        IntegrationAction,
        IntegrationScope,
        IntegrationTarget,
        SkillApplyCommand,
        SkillPreviewCommand,
    )
    from finishup.ports.plugin_artifacts import PluginMutationReviewPort

    plugin = shape != "strict-direct"
    direct = shape in {"strict-direct", "legacy-both"}
    foreign = False
    host_calls: list[tuple[str, ...]] = []
    route = "strict" if shape == "strict-direct" else "policy"
    project, home = tmp_path / "project", tmp_path / "home"
    project.mkdir(mode=0o700)
    home.mkdir(mode=0o700)
    target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, str(project))
    operation = request_id("req_00000000-0000-4000-8000-000000000180")
    skill = CodexSkillIntegration(allow_untested=True)

    async def install() -> None:
        preview = await skill.preview_skill(
            HarnessId.CODEX,
            SkillPreviewCommand(operation, target, IntegrationAction.INSTALL, False),
        )
        await skill.install_skill(
            HarnessId.CODEX,
            SkillApplyCommand(
                operation, target, IntegrationAction.INSTALL, preview.preview_digest, True, False
            ),
        )

    anyio.run(install)

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        nonlocal direct
        host_calls.append(argv)
        if argv[1:3] == ("mcp", "remove"):
            assert direct and not foreign
            direct = False
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        if foreign:
            return CommandOutput(0, b'{"command":"someone-else","args":[]}')
        if direct or plugin:
            args = b',"--semantic","off"' if route == "strict" else b""
            return CommandOutput(
                0, b'{"command":"finishup","args":["mcp","serve","--host","codex"' + args + b"]}"
            )
        return CommandOutput(1, b"")

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        preview = _plugin_removal("sha256:" + "c" * 64)
        preview.outcome = RemovalOutcome.REMOVE if plugin else RemovalOutcome.ALREADY_ABSENT
        return preview

    def remove_plugin(*_args: object, **_kwargs: object) -> None:
        nonlocal plugin, foreign
        plugin = False
        foreign = shape == "foreign-race"

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    def no_members(*_args: object) -> tuple[tuple[str, ...], tuple[str, ...]]:
        return (), ()

    def no_projects(*_args: object) -> tuple[str, ...]:
        return ()

    def config_loads(*_args: object) -> str:
        return "loads"

    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "preview_removal", plugin_preview)
    monkeypatch.setattr(codex_connection, "apply_removal", remove_plugin)
    monkeypatch.setattr(codex_connection, "other_members", no_members)
    monkeypatch.setattr(codex_connection, "connected_projects", no_projects)
    monkeypatch.setattr(codex_connection, "probe_project_config_load", config_loads)
    installation = HostInstallation("codex", Path("/opt/codex"), "0.162.1", home, "Codex")

    def prepare():
        return codex_connection.prepare_codex_connection(
            installation, project, action="disconnect", route="strict", request_value=str(operation)
        )

    plan = prepare()
    assert plan.body["route_profile"] == route
    # The complete composition and its real generator-based lock must preserve typed errors.
    if shape == "foreign-race":
        with pytest.raises(McpRegistrationError) as caught:
            apply_connection(
                plan,
                accepted_digest=plan.digest,
                refresh=prepare,
                authority=None,
                review=cast(PluginMutationReviewPort, None),
            )
        assert caught.value.reason is McpRegistrationReason.PREVIEW_STALE
        assert (project / ".agents/skills/finishup").exists()
    else:
        result = apply_connection(
            plan,
            accepted_digest=plan.digest,
            refresh=prepare,
            authority=None,
            review=cast(PluginMutationReviewPort, None),
        )
        assert result["configured"] is False
        assert not (project / ".agents/skills/finishup").exists()
        assert not plugin and not direct
        assert sum(argv[1:3] == ("mcp", "remove") for argv in host_calls) == (
            shape in {"strict-direct", "legacy-both"}
        )
