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
