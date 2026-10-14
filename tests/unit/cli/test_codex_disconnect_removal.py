"""The composed disconnect preserves MCP outcome and stops later cleanup on uncertainty."""

from pathlib import Path
from types import SimpleNamespace

import pytest

from yoetz.adapters.integrations.codex_marketplace import RemovalOutcome
from yoetz.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from yoetz.adapters.integrations.host_discovery import HostInstallation
from yoetz.application.host_connection import ConnectionError
from yoetz.cli import codex_connection
from yoetz.cli.host_connection import connection_summary
from yoetz.ports.integrations import IntegrationState
from yoetz.protocol.schemas import validate_schema_instance


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
        return CommandOutput(0, b'{"command":"yoetz","args":["mcp","serve","--host","codex"]}')

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    def plugin_preview(*_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            preview_digest=digest, outcome=RemovalOutcome.ALREADY_ABSENT, possible_users=()
        )

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=digest, state_before=IntegrationState.INSTALLED_EXACT
            )

        async def remove_skill(self, *_args: object) -> None:
            cleanup.append("skill")

    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
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
