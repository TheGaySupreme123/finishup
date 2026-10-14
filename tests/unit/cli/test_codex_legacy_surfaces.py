"""Codex connection and menu surfaces name a Yoetz-era registration or activation (ADR-048)."""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations.codex_marketplace import ActivationInspection, ActivationState
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.application.host_connection import apply_connection
from finishup.cli import codex_connection, menu, setup
from finishup.ports.harness_mcp import (
    MCP_LEGACY_SERVE_COMMAND,
    MCP_SERVE_COMMAND,
    HarnessBinary,
    McpRegistrationObservation,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId
from finishup.ports.plugin_artifacts import ArtifactAuthority

_DIGEST = "sha256:" + "d" * 64


@dataclasses.dataclass(frozen=True)
class _Plan:
    changes: tuple[str, ...]
    already_registered: bool
    preview_digest: str = _DIGEST
    activation_mcp_command: tuple[str, ...] = ()
    skill_preview_digest: str = _DIGEST
    activation_preview_digest: str = _DIGEST
    policy_digest: str | None = None
    project_root: str = ""
    managed_paths: tuple[str, ...] = ()


def _observation(legacy: str) -> McpRegistrationObservation:
    return McpRegistrationObservation(
        HarnessId.CODEX,
        McpRegistrationState.FINISHUP_OWNED,
        "policy",
        "ambient",
        ("finishup", "mcp", "serve", "--host", "codex"),
        legacy,  # type: ignore[arg-type]
    )


class _Adapter:
    legacy = "none"

    def __init__(self, **_kwargs: object) -> None:
        pass

    async def observe_registration(self, _binary: HarnessBinary) -> McpRegistrationObservation:
        return _observation(self.legacy)


def _connect(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    legacy_registration: str,
    legacy_activation: bool,
    legacy_trees: tuple[str, ...] = (),
) -> codex_connection.ConnectionPlan:
    managed = (".agents/skills/finishup", ".agents/plugins/finishup", *legacy_trees)

    class Runtime:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def integration_plan(self, *_args: object) -> _Plan:
            # The MCP preview already matches; only the legacy pieces could still change.
            return _Plan(
                changes=("register_mcp",),
                already_registered=True,
                project_root=str(tmp_path),
                managed_paths=tuple(str(tmp_path / path) for path in managed),
            )

    def activation(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(
            True, True, ActivationState.ACTIVE, True, True, legacy_activation=legacy_activation
        )

    adapter = type("Adapter", (_Adapter,), {"legacy": legacy_registration})
    monkeypatch.setattr(codex_connection, "FinishUpRuntime", Runtime)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "inspect_activation", activation)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.153.4", tmp_path / "home", "Codex Testing"
    )
    return codex_connection.prepare_codex_connection(
        installation,
        tmp_path,
        action="connect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )


def test_connect_is_complete_only_without_legacy_pieces(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _connect(monkeypatch, tmp_path, legacy_registration="none", legacy_activation=False)
    assert plan.body["changes"] == []
    status = plan.status()
    assert status["legacy_registration"] == "none"
    assert status["legacy_activation"] is False


def test_connect_migrates_an_owned_legacy_registration_and_activation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _connect(monkeypatch, tmp_path, legacy_registration="duplicate", legacy_activation=True)
    assert plan.body["changes"] == [
        "register_mcp",
        "migrate_legacy_mcp_registration",
        "migrate_legacy_plugin",
    ]
    status = plan.status()
    assert status["legacy_registration"] == "duplicate"
    assert status["legacy_activation"] is True


def test_connect_reports_a_foreign_legacy_registration_without_touching_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _connect(monkeypatch, tmp_path, legacy_registration="foreign", legacy_activation=False)
    assert plan.body["changes"] == []
    assert plan.body["warnings"] == ["legacy_registration_foreign"]


class _McpHost:
    """Model both Codex keys, preserving each retained entry's exact response bytes."""

    def __init__(self, *, current: str, legacy: bool) -> None:
        self.entries: dict[str, bytes] = {}
        self.calls: list[tuple[str, ...]] = []
        if current == "foreign":
            self.entries["finishup"] = b'{"command":"other-server", "args":["private-value"]}'
        elif current == "owned":
            self.entries["finishup"] = self._entry(MCP_SERVE_COMMAND)
        if legacy:
            self.entries["yoetz"] = self._entry(MCP_LEGACY_SERVE_COMMAND)

    @staticmethod
    def _entry(command: tuple[str, ...]) -> bytes:
        return json.dumps({"command": command[0], "args": command[1:]}).encode()

    def run(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        if argv[1:3] == ("mcp", "get"):
            raw = self.entries.get(argv[3])
            return CommandOutput(1, b"") if raw is None else CommandOutput(0, raw)
        if argv[1:3] == ("mcp", "list"):
            rows = [
                {"name": name, "transport": json.loads(raw)} for name, raw in self.entries.items()
            ]
            return CommandOutput(0, json.dumps(rows).encode())
        if argv[1:3] == ("mcp", "remove"):
            del self.entries[argv[3]]
            return CommandOutput(0, b"")
        raise AssertionError(f"unexpected host command: {argv[1:3]}")


def _removal_adapter(monkeypatch: pytest.MonkeyPatch, host: _McpHost) -> CodexMcpAdapter:
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    return CodexMcpAdapter(host.run)


@dataclasses.dataclass(frozen=True)
class _AbsentActivation:
    """Keep the unrelated plugin activation layer absent, without running a host CLI."""

    preview_digest: str = _DIGEST
    outcome: codex_connection.RemovalOutcome = codex_connection.RemovalOutcome.ALREADY_ABSENT
    legacy_removed_block: str = ""
    legacy_cache_versions: tuple[str, ...] = ()


class _Review:
    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        assert authority.target_digest == preview_digest


@pytest.mark.parametrize(
    ("current", "legacy", "removed_names"),
    [
        ("foreign", True, ["yoetz"]),
        ("absent", True, ["yoetz"]),
        ("owned", True, ["finishup", "yoetz"]),
        ("owned", False, ["finishup"]),
    ],
)
def test_reviewed_disconnect_reports_only_owned_mcp_configuration(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    current: str,
    legacy: bool,
    removed_names: list[str],
) -> None:
    host = _McpHost(current=current, legacy=legacy)
    foreign_before = host.entries.get("finishup") if current == "foreign" else None
    adapter = _removal_adapter(monkeypatch, host)

    def mcp_adapter(**_kwargs: object) -> CodexMcpAdapter:
        return adapter

    def absent_activation(*_args: object, **_kwargs: object) -> _AbsentActivation:
        return _AbsentActivation()

    def remove_activation(*_args: object, **_kwargs: object) -> None:
        return None

    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", mcp_adapter)
    monkeypatch.setattr(codex_connection, "preview_removal", absent_activation)
    monkeypatch.setattr(codex_connection, "apply_removal", remove_activation)
    # The real MCP service clears its applied-route record on success; keep that write isolated.
    monkeypatch.setattr("finishup.application.applied_mcp_route.state_dir", lambda: tmp_path)
    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    installation = HostInstallation(
        "codex", Path("/opt/codex-testing"), "0.153.4", tmp_path / "codex-home", "Codex Testing"
    )

    def prepare() -> codex_connection.ConnectionPlan:
        return codex_connection.prepare_codex_connection(
            installation,
            project,
            action="disconnect",
            route="policy",
            request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
        )

    plan = prepare()
    assert plan.status()["configured"] is True
    changes = plan.body["changes"]
    assert isinstance(changes, list)
    assert ("remove_legacy_mcp_registration" in changes) is legacy
    if current == "foreign":
        warnings = plan.body["warnings"]
        assert isinstance(warnings, list)
        assert "foreign_entry_present" in warnings
    status = apply_connection(
        plan,
        accepted_digest=plan.digest,
        refresh=prepare,
        authority=ArtifactAuthority("review_only", plan.digest, "test"),
        review=_Review(),
    )
    assert status["configured"] is False
    assert status["legacy_registration"] == "none"
    assert status["mcp_removal"] == {
        "schema": "yoetz.mcp-removal/1",
        "outcome": "completed",
        "state_after": "absent",
        "warnings": [],
        "next_action": None,
    }
    mutations = [call for call in host.calls if call[1:3] in {("mcp", "add"), ("mcp", "remove")}]
    assert mutations == [
        (str(installation.executable), "mcp", "remove", name) for name in removed_names
    ]
    assert host.entries == ({} if foreign_before is None else {"finishup": foreign_before})


@pytest.mark.parametrize(
    ("current", "legacy", "name_line", "removed_names"),
    [
        ("foreign", True, "MCP server name: yoetz", ["yoetz"]),
        ("absent", True, "MCP server name: yoetz", ["yoetz"]),
        ("owned", True, "MCP server names: finishup, yoetz", ["finishup", "yoetz"]),
        ("owned", False, "MCP server name: finishup", ["finishup"]),
    ],
)
def test_removal_preview_names_the_keys_the_adapter_removes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    current: str,
    legacy: bool,
    name_line: str,
    removed_names: list[str],
) -> None:
    from finishup.ports.harness_mcp import McpRegistrationCommand

    host = _McpHost(current=current, legacy=legacy)
    adapter = _removal_adapter(monkeypatch, host)
    binary = HarnessBinary(HarnessId.CODEX, "/opt/codex-testing", "0.153.4", "untested")
    preview = anyio.run(lambda: adapter.preview_unregistration(binary))
    setup._emit_unregistration_preview(preview)  # pyright: ignore[reportPrivateUsage]
    rendered = capsys.readouterr().out
    assert [
        line.strip() for line in rendered.splitlines() if line.startswith("  MCP server name")
    ] == [name_line]
    assert ("Foreign MCP server finishup: retained; not provably FinishUP's" in rendered) is (
        current == "foreign"
    )
    assert preview.preview_digest in rendered
    assert "private-value" not in rendered
    anyio.run(
        lambda: adapter.apply_unregistration(
            binary, McpRegistrationCommand(preview.preview_digest, True)
        )
    )
    assert [call[3] for call in host.calls if call[1:3] == ("mcp", "remove")] == removed_names


@pytest.mark.parametrize(
    ("trees", "changes"),
    [
        ((".agents/plugins/yoetz",), ["remove_legacy_plugin_sources"]),
        ((".agents/skills/yoetz",), ["remove_legacy_project_skill"]),
        (
            (".agents/plugins/yoetz", ".agents/skills/yoetz"),
            ["remove_legacy_plugin_sources", "remove_legacy_project_skill"],
        ),
    ],
)
def test_connect_names_each_legacy_tree_its_digests_delete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    trees: tuple[str, ...],
    changes: list[str],
) -> None:
    """A tree-only Yoetz install still reads as a change, and the summary names each deletion."""

    plan = _connect(
        monkeypatch,
        tmp_path,
        legacy_registration="none",
        legacy_activation=False,
        legacy_trees=trees,
    )
    assert plan.body["changes"] == ["register_mcp", *changes]


def test_connect_ignores_a_legacy_named_path_outside_the_project(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    plan = _connect(
        monkeypatch,
        tmp_path / "nested",
        legacy_registration="none",
        legacy_activation=False,
        legacy_trees=("../.agents/plugins/yoetz",),
    )
    assert plan.body["changes"] == []


@pytest.mark.parametrize(
    ("legacy", "suffix"),
    [
        ("none", None),
        ("legacy_only", "registered under the earlier name yoetz (setup migrates it)"),
        ("duplicate", "also registered under the earlier name yoetz (setup removes it)"),
        (
            "foreign",
            "the earlier name yoetz holds an entry FinishUP cannot prove is its own (kept)",
        ),
    ],
)
def test_menu_summary_names_the_legacy_registration(
    monkeypatch: pytest.MonkeyPatch, legacy: str, suffix: str | None
) -> None:
    binary = HarnessBinary(HarnessId.CODEX, "/opt/codex-testing", "0.153.4", "untested")
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: (binary,),
    )
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.CodexMcpAdapter",
        type("Adapter", (_Adapter,), {"legacy": legacy}),
    )
    (line,) = anyio.run(menu._harness_summary)  # pyright: ignore[reportPrivateUsage]
    expected = "codex (0.153.4) — MCP registration: yoetz_owned, isolation: ambient"
    assert line == (expected if suffix is None else f"{expected}, {suffix}")
