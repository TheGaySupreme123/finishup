"""Codex connection and menu surfaces name a Yoetz-era registration or activation (ADR-048)."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import anyio
import pytest

from finishup.adapters.integrations.codex_marketplace import ActivationInspection, ActivationState
from finishup.adapters.integrations.host_discovery import HostInstallation
from finishup.cli import codex_connection, menu
from finishup.ports.harness_mcp import (
    HarnessBinary,
    McpRegistrationObservation,
    McpRegistrationState,
)
from finishup.ports.integrations import HarnessId

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
