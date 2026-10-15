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
    # The multi-project route-change disclosure (#1058): no other project here.
    route_profile_before: str | None = None
    route_changes_for: tuple[str, ...] = ()
    route_changes_possible_for: tuple[str, ...] = ()
    # Projects whose Codex configuration still needs the owned ``yoetz`` entry (ADR-048).
    legacy_registration_kept_for: tuple[str, ...] = ()
    legacy_registration_kept_unchecked: bool = False
    legacy_registration_route_profile: str | None = None
    legacy_registration_kept_unread: tuple[str, ...] = ()


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
    # No other project shares this home (#1058).
    shared_with: tuple[str, ...] = ()
    rebind_to: str | None = None
    possible_users: tuple[str, ...] = ()
    unserved_members: tuple[str, ...] = ()
    keeps_shared: bool = False
    missing_members: tuple[str, ...] = ()


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


@pytest.mark.parametrize("legacy", ["legacy_only", "duplicate"])
def test_menu_summary_does_not_promise_a_migration_setup_keeps_back(
    monkeypatch: pytest.MonkeyPatch, legacy: str
) -> None:
    """A project's Codex settings still use the owned ``yoetz`` entry, so setup keeps it beside
    ``finishup``; the menu must not say setup migrates or removes it (#1073)."""

    binary = HarnessBinary(HarnessId.CODEX, "/opt/codex-testing", "0.153.4", "untested")
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: (binary,),
    )
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.CodexMcpAdapter",
        type("Adapter", (_Adapter,), {"legacy": legacy}),
    )

    from finishup.adapters.integrations.codex_mcp import LegacyRegistrationUse

    def needed(_home: object) -> LegacyRegistrationUse:
        return LegacyRegistrationUse(needed_by=("/work/a",), unreadable=(), unread=())

    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.legacy_registration_dependents", needed
    )
    (line,) = anyio.run(menu._harness_summary)  # pyright: ignore[reportPrivateUsage]
    assert "kept: a project's Codex settings still use it" in line
    assert "setup migrates" not in line and "setup removes" not in line

    # Only an incomplete read keeps it: say that, not that a project uses it (round 3).
    def unread(_home: object) -> LegacyRegistrationUse:
        return LegacyRegistrationUse(
            needed_by=(), unreadable=(), unread=("user_config_unreadable",)
        )

    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.legacy_registration_dependents", unread
    )
    (line,) = anyio.run(menu._harness_summary)  # pyright: ignore[reportPrivateUsage]
    assert "kept: not every project of this Codex home could be read" in line
    assert "still use it" not in line


def test_disconnecting_beside_a_yoetz_era_project_keeps_the_registration_it_uses(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ADR-048 x #1058: Yoetz 0.2 activated A in this home and registered the user-level server;
    B then connected with FinishUP (migrating that registration). B's disconnect removes B's
    FinishUP pieces but keeps the registration A uses, names A, and does not report the kept
    registration as B's configuration."""

    from types import SimpleNamespace

    from tests.unit.adapters.test_codex_marketplace import (
        _FakeCodex,  # pyright: ignore[reportPrivateUsage]
        _legacy_tables,  # pyright: ignore[reportPrivateUsage]
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )
    from tests.unit.adapters.test_codex_multi_project import (
        _connect as connect_project,  # pyright: ignore[reportPrivateUsage]
    )
    from tests.unit.adapters.test_codex_multi_project import (
        _home,  # pyright: ignore[reportPrivateUsage]
        _project,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations import codex_marketplace
    from finishup.ports.integrations import IntegrationState, IntegrationTarget

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    _write_legacy_activation(root_a, home)
    config = home / "config.toml"
    config.write_text(config.read_text() + f'\n[projects."{root_a}"]\ntrust_level = "trusted"\n')
    connect_project(target_b, home)
    entry = b'{"command":"finishup","args":["mcp","serve","--host","codex"]}'

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return CommandOutput(0, entry)

    def adapter(**_kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(runner)

    def preview_removal(
        target: IntegrationTarget,
        *,
        executable_path: str,
        codex_home: Path,
        remove_shared: bool = False,
    ) -> object:
        del executable_path
        fake = _FakeCodex(target, codex_home)
        return codex_marketplace.preview_removal(
            target,
            executable_path=str(fake.executable),
            codex_home=codex_home,
            remove_shared=remove_shared,
            _run=fake,
        )

    def apply_removal(
        target: IntegrationTarget,
        *,
        approved_digest: str,
        executable_path: str,
        codex_home: Path,
        remove_shared: bool = False,
    ) -> object:
        del executable_path
        fake = _FakeCodex(target, codex_home)
        return codex_marketplace.apply_removal(
            target,
            approved_digest=approved_digest,
            executable_path=str(fake.executable),
            codex_home=codex_home,
            remove_shared=remove_shared,
            _run=fake,
        )

    def loads(*_args: object) -> str:
        return "loads"

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=_DIGEST, state_before=IntegrationState.ABSENT, warnings=()
            )

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", preview_removal)
    monkeypatch.setattr(codex_connection, "apply_removal", apply_removal)
    monkeypatch.setattr(codex_connection, "probe_project_config_load", loads)
    installation = HostInstallation("codex", Path("/opt/codex-testing"), "0.153.4", home, "Codex")

    plan = codex_connection.prepare_codex_connection(
        installation,
        root_b,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )

    changes = plan.body["changes"]
    assert isinstance(changes, list)
    assert "remove_mcp_registration" not in changes
    assert plan.body["mcp_preview_digest"] is None
    assert plan.disclosure["shared_with"] == [str(root_a)]
    retained = plan.body["retained"]
    assert isinstance(retained, list)
    assert "FinishUP MCP registration used by other connected projects" in retained

    plan.apply_reviewed_steps()

    status = plan.status()
    assert status["configured"] is False
    assert status["shared_registration_retained"] is True
    assert status["shared_with"] == [str(root_a)]
    assert _legacy_tables(root_a) in config.read_text()


class _KeyedHost:
    """Both Codex keys with ``add`` and ``remove``, so the real adapter decides and applies.

    Every change is mirrored into the home's ``config.toml``, as Codex writes it, so the static
    readers (leftover detection, status) see the same registrations.
    """

    def __init__(self, home: Path) -> None:
        self._config = home / "config.toml"
        self.entries: dict[str, bytes] = {
            "yoetz": json.dumps(
                {"command": "yoetz", "args": list(MCP_LEGACY_SERVE_COMMAND[1:])}
            ).encode()
        }
        self._mirror()

    def _mirror(self) -> None:
        tables = "".join(
            f"\n[mcp_servers.{name}]\ncommand = {json.dumps(transport['command'])}\n"
            f"args = {json.dumps(transport['args'])}\n"
            for name, transport in ((n, json.loads(raw)) for n, raw in self.entries.items())
        )
        # The registrations sit last; everything before them is what other writers left.
        current = self._config.read_text()
        cut = current.find("\n[mcp_servers.")
        self._config.write_text((current if cut < 0 else current[:cut]) + tables)

    def run(self, argv: tuple[str, ...]) -> CommandOutput:
        verb = argv[2]
        if verb == "get":
            raw = self.entries.get(argv[3])
            return CommandOutput(1, b"") if raw is None else CommandOutput(0, raw)
        if verb == "list":
            rows = [
                {"name": name, "transport": json.loads(raw)} for name, raw in self.entries.items()
            ]
            return CommandOutput(0, json.dumps(rows).encode())
        if verb == "add":
            command = argv[argv.index("--") + 1 :]
            self.entries[argv[3]] = json.dumps(
                {"command": command[0], "args": list(command[1:])}
            ).encode()
            self._mirror()
            return CommandOutput(0, b"")
        if verb == "remove":
            self.entries.pop(argv[3], None)
            self._mirror()
            return CommandOutput(0, b"")
        raise AssertionError(f"unexpected host command: {argv}")


def _yoetz_era_home_with_grant(tmp_path: Path) -> tuple[Path, Path, Path]:
    """Yoetz 0.2 activated A in this home and its ``integrate codex admission grant`` wrote the
    exact ``[mcp_servers.yoetz.tools.check]`` table into A; B is a second project."""

    from tests.unit.adapters.test_codex_marketplace import (
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )
    from tests.unit.adapters.test_codex_multi_project import (
        _home,  # pyright: ignore[reportPrivateUsage]
        _project,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    _target_b, root_b = _project(tmp_path, "b")
    _write_legacy_activation(root_a, home)
    config = home / "config.toml"
    config.write_text(
        config.read_text()
        + f'\n[projects."{root_a}"]\ntrust_level = "trusted"\n'
        + f'\n[projects."{root_b}"]\ntrust_level = "trusted"\n'
    )
    (root_a / ".codex").mkdir(mode=0o700)
    (root_a / ".codex" / "config.toml").write_text(CODEX_LEGACY_ADMISSION_TABLES[0])
    return home, root_a, root_b


def _connect_through_adapter(
    monkeypatch: pytest.MonkeyPatch,
    home: Path,
    project: Path,
    host: _KeyedHost,
    *,
    route: str = "policy",
    legacy_activation: bool = False,
) -> codex_connection.ConnectionPlan:
    """A connect whose registration preview and apply are the real adapter's."""

    from finishup.ports.harness_mcp import McpRegistrationAction, McpRegistrationCommand

    def adapter(**kwargs: object) -> CodexMcpAdapter:
        return CodexMcpAdapter(host.run, **kwargs)  # type: ignore[arg-type]

    class Runtime:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def integration_plan(
            self, option: object, codex_home: Path, route_profile: str
        ) -> _Plan:
            del option
            preview = await adapter(
                route_profile=route_profile, codex_home=codex_home
            ).preview_registration(_CODEX)
            noop = preview.action is McpRegistrationAction.NOOP
            return _Plan(
                changes=() if noop else ("register_mcp",),
                already_registered=noop,
                preview_digest=preview.preview_digest,
                project_root=str(project),
                legacy_registration_kept_for=preview.legacy_kept_for,
                legacy_registration_kept_unchecked=preview.legacy_kept_unchecked,
                legacy_registration_route_profile=preview.legacy_route_profile,
                legacy_registration_kept_unread=preview.legacy_kept_unread,
            )

    async def apply_codex(
        binary: HarnessBinary,
        *,
        route_profile: str,
        approved_preview_digest: str,
        codex_home: Path,
        **_kwargs: object,
    ) -> dict[str, object]:
        await adapter(route_profile=route_profile, codex_home=codex_home).apply_registration(
            binary, McpRegistrationCommand(approved_preview_digest, True)
        )
        return {"outcome": "registered"}

    def activation(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(
            True,
            True,
            ActivationState.INSTALLED_NOT_ACTIVATED,
            True,
            True,
            legacy_activation=legacy_activation,
        )

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(codex_connection, "FinishUpRuntime", Runtime)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "inspect_activation", activation)
    monkeypatch.setattr(setup, "apply_codex_integration", apply_codex)
    monkeypatch.setattr("finishup.application.applied_mcp_route.state_dir", lambda: home.parent)
    installation = HostInstallation("codex", Path("/opt/codex-testing"), "0.153.4", home, "Codex")
    return codex_connection.prepare_codex_connection(
        installation,
        project,
        action="connect",
        route=route,  # type: ignore[arg-type]
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )


_CODEX = HarnessBinary(HarnessId.CODEX, "/opt/codex-testing", "0.153.4", "untested")


def _revoke_arguments(project: Path) -> list[str]:
    return [
        "integrate",
        "codex",
        "admission",
        "preview",
        "--project-root",
        str(project),
        "--action",
        "revoke",
    ]


def test_connecting_beside_a_yoetz_era_grant_keeps_the_registration_it_needs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """B's connect must not migrate away the ``yoetz`` transport A's Yoetz-era approval table
    still needs (Codex would refuse to load A's configuration). It keeps the owned ``yoetz``
    entry beside ``finishup``, names A, and gives A's exact revoke (#1073)."""

    from finishup.adapters.integrations.codex_mcp import codex_project_mcp_leftovers
    from finishup.cli.host_connection import connection_summary

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)

    plan = _connect_through_adapter(monkeypatch, home, root_b, host)

    changes = plan.body["changes"]
    assert isinstance(changes, list)
    assert "register_mcp" in changes
    assert "migrate_legacy_mcp_registration" not in changes
    assert plan.body["warnings"] == ["legacy_registration_kept"]
    assert plan.disclosure["legacy_registration_kept_for"] == [
        {
            "project_root": str(root_a),
            "dependence": "depends",
            "next_arguments": _revoke_arguments(root_a),
        }
    ]
    # A keeps working, and the plan says why the earlier entry stays.
    assert plan.disclosure["shared_with"] == [str(root_a)]
    summary = "\n".join(connection_summary(plan))
    assert "earlier name yoetz stays" in summary
    assert str(root_a) in summary
    assert "--action revoke" in summary

    plan.apply_reviewed_steps()

    assert set(host.entries) == {"finishup", "yoetz"}
    assert codex_project_mcp_leftovers(home, root_a) == ()
    status = plan.status()
    assert status["legacy_registration"] == "duplicate"
    assert status["legacy_registration_kept_for"] == [
        {
            "project_root": str(root_a),
            "dependence": "depends",
            "next_arguments": _revoke_arguments(root_a),
        }
    ]


def test_a_yoetz_era_projects_own_connect_keeps_the_entry_its_grant_needs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations.codex_mcp import codex_project_mcp_leftovers

    home, root_a, _root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)

    plan = _connect_through_adapter(monkeypatch, home, root_a, host, legacy_activation=True)

    changes = plan.body["changes"]
    assert isinstance(changes, list)
    assert "migrate_legacy_mcp_registration" not in changes
    assert "migrate_legacy_plugin" in changes
    kept = plan.disclosure["legacy_registration_kept_for"]
    assert isinstance(kept, list)
    assert [item["project_root"] for item in kept if isinstance(item, dict)] == [str(root_a)]

    plan.apply_reviewed_steps()

    assert set(host.entries) == {"finishup", "yoetz"}
    assert codex_project_mcp_leftovers(home, root_a) == ()


def test_revoking_the_yoetz_era_grant_lets_the_next_connect_finish_the_migration(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations.codex_mcp import codex_project_mcp_leftovers
    from finishup.adapters.integrations.host_admission import (
        HostAdmissionAction,
        apply_host_admission,
        preview_host_admission,
    )

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)
    _connect_through_adapter(monkeypatch, home, root_b, host).apply_reviewed_steps()
    assert set(host.entries) == {"finishup", "yoetz"}

    # The continuation the plan named: revoke A's exact earlier-name approval table.
    revoke = preview_host_admission(
        "codex", root_a, HostAdmissionAction.REVOKE, route_profile=None, grant_permits=None
    )
    apply_host_admission(revoke, root_a, accepted_preview_digest=revoke.preview_digest)

    plan = _connect_through_adapter(monkeypatch, home, root_b, host)
    changes = plan.body["changes"]
    assert isinstance(changes, list)
    assert "migrate_legacy_mcp_registration" in changes
    assert "legacy_registration_kept_for" not in plan.disclosure
    plan.apply_reviewed_steps()

    assert set(host.entries) == {"finishup"}
    assert codex_project_mcp_leftovers(home, root_a) == ()
    assert "legacy_registration_kept_for" not in plan.status()


def test_a_kept_entry_on_another_review_mode_stops_the_connect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The kept ``yoetz`` entry serves every project of the home on its own review mode; a
    connect that changes the mode would leave AI-powered review running beside a local-only
    choice (or the reverse). Nothing changes; the refusal names the way on."""

    from finishup.application.host_connection import ConnectionError as SetupConnectionError

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)
    before = dict(host.entries)

    with pytest.raises(SetupConnectionError) as caught:
        _connect_through_adapter(monkeypatch, home, root_b, host, route="strict")

    assert str(caught.value) == "connection_legacy_registration_route_kept"
    status = caught.value.status
    assert status is not None
    assert status["route_profile_before"] == "policy"
    kept = status["legacy_registration_kept_for"]
    assert isinstance(kept, list)
    assert [item["project_root"] for item in kept if isinstance(item, dict)] == [str(root_a)]
    assert host.entries == before


def _wire_disconnect(
    monkeypatch: pytest.MonkeyPatch, home: Path, host: _KeyedHost | None = None
) -> HostInstallation:
    """A disconnect whose plugin removal is the real adapter's over a fake Codex."""

    from types import SimpleNamespace

    from tests.unit.adapters.test_codex_marketplace import (
        _FakeCodex,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations import codex_marketplace
    from finishup.ports.integrations import IntegrationState, IntegrationTarget

    entry = b'{"command":"finishup","args":["mcp","serve","--host","codex"]}'
    registered = {"finishup": True}

    def runner(argv: tuple[str, ...]) -> CommandOutput:
        if argv[1:3] == ("mcp", "remove"):
            registered["finishup"] = False
            return CommandOutput(0, b"")
        if argv[1:3] == ("mcp", "list"):
            return CommandOutput(0, b"[]")
        return CommandOutput(0, entry) if registered["finishup"] else CommandOutput(1, b"")

    def adapter(**kwargs: object) -> CodexMcpAdapter:
        if host is not None:
            return CodexMcpAdapter(host.run, **kwargs)  # type: ignore[arg-type]
        return CodexMcpAdapter(runner)

    def preview_removal(
        target: IntegrationTarget,
        *,
        executable_path: str,
        codex_home: Path,
        remove_shared: bool = False,
    ) -> object:
        del executable_path
        fake = _FakeCodex(target, codex_home)
        return codex_marketplace.preview_removal(
            target,
            executable_path=str(fake.executable),
            codex_home=codex_home,
            remove_shared=remove_shared,
            _run=fake,
        )

    def apply_removal(
        target: IntegrationTarget,
        *,
        approved_digest: str,
        executable_path: str,
        codex_home: Path,
        remove_shared: bool = False,
    ) -> object:
        del executable_path
        fake = _FakeCodex(target, codex_home)
        return codex_marketplace.apply_removal(
            target,
            approved_digest=approved_digest,
            executable_path=str(fake.executable),
            codex_home=codex_home,
            remove_shared=remove_shared,
            _run=fake,
        )

    def loads(*_args: object) -> str:
        return "loads"

    class Skill:
        async def preview_skill(self, *_args: object) -> SimpleNamespace:
            return SimpleNamespace(
                preview_digest=_DIGEST, state_before=IntegrationState.ABSENT, warnings=()
            )

    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)
    monkeypatch.setattr(codex_connection, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection, "CodexSkillIntegration", Skill)
    monkeypatch.setattr(codex_connection, "preview_removal", preview_removal)
    monkeypatch.setattr(codex_connection, "apply_removal", apply_removal)
    monkeypatch.setattr(codex_connection, "probe_project_config_load", loads)
    monkeypatch.setattr("finishup.application.applied_mcp_route.state_dir", lambda: home.parent)
    return HostInstallation("codex", Path("/opt/codex-testing"), "0.153.4", home, "Codex")


def test_the_kept_entry_stays_for_its_project_and_goes_with_the_last_disconnect(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """After B's connect kept the owned ``yoetz`` entry beside ``finishup`` for A, B's disconnect
    keeps both for A; A's own disconnect sweeps its exact earlier-name approval table first and,
    with nobody else needing either key, removes both (#1073)."""

    from finishup.adapters.integrations.codex_mcp import codex_project_mcp_leftovers

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)
    _connect_through_adapter(monkeypatch, home, root_b, host).apply_reviewed_steps()
    assert set(host.entries) == {"finishup", "yoetz"}
    installation = _wire_disconnect(monkeypatch, home, host)

    def disconnect(project: Path) -> codex_connection.ConnectionPlan:
        return codex_connection.prepare_codex_connection(
            installation,
            project,
            action="disconnect",
            route="policy",
            request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
        )

    plan_b = disconnect(root_b)
    assert "remove_mcp_registration" not in cast_list(plan_b.body["changes"])
    plan_b.apply_reviewed_steps()
    assert set(host.entries) == {"finishup", "yoetz"}

    plan_a = disconnect(root_a)
    changes = cast_list(plan_a.body["changes"])
    assert "remove_project_admission" in changes
    assert "remove_mcp_registration" in changes
    assert "remove_legacy_mcp_registration" in changes
    plan_a.apply_reviewed_steps()
    assert host.entries == {}
    assert codex_project_mcp_leftovers(home, root_a) == ()
    assert plan_a.status()["legacy_registration"] == "none"


def cast_list(value: object) -> list[object]:
    assert isinstance(value, list)
    return list(value)  # pyright: ignore[reportUnknownArgumentType]


def test_a_removed_plugin_beside_a_yoetz_era_member_names_who_loses_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A is Yoetz-era (it uses the MCP registration), B anchors the FinishUP binding, and C is a
    FinishUP member whose plugin files are missing right now. No project can carry the binding,
    so B's disconnect removes the shared plugin: C loses it, and only the registration stays for
    A. The preview must say so instead of "only this project's pieces are removed" (#1073)."""

    from tests.unit.adapters.test_codex_marketplace import (
        _write_legacy_activation,  # pyright: ignore[reportPrivateUsage]
    )
    from tests.unit.adapters.test_codex_multi_project import (
        _connect as connect_project,  # pyright: ignore[reportPrivateUsage]
    )
    from tests.unit.adapters.test_codex_multi_project import (
        _home,  # pyright: ignore[reportPrivateUsage]
        _project,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.cli.host_connection import connection_summary

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    target_b, root_b = _project(tmp_path, "b")
    target_c, root_c = _project(tmp_path, "c")
    _write_legacy_activation(root_a, home)
    config = home / "config.toml"
    config.write_text(config.read_text() + f'\n[projects."{root_a}"]\ntrust_level = "trusted"\n')
    connect_project(target_b, home)
    connect_project(target_c, home)
    (root_c / ".agents" / "plugins" / "marketplace.json").unlink()  # a branch switch
    installation = _wire_disconnect(monkeypatch, home)

    plan = codex_connection.prepare_codex_connection(
        installation,
        root_b,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )

    assert plan.body["changes"] == ["deactivate_plugin"]
    assert plan.disclosure["members_not_serving"] == [str(root_c)]
    assert plan.disclosure["shared_with"] == [str(root_a)]
    assert plan.disclosure["shared_plugin_removed"] is True
    summary = "\n".join(connection_summary(plan))
    assert (
        "The shared FinishUP plugin is removed from this home; only the MCP registration stays "
        f"for: {root_a}"
    ) in summary
    assert "only this project's pieces are removed" not in summary

    plan.apply_reviewed_steps()

    assert "[marketplaces.finishup]" not in config.read_text()
    status = plan.status()
    assert status["shared_with"] == [str(root_a)]


def _remove_under_both_names(monkeypatch: pytest.MonkeyPatch, home: Path, host: _KeyedHost) -> None:
    """Follow the named way out: the low-level `integrate codex mcp preview-remove`, then
    `remove --accept --preview-digest` with that preview's digest."""

    emitted: list[dict[str, object]] = []

    def emit(value: dict[str, object], *, json_output: bool) -> None:
        del json_output
        emitted.append(dict(value))

    def adapter(
        route_profile: str | None = None, *, codex_home: Path | None = None
    ) -> CodexMcpAdapter:
        return CodexMcpAdapter(
            host.run,  # type: ignore[arg-type]
            route_profile="strict" if route_profile is None else route_profile,  # type: ignore[arg-type]
            codex_home=codex_home,
        )

    monkeypatch.setattr(setup, "_emit", emit)
    monkeypatch.setattr(setup, "discover_codex_binaries", lambda: (_CODEX,))
    monkeypatch.setattr(setup, "_mcp_adapter", adapter)

    async def run(action: str, digest: str | None = None) -> int:
        return await setup.integrate_mcp(
            action,
            "codex",
            codex_path=None,
            codex_home=home,
            accept=digest is not None,
            preview_digest=digest,
            json_output=True,
            _state=home.parent,
        )

    assert anyio.run(run, "preview-remove") == 0
    digest = emitted[-1]["preview_digest"]
    assert isinstance(digest, str)
    assert anyio.run(run, "remove", digest) == 0


def test_an_unreadable_project_config_gets_its_own_step_and_the_way_out_works(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A's .codex/config.toml is a symlink: FinishUP cannot tell whether it needs the `yoetz`
    server, so the entry stays. The step says why and what makes it readable (never "remove the
    tables"), and names the explicit way out, which works: the low-level removal under both
    names, then a connect (#1073 round 3)."""

    from finishup.cli.host_connection import connection_summary

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    real = tmp_path / "dotfiles-codex.toml"
    real.write_text('model = "o3"\n')
    (root_a / ".codex" / "config.toml").unlink()
    (root_a / ".codex" / "config.toml").symlink_to(real)
    host = _KeyedHost(home)

    plan = _connect_through_adapter(monkeypatch, home, root_b, host)

    assert plan.disclosure["legacy_registration_kept_for"] == [
        {"project_root": str(root_a), "dependence": "unknown", "unreadable": "symlink"}
    ]
    summary = "\n".join(connection_summary(plan))
    assert "could not read its .codex/config.toml safely (a symlink)" in summary
    assert "regular file you own" in summary
    assert "remove the [mcp_servers.yoetz] tables" not in summary
    assert "After those revokes" not in summary
    assert "integrate codex mcp preview-remove --codex-path /opt/codex-testing" in summary
    assert f"--codex-home {home}" in summary
    assert "your explicit choice" in summary

    plan.apply_reviewed_steps()
    assert set(host.entries) == {"finishup", "yoetz"}
    _remove_under_both_names(monkeypatch, home, host)
    assert host.entries == {}
    again = _connect_through_adapter(monkeypatch, home, root_b, host)
    assert "legacy_registration_kept_for" not in again.disclosure
    again.apply_reviewed_steps()
    assert set(host.entries) == {"finishup"}


def test_a_strict_kept_entry_leaves_a_path_to_ai_powered_review(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A strict (local-only) `yoetz` entry is kept for A; first-run setup and the wizard always
    ask for the policy route. The refusal keeps either mode reachable: keep local only (the full
    selected command), or remove the earlier entry as an explicit choice and connect again."""

    from finishup.adapters.integrations.codex_mcp import codex_project_mcp_leftovers
    from finishup.application.host_connection import ConnectionError as SetupConnectionError
    from finishup.cli.host_connection import refusal_step, rendered_status
    from finishup.ports.harness_mcp import MCP_LEGACY_STRICT_SERVE_COMMAND

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    host = _KeyedHost(home)
    host.entries["yoetz"] = json.dumps(
        {"command": "yoetz", "args": list(MCP_LEGACY_STRICT_SERVE_COMMAND[1:])}
    ).encode()
    host._mirror()  # pyright: ignore[reportPrivateUsage]

    with pytest.raises(SetupConnectionError) as caught:
        _connect_through_adapter(monkeypatch, home, root_b, host, route="policy")

    step = refusal_step(str(caught.value), rendered_status(caught.value.status or {}))
    assert step is not None
    selection = f"--host-path /opt/codex-testing --host-config-root {home}"
    assert f"setup run --host codex {selection} --project {root_b} --route-profile strict" in step
    assert "integrate codex mcp preview-remove" in step
    assert f"--project {root_b} --route-profile policy" in step
    assert "finishup setup run --host codex --route-profile" not in step

    _remove_under_both_names(monkeypatch, home, host)
    plan = _connect_through_adapter(monkeypatch, home, root_b, host, route="policy")
    plan.apply_reviewed_steps()
    assert set(host.entries) == {"finishup"}
    # The consequence the way out names: A's earlier-name table now has no transport.
    assert codex_project_mcp_leftovers(home, root_a) == (("yoetz", "tools_only"),)


@pytest.mark.parametrize("edited", [False, True], ids=["exact", "edited"])
def test_the_revoke_promise_is_given_only_when_the_revokes_release_it(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, edited: bool
) -> None:
    from finishup.cli.host_connection import connection_summary

    home, root_a, root_b = _yoetz_era_home_with_grant(tmp_path)
    if edited:
        (root_a / ".codex" / "config.toml").write_text(
            '[mcp_servers.yoetz.tools.check]\napproval_mode = "prompt"\n'
        )
    host = _KeyedHost(home)

    summary = "\n".join(
        connection_summary(_connect_through_adapter(monkeypatch, home, root_b, host))
    )

    promise = "After those revokes, connect again to finish moving to FinishUP."
    assert (promise in summary) is not edited
    assert ("--action revoke" in summary) is not edited
    assert ("remove them yourself" in summary) is edited


def test_a_disconnect_reads_a_large_home_config_and_keeps_what_others_need(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A user config over 64 KiB (but within Codex's own 1 MiB bound) is still read: B's
    disconnect keeps the registration A's Yoetz-era approval table needs. A is only a trusted
    project here (no Yoetz-era activation), so nothing else keeps it (#1073 round 3)."""

    from tests.unit.adapters.test_codex_multi_project import (
        _home,  # pyright: ignore[reportPrivateUsage]
        _project,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES

    home = _home(tmp_path)
    _target_a, root_a = _project(tmp_path, "a")
    _target_b, root_b = _project(tmp_path, "b")
    (home / "config.toml").write_text(
        f'[projects."{root_a}"]\ntrust_level = "trusted"\n'
        f'\n[projects."{root_b}"]\ntrust_level = "trusted"\n'
    )
    (root_a / ".codex").mkdir(mode=0o700)
    (root_a / ".codex" / "config.toml").write_text(CODEX_LEGACY_ADMISSION_TABLES[0])
    host = _KeyedHost(home)
    _connect_through_adapter(monkeypatch, home, root_b, host).apply_reviewed_steps()
    config = home / "config.toml"
    config.write_text("# padding\n" * 8000 + config.read_text())
    assert config.stat().st_size > 65_536
    installation = _wire_disconnect(monkeypatch, home, host)

    plan = codex_connection.prepare_codex_connection(
        installation,
        root_b,
        action="disconnect",
        route="policy",
        request_value="req_52e989dd-b118-4f49-a359-707a6b32bfa4",
    )

    assert "remove_mcp_registration" not in cast_list(plan.body["changes"])
    others = cast_list(plan.disclosure["admission_other_projects"])
    assert [item["project_root"] for item in others if isinstance(item, dict)] == [str(root_a)]
    plan.apply_reviewed_steps()
    assert set(host.entries) == {"finishup", "yoetz"}


def test_an_unread_record_never_reads_as_nobody_needs_the_registration(tmp_path: Path) -> None:
    """The disconnect scan treats an unreadable input as the connect does: unproven, so an
    ordinary disconnect keeps the transport and says why (#1073 round 3)."""

    from tests.unit.adapters.test_codex_multi_project import (
        _home,  # pyright: ignore[reportPrivateUsage]
        _project,  # pyright: ignore[reportPrivateUsage]
    )

    from finishup.adapters.integrations.host_projects import CONNECTED_PROJECTS_FILE

    home = _home(tmp_path)
    _target, root_b = _project(tmp_path, "b")
    (home / "config.toml").write_text(f'[projects."{root_b}"]\ntrust_level = "trusted"\n')
    record = home / CONNECTED_PROJECTS_FILE
    record.write_text("not json")
    record.chmod(0o600)

    needing, enumeration = codex_connection._other_projects_needing_transport(  # pyright: ignore[reportPrivateUsage]
        home, root_b, ("finishup", "yoetz")
    )

    assert needing == []
    assert enumeration.get("admission_other_projects_unread") == ["connected_projects_unreadable"]
