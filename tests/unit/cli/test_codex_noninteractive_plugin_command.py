"""Noninteractive Codex connect approves the activation-cache MCP command.

The cache writes a proven absolute launcher. Approving the bare policy tuple instead makes
the post-activation re-read look foreign, and a ``codex mcp get`` that drops plugin ``env``
must not be registered over.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from finishup.adapters.integrations.codex_marketplace import (
    ActivationInspection,
    ActivationPreview,
    ActivationState,
)
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.ports.harness_mcp import MCP_SERVE_COMMAND, MCP_STRICT_SERVE_COMMAND
from finishup.ports.integrations import IntegrationAction, IntegrationPreview, IntegrationState

pytestmark = pytest.mark.anyio

_ACTIVATION_DIGEST = "sha256:" + "d" * 64
_SKILL_DIGEST = "sha256:" + "e" * 64


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _ScriptedRunner:
    def __init__(self, outputs: list[CommandOutput]) -> None:
        self.outputs = outputs
        self.calls: list[tuple[str, ...]] = []
        self._after_found_get = False

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        if argv[1:3] == ("mcp", "list") and self._after_found_get:
            self._after_found_get = False
            return CommandOutput(0, b"[]")
        output = self.outputs.pop(0)
        self._after_found_get = argv[1:3] == ("mcp", "get") and output.exit_code == 0
        return output


def _absent() -> list[CommandOutput]:
    return [CommandOutput(1, b""), CommandOutput(0, b"[]")]


def _entry(route: str, launcher: str, *, env: dict[str, str] | None) -> CommandOutput:
    command = MCP_STRICT_SERVE_COMMAND if route == "strict" else MCP_SERVE_COMMAND
    body: dict[str, object] = {"command": launcher, "args": list(command[1:])}
    if env is not None:
        body["env"] = env
    return CommandOutput(0, json.dumps(body).encode())


def _activation(home: Path, executable: str) -> ActivationPreview:
    return ActivationPreview(
        b'{"name":"finishup","plugins":[]}\n',
        '[plugins."finishup@finishup"]\nenabled = true\n',
        _ACTIVATION_DIGEST,
        ActivationInspection(False, False, ActivationState.INSTALLED_NOT_ACTIVATED),
        "sha256:" + "1" * 64,
        home,
        home / "plugins/cache/finishup/finishup/0.0.0",
        "sha256:" + "2" * 64,
        Path(executable),
        "sha256:" + "3" * 64,
        "0.148.0",
        ("--version",),
        ("plugin", "list", "--marketplace", "finishup", "--json"),
        ("plugin", "add", "finishup@finishup", "--json"),
        "temporary_owner_private_home",
        (("CODEX_HOME", str(home)), ("CODEX_TESTING_HOME", str(home))),
        "sha256:" + "4" * 64,
        "sha256:" + "5" * 64,
        True,
    )


def _skill() -> IntegrationPreview:
    return IntegrationPreview(
        IntegrationAction.INSTALL,
        IntegrationState.ABSENT,
        _SKILL_DIGEST,
        None,
        "unsupported",
        (),
        (),
        _SKILL_DIGEST,
    )


def _install_fakes(
    monkeypatch: pytest.MonkeyPatch,
    *,
    home: Path,
    outputs: list[CommandOutput],
    state_dir: Path,
) -> list[list[tuple[str, ...]]]:
    import finishup.application.applied_mcp_route as applied_route
    import finishup.application.codex_plugin as plugin_service_module
    import finishup.cli.codex_connection as connection
    import finishup.cli.setup as setup_module
    from finishup.adapters.integrations.codex_plugin import PluginHookPresence, PluginInspection
    from finishup.application.codex_plugin import CodexPluginPreview

    calls: list[list[tuple[str, ...]]] = []

    class Scripted(CodexMcpAdapter):
        def __init__(
            self,
            runner: object = None,
            *,
            route_profile: str = "policy",
            codex_home: Path | None = None,
        ) -> None:
            del runner
            recorded = _ScriptedRunner(outputs)
            calls.append(recorded.calls)
            super().__init__(
                recorded,
                route_profile=route_profile,  # type: ignore[arg-type]
                codex_home=codex_home,
            )

    class _Plugins:
        def preview(
            self, target: object, *, codex_version: str | None = None
        ) -> CodexPluginPreview:
            del target, codex_version
            return CodexPluginPreview(PluginHookPresence.ABSENT, 4, False, None, ())

        def inspect(self, target: object, *, codex_version: str | None = None) -> PluginInspection:
            del target, codex_version
            return PluginInspection(PluginHookPresence.ABSENT, False, None, ())

        def install(self, target: object, **kwargs: object) -> PluginInspection:
            del target, kwargs
            return PluginInspection(PluginHookPresence.INSTALLED, False, "sha256:" + "b" * 64, ())

    def fake_codex_activation(
        binary: object, codex_home: Path, workspace: Path | None = None
    ) -> ActivationPreview:
        del workspace
        return _activation(codex_home, getattr(binary, "executable_path"))

    def fake_preview_activation(
        target: object,
        *,
        executable_path: str,
        codex_home: Path,
        **_kwargs: object,
    ) -> ActivationPreview:
        del target
        return _activation(codex_home, executable_path)

    def fake_apply(target: object, **_kwargs: object) -> ActivationInspection:
        del target
        return ActivationInspection(True, True, ActivationState.ACTIVE, plugin_cached=True)

    async def fake_project_skill(workspace: Path | None = None) -> IntegrationPreview:
        del workspace
        return _skill()

    async def fake_preview_skill(target: object) -> SimpleNamespace:
        del target
        return SimpleNamespace(adapter=object(), operation_id="req_test", preview=_skill())

    async def fake_install(*_args: object, **_kwargs: object) -> dict[str, object]:
        return {
            "outcome": "installed",
            "presence": "installed_exact",
            "installed_digest": "sha256:" + "c" * 64,
        }

    def fake_grant(workspace: Path | None = None) -> dict[str, str]:
        del workspace
        return {"outcome": "granted", "workspace_commitment": "hmac-sha256:" + "a" * 64}

    def resolve(_path: str, *, codex_home: Path | None = None) -> Path:
        assert codex_home is not None
        return codex_home

    for module in (
        "finishup.adapters.integrations.codex_mcp",
        "finishup.cli.setup",
        "finishup.cli.codex_connection",
    ):
        monkeypatch.setattr(f"{module}.CodexMcpAdapter", Scripted)
    monkeypatch.setattr(setup_module, "codex_activation_preview", fake_codex_activation)
    monkeypatch.setattr(setup_module, "preview_activation", fake_preview_activation)
    monkeypatch.setattr(setup_module, "apply_activation", fake_apply)
    monkeypatch.setattr(setup_module, "resolve_codex_home_for_binary", resolve)
    monkeypatch.setattr(setup_module, "project_skill_preview", fake_project_skill)
    monkeypatch.setattr(setup_module, "_preview_project_skill", fake_preview_skill)
    monkeypatch.setattr(setup_module, "_install_project_skill", fake_install)
    monkeypatch.setattr(setup_module, "_grant_observation_consent", fake_grant)
    monkeypatch.setattr(setup_module, "CodexPluginService", _Plugins)
    monkeypatch.setattr(plugin_service_module, "CodexPluginService", _Plugins)
    monkeypatch.setattr(applied_route, "state_dir", lambda: state_dir)

    def fake_inspect(*_args: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(False, False, ActivationState.NOT_INSTALLED)

    def empty_home(_home: Path) -> dict[str, object]:
        return {}

    monkeypatch.setattr(connection, "inspect_activation", fake_inspect)
    monkeypatch.setattr(connection, "home_projects_status", empty_home)
    return calls


def _bind(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> tuple[str, dict[str, str]]:
    launcher = str(tmp_path / "runtime" / "bin" / "finishup")
    root = tmp_path / "root"
    root.mkdir(mode=0o700)
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.installed_launcher",
        lambda name="finishup": (launcher, "sha256:" + "cd" * 32),
    )
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: root)
    return launcher, {
        "FINISHUP_ISOLATED_ROOT": str(root),
        "YOETZ_ISOLATED_ROOT": str(root),
    }


def _flat(calls: list[list[tuple[str, ...]]]) -> list[tuple[str, ...]]:
    return [call for group in calls for call in group]


async def test_tui_connect_approves_the_cache_command_and_its_isolation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations.codex_plugin import activation_cache_mcp_binding
    from finishup.tui.models import HarnessOption
    from finishup.tui.runtime import FinishUpRuntime

    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    launcher, isolation = _bind(monkeypatch, tmp_path)
    bound, _environment = activation_cache_mcp_binding()
    outputs = [
        *_absent(),
        *_absent(),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        CommandOutput(0, b""),
        _entry("strict", launcher, env=isolation),
        _entry("strict", launcher, env=isolation),
    ]
    calls = _install_fakes(monkeypatch, home=home, outputs=outputs, state_dir=tmp_path / "state")
    option = HarnessOption(str(tmp_path / "codex"), "0.150.1", "Codex", "")
    runtime = FinishUpRuntime(cwd=project)

    plan = await runtime.integration_plan(option, home, "strict")

    assert plan.activation_mcp_command == bound
    assert plan.activation_mcp_command != MCP_SERVE_COMMAND
    assert plan.activation_mcp_command[0] == launcher
    outcome = await runtime.apply_integration(option, plan)
    assert outcome.outcome == "reregistered"
    assert any(call[1:3] == ("mcp", "add") for call in _flat(calls))


async def test_tui_connect_does_not_accept_a_plugin_entry_whose_env_was_dropped(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.tui.models import HarnessOption
    from finishup.tui.runtime import FinishUpRuntime

    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    launcher, isolation = _bind(monkeypatch, tmp_path)
    outputs = [
        *_absent(),
        *_absent(),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=None),
    ]
    calls = _install_fakes(monkeypatch, home=home, outputs=outputs, state_dir=tmp_path / "state")
    option = HarnessOption(str(tmp_path / "codex"), "0.150.1", "Codex", "")
    runtime = FinishUpRuntime(cwd=project)
    plan = await runtime.integration_plan(option, home, "strict")

    outcome = await runtime.apply_integration(option, plan)

    assert outcome.outcome == "failed"
    assert outcome.reason == "plugin_isolation_unobserved"
    assert outcome.next_step is not None
    assert "did not report the isolation environment" in outcome.next_step
    assert "setup" in outcome.next_step and "run" in outcome.next_step
    assert not any(call[1:3] == ("mcp", "add") for call in _flat(calls))


def test_finishup_connect_approves_the_same_cache_command(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.integrations.codex_plugin import activation_cache_mcp_binding
    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.cli.codex_connection import prepare_codex_connection

    project = tmp_path / "project"
    project.mkdir(mode=0o700)
    home = tmp_path / "codex-home"
    home.mkdir(mode=0o700)
    executable = tmp_path / "codex"
    executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher, isolation = _bind(monkeypatch, tmp_path)
    bound, _environment = activation_cache_mcp_binding()
    outputs = [
        *_absent(),
        *_absent(),
        *_absent(),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        _entry("policy", launcher, env=isolation),
        CommandOutput(0, b""),
        _entry("strict", launcher, env=isolation),
        _entry("strict", launcher, env=isolation),
    ]
    calls = _install_fakes(monkeypatch, home=home, outputs=outputs, state_dir=tmp_path / "state")
    installation = HostInstallation("codex", executable, "0.150.1", home, "Codex")

    plan = prepare_codex_connection(
        installation,
        project,
        action="connect",
        route="strict",
        request_value="req_00000000-0000-4000-8000-0000000000c1",
    )
    stored = plan.body["codex_plan"]
    assert isinstance(stored, dict)
    raw_command = stored.get("activation_mcp_command")
    assert isinstance(raw_command, tuple)
    assert all(isinstance(item, str) for item in raw_command)
    assert raw_command == bound

    plan.apply_reviewed_steps()

    assert any(call[1:3] == ("mcp", "add") for call in _flat(calls))
