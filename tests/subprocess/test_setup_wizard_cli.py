"""Setup wizard CLI: discovery reporting, confirmation gates, marker, and help fallback."""

from __future__ import annotations

import asyncio
import json
import os
import re
from collections.abc import Awaitable, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Literal, cast

import pytest
from typer.testing import CliRunner

import finishup.cli.app as cli
import finishup.cli.setup as _setup_module_at_import
from finishup.adapters.integrations.codex_marketplace import (
    ActivationInspection,
    ActivationPreview,
    ActivationState,
)
from finishup.adapters.integrations.codex_mcp import CodexMcpAdapter, CommandOutput
from finishup.adapters.integrations.observation_local import (
    LocalContentCaptureAuthority,
    LocalObservationStore,
)
from finishup.application.harness_mcp import HarnessMcpService
from finishup.domain.observation import ObservationRevokeCommand
from finishup.domain.observation_budget import LARGEST_CAPACITY
from finishup.domain.observation_profiles import CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
from finishup.domain.observation_settings import (
    ObservationDetailProfile,
    ObservationSelection,
    ObservationSelectionSettings,
)
from finishup.domain.privacy import ConversationReview
from finishup.ports.control import ControlClientKind, ControlError
from finishup.ports.harness_mcp import (
    MCP_SERVE_COMMAND,
    MCP_STRICT_SERVE_COMMAND,
    HarnessBinary,
)
from finishup.ports.integrations import (
    HarnessId,
    IntegrationError,
    IntegrationReason,
    IntegrationState,
    IntegrationTarget,
    SkillSource,
)
from finishup.ports.plugin_artifacts import ArtifactAuthority
from finishup.protocol.canonical import JsonValue
from finishup.service.client import ServiceClient

_RUNNER = CliRunner()
# ``wizard_env`` replaces the consent step with a canned report; the issue #835 composition
# tests below restore this real one against a disposable observation store.
_REAL_GRANT_OBSERVATION_CONSENT = _setup_module_at_import._grant_observation_consent  # pyright: ignore[reportPrivateUsage]
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _plain(text: str) -> str:
    """Strip ANSI SGR sequences so Rich usage panels stay assertable."""

    return _ANSI_ESCAPE.sub("", text)


def _skip_provider_binding(**_kwargs: object) -> None:
    """Stand in for the interactive endpoint prompt without an untyped lambda."""


async def _fake_repository_privacy_snapshot(*_args: object) -> SimpleNamespace:
    return SimpleNamespace(bound_scope={"workspace_ref_commitment": "hmac-sha256:" + "7" * 64})


def _binary(path: str = "/opt/harness/bin/codex") -> HarnessBinary:
    return HarnessBinary(
        harness_id=HarnessId.CODEX,
        executable_path=path,
        reported_version="0.144.5",
        compatibility="untested",
    )


class _ScriptedRunner:
    """Scripted Codex subprocess stand-in.

    Every MCP observation lists the host's entries once to read the legacy ``yoetz`` key
    (ADR-048). After a successful named ``get`` that list is answered with no entries instead
    of the scripted queue, so each script names only the calls it is about.
    """

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


def _finishup_entry(
    route_profile: Literal["policy", "strict"] = "strict",
    *,
    launcher: str = "finishup",
    env: dict[str, str] | None = None,
) -> CommandOutput:
    command = MCP_STRICT_SERVE_COMMAND if route_profile == "strict" else MCP_SERVE_COMMAND
    body: dict[str, object] = {"command": launcher, "args": list(command[1:])}
    if env is not None:
        body["env"] = env
    return CommandOutput(0, json.dumps(body).encode())


def _absent_mcp() -> list[CommandOutput]:
    """A failed named lookup plus a successful structural proof of absence."""

    return [CommandOutput(1, b""), CommandOutput(0, b"[]")]


@pytest.fixture
def wizard_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, object]:
    """Fake discovery, adapter subprocesses, service client, and marker path."""
    # The legacy Codex wizard fixtures must not probe real Claude/Cursor installations.
    # Shared multi-host discovery and explicit setup are exercised in their own tests.
    monkeypatch.setattr("finishup.adapters.integrations.host_discovery.discover_hosts", lambda: ())

    # These scripted entries model the legacy embedded/bare-launcher cell, not whichever
    # wheel happens to host pytest. Absolute installation proof is supplied explicitly in
    # the absolute CLI regression below and exercised for real by the packaged Codex test.
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.installed_launcher", lambda: None)

    state: dict[str, object] = {
        "binaries": (_binary(),),
        "outputs": _absent_mcp(),
        "calls": [],
        "activation_apply_calls": 0,
        "mcp_homes": [],
    }
    marker = tmp_path / "setup-wizard.json"
    codex_home = tmp_path / "codex-home"
    codex_home.mkdir()

    def fake_discover(*, _probe: object = None) -> tuple[HarnessBinary, ...]:
        return cast(tuple[HarnessBinary, ...], state["binaries"])

    def fake_adapter(
        *,
        route_profile: Literal["policy", "strict"] = "policy",
        codex_home: Path | None = None,
    ) -> CodexMcpAdapter:
        cast(list[Path | None], state["mcp_homes"]).append(codex_home)
        runner = _ScriptedRunner(cast(list[CommandOutput], state["outputs"]))
        cast(list[list[tuple[str, ...]]], state["calls"]).append(runner.calls)
        return CodexMcpAdapter(runner, route_profile=route_profile, codex_home=codex_home)

    async def unreachable_client() -> object:
        raise ControlError("service_unavailable")

    async def unreachable_on_demand(_kind: ControlClientKind) -> ServiceClient:
        raise ControlError("service_unavailable")

    async def fake_install_project_skill(_target: object, **_kwargs: object) -> dict[str, object]:
        return {
            "compatibility": "unsupported",
            "installed_digest": "sha256:" + "c" * 64,
            "outcome": "installed",
            "presence": "installed_exact",
            "reason": None,
        }

    def fake_grant_observation_consent(workspace: Path | None = None) -> dict[str, str]:
        del workspace
        return {
            "outcome": "granted",
            "workspace_commitment": "hmac-sha256:" + "a" * 64,
        }

    class _FakePluginService:
        def preview(self, target: object, *, codex_version: str | None = None) -> object:
            del target, codex_version
            from finishup.adapters.integrations.codex_plugin import PluginHookPresence
            from finishup.application.codex_plugin import CodexPluginPreview

            return CodexPluginPreview(
                presence_before=PluginHookPresence.ABSENT,
                planned_file_count=4,
                trust_observable=False,
                installed_digest=None,
                notes=("codex_hook_trust_not_observable_from_installation_state",),
            )

        def inspect(self, target: object, *, codex_version: str | None = None) -> object:
            del target, codex_version
            from finishup.adapters.integrations.codex_plugin import (
                PluginHookPresence,
                PluginInspection,
            )

            return PluginInspection(
                PluginHookPresence.ABSENT,
                False,
                None,
                ("codex_hook_trust_not_observable_from_installation_state",),
            )

        def install(self, target: object, **kwargs: object) -> object:
            del target, kwargs
            from finishup.adapters.integrations.codex_plugin import (
                PluginHookPresence,
                PluginInspection,
            )

            return PluginInspection(
                PluginHookPresence.INSTALLED,
                False,
                "sha256:" + "b" * 64,
                ("codex_hook_trust_not_observable_from_installation_state",),
            )

    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.setup as setup_module
    import finishup.service.client as service_client_module

    monkeypatch.setattr(setup_module, "discover_codex_binaries", fake_discover)
    monkeypatch.setattr(setup_module, "CodexMcpAdapter", fake_adapter)
    monkeypatch.setattr(setup_module, "_configured_mcp_route_profile", lambda: "strict")
    monkeypatch.setattr(setup_module, "CodexPluginService", _FakePluginService)

    async def fake_privacy_setup(**_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(
            outcome="configured",
            profile="local_only",
            proposal_id="pvp_test",
            grant_state="granted",
            migration_state="not_applicable",
            reason=None,
        )

    monkeypatch.setattr(privacy_setup_module, "run_privacy_setup", fake_privacy_setup)

    def resolve_codex_home(_path: str, *, codex_home: Path | None = None) -> Path:
        assert codex_home is not None
        return codex_home

    monkeypatch.setattr(setup_module, "resolve_codex_home_for_binary", resolve_codex_home)

    activation_digest = "sha256:" + "d" * 64

    def fake_activation_preview(
        _target: object, *, executable_path: str, codex_home: Path
    ) -> ActivationPreview:
        return ActivationPreview(
            b'{"name":"finishup","plugins":[]}\n',
            '[plugins."finishup@finishup"]\nenabled = true\n',
            activation_digest,
            ActivationInspection(False, False, ActivationState.INSTALLED_NOT_ACTIVATED),
            "sha256:" + "e" * 64,
            codex_home,
            codex_home / "plugins/cache/finishup/finishup/0.1.0",
            "sha256:" + "f" * 64,
            Path(executable_path),
            "sha256:" + "a" * 64,
            "0.148.0-alpha.6",
            ("--version",),
            ("plugin", "list", "--marketplace", "finishup", "--json"),
            ("plugin", "add", "finishup@finishup", "--json"),
            "temporary_owner_private_home",
            (("CODEX_HOME", str(codex_home)), ("CODEX_TESTING_HOME", str(codex_home))),
            "sha256:" + "b" * 64,
            "sha256:" + "c" * 64,
            True,
        )

    monkeypatch.setattr(setup_module, "preview_activation", fake_activation_preview)

    def fake_apply_activation(_target: object, **_kwargs: object) -> ActivationInspection:
        state["activation_apply_calls"] = cast(int, state["activation_apply_calls"]) + 1
        return ActivationInspection(True, True, ActivationState.ACTIVE)

    monkeypatch.setattr(setup_module, "apply_activation", fake_apply_activation)

    def fake_inspect_activation(_target: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(True, True, ActivationState.ACTIVE)

    monkeypatch.setattr(setup_module, "inspect_activation", fake_inspect_activation)

    def absent_skill_destination(
        _target: IntegrationTarget, _source: SkillSource
    ) -> SimpleNamespace:
        return SimpleNamespace(
            state=IntegrationState.ABSENT,
            installed_digest=None,
        )

    monkeypatch.setattr(
        setup_module,
        "inspect_destination",
        absent_skill_destination,
    )
    from finishup.adapters.integrations.codex_plugin import (
        PluginHookPresence,
        PluginInspection,
    )

    def absent_plugin(_target: object) -> PluginInspection:
        return PluginInspection(
            PluginHookPresence.ABSENT,
            False,
            None,
            ("codex_hook_trust_not_observable_from_installation_state",),
        )

    monkeypatch.setattr(
        setup_module,
        "inspect_plugin",
        absent_plugin,
    )
    monkeypatch.setattr(setup_module, "setup_marker_path", lambda: marker)
    monkeypatch.setattr(
        setup_module,
        "_grant_observation_consent",
        fake_grant_observation_consent,
    )
    monkeypatch.setattr(setup_module, "_install_project_skill", fake_install_project_skill)
    monkeypatch.setattr(cli, "build_service_client", unreachable_client)
    monkeypatch.setattr(
        service_client_module,
        "connect_service_on_demand",
        unreachable_on_demand,
    )
    # The applied-route record lives under the ambient state directory by default; keep
    # CLI-invoked flows (``setup run``, ``integrate mcp``) inside the test tree.
    import finishup.application.applied_mcp_route as applied_route_module

    isolated_state = tmp_path / "isolated-state"
    monkeypatch.setattr(applied_route_module, "state_dir", lambda: isolated_state)
    state["marker"] = marker
    state["codex_home"] = codex_home
    state["activation_digest"] = activation_digest
    state["isolated_state"] = isolated_state
    return state


def _wire_composed_provider_setup(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    credential_outcome: Literal["stored", "failed"],
    credential_reason: str = "empty_input",
) -> dict[str, object]:
    """Keep the real composed wizard/provider flow and fake only external boundaries."""

    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.provider_binding as provider_binding_module
    import finishup.cli.provider_status as provider_status_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module

    provider = SimpleNamespace(
        provider_id="fireworks",
        model="accounts/fireworks/models/minimax-m3",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
    )
    config_path = tmp_path / "config.toml"
    state: dict[str, object] = {
        "binding_embedded_flags": [],
        "credential_targets": [],
        "privacy_calls": [],
        "reports": [],
        "restart_calls": 0,
        "status_reads": 0,
        "stored": False,
    }

    async def ready(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "os_managed"}

    async def restart() -> dict[str, object]:
        state["restart_calls"] = cast(int, state["restart_calls"]) + 1
        return {"reachable": True, "state": "ready", "vault_mode": "os_managed"}

    def prompt_binding(
        *,
        path: Path | None = None,
        show_standalone_next_step: bool = True,
    ) -> Path:
        del path
        cast(list[bool], state["binding_embedded_flags"]).append(show_standalone_next_step)
        config_path.write_text("[provider]\n", encoding="utf-8")
        return config_path

    def load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(
            storage=SimpleNamespace(data_dir=tmp_path),
            provider=provider,
        )

    async def privacy_setup(
        *,
        recipe_hint: str | None = None,
        offer_recommended: bool = False,
        credential_probe_authorized: bool = False,
        update_checks_override: bool | None = None,
        conversation_review: ConversationReview | None = None,
        workspace_locator: Path | None = None,
        ai_review_add_on: bool = False,
    ) -> SimpleNamespace:
        state["conversation_review"] = conversation_review
        state["ai_review_add_on"] = ai_review_add_on
        cast(list[tuple[str | None, bool, bool, bool | None]], state["privacy_calls"]).append(
            (
                recipe_hint,
                offer_recommended,
                credential_probe_authorized,
                update_checks_override,
            )
        )
        return SimpleNamespace(
            outcome="configured",
            profile="trusted_provider",
            proposal_id="pvp_issue_165",
            grant_state="granted",
            migration_state="not_applicable",
            reason=None,
        )

    async def provider_status(*, workspace_locator: Path | None = None) -> dict[str, object]:
        del workspace_locator
        state["status_reads"] = cast(int, state["status_reads"]) + 1
        if state["status_reads"] == 1:
            return {"credential_connected": False}
        stored = state["stored"] is True
        blockers: tuple[dict[str, object], ...] = ()
        if not stored:
            blockers = (
                {
                    "condition": "provider_credential",
                    "state": "not_connected",
                    "next_command": "finishup provider credential set",
                },
            )
        return {
            "semantic_ready": stored,
            "endpoint_bound": True,
            "credential_connected": stored,
            "llm_inference_enabled": True,
            "repository_grant_state": "granted",
            "blockers": blockers,
            # The owner turned background advice on; the default-off case is unit-tested (#888).
            "background_advice": {"enabled": True, "reason": "owner_enabled"},
        }

    async def set_credential(
        target: object,
        credential: bytearray | None,
        reauthentication: bytearray | None,
    ) -> SimpleNamespace:
        assert credential is None
        assert reauthentication is None
        cast(list[object], state["credential_targets"]).append(target)
        if credential_outcome == "failed":
            raise unlock_module.HumanCeremonyCliError(credential_reason)
        state["stored"] = True
        return SimpleNamespace(activation_status="stored")

    original_emit_human_report = setup_module._emit_human_report  # pyright: ignore[reportPrivateUsage]

    def capture_report(report: dict[str, JsonValue]) -> None:
        cast(list[dict[str, object]], state["reports"]).append(
            cast(dict[str, object], json.loads(json.dumps(report)))
        )
        original_emit_human_report(report)

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup_module, "_service_reachability", ready)
    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", restart)
    monkeypatch.setattr(setup_module, "_emit_human_report", capture_report)
    monkeypatch.setattr(
        provider_binding_module,
        "prompt_provider_endpoint_binding",
        prompt_binding,
    )
    monkeypatch.setattr(config_module, "load_config", load_config)
    monkeypatch.setattr(privacy_setup_module, "run_privacy_setup", privacy_setup)
    monkeypatch.setattr(
        privacy_setup_module,
        "get_privacy_setup_snapshot",
        _fake_repository_privacy_snapshot,
    )
    monkeypatch.setattr(provider_status_module, "provider_status_report", provider_status)
    monkeypatch.setattr(unlock_module, "set_provider_credential", set_credential)
    return state


def test_wizard_ambient_configuration_resolves_inside_the_hermetic_home() -> None:
    """The wizard's ``load_config({}, os.environ, None)`` reads never reach a developer's config.

    ``setup run`` decides the route profile, the credential-probe prompt, and AI-powered review readiness
    from ambient configuration on purpose; the suite, not the product, owns keeping that read
    inside the per-test tree (issue #551). This pins the contract the ``tests/subprocess``
    ``conftest`` provides so a regression fails here rather than three unrelated cases below.
    """

    from finishup.config.load import default_config_file_path, load_config

    config_home = Path(os.environ["XDG_CONFIG_HOME"])
    assert default_config_file_path() == config_home / "finishup" / "config.toml"
    assert not default_config_file_path().exists()
    assert Path.home() == Path(os.environ["HOME"])
    assert Path(os.environ["HOME"]).parent == config_home.parent
    assert not [name for name in os.environ if name.startswith("FINISHUP_")]
    config = load_config({}, os.environ, None)
    assert config.external_runtime is None
    assert config.provider is None


def test_non_interactive_without_accept_is_a_dry_run(wizard_env: dict[str, object]) -> None:
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert report["schema"] == "yoetz.setup-wizard-report/1"
    assert report["registration"]["outcome"] == "declined"
    assert report["marker_written"] is False
    assert not cast(Path, wizard_env["marker"]).exists()
    # Honest next steps always include the confidential ceremonies it cannot run.
    steps = " ".join(report["next_steps"])
    assert "finishup --privacy" in steps
    assert "finishup provider credential set" in steps
    assert "finishup service run" in steps
    # A non-interactive run is what a coding agent sees; it is pointed at the agent guide.
    assert "docs/usage/agent-start.md" in steps


@pytest.mark.parametrize(
    ("choice", "privacy_outcome", "expected_network"),
    [
        (False, "configured", False),
        (False, "cancelled", False),
        (False, "failed", False),
        (True, "cancelled", False),
        (True, "failed", False),
        (True, "configured", True),
    ],
)
def test_setup_update_network_requires_yes_and_successful_trusted_commit(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    choice: bool,
    privacy_outcome: str,
    expected_network: bool,
) -> None:
    """An older enabled policy cannot override this run's NO or failed ceremony."""

    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.setup as setup_module

    wizard_env["binaries"] = ()
    network_calls: list[bool] = []
    recommendation_calls: list[bool] = []

    async def privacy_setup(**kwargs: object) -> SimpleNamespace:
        assert kwargs["update_checks_override"] is choice
        # ADR-049: the local-only answer is recorded as the owner's explicit setting.
        assert kwargs["conversation_review"] is ConversationReview.LOCAL_ONLY
        return SimpleNamespace(
            outcome=privacy_outcome,
            profile="local_only",
            proposal_id=None,
            grant_state="granted" if privacy_outcome == "configured" else "missing",
            migration_state="not_applicable",
            reason=None if privacy_outcome == "configured" else "privacy_decision_not_approved",
        )

    async def package_update(*, interactive: bool) -> dict[str, JsonValue]:
        network_calls.append(interactive)
        return {
            "installed_version": "0.1.0",
            "is_newer": False,
            "latest_version": None,
            "outcome": "skipped_policy",
            "source": "none",
            "upgrade_command": "finishup upgrade",
        }

    async def recommendations(**kwargs: object) -> dict[str, JsonValue]:
        recommendation_calls.append(cast(bool, kwargs["allow_network"]))
        return {"outcome": "refreshed", "pending": []}

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(privacy_setup_module, "run_privacy_setup", privacy_setup)
    monkeypatch.setattr(setup_module, "_resolve_setup_package_update", package_update)
    monkeypatch.setattr(setup_module, "_refresh_setup_recommendations", recommendations)
    answer = "Y" if choice else "N"

    result = _RUNNER.invoke(cli.app, ["setup", "run"], input=f"2\n{answer}\n")

    assert result.exit_code == 0, (result.output, result.exception)
    assert network_calls == [expected_network]
    assert recommendation_calls == [expected_network]


def test_non_interactive_accept_registers_and_writes_marker(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = [
        *_absent_mcp(),  # preview: confirmed absent
        *_absent_mcp(),  # apply re-preview: confirmed absent
        CommandOutput(0, b""),  # add
        _finishup_entry(),  # verify get
    ]
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--accept", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    assert result.stderr == ""
    report = json.loads(result.stdout)
    assert report["registration"]["outcome"] == "registered"
    assert report["registration"]["state"] == "yoetz_owned"
    assert report["registration"]["observation_consent"] == {
        "outcome": "granted",
        "workspace_commitment": "hmac-sha256:" + "a" * 64,
    }
    assert report["registration"]["plugin"]["outcome"] == "installed"
    assert report["registration"]["plugin"]["presence"] == "installed"
    assert report["registration"]["skill"]["outcome"] == "installed"
    assert report["registration"]["skill"]["presence"] == "installed_exact"
    assert report["registration"]["plugin_activation"]["outcome"] == "skipped"
    assert report["registration"]["plugin_activation"]["reason"] == "codex_home_required"
    assert wizard_env["activation_apply_calls"] == 0
    assert report["readiness"]["observation_ready"] is False  # service unreachable
    assert report["readiness"]["consent"] == "granted"
    assert report["service"]["reachable"] is False
    assert report["marker_written"] is True
    marker = json.loads(cast(Path, wizard_env["marker"]).read_text())
    assert marker["schema"] == "yoetz.setup-wizard-marker/1"
    assert marker["outcome"] == "registered"


def test_interactive_generic_accept_does_not_authorize_unshown_activation(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    wizard_env["outputs"] = [
        *_absent_mcp(),
        *_absent_mcp(),
        CommandOutput(0, b""),
        _finishup_entry(),
    ]
    import finishup.cli.setup as setup_module

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run", "--accept"],
        input=f"1\n{wizard_env['codex_home']}\n2\nY\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    assert "Exact marketplace.json bytes:" not in result.stdout
    assert "Codex plugin activation: installed_not_activated" in result.stdout
    assert wizard_env["activation_apply_calls"] == 0


def test_already_registered_mcp_still_installs_plugin_and_grants_consent(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = [
        _finishup_entry(),  # preview get: already finishup-owned
        _finishup_entry(),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry(),  # status verify after plugin install
    ]
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--accept", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert report["registration"]["outcome"] == "already_registered"
    assert report["registration"]["plugin"]["outcome"] == "installed"
    assert report["registration"]["skill"]["outcome"] == "installed"
    assert report["registration"]["observation_consent"]["outcome"] == "granted"
    assert report["marker_written"] is True


def test_foreign_entry_is_preserved_and_reported(wizard_env: dict[str, object]) -> None:
    foreign = CommandOutput(0, json.dumps({"command": "other"}).encode())
    wizard_env["outputs"] = [foreign]
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--accept", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert report["registration"]["outcome"] == "skipped"
    assert report["registration"]["reason"] == "foreign_entry_present"
    assert report["registration"]["observation_consent"]["outcome"] == "absent"
    assert report["registration"]["plugin"]["outcome"] == "skipped"
    assert report["registration"]["skill"]["outcome"] == "skipped"
    # No mutating `mcp add` ever ran.
    for calls in cast(list[list[tuple[str, ...]]], wizard_env["calls"]):
        assert all(call[1:3] in {("mcp", "get"), ("mcp", "list")} for call in calls)


@pytest.mark.anyio
async def test_tui_apply_refuses_a_skill_preview_digest_not_shown_to_the_user(
    wizard_env: dict[str, object],
) -> None:
    import finishup.cli.setup as setup_module

    preview_runner = _ScriptedRunner([_finishup_entry()])
    mcp_preview = await HarnessMcpService(
        CodexMcpAdapter(
            preview_runner, route_profile="strict", codex_home=cast(Path, wizard_env["codex_home"])
        )
    ).preview(_binary())
    workspace = cast(Path, wizard_env["marker"]).parent
    # Preview get, then the observe get that reads the registered route.
    wizard_env["outputs"] = [_finishup_entry(), _finishup_entry()]

    report = await setup_module.apply_codex_integration(
        _binary(),
        workspace=workspace,
        approved_preview_digest=mcp_preview.preview_digest,
        approved_skill_preview_digest="sha256:" + "0" * 64,
        approved_activation_digest=cast(str, wizard_env["activation_digest"]),
        codex_home=cast(Path, wizard_env["codex_home"]),
        _state=cast(Path, wizard_env["isolated_state"]),
    )

    assert report["outcome"] == "failed"
    assert report["reason"] == "preview_stale"
    skill_report = report["skill"]
    assert isinstance(skill_report, dict)
    assert skill_report["reason"] == "preview_stale"
    assert not (workspace / ".agents").exists()


@pytest.mark.anyio
async def test_a_preview_and_apply_that_disagree_on_the_route_refuse_as_stale(
    wizard_env: dict[str, object],
) -> None:
    """The terminal interface previews and applies in two calls, so the route must survive both.

    This is the shape of a defect the terminal interface used to have: it previewed with the
    adapter default (``policy``) and applied on the configured route, which resolves ``strict``
    with no provider bound, so first run's first action failed as stale. The route now travels
    on the approved plan, and this pins the gate that made the mismatch visible rather than
    silent. Only the route differs here -- the skill digest is the real one, so nothing else
    can explain the refusal.
    """

    import finishup.cli.setup as setup_module

    workspace = cast(Path, wizard_env["marker"]).parent
    skill_preview = await setup_module.project_skill_preview(workspace)

    # Exactly what the TUI does today: no route_profile, so the class default (policy) applies.
    preview_runner = _ScriptedRunner(_absent_mcp())
    mcp_preview = await HarnessMcpService(
        CodexMcpAdapter(preview_runner, codex_home=cast(Path, wizard_env["codex_home"]))
    ).preview(_binary())

    # And exactly what apply does today: the configured route, strict with no provider bound.
    wizard_env["outputs"] = _absent_mcp()
    report = await setup_module.apply_codex_integration(
        _binary(),
        workspace=workspace,
        approved_preview_digest=mcp_preview.preview_digest,
        approved_skill_preview_digest=skill_preview.preview_digest,
        approved_activation_digest=cast(str, wizard_env["activation_digest"]),
        codex_home=cast(Path, wizard_env["codex_home"]),
        _state=cast(Path, wizard_env["isolated_state"]),
    )

    assert report["outcome"] == "failed"
    assert report["reason"] == "preview_stale"
    assert not (workspace / ".agents").exists()


@pytest.mark.anyio
async def test_a_preview_and_apply_on_the_same_route_register(
    wizard_env: dict[str, object],
) -> None:
    """Control for the refusal above: the route is the cause, not the skill or plugin previews.

    Identical to that case in every input except the previewing adapter's route, which here
    matches what apply resolves. Without this, a refusal for some unrelated reason would read
    as proof of a route problem.
    """

    import finishup.cli.setup as setup_module

    workspace = cast(Path, wizard_env["marker"]).parent
    skill_preview = await setup_module.project_skill_preview(workspace)

    preview_runner = _ScriptedRunner(_absent_mcp())
    mcp_preview = await HarnessMcpService(
        CodexMcpAdapter(
            preview_runner,
            route_profile="strict",
            codex_home=cast(Path, wizard_env["codex_home"]),
        )
    ).preview(_binary())

    wizard_env["outputs"] = [
        *_absent_mcp(),  # step preview: confirmed absent
        *_absent_mcp(),  # adapter install re-preview: confirmed absent
        CommandOutput(0, b""),  # add
        _finishup_entry("strict"),  # verify get
        _finishup_entry("strict"),  # applied-route record observation
    ]
    report = await setup_module.apply_codex_integration(
        _binary(),
        workspace=workspace,
        approved_preview_digest=mcp_preview.preview_digest,
        approved_skill_preview_digest=skill_preview.preview_digest,
        approved_activation_digest=cast(str, wizard_env["activation_digest"]),
        codex_home=cast(Path, wizard_env["codex_home"]),
        _state=cast(Path, wizard_env["isolated_state"]),
    )

    assert wizard_env["mcp_homes"] == [wizard_env["codex_home"]]
    assert report["reason"] is None
    assert report["outcome"] == "registered"
    # The successful apply durably records the strict route it verified post-write.
    from finishup.application.applied_mcp_route import read_applied_route

    record = read_applied_route(_state=cast(Path, wizard_env["isolated_state"]))
    assert record is not None
    assert record["applied_profile"] == "strict"
    assert record["applied_serve_command"] == list(MCP_STRICT_SERVE_COMMAND)
    assert record["observed_serve_command_post_write"] == [
        *MCP_STRICT_SERVE_COMMAND,
    ]


def test_multiple_candidates_fail_closed_non_interactively(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["binaries"] = (_binary("/a/codex"), _binary("/b/codex"))
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--accept", "--json"])
    assert result.exit_code == 2
    assert "--codex-path" in result.stderr


def test_interactive_wizard_selects_harness_then_installation_and_requires_y_or_n(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wizard_env["binaries"] = (_binary("/a/codex"), _binary("/b/codex"))
    wizard_env["outputs"] = [
        *_absent_mcp(),  # preview: confirmed absent
        *_absent_mcp(),  # apply re-preview: confirmed absent
        CommandOutput(0, b""),  # add
        # ADR-049: local only registers the policy route too; the privacy policy keeps it local.
        _finishup_entry("policy"),  # verify get
    ]

    import finishup.cli.provider_binding as provider_binding
    import finishup.cli.setup as setup_module

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(
        provider_binding, "prompt_provider_endpoint_binding", _skip_provider_binding
    )

    # Harness 1, installation 2, local-only, update checks yes, then policy setup confirmation.
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n2\n{wizard_env['codex_home']}\n2\nY\nmaybe\nY\n",
    )

    assert result.exit_code == 0
    assert "Automatically detected harnesses:" in result.stdout
    assert "1. Codex (2 installations)" in result.stdout
    assert "Select a harness to connect to FinishUP" in result.stdout
    assert "Detected Codex installations:" in result.stdout
    assert "Select the Codex installation to configure" in result.stdout
    assert "Codex home used by /b/codex" in result.stdout
    assert "Choose how FinishUP should review work:" in result.stdout
    assert "complete FinishUP Codex project integration" in result.stdout
    assert "MCP server name: finishup" in result.stdout
    assert "Command: finishup mcp serve --host codex\n" in result.stdout
    assert "Codex executable: /b/codex" in result.stdout
    assert "Confirm Codex project setup? [Y/N]" in result.stdout
    assert "Observation consent for this workspace" in result.stdout
    assert "Please enter Y or N." in result.stdout
    assert "MCP registration: registered" in result.stdout
    assert "Codex plugin activation: active" in result.stdout
    assert "Selected Codex config target:" in result.stdout
    assert "Standing-trust warning:" in result.stdout
    assert wizard_env["activation_apply_calls"] == 1
    assert "Skill support: no tested capability profile; automatic activation not tested" in (
        result.stdout
    )
    assert "Plugin source files:" in result.stdout
    assert "Project skill installation:" in result.stdout
    assert "Hook installation:" in result.stdout
    assert "Observation readiness:" in result.stdout


def test_interactive_registration_n_declines_without_mutation(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.provider_binding as provider_binding
    import finishup.cli.setup as setup_module

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(
        provider_binding, "prompt_provider_endpoint_binding", _skip_provider_binding
    )

    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n1\nY\nN\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    assert "Confirm Codex project setup? [Y/N]" in result.stdout
    assert "MCP registration: declined" in result.stdout
    assert "Skill support: no tested capability profile; automatic activation not tested" in (
        result.stdout
    )
    for calls in cast(list[list[tuple[str, ...]]], wizard_env["calls"]):
        assert all(call[1:3] in {("mcp", "get"), ("mcp", "list")} for call in calls)


def test_semantic_first_run_lists_the_ai_review_recipes_for_the_privacy_draft(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.provider_status as provider_status_module
    import finishup.cli.setup as setup_module

    wizard_env["outputs"] = [
        *_absent_mcp(),  # preview: confirmed absent
        *_absent_mcp(),  # apply re-preview: confirmed absent
        CommandOutput(0, b""),  # add
        _finishup_entry("policy"),  # verify get
    ]
    privacy_calls: list[tuple[str | None, bool, bool, bool | None, object, bool]] = []

    async def ready(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    async def provider_setup(
        service: dict[str, object],
        *,
        provider_choice: str | None = None,
        model: str | None = None,
        before_credential: Callable[[], Awaitable[str | None]] | None = None,
        project: Path | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        del provider_choice, model, project
        assert before_credential is not None
        # None means the privacy step did not block the credential step.
        assert await before_credential() is None
        return service, {"binding": "configured", "credential": "stored"}

    async def privacy_setup(
        *,
        recipe_hint: str | None = None,
        offer_recommended: bool = False,
        credential_probe_authorized: bool = False,
        update_checks_override: bool | None = None,
        conversation_review: ConversationReview | None = None,
        workspace_locator: Path | None = None,
        ai_review_add_on: bool = False,
    ) -> SimpleNamespace:
        privacy_calls.append(
            (
                recipe_hint,
                offer_recommended,
                credential_probe_authorized,
                update_checks_override,
                conversation_review,
                ai_review_add_on,
            )
        )
        return SimpleNamespace(
            outcome="configured",
            profile="confirm_every_request",
            proposal_id="pvp_1",
            reason=None,
        )

    async def provider_status(*, workspace_locator: Path | None = None) -> dict[str, object]:
        del workspace_locator
        return {"semantic_ready": True}

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup_module, "_service_reachability", ready)
    monkeypatch.setattr(setup_module, "_interactive_provider_setup", provider_setup)
    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", ready)
    monkeypatch.setattr(privacy_setup_module, "run_privacy_setup", privacy_setup)
    monkeypatch.setattr(provider_status_module, "provider_status_report", provider_status)

    # Harness 1, AI-powered review, registration confirmation, then credential-probe consent.
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n1\nY\nY\nY\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    # ADR-049: the recommended first answer drafts the hybrid conversation setting, and its
    # privacy step lists the AI-powered review recipes (Assisted review by default), never the
    # released Private recommendation a subscription reviewer gets (review round 1, P2-3).
    assert privacy_calls == [(None, False, True, True, ConversationReview.LOCAL_AGENT_OPT_IN, True)]
    assert "Privacy: configured (confirm_every_request)" in result.stdout


def test_visible_consent_prompt_never_reflects_credential_shaped_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module

    fake_credential = "sk-fake-issue-165-never-repeat"
    answers = iter((fake_credential, "yes"))
    emitted: list[str] = []

    def prompt(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    def echo(value: object = "", **_kwargs: object) -> None:
        emitted.append(str(value))

    monkeypatch.setattr(setup_module.typer, "prompt", prompt)
    monkeypatch.setattr(setup_module.typer, "echo", echo)

    assert (
        setup_module._prompt_yes_no_before_credential(  # pyright: ignore[reportPrivateUsage]
            "Consent?",
            default=True,
        )
        is True
    )
    rendered = "\n".join(emitted)
    assert fake_credential not in rendered
    assert "not credential entry" in rendered
    assert "No API key was read or stored" in rendered

    _service, sanitized = setup_module._provider_setup_result(  # pyright: ignore[reportPrivateUsage]
        {"reachable": True, "state": "ready"},
        {
            "binding": "configured",
            "credential": "failed",
            "credential_reason": fake_credential,
        },
    )
    assert sanitized["credential_reason"] == "credential_setup_failed"
    assert fake_credential not in json.dumps(sanitized)


@pytest.mark.parametrize(
    ("reason", "expected"),
    [
        ("cancelled", "cancelled"),
        ("empty_input", "empty_input"),
        ("eof", "eof"),
        ("confirmation_mismatch", "confirmation_mismatch"),
        ("credential_ambiguous", "credential_ambiguous"),
        ("credential_secret_rejected", "credential_secret_rejected"),
        ("credential_service_unavailable", "credential_service_unavailable"),
        ("privacy_authority_required", "privacy_authority_required"),
        ("privacy_setup_grant_missing", "privacy_setup_grant_missing"),
        ("config_toml_invalid", "config_toml_invalid"),
        ("config_file_unreadable", "config_file_unreadable"),
        ("durability_unsupported", "durability_unsupported"),
        ("external_runtime_forbids_provider", "external_runtime_forbids_provider"),
        ("config_preimage_mismatch", "config_preimage_mismatch"),
        ("privacy_secret-shaped-caller-text", "credential_setup_failed"),
        ("secret-shaped-caller-text", "credential_setup_failed"),
    ],
)
def test_provider_setup_reason_is_bounded_and_allowlisted(reason: str, expected: str) -> None:
    import finishup.cli.setup as setup_module

    assert (
        setup_module._allowlisted_provider_setup_reason(  # pyright: ignore[reportPrivateUsage]
            reason
        )
        == expected
    )


def test_composed_wizard_preserves_privacy_when_hidden_credential_input_is_empty(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import finishup.cli.setup as setup_module

    fake_credential = "sk-fake-issue-165-must-never-appear"
    wizard_env["outputs"] = [
        *_absent_mcp(),
        *_absent_mcp(),
        CommandOutput(0, b""),
        _finishup_entry("policy"),
    ]
    state = _wire_composed_provider_setup(
        monkeypatch,
        tmp_path,
        credential_outcome="failed",
        credential_reason="empty_input",
    )
    original_prompt = cast(Callable[..., object], setup_module.typer.prompt)
    probe_answers = iter((fake_credential, "yes"))

    def route_visible_prompts(prompt: str, *args: object, **kwargs: object) -> object:
        if prompt.startswith("After storage, permit one fixed"):
            return next(probe_answers)
        return original_prompt(prompt, *args, **kwargs)

    monkeypatch.setattr(setup_module.typer, "prompt", route_visible_prompts)

    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n1\nY\nY\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    reports = cast(list[dict[str, object]], state["reports"])
    assert len(reports) == 1
    report = reports[0]
    assert report["privacy"] == {
        "outcome": "configured",
        "profile": "trusted_provider",
        "proposal_id": "pvp_issue_165",
        "grant_state": "granted",
        "migration_state": "not_applicable",
        "reason": None,
    }
    assert report["provider"] == {
        "binding": "configured",
        "credential": "failed",
        "credential_reason": "empty_input",
    }
    assert report["service"] == {
        "reachable": True,
        "state": "ready",
        "vault_mode": "os_managed",
    }
    assert report["next_steps"] == [setup_module._NEXT_CREDENTIAL]  # pyright: ignore[reportPrivateUsage]
    semantic_status = cast(dict[str, object], report["semantic_status"])
    assert semantic_status["semantic_ready"] is False
    assert semantic_status["repository_grant_state"] == "granted"
    assert report["marker_written"] is False
    assert state["binding_embedded_flags"] == [False]
    # ADR-049 review round 1: the AI-powered review answer lists the AI recipes.
    assert state["privacy_calls"] == [(None, False, True, True)]
    assert state["ai_review_add_on"] is True
    assert state["status_reads"] == 2
    assert state["restart_calls"] == 1
    assert state["stored"] is False
    assert len(cast(list[object], state["credential_targets"])) == 1

    assert "Privacy and credential-verification consent" in result.stdout
    assert "API-key entry has not started" in result.stdout
    assert "not credential entry" in result.stderr
    assert "Hidden credential ceremony begins now" in result.stdout
    assert "Privacy: configured (trusted_provider)" in result.stdout
    assert "repository grant: granted" in result.stdout
    assert "Credential: not stored" in result.stdout
    assert "Credential reason: empty_input" in result.stdout
    assert "next: run 'finishup provider credential set'" not in result.stdout
    assert "restart the FinishUP service" not in " ".join(cast(list[str], report["next_steps"]))
    assert "finishup --privacy" not in " ".join(cast(list[str], report["next_steps"]))
    assert fake_credential not in result.output
    assert fake_credential not in json.dumps(report)
    secret_bytes = fake_credential.encode("utf-8")
    for candidate in tmp_path.rglob("*"):
        if candidate.is_file():
            assert secret_bytes not in candidate.read_bytes()


def test_composed_wizard_reaches_semantic_readiness_after_hidden_credential_storage(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    wizard_env["outputs"] = [
        *_absent_mcp(),
        *_absent_mcp(),
        CommandOutput(0, b""),
        _finishup_entry("policy"),
    ]
    state = _wire_composed_provider_setup(
        monkeypatch,
        tmp_path,
        credential_outcome="stored",
    )

    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n1\nY\nY\nY\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    reports = cast(list[dict[str, object]], state["reports"])
    assert len(reports) == 1
    report = reports[0]
    assert report["privacy"] == {
        "outcome": "configured",
        "profile": "trusted_provider",
        "proposal_id": "pvp_issue_165",
        "grant_state": "granted",
        "migration_state": "not_applicable",
        "reason": None,
    }
    assert report["provider"] == {
        "binding": "configured",
        "credential": "stored",
        "credential_display": "********",
    }
    assert cast(dict[str, object], report["semantic_status"])["semantic_ready"] is True
    assert report["next_steps"] == []
    assert report["marker_written"] is True
    assert state["binding_embedded_flags"] == [False]
    # ADR-049 review round 1: the AI-powered review answer lists the AI recipes.
    assert state["privacy_calls"] == [(None, False, True, True)]
    assert state["ai_review_add_on"] is True
    assert state["status_reads"] == 2
    assert state["restart_calls"] == 2
    assert state["stored"] is True
    targets = cast(list[object], state["credential_targets"])
    assert len(targets) == 1
    assert getattr(targets[0], "repository_privacy_commitment") == "hmac-sha256:" + "7" * 64
    assert "Hidden credential ceremony begins now" in result.stdout
    assert "Credential: ********" in result.stdout
    assert "AI-powered advice readiness: ready" in result.stdout


def test_no_codex_found_still_completes_with_guidance(wizard_env: dict[str, object]) -> None:
    wizard_env["binaries"] = ()
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["registration"] == {
        "outcome": "skipped",
        "reason": "codex_not_found",
        "state": None,
    }


def test_setup_status_is_read_only(wizard_env: dict[str, object]) -> None:
    wizard_env["outputs"] = [_finishup_entry()]
    result = _RUNNER.invoke(cli.app, ["setup", "status", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["schema"] == "yoetz.setup-status/2"
    assert report["discovered"][0]["registration_state"] == "yoetz_owned"
    # `finishup_owned` reads the same for both serve commands, so the row has to name the route.
    assert report["discovered"][0]["registered_route_profile"] == "strict"
    assert report["marker_present"] is False
    assert report["service"]["reachable"] is False
    # Host facts are named once here rather than per rejected check (issues #720, #721, #724).
    platform_report = report["platform"]
    assert set(platform_report) == {"cell", "check_sandbox", "secure_storage"}
    assert set(platform_report["cell"]) == {
        "cell",
        "certified",
        "certified_cells",
        "machine",
        "os_name",
    }
    assert platform_report["check_sandbox"]["status"] in {"ready", "unavailable"}
    assert set(platform_report["check_sandbox"]) == {
        "mechanism",
        "reason",
        "remediation",
        "status",
    }
    assert set(platform_report["secure_storage"]) == {
        "approved",
        "backend_id",
        "reason",
        "requirement",
    }
    assert report["integration"] == {
        "hooks": {
            "presence": "absent",
            "trust_observable": False,
            "trust_state": "unknown",
        },
        "plugin": {"digest": None, "presence": "absent"},
        "skill": {
            "automatic_activation_tested": False,
            "compatibility": "unsupported",
            "installed_digest": None,
            "presence": "absent",
            "source_state": "verified",
            "tested_profiles": [],
        },
    }
    assert not cast(Path, wizard_env["marker"]).exists()


def test_setup_status_reports_invalid_packaged_skill_source(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.cli.setup as setup_module

    monkeypatch.setattr(
        setup_module,
        "load_packaged_skill_source",
        lambda: (_ for _ in ()).throw(IntegrationError(IntegrationReason.SOURCE_INVALID, {})),
    )
    wizard_env["outputs"] = [_finishup_entry()]
    result = _RUNNER.invoke(cli.app, ["setup", "status", "--json"])
    assert result.exit_code == 0
    report = json.loads(result.stdout)
    assert report["integration"]["skill"] == {
        "automatic_activation_tested": False,
        "compatibility": "unsupported",
        "installed_digest": None,
        "presence": "unknown",
        "source_state": "source_invalid",
        "tested_profiles": [],
    }


def test_installed_hooks_use_nested_plugin_hook_path(tmp_path: Path) -> None:
    import finishup.cli.setup as setup_module

    hooks_path = tmp_path / ".agents" / "plugins" / "finishup" / "hooks" / "hooks.json"
    hooks_path.parent.mkdir(parents=True)
    hooks_path.write_text(
        '{"hooks":{"SessionStart":[{"command":"finishup hooks observe '
        '--event SessionStart --workspace ."}]}}'
    )

    assert (
        setup_module._installed_hooks_declare_workspace_binding(tmp_path) is True  # pyright: ignore[reportPrivateUsage]
    )


def test_integrate_mcp_status_preview_install(wizard_env: dict[str, object]) -> None:
    wizard_env["outputs"] = _absent_mcp()
    status = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "status", "--json"])
    assert status.exit_code == 0
    absent_status = json.loads(status.stdout)
    assert absent_status["state"] == "absent"
    # An absent entry has no FinishUP route to describe; the field is present and null, never guessed.
    assert absent_status["route_profile"] is None

    wizard_env["outputs"] = _absent_mcp()
    preview = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "preview", "--json"])
    assert preview.exit_code == 0
    body = json.loads(preview.stdout)
    assert body["action"] == "register"
    assert body["preview_digest"].startswith("sha256:")

    wizard_env["outputs"] = [
        *_absent_mcp(),
        *_absent_mcp(),
        CommandOutput(0, b""),
        _finishup_entry(),
    ]
    install = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "install",
            "--accept",
            "--preview-digest",
            body["preview_digest"],
            "--json",
        ],
    )
    assert install.exit_code == 0
    assert json.loads(install.stdout)["state_after"] == "yoetz_owned"


def test_integrate_mcp_status_names_the_registered_route(
    wizard_env: dict[str, object],
) -> None:
    """Status has to distinguish the two owned registrations, or #132's conflation stays.

    Both serve commands classify as ``yoetz_owned``, so an operator reading only the state
    cannot tell whether the agent route can request AI-powered review at all.
    """

    for route_profile in ("strict", "policy"):
        wizard_env["outputs"] = [_finishup_entry(route_profile)]
        result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "status", "--json"])
        assert result.exit_code == 0
        body = json.loads(result.stdout)
        assert body["state"] == "yoetz_owned"
        assert body["route_profile"] == route_profile


def test_integrate_mcp_install_without_accept_fails_closed(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = _absent_mcp()
    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "install", "--json"])
    assert result.exit_code == 2
    assert "confirmation_required" in result.stderr


def test_integrate_mcp_refuses_foreign_entry(wizard_env: dict[str, object]) -> None:
    wizard_env["outputs"] = [CommandOutput(0, json.dumps({"command": "other"}).encode())]
    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "install", "--accept", "--json"])
    assert result.exit_code == 2
    assert "foreign_entry_present" in result.stderr


@pytest.mark.parametrize("exit_code", [0, 1])
def test_integrate_mcp_remove_owned_entry(wizard_env: dict[str, object], exit_code: int) -> None:
    wizard_env["outputs"] = [_finishup_entry()]
    previewed = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "preview-remove", "--json"])
    assert previewed.exit_code == 0, (previewed.output, previewed.exception)
    preview = json.loads(previewed.stdout)
    assert preview["action"] == "unregister"
    assert preview["route_profile"] == "strict"
    assert preview["serve_command"] == list(MCP_STRICT_SERVE_COMMAND)
    assert preview["warnings"] == ["host_remove_not_compare_and_swap"]
    assert preview["preview_digest"].startswith("sha256:")

    wizard_env["outputs"] = [_finishup_entry()]
    refused = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "remove", "--json"])
    assert refused.exit_code == 2
    assert "confirmation_required" in refused.stderr

    wizard_env["outputs"] = [_finishup_entry()]
    unbound = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "remove", "--accept", "--json"])
    assert unbound.exit_code == 2
    assert "confirmation_required" in unbound.stderr

    wizard_env["outputs"] = [
        _finishup_entry(),
        _finishup_entry(),
        _finishup_entry(),
        CommandOutput(exit_code, b""),
        CommandOutput(1, b""),
        CommandOutput(0, b"[]"),
    ]
    result = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "remove",
            "--accept",
            "--preview-digest",
            preview["preview_digest"],
            "--json",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    body = json.loads(result.stdout)
    assert body["action"] == "unregister"
    assert body["state_after"] == "absent"
    assert body["removal"]["warnings"] == (["host_remove_returned_nonzero"] if exit_code else [])


def test_integrate_mcp_interactive_remove_surfaces_complete_warning_bound_preview(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    import finishup.cli.setup as setup_module

    wizard_env["outputs"] = [
        _finishup_entry(),
        _finishup_entry(),
        _finishup_entry(),
        CommandOutput(0, b""),
        *_absent_mcp(),
    ]
    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup_module, "_confirm_registration", lambda: True)

    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "remove"])

    assert result.exit_code == 0, (result.output, result.exception)
    assert "Command: finishup mcp serve --host codex --semantic off" in result.output
    assert "MCP route profile: strict" in result.output
    assert "Warning: host_remove_not_compare_and_swap" in result.output
    assert "Preview digest: sha256:" in result.output


def test_integrate_mcp_remove_absent_entry_is_noop(wizard_env: dict[str, object]) -> None:
    project = cast(Path, wizard_env["marker"]).parent / "project-remove-noop"
    config = project / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        '[mcp_servers.finishup.tools.check]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    wizard_env["outputs"] = _absent_mcp()
    previewed = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "preview-remove",
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert previewed.exit_code == 0, (previewed.output, previewed.exception)
    preview_digest = json.loads(previewed.stdout)["preview_digest"]

    wizard_env["outputs"] = _absent_mcp()
    result = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "remove",
            "--accept",
            "--preview-digest",
            preview_digest,
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    body = json.loads(result.stdout)
    assert body["action"] == "noop"
    assert body["admission_cleanup"]["outcome"] == "removed"
    assert not config.exists()


def test_integrate_mcp_strict_install_noop_still_revokes_host_admission(
    wizard_env: dict[str, object],
) -> None:
    project = cast(Path, wizard_env["marker"]).parent / "project-strict-noop"
    config = project / ".codex" / "config.toml"
    config.parent.mkdir(parents=True)
    config.write_text(
        '[mcp_servers.finishup.tools.check]\napproval_mode = "approve"\n',
        encoding="utf-8",
    )
    # Preview get, then the observe get that reads the registered route.
    wizard_env["outputs"] = [_finishup_entry("strict"), _finishup_entry("strict")]
    result = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "install",
            "--accept",
            "--route-profile",
            "strict",
            "--project-root",
            str(project),
            "--json",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    body = json.loads(result.stdout)
    assert body["action"] == "noop"
    assert body["admission_cleanup"]["outcome"] == "removed"
    assert not config.exists()


def test_integrate_mcp_remove_refuses_foreign_entry(wizard_env: dict[str, object]) -> None:
    wizard_env["outputs"] = [CommandOutput(0, json.dumps({"command": "other"}).encode())]
    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "remove", "--accept", "--json"])
    assert result.exit_code == 2
    assert "foreign_entry_present" in result.stderr


def test_integrate_mcp_remove_refuses_stale_preview_digest(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = [_finishup_entry()]
    result = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "remove",
            "--accept",
            "--preview-digest",
            "sha256:" + "0" * 64,
            "--json",
        ],
    )
    assert result.exit_code == 2
    assert "preview_stale" in result.stderr


def test_non_interactive_accept_preserves_existing_policy_route(
    wizard_env: dict[str, object],
) -> None:
    """#389: ``--accept`` without an explicit route never rewrites an owned registration."""

    wizard_env["outputs"] = [
        _finishup_entry("policy"),  # tentative strict preview get: owned, other route
        _finishup_entry("policy"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy"),  # preserved policy re-preview get: noop
        _finishup_entry("policy"),  # status verify after plugin install
    ]
    result = _RUNNER.invoke(cli.app, ["setup", "run", "--non-interactive", "--accept", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert report["registration"]["outcome"] == "already_registered"
    assert report["registration"]["route_profile"] == "policy"
    assert report["registration"]["route_profile_before"] == "policy"
    assert report["registration"]["serve_command"] == list(MCP_SERVE_COMMAND)
    # No mutating ``mcp add`` ever ran: the existing policy route survives.
    for calls in cast(list[list[tuple[str, ...]]], wizard_env["calls"]):
        assert all(call[1:3] in {("mcp", "get"), ("mcp", "list")} for call in calls)


def test_explicit_route_profile_flag_reregisters_and_reports_the_transition(
    wizard_env: dict[str, object],
) -> None:
    """#389: only an explicit ``--route-profile`` may change an existing owned route."""

    wizard_env["outputs"] = [
        _finishup_entry("policy"),  # preview get: owned on the policy route
        _finishup_entry("policy"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy"),  # adapter apply re-preview get
        CommandOutput(0, b""),  # add
        _finishup_entry("strict"),  # verify get
    ]
    result = _RUNNER.invoke(
        cli.app,
        [
            "setup",
            "run",
            "--non-interactive",
            "--accept",
            "--route-profile",
            "strict",
            "--json",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    assert report["registration"]["outcome"] == "reregistered"
    assert report["registration"]["route_profile"] == "strict"
    assert report["registration"]["route_profile_before"] == "policy"


def test_route_profile_flag_rejects_unknown_values(wizard_env: dict[str, object]) -> None:
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run", "--non-interactive", "--accept", "--route-profile", "open", "--json"],
    )
    assert result.exit_code == 2


def test_interactive_preview_surfaces_a_route_profile_transition(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """#389: a route change must be visible in the preview the human confirms."""

    import finishup.cli.provider_binding as provider_binding
    import finishup.cli.setup as setup_module

    wizard_env["outputs"] = [
        _finishup_entry("strict"),  # preview get: owned on the strict route (an earlier setup)
        _finishup_entry("strict"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("strict"),  # adapter apply re-preview get
        CommandOutput(0, b""),  # add
        _finishup_entry("policy"),  # verify get
    ]
    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(
        provider_binding, "prompt_provider_endpoint_binding", _skip_provider_binding
    )

    # Installation, home, local-only review, update checks yes, confirm. ADR-049: every answer
    # registers the policy route, so an earlier strict registration visibly moves to it.
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n2\nY\nY\n",
    )

    assert result.exit_code == 0, (result.output, result.exception)
    assert "MCP route profile change: strict -> policy" in result.stdout
    assert "MCP route profile: policy (changed from strict)" in result.stdout


def test_failed_activation_preview_reports_bound_home_and_real_reason(
    wizard_env: dict[str, object],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """#390: an explicit ``--codex-home`` failure must not read as ``codex_home_required``."""

    import finishup.cli.setup as setup_module

    codex = tmp_path / "codex-testing"
    codex.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    codex.chmod(0o700)
    codex_home = cast(Path, wizard_env["codex_home"])

    def conflicted(*_args: object, **_kwargs: object) -> object:
        raise IntegrationError(IntegrationReason.DESTINATION_CONFLICT, {})

    monkeypatch.setattr(setup_module, "preview_activation", conflicted)
    monkeypatch.setattr(setup_module, "inspect_activation", conflicted)
    wizard_env["outputs"] = [
        *_absent_mcp(),  # preview: confirmed absent
        *_absent_mcp(),  # apply re-preview: confirmed absent
        CommandOutput(0, b""),  # add
        _finishup_entry(),  # verify get
    ]

    result = _RUNNER.invoke(
        cli.app,
        [
            "setup",
            "run",
            "--non-interactive",
            "--accept",
            "--codex-path",
            str(codex),
            "--codex-home",
            str(codex_home),
            "--json",
        ],
    )

    assert result.exit_code == 0, (result.output, result.exception)
    report = json.loads(result.stdout)
    activation = report["registration"]["plugin_activation"]
    assert activation["outcome"] == "skipped"
    assert activation["reason"] == "destination_conflict"
    assert activation["codex_home"] == str(codex_home)
    assert activation["config_path"] == str(codex_home / "config.toml")
    readiness_activation = report["readiness"]["plugin_activation"]
    assert readiness_activation["codex_home"] == str(codex_home)
    assert readiness_activation["config_path"] == str(codex_home / "config.toml")
    assert readiness_activation["reason"] == "destination_conflict"
    # Unobserved facts are reported as unknown (null), never asserted false.
    assert readiness_activation["marketplace_registered"] is None
    assert readiness_activation["plugin_enabled"] is None


def test_integrate_mcp_install_without_route_input_preserves_owned_policy_route(
    wizard_env: dict[str, object],
) -> None:
    """#389: the ``integrate codex mcp`` surface must not rewrite an owned route either."""

    wizard_env["outputs"] = [
        _finishup_entry("policy"),  # derived-strict preview get: owned, other route
        _finishup_entry("policy"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy"),  # preserved policy re-preview get: noop
    ]
    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "install", "--accept", "--json"])
    assert result.exit_code == 0, (result.output, result.exception)
    body = json.loads(result.stdout)
    assert body["action"] == "noop"
    assert body["state_after"] == "yoetz_owned"
    for calls in cast(list[list[tuple[str, ...]]], wizard_env["calls"]):
        assert all(call[1:3] in {("mcp", "get"), ("mcp", "list")} for call in calls)


def test_integrate_mcp_preview_names_the_observed_route_before(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = [
        _finishup_entry("policy"),
        _finishup_entry("policy"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy"),
    ]
    result = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "preview", "--json"])
    assert result.exit_code == 0
    body = json.loads(result.stdout)
    assert body["action"] == "noop"
    assert body["route_profile"] == "policy"
    assert body["route_profile_before"] == "policy"


def test_integrate_mcp_explicit_route_profile_reregisters(
    wizard_env: dict[str, object],
) -> None:
    wizard_env["outputs"] = [
        _finishup_entry("policy"),  # preview get: owned on the policy route
        _finishup_entry("policy"),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy"),  # adapter apply re-preview get
        CommandOutput(0, b""),  # add
        _finishup_entry("strict"),  # verify get
    ]
    result = _RUNNER.invoke(
        cli.app,
        [
            "integrate",
            "codex",
            "mcp",
            "install",
            "--accept",
            "--route-profile",
            "strict",
            "--json",
        ],
    )
    assert result.exit_code == 0, (result.output, result.exception)
    body = json.loads(result.stdout)
    assert body["action"] == "reregister"
    assert body["state_after"] == "yoetz_owned"


def test_absolute_mcp_cli_preserves_launcher_and_route(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch
) -> None:
    launcher = "/test/FinishUP Runtime/bin/finishup"
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.installed_launcher",
        lambda: (launcher, "sha256:" + "e" * 64),
    )
    monkeypatch.setattr("finishup.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    wizard_env["outputs"] = _absent_mcp()
    preview = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "preview", "--json"])
    assert preview.exit_code == 0, (preview.output, preview.exception)
    assert json.loads(preview.stdout)["serve_command"][0] == launcher
    wizard_env["outputs"] = [
        *_absent_mcp(),
        *_absent_mcp(),
        CommandOutput(0, b""),
        _finishup_entry(launcher=launcher),
        _finishup_entry(launcher=launcher),
    ]
    installed = _RUNNER.invoke(
        cli.app, ["integrate", "codex", "mcp", "install", "--accept", "--json"]
    )
    assert installed.exit_code == 0, (installed.output, installed.exception)
    assert json.loads(installed.stdout)["state_after"] == "yoetz_owned"
    calls = [
        call for group in cast(list[list[tuple[str, ...]]], wizard_env["calls"]) for call in group
    ]
    additions = [call for call in calls if call[1:3] == ("mcp", "add")]
    assert additions[0][additions[0].index("--") + 1] == launcher

    # No explicit route input must retain the existing policy route, even though setup's
    # configured default in this fixture is strict.
    wizard_env["outputs"] = [
        _finishup_entry("policy", launcher=launcher),
        _finishup_entry(
            "policy", launcher=launcher
        ),  # observe get: the registered route (#1058 review round 3)
        _finishup_entry("policy", launcher=launcher),
    ]
    noop = _RUNNER.invoke(cli.app, ["integrate", "codex", "mcp", "install", "--accept", "--json"])
    assert noop.exit_code == 0, (noop.output, noop.exception)
    assert json.loads(noop.stdout)["action"] == "noop"


def test_setup_surfaces_no_secret_shaped_option() -> None:
    for args in (
        ["--help"],
        ["setup", "run", "--help"],
        ["setup", "status", "--help"],
    ):
        result = _RUNNER.invoke(cli.app, args)
        assert result.exit_code == 0
        lowered = result.stdout.lower()
        for token in ("api-key", "apikey", "password"):
            assert token not in lowered, (args, token)


def test_bare_invocation_without_tty_prints_help() -> None:
    result = _RUNNER.invoke(cli.app, [])
    assert result.exit_code == 0
    assert "Usage" in result.stdout
    assert "docs/usage/agent-start.md" in result.stdout


def test_root_privacy_shortcut_dispatches_guided_privacy_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[str] = []

    async def privacy_setup() -> int:
        calls.append("privacy")
        return 0

    monkeypatch.setattr(cli, "_run_privacy_setup_command", privacy_setup)

    result = _RUNNER.invoke(cli.app, ["--privacy"])

    assert result.exit_code == 0
    assert calls == ["privacy"]


def test_root_privacy_shortcut_rejects_provider_setup_options() -> None:
    result = _RUNNER.invoke(cli.app, ["--privacy", "--set"], env={"NO_COLOR": "1"})

    assert result.exit_code == 2
    assert "--privacy cannot be combined" in _plain(result.output)


def test_root_set_fireworks_dispatches_simple_provider_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module

    received: dict[str, object] = {}

    async def fake_provider_setup(*, fireworks: bool, model: str | None) -> int:
        received.update(fireworks=fireworks, model=model)
        return 0

    monkeypatch.setattr(setup_module, "run_provider_setup", fake_provider_setup)
    result = _RUNNER.invoke(
        cli.app,
        [
            "--set",
            "--fireworks",
            "--model",
            "accounts/fireworks/models/minimax-m3",
        ],
    )

    assert result.exit_code == 0
    assert received == {
        "fireworks": True,
        "model": "accounts/fireworks/models/minimax-m3",
    }


def test_root_set_dispatches_new_provider_setup_without_secret_argument(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module

    received: dict[str, object] = {}

    async def fake_provider_setup(**kwargs: object) -> int:
        received.update(kwargs)
        return 0

    monkeypatch.setattr(setup_module, "run_provider_setup", fake_provider_setup)
    result = _RUNNER.invoke(
        cli.app,
        ["--set", "--provider", "anthropic", "--model", "claude-sonnet-4-6"],
    )

    assert result.exit_code == 0
    assert received == {
        "fireworks": False,
        "provider": "anthropic",
        "model": "claude-sonnet-4-6",
    }


def test_root_set_grok_dispatches_simple_provider_setup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module

    received: dict[str, object] = {}

    async def fake_provider_setup(**kwargs: object) -> int:
        received.update(kwargs)
        return 0

    monkeypatch.setattr(setup_module, "run_provider_setup", fake_provider_setup)
    result = _RUNNER.invoke(cli.app, ["--set", "--grok", "--model", "grok-4.5"])

    assert result.exit_code == 0
    assert received == {"fireworks": False, "model": "grok-4.5", "grok": True}


def test_provider_flags_require_set() -> None:
    # Rich may colorize option tokens inside the Error panel (e.g. FORCE_COLOR CI),
    # splitting "--set" across ANSI codes; assert on the stripped combined output.
    result = _RUNNER.invoke(cli.app, ["--fireworks"], env={"NO_COLOR": "1"})
    assert result.exit_code == 2
    assert "require --set" in _plain(result.output)


def test_provider_setup_success_reports_layers_without_ready_overclaim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module
    from finishup.cli.privacy_setup import PrivacySetupReport

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready"}

    async def fake_interactive(
        service: dict[str, object],
        *,
        provider_choice: str | None = None,
        model: str | None = None,
        before_credential: Callable[[], Awaitable[str | None]] | None = None,
        project: Path | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        del provider_choice, model, project
        assert before_credential is not None
        # None means the privacy step did not block the credential step.
        assert await before_credential() is None
        return service, {"binding": "configured", "credential": "stored"}

    async def fake_privacy_setup(**_kwargs: object) -> PrivacySetupReport:
        return PrivacySetupReport("configured", "trusted_provider")

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)
    monkeypatch.setattr(setup_module, "_interactive_provider_setup", fake_interactive)
    monkeypatch.setattr("finishup.cli.privacy_setup.run_privacy_setup", fake_privacy_setup)

    result = _RUNNER.invoke(cli.app, ["--set", "--fireworks", "--model", "m"], input="Y\n")
    plain = _plain(result.output)
    assert result.exit_code == 0
    assert "FinishUP is ready to use this provider." not in plain
    assert "Provider binding and vault credential storage succeeded" in plain
    assert "SDK extra (semantic-openai):" in plain
    assert "_semantic_not_configured" in plain
    assert "Privacy policy: configured" in plain
    assert "Transport probe: not demonstrated" in plain
    assert "Installed artifact evidence: not demonstrated" in plain
    assert "not proof of live provider dispatch or AI-powered review" in plain


@pytest.mark.parametrize(
    "choice",
    [
        "official_openai",
        "fireworks",
        "anthropic",
        "google_gemini",
        "openrouter",
        "grok",
        "vercel_ai_gateway",
    ],
)
def test_secure_set_paths_share_provider_model_picker(
    choice: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.setup as setup_module
    import finishup.config.load as config_module

    picked: list[str] = []
    applied: list[tuple[str, str]] = []

    def fake_pick(selected_choice: str) -> str:
        picked.append(selected_choice)
        return "selected-model"

    def fake_apply(selected_choice: str, *, model: str) -> tuple[Path, object]:
        applied.append((selected_choice, model))
        return tmp_path / "config.toml", object()

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(provider=None)

    monkeypatch.setattr(binding_module, "prompt_provider_model", fake_pick)
    monkeypatch.setattr(binding_module, "apply_provider_endpoint_choice", fake_apply)
    monkeypatch.setattr(config_module, "load_config", fake_load_config)

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "unavailable"},
            provider_choice=choice,
        )
    )

    assert picked == [choice]
    assert applied == [(choice, "selected-model")]
    assert report["binding"] == "configured"
    assert report["credential_reason"] == "service_not_ready"


def test_uninitialized_provider_setup_provisions_auto_unlock(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The wizard must keep the auto-unlock write side reachable in product code."""

    import finishup.adapters.keys.os_keyring as keyring_module
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.paths as paths_module

    calls: list[str] = []
    supplied: list[bytes] = []
    loaded_env: list[object] = []

    def fake_slot_report(_store: object) -> dict[str, str]:
        return {
            "active": "absent",
            "staged_initialization": "absent",
            "staged_rotation": "absent",
        }

    def fake_stage_for_initialization(_store: object) -> bytearray:
        calls.append("stage_for_initialization")
        return bytearray(b"a" * 48)

    def fake_promote(_store: object) -> None:
        calls.append("promote_staged_initialization")

    async def fake_initialize(passphrase: bytearray | None = None) -> object:
        supplied.append(bytes(passphrase or b""))
        return SimpleNamespace(state="ready", reason="succeeded")

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    def fake_bundle_root(*, _data_dir: Path | None = None, _probe: object | None = None) -> Path:
        del _data_dir, _probe
        return tmp_path.resolve()

    def fake_load_config(overrides: object, env: object, config_path: object) -> SimpleNamespace:
        del overrides, config_path
        loaded_env.append(env)
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path))

    monkeypatch.setattr(
        keyring_module.AutoUnlockPassphraseStore,
        "slot_report",
        fake_slot_report,
    )
    monkeypatch.setattr(
        keyring_module.AutoUnlockPassphraseStore,
        "stage_for_initialization",
        fake_stage_for_initialization,
    )
    monkeypatch.setattr(
        keyring_module.AutoUnlockPassphraseStore,
        "promote_staged_initialization",
        fake_promote,
    )
    monkeypatch.setattr(unlock_module, "initialize_passphrase_vault", fake_initialize)
    monkeypatch.setattr(binding_module, "prompt_provider_endpoint_binding", _skip_provider_binding)
    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(paths_module, "bundle_root", fake_bundle_root)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)

    service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "locked", "vault_mode": "uninitialized"}
        )
    )

    assert calls == ["stage_for_initialization", "promote_staged_initialization"]
    assert loaded_env == [os.environ]
    assert supplied == [b"a" * 48]
    assert service["state"] == "ready"
    assert report["binding"] == "skipped"


def test_uninitialized_setup_refuses_preexisting_auto_unlock_entry(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """RT-vault-secrets-1 / ADR-015: pre-existing scoped entry must block vault init.

    Interactive setup must use stage_for_initialization (like elevated bootstrap)
    and must never submit a pre-planted auto-unlock secret to vault_initialize.
    """

    import base64
    import hashlib

    import finishup.adapters.keys.os_keyring as keyring_module
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.paths as paths_module

    # Known secret that must not become the vault root passphrase.
    planted = bytearray(b"attacker-known-vault-secret-0123456789abcdef!!!!")
    assert 32 <= len(planted) <= 128

    class _AtomicBackend:
        def __init__(self) -> None:
            self.values: dict[tuple[str, str], str] = {}

        def get_password(self, service: str, username: str) -> str | None:
            return self.values.get((service, username))

        def set_password(self, service: str, username: str, password: str) -> None:
            self.values[(service, username)] = password

        def delete_password(self, service: str, username: str) -> None:
            del self.values[(service, username)]

    backend = _AtomicBackend()
    store = keyring_module.AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = (  # pyright: ignore[reportPrivateUsage]
        "keyring.backends.macOS.Keyring"
    )
    store.save(bytearray(planted))
    encoded = base64.urlsafe_b64encode(planted).rstrip(b"=").decode("ascii")
    username = (
        "bundle-" + hashlib.sha256(os.fsencode(os.path.abspath(tmp_path.resolve()))).hexdigest()
    )
    assert backend.values[("yoetz.auto-unlock.v1", username)] == encoded
    with pytest.raises(keyring_module.OSKeyringError) as elevated_exc:
        store.stage_for_initialization()
    assert elevated_exc.value.reason == "entry_exists"

    supplied: list[bytes] = []

    async def fake_initialize(passphrase: bytearray | None = None) -> object:
        supplied.append(bytes(passphrase or b""))
        return object()

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    def fake_store(_path: Path) -> keyring_module.AutoUnlockPassphraseStore:
        return store

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path))

    def fake_bundle_root(*, _data_dir: Path | None = None, _probe: object | None = None) -> Path:
        del _data_dir, _probe
        return tmp_path.resolve()

    monkeypatch.setattr(keyring_module, "AutoUnlockPassphraseStore", fake_store)
    monkeypatch.setattr(unlock_module, "initialize_passphrase_vault", fake_initialize)
    monkeypatch.setattr(binding_module, "prompt_provider_endpoint_binding", _skip_provider_binding)
    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(paths_module, "bundle_root", fake_bundle_root)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)

    service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "locked", "vault_mode": "uninitialized"}
        )
    )

    # Fail-closed: no vault_initialize with the planted secret; entry unchanged.
    assert supplied == []
    assert service == {"reachable": True, "state": "locked", "vault_mode": "uninitialized"}
    assert report["credential_reason"] == "auto_unlock_entry_exists"
    assert report["binding"] == "skipped"
    assert backend.values[("yoetz.auto-unlock.v1", username)] == encoded

    # Blocking is only useful if the operator can find and clear the entry that blocked them,
    # and the message must never echo the secret it refused to adopt.
    stderr = capsys.readouterr().err
    assert "yoetz.auto-unlock.v1" in stderr
    assert username in stderr
    assert "finishup setup" in stderr
    assert encoded not in stderr
    assert planted.decode("ascii") not in stderr


def test_uninitialized_setup_stops_after_write_with_failed_readback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An ambiguous committed entry must never trigger a different manual passphrase."""

    import finishup.adapters.keys.os_keyring as keyring_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.paths as paths_module

    class _WriteThenUnreadable:
        def __init__(self) -> None:
            self.written: str | None = None

        def get_password(self, service: str, username: str) -> None:
            del service, username
            return None

        def set_password(self, service: str, username: str, password: str) -> None:
            del service, username
            self.written = password

        def delete_password(self, service: str, username: str) -> None:
            del service, username

    backend = _WriteThenUnreadable()
    store = keyring_module.AutoUnlockPassphraseStore(tmp_path.resolve(), backend=backend)
    store._backend_id = (  # pyright: ignore[reportPrivateUsage]
        "keyring.backends.macOS.Keyring"
    )
    initialized: list[bytes] = []

    async def fake_initialize(passphrase: bytearray | None = None) -> object:
        initialized.append(bytes(passphrase or b""))
        return object()

    def fake_store(_path: Path) -> keyring_module.AutoUnlockPassphraseStore:
        return store

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path))

    def fake_bundle_root(*, _data_dir: Path | None = None) -> Path:
        del _data_dir
        return tmp_path.resolve()

    monkeypatch.setattr(keyring_module, "AutoUnlockPassphraseStore", fake_store)
    monkeypatch.setattr(unlock_module, "initialize_passphrase_vault", fake_initialize)
    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(paths_module, "bundle_root", fake_bundle_root)

    service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "locked", "vault_mode": "uninitialized"}
        )
    )

    assert backend.written is not None
    assert initialized == []
    assert service == {"reachable": True, "state": "locked", "vault_mode": "uninitialized"}
    assert report["credential_reason"] == "auto_unlock_unverified"


def test_ready_auto_unlock_vault_reuses_scoped_secret_for_provider_reauthentication(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Fresh Keychain-backed setup must ask only for the provider credential."""

    import finishup.adapters.keys.os_keyring as keyring_module
    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.paths as paths_module
    import finishup.config.write as write_module

    loaded: list[bytes] = []
    supplied_reauthentication: list[bytes | None] = []

    def fake_load(_store: object) -> bytearray:
        loaded.append(b"a" * 48)
        return bytearray(b"a" * 48)

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(
            storage=SimpleNamespace(data_dir=tmp_path),
            provider=SimpleNamespace(
                provider_id="fireworks",
                model="accounts/fireworks/models/minimax-m3",
                endpoint_profile_id="fireworks-responses",
                endpoint_profile_version="1.0.0",
            ),
        )

    def fake_bundle_root(*, _data_dir: Path | None = None) -> Path:
        del _data_dir
        return tmp_path.resolve()

    def fake_write(_choice: str, *, model: str) -> tuple[Path, object]:
        assert _choice == "fireworks"
        assert model == "accounts/fireworks/models/minimax-m3"
        return tmp_path / "config.toml", object()

    async def fake_set(
        _target: object,
        _credential: bytearray | None,
        reauthentication: bytearray | None,
    ) -> SimpleNamespace:
        supplied_reauthentication.append(
            None if reauthentication is None else bytes(reauthentication)
        )
        return SimpleNamespace(activation_status="stored")

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    async def fake_restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    async def fake_provider_status() -> dict[str, object]:
        return {"credential_connected": False}

    def fake_provider_preset(_provider: str) -> SimpleNamespace:
        return SimpleNamespace(choice="fireworks", provider_id="fireworks")

    monkeypatch.setattr(keyring_module.AutoUnlockPassphraseStore, "load", fake_load)
    monkeypatch.setattr(
        privacy_setup_module,
        "get_privacy_setup_snapshot",
        _fake_repository_privacy_snapshot,
    )
    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(paths_module, "bundle_root", fake_bundle_root)
    monkeypatch.setattr(binding_module, "apply_provider_endpoint_choice", fake_write)
    monkeypatch.setattr(unlock_module, "set_provider_credential", fake_set)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)
    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", fake_restart)
    import finishup.cli.provider_status as provider_status_module

    monkeypatch.setattr(provider_status_module, "provider_status_report", fake_provider_status)
    monkeypatch.setattr(
        write_module,
        "provider_preset",
        fake_provider_preset,
    )

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "ready", "vault_mode": "passphrase"},
            provider_choice="fireworks",
            model="accounts/fireworks/models/minimax-m3",
        )
    )

    assert loaded == [b"a" * 48]
    assert supplied_reauthentication == [b"a" * 48]
    assert report["binding"] == "configured"
    assert report["credential"] == "stored"
    assert report["credential_display"] == "********"


def test_existing_bound_credential_can_be_reused_without_requesting_it_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.provider_status as provider_status_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.write as write_module

    provider = SimpleNamespace(
        provider_id="fireworks",
        model="accounts/fireworks/models/minimax-m3",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
    )

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path), provider=provider)

    def fake_write(*_args: object, **_kwargs: object) -> tuple[Path, object]:
        return tmp_path / "config.toml", object()

    def fake_preset(_provider: object) -> SimpleNamespace:
        return SimpleNamespace(choice="fireworks", provider_id="fireworks")

    monkeypatch.setattr(
        config_module,
        "load_config",
        fake_load_config,
    )
    monkeypatch.setattr(
        binding_module,
        "apply_provider_endpoint_choice",
        fake_write,
    )
    monkeypatch.setattr(write_module, "provider_preset", fake_preset)

    async def fake_restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": "passphrase"}

    async def fake_status() -> dict[str, object]:
        return {"credential_connected": True}

    async def forbidden_set(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("stored credential must not be requested again")

    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", fake_restart)
    monkeypatch.setattr(provider_status_module, "provider_status_report", fake_status)
    monkeypatch.setattr(unlock_module, "set_provider_credential", forbidden_set)

    def reuse(*_args: object, **_kwargs: object) -> bool:
        return True

    monkeypatch.setattr(setup_module, "_prompt_yes_no_before_credential", reuse)

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "ready", "vault_mode": "passphrase"},
            provider_choice="fireworks",
            model="accounts/fireworks/models/minimax-m3",
        )
    )

    assert report["credential"] == "stored"
    assert report["credential_display"] == "********"


@pytest.mark.parametrize(
    ("result_lost", "expected_credential"),
    [(False, "stored"), (True, "failed")],
)
def test_existing_bound_credential_replacement_does_not_inherit_old_presence(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    result_lost: bool,
    expected_credential: str,
) -> None:
    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.provider_status as provider_status_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.write as write_module
    from finishup.service.confidential_client import ConfidentialClientError

    provider = SimpleNamespace(
        provider_id="fireworks",
        model="accounts/fireworks/models/minimax-m3",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
    )
    replacements: list[object] = []

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path), provider=provider)

    def fake_write(*_args: object, **_kwargs: object) -> tuple[Path, object]:
        return tmp_path / "config.toml", object()

    def fake_preset(_provider: object) -> SimpleNamespace:
        return SimpleNamespace(choice="fireworks", provider_id="fireworks")

    async def fake_restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": "os_managed"}

    async def fake_status() -> dict[str, object]:
        return {"credential_connected": True}

    async def replace(target: object, *_args: object, **_kwargs: object) -> SimpleNamespace:
        replacements.append(target)
        if result_lost:
            raise ConfidentialClientError("ambiguous")
        return SimpleNamespace(activation_status="stored")

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready", "vault_mode": "os_managed"}

    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(
        privacy_setup_module,
        "get_privacy_setup_snapshot",
        _fake_repository_privacy_snapshot,
    )
    monkeypatch.setattr(binding_module, "apply_provider_endpoint_choice", fake_write)
    monkeypatch.setattr(write_module, "provider_preset", fake_preset)
    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", fake_restart)
    monkeypatch.setattr(provider_status_module, "provider_status_report", fake_status)
    monkeypatch.setattr(unlock_module, "set_provider_credential", replace)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)

    def replace_stored(*_args: object, **_kwargs: object) -> bool:
        return False

    monkeypatch.setattr(setup_module, "_prompt_yes_no_before_credential", replace_stored)

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "ready", "vault_mode": "os_managed"},
            provider_choice="fireworks",
            model="accounts/fireworks/models/minimax-m3",
        )
    )

    assert len(replacements) == 1
    assert report["credential"] == expected_credential
    if result_lost:
        assert report["credential_reason"] == "credential_ambiguous"
        assert "credential_display" not in report
    else:
        assert report["credential_display"] == "********"


def test_lost_credential_result_recovers_from_recomposed_presence(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.privacy_setup as privacy_setup_module
    import finishup.cli.provider_binding as binding_module
    import finishup.cli.provider_status as provider_status_module
    import finishup.cli.setup as setup_module
    import finishup.cli.unlock as unlock_module
    import finishup.config.load as config_module
    import finishup.config.write as write_module
    from finishup.service.confidential_client import ConfidentialClientError

    provider = SimpleNamespace(
        provider_id="fireworks",
        model="accounts/fireworks/models/minimax-m3",
        endpoint_profile_id="fireworks-responses",
        endpoint_profile_version="1.0.0",
    )
    status_reads = iter((False, True))

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(storage=SimpleNamespace(data_dir=tmp_path), provider=provider)

    def fake_write(*_args: object, **_kwargs: object) -> tuple[Path, object]:
        return tmp_path / "config.toml", object()

    def fake_preset(_provider: object) -> SimpleNamespace:
        return SimpleNamespace(choice="fireworks", provider_id="fireworks")

    monkeypatch.setattr(
        config_module,
        "load_config",
        fake_load_config,
    )
    monkeypatch.setattr(
        privacy_setup_module,
        "get_privacy_setup_snapshot",
        _fake_repository_privacy_snapshot,
    )
    monkeypatch.setattr(
        binding_module,
        "apply_provider_endpoint_choice",
        fake_write,
    )
    monkeypatch.setattr(write_module, "provider_preset", fake_preset)

    async def fake_restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": "os_managed"}

    async def fake_status() -> dict[str, object]:
        return {"credential_connected": next(status_reads)}

    async def lost_result(*_args: object, **_kwargs: object) -> object:
        raise ConfidentialClientError("ambiguous")

    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", fake_restart)
    monkeypatch.setattr(provider_status_module, "provider_status_report", fake_status)
    monkeypatch.setattr(unlock_module, "set_provider_credential", lost_result)

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "ready", "vault_mode": "os_managed"},
            provider_choice="fireworks",
            model="accounts/fireworks/models/minimax-m3",
        )
    )

    assert report["credential"] == "stored"
    assert report["credential_display"] == "********"
    assert report["credential_reason"] == "stored_result_recovered"


def test_human_report_states_why_the_credential_was_not_stored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The JSON report already carried the cause; the human run showed a blank credential."""

    import finishup.cli.setup as setup_module

    setup_module._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {"outcome": "already_registered"},
            "service": {"reachable": True, "state": "ready"},
            "provider": {
                "binding": "configured",
                "credential": "failed",
                "credential_reason": "repository_privacy_scope_unavailable",
            },
            "privacy": {"outcome": "failed", "profile": "unknown", "reason": "grant_missing"},
            "integration": {},
            "next_steps": [],
        }
    )

    plain = _plain(capsys.readouterr().out)
    assert "Credential reason: repository_privacy_scope_unavailable" in plain


def test_human_report_omits_a_credential_reason_once_the_credential_is_stored(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import finishup.cli.setup as setup_module

    setup_module._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {"outcome": "already_registered"},
            "service": {"reachable": True, "state": "ready"},
            "provider": {
                "binding": "configured",
                "credential": "stored",
                "credential_reason": "stored_result_recovered",
            },
            "integration": {},
            "next_steps": [],
        }
    )

    assert "Credential reason:" not in _plain(capsys.readouterr().out)


@pytest.mark.parametrize("login_reused", [True, False])
def test_human_report_states_whether_the_codex_sign_in_was_reused(
    capsys: pytest.CaptureFixture[str], login_reused: bool
) -> None:
    """First-run must say when setup reused the dedicated home's existing Codex login (#534)."""

    import finishup.cli.setup as setup_module

    setup_module._emit_human_report(  # pyright: ignore[reportPrivateUsage]
        {
            "registration": {"outcome": "already_registered"},
            "service": {"reachable": True, "state": "ready"},
            "provider": {
                "binding": "configured",
                "credential": "external_runtime_oauth",
                "login_reused": login_reused,
            },
            "integration": {},
            "next_steps": [],
        }
    )

    plain = _plain(capsys.readouterr().out)
    assert "Credential authority: Codex-managed ChatGPT login" in plain
    assert ("Sign-in: reused the existing Codex login" in plain) is login_reused


def test_blocked_privacy_step_reports_its_own_reason_for_the_credential(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """privacy_setup_incomplete hid the exact privacy cause the report already knew."""

    import finishup.cli.provider_binding as binding_module
    import finishup.cli.setup as setup_module
    import finishup.config.load as config_module
    import finishup.config.write as write_module

    def fake_write(_choice: str, *, model: str) -> tuple[Path, object]:
        del model
        return tmp_path / "config.toml", object()

    def fake_load_config(*_args: object) -> SimpleNamespace:
        return SimpleNamespace(
            storage=SimpleNamespace(data_dir=tmp_path),
            provider=SimpleNamespace(
                provider_id="fireworks",
                model="accounts/fireworks/models/minimax-m3",
                endpoint_profile_id="fireworks-responses",
                endpoint_profile_version="1.0.0",
            ),
        )

    def fake_provider_preset(_provider: str) -> SimpleNamespace:
        return SimpleNamespace(choice="fireworks", provider_id="fireworks")

    async def fake_restart() -> dict[str, object]:
        return {"reachable": True, "state": "ready", "vault_mode": "os_keyring"}

    async def blocked() -> str | None:
        return "privacy_authority_required"

    monkeypatch.setattr(config_module, "load_config", fake_load_config)
    monkeypatch.setattr(binding_module, "apply_provider_endpoint_choice", fake_write)
    monkeypatch.setattr(write_module, "provider_preset", fake_provider_preset)
    monkeypatch.setattr(setup_module, "_restart_service_for_semantic_composition", fake_restart)

    _service, report = asyncio.run(
        setup_module._interactive_provider_setup(  # pyright: ignore[reportPrivateUsage]
            {"reachable": True, "state": "ready", "vault_mode": "os_keyring"},
            provider_choice="fireworks",
            model="accounts/fireworks/models/minimax-m3",
            before_credential=blocked,
        )
    )

    assert report["credential"] != "stored"
    assert report["credential_reason"] == "privacy_authority_required"


def test_set_reports_the_underlying_privacy_reason_rather_than_a_generic_block(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module
    from finishup.cli.privacy_setup import PrivacySetupReport

    async def fake_reachability(*, start_if_absent: bool = False) -> dict[str, object]:
        del start_if_absent
        return {"reachable": True, "state": "ready"}

    async def fake_interactive(
        service: dict[str, object],
        *,
        provider_choice: str | None = None,
        model: str | None = None,
        before_credential: Callable[[], Awaitable[str | None]] | None = None,
        project: Path | None = None,
    ) -> tuple[dict[str, object], dict[str, object]]:
        del provider_choice, model, project
        assert before_credential is not None
        reason = await before_credential()
        return service, {
            "binding": "configured",
            "credential": "skipped",
            "credential_reason": reason,
        }

    async def fake_privacy_setup(**_kwargs: object) -> PrivacySetupReport:
        return PrivacySetupReport("failed", "unknown", reason="privacy_setup_grant_missing")

    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    monkeypatch.setattr(setup_module, "_service_reachability", fake_reachability)
    monkeypatch.setattr(setup_module, "_interactive_provider_setup", fake_interactive)
    monkeypatch.setattr("finishup.cli.privacy_setup.run_privacy_setup", fake_privacy_setup)

    result = _RUNNER.invoke(cli.app, ["--set", "--fireworks", "--model", "m"], input="Y\n")

    assert result.exit_code == 20
    assert "Reason: privacy_setup_grant_missing" in _plain(result.output)


@pytest.mark.parametrize("approved", [True, False])
def test_interactive_setup_reconfirms_mcp_entry_exposed_by_plugin_activation(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch, approved: bool
) -> None:
    import finishup.cli.setup as setup_module

    # ADR-049: the local-only answer registers the policy route, so an activation that exposes
    # a strict entry is the different one the owner must reconfirm.
    wizard_env["outputs"] = [
        *_absent_mcp(),
        _finishup_entry("strict"),  # Activation exposes the bundled entry after the first preview.
        _finishup_entry("strict"),  # The replacement preview must describe that actual entry.
        *(
            [_finishup_entry("strict"), CommandOutput(0, b""), _finishup_entry("policy")]
            if approved
            else []
        ),
    ]
    monkeypatch.setattr(setup_module, "_is_interactive_terminal", lambda: True)
    answer = "Y" if approved else "N"
    result = _RUNNER.invoke(
        cli.app,
        ["setup", "run"],
        input=f"1\n{wizard_env['codex_home']}\n2\nY\nY\n{answer}\n",
    )
    assert result.exit_code == 0, (result.output, result.exception)
    assert "Plugin activation changed the effective MCP entry" in result.stdout
    assert "Confirm updated MCP registration?" in result.stdout
    calls = [
        call for group in cast(list[list[tuple[str, ...]]], wizard_env["calls"]) for call in group
    ]
    assert any(call[1:3] == ("mcp", "add") for call in calls) is approved
    assert (
        "MCP registration: reregistered" if approved else "confirmation_required"
    ) in result.stdout


@pytest.mark.parametrize("expected_transition", [True, False])
def test_complete_codex_plan_accepts_only_its_generated_activation_transition(
    wizard_env: dict[str, object],
    expected_transition: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.setup as setup_module
    from finishup.adapters.integrations.codex_plugin import activation_cache_mcp_binding

    binary = _binary()
    home = cast(Path, wizard_env["codex_home"])
    pinned = "/opt/pinned/bin/finishup"
    root = "/opt/pinned/root"
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.installed_launcher",
        lambda name="finishup": (pinned, "sha256:" + "cd" * 32),
    )
    monkeypatch.setattr(
        "finishup.adapters.integrations.codex_mcp.isolated_root", lambda: Path(root)
    )
    approved_command, _environment = activation_cache_mcp_binding()
    isolation = {"FINISHUP_ISOLATED_ROOT": root, "YOETZ_ISOLATED_ROOT": root}

    async def prepare():
        adapter = setup_module._mcp_adapter("strict", codex_home=home)  # pyright: ignore[reportPrivateUsage]
        preview = await HarnessMcpService(adapter).preview(binary)
        skill = await setup_module.project_skill_preview(Path.cwd())
        return preview, skill

    preview, skill = asyncio.run(prepare())
    generated = _finishup_entry("policy", launcher=pinned, env=isolation)
    strict = _finishup_entry("strict", launcher=pinned, env=isolation)
    wizard_env["outputs"] = [
        *_absent_mcp(),
        generated,
        generated if expected_transition else strict,
        *(
            [generated, generated, CommandOutput(0, b""), strict, strict]
            if expected_transition
            else []
        ),
    ]
    result = asyncio.run(
        setup_module.apply_codex_integration(
            binary,
            route_profile="strict",
            workspace=Path.cwd(),
            codex_home=home,
            approved_preview_digest=preview.preview_digest,
            approved_skill_preview_digest=skill.preview_digest,
            approved_activation_digest=cast(str, wizard_env["activation_digest"]),
            approved_activation_mcp_command=approved_command,
        )
    )
    calls = [
        call for group in cast(list[list[tuple[str, ...]]], wizard_env["calls"]) for call in group
    ]
    assert any(call[1:3] == ("mcp", "add") for call in calls) is expected_transition
    assert result["outcome"] == ("reregistered" if expected_transition else "failed")


class _CodexMcpHost:
    """A Codex MCP CLI answering from one registration flag, whatever the call order."""

    def __init__(self) -> None:
        self.registered = False
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, argv: tuple[str, ...]) -> CommandOutput:
        self.calls.append(argv)
        verb = argv[1:3]
        if verb == ("mcp", "get"):
            return _finishup_entry("strict") if self.registered else CommandOutput(1, b"")
        if verb == ("mcp", "list"):
            # Every observation also lists entries for the legacy ``yoetz`` key (ADR-048).
            if not self.registered:
                return CommandOutput(0, b"[]")
            entry = {
                "name": "finishup",
                "transport": {"command": "finishup", "args": list(MCP_STRICT_SERVE_COMMAND[1:])},
            }
            return CommandOutput(0, json.dumps([entry]).encode())
        if verb == ("mcp", "add"):
            self.registered = True
            return CommandOutput(0, b"")
        raise AssertionError(f"unexpected Codex MCP call: {argv[1:]}")


@pytest.fixture
def consent_arm_env(
    wizard_env: dict[str, object], monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> dict[str, object]:
    """The composed Codex connection with its real consent step on a disposable store."""

    import finishup.adapters.integrations.observation_local as observation_local
    import finishup.cli.setup as setup_module

    host = _CodexMcpHost()

    def adapter(
        *,
        route_profile: Literal["policy", "strict"] = "policy",
        codex_home: Path | None = None,
    ) -> CodexMcpAdapter:
        return CodexMcpAdapter(host, route_profile=route_profile, codex_home=codex_home)

    import finishup.adapters.integrations.codex_mcp as codex_mcp_module
    import finishup.cli.codex_connection as codex_connection_module

    monkeypatch.setattr(setup_module, "CodexMcpAdapter", adapter)
    # The host-connection preview and its terminal-interface plan reach the same host.
    monkeypatch.setattr(codex_mcp_module, "CodexMcpAdapter", adapter)
    monkeypatch.setattr(codex_connection_module, "CodexMcpAdapter", adapter)

    def installed_activation(_target: object, **_kwargs: object) -> ActivationInspection:
        return ActivationInspection(
            True,
            True,
            ActivationState.ACTIVE,
            plugin_cached=cast(bool, wizard_env["plugin_cached"]),
        )

    monkeypatch.setattr(codex_connection_module, "inspect_activation", installed_activation)
    monkeypatch.setattr(setup_module, "_grant_observation_consent", _REAL_GRANT_OBSERVATION_CONSENT)
    observation_state = tmp_path / "observation-state"
    monkeypatch.setattr(observation_local, "state_dir", lambda: observation_state)
    workspace = tmp_path / "project"
    workspace.mkdir()
    store = LocalObservationStore()
    store.set_runtime_enabled(True)
    wizard_env["host"] = host
    wizard_env["plugin_cached"] = False
    wizard_env["workspace"] = workspace
    wizard_env["commitment"] = store.workspace_commitment(str(workspace.resolve()))
    return wizard_env


async def _connect_codex(env: dict[str, object]) -> dict[str, JsonValue]:
    """Preview and apply exactly as the host connection and terminal interface do."""

    import finishup.cli.setup as setup_module

    workspace = cast(Path, env["workspace"])
    home = cast(Path, env["codex_home"])
    skill_preview = await setup_module.project_skill_preview(workspace)
    mcp_preview = await HarnessMcpService(
        CodexMcpAdapter(cast(_CodexMcpHost, env["host"]), route_profile="strict", codex_home=home)
    ).preview(_binary())
    return await setup_module.apply_codex_integration(
        _binary(),
        route_profile="strict",
        workspace=workspace,
        approved_preview_digest=mcp_preview.preview_digest,
        approved_skill_preview_digest=skill_preview.preview_digest,
        approved_activation_digest=cast(str, env["activation_digest"]),
        codex_home=home,
        _state=cast(Path, env["isolated_state"]),
    )


class _NoOsPresenceReview:
    """Codex connection plans declare no OS-presence review; consuming one is a defect."""

    def consume_setup_authority(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        raise AssertionError("Codex connection must not consume setup authority")

    def consume_artifact_review(self, authority: ArtifactAuthority, preview_digest: str) -> None:
        raise AssertionError("Codex connection must not consume an artifact review")


def _host_connect_codex(env: dict[str, object]) -> tuple[bool, dict[str, JsonValue]]:
    """Run ``finishup connect codex``'s prepare/accept/apply composition; report if it applied."""

    from finishup.adapters.integrations.host_discovery import HostInstallation
    from finishup.application.host_connection import ConnectionPlan, apply_connection
    from finishup.cli.codex_connection import prepare_codex_connection
    from finishup.protocol.ids import IdKind, new_id

    binary = _binary()
    installation = HostInstallation(
        "codex",
        Path(binary.executable_path),
        binary.reported_version,
        cast(Path, env["codex_home"]),
        "Codex",
    )
    request = new_id(IdKind.REQUEST)

    def prepare() -> ConnectionPlan:
        return prepare_codex_connection(
            installation,
            cast(Path, env["workspace"]),
            action="connect",
            route="strict",
            request_value=request,
        )

    plan = prepare()
    status = apply_connection(
        plan,
        accepted_digest=plan.digest,
        refresh=prepare,
        authority=None,
        review=_NoOsPresenceReview(),
    )
    return not plan.unchanged, status


def _approve_claude_capture(env: dict[str, object]) -> None:
    """The documented Claude steps: structural grant, then the explicit content arm."""

    import finishup.cli.observe as observe_cli

    workspace = str(cast(Path, env["workspace"]))
    assert observe_cli.grant_observation(workspace=workspace) == 0
    assert (
        observe_cli.enable_observation_content(
            profile=CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID, workspace=workspace
        )
        == 0
    )


def _select_detailed_largest(env: dict[str, object]) -> ObservationSelectionSettings:
    store = LocalObservationStore()
    commitment = cast(str, env["commitment"])
    store.set_workspace_selection(
        commitment,
        ObservationSelection(
            detail=ObservationDetailProfile.DETAILED,
            capacity=LARGEST_CAPACITY,
        ),
    )
    return store.selection_settings_for(commitment)


def _authority(env: dict[str, object]) -> LocalContentCaptureAuthority:
    authority = LocalObservationStore().content_capture_authority(cast(str, env["commitment"]))
    assert authority is not None
    assert authority.active and authority.runtime_enabled
    return authority


def _consent_report(report: dict[str, JsonValue]) -> dict[str, JsonValue]:
    consent = report["observation_consent"]
    assert isinstance(consent, dict)
    return consent


def _still_current(env: dict[str, object], authority: LocalContentCaptureAuthority) -> bool:
    """The same local fence the service rechecks before it opens or dispatches content."""

    return LocalObservationStore().content_capture_authority_is_current(
        cast(str, env["commitment"]), authority.generation, authority.profiles
    )


def test_codex_connection_after_claude_keeps_claude_capture_and_selection(
    consent_arm_env: dict[str, object],
) -> None:
    """Issue #835, Claude first: connecting Codex must not clear or re-fence Claude's arm."""

    env = consent_arm_env
    _approve_claude_capture(env)
    selection = _select_detailed_largest(env)
    claude = _authority(env)
    assert claude.profiles == (CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,)

    report = asyncio.run(_connect_codex(env))

    assert report["outcome"] == "registered"
    assert _authority(env) == claude
    assert _still_current(env, claude)
    assert LocalObservationStore().selection_settings_for(cast(str, env["commitment"])) == (
        selection
    )
    assert _consent_report(report) == {
        "outcome": "granted",
        "transition": "unchanged",
        "workspace_commitment": env["commitment"],
        "content_capture_profiles": [CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID],
    }

    # Reconnecting is the same idempotent structural setup.
    again = asyncio.run(_connect_codex(env))

    assert again["outcome"] == "already_registered"
    assert _authority(env) == claude
    assert _still_current(env, claude)
    assert _consent_report(again)["transition"] == "unchanged"
    assert [call[1:3] for call in cast(_CodexMcpHost, env["host"]).calls].count(("mcp", "add")) == 1


def test_claude_arm_added_after_codex_survives_codex_reconnection(
    consent_arm_env: dict[str, object],
) -> None:
    """Issue #835, Codex first: Claude's later arm survives a repeated Codex connection."""

    env = consent_arm_env
    first = asyncio.run(_connect_codex(env))
    assert first["outcome"] == "registered"
    codex_only = _authority(env)
    assert codex_only.profiles == ()

    import finishup.cli.observe as observe_cli

    # Claude's structural grant repeats an effective consent: Codex's own profileless hook
    # authority is not re-fenced by it.
    assert observe_cli.grant_observation(workspace=str(cast(Path, env["workspace"]))) == 0
    assert _authority(env) == codex_only
    _approve_claude_capture(env)
    claude = _authority(env)
    assert claude.profiles == (CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,)
    assert claude.generation != codex_only.generation  # enabling an arm is a real transition
    selection = _select_detailed_largest(env)

    again = asyncio.run(_connect_codex(env))

    assert again["outcome"] == "already_registered"
    assert _authority(env) == claude
    assert _still_current(env, claude)
    assert LocalObservationStore().selection_settings_for(cast(str, env["commitment"])) == (
        selection
    )
    assert _consent_report(first)["transition"] == "granted"
    assert _consent_report(again)["transition"] == "unchanged"
    assert _consent_report(again)["content_capture_profiles"] == [
        CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    ]


def test_revocation_after_connection_fences_and_reconnection_infers_no_arm(
    consent_arm_env: dict[str, object],
) -> None:
    env = consent_arm_env
    _approve_claude_capture(env)
    assert asyncio.run(_connect_codex(env))["outcome"] == "registered"
    in_flight = _authority(env)
    commitment = cast(str, env["commitment"])

    store = LocalObservationStore()
    store.revoke(ObservationRevokeCommand(commitment, retain_evidence=True))
    assert not _still_current(env, in_flight)

    # While the project fence is pending, reconnecting cannot revive consent.
    blocked = asyncio.run(_connect_codex(env))
    assert blocked["outcome"] == "already_registered"
    assert _consent_report(blocked)["outcome"] == "failed"
    consent = store.consent_for(commitment)
    assert consent is not None and consent.revoked_at is not None
    assert store.content_capture_profiles(commitment) == ()

    pending = store.pending_consent_revocation(commitment)
    assert pending is not None
    store.mark_consent_revocation_fenced(commitment, pending[0])
    fresh = asyncio.run(_connect_codex(env))

    assert _authority(env).profiles == ()
    assert not _still_current(env, in_flight)
    assert _consent_report(fresh)["transition"] == "granted"
    assert _consent_report(fresh)["content_capture_profiles"] == []


def test_host_connection_codex_after_claude_keeps_claude_capture(
    consent_arm_env: dict[str, object],
) -> None:
    """Issue #835 through ``finishup connect codex``: preview, accept, apply, and reconnect."""

    env = consent_arm_env
    _approve_claude_capture(env)
    selection = _select_detailed_largest(env)
    claude = _authority(env)

    applied, status = _host_connect_codex(env)

    assert applied
    assert status["configured"] is True
    assert _authority(env) == claude
    assert _still_current(env, claude)
    assert LocalObservationStore().selection_settings_for(cast(str, env["commitment"])) == (
        selection
    )

    # A missing plugin cache makes reconnection apply the whole composition again.
    applied_again, _status = _host_connect_codex(env)
    assert applied_again
    assert _authority(env) == claude
    assert _still_current(env, claude)

    # A fully installed reconnection has no changes and applies nothing.
    env["plugin_cached"] = True
    applied_last, _status = _host_connect_codex(env)
    assert not applied_last
    assert _authority(env) == claude
    assert [call[1:3] for call in cast(_CodexMcpHost, env["host"]).calls].count(("mcp", "add")) == 1
