"""The TUI names Yoetz-era registrations and installs instead of hiding them (ADR-048)."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from builders.tui_runtime import CLI
from finishup.tui.models import HarnessOption, LayerState
from finishup.tui.runtime import FinishUpRuntime

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def _stub_plan_inputs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    preview: object,
    *,
    skill_warnings: tuple[str, ...] = (),
    plugin_tree_planned: bool = False,
    removed_block: str = "",
    cache_versions: tuple[str, ...] = (),
    policy: dict[str, object] | None = None,
) -> None:
    from finishup.adapters.integrations import codex_mcp
    from finishup.application import codex_plugin
    from finishup.cli import setup

    activation = SimpleNamespace(
        codex_home=tmp_path / "codex-home",
        codex_version="0.1.0",
        marketplace_bytes=b"{}\n",
        config_toml_block="",
        plugin_source_digest="sha256:" + "1" * 64,
        inspection=SimpleNamespace(inventory_verified=True),
        plugin_install_path=tmp_path / "cache",
        plugin_install_digest="sha256:" + "2" * 64,
        executable_digest="sha256:" + "3" * 64,
        probe_command=("--version",),
        inventory_command=("plugin", "list"),
        install_command=("plugin", "install"),
        probe_environment="ambient",
        activation_environment=(),
        marketplace_preimage_digest="sha256:" + "4" * 64,
        config_preimage_digest="sha256:" + "5" * 64,
        cache_mutation_planned=False,
        legacy_plugin_tree_planned=plugin_tree_planned,
        legacy_removed_block=removed_block,
        legacy_cache_versions=cache_versions,
        preview_digest="sha256:" + "6" * 64,
    )

    class Adapter:
        def __init__(self, *, route_profile: str, codex_home: Path | None = None) -> None:
            del route_profile, codex_home

        async def preview_registration(self, _binary: object) -> object:
            return preview

    async def skill(_workspace: object = None) -> SimpleNamespace:
        return SimpleNamespace(
            file_changes=(), preview_digest="sha256:" + "7" * 64, warnings=skill_warnings
        )

    def activation_preview(*_args: object) -> SimpleNamespace:
        return activation

    def policy_preview(_root: object) -> dict[str, object]:
        return {} if policy is None else policy

    def plugin_preview(_self: object, *_args: object, **_kwargs: object) -> SimpleNamespace:
        return SimpleNamespace(planned_file_count=3)

    monkeypatch.setattr(setup, "codex_activation_preview", activation_preview)
    monkeypatch.setattr(setup, "project_skill_preview", skill)
    monkeypatch.setattr(setup, "check_policy_preview", policy_preview)
    monkeypatch.setattr(codex_mcp, "CodexMcpAdapter", Adapter)
    monkeypatch.setattr(codex_plugin.CodexPluginService, "preview", plugin_preview)


def _preview(action: str, *, legacy: str = "none", route_before: str | None = None) -> object:
    from finishup.ports.harness_mcp import (
        McpRegistrationAction,
        McpRegistrationPreview,
        McpRegistrationState,
    )
    from finishup.ports.integrations import HarnessId

    owned = action != "register"
    return McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction(action),
        McpRegistrationState.FINISHUP_OWNED if owned else McpRegistrationState.ABSENT,
        (),
        "sha256:" + "8" * 64,
        legacy_registration=legacy,  # type: ignore[arg-type]
        route_profile_before=route_before,  # type: ignore[arg-type]
    )


async def test_a_legacy_key_migration_is_not_presented_as_left_alone(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The owned entry still serves the policy route under ``yoetz``: re-registering it keeps the
    # route, and the plan must say it is replaced, not merely verified.
    preview = _preview("reregister", legacy="legacy_only", route_before="policy")
    _stub_plan_inputs(
        monkeypatch,
        tmp_path,
        preview,
        skill_warnings=("legacy_skill_tree_owned",),
        plugin_tree_planned=True,
    )

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "policy")

    assert plan.already_registered is False
    assert plan.state_before.startswith("yoetz_owned; ")
    assert "earlier name yoetz" in plan.state_before
    assert "route" not in plan.state_before
    root = FinishUpRuntime(cwd=tmp_path).project_root()
    assert str(root / ".agents" / "skills" / "yoetz") in plan.managed_paths
    assert str(root / ".agents" / "plugins" / "yoetz") in plan.managed_paths


async def test_a_kept_legacy_entry_is_named_and_not_promised_as_migrated(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A project's Codex configuration still needs the owned ``yoetz`` entry (a Yoetz 0.2
    approval table): the adapter keeps it beside ``finishup``, and the plan must say so instead
    of promising the migration, with the revoke and the explicit way out (#1073)."""

    from finishup.adapters.integrations.host_admission import CODEX_LEGACY_ADMISSION_TABLES
    from finishup.ports.harness_mcp import (
        McpRegistrationAction,
        McpRegistrationPreview,
        McpRegistrationState,
    )
    from finishup.ports.integrations import HarnessId

    dependent = tmp_path / "a"
    (dependent / ".codex").mkdir(parents=True, mode=0o700)
    (dependent / ".codex" / "config.toml").write_text(CODEX_LEGACY_ADMISSION_TABLES[0])
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        ("legacy_registration_kept", "legacy_registration_owned"),
        "sha256:" + "8" * 64,
        legacy_registration="legacy_only",
        route_profile_before="policy",
        legacy_kept_for=(str(dependent),),
        legacy_route_profile="policy",
    )
    _stub_plan_inputs(monkeypatch, tmp_path, preview)

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "policy")

    assert plan.legacy_registration_kept_for == (str(dependent),)
    assert plan.legacy_registration_route_profile == "policy"
    assert "connecting migrates it" not in plan.state_before
    assert "kept" in plan.state_before
    assert not any("Move the MCP registration" in line for line in plan.replacements)
    assert any("yoetz" in line and "Keep" in line for line in plan.replacements)
    lines = "\n".join(plan.legacy_registration_kept_lines)
    assert str(dependent) in lines
    assert "--action revoke" in lines
    assert "integrate codex mcp preview-remove" in lines


async def test_an_unreadable_dependent_is_not_promised_a_revoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.ports.harness_mcp import (
        McpRegistrationAction,
        McpRegistrationPreview,
        McpRegistrationState,
    )
    from finishup.ports.integrations import HarnessId

    dependent = tmp_path / "a"
    (dependent / ".codex").mkdir(parents=True, mode=0o700)
    real = tmp_path / "shared.toml"
    real.write_text('model = "o3"\n')
    (dependent / ".codex" / "config.toml").symlink_to(real)
    preview = McpRegistrationPreview(
        HarnessId.CODEX,
        McpRegistrationAction.REREGISTER,
        McpRegistrationState.FINISHUP_OWNED,
        ("legacy_registration_kept", "legacy_registration_owned"),
        "sha256:" + "8" * 64,
        legacy_registration="legacy_only",
        route_profile_before="policy",
        legacy_kept_for=(str(dependent),),
        legacy_kept_unreadable=(str(dependent),),
        legacy_route_profile="policy",
    )
    _stub_plan_inputs(monkeypatch, tmp_path, preview)

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "policy")

    lines = "\n".join(plan.legacy_registration_kept_lines)
    assert "could not read its .codex/config.toml safely (a symlink)" in lines
    assert "--action revoke" not in lines
    assert not any("revoke" in line for line in plan.replacements)


async def test_the_observed_route_before_names_a_route_change(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_plan_inputs(monkeypatch, tmp_path, _preview("reregister", route_before="policy"))

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "strict")

    assert plan.already_registered is False
    assert plan.state_before == "yoetz_owned; route policy -> strict"
    assert all("yoetz" not in Path(path).name for path in plan.managed_paths)


async def test_an_exact_owned_entry_is_verified_not_replaced(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_plan_inputs(monkeypatch, tmp_path, _preview("noop", route_before="policy"))

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "policy")

    assert plan.already_registered is True
    assert plan.state_before == "yoetz_owned"


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ({"legacy_installation": "none"}, "Selected agent"),
        (
            {"legacy_installation": "legacy_only"},
            "Selected agent; installed under the earlier name yoetz (connecting migrates it)",
        ),
        (
            {
                "legacy_installation": "foreign",
                "project_mcp": {"legacy_registration": "duplicate"},
            },
            "Selected agent; the earlier name yoetz holds an install FinishUP cannot prove is "
            "its own (kept); also registered under the earlier name yoetz (connecting removes it)",
        ),
    ],
)
async def test_host_plugin_layer_names_a_yoetz_era_install(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: dict[str, object],
    expected: str,
) -> None:
    async def host_status(_self: FinishUpRuntime, _option: HarnessOption) -> dict[str, object]:
        return {"installed": True, "configured": True, "enabled": True, **status}

    monkeypatch.setattr(FinishUpRuntime, "_host_connection_status", host_status)
    option = HarnessOption("/opt/agent", "1.0.0", "Selected agent", "", host="cursor-ide")
    layers = await FinishUpRuntime(cwd=tmp_path)._host_plugin_layers(option)  # pyright: ignore[reportPrivateUsage]

    assert layers[0].state is LayerState.VERIFIED
    assert layers[0].detail == expected


async def test_codex_registration_reports_its_legacy_key(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.application.harness_mcp import HarnessMcpService
    from finishup.ports.harness_mcp import McpRegistrationObservation, McpRegistrationState
    from finishup.ports.integrations import HarnessId

    async def observe(_self: object, _binary: object) -> McpRegistrationObservation:
        return McpRegistrationObservation(
            HarnessId.CODEX,
            McpRegistrationState.FINISHUP_OWNED,
            "policy",
            isolation_binding="ambient",
            legacy_registration="duplicate",
        )

    monkeypatch.setattr(HarnessMcpService, "observe", observe)
    assert await FinishUpRuntime(cwd=tmp_path).mcp_registration(CLI) == (
        "yoetz_owned",
        "duplicate",
    )

    async def state(_self: FinishUpRuntime, _option: HarnessOption) -> str:
        return "absent"

    monkeypatch.setattr(FinishUpRuntime, "mcp_state", state)
    other = HarnessOption("/opt/agent", "1.0.0", "Agent", "", host="claude")
    assert await FinishUpRuntime(cwd=tmp_path).mcp_registration(other) == ("absent", "none")


@pytest.mark.parametrize("kept", ["none", "needed", "unread"])
async def test_the_readiness_words_do_not_promise_a_migration_connecting_keeps_back(
    monkeypatch: pytest.MonkeyPatch, kept: str
) -> None:
    """The ``MCP registered`` layer names the earlier ``yoetz`` key; while a project's Codex
    settings still need it, or not every project could be read, connecting keeps it, and the
    words say which (#1073)."""

    from finishup.adapters.integrations import codex_mcp
    from finishup.tui import runtime as runtime_module

    def dependents(_home: object) -> codex_mcp.LegacyRegistrationUse:
        return codex_mcp.LegacyRegistrationUse(
            needed_by=("/work/a",) if kept == "needed" else (),
            unreadable=(),
            unread=("user_config_unreadable",) if kept == "unread" else (),
        )

    monkeypatch.setattr(codex_mcp, "legacy_registration_dependents", dependents)
    words = runtime_module._codex_legacy_registration_text  # pyright: ignore[reportPrivateUsage]

    assert words("none") is None
    text = words("legacy_only")
    assert text is not None
    assert ("connecting migrates it" in text) is (kept == "none")
    assert ("a project's Codex settings still use it" in text) is (kept == "needed")
    assert ("not every project of this Codex home could be read" in text) is (kept == "unread")


async def test_the_plan_carries_every_yoetz_era_removal_it_binds(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _stub_plan_inputs(
        monkeypatch,
        tmp_path,
        _preview("reregister", legacy="legacy_only", route_before="policy"),
        skill_warnings=("legacy_skill_tree_owned",),
        plugin_tree_planned=True,
        removed_block='[plugins."yoetz@yoetz"]\nenabled = true\n',
        cache_versions=("0.2.5",),
        policy={"outcome": "ambiguous", "reason": "policy_ambiguous", "policy_digest": None},
    )

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "policy")

    assert plan.route_profile_before == "policy"
    assert plan.legacy_registration == "legacy_only"
    assert plan.activation_legacy_removed_block == '[plugins."yoetz@yoetz"]\nenabled = true\n'
    assert plan.activation_legacy_cache_versions == ("0.2.5",)
    assert plan.activation_legacy_plugin_tree_planned is True
    assert plan.legacy_skill_tree_planned is True
    assert plan.policy_ambiguous is True
    assert plan.policy_digest is None
    assert any("earlier name yoetz to finishup" in line for line in plan.replacements)


async def test_an_unobserved_route_on_a_reregistration_is_the_other_route(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # The rule ``finishup setup`` applies when the adapter could not read the current route.
    _stub_plan_inputs(monkeypatch, tmp_path, _preview("reregister"))

    plan = await FinishUpRuntime(cwd=tmp_path).integration_plan(CLI, tmp_path, "strict")

    assert plan.route_profile_before == "policy"
    assert plan.state_before == "yoetz_owned; route policy -> strict"


@pytest.mark.parametrize("outcome", ["registered", "reregistered", "already_registered"])
def test_every_successful_registration_outcome_reads_as_registered(
    tmp_path: Path, outcome: str
) -> None:
    result = FinishUpRuntime(cwd=tmp_path)._integration_outcome(  # pyright: ignore[reportPrivateUsage]
        {"outcome": outcome, "state": "yoetz_owned"}
    )

    layers = {layer.key: layer for layer in result.layers}
    assert layers["mcp_registered"].state is LayerState.VERIFIED
    assert layers["mcp_verified"].state is LayerState.VERIFIED


def test_an_ambiguous_policy_outcome_names_both_files(tmp_path: Path) -> None:
    result = FinishUpRuntime(cwd=tmp_path)._integration_outcome(  # pyright: ignore[reportPrivateUsage]
        {
            "outcome": "registered",
            "state": "yoetz_owned",
            "check_policy": {"outcome": "ambiguous", "reason": "policy_ambiguous"},
        }
    )

    policy = {layer.key: layer for layer in result.layers}["policy_digest_trusted"]
    assert policy.state is LayerState.NOT_CONFIGURED
    assert ".finishup/checks.toml" in policy.detail
    assert ".yoetz/checks.toml" in policy.detail


def test_the_policy_layer_does_not_call_an_ambiguous_policy_absent(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.cli import setup

    def ambiguous(_root: object) -> dict[str, object]:
        return {"outcome": "ambiguous", "reason": "policy_ambiguous", "policy_digest": None}

    monkeypatch.setattr(setup, "check_policy_preview", ambiguous)

    layer = FinishUpRuntime(cwd=tmp_path)._policy_digest_layer(tmp_path)  # pyright: ignore[reportPrivateUsage]

    assert layer.state is LayerState.NOT_CONFIGURED
    assert "declares no approved checks" not in layer.detail
    assert "neither is used until you remove one" in layer.detail


@pytest.mark.parametrize(
    ("project_mcp", "expected"),
    [
        (
            {"state": "yoetz_owned", "legacy_registration": "legacy_only"},
            "registered under the earlier name yoetz (connecting migrates it)",
        ),
        (
            {"state": "external_source", "legacy_registration": "legacy_only"},
            "the earlier name yoetz is registered where connecting will not edit it",
        ),
        (
            {"state": "multiple_sources", "legacy_registration": "duplicate"},
            "the earlier name yoetz is registered where connecting will not edit it",
        ),
        (
            {"state": "external_source", "legacy_registration": "foreign"},
            "the earlier name yoetz holds an entry FinishUP cannot prove is its own (kept)",
        ),
    ],
)
async def test_cursor_legacy_text_never_promises_a_migration_connect_refuses(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    project_mcp: dict[str, object],
    expected: str,
) -> None:
    async def host_status(_self: FinishUpRuntime, _option: HarnessOption) -> dict[str, object]:
        return {"installed": True, "legacy_installation": "none", "project_mcp": project_mcp}

    monkeypatch.setattr(FinishUpRuntime, "_host_connection_status", host_status)
    option = HarnessOption("/opt/agent", "1.0.0", "Cursor", "", host="cursor-ide")
    layers = await FinishUpRuntime(cwd=tmp_path)._host_plugin_layers(option)  # pyright: ignore[reportPrivateUsage]

    assert layers[0].detail.startswith("Cursor; " + expected)
    if "will not edit" in expected:
        assert "migrates" not in layers[0].detail


@pytest.mark.parametrize(("package", "launcher"), [("finishup", "finishup"), ("yoetz", "yoetz")])
async def test_the_update_remedy_names_the_launcher_this_install_has(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, package: str, launcher: str
) -> None:
    from finishup.application.package_update import build_package_update_advisory
    from finishup.tui import runtime as runtime_module

    advisory = build_package_update_advisory(
        installed_version="0.3.0", latest_version="9.0.0", source="cache", package=package
    )

    async def advise(_self: object, **_kwargs: object) -> object:
        return advisory

    async def no_snapshot(_self: object) -> object:
        return SimpleNamespace(layers=())

    monkeypatch.setattr(runtime_module, "_host_entries", lambda: ())
    monkeypatch.setattr(
        runtime_module,
        "_installation_folders_entry",
        lambda: runtime_module.DoctorEntry(
            "installation_folders", "Installation folders", LayerState.VERIFIED
        ),
    )
    monkeypatch.setattr(FinishUpRuntime, "package_update_advisory", advise)
    monkeypatch.setattr(FinishUpRuntime, "status_snapshot", no_snapshot)

    report = await FinishUpRuntime(cwd=tmp_path).doctor()

    package_entry = {entry.key: entry for entry in report.entries}["package"]
    assert package_entry.remediation.endswith(f"# then re-run {launcher}")
    assert package_entry.remediation.startswith(advisory.upgrade_command)


async def test_a_refused_connection_names_the_folder_token_and_its_remedy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from finishup.adapters.control.unix_socket import LocalControlTransportError
    from finishup.cli import app as app_module
    from finishup.service import client as client_module
    from finishup.tui.runtime import RuntimeError_

    refused = client_module._transport_error(  # pyright: ignore[reportPrivateUsage]
        LocalControlTransportError(
            "runtime_directory_unsafe", path_reason="installation_root_ambiguous"
        )
    )

    async def build(*_args: object, **_kwargs: object) -> object:
        raise refused

    monkeypatch.setattr(app_module, "build_service_client", build)

    with pytest.raises(RuntimeError_) as caught:
        await FinishUpRuntime(cwd=tmp_path).service_lock()

    assert caught.value.reason == "installation_root_ambiguous"
    assert caught.value.message == "FinishUP's local folders cannot be used safely"
    assert "vault and catalog" in caught.value.details[0]

    async def unavailable(*_args: object, **_kwargs: object) -> object:
        from finishup.ports.control import ControlError

        raise ControlError("service_unavailable", retryable=True)

    monkeypatch.setattr(app_module, "build_service_client", unavailable)
    with pytest.raises(RuntimeError_) as plain:
        await FinishUpRuntime(cwd=tmp_path).service_lock()
    assert plain.value.reason == "service_unavailable"
    assert plain.value.message == "the local FinishUP service is not reachable"
