"""Unit tests for the read-only AI-powered review readiness report.

The r4 dogfood spent four runs against an installation that structurally could not dispatch
AI-powered review, because nothing surfaced readiness before a check returned
``provider_not_configured``. These tests pin the two ways such a report can lie: reporting a
condition it never actually read, and counting a credential that belongs to a different provider
than the bound endpoint.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Literal, cast

import pytest

from yoetz.cli import provider_status as module
from yoetz.cli import setup as cli_setup
from yoetz.config.models import ProviderProfileConfig, VerificationConfig, YoetzConfig
from yoetz.ports.control import ControlError
from yoetz.ports.harness_mcp import McpRegistrationError, McpRegistrationReason

pytestmark = pytest.mark.anyio

# Captured before any test patches it, so the fail-soft test can exercise the real probe.
_REAL_ROUTE_OBSERVATION = module.mcp_route_observation


def _provider(provider_id: str = "openai") -> ProviderProfileConfig:
    return ProviderProfileConfig(
        provider_id=provider_id,
        endpoint_profile_id="openai-responses",
        endpoint_profile_version="1.0.0",
        model="gpt-5.4",
        capability_profile="openai-responses-structured-1",
    )


def test_credential_human_display_uses_one_constant_mask() -> None:
    assert module.credential_human_display(True) == "********"
    assert module.credential_human_display(False) == "not stored"
    assert module.credential_human_display(None) == "unknown"
    assert module.credential_human_display("a-real-key-must-never-be-reflected") == "unknown"


def _policy(
    *,
    llm_inference_enabled: bool,
    profile: str = "local_only",
    grant_state: str = "granted",
) -> dict[str, object]:
    return {
        "schema_version": "2.0.0",
        "composed_policy": {
            "profile": profile,
            "channel_policies": [
                {"channel": "capability_testing", "enabled": False},
                {"channel": "llm_inference", "enabled": llm_inference_enabled},
                {"channel": "update_checks", "enabled": False},
            ],
        },
        "bound_scope": {"kind": "workspace"},
        "authority_digest": "sha256:" + "d" * 64,
        "grant_state": grant_state,
        "migration_state": "not_applicable",
    }


class _Client:
    def __init__(
        self,
        capabilities: tuple[str, ...],
        policy: dict[str, object],
        *,
        state: str = "ready",
        state_reason: str = "none",
    ) -> None:
        self._capabilities = capabilities
        self._policy = policy
        self._state = state
        self._state_reason = state_reason
        self.closed = False

    async def service_status(self) -> Any:
        return SimpleNamespace(
            state=SimpleNamespace(value=self._state),
            state_reason=self._state_reason,
            capabilities=self._capabilities,
        )

    async def privacy_get_setup(self, request: object) -> dict[str, object]:
        assert request == {"schema_version": "2.0.0"}
        return self._policy

    async def close(self) -> None:
        self.closed = True


def _install(
    monkeypatch: pytest.MonkeyPatch,
    _tmp_path: Path,
    *,
    semantic: str = "optional",
    provider: ProviderProfileConfig | None = None,
    capabilities: tuple[str, ...] = ("external_provider",),
    llm_inference_enabled: bool = True,
    grant_state: str = "granted",
    service_state: str = "ready",
    service_state_reason: str = "none",
    mcp_route: dict[str, object] | None = None,
) -> _Client:
    config = YoetzConfig(
        profile="strict-local" if provider is None else "local-openai",
        verification=VerificationConfig(semantic=cast(Any, semantic)),
        provider=provider,
    )
    client = _Client(
        capabilities,
        _policy(llm_inference_enabled=llm_inference_enabled, grant_state=grant_state),
        state=service_state,
        state_reason=service_state_reason,
    )

    def _load(*_args: object) -> YoetzConfig:
        return config

    monkeypatch.setattr(module, "load_config", _load)

    async def _connect(_kind: object, *, workspace_locator: object = None) -> _Client:
        assert workspace_locator is not None
        return client

    monkeypatch.setattr(module, "connect_service", _connect)

    # The route probe shells out to a discovered `codex`, so leaving it unpatched would make
    # every test in this module depend on the developer's own registration. The default is the
    # "could not read" answer, which is what a host without Codex actually produces.
    observation = _UNREAD_ROUTE if mcp_route is None else mcp_route

    async def _observe(
        _workspace_locator: Path | None = None, *, _state: Path | None = None
    ) -> dict[str, object]:
        return dict(observation)

    monkeypatch.setattr(module, "mcp_route_observation", _observe)
    return client


_UNREAD_ROUTE: dict[str, object] = {
    "registration_state": None,
    "registered_profile": None,
    "configured_profile": None,
    "observed": False,
    "owner_source": None,
    "ownership_state": "ambiguous",
    "external_registration_state": None,
    "plugin_managed_state": "absent",
    # Issue #537 slice B: unread observations never report drift.
    "applied_profile": None,
    "drift_since_install": False,
}


def _route(
    registered: str | None,
    *,
    configured: str | None = None,
    state: str = "yoetz_owned",
    applied_profile: str | None = None,
    drift_since_install: bool = False,
) -> dict[str, object]:
    return {
        "registration_state": state,
        "registered_profile": registered,
        "configured_profile": registered if configured is None else configured,
        "observed": True,
        "owner_source": "external_registration",
        "ownership_state": "external",
        "external_registration_state": state,
        "plugin_managed_state": "absent",
        "applied_profile": applied_profile,
        "drift_since_install": drift_since_install,
    }


def _plugin_route(
    registered: str,
    *,
    ownership_state: str = "plugin",
    applied_profile: str | None = None,
    drift_since_install: bool = False,
) -> dict[str, object]:
    return {
        "registration_state": "absent",
        "registered_profile": registered,
        "configured_profile": registered,
        "observed": True,
        "owner_source": "plugin_managed" if ownership_state == "plugin" else ownership_state,
        "ownership_state": ownership_state,
        "external_registration_state": "absent",
        "plugin_managed_state": ownership_state,
        "applied_profile": applied_profile,
        "drift_since_install": drift_since_install,
    }


async def test_all_four_conditions_met_reports_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    client = _install(monkeypatch, tmp_path, provider=_provider())

    report = await module.provider_status_report()

    assert report["semantic_enabled"] is True
    assert report["endpoint_bound"] is True
    assert report["credential_connected"] is True
    assert report["llm_inference_enabled"] is True
    assert report["semantic_ready"] is True
    assert report["blockers"] == ()
    assert client.closed is True


async def test_missing_repository_grant_keeps_external_review_off(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), grant_state="missing")

    report = await module.provider_status_report(workspace_locator=tmp_path)

    assert report["repository_grant_state"] == "missing"
    assert report["readiness_determinable"] is True
    assert report["semantic_ready"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert {
        "condition": "repository_privacy_grant",
        "state": "missing",
        "next_command": "yoetz --privacy",
    } in blockers


async def test_llm_inference_channel_is_actually_read_from_canonical_policy(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A disabled channel must read as disabled, not as unknown.

    The canonical policy names this list ``channel_policies``. Reading any other key returns None
    for every channel, which silently makes readiness unreachable on a correctly configured host.
    """

    _install(monkeypatch, tmp_path, provider=_provider(), llm_inference_enabled=False)

    report = await module.provider_status_report()

    assert report["llm_inference_enabled"] is False
    assert report["semantic_ready"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    channel_blockers = [
        item for item in blockers if item.get("condition") == "llm_inference_channel"
    ]
    assert len(channel_blockers) == 1
    # "disabled" is a read answer; "unknown" would mean the policy was never inspected.
    assert channel_blockers[0]["state"] == "disabled"
    assert channel_blockers[0]["next_command"] == "yoetz --privacy"


async def test_credential_for_a_different_provider_is_not_counted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The service withholds external_provider unless the *configured* provider is connected."""

    _install(monkeypatch, tmp_path, provider=_provider("anthropic"), capabilities=())

    report = await module.provider_status_report()

    assert report["endpoint_bound"] is True
    assert report["credential_connected"] is False
    assert report["semantic_ready"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    credential = [item for item in blockers if item.get("condition") == "provider_credential"]
    assert len(credential) == 1
    assert credential[0]["state"] == "not_connected"
    assert credential[0]["next_command"] == "yoetz provider credential set"


async def test_unbound_endpoint_and_disabled_semantic_are_named_with_next_commands(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        semantic="disabled",
        provider=None,
        capabilities=(),
        llm_inference_enabled=False,
    )

    report = await module.provider_status_report()

    assert report["semantic_ready"] is False
    conditions = tuple(
        cast(dict[str, object], item)["condition"]
        for item in cast(tuple[object, ...], report["blockers"])
    )
    assert conditions == (
        "verification.semantic",
        "provider_endpoint",
        "provider_credential",
        "llm_inference_channel",
    )
    # Every blocker carries an actionable next command; that is the whole point of the report.
    assert all(
        cast(dict[str, object], item)["next_command"]
        for item in cast(tuple[object, ...], report["blockers"])
    )
    assert len(cast(tuple[object, ...], report["next_commands"])) == 4


async def test_report_never_claims_a_live_provider_smoke(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider())

    report = await module.provider_status_report()

    notes = " ".join(cast(tuple[str, ...], report["notes"]))
    assert "does not prove live provider dispatch" in notes


async def test_exit_code_is_nonzero_when_not_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), capabilities=())

    assert await module.run_provider_status(json_output=True) == 20


async def test_exit_code_is_zero_when_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider())

    assert await module.run_provider_status(json_output=True) == 0


async def test_repository_setup_does_not_trust_client_installation_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The service binds repository and installation; client state cannot choose either.

    No installation marker exists anywhere in this cell, so a report that read one — instead of
    letting the service bind the installation — could not produce these policy-derived facts.
    """

    _install(monkeypatch, tmp_path, provider=_provider())

    report = await module.provider_status_report()

    assert report["llm_inference_enabled"] is True
    assert report["repository_grant_state"] == "granted"
    assert report["readiness_determinable"] is True
    assert report["semantic_ready"] is True


async def test_locked_service_reports_real_blocker_first_without_false_remediation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        service_state="locked",
        service_state_reason="passphrase_required",
    )

    report = await module.provider_status_report()

    assert report["readiness_determinable"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert blockers[0] == {
        "condition": "service_unlocked",
        "state": "locked",
        "reason": "passphrase_required",
        "next_command": "yoetz service unlock",
        "probed_lifecycle": "user_service_no_autostart",
        # A locked service is present, so MCP shares it rather than starting a new one.
        "mcp_local_composition": "shares_this_service",
    }
    unknown = tuple(item for item in blockers if item.get("state") == "unknown")
    assert {item["condition"] for item in unknown} == {
        "provider_credential",
        "llm_inference_channel",
        "repository_privacy_grant",
    }
    assert all("next_command" not in item for item in unknown)
    assert report["next_commands"] == ("yoetz service unlock",)


async def test_absent_service_names_the_probed_lifecycle_and_the_mcp_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An absent service must not read as a contradiction of a working MCP session.

    The 2026-07-26 dogfood saw `service_unavailable` here while MCP-local work and live AI-powered review
    dispatch succeeded, because the bridge starts the service on demand and this surface never
    does. The report has to say which lifecycle it probed.
    """

    _install(monkeypatch, tmp_path, provider=_provider())

    async def _refuse(_kind: object, *, workspace_locator: object = None) -> object:
        assert workspace_locator is not None
        raise ControlError("service_unavailable", retryable=True)

    monkeypatch.setattr(module, "connect_service", _refuse)

    report = await module.provider_status_report()

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert blockers[0]["condition"] == "service_unlocked"
    assert blockers[0]["state"] == "service_unavailable"
    assert blockers[0]["probed_lifecycle"] == "user_service_no_autostart"
    assert blockers[0]["mcp_local_composition"] == "starts_on_demand"
    # The existing remediation for an operator who wants a persistent service is unchanged.
    assert blockers[0]["next_command"] == "yoetz service run"
    assert report["semantic_ready"] is False


async def test_stale_auto_unlock_points_to_repair_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        service_state="locked",
        service_state_reason="auto_unlock_stale",
    )

    report = await module.provider_status_report()

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert blockers[0]["next_command"] == "yoetz service auto-unlock repair"
    assert report["next_commands"] == ("yoetz service auto-unlock repair",)


async def test_rejected_auto_unlock_points_to_repair_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        service_state="locked",
        service_state_reason="auto_unlock_rejected",
    )

    report = await module.provider_status_report()

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert blockers[0]["next_command"] == "yoetz service auto-unlock repair"
    assert report["next_commands"] == ("yoetz service auto-unlock repair",)


async def test_strict_registered_route_is_not_ready_for_the_agent_but_leaves_the_install_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The exact conflation #132 names: registration is not activation.

    A strict Codex registration cannot dispatch AI-powered review, but ADR-018 decision 2 makes
    that ceiling process-local — CLI and terminal checks on the same installation still can. So
    the agent-route verdict flips and ``semantic_ready`` must not.
    """

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("strict"))

    report = await module.provider_status_report()

    assert report["semantic_ready"] is True
    assert report["agent_route_semantic_ready"] is False
    assert report["mcp_route"] == _route("strict")
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    route = [item for item in blockers if item.get("condition") == "mcp_route_profile"]
    assert len(route) == 1
    assert route[0]["state"] == "strict"
    # The scope marks this as an agent-route blocker, not an installation blocker.
    assert route[0]["scope"] == "agent_route"
    assert route[0]["next_command"] == "yoetz integrate codex mcp preview"


async def test_strict_registered_route_does_not_change_the_exit_code(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Exit code stays driven by installation readiness, so existing callers keep their contract."""

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("strict"))

    assert await module.run_provider_status(json_output=True) == 0


async def test_policy_registered_route_makes_both_verdicts_true(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("policy"))

    report = await module.provider_status_report()

    assert report["semantic_ready"] is True
    assert report["agent_route_semantic_ready"] is True
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert [item for item in blockers if item.get("condition") == "mcp_route_profile"] == []


async def test_policy_plugin_managed_route_makes_agent_route_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_plugin_route("policy"))

    report = await module.provider_status_report(workspace_locator=tmp_path)

    assert report["semantic_ready"] is True
    assert report["agent_route_semantic_ready"] is True
    route = cast(dict[str, object], report["mcp_route"])
    assert route["owner_source"] == "plugin_managed"
    assert route["ownership_state"] == "plugin"


@pytest.mark.parametrize("ownership_state", ["dual", "foreign", "ambiguous"])
async def test_conflicting_or_ambiguous_route_never_reports_agent_readiness(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    ownership_state: str,
) -> None:
    route = _plugin_route("policy", ownership_state=ownership_state)
    if ownership_state in {"dual", "foreign"}:
        route["registered_profile"] = None
    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=route)

    report = await module.provider_status_report(workspace_locator=tmp_path)

    assert report["agent_route_semantic_ready"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    ownership = [item for item in blockers if item.get("condition") == "mcp_ownership_state"]
    assert ownership == [
        {"condition": "mcp_ownership_state", "state": ownership_state, "scope": "agent_route"}
    ]


async def test_a_policy_route_on_an_unready_installation_is_not_agent_route_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The agent-route verdict is a conjunction; a policy route alone never grants it."""

    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        capabilities=(),
        mcp_route=_route("policy"),
    )

    report = await module.provider_status_report()

    assert report["semantic_ready"] is False
    assert report["agent_route_semantic_ready"] is False


async def test_unread_route_is_unknown_and_never_a_blocker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unobservable route reads as unread, matching how an unreadable credential is handled.

    Failing soft here is the point: this report has to stay readable on a host with no Codex, a
    broken Codex, or an unparseable registration entry.
    """

    _install(monkeypatch, tmp_path, provider=_provider())

    report = await module.provider_status_report()

    assert report["mcp_route"] == _UNREAD_ROUTE
    assert report["agent_route_semantic_ready"] is False
    assert report["semantic_ready"] is True
    assert report["blockers"] == ()
    assert await module.run_provider_status(json_output=True) == 0


async def test_route_probe_failure_degrades_instead_of_raising(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The real probe, not a stub: discovery and registration errors must not reach the caller."""

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)

    def _explode() -> tuple[object, ...]:
        raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})

    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", _explode
    )
    monkeypatch.setattr(cli_setup, "_configured_mcp_route_profile", lambda: "policy")

    report = await module.provider_status_report(_state=tmp_path)

    assert report["mcp_route"] == {
        "registration_state": None,
        "registered_profile": None,
        # Configured profile is config-local, so it survives a failed probe.
        "configured_profile": "policy",
        "observed": False,
        "owner_source": None,
        "ownership_state": "ambiguous",
        "external_registration_state": None,
        "plugin_managed_state": "absent",
        # Issue #537 slice B: unread observations never report drift, and an
        # isolated _state keeps the ambient applied record out of the probe.
        "applied_profile": None,
        "drift_since_install": False,
    }
    assert report["agent_route_semantic_ready"] is False


async def test_multiple_codex_binaries_require_an_explicit_route_selector(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from yoetz.ports.harness_mcp import HarnessBinary
    from yoetz.ports.integrations import HarnessId

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    chosen_home = tmp_path / "selected-home"
    chosen_home.mkdir(mode=0o700)
    from yoetz.cli import setup_readiness

    monkeypatch.setattr(setup_readiness, "invoking_launcher", lambda: ("/opt/yoetz/bin/yoetz",))
    monkeypatch.setattr(setup_readiness, "isolated_root", lambda: tmp_path / "isolated-root")
    binaries = (
        HarnessBinary(HarnessId.CODEX, "/opt/codex-a", "0.150.1", "untested"),
        HarnessBinary(HarnessId.CODEX, "/opt/codex-b", "0.150.1", "untested"),
    )
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: binaries,
    )

    report = await module.provider_status_report(_state=tmp_path, codex_home=chosen_home)

    route = cast(dict[str, object], report["mcp_route"])
    assert route["binary_selection"] == "multiple"
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    selection = next(item for item in blockers if item["condition"] == "codex_binary_selection")
    assert selection["state"] == "multiple"
    assert selection["scope"] == "agent_route"
    command = cast(str, selection["next_command"])
    assert "/opt/yoetz/bin/yoetz" in command
    assert "YOETZ_ISOLATED_ROOT=" + str(tmp_path / "isolated-root") in command
    assert "--codex-path '<exact-executable>'" in command
    assert "--codex-home " + str(chosen_home) in command
    assert report["next_commands"] == (command,)


async def test_unresolvable_explicit_codex_path_has_a_bounded_selector_hint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from yoetz.ports.harness_mcp import HarnessBinary
    from yoetz.ports.integrations import HarnessId

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: (HarnessBinary(HarnessId.CODEX, "/opt/codex", "0.150.1", "untested"),),
    )

    report = await module.provider_status_report(
        _state=tmp_path, codex_path=str(tmp_path / "missing-codex")
    )

    route = cast(dict[str, object], report["mcp_route"])
    assert route["binary_selection"] == "explicit_path_unresolved"
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert any(
        item.get("condition") == "codex_binary_selection" and item.get("state") == "not_found"
        for item in blockers
    )


async def test_registration_drift_from_configuration_is_visible(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """`registered_profile != configured_profile` is the drift signal the runbook reads.

    Setup would register a policy route now, but the live agent is still on the strict one. Only
    reporting both facts makes that difference observable.
    """

    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        mcp_route=_route("strict", configured="policy"),
    )

    report = await module.provider_status_report()

    route = cast(dict[str, object], report["mcp_route"])
    assert route["registered_profile"] == "strict"
    assert route["configured_profile"] == "policy"
    assert report["agent_route_semantic_ready"] is False


async def test_the_two_readiness_verdicts_are_documented_as_non_substitutable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("strict"))

    report = await module.provider_status_report()

    notes = " ".join(cast(tuple[str, ...], report["notes"]))
    assert "Neither substitutes for the other." in notes
    assert "does not make this installation not-ready" in notes


async def test_uninitialized_vault_points_to_guided_setup(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        service_state="locked",
        service_state_reason="vault_uninitialized",
    )

    report = await module.provider_status_report()

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert blockers[0]["next_command"] == "yoetz setup"
    assert report["next_commands"] == ("yoetz setup",)


def _admit_claude(project: Path) -> None:
    (project / ".claude").mkdir(exist_ok=True)
    (project / ".claude" / "settings.local.json").write_text(
        json.dumps({"permissions": {"allow": ["mcp__plugin_yoetz_yoetz__check"]}}),
        encoding="utf-8",
    )


async def test_host_admission_is_reported_per_host_and_unknown_when_unreadable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #467: admission is a fourth route-bound fact, read from the hosts' own files."""

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("policy"))
    project = tmp_path / "project"
    project.mkdir()
    _admit_claude(project)
    (project / ".cursor").mkdir()
    (project / ".cursor" / "permissions.json").write_bytes(b"{broken")

    report = await module.provider_status_report(workspace_locator=project)

    admission = cast(dict[str, dict[str, object]], report["host_admission"])
    assert admission["claude"]["state"] == "present"
    assert admission["codex"]["state"] == "absent"
    assert admission["cursor"]["state"] == "unknown"
    assert admission["cursor"]["observed"] is False
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert [item for item in blockers if item.get("condition") == "host_admission_drift"] == []
    assert report["agent_route_semantic_ready"] is True
    assert str(project) not in json.dumps(report)


async def test_present_admission_without_a_permitting_grant_is_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(
        monkeypatch,
        tmp_path,
        provider=_provider(),
        llm_inference_enabled=False,
        mcp_route=_route("policy"),
    )
    project = tmp_path / "project"
    project.mkdir()
    _admit_claude(project)

    report = await module.provider_status_report(workspace_locator=project)

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    drift = [item for item in blockers if item.get("condition") == "host_admission_drift"]
    assert drift == [
        {
            "condition": "host_admission_drift",
            "state": "present",
            "scope": "agent_route",
            "host": "claude",
            "next_command": (
                "yoetz integrate claude admission preview --action revoke --project-root ."
            ),
        }
    ]


async def test_strict_codex_route_with_a_codex_admission_is_drift_for_codex_only(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("strict"))
    project = tmp_path / "project"
    project.mkdir()
    _admit_claude(project)
    (project / ".codex").mkdir()
    (project / ".codex" / "config.toml").write_text(
        '[mcp_servers.yoetz.tools.check]\napproval_mode = "approve"\n', encoding="utf-8"
    )

    report = await module.provider_status_report(workspace_locator=project)

    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    drift = [item for item in blockers if item.get("condition") == "host_admission_drift"]
    assert [item["host"] for item in drift] == ["codex"]
    # Drift never moves installation readiness (ADR-018 decision 2 still holds).
    assert report["semantic_ready"] is True


async def test_host_admission_is_read_at_the_repository_root_from_a_subdirectory(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PR #478 review: admission files live at the repository root, not the launch directory."""

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("policy"))
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    _admit_claude(project)
    subdirectory = project / "src" / "nested"
    subdirectory.mkdir(parents=True)

    report = await module.provider_status_report(workspace_locator=subdirectory)

    admission = cast(dict[str, dict[str, object]], report["host_admission"])
    assert admission["claude"]["state"] == "present"
    assert admission["codex"]["state"] == "absent"


async def test_host_admission_from_cwd_walks_to_the_repository_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """A CLI launch with no locator still observes the root, not the current directory."""

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("policy"))
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    _admit_claude(project)
    subdirectory = project / "src" / "nested"
    subdirectory.mkdir(parents=True)
    monkeypatch.chdir(subdirectory)

    report = await module.provider_status_report()

    admission = cast(dict[str, dict[str, object]], report["host_admission"])
    assert admission["claude"]["state"] == "present"


async def test_a_relative_workspace_locator_is_absolutized_never_unknown(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """PR #478 review: a relative locator must not degrade every host to `target_unsafe`."""

    _install(monkeypatch, tmp_path, provider=_provider(), mcp_route=_route("policy"))
    project = tmp_path / "project"
    (project / ".git").mkdir(parents=True)
    _admit_claude(project)
    monkeypatch.chdir(tmp_path)

    report = await module.provider_status_report(workspace_locator=Path("project"))

    admission = cast(dict[str, dict[str, object]], report["host_admission"])
    assert admission["claude"]["state"] == "present"
    assert admission["cursor"]["state"] == "absent"


def test_admission_root_resolution_never_follows_a_symlinked_root(tmp_path: Path) -> None:
    """The repository-root walk keeps the final symlink, so the adapter still refuses it."""

    real = tmp_path / "real"
    (real / ".git").mkdir(parents=True)
    _admit_claude(real)
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    admission = module.host_admission_observation(link)

    claude = cast(dict[str, object], admission["claude"])
    assert claude["state"] == "unknown"
    assert claude["reason"] == "target_unsafe"


def test_a_locator_without_a_repository_observes_the_locator_itself(tmp_path: Path) -> None:
    project = tmp_path / "bare"
    project.mkdir()
    _admit_claude(project)

    admission = module.host_admission_observation(project)

    assert cast(dict[str, object], admission["claude"])["state"] == "present"


async def test_unknown_grant_never_reports_admission_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _install(monkeypatch, tmp_path, provider=_provider(), service_state="locked")
    project = tmp_path / "project"
    project.mkdir()
    _admit_claude(project)
    report = await module.provider_status_report(workspace_locator=project)
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    assert [item for item in blockers if item.get("condition") == "host_admission_drift"] == []


def _stub_live_route(
    monkeypatch: pytest.MonkeyPatch,
    *,
    registered: Literal["policy", "strict"] | None,
    observed: bool = True,
) -> None:
    """Stub the live host resolution for drift-join tests (issue #537)."""

    from yoetz.ports.harness_mcp import (
        HarnessBinary,
        McpRegistrationObservation,
        McpRegistrationState,
    )
    from yoetz.ports.integrations import HarnessId

    binary = HarnessBinary(
        harness_id=HarnessId.CODEX,
        executable_path="/opt/harness/bin/codex",
        reported_version=None,
        compatibility="untested",
    )
    observation = McpRegistrationObservation(
        HarnessId.CODEX,
        McpRegistrationState.YOETZ_OWNED if observed else McpRegistrationState.ABSENT,
        registered if observed else None,
        "ambient" if observed else None,
    )

    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: (binary,),
    )

    async def _fake_observe(self: object, _binary: object) -> McpRegistrationObservation:
        return observation

    monkeypatch.setattr("yoetz.application.harness_mcp.HarnessMcpService.observe", _fake_observe)
    monkeypatch.setattr(cli_setup, "configured_mcp_route_profile", lambda: "policy")


@pytest.mark.parametrize("dual", [False, True])
async def test_proven_absolute_adapter_feeds_provider_readiness(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, dual: bool
) -> None:
    from yoetz.adapters.integrations.codex_mcp import CommandOutput
    from yoetz.adapters.integrations.portable_plugin import PluginManagedMcpObservation
    from yoetz.ports.harness_mcp import HarnessBinary
    from yoetz.ports.integrations import HarnessId
    from yoetz.ports.plugin_artifacts import McpOwnershipState

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    binary = HarnessBinary(HarnessId.CODEX, "/test/codex", "0.150.1", "supported")
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", lambda: (binary,)
    )
    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp.isolated_root", lambda: None)
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_mcp.installed_launcher",
        lambda: ("/test/runtime/bin/yoetz", "sha256:" + "a" * 64),
    )

    def entry(_argv: tuple[str, ...], *, codex_home: Path | None = None) -> CommandOutput:
        from yoetz.adapters.integrations.codex_session_stream import resolve_codex_home

        assert codex_home == resolve_codex_home().absolute()
        return CommandOutput(
            0,
            json.dumps(
                {"command": "/test/runtime/bin/yoetz", "args": ["mcp", "serve", "--host", "codex"]}
            ).encode(),
        )

    def plugin(_root: object) -> PluginManagedMcpObservation:
        return PluginManagedMcpObservation(
            McpOwnershipState.PLUGIN if dual else McpOwnershipState.ABSENT,
            "policy" if dual else None,
            True,
        )

    monkeypatch.setattr("yoetz.adapters.integrations.codex_mcp._default_runner", entry)
    monkeypatch.setattr(
        "yoetz.adapters.integrations.portable_plugin.observe_plugin_managed_mcp", plugin
    )
    report = await module.provider_status_report(workspace_locator=tmp_path)
    assert report["semantic_ready"] is True
    assert report["agent_route_semantic_ready"] is (not dual)
    route = cast(dict[str, object], report["mcp_route"])
    assert route["external_registration_state"] == "yoetz_owned"
    assert route["ownership_state"] == ("dual" if dual else "external")


async def test_applied_route_drift_true_when_serving_differs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Applied policy but serving strict is drift (issue #537 slice B)."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    _stub_live_route(monkeypatch, registered="strict")
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["registered_profile"] == "strict"
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is True
    assert route["observed"] is True


async def test_applied_route_no_drift_when_profiles_match(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    _stub_live_route(monkeypatch, registered="policy")
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["registered_profile"] == "policy"
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is False


async def test_applied_route_unread_never_reports_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """An unread observation degrades to drift False even with a record (slice B)."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)

    def _explode() -> tuple[object, ...]:
        raise McpRegistrationError(McpRegistrationReason.HARNESS_UNAVAILABLE, {})

    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries", _explode
    )
    monkeypatch.setattr(cli_setup, "configured_mcp_route_profile", lambda: "policy")
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["observed"] is False
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is False


async def test_applied_route_absent_never_reports_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """ABSENT (registered None, observed True) with a policy record is not drift (B1)."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    # External ABSENT + plugin ABSENT (empty dir) joins to ABSENT.
    _stub_live_route(monkeypatch, registered=None, observed=False)
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["registered_profile"] is None
    assert route["ownership_state"] == "absent"
    assert route["observed"] is True
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is False


async def test_applied_route_dual_never_reports_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """DUAL (registered None, observed True) with a policy record is not drift (B1)."""

    from yoetz.adapters.integrations.portable_plugin import PluginManagedMcpObservation
    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import MCP_SERVE_COMMAND
    from yoetz.ports.plugin_artifacts import McpOwnershipState

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)
    # External YOETZ_OWNED strict + plugin PLUGIN policy joins to DUAL.
    _stub_live_route(monkeypatch, registered="strict")

    def _plugin_policy(_root: object) -> PluginManagedMcpObservation:
        return PluginManagedMcpObservation(McpOwnershipState.PLUGIN, "policy", True)

    monkeypatch.setattr(
        "yoetz.adapters.integrations.portable_plugin.observe_plugin_managed_mcp",
        _plugin_policy,
    )
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["ownership_state"] == "dual"
    assert route["registered_profile"] is None
    assert route["observed"] is True
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is False


async def test_applied_route_foreign_never_reports_drift(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """FOREIGN (registered None, observed True) with a policy record is not drift (B1)."""

    from yoetz.application.applied_mcp_route import record_applied_route
    from yoetz.ports.harness_mcp import (
        MCP_SERVE_COMMAND,
        HarnessBinary,
        McpRegistrationObservation,
        McpRegistrationState,
    )
    from yoetz.ports.integrations import HarnessId

    _install(monkeypatch, tmp_path, provider=_provider())
    monkeypatch.setattr(module, "mcp_route_observation", _REAL_ROUTE_OBSERVATION)

    binary = HarnessBinary(
        harness_id=HarnessId.CODEX,
        executable_path="/opt/harness/bin/codex",
        reported_version=None,
        compatibility="untested",
    )
    foreign = McpRegistrationObservation(
        HarnessId.CODEX, McpRegistrationState.FOREIGN_PRESENT, None
    )
    monkeypatch.setattr(
        "yoetz.adapters.integrations.codex_discovery.discover_codex_binaries",
        lambda: (binary,),
    )

    async def _fake_foreign_observe(self: object, _binary: object) -> McpRegistrationObservation:
        return foreign

    monkeypatch.setattr(
        "yoetz.application.harness_mcp.HarnessMcpService.observe", _fake_foreign_observe
    )
    monkeypatch.setattr(cli_setup, "configured_mcp_route_profile", lambda: "policy")
    record_applied_route(
        "policy",
        list(MCP_SERVE_COMMAND),
        list(MCP_SERVE_COMMAND),
        "sha256:" + "a" * 64,
        _state=tmp_path,
    )

    route = await module.mcp_route_observation(tmp_path, _state=tmp_path)

    assert route["ownership_state"] == "foreign"
    assert route["registered_profile"] is None
    assert route["observed"] is True
    assert route["applied_profile"] == "policy"
    assert route["drift_since_install"] is False


@pytest.mark.parametrize(
    ("semantic", "chosen", "enabled", "reason"),
    [
        ("required", None, True, "default_enabled"),
        ("optional", None, True, "default_enabled"),
        ("required", True, True, "owner_enabled"),
        ("optional", False, False, "owner_disabled"),
        ("disabled", True, False, "semantic_review_disabled"),
    ],
)
async def test_background_advice_reports_the_effective_switch_and_its_reason(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    semantic: str,
    chosen: bool | None,
    enabled: bool,
    reason: str,
) -> None:
    """Issue #888: status names whether background advice is on and why, in fixed words."""

    from yoetz.config.models import ObservationConfig

    _install(monkeypatch, tmp_path, semantic=semantic, provider=_provider())
    config = YoetzConfig(
        profile="local-openai",
        provider=_provider(),
        verification=VerificationConfig(semantic=cast(Any, semantic)),
        observation=ObservationConfig(semantic_advice_enabled=chosen),
    )

    def _load(*_args: object) -> YoetzConfig:
        return config

    monkeypatch.setattr(module, "load_config", _load)

    report = await module.provider_status_report()

    assert report["background_advice"] == {"enabled": enabled, "reason": reason}
    line = module.background_advice_human_line(report["background_advice"])
    assert line is not None
    assert line.startswith("on" if enabled else "off")
    if reason == "default_enabled":
        # On by default, and the way to turn it off is named.
        assert "semantic_advice_enabled = false" in line
    if reason == "owner_disabled":
        # The way back is named only where the owner turned it off.
        assert "set it to true" in line
    else:
        assert "true" not in line
    # Only fixed text renders; an unknown token renders nothing.
    assert module.background_advice_human_line({"reason": "owner-authored text"}) is None


async def test_provider_status_shows_the_same_filter_pair_as_status(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Issue #982 review: one derivation, read from the repository setup, on every surface."""

    client = _install(monkeypatch, tmp_path, provider=_provider())
    report = await module.provider_status_report()
    assert "credential_heuristic" not in report  # the setup read carried no pair
    client._policy["credential_heuristic"] = {  # pyright: ignore[reportPrivateUsage]
        "repository": "enforced",
        "machine_default": "disabled",
    }
    report = await module.provider_status_report()
    pair = cast(dict[str, str], report["credential_heuristic"])
    assert (pair["repository"], pair["machine_default"]) == ("enforced", "disabled")
    assert "enable --machine-default" in pair["summary"]
    # A no-grant repository whose composed (installation) policy is off is not told to run the
    # repository `enable`: that would only answer `repository_privacy_grant_missing`.
    assert "Turn it back on here" not in pair["summary"]
