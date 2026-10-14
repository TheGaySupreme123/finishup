"""Issue #582: ``provider status`` reports the declared pairing as two roles, two credentials."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from finishup.cli import provider_status as module
from finishup.config.models import (
    ExternalRuntimeProfileConfig,
    FinishUpConfig,
    SemanticFallbackConfig,
    VerificationConfig,
)
from finishup.config.write import codex_subscription_runtime
from unit.cli.test_provider_status import (
    _UNREAD_ROUTE,  # pyright: ignore[reportPrivateUsage]
    _Client,  # pyright: ignore[reportPrivateUsage]
    _policy,  # pyright: ignore[reportPrivateUsage]
    _provider,  # pyright: ignore[reportPrivateUsage]
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "a" * 64


def _runtime() -> ExternalRuntimeProfileConfig:
    return codex_subscription_runtime(
        executable_path="/Applications/Codex.app/Contents/Resources/codex",
        executable_sha256=_DIGEST,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        app_server_schema_sha256=_DIGEST,
        capability_cell_sha256=_DIGEST,
        isolated_config_sha256=_DIGEST,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home="/opt/FinishUP Tools/codex-home",
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    primary: Literal["api_provider", "codex_subscription"] | None,
    capabilities: tuple[str, ...],
    service_state: str = "ready",
) -> _Client:
    if primary is None:
        config = FinishUpConfig(
            profile="local-openai",
            verification=VerificationConfig(semantic=cast(Any, "optional")),
            provider=_provider(),
        )
    else:
        config = FinishUpConfig(
            profile="codex-subscription" if primary == "codex_subscription" else "local-openai",
            verification=VerificationConfig(semantic=cast(Any, "optional")),
            provider=_provider(),
            external_runtime=_runtime(),
            semantic_fallback=SemanticFallbackConfig(primary=primary),
        )
    client = _Client(capabilities, _policy(llm_inference_enabled=True), state=service_state)

    def _load(*_args: object) -> FinishUpConfig:
        return config

    monkeypatch.setattr(module, "load_config", _load)

    # These cases pin role-scoped credential reporting; the synthetic runtime's paths are never
    # real executables, so its local structure is reported ready (#855 structure has its own cases).
    def ready_fact(loaded: FinishUpConfig) -> dict[str, object] | None:
        if loaded.external_runtime is None:
            return None
        return {
            "role": "fallback" if primary == "api_provider" else "primary",
            "state": "ready",
            "capability": "current",
            "executable": "admitted",
            "home": "ready",
            "uses_managed_runtime": True,
            "next_command": None,
        }

    monkeypatch.setattr(module, "external_runtime_fact", ready_fact)

    async def _connect(_kind: object, *, workspace_locator: object = None) -> _Client:
        assert workspace_locator is not None
        return client

    monkeypatch.setattr(module, "connect_service", _connect)

    async def _observe(
        _workspace_locator: Path | None = None, *, _state: Path | None = None
    ) -> dict[str, object]:
        return dict(_UNREAD_ROUTE)

    monkeypatch.setattr(module, "mcp_route_observation", _observe)
    return client


def _blockers(report: Mapping[str, object], condition: str) -> list[dict[str, object]]:
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    return [item for item in blockers if item["condition"] == condition]


async def test_without_a_pairing_the_fallback_keys_are_absent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, primary=None, capabilities=("external_provider",))

    report = await module.provider_status_report()

    assert "fallback_endpoint" not in report
    assert "fallback_credential_connected" not in report
    endpoint = cast(dict[str, object], report["endpoint"])
    assert endpoint["role"] == "primary"
    assert endpoint["provider_id"] == "openai"
    assert _blockers(report, "fallback_provider_credential") == []
    assert report["semantic_ready"] is True


async def test_an_api_primary_with_a_codex_fallback_reports_both_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _install(
        monkeypatch,
        primary="api_provider",
        capabilities=("external_provider", "fallback_provider"),
    )

    report = await module.provider_status_report()

    endpoint = cast(dict[str, object], report["endpoint"])
    fallback = cast(dict[str, object], report["fallback_endpoint"])
    assert endpoint["role"] == "primary"
    assert endpoint["credential_authority"] == "finishup_vault_api_credential"
    assert endpoint["provider_id"] == "openai"
    assert fallback["role"] == "fallback"
    assert fallback["provider_id"] == "openai-codex"
    assert fallback["credential_authority"] == "external_runtime_oauth"
    assert fallback["runtime_version"] == "0.150.1"
    assert fallback["upstream_body_observability"] == "unavailable"
    # Issue #571: the Codex slot names each profile's exact effort and output limit; this
    # legacy-shaped binding keeps its single effort for routine checks.
    assert fallback["review_budgets"] == {
        "routine": {
            "reasoning_effort": "high",
            "output_limit": 4096,
            "effort_source": "legacy_single_effort",
        },
        "final": {"reasoning_effort": "high", "output_limit": 8192, "effort_source": "configured"},
    }
    assert "review_budgets" not in endpoint
    assert module.review_budget_human_line(fallback) == (
        "routine effort=high (legacy single effort) output_limit=4096 tokens; "
        "final effort=high output_limit=8192 tokens"
    )
    assert module.review_budget_human_line(endpoint) is None
    assert report["credential_connected"] is True
    assert report["fallback_credential_connected"] is True
    assert report["blockers"] == ()
    assert report["semantic_ready"] is True
    assert client.closed is True


async def test_a_codex_primary_with_an_api_fallback_swaps_the_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        primary="codex_subscription",
        capabilities=("external_provider", "fallback_provider"),
    )

    report = await module.provider_status_report()

    endpoint = cast(dict[str, object], report["endpoint"])
    fallback = cast(dict[str, object], report["fallback_endpoint"])
    assert (endpoint["role"], endpoint["provider_id"]) == ("primary", "openai-codex")
    assert (fallback["role"], fallback["provider_id"]) == ("fallback", "openai")
    assert fallback["credential_authority"] == "finishup_vault_api_credential"
    assert "runtime_version" not in fallback


async def test_a_missing_fallback_capability_is_a_blocker_of_the_fallback_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, primary="api_provider", capabilities=("external_provider",))

    report = await module.provider_status_report()

    assert report["credential_connected"] is True
    assert report["fallback_credential_connected"] is False
    assert _blockers(report, "provider_credential") == []
    assert _blockers(report, "fallback_provider_credential") == [
        {
            "condition": "fallback_provider_credential",
            "state": "not_connected",
            "next_command": "finishup provider codex-subscription status",
        }
    ]
    # The fallback's credential never gates the primary's readiness: the blocker is reported
    # under its own condition while the installation stays ready to dispatch on the primary.
    assert report["semantic_ready"] is True
    assert len(cast(tuple[object, ...], report["blockers"])) == 1


async def test_the_fallback_next_command_names_the_api_credential_when_the_api_is_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, primary="codex_subscription", capabilities=("external_provider",))

    report = await module.provider_status_report()

    assert _blockers(report, "fallback_provider_credential") == [
        {
            "condition": "fallback_provider_credential",
            "state": "not_connected",
            "next_command": "finishup provider credential set",
        }
    ]


async def test_a_primary_credential_gap_names_the_primary_command_under_a_pairing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(monkeypatch, primary="codex_subscription", capabilities=("fallback_provider",))

    report = await module.provider_status_report()

    assert report["credential_connected"] is False
    assert report["fallback_credential_connected"] is True
    assert _blockers(report, "provider_credential") == [
        {
            "condition": "provider_credential",
            "state": "not_connected",
            "next_command": "finishup provider codex-subscription status",
        }
    ]
    assert _blockers(report, "fallback_provider_credential") == []


async def test_an_unready_service_leaves_both_credentials_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        primary="api_provider",
        capabilities=("external_provider", "fallback_provider"),
        service_state="locked",
    )

    report = await module.provider_status_report()

    assert report["credential_connected"] is None
    assert report["fallback_credential_connected"] is None
    assert _blockers(report, "fallback_provider_credential") == [
        {"condition": "fallback_provider_credential", "state": "unknown"}
    ]
    assert cast(dict[str, object], report["fallback_endpoint"])["role"] == "fallback"
