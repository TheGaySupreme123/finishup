"""Issue #855: ``provider status`` names a stranded Codex runtime and its exact repair."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Any, Literal, cast

import pytest

from builders.codex_capability import LINUX, binding_for, record_for
from unit.cli.test_provider_status import (
    _UNREAD_ROUTE,  # pyright: ignore[reportPrivateUsage]
    _Client,  # pyright: ignore[reportPrivateUsage]
    _policy,  # pyright: ignore[reportPrivateUsage]
    _provider,  # pyright: ignore[reportPrivateUsage]
)
from yoetz.adapters.providers.codex_capability import codex_source_identity
from yoetz.adapters.providers.codex_evaluator_runtime import (
    CodexBindingDiagnosis,
    managed_runtime_path,
)
from yoetz.cli import codex_subscription
from yoetz.cli import provider_status as module
from yoetz.config.models import (
    ExternalRuntimeProfileConfig,
    SemanticFallbackConfig,
    VerificationConfig,
    YoetzConfig,
)

pytestmark = pytest.mark.anyio

_REPAIR = "yoetz provider codex-subscription repair"


def _runtime(
    executable: str = "/opt/npm/lib/node_modules/@openai/codex/bin/codex.js",
) -> ExternalRuntimeProfileConfig:
    record = record_for(b"codex", b"host", platform=LINUX)
    return binding_for(
        record, Path(executable), Path("/opt/yoetz/codex-home"), model="gpt-5.6-luna"
    )


def _fact(state: str, role: str, *, next_command: str | None = _REPAIR) -> dict[str, object]:
    return {
        "role": role,
        "state": state,
        "capability": "current",
        "executable": "changed" if state != "ready" else "admitted",
        "home": "ready",
        "uses_managed_runtime": state == "ready" and next_command is None,
        "next_command": next_command,
    }


def _install(
    monkeypatch: pytest.MonkeyPatch,
    *,
    primary: Literal["codex_subscription", "api_provider"] | None,
    capabilities: tuple[str, ...],
    fact: dict[str, object],
) -> None:
    config = YoetzConfig(
        profile="codex-subscription" if primary != "api_provider" else "local-openai",
        verification=VerificationConfig(semantic=cast(Any, "optional")),
        provider=None if primary is None else _provider(),
        external_runtime=_runtime(),
        semantic_fallback=None if primary is None else SemanticFallbackConfig(primary=primary),
    )
    client = _Client(capabilities, _policy(llm_inference_enabled=True))

    def load(*_args: object) -> YoetzConfig:
        return config

    async def connect(_kind: object, *, workspace_locator: object = None) -> _Client:
        return client

    async def observe(
        _workspace_locator: Path | None = None, *, _state: Path | None = None
    ) -> dict[str, object]:
        return dict(_UNREAD_ROUTE)

    monkeypatch.setattr(module, "load_config", load)
    monkeypatch.setattr(module, "connect_service", connect)
    monkeypatch.setattr(module, "mcp_route_observation", observe)

    def runtime_fact(_config: YoetzConfig) -> dict[str, object]:
        return fact

    monkeypatch.setattr(module, "external_runtime_fact", runtime_fact)


def _blockers(report: Mapping[str, object], condition: str) -> list[dict[str, object]]:
    blockers = cast(tuple[dict[str, object], ...], report["blockers"])
    return [item for item in blockers if item["condition"] == condition]


async def test_a_stranded_primary_runtime_is_a_blocker_even_when_the_service_says_connected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A service composed before the host update still reports the credential as connected.
    _install(
        monkeypatch,
        primary=None,
        capabilities=("external_provider",),
        fact=_fact("codex_runtime_executable_changed", "primary"),
    )

    report = await module.provider_status_report()

    assert report["credential_connected"] is True
    assert _blockers(report, "external_runtime_structure") == [
        {
            "condition": "external_runtime_structure",
            "state": "codex_runtime_executable_changed",
            "role": "primary",
            "next_command": _REPAIR,
        }
    ]
    assert cast(Mapping[str, object], report["external_runtime"])["state"] == (
        "codex_runtime_executable_changed"
    )
    assert report["semantic_ready"] is False
    assert report["next_commands"] == (_REPAIR,)


async def test_the_credential_blocker_names_the_repair_not_a_login_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        primary=None,
        capabilities=(),
        fact=_fact("codex_runtime_profile_outdated", "primary"),
    )

    report = await module.provider_status_report()

    assert _blockers(report, "provider_credential") == [
        {"condition": "provider_credential", "state": "not_connected", "next_command": _REPAIR}
    ]
    # One continuation, even though two blockers name it.
    assert report["next_commands"] == (_REPAIR,)


async def test_a_stranded_fallback_runtime_does_not_gate_the_primary(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        primary="api_provider",
        capabilities=("external_provider",),
        fact=_fact("codex_runtime_executable_changed", "fallback"),
    )

    report = await module.provider_status_report()

    assert _blockers(report, "external_runtime_structure")[0]["role"] == "fallback"
    assert _blockers(report, "fallback_provider_credential")[0]["next_command"] == _REPAIR
    assert report["semantic_ready"] is True


async def test_a_ready_host_bound_runtime_is_advised_but_not_blocked(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _install(
        monkeypatch,
        primary=None,
        capabilities=("external_provider",),
        fact=_fact("ready", "primary"),
    )

    report = await module.provider_status_report()

    assert _blockers(report, "external_runtime_structure") == []
    assert report["semantic_ready"] is True
    assert cast(Mapping[str, object], report["external_runtime"])["next_command"] == _REPAIR


def test_the_runtime_fact_is_local_and_reports_role_and_ownership(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr("platform.machine", lambda: "x86_64")

    def runtime_bundle(_config: YoetzConfig | None = None) -> Path:
        return tmp_path

    monkeypatch.setattr(codex_subscription, "runtime_bundle", runtime_bundle)

    def diagnose(_binding: ExternalRuntimeProfileConfig) -> CodexBindingDiagnosis:
        return CodexBindingDiagnosis("ready", "current", "admitted", "ready")

    monkeypatch.setattr(codex_subscription, "diagnose_bound_runtime", diagnose)
    managed = str(managed_runtime_path(tmp_path, codex_source_identity(LINUX, "0.159.0")))

    host_bound = YoetzConfig(profile="codex-subscription", external_runtime=_runtime())
    fact = module.external_runtime_fact(host_bound)
    assert fact is not None
    assert (fact["role"], fact["state"], fact["uses_managed_runtime"]) == (
        "primary",
        "ready",
        False,
    )
    assert fact["next_command"] == _REPAIR

    retained = YoetzConfig(profile="codex-subscription", external_runtime=_runtime(managed))
    fact = module.external_runtime_fact(retained)
    assert fact is not None
    assert (fact["uses_managed_runtime"], fact["next_command"]) == (True, None)
    assert module.external_runtime_fact(YoetzConfig()) is None
