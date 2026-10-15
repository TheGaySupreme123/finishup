"""The interface reports the agent route as its own verdict, never folded into readiness."""

from __future__ import annotations

from finishup.tui.models import LayerState, PrivacyPosture, ProviderPosture
from finishup.tui.runtime import FinishUpRuntime


def _provider(**overrides: object) -> ProviderPosture:
    values: dict[str, object] = {
        "endpoint_bound": True,
        "provider_id": "openai",
        "model": "gpt-5",
        "endpoint_profile_id": "openai-responses",
        "credential_connected": True,
        "llm_inference_enabled": True,
        "semantic_enabled": True,
        "semantic_ready": True,
        "readiness_determinable": True,
    }
    values.update(overrides)
    return ProviderPosture(**values)  # type: ignore[arg-type]


_PRIVACY = PrivacyPosture(profile="assisted_review", llm_inference_enabled=True, readable=True)


def _layer(provider: ProviderPosture) -> LayerState:
    runtime = FinishUpRuntime()
    layers = runtime._provider_layers(provider, _PRIVACY)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    return next(layer for layer in layers if layer.key == "agent_route_review_ready").state


def _detail(provider: ProviderPosture) -> str:
    runtime = FinishUpRuntime()
    layers = runtime._provider_layers(provider, _PRIVACY)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    return next(layer for layer in layers if layer.key == "agent_route_review_ready").detail


def test_a_strict_registration_is_reported_without_calling_the_install_unready() -> None:
    """The installation stays ready; only the agent route is not.

    Collapsing the two would tell an operator with a deliberate strict registration that their
    installation is broken, and would contradict ADR-018: the route ceiling is process-local.
    """

    provider = _provider(agent_route_semantic_ready=False, registered_route_profile="strict")

    runtime = FinishUpRuntime()
    layers = runtime._provider_layers(provider, _PRIVACY)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    by_key = {layer.key: layer.state for layer in layers}

    assert by_key["semantic_review_ready"] is LayerState.VERIFIED
    assert by_key["agent_route_review_ready"] is LayerState.NOT_CONFIGURED
    assert "finishup integrate codex mcp preview" in _detail(provider)


def test_a_policy_registration_reports_the_route_as_ready() -> None:
    provider = _provider(agent_route_semantic_ready=True, registered_route_profile="policy")
    assert _layer(provider) is LayerState.VERIFIED
    assert _detail(provider) == ""


def test_an_unread_registration_is_unknown_rather_than_a_blocker() -> None:
    """Absent evidence is not evidence of a strict route."""

    provider = _provider(agent_route_semantic_ready=None, registered_route_profile=None)
    assert _layer(provider) is LayerState.UNKNOWN
    assert "could not be read" in _detail(provider)


def _admission_layer(provider: ProviderPosture) -> tuple[LayerState, str]:
    runtime = FinishUpRuntime()
    layers = runtime._provider_layers(provider, _PRIVACY)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    layer = next(layer for layer in layers if layer.key == "host_admission")
    return layer.state, layer.detail


def test_host_admission_is_its_own_layer_and_names_each_host() -> None:
    """Issue #467: a ready installation with no admission is where auto-review hosts hold checks."""

    ready = _provider(agent_route_semantic_ready=True, registered_route_profile="policy")
    state, detail = _admission_layer(ready)
    assert state is LayerState.UNKNOWN
    assert "could not be read" in detail

    present = _provider(
        host_admission=(("claude", "present"), ("codex", "absent"), ("cursor", "absent"))
    )
    state, detail = _admission_layer(present)
    assert state is LayerState.VERIFIED
    assert detail == "claude present, codex absent, cursor absent"

    absent = _provider(
        host_admission=(("claude", "absent"), ("codex", "absent"), ("cursor", "absent"))
    )
    state, detail = _admission_layer(absent)
    assert state is LayerState.NOT_CONFIGURED
    assert "finishup integrate <host> admission preview" in detail

    unreadable = _provider(host_admission=(("claude", "unknown"), ("codex", "absent")))
    assert _admission_layer(unreadable)[0] is LayerState.UNKNOWN

    drifted = _provider(
        host_admission=(("claude", "present"), ("codex", "absent"), ("cursor", "absent")),
        blockers=(("host_admission_drift", "present"),),
    )
    state, detail = _admission_layer(drifted)
    assert state is LayerState.NOT_CONFIGURED
    assert "revoke" in detail


def test_applied_policy_drift_names_reregistration_on_strict_route() -> None:
    """Issue #537 slice C: a stale strict process names re-registration, not just the route."""

    provider = _provider(
        agent_route_semantic_ready=False,
        registered_route_profile="strict",
        route_drift_since_install=True,
    )
    assert _layer(provider) is LayerState.NOT_CONFIGURED
    detail = _detail(provider)
    assert "registered on the strict route" in detail
    assert "applied route differs since install" in detail
    assert "fresh Codex process" in detail


def test_genuine_strict_route_keeps_terminal_detail() -> None:
    """Without drift the strict detail keeps today's terminal wording exactly."""

    provider = _provider(agent_route_semantic_ready=False, registered_route_profile="strict")
    assert _detail(provider) == (
        "registered on the strict route; 'finishup integrate codex mcp preview' to change it"
    )


def _advice_layer(provider: ProviderPosture) -> tuple[LayerState, str]:
    runtime = FinishUpRuntime()
    layers = runtime._provider_layers(provider, _PRIVACY)  # pyright: ignore[reportPrivateUsage]  # noqa: SLF001
    layer = next(layer for layer in layers if layer.key == "background_advice")
    return layer.state, layer.detail


def test_background_advice_is_its_own_layer_with_its_reason() -> None:
    """Issue #888: the terminal interface shows the effective switch and why."""

    state, detail = _advice_layer(
        _provider(background_advice_enabled=False, background_advice_reason="owner_disabled")
    )
    assert state is LayerState.NOT_CONFIGURED
    assert "set to false" in detail
    assert "set it to true" in detail

    # On by default where AI-powered review is configured (#888), still unproven.
    state, detail = _advice_layer(
        _provider(background_advice_enabled=True, background_advice_reason="default_enabled")
    )
    assert state is LayerState.UNPROVEN
    assert "on by default" in detail
    assert "semantic_advice_enabled = false" in detail

    # Even when on it is unproven: it runs only while a provider is usable (#923).
    state, detail = _advice_layer(
        _provider(background_advice_enabled=True, background_advice_reason="owner_enabled")
    )
    assert state is LayerState.UNPROVEN
    assert "provider is usable" in detail

    state, detail = _advice_layer(_provider())
    assert state is LayerState.UNKNOWN
    assert "could not be read" in detail
