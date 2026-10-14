"""The first-run questionnaire materializes only closed, bounded policies."""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

import pytest

from builders.privacy_policies import local_only_policy
from finishup.cli.privacy_setup import (
    PrivacyRecipe,
    PrivacySetupAnswers,
    build_candidate_policy,
)
from finishup.config.models import OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID, FinishUpConfig
from finishup.config.write import codex_subscription_runtime
from finishup.domain.privacy import (
    AuthorizationScopeKind,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    ProviderBinding,
    ReviewContextProfile,
)
from finishup.domain.values import JsonObject
from finishup.protocol.models import DataCategory
from finishup.service.confidential_protocol import PrivacyDecisionResult


def _answers(**overrides: object) -> PrivacySetupAnswers:
    values: dict[str, object] = {
        "network_egress": True,
        "local_models": False,
        "external_provider": ProviderBinding(
            "fireworks",
            "accounts/fireworks/models/minimax-m3",
            "fireworks-responses",
            "1.0.0",
            "external",
        ),
        "require_current_provider_data_use_evidence": False,
        "local_model_binding": None,
        "review_context": ReviewContextProfile.ASSISTED,
        "content_categories": (
            DataCategory.BOUNDED_STRUCTURAL_METADATA,
            DataCategory.EVIDENCE_EXCERPT,
            DataCategory.REPOSITORY_EXCERPT,
        ),
        "content_data_classes": (
            DataClass.PUBLIC_STRUCTURAL,
            DataClass.ORDINARY_USER_CONTENT,
        ),
        "agent_context_categories": (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        "agent_context_data_classes": (DataClass.PUBLIC_STRUCTURAL,),
        "local_model_categories": (),
        "local_model_data_classes": (),
        "request_confirmation": False,
        "telemetry": False,
        "crash_diagnostics": False,
        "updates": False,
        "capability_testing": False,
        "authorization_scope": AuthorizationScopeKind.TASK,
        "credential_probe": False,
    }
    values.update(overrides)
    return PrivacySetupAnswers(**values)  # type: ignore[arg-type]


def test_configured_bindings_accepts_the_exact_external_runtime_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module
    import finishup.config.load as config_load

    runtime = codex_subscription_runtime(
        executable_path="/opt/codex/0.150.1/codex",
        executable_sha256="sha256:" + "a" * 64,
        runtime_version="0.150.1",
        source_identity="openai-codex-npm-darwin-arm64-0.150.1",
        app_server_schema_sha256="sha256:" + "b" * 64,
        capability_cell_sha256="sha256:" + "d" * 64,
        isolated_config_sha256="sha256:" + "c" * 64,
        capability_profile="codex-evaluator/0.150.1/v1",
        capability_evidence_expires_at="2026-11-30T00:00:00Z",
        codex_home="/var/lib/finishup/codex-0.150.1",
        model="gpt-5.6-sol",
        reasoning_effort="high",
    )
    config = FinishUpConfig(profile="codex-subscription", external_runtime=runtime)

    def load_runtime_config(*_args: object, **_kwargs: object) -> FinishUpConfig:
        return config

    monkeypatch.setattr(config_load, "load_config", load_runtime_config)

    external, local = module._configured_bindings()  # pyright: ignore[reportPrivateUsage]

    assert local is None
    assert external == ProviderBinding(
        "openai-codex",
        "gpt-5.6-sol",
        "codex-chatgpt-subscription",
        "1.0.0",
        "external",
    )


def test_assisted_review_is_bound_to_one_provider_and_bounded_categories() -> None:
    current = local_only_policy()
    candidate = build_candidate_policy(
        current,
        _answers(),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )

    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert candidate.network_egress_permitted is True
    assert llm.enabled is True
    assert llm.provider_binding is not None
    assert llm.provider_binding.provider_id == "fireworks"
    assert llm.scope_ceiling is AuthorizationScopeKind.TASK
    assert llm.allowed_purposes == ("semantic-review",)
    assert llm.allowed_data_classes == (
        DataClass.ORDINARY_USER_CONTENT,
        DataClass.PUBLIC_STRUCTURAL,
    )
    assert DataCategory.TRANSCRIPT_EXCERPT not in llm.allowed_categories
    assert all(
        not channel.enabled
        for channel in candidate.channel_policies
        if channel.channel not in {EgressChannel.LLM_INFERENCE, EgressChannel.UPDATE_CHECKS}
    )
    # Product default recipes and _answers leave updates off unless set; this helper defaults off.
    assert candidate.supersedes_policy_digest == current.policy_digest


def test_unavailable_network_channels_fail_closed() -> None:
    with pytest.raises(ValueError, match="privacy_setup_channel_unsupported"):
        build_candidate_policy(
            local_only_policy(),
            _answers(telemetry=True),
            now=datetime(2026, 7, 29, tzinfo=UTC),
        )


def test_credential_probe_requires_explicit_provider_authorization() -> None:
    with pytest.raises(ValueError, match="privacy_setup_credential_probe_requires_provider"):
        build_candidate_policy(
            local_only_policy(),
            _answers(network_egress=False, external_provider=None, credential_probe=True),
            now=datetime(2026, 7, 29, tzinfo=UTC),
        )

    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(credential_probe=True),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )
    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert llm.allowed_purposes == ("credential-probe", "semantic-review")


def test_update_checks_may_be_enabled_without_llm() -> None:
    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(
            network_egress=False,
            external_provider=None,
            review_context=ReviewContextProfile.STRUCTURAL,
            content_categories=(),
            content_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
            request_confirmation=False,
            updates=True,
            authorization_scope=AuthorizationScopeKind.MACHINE,
        ),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )
    updates = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.UPDATE_CHECKS
    )
    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert candidate.network_egress_permitted is True
    assert updates.enabled is True
    assert llm.enabled is False
    assert candidate.profile.value == "local_only"


def test_network_egress_requires_an_exact_provider_binding() -> None:
    with pytest.raises(ValueError, match="privacy_setup_provider_binding_required"):
        build_candidate_policy(
            local_only_policy(),
            _answers(external_provider=None),
            now=datetime(2026, 7, 29, tzinfo=UTC),
        )


def test_metadata_only_hint_is_the_selected_privacy_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[tuple[str, str]] = []

    def prompt(label: str, *, default: str) -> str:
        prompts.append((label, default))
        return default

    monkeypatch.setattr(module.typer, "prompt", prompt)

    recipe = module._recipe_prompt(  # pyright: ignore[reportPrivateUsage]
        "metadata_only", "metadata_only"
    )

    assert recipe == "metadata_only"
    assert prompts == [("Choose a privacy option", "2")]


def test_listing_the_options_never_reads_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Rendering must not be able to fail on an unrelated environment variable.

    `_recipe_prompt` briefly derived the recommendation itself, which loads configuration and
    raises `ConfigError` on any unrecognized `FINISHUP_*` variable. `ConfigError` is not a
    `ValueError`, so it escaped every handler and turned the option list into a traceback.
    """

    import finishup.cli.privacy_setup as module

    def exploding_bindings() -> tuple[ProviderBinding | None, ProviderBinding | None]:
        raise AssertionError("rendering the option list must not read configuration")

    def prompt(_label: str, *, default: str) -> str:
        return default

    monkeypatch.setattr(module, "_configured_bindings", exploding_bindings)
    monkeypatch.setattr(module.typer, "prompt", prompt)

    assert (
        module._recipe_prompt("private", "private")  # pyright: ignore[reportPrivateUsage]
        == "private"
    )


def test_recommendation_is_assisted_for_fireworks_store_false_route() -> None:
    from finishup.cli.privacy_setup import recommended_privacy_recipe

    assert (
        recommended_privacy_recipe(
            _answers().external_provider, now=datetime(2026, 8, 5, tzinfo=UTC)
        )
        == "assisted_review"
    )


def test_recommendation_is_assisted_for_an_eligible_exact_provider_route() -> None:
    from finishup.cli.privacy_setup import recommended_privacy_recipe

    binding = ProviderBinding(
        "openai",
        "gpt-5",
        OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID,
        "1.0.0",
        "external",
    )

    assert (
        recommended_privacy_recipe(binding, now=datetime(2026, 8, 5, tzinfo=UTC))
        == "assisted_review"
    )


def test_recommendation_is_private_for_router_without_constrained_downstream() -> None:
    from finishup.cli.privacy_setup import recommended_privacy_recipe

    binding = ProviderBinding(
        "openrouter",
        "openai/gpt-5",
        "openrouter-openai-chat-completions",
        "1.0.0",
        "external",
    )

    assert recommended_privacy_recipe(binding, now=datetime(2026, 8, 5, tzinfo=UTC)) == "private"


def test_router_route_cannot_receive_standing_assisted_authority() -> None:
    with pytest.raises(ValueError, match="privacy_setup_router_route_unconstrained"):
        build_candidate_policy(
            local_only_policy(),
            _answers(
                external_provider=ProviderBinding(
                    "openrouter",
                    "openai/gpt-5",
                    "openrouter-openai-chat-completions",
                    "1.0.0",
                    "external",
                ),
                require_current_provider_data_use_evidence=False,
                request_confirmation=False,
            ),
            now=datetime(2026, 8, 5, tzinfo=UTC),
        )


def test_router_route_remains_available_with_per_request_confirmation() -> None:
    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(
            external_provider=ProviderBinding(
                "openrouter",
                "openai/gpt-5",
                "openrouter-openai-chat-completions",
                "1.0.0",
                "external",
            ),
            review_context=ReviewContextProfile.STRUCTURAL,
            content_categories=(
                DataCategory.BOUNDED_STRUCTURAL_METADATA,
                DataCategory.DECLARED_FILE_TYPE,
            ),
            content_data_classes=(DataClass.PUBLIC_STRUCTURAL,),
            request_confirmation=True,
        ),
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )

    llm = next(
        channel
        for channel in candidate.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    assert llm.preview_required is True


def test_recommendation_is_private_when_no_provider_is_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    monkeypatch.setattr(module, "_configured_bindings", lambda: (None, None))

    assert module.recommended_privacy_recipe() == "private"


def test_recommended_metadata_recipe_is_bounded_and_confirmation_first() -> None:
    import finishup.cli.privacy_setup as module

    external = _answers().external_provider
    answers = module._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "metadata_only", local_only_policy(), external
    )

    assert answers.network_egress is True
    assert answers.external_provider == external
    assert answers.review_context is ReviewContextProfile.STRUCTURAL
    assert answers.content_categories == (
        DataCategory.BOUNDED_STRUCTURAL_METADATA,
        DataCategory.DECLARED_FILE_TYPE,
    )
    assert answers.content_data_classes == (DataClass.PUBLIC_STRUCTURAL,)
    assert answers.request_confirmation is True
    assert answers.require_current_provider_data_use_evidence is False
    assert answers.authorization_scope is AuthorizationScopeKind.TASK


def test_private_recipe_requires_no_provider() -> None:
    import finishup.cli.privacy_setup as module

    answers = module._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "private", local_only_policy(), None
    )

    assert answers.network_egress is False
    assert answers.external_provider is None
    assert answers.content_categories == ()
    assert answers.request_confirmation is False
    assert answers.authorization_scope is AuthorizationScopeKind.MACHINE


@pytest.mark.parametrize("recipe", ["metadata_only", "assisted_review", "expanded_review"])
def test_external_recipes_fail_closed_without_a_configured_provider(
    recipe: PrivacyRecipe,
) -> None:
    """No recipe may enable egress against a destination the installation has not bound."""

    import finishup.cli.privacy_setup as module

    with pytest.raises(ValueError, match="privacy_setup_provider_binding_required"):
        module._recipe_answers(recipe, local_only_policy(), None)  # pyright: ignore[reportPrivateUsage]


def test_named_recipes_never_enable_an_unsupported_channel() -> None:
    """Telemetry, diagnostics, and capability testing stay off; update_checks defaults on."""

    import finishup.cli.privacy_setup as module

    named: tuple[PrivacyRecipe, ...] = (
        "private",
        "metadata_only",
        "assisted_review",
        "expanded_review",
    )
    for recipe in named:
        answers = module._recipe_answers(  # pyright: ignore[reportPrivateUsage]
            recipe, local_only_policy(), _answers().external_provider
        )
        assert (
            answers.telemetry,
            answers.crash_diagnostics,
            answers.updates,
            answers.capability_testing,
        ) == (False, False, True, False)


def test_privacy_options_explain_tradeoffs_and_change_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    import finishup.cli.privacy_setup as module

    module._render_recipe_options(  # pyright: ignore[reportPrivateUsage]
        recommended="metadata_only"
    )

    output = capsys.readouterr().out
    assert "Private — maximum confidentiality" in output
    assert "Metadata only (recommended)" in output
    assert "Assisted review — better problem-specific feedback" in output
    assert "Expanded review — most reviewer context" in output
    assert "Custom — maximum control" in output
    assert "finishup --privacy" in output


def test_named_review_context_reprompts_instead_of_aborting_on_yes(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    import finishup.cli.privacy_setup as module

    answers = iter(("y", "assisted"))

    def prompt(*_args: object, **_kwargs: object) -> str:
        return next(answers)

    monkeypatch.setattr(module.typer, "prompt", prompt)

    review = module._review_context_prompt(  # pyright: ignore[reportPrivateUsage]
        ReviewContextProfile.ASSISTED
    )

    assert review is ReviewContextProfile.ASSISTED
    assert "Choose structural, goal_aware, assisted, or expanded." in capsys.readouterr().out


def _install_setup_stubs(
    monkeypatch: pytest.MonkeyPatch,
    *,
    current: PrivacyPolicy,
    confirmations: Iterator[bool],
    prompts: list[str],
    external: ProviderBinding | None = None,
    grant_state: Literal["granted", "missing"] = "missing",
    migration_state: Literal[
        "not_applicable",
        "legacy_route_available",
        "first_repository_available",
        "consumed",
    ] = "not_applicable",
) -> None:
    """Stub only the I/O edges, leaving the real recipe and branch selection under test."""

    import finishup.cli.privacy_setup as module

    async def snapshot(_workspace_locator: object = None) -> object:
        return module.PrivacySetupSnapshot(
            current,
            JsonObject({"kind": "workspace"}),
            "sha256:" + "d" * 64,
            grant_state,
            migration_state,
        )

    async def propose(
        _candidate: PrivacyPolicy,
        _digest: str,
        *,
        workspace_locator: object = None,
    ) -> str:
        del workspace_locator
        return "pvp_1"

    async def decide(_proposal: str) -> PrivacyDecisionResult:
        return PrivacyDecisionResult("committed", "sha256:" + "c" * 64)

    def confirm(prompt: str, *, default: bool = False) -> bool:
        del default
        prompts.append(prompt)
        return next(confirmations)

    def interactive() -> bool:
        return True

    def bindings() -> tuple[ProviderBinding | None, ProviderBinding | None]:
        return external, None

    def render_options(*, recommended: object = None) -> None:
        del recommended

    def render_review(_candidate: PrivacyPolicy) -> None:
        return None

    monkeypatch.setattr(module, "_interactive_terminal", interactive)
    monkeypatch.setattr(module, "get_privacy_setup_snapshot", snapshot)
    monkeypatch.setattr(module, "_configured_bindings", bindings)
    monkeypatch.setattr(module, "_configured_fallback_binding", lambda: None)
    monkeypatch.setattr(module, "_render_recipe_options", render_options)
    monkeypatch.setattr(module, "_render_review", render_review)
    monkeypatch.setattr(module.typer, "confirm", confirm)
    monkeypatch.setattr(module, "_propose", propose)
    monkeypatch.setattr(module, "_decide", decide)


def _forbid_custom_sections(monkeypatch: pytest.MonkeyPatch, reason: str) -> None:
    import finishup.cli.privacy_setup as module

    def forbidden(*_args: object) -> PrivacySetupAnswers:
        raise AssertionError(reason)

    monkeypatch.setattr(module, "_ask_custom_answers", forbidden)


def _stub_route(monkeypatch: pytest.MonkeyPatch, observation: object) -> list[str]:
    """Replace the Codex route probe and capture what the ceremony prints about it."""

    import finishup.cli.privacy_setup as module
    import finishup.cli.provider_status as provider_status

    printed: list[str] = []

    async def observe(_workspace_locator: Path | None = None) -> object:
        if isinstance(observation, Exception):
            raise observation
        return observation

    def echo(message: str = "", *_args: object, **_kwargs: object) -> None:
        printed.append(message)

    monkeypatch.setattr(provider_status, "mcp_route_observation", observe)
    monkeypatch.setattr(module.typer, "echo", echo)
    return printed


@pytest.mark.anyio
async def test_tui_opt_out_reaches_review_without_proposing_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The documented prompt-loop opt-out is not service configuration.

    The privacy ceremony loads the configured bindings after rendering repository authority.
    Treating ``FINISHUP_TUI`` as an unknown config override failed there before the first review or
    decision prompt, even though the variable can only choose the terminal presentation layer.
    """

    import os

    import finishup.cli.privacy_setup as module

    configured_bindings = module._configured_bindings  # pyright: ignore[reportPrivateUsage]
    prompts: list[str] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((False,)),
        prompts=prompts,
        migration_state="legacy_route_available",
    )
    monkeypatch.setattr(module, "_configured_bindings", configured_bindings)
    for name in tuple(os.environ):
        if name.startswith("FINISHUP_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("FINISHUP_CONFIG", str(tmp_path / "missing.toml"))
    monkeypatch.setenv("FINISHUP_TUI", "0")

    async def forbidden_propose(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("declining the review must not create a privacy proposal")

    monkeypatch.setattr(module, "_propose", forbidden_propose)

    report = await module.run_privacy_setup(recipe_hint="private")

    assert report.outcome == "cancelled"
    assert report.migration_state == "legacy_route_available"
    assert prompts == ["Create this exact privacy proposal (Private)?"]


@pytest.mark.anyio
async def test_a_widening_commit_names_a_strict_route_that_cannot_dispatch_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Committing external review with a strict registration must not pass silently.

    Otherwise the policy is correct, every check in the next Codex session returns
    ``blocked_by_policy`` / ``route_semantic_ceiling``, and nothing anywhere connects the two.
    """

    import finishup.cli.privacy_setup as module

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )
    printed = _stub_route(monkeypatch, {"registered_profile": "strict", "observed": True})

    report = await module.run_privacy_setup(offer_recommended=True)

    assert report.outcome == "configured"
    assert any("'strict'" in line for line in printed)
    assert any("finishup integrate codex mcp preview" in line for line in printed)


@pytest.mark.anyio
async def test_a_policy_route_draws_no_registration_note(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )
    printed = _stub_route(monkeypatch, {"registered_profile": "policy", "observed": True})

    report = await module.run_privacy_setup(offer_recommended=True)

    assert report.outcome == "configured"
    assert not any("integrate codex mcp preview" in line for line in printed)


@pytest.mark.anyio
async def test_an_unreadable_route_says_nothing_and_changes_no_outcome(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The note is advisory: an unobservable route is unknown, never a warning or a failure."""

    import finishup.cli.privacy_setup as module

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )
    printed = _stub_route(monkeypatch, RuntimeError("codex unreadable"))

    report = await module.run_privacy_setup(offer_recommended=True)

    assert report.outcome == "configured"
    assert not any("integrate codex mcp preview" in line for line in printed)


@pytest.mark.anyio
async def test_a_local_only_commit_never_mentions_the_agent_route(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A policy that permits no external review has nothing to say about the route."""

    import finishup.cli.privacy_setup as module

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=None,
    )
    probed: list[str] = []

    async def observe(_workspace_locator: Path | None = None) -> object:
        probed.append("observed")
        return {"registered_profile": "strict", "observed": True}

    import finishup.cli.provider_status as provider_status

    monkeypatch.setattr(provider_status, "mcp_route_observation", observe)

    report = await module.run_privacy_setup(offer_recommended=True)

    # Guards against passing vacuously: an "unchanged" report would never reach the probe.
    assert report.outcome == "configured"
    assert probed == []


@pytest.mark.anyio
async def test_accepting_recommended_policy_asks_nothing_else(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []

    def forbidden_choice(_hint: object) -> str:
        raise AssertionError("accepting the recommendation must not open the recipe list")

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=prompts,
        external=_answers().external_provider,
    )
    _forbid_custom_sections(
        monkeypatch, "recommended acceptance must skip field-level configuration"
    )
    monkeypatch.setattr(module, "_recipe_choice", forbidden_choice)

    report = await module.run_privacy_setup(offer_recommended=True)

    assert report.outcome == "configured"
    assert prompts == ["Use this recommended privacy policy?"]


@pytest.mark.anyio
async def test_declining_recommended_policy_opens_the_recipe_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []
    offered: list[object] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((False, True)),
        prompts=prompts,
        external=_answers().external_provider,
    )

    def choose(hint: object) -> str:
        offered.append(hint)
        return "assisted_review"

    monkeypatch.setattr(module, "_recipe_choice", choose)
    _forbid_custom_sections(monkeypatch, "a named recipe must not open field-level configuration")

    report = await module.run_privacy_setup(offer_recommended=True)

    assert report.outcome == "configured"
    # The declined recommendation is what the recipe list starts on.
    assert offered == ["assisted_review"]
    assert prompts == [
        "Use this recommended privacy policy?",
        "Create this exact privacy proposal (Assisted review)?",
    ]


@pytest.mark.anyio
async def test_a_named_recipe_hint_skips_both_the_list_and_the_custom_sections(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []

    def forbidden_prompt(_hint: object) -> str:
        raise AssertionError("a named hint must not re-ask which recipe to use")

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=prompts,
        external=_answers().external_provider,
    )
    monkeypatch.setattr(module, "_recipe_prompt", forbidden_prompt)
    _forbid_custom_sections(monkeypatch, "a named recipe must not open field-level configuration")

    report = await module.run_privacy_setup(recipe_hint="expanded_review")

    assert report.outcome == "configured"
    assert prompts == ["Create this exact privacy proposal (Expanded review)?"]


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("override", "expected_enabled"),
    ((True, True), (False, False), (None, True)),
)
async def test_named_private_recipe_applies_explicit_update_choice_before_proposal(
    monkeypatch: pytest.MonkeyPatch,
    override: bool | None,
    expected_enabled: bool,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []
    proposed: list[PrivacyPolicy] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=prompts,
        external=None,
    )

    async def capture_proposal(
        candidate: PrivacyPolicy,
        _digest: str,
        *,
        workspace_locator: object = None,
    ) -> str:
        del workspace_locator
        proposed.append(candidate)
        return "pvp_1"

    monkeypatch.setattr(module, "_propose", capture_proposal)

    report = await module.run_privacy_setup(
        recipe_hint="private",
        update_checks_override=override,
    )

    assert report.outcome == "configured"
    assert prompts == ["Create this exact privacy proposal (Private)?"]
    assert len(proposed) == 1
    candidate = proposed[0]
    updates = next(
        row for row in candidate.channel_policies if row.channel is EgressChannel.UPDATE_CHECKS
    )
    assert updates.enabled is expected_enabled
    assert candidate.network_egress_permitted is expected_enabled
    assert candidate.profile.value == "local_only"
    assert all(
        not row.enabled
        for row in candidate.channel_policies
        if row.channel is not EgressChannel.UPDATE_CHECKS
    )


@pytest.mark.anyio
async def test_recommended_recipe_applies_update_override_without_changing_review_fields(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []
    proposed: list[PrivacyPolicy] = []
    external = _answers().external_provider
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=prompts,
        external=external,
    )

    def recommend(_external: ProviderBinding | None = None) -> PrivacyRecipe:
        return "assisted_review"

    monkeypatch.setattr(module, "recommended_privacy_recipe", recommend)

    async def capture_proposal(
        candidate: PrivacyPolicy,
        _digest: str,
        *,
        workspace_locator: object = None,
    ) -> str:
        del workspace_locator
        proposed.append(candidate)
        return "pvp_1"

    monkeypatch.setattr(module, "_propose", capture_proposal)

    report = await module.run_privacy_setup(
        offer_recommended=True,
        update_checks_override=False,
    )

    assert report.outcome == "configured"
    assert prompts == ["Use this recommended privacy policy?"]
    candidate = proposed[0]
    expected = module.build_candidate_policy(
        local_only_policy(),
        replace(
            module.recipe_answers("assisted_review", local_only_policy(), external), updates=False
        ),
        now=candidate.created_at,
    )
    assert candidate.profile is expected.profile
    assert candidate.review_context_profile is expected.review_context_profile
    assert candidate.review_selection == expected.review_selection
    assert candidate.require_current_provider_data_use_evidence is (
        expected.require_current_provider_data_use_evidence
    )
    assert candidate.channel_policies == expected.channel_policies


@pytest.mark.anyio
async def test_update_override_never_bypasses_exact_candidate_confirmation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((False,)),
        prompts=prompts,
        external=None,
    )

    async def forbidden_propose(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("declined update override must not reach the trusted proposal")

    monkeypatch.setattr(module, "_propose", forbidden_propose)

    report = await module.run_privacy_setup(
        recipe_hint="private",
        update_checks_override=False,
    )

    assert report.outcome == "cancelled"
    assert prompts == ["Create this exact privacy proposal (Private)?"]


@pytest.mark.anyio
async def test_custom_is_the_only_path_into_field_level_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    prompts: list[str] = []
    asked: list[object] = []
    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=prompts,
        external=_answers().external_provider,
    )

    def custom_recipe(_hint: object) -> str:
        return "custom"

    def custom(*args: object) -> PrivacySetupAnswers:
        asked.append(args)
        return _answers()

    monkeypatch.setattr(module, "_recipe_prompt", custom_recipe)
    monkeypatch.setattr(module, "_ask_custom_answers", custom)

    report = await module.run_privacy_setup(recipe_hint="custom")

    assert report.outcome == "configured"
    assert len(asked) == 1
    assert prompts == ["Use this exact custom privacy policy?"]


@pytest.mark.anyio
async def test_a_custom_hint_does_not_reopen_the_recipe_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A caller that passed `custom` already chose; asking again is a confirmation of nothing."""

    import finishup.cli.privacy_setup as module

    def forbidden_prompt(*_args: object) -> str:
        raise AssertionError("a custom hint must not reopen the recipe list")

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )

    def custom(*_args: object) -> PrivacySetupAnswers:
        return _answers()

    monkeypatch.setattr(module, "_recipe_prompt", forbidden_prompt)
    monkeypatch.setattr(module, "_ask_custom_answers", custom)

    assert (await module.run_privacy_setup(recipe_hint="custom")).outcome == "configured"


def test_custom_configuration_announces_all_five_sections(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Grouped sections replace the flat thirteen questions, and none is silently skipped."""

    import finishup.cli.privacy_setup as module

    confirmations: list[tuple[str, bool]] = []

    def confirm(prompt: str, *, default: bool = False) -> bool:
        confirmations.append((prompt, default))
        return False

    def prompt(_label: str, *, default: str = "") -> str:
        return default

    monkeypatch.setattr(module.typer, "confirm", confirm)
    monkeypatch.setattr(module.typer, "prompt", prompt)

    answers = module._ask_custom_answers(  # pyright: ignore[reportPrivateUsage]
        local_only_policy(), _answers().external_provider, None
    )

    output = capsys.readouterr().out
    for number, title in (
        (1, "External and local destinations"),
        (2, "What an external reviewer may see"),
        (3, "Local visibility: agent host and local model"),
        (4, "Per-request confirmation and authorization scope"),
        (5, "Package updates and unsupported channels"),
    ):
        assert f"Section {number} of 5 — {title}" in output
    # Section 5 asks about package updates; the other three remain unsupported/off.
    assert "cannot be turned on here" in output
    assert "package update" in output.casefold()
    assert (
        "Check PyPI for FinishUP updates (package name and version only)?",
        True,
    ) in confirmations
    # Mock confirm returns False for every prompt, so updates is explicitly declined.
    assert (
        answers.telemetry,
        answers.crash_diagnostics,
        answers.updates,
        answers.capability_testing,
    ) == (False, False, False, False)


@pytest.mark.anyio
async def test_repository_setup_snapshot_accepts_service_json_object(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.app as app_module
    import finishup.cli.privacy_setup as module
    from finishup.adapters.privacy.catalog import encode_privacy_policy_json

    current = local_only_policy()

    class Client:
        async def privacy_get_setup(self, request: object) -> JsonObject:
            assert request == JsonObject({"schema_version": "2.0.0"})
            return JsonObject(
                {
                    "schema_version": "2.0.0",
                    "composed_policy": encode_privacy_policy_json(current),
                    "bound_scope": {"kind": "workspace"},
                    "authority_digest": "sha256:" + "d" * 64,
                    "grant_state": "missing",
                    "migration_state": "not_applicable",
                }
            )

        async def close(self) -> None:
            return None

    async def build_client(
        *,
        workspace_locator: object = None,
        projection_render_mode: object = None,
        output_is_controlling_tty: bool = False,
    ) -> Client:
        assert workspace_locator is not None
        assert getattr(projection_render_mode, "value", None) == "human_readable"
        assert type(output_is_controlling_tty) is bool
        return Client()

    monkeypatch.setattr(app_module, "build_service_client", build_client)

    observed = await module.get_privacy_setup_snapshot()

    assert observed.composed_policy == current
    assert observed.grant_state == "missing"


@pytest.mark.anyio
async def test_repository_proposal_carries_the_snapshot_authority_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.app as app_module
    import finishup.cli.privacy_setup as module

    requests: list[JsonObject] = []

    class Client:
        async def privacy_propose_policy(self, request: JsonObject) -> JsonObject:
            requests.append(request)
            return JsonObject({"schema_version": "2.0.0", "outcome": "tightening_applied"})

        async def close(self) -> None:
            return None

    async def build_client(
        *,
        workspace_locator: object = None,
        projection_render_mode: object = None,
        output_is_controlling_tty: bool = False,
    ) -> Client:
        assert getattr(workspace_locator, "path", None) == str(tmp_path)
        assert getattr(projection_render_mode, "value", None) == "human_readable"
        assert type(output_is_controlling_tty) is bool
        return Client()

    monkeypatch.setattr(app_module, "build_service_client", build_client)
    digest = "sha256:" + "d" * 64

    assert (
        await module._propose(  # pyright: ignore[reportPrivateUsage]
            local_only_policy(), digest, workspace_locator=tmp_path
        )
        is None
    )
    assert requests[0]["schema_version"] == "2.0.0"
    assert requests[0]["authority_digest"] == digest
    assert "expected_policy_digest" not in requests[0]


@pytest.mark.anyio
async def test_widening_reports_configured_only_after_committed_trusted_decision(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import finishup.cli.privacy_setup as module

    def custom_recipe(_hint: object) -> str:
        return "custom"

    def custom(*_args: object) -> PrivacySetupAnswers:
        return _answers()

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )
    monkeypatch.setattr(module, "_recipe_prompt", custom_recipe)
    monkeypatch.setattr(module, "_ask_custom_answers", custom)

    report = await module.run_privacy_setup(recipe_hint="custom")

    assert report.outcome == "configured"
    assert report.proposal_id == "pvp_1"


def test_review_warns_when_data_use_requirement_cannot_be_satisfied(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """RT-privacy-egress-2 companion: the refusal must be visible before it is committed."""

    from finishup.cli.privacy_setup import _render_review  # pyright: ignore[reportPrivateUsage]

    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(
            external_provider=ProviderBinding(
                "openrouter",
                "openai/gpt-5",
                "openrouter-openai-chat-completions",
                "1.0.0",
                "external",
            ),
            require_current_provider_data_use_evidence=True,
            request_confirmation=True,
        ),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )
    assert candidate.require_current_provider_data_use_evidence is True

    _render_review(candidate)

    out = capsys.readouterr().out
    assert "openrouter-openai-chat-completions" in out
    assert "downstream provider" in out
    assert "Customer-content training: unknown" in out
    assert "Retention: unknown" in out
    assert "Provider human access: unknown" in out
    assert "runtime evidence guard is ON" in out
    assert "will be refused" in out


def test_review_is_silent_when_the_requirement_is_off(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.cli.privacy_setup import _render_review  # pyright: ignore[reportPrivateUsage]

    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(require_current_provider_data_use_evidence=False),
        now=datetime(2026, 7, 29, tzinfo=UTC),
    )

    _render_review(candidate)

    assert "will be refused" not in capsys.readouterr().out


def test_assisted_recipe_requires_data_use_only_where_it_can_be_satisfied() -> None:
    """The recipe default must stay dispatchable; the requirement is the operator's call.

    require_current_provider_data_use_evidence is enforced at dispatch, so setting it against an
    endpoint with unknown data-use facts yields a setup that refuses every external review. The
    recipe therefore asks for it only where the bound endpoint ships reviewed evidence.
    """

    import finishup.cli.privacy_setup as module

    owner_declared = ProviderBinding(
        "openrouter",
        "openai/gpt-5",
        "openrouter-openai-chat-completions",
        "1.0.0",
        "external",
    )
    reviewed = ProviderBinding(
        "openai",
        "gpt-5",
        OFFICIAL_OPENAI_ENDPOINT_PROFILE_ID,
        "1.0.0",
        "external",
    )

    unknown_answers = module._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "assisted_review", local_only_policy(), owner_declared
    )
    reviewed_answers = module._recipe_answers(  # pyright: ignore[reportPrivateUsage]
        "assisted_review", local_only_policy(), reviewed
    )

    assert unknown_answers.require_current_provider_data_use_evidence is False
    assert reviewed_answers.require_current_provider_data_use_evidence is True


def test_informed_assisted_override_discloses_unknown_facts_and_guard_off(
    capsys: pytest.CaptureFixture[str],
) -> None:
    from finishup.cli.privacy_setup import _render_review  # pyright: ignore[reportPrivateUsage]

    candidate = build_candidate_policy(
        local_only_policy(),
        _answers(
            external_provider=ProviderBinding(
                "google_gemini",
                "gemini-3.5-flash",
                "google-gemini-openai-chat-completions",
                "1.0.0",
                "external",
            ),
            require_current_provider_data_use_evidence=False,
        ),
        now=datetime(2026, 8, 5, tzinfo=UTC),
    )

    _render_review(candidate)

    out = capsys.readouterr().out
    assert "Assisted recommendation eligible now: no" in out
    assert "runtime evidence guard is OFF" in out
    assert "informed standing authorization" in out


def _admit_claude(project: Path) -> Path:
    settings = project / ".claude" / "settings.local.json"
    settings.parent.mkdir(exist_ok=True)
    settings.write_text(
        json.dumps({"permissions": {"allow": ["mcp__plugin_finishup_finishup__check"]}}),
        encoding="utf-8",
    )
    return settings


@pytest.mark.anyio
async def test_a_commit_that_stops_external_review_removes_the_host_admission_finishup_wrote(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Grant revoke is a reverse transition for host admission (issue #467).

    The host rule is derived from the grant; when the trusted ceremony withdraws the grant, the
    same ceremony removes exactly the entry FinishUP wrote and says so.
    """

    import finishup.cli.privacy_setup as module

    answers = _answers()
    assisted = module.build_candidate_policy(local_only_policy(), answers, now=datetime.now(UTC))
    _install_setup_stubs(
        monkeypatch,
        current=assisted,
        confirmations=iter((True,)),
        prompts=[],
        external=answers.external_provider,
        grant_state="granted",
    )
    printed = _stub_route(monkeypatch, {"registered_profile": "policy", "observed": True})
    settings = _admit_claude(tmp_path)
    foreign = tmp_path / ".cursor" / "permissions.json"
    foreign.parent.mkdir()
    foreign.write_text(json.dumps({"mcpAllowlist": ["finishup:*"]}), encoding="utf-8")

    report = await module.run_privacy_setup(recipe_hint="private", workspace_locator=tmp_path)

    assert report.outcome == "configured"
    assert not settings.exists()
    assert json.loads(foreign.read_text(encoding="utf-8")) == {"mcpAllowlist": ["finishup:*"]}
    assert any("admission removed" in line and "claude" in line for line in printed)
    assert not any("cursor" in line for line in printed)


@pytest.mark.anyio
async def test_a_widening_commit_names_hosts_that_will_still_hold_every_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    import finishup.cli.privacy_setup as module

    _install_setup_stubs(
        monkeypatch,
        current=local_only_policy(),
        confirmations=iter((True,)),
        prompts=[],
        external=_answers().external_provider,
    )
    printed = _stub_route(monkeypatch, {"registered_profile": "policy", "observed": True})
    _admit_claude(tmp_path)

    report = await module.run_privacy_setup(offer_recommended=True, workspace_locator=tmp_path)

    assert report.outcome == "configured"
    note = next(line for line in printed if "no host auto-review admission" in line)
    assert "codex, cursor" in note
    assert "claude" not in note
    assert any("finishup integrate <host> admission preview" in line for line in printed)
    # A widening never removes anything.
    assert (tmp_path / ".claude" / "settings.local.json").exists()
