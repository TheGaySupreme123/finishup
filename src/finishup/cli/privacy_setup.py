"""Trusted interactive privacy setup used by first run and ``privacy setup``.

One recommendation rule decides the first screen everywhere: **Assisted review** for an exact
external route with current qualifying data-use evidence, and **Private** otherwise. Accepting the
recommendation asks nothing further. Declining opens the named recipes, which materialize
straight into an exact draft; only ``Custom`` opens field-level configuration, and that is
five grouped sections rather than a flat questionnaire.

Every path ends at the same two gates: the exact resulting disclosure boundary, and — for any
widening — the separately reauthenticated trusted-terminal ceremony that renders the complete
``before → after`` policy diff.  Nothing here is an authorization; this module only builds a
candidate and asks the service to classify it.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, cast

import typer

from finishup.adapters.privacy.catalog import (
    decode_privacy_policy_canonical,
    encode_privacy_policy_json,
)
from finishup.adapters.privacy.local_enforcer import estimated_token_count
from finishup.adapters.providers.data_use_catalog import data_use_record_for_endpoint
from finishup.adapters.providers.openai_responses_factory import (
    endpoint_profile_data_use_reviewed,
)
from finishup.domain.privacy import (
    AuthorizationScopeKind,
    ChannelPolicy,
    CredentialHeuristic,
    DataClass,
    EgressChannel,
    PrivacyPolicy,
    PrivacyProfile,
    ProviderBinding,
    ReviewContextProfile,
    ReviewSelectionPolicy,
)
from finishup.domain.task_statement import task_statement_disclosure_text
from finishup.domain.values import JsonObject, validate_sha256_digest
from finishup.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from finishup.protocol.consent import RepositoryPrivacyRecipe
from finishup.protocol.models import DataCategory

__all__ = [
    "ProviderBindingRequiredError",
    "PrivacyRecipe",
    "PrivacySetupReport",
    "PrivacySetupSnapshot",
    "build_candidate_policy",
    "credential_heuristic_candidate",
    "run_credential_heuristic_change",
    "configured_bindings",
    "get_privacy_setup_snapshot",
    "propose_privacy_candidate",
    "recipe_answers",
    "recommended_privacy_recipe",
    "run_privacy_setup",
]

type PrivacyRecipe = RepositoryPrivacyRecipe | Literal["expanded_review", "custom"]


class ProviderBindingRequiredError(ValueError):
    """Raised when a provider-backed privacy recipe has no external provider binding."""

    def __init__(self) -> None:
        super().__init__("privacy_setup_provider_binding_required")


_SEMANTIC_CATEGORIES: Final = (
    DataCategory.BOUNDED_STRUCTURAL_METADATA,
    DataCategory.DECLARED_FILE_TYPE,
    DataCategory.TASK_DESCRIPTION,
    DataCategory.CLAIM_TEXT,
    DataCategory.OBLIGATION_TEXT,
    DataCategory.DECISION_EXCERPT,
    DataCategory.EVIDENCE_EXCERPT,
    DataCategory.FINDING_SUMMARY,
    DataCategory.COMMAND_METADATA,
    DataCategory.DIFF_METADATA,
    DataCategory.REPOSITORY_EXCERPT,
)
_AGENT_CATEGORIES: Final = tuple(DataCategory)
# Remaining non-LLM channels with no production transport. ``update_checks`` ships a
# bounded structural transport and is a real yes/no in section 5 (product default: on).
_UNSUPPORTED_CHANNELS: Final = (
    EgressChannel.PRODUCT_TELEMETRY,
    EgressChannel.CRASH_DIAGNOSTICS,
    EgressChannel.CAPABILITY_TESTING,
)
_UNCONSTRAINED_ROUTER_ENDPOINTS: Final = frozenset(
    {
        "openrouter-openai-chat-completions",
        "vercel-ai-gateway-openai-responses",
    }
)

_UPDATE_CHECKS_MAX_BYTES: Final = 4096
_UPDATE_CHECKS_MAX_TOKENS: Final = 1024
_UPDATE_CHECKS_TTL_SECONDS: Final = 60
# The two whole-case ceilings have to express the same budget. The enforcer estimates tokens
# from the prepared byte count, so a token ceiling set independently of the byte ceiling becomes
# the real limit at a completely different size: 4096 tokens binds at 16 KiB, sixteen times
# tighter than 256 KiB, and below the 128 KiB of excerpts the assisted and expanded review
# selections are already allowed to gather. Derive one from the other so they cannot drift.
_CASE_MAX_BYTES: Final = 256 * 1024
_CASE_MAX_TOKENS: Final = estimated_token_count(_CASE_MAX_BYTES)

_RECIPE_DEFAULTS: Final = {
    "private": "1",
    "metadata_only": "2",
    "assisted_review": "3",
    "expanded_review": "4",
    "custom": "5",
}
_RECIPE_CHOICES: Final = {
    "1": "private",
    "2": "metadata_only",
    "3": "assisted_review",
    "4": "expanded_review",
    "5": "custom",
}


@dataclass(frozen=True, slots=True)
class PrivacySetupAnswers:
    network_egress: bool
    local_models: bool
    external_provider: ProviderBinding | None
    require_current_provider_data_use_evidence: bool
    local_model_binding: ProviderBinding | None
    review_context: ReviewContextProfile
    content_categories: tuple[DataCategory, ...]
    content_data_classes: tuple[DataClass, ...]
    agent_context_categories: tuple[DataCategory, ...]
    agent_context_data_classes: tuple[DataClass, ...]
    local_model_categories: tuple[DataCategory, ...]
    local_model_data_classes: tuple[DataClass, ...]
    request_confirmation: bool
    telemetry: bool
    crash_diagnostics: bool
    updates: bool
    capability_testing: bool
    authorization_scope: AuthorizationScopeKind
    # The declared fallback destination (#582); approved together with the primary so the
    # policy names the exact set of endpoints AI-powered review may reach.
    fallback_provider: ProviderBinding | None = None
    # This request is distinct from AI-powered review: it carries only a fixed literal and is
    # available solely while a person is deliberately setting a provider credential.
    credential_probe: bool = False


@dataclass(frozen=True, slots=True)
class PrivacySetupReport:
    outcome: Literal["configured", "unchanged", "cancelled", "failed"]
    profile: str
    proposal_id: str | None = None
    reason: str | None = None
    grant_state: Literal["granted", "missing"] | None = None
    migration_state: str | None = None


@dataclass(frozen=True, slots=True)
class PrivacySetupSnapshot:
    """Repository-bound setup authority returned by the trusted local service.

    The raw repository path never appears here. ``bound_scope`` contains only the installation
    identifier and keyed repository commitment, and ``authority_digest`` binds the complete
    machine-ceiling/repository-row snapshot that a proposal must compare-and-swap against.
    """

    composed_policy: PrivacyPolicy
    bound_scope: JsonObject
    authority_digest: str
    grant_state: Literal["granted", "missing"]
    migration_state: Literal[
        "not_applicable",
        "legacy_route_available",
        "first_repository_available",
        "consumed",
    ]

    def __post_init__(self) -> None:
        if (
            type(self.composed_policy) is not PrivacyPolicy
            or type(self.bound_scope) is not JsonObject
        ):
            raise TypeError("privacy_setup_snapshot_invalid")
        validate_sha256_digest(self.authority_digest)
        if self.grant_state not in {"granted", "missing"}:
            raise ValueError("privacy_setup_snapshot_invalid")
        if self.migration_state not in {
            "not_applicable",
            "legacy_route_available",
            "first_repository_available",
            "consumed",
        }:
            raise ValueError("privacy_setup_snapshot_invalid")


def _disabled_channel(channel: EgressChannel) -> ChannelPolicy:
    return ChannelPolicy(
        channel,
        False,
        (),
        (),
        None,
        (),
        AuthorizationScopeKind.MACHINE,
        False,
        0,
        0,
        0,
    )


def _update_checks_channel(*, enabled: bool) -> ChannelPolicy:
    """Structural-only package version check row (no task/user content)."""

    if not enabled:
        return _disabled_channel(EgressChannel.UPDATE_CHECKS)
    return ChannelPolicy(
        EgressChannel.UPDATE_CHECKS,
        True,
        (DataCategory.BOUNDED_STRUCTURAL_METADATA,),
        (DataClass.PUBLIC_STRUCTURAL,),
        None,
        ("package-update-check",),
        AuthorizationScopeKind.MACHINE,
        False,
        _UPDATE_CHECKS_MAX_BYTES,
        _UPDATE_CHECKS_MAX_TOKENS,
        _UPDATE_CHECKS_TTL_SECONDS,
    )


def _ordered_channels(
    channels: dict[EgressChannel, ChannelPolicy],
) -> tuple[ChannelPolicy, ...]:
    return tuple(
        channels[channel] for channel in sorted(EgressChannel, key=lambda item: item.value)
    )


def build_candidate_policy(
    current: PrivacyPolicy,
    answers: PrivacySetupAnswers,
    *,
    now: datetime,
) -> PrivacyPolicy:
    """Materialize one reviewed questionnaire into the closed policy type."""

    if type(current) is not PrivacyPolicy or type(answers) is not PrivacySetupAnswers:
        raise TypeError("privacy_setup_candidate_invalid")
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    if any(
        (
            answers.telemetry,
            answers.crash_diagnostics,
            answers.capability_testing,
        )
    ):
        raise ValueError("privacy_setup_channel_unsupported")
    if answers.local_models != (answers.local_model_binding is not None):
        raise ValueError("privacy_setup_local_model_binding_required")
    if not answers.local_models and (
        answers.local_model_categories or answers.local_model_data_classes
    ):
        raise ValueError("privacy_setup_local_model_binding_required")
    # External LLM binding is independent of the global ceiling: package update checks may
    # raise network_egress_permitted without binding an AI-powered review provider.
    if answers.network_egress != (answers.external_provider is not None):
        raise ProviderBindingRequiredError
    if answers.credential_probe and not answers.network_egress:
        raise ValueError("privacy_setup_credential_probe_requires_provider")
    if (
        answers.external_provider is not None
        and answers.external_provider.endpoint_profile_id in _UNCONSTRAINED_ROUTER_ENDPOINTS
        and not answers.request_confirmation
    ):
        raise ValueError("privacy_setup_router_route_unconstrained")

    channels = {channel: _disabled_channel(channel) for channel in EgressChannel}
    channels[EgressChannel.UPDATE_CHECKS] = _update_checks_channel(enabled=answers.updates)
    if answers.network_egress:
        profile = (
            PrivacyProfile.CONFIRM_EVERY_REQUEST
            if answers.request_confirmation
            else (
                PrivacyProfile.TRUSTED_PROVIDER
                if answers.require_current_provider_data_use_evidence
                or answers.review_context is ReviewContextProfile.EXPANDED
                else PrivacyProfile.MINIMAL_EXTERNAL
            )
        )
        channels[EgressChannel.LLM_INFERENCE] = ChannelPolicy(
            EgressChannel.LLM_INFERENCE,
            True,
            answers.content_categories,
            answers.content_data_classes,
            answers.external_provider,
            tuple(
                purpose
                for purpose in ("credential-probe", "semantic-review")
                if purpose != "credential-probe" or answers.credential_probe
            ),
            answers.authorization_scope,
            answers.request_confirmation,
            _CASE_MAX_BYTES,
            _CASE_MAX_TOKENS,
            300,
            answers.fallback_provider,
        )
    else:
        profile = PrivacyProfile.LOCAL_ONLY

    # Ceiling is true when any network channel is on (LLM and/or update_checks).
    network_ceiling = bool(answers.network_egress or answers.updates)

    placeholder = PrivacyPolicy(
        current.policy_id,
        current.version + 1,
        "sha256:" + "0" * 64,
        profile,
        answers.review_context,
        ReviewSelectionPolicy.for_profile(answers.review_context),
        answers.require_current_provider_data_use_evidence,
        network_ceiling,
        current.effective_scope,
        _ordered_channels(channels),
        answers.local_models,
        answers.local_model_binding,
        answers.local_model_categories,
        answers.local_model_data_classes,
        answers.agent_context_categories,
        answers.agent_context_data_classes,
        current.trusted_human_control_categories,
        current.trusted_human_control_data_classes,
        now,
        current.policy_digest,
        # A recipe change keeps the owner's credential-heuristic choice (issue #982); only
        # ``finishup privacy credential-heuristic`` moves it.
        current.credential_heuristic,
    )
    identity = encode_privacy_policy_json(placeholder)
    identity.pop("policy_digest")
    return replace(placeholder, policy_digest=canonical_digest(cast(JsonValue, identity)))


_IDENTITY_EXCLUDED_KEYS: Final = frozenset(
    {"policy_digest", "version", "created_at", "supersedes_policy_digest"}
)


def _substantive_identity(policy: PrivacyPolicy) -> str:
    """Digest only the disclosure boundary, ignoring lineage and issue time.

    A candidate always carries a fresh version, ``created_at``, and supersedes link, so the
    policy digest alone can never answer "did the human actually change anything?".
    """

    encoded = encode_privacy_policy_json(policy)
    identity = {key: value for key, value in encoded.items() if key not in _IDENTITY_EXCLUDED_KEYS}
    return canonical_digest(cast(JsonValue, identity))


def _interactive_terminal() -> bool:
    try:
        return sys.stdin.isatty() and sys.stdout.isatty()
    except OSError, ValueError:
        return False


def _output_is_controlling_tty() -> bool:
    """Return the presentation fact used only for ordinary result projection."""

    try:
        fd = sys.stdout.fileno()
        return os.isatty(fd) and os.tcgetpgrp(fd) == os.getpgrp()
    except AttributeError, OSError, ValueError:
        return False


_RECIPE_SUMMARIES: Final[dict[PrivacyRecipe, str]] = {
    "private": "maximum confidentiality; no network egress or external AI-powered review",
    "metadata_only": (
        "strongest AI-powered review privacy; structural metadata only and approval every request"
    ),
    "assisted_review": (
        "better problem-specific feedback from bounded excerpts; "
        "requires eligible provider data-use evidence"
    ),
    "expanded_review": "most reviewer context and detail; allows broader in-scope excerpts",
    "custom": "maximum control; configure each privacy setting yourself",
}
_RECIPE_LABELS: Final[dict[PrivacyRecipe, str]] = {
    "private": "Private",
    "metadata_only": "Metadata only",
    "assisted_review": "Assisted review",
    "expanded_review": "Expanded review",
    "custom": "Custom",
}
# What accepting the recommendation costs, stated next to what it buys. A recommendation that
# only lists benefits is advice, not a choice.
_RECOMMENDATION_TRADEOFF: Final[
    dict[Literal["private", "metadata_only", "assisted_review"], tuple[str, str]]
] = {
    "private": (
        "No eligible exact provider route is configured, so this keeps external review off.",
        "Trade-off: no external AI-powered review at all; only local checks run.",
    ),
    "metadata_only": (
        "It enables AI-powered review while disclosing the least that still works, and asks "
        "before every provider request.",
        "Trade-off: the reviewer sees structural metadata and declared file types only, so it "
        "cannot judge whether a claim is actually supported.",
    ),
    "assisted_review": (
        "This exact provider route has current reviewed evidence of no default model training "
        "and retention no longer than 30 days. It enables bounded Assisted review for this workspace.",
        "Trade-off: selected problem-local ordinary user content may be sent; the policy review "
        "names provider human-access, safety, legal, and support caveats before approval.",
    ),
}


def recommended_privacy_recipe(
    external: ProviderBinding | None = None,
    *,
    now: datetime | None = None,
) -> Literal["private", "metadata_only", "assisted_review"]:
    """The one recommendation rule, shared by first run, ``--privacy``, and the TUI.

    Pass ``external`` to avoid re-reading configuration; omit it to load the configured
    binding. Keeping this in one function is why the CLI and the TUI cannot drift into
    recommending different postures for the same installation.
    """

    if external is None:
        external, _local = _configured_bindings()
    if external is None:
        return "private"
    current = datetime.now(UTC) if now is None else now
    return (
        "assisted_review"
        if endpoint_profile_data_use_reviewed(external.endpoint_profile_id, now=current)
        else "private"
    )


def _render_recipe_options(*, recommended: PrivacyRecipe | None = None) -> None:
    typer.echo("Privacy options:")
    for number, recipe in sorted(_RECIPE_CHOICES.items()):
        marker = " (recommended)" if recipe == recommended else ""
        label = _RECIPE_LABELS[cast(PrivacyRecipe, recipe)]
        typer.echo(
            f"  {number}. {label}{marker} — {_RECIPE_SUMMARIES[cast(PrivacyRecipe, recipe)]}"
        )
    typer.echo("Credentials, secrets, complete transcripts, and unrelated files are never sent.")
    typer.echo("You can change this any time by running 'finishup --privacy'.")


def _recipe_choice(hint: PrivacyRecipe | None) -> PrivacyRecipe:
    while True:
        raw = typer.prompt(
            "Choose a privacy option",
            default=_RECIPE_DEFAULTS.get(hint or "private", "1"),
        ).strip()
        choice = cast(PrivacyRecipe | None, _RECIPE_CHOICES.get(raw))
        if choice is not None:
            return choice
        typer.echo("Please enter 1, 2, 3, 4, or 5.")


def _recipe_prompt(hint: PrivacyRecipe | None, recommended: PrivacyRecipe | None) -> PrivacyRecipe:
    """Render the options and take one choice.

    The recommendation is passed in rather than derived here. Reading configuration from a
    rendering helper made merely *listing* the privacy options able to raise ``ConfigError`` —
    an unrecognized ``FINISHUP_*`` variable in the environment turned the option list into an
    unhandled traceback, since ``ConfigError`` is not a ``ValueError``.
    """

    _render_recipe_options(recommended=recommended)
    return _recipe_choice(hint)


def _agent_defaults(
    current: PrivacyPolicy,
) -> tuple[tuple[DataCategory, ...], tuple[DataClass, ...]]:
    """Agent-context visibility is never changed by a named recipe.

    A recipe describes what may leave the machine. What a local agent host may read back is a
    separate ceiling, so a named recipe carries the current one forward untouched rather than
    quietly widening or narrowing it.
    """

    categories = current.agent_context_categories or (
        DataCategory.BOUNDED_STRUCTURAL_METADATA,
        DataCategory.DECLARED_FILE_TYPE,
    )
    return categories, (current.agent_context_data_classes or (DataClass.PUBLIC_STRUCTURAL,))


def _recipe_answers(
    recipe: PrivacyRecipe,
    current: PrivacyPolicy,
    external: ProviderBinding | None,
    fallback: ProviderBinding | None = None,
) -> PrivacySetupAnswers:
    """Materialize one named recipe into the exact typed answers, asking nothing.

    ``fallback`` is the declared fallback destination; callers that already read the config
    pass it explicitly; recipe construction never reads configuration or the environment.
    """

    if recipe == "custom":
        raise ValueError("privacy_setup_recipe_invalid")
    network = recipe != "private"
    if network and external is None:
        raise ProviderBindingRequiredError
    context = {
        "private": ReviewContextProfile.STRUCTURAL,
        "metadata_only": ReviewContextProfile.STRUCTURAL,
        "assisted_review": ReviewContextProfile.ASSISTED,
        "expanded_review": ReviewContextProfile.EXPANDED,
    }[recipe]
    categories: tuple[DataCategory, ...] = (
        ()
        if recipe == "private"
        else (
            (DataCategory.BOUNDED_STRUCTURAL_METADATA, DataCategory.DECLARED_FILE_TYPE)
            if recipe == "metadata_only"
            else _SEMANTIC_CATEGORIES
        )
    )
    classes: tuple[DataClass, ...] = (
        (DataClass.PUBLIC_STRUCTURAL,)
        if recipe in {"private", "metadata_only"}
        else (DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT)
    )
    agent_categories, agent_classes = _agent_defaults(current)
    # assisted_review asks for current provider data-use evidence, but that requirement is
    # enforced at dispatch: against an endpoint whose data-use facts are unknown it refuses every
    # external review, so a recipe that set it unconditionally would hand most operators a setup
    # that cannot dispatch at all. Ask for it only where the bound endpoint can actually satisfy
    # it; elsewhere the review screen states the facts are unknown and the operator turns the
    # requirement on deliberately.
    # A declared fallback is a second dispatch destination under the same requirement, so it
    # must satisfy it too: otherwise every fallback dispatch would be policy-denied exactly when
    # the primary cannot serve, which is the one moment the pairing exists for (#582).
    fallback = fallback if network else None
    require_data_use = (
        recipe == "assisted_review"
        and network
        and external is not None
        and endpoint_profile_data_use_reviewed(external.endpoint_profile_id, now=datetime.now(UTC))
        and (
            fallback is None
            or endpoint_profile_data_use_reviewed(
                fallback.endpoint_profile_id, now=datetime.now(UTC)
            )
        )
    )
    return PrivacySetupAnswers(
        network_egress=network,
        local_models=False,
        external_provider=external if network else None,
        fallback_provider=fallback,
        require_current_provider_data_use_evidence=require_data_use,
        local_model_binding=None,
        review_context=context,
        content_categories=categories,
        content_data_classes=classes,
        agent_context_categories=agent_categories,
        agent_context_data_classes=agent_classes,
        local_model_categories=(),
        local_model_data_classes=(),
        request_confirmation=recipe == "metadata_only",
        telemetry=False,
        crash_diagnostics=False,
        # Product default: structural package update checks on (opt-out in custom).
        updates=True,
        capability_testing=False,
        authorization_scope={
            "private": AuthorizationScopeKind.MACHINE,
            "metadata_only": AuthorizationScopeKind.TASK,
            "assisted_review": AuthorizationScopeKind.WORKSPACE,
            "expanded_review": AuthorizationScopeKind.WORKSPACE,
        }[recipe],
    )


def recipe_answers(
    recipe: PrivacyRecipe,
    current: PrivacyPolicy,
    external: ProviderBinding | None,
) -> PrivacySetupAnswers:
    """Materialize one reviewed named recipe through the public typed helper."""

    return _recipe_answers(recipe, current, external)


def _section(number: int, title: str) -> None:
    typer.echo("")
    typer.echo(f"Section {number} of 5 — {title}")


def _review_context_prompt(default: ReviewContextProfile) -> ReviewContextProfile:
    typer.echo("Review context: structural, goal_aware, assisted, or expanded")
    while True:
        raw = typer.prompt("Review context", default=default.value).strip()
        try:
            review = ReviewContextProfile(raw)
        except ValueError:
            typer.echo("Choose structural, goal_aware, assisted, or expanded.")
            continue
        if review is ReviewContextProfile.CUSTOM:
            typer.echo("Custom selectors use desired-state TOML; choose a listed context here.")
            continue
        return review


def _authorization_scope_prompt(default: str) -> AuthorizationScopeKind:
    while True:
        raw = typer.prompt(
            "Authorization ceiling (request, task, workspace, machine)",
            default=default,
        ).strip()
        try:
            return AuthorizationScopeKind(raw)
        except ValueError:
            typer.echo("Choose request, task, workspace, or machine.")


def _categories_prompt(label: str, default: tuple[DataCategory, ...]) -> tuple[DataCategory, ...]:
    raw = typer.prompt(
        f"{label} (comma separated)",
        default=",".join(item.value for item in default),
    ).strip()
    if not raw:
        return ()
    try:
        values = tuple(DataCategory(part.strip()) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise ValueError("privacy_setup_category_invalid") from exc
    if len(set(values)) != len(values):
        raise ValueError("privacy_setup_category_invalid")
    return values


def _data_classes_prompt(label: str, default: tuple[DataClass, ...]) -> tuple[DataClass, ...]:
    allowed = {
        DataClass.PUBLIC_STRUCTURAL,
        DataClass.ORDINARY_USER_CONTENT,
        DataClass.SENSITIVE_CONFIDENTIAL,
    }
    raw = typer.prompt(
        f"{label} data classes (comma separated)",
        default=",".join(item.value for item in default),
    ).strip()
    if not raw:
        return ()
    try:
        values = tuple(DataClass(part.strip()) for part in raw.split(",") if part.strip())
    except ValueError as exc:
        raise ValueError("privacy_setup_data_class_invalid") from exc
    if len(set(values)) != len(values) or not set(values) <= allowed:
        raise ValueError("privacy_setup_data_class_invalid")
    return values


def _configured_bindings() -> tuple[ProviderBinding | None, ProviderBinding | None]:
    from finishup.config.load import load_config
    from finishup.config.models import primary_external_endpoint

    config = load_config({}, os.environ, None)
    external_config = primary_external_endpoint(config)
    external = (
        None
        if external_config is None
        else ProviderBinding(
            external_config.provider_id,
            external_config.model,
            external_config.endpoint_profile_id,
            external_config.endpoint_profile_version,
            "external",
        )
    )
    local = (
        None
        if config.local_model is None
        else ProviderBinding(
            config.local_model.profile_id,
            config.local_model.model,
            config.local_model.endpoint_profile_id,
            config.local_model.endpoint_profile_version,
            "local_af_unix",
        )
    )
    return external, local


def configured_bindings() -> tuple[ProviderBinding | None, ProviderBinding | None]:
    """Return configured external and local provider bindings."""

    return _configured_bindings()


def _configured_fallback_binding() -> ProviderBinding | None:
    from finishup.config.load import load_config
    from finishup.config.models import fallback_external_endpoint

    fallback_config = fallback_external_endpoint(load_config({}, os.environ, None))
    if fallback_config is None:
        return None
    return ProviderBinding(
        fallback_config.provider_id,
        fallback_config.model,
        fallback_config.endpoint_profile_id,
        fallback_config.endpoint_profile_version,
        "external",
    )


def configured_fallback_binding() -> ProviderBinding | None:
    """Return the declared fallback external binding, or ``None`` without a pairing (#582)."""

    return _configured_fallback_binding()


def _ask_custom_answers(
    current: PrivacyPolicy,
    external: ProviderBinding | None,
    local: ProviderBinding | None,
    fallback: ProviderBinding | None = None,
) -> PrivacySetupAnswers:
    """The only field-level path, grouped into five sections a person can hold in mind.

    Every section is announced even when its questions do not apply, so the shape of what is
    being decided stays visible and a skipped section reads as "off", never as "hidden".
    """

    _section(1, "External and local destinations")
    network = typer.confirm("Permit network egress at all?", default=False)
    use_provider = False
    require_evidence = False
    use_fallback = False
    if network:
        provider_label = (
            "none configured" if external is None else f"{external.provider_id}/{external.model_id}"
        )
        use_provider = typer.confirm(
            f"Bind external AI-powered review to {provider_label}?", default=external is not None
        )
        if use_provider and fallback is not None:
            use_fallback = typer.confirm(
                f"Authorize fallback AI-powered review to {fallback.provider_id}/{fallback.model_id}?",
                default=False,
            )
        if use_provider:
            require_evidence = typer.confirm(
                "Require a current eligible provider data-use record?", default=True
            )
    else:
        typer.echo("Network egress stays off, so no external destination is configurable.")
    local_models = typer.confirm(
        "Permit configured local-model processing?",
        default=local is not None and current.local_model_enabled,
    )

    _section(2, "What an external reviewer may see")
    review = ReviewContextProfile.STRUCTURAL
    content: tuple[DataCategory, ...] = ()
    content_classes: tuple[DataClass, ...] = (DataClass.PUBLIC_STRUCTURAL,)
    if use_provider:
        review = _review_context_prompt(ReviewContextProfile.ASSISTED)
        content = _categories_prompt("External content categories", _SEMANTIC_CATEGORIES)
        content_classes = _data_classes_prompt(
            "External content", (DataClass.PUBLIC_STRUCTURAL, DataClass.ORDINARY_USER_CONTENT)
        )
    else:
        typer.echo("No external destination is bound, so nothing is sent for review.")

    _section(3, "Local visibility: agent host and local model")
    agent = _categories_prompt(
        "Local agent-context categories", current.agent_context_categories or _AGENT_CATEGORIES
    )
    agent_classes = _data_classes_prompt("Local agent context", current.agent_context_data_classes)
    local_categories: tuple[DataCategory, ...] = ()
    local_classes: tuple[DataClass, ...] = ()
    if local_models:
        local_categories = _categories_prompt(
            "Local-model categories", current.local_model_categories
        )
        local_classes = _data_classes_prompt("Local model", current.local_model_data_classes)
    else:
        typer.echo("Local-model processing is off, so it receives nothing.")

    _section(4, "Per-request confirmation and authorization scope")
    confirmation = typer.confirm(
        "Require confirmation before every provider request?", default=True
    )
    scope = _authorization_scope_prompt("task" if use_provider else "machine")

    _section(5, "Package updates and unsupported channels")
    updates = typer.confirm(
        "Check PyPI for FinishUP updates (package name and version only)?",
        default=True,
    )
    typer.echo(
        "Product telemetry, crash diagnostics, and external capability testing ship no "
        "transport in this release. They are off and cannot be turned on here."
    )

    if network and not use_provider:
        raise ProviderBindingRequiredError
    if local_models and local is None:
        raise ValueError("privacy_setup_local_model_binding_required")
    return PrivacySetupAnswers(
        network,
        local_models,
        external if use_provider else None,
        require_evidence,
        local if local_models else None,
        review,
        content,
        content_classes,
        agent,
        agent_classes,
        local_categories,
        local_classes,
        confirmation,
        False,
        False,
        updates,
        False,
        scope,
        fallback_provider=fallback if use_fallback else None,
    )


def _render_data_use_warning(candidate: PrivacyPolicy, llm: ChannelPolicy) -> None:
    """Render the exact route evidence and whether the runtime assurance guard is active."""

    binding = llm.provider_binding
    if binding is None:
        return
    record = data_use_record_for_endpoint(binding.endpoint_profile_id)
    profile = record.profile
    eligible = endpoint_profile_data_use_reviewed(
        binding.endpoint_profile_id, now=datetime.now(UTC)
    )
    retention = profile.retention
    if profile.retention_days_ceiling is not None:
        retention += f" (at most {profile.retention_days_ceiling} days)"
    typer.echo("")
    typer.echo("  Provider data-use evidence:")
    typer.echo(f"    Route qualification: {record.route_qualifier}")
    typer.echo(f"    Customer-content training: {profile.customer_content_training}")
    typer.echo(f"    Retention: {retention}")
    typer.echo(f"    Provider human access: {profile.provider_human_access}")
    typer.echo(f"    Reviewed: {profile.reviewed_at.date()} through {profile.expires_at.date()}")
    typer.echo(f"    Assisted recommendation eligible now: {'yes' if eligible else 'no'}")
    if record.official_source_urls:
        typer.echo("    Official sources: " + ", ".join(record.official_source_urls))
    for caveat in record.caveats:
        typer.echo(f"    Caveat: {caveat}")
    if candidate.require_current_provider_data_use_evidence and not eligible:
        typer.echo(
            "  Warning: the runtime evidence guard is ON, so external review will be refused "
            "while this exact route remains ineligible."
        )
    elif not candidate.require_current_provider_data_use_evidence and not eligible:
        typer.echo(
            "  Warning: the runtime evidence guard is OFF. Approving this draft is an informed "
            "standing authorization despite unknown, stale, or route-unqualified provider facts."
        )


def _permits_external_review(policy: PrivacyPolicy) -> bool:
    """True when this policy would let a check dispatch to an external provider."""

    return policy.network_egress_permitted and any(
        channel.channel is EgressChannel.LLM_INFERENCE
        and channel.enabled
        and channel.provider_binding is not None
        for channel in policy.channel_policies
    )


def _reconcile_host_admission(policy: PrivacyPolicy, workspace_locator: Path) -> None:
    """Keep each host's admission entry for ``check`` consistent with the committed grant.

    Host admission (issue #467) is derived from the repository grant, so the trusted ceremony
    that changes the grant is the place where the reverse transition happens: a policy that no
    longer permits external review removes exactly the entries FinishUP wrote, and a policy that
    does permit it names the hosts that will still hold every AI-powered check. Advisory output
    only; a failed sweep is reported, never hidden, and never fails the ceremony.
    """

    from finishup.adapters.integrations.host_admission import (
        ADMISSION_HOSTS,
        HostAdmissionError,
        observe_host_admission,
        sweep_host_admission,
    )

    try:
        if _permits_external_review(policy):
            missing = [
                host
                for host in ADMISSION_HOSTS
                if observe_host_admission(host, workspace_locator).state.value == "absent"
            ]
            if missing:
                typer.echo("")
                typer.echo(
                    "  Note: no host auto-review admission for this repository on "
                    + ", ".join(missing)
                    + ". An automatic reviewer there will still hold every AI-powered check."
                )
                typer.echo(
                    "  Run 'finishup integrate <host> admission preview --project-root .' to let "
                    "that host admit the owner-authorized check."
                )
            return
        outcomes = sweep_host_admission(workspace_locator)
        removed = [item.host for item in outcomes if item.outcome == "removed"]
        failed = [item.host for item in outcomes if item.outcome in {"write_failed", "unknown"}]
        if removed:
            typer.echo("")
            typer.echo(
                "  Host auto-review admission removed for this repository: " + ", ".join(removed)
            )
        if failed:
            typer.echo("")
            typer.echo(
                "  Could not remove host auto-review admission on "
                + ", ".join(failed)
                + "; run 'finishup integrate <host> admission preview --action revoke "
                "--project-root .' and review the host file."
            )
    except HostAdmissionError, OSError:
        return


async def _warn_if_agent_route_cannot_dispatch(policy: PrivacyPolicy) -> None:
    """Say so when the committed policy allows external review the agent route cannot reach.

    Policy and registration are separate facts, and only the wizard that changes the first ever
    looks at the second. Someone who moves from local-only to assisted review here, with a
    strict registration still in place from an earlier setup, gets a correct policy and a Codex
    session where every check returns ``blocked_by_policy`` / ``route_semantic_ceiling`` --
    honest, silent, and indistinguishable from having chosen local only.

    Advisory only: never fails the ceremony, never changes an exit code, and says nothing at all
    when the route cannot be read.
    """

    if not _permits_external_review(policy):
        return
    from finishup.cli.provider_status import mcp_route_observation

    try:
        route = await mcp_route_observation()
    except Exception:
        return
    if route.get("registered_profile") != "strict":
        return
    typer.echo("")
    typer.echo(
        "  Note: the registered Codex MCP route is 'strict', which ceilings AI-powered review "
        "for that process regardless of this policy."
    )
    typer.echo(
        "  Run 'finishup integrate codex mcp preview' and accept the re-registration to let the "
        "agent route dispatch the review this policy allows."
    )


def _byte_size_text(value: int) -> str:
    """KiB when exact, otherwise the exact byte count, so a limit never reads as rounded down."""

    return f"{value // 1024} KiB" if value % 1024 == 0 else f"{value:,} bytes"


def _excerpt_limits_text(selection: ReviewSelectionPolicy) -> str:
    if selection.max_excerpts == 0:
        return "no excerpts are sent"
    return (
        f"{selection.max_excerpts} excerpts, {_byte_size_text(selection.max_excerpt_bytes)} "
        f"each, {_byte_size_text(selection.max_total_excerpt_bytes)} in total"
    )


def policy_excerpt_limits_disclosure(policy: PrivacyPolicy) -> str:
    """The approved excerpt limits, beside what the current recipe would offer (issue #907).

    A policy approved under an earlier recipe keeps its limits; the newer ones apply only after
    the owner approves them, and approving nothing keeps the current limits.
    """

    current = policy.review_selection
    profile = policy.review_context_profile
    if profile in {ReviewContextProfile.CUSTOM, ReviewContextProfile.STRUCTURAL}:
        return _excerpt_limits_text(current)
    offered = ReviewSelectionPolicy.for_profile(profile)
    limits = ("max_excerpts", "max_excerpt_bytes", "max_total_excerpt_bytes")
    if all(getattr(current, name) == getattr(offered, name) for name in limits):
        return f"{_excerpt_limits_text(current)} (the current {profile.value} recipe)"
    return (
        f"current {_excerpt_limits_text(current)}; proposed by the current {profile.value} "
        f"recipe: {_excerpt_limits_text(offered)}. Nothing changes until you approve it with "
        "'finishup --privacy'; approving nothing keeps the current limits"
    )


def policy_task_statement_disclosure(policy: PrivacyPolicy) -> str:
    """Whether ``policy`` sends the agent's transcription of the user's request (issue #908)."""

    llm = next(
        channel
        for channel in policy.channel_policies
        if channel.channel is EgressChannel.LLM_INFERENCE
    )
    profile = policy.review_context_profile
    return task_statement_disclosure_text(
        section_selected="task_statement" in policy.review_selection.sections,
        channel_sends_task_description=(
            llm.enabled and DataCategory.TASK_DESCRIPTION in llm.allowed_categories
        ),
        predates_section=(
            profile not in {ReviewContextProfile.CUSTOM, ReviewContextProfile.STRUCTURAL}
            and policy.review_selection
            == ReviewSelectionPolicy.for_profile(profile, preset_version="1.1.0")
        ),
    )


def _render_review(candidate: PrivacyPolicy) -> None:
    llm = next(
        policy
        for policy in candidate.channel_policies
        if policy.channel is EgressChannel.LLM_INFERENCE
    )
    typer.echo("")
    typer.echo("Exact privacy draft:")
    typer.echo(f"  Profile: {candidate.profile.value}")
    typer.echo(f"  Network egress: {'allowed' if candidate.network_egress_permitted else 'off'}")
    typer.echo(f"  LLM inference: {'enabled' if llm.enabled else 'off'}")
    if llm.provider_binding is not None:
        typer.echo(
            "  Destination: "
            f"{llm.provider_binding.provider_id}/{llm.provider_binding.model_id} "
            f"via {llm.provider_binding.endpoint_profile_id}@"
            f"{llm.provider_binding.endpoint_profile_version}"
        )
    if llm.fallback_provider_binding is not None:
        fallback = llm.fallback_provider_binding
        typer.echo(
            "  Fallback destination (after the primary cannot serve): "
            f"{fallback.provider_id}/{fallback.model_id} "
            f"via {fallback.endpoint_profile_id}@{fallback.endpoint_profile_version}"
        )
    typer.echo(
        "  Allowed categories: "
        + (", ".join(item.value for item in llm.allowed_categories) or "none")
    )
    typer.echo(
        "  Allowed data classes: "
        + (", ".join(item.value for item in llm.allowed_data_classes) or "none")
    )
    typer.echo("  Task statement: " + policy_task_statement_disclosure(candidate))
    typer.echo("  Allowed purposes: " + (", ".join(llm.allowed_purposes) or "none"))
    typer.echo(f"  Authorization ceiling: {llm.scope_ceiling.value}")
    typer.echo(f"  Per-request confirmation: {'yes' if llm.preview_required else 'no'}")
    typer.echo(
        "  Current provider data-use evidence required: "
        + ("yes" if candidate.require_current_provider_data_use_evidence else "no")
    )
    _render_data_use_warning(candidate, llm)
    # Read the ceilings off the draft rather than restating constants: these are enforced at
    # admission, so a case above either one is refused, and the operator is entitled to see the
    # numbers that will actually refuse it.
    typer.echo(
        f"  Maximum: {_excerpt_limits_text(candidate.review_selection)}; "
        f"{llm.max_bytes // 1024} KiB / {llm.max_tokens} tokens per case"
    )
    typer.echo(
        "  Never sent: credentials, encryption material, environment variables, "
        "complete transcripts, unrelated or out-of-scope files"
    )
    updates_row = next(
        policy
        for policy in candidate.channel_policies
        if policy.channel is EgressChannel.UPDATE_CHECKS
    )
    typer.echo(
        "  Package update checks: "
        + ("on (structural PyPI version only)" if updates_row.enabled else "off")
    )
    typer.echo("  Telemetry, crash diagnostics, capability testing: off")


def _setup_snapshot_from_wire(raw: object) -> PrivacySetupSnapshot:
    try:
        plain = dict(cast(Mapping[str, JsonValue], raw))
        if plain.get("schema_version") != "2.0.0":
            raise ValueError("privacy_setup_snapshot_invalid")
        policy = plain["composed_policy"]
        scope = plain["bound_scope"]
        authority_digest = plain["authority_digest"]
        grant_state = plain["grant_state"]
        migration_state = plain["migration_state"]
        if not isinstance(policy, Mapping) or not isinstance(scope, Mapping):
            raise ValueError("privacy_setup_snapshot_invalid")
        if type(authority_digest) is not str or type(grant_state) is not str:
            raise ValueError("privacy_setup_snapshot_invalid")
        if type(migration_state) is not str:
            raise ValueError("privacy_setup_snapshot_invalid")
        frozen_scope = JsonObject(cast(Mapping[str, JsonValue], scope))
        decoded = decode_privacy_policy_canonical(canonical_encode(cast(JsonValue, policy)))
        return PrivacySetupSnapshot(
            decoded,
            frozen_scope,
            authority_digest,
            cast(Literal["granted", "missing"], grant_state),
            cast(
                Literal[
                    "not_applicable",
                    "legacy_route_available",
                    "first_repository_available",
                    "consumed",
                ],
                migration_state,
            ),
        )
    except KeyError, TypeError, ValueError:
        raise ValueError("privacy_setup_snapshot_invalid") from None


async def get_privacy_setup_snapshot(
    workspace_locator: Path | None = None,
) -> PrivacySetupSnapshot:
    from finishup.cli.app import build_service_client
    from finishup.ports.control import ProjectionRenderMode, WorkspaceLocator

    locator = Path.cwd() if workspace_locator is None else workspace_locator
    client = await build_service_client(
        workspace_locator=WorkspaceLocator(str(locator.resolve(strict=True))),
        projection_render_mode=ProjectionRenderMode.HUMAN_READABLE,
        output_is_controlling_tty=_output_is_controlling_tty(),
    )
    try:
        raw = await client.privacy_get_setup(JsonObject({"schema_version": "2.0.0"}))
    finally:
        await client.close()
    return _setup_snapshot_from_wire(raw)


async def _propose(
    candidate: PrivacyPolicy,
    authority_digest: str,
    *,
    workspace_locator: Path | None = None,
) -> str | None:
    from finishup.adapters.privacy.catalog import encode_privacy_policy_json
    from finishup.cli.app import build_service_client
    from finishup.ports.control import ProjectionRenderMode, WorkspaceLocator

    locator = Path.cwd() if workspace_locator is None else workspace_locator
    client = await build_service_client(
        workspace_locator=WorkspaceLocator(str(locator.resolve(strict=True))),
        projection_render_mode=ProjectionRenderMode.HUMAN_READABLE,
        output_is_controlling_tty=_output_is_controlling_tty(),
    )
    try:
        result = await client.privacy_propose_policy(
            JsonObject(
                {
                    "schema_version": "2.0.0",
                    "authority_digest": authority_digest,
                    "candidate_policy": encode_privacy_policy_json(candidate),
                }
            )
        )
    finally:
        await client.close()
    if result.get("schema_version") != "2.0.0":
        raise ValueError("privacy_setup_proposal_invalid")
    proposal_id = result.get("proposal_id")
    if result.get("outcome") == "decision_required" and type(proposal_id) is str:
        return proposal_id
    if result.get("outcome") == "tightening_applied":
        return None
    raise ValueError("privacy_setup_proposal_invalid")


async def propose_privacy_candidate(
    candidate: PrivacyPolicy,
    authority_digest: str,
    *,
    workspace_locator: Path | None = None,
) -> str | None:
    """Propose one exact privacy candidate through the public setup helper."""

    return await _propose(
        candidate,
        authority_digest,
        workspace_locator=workspace_locator,
    )


async def _decide(proposal_id: str) -> object:
    from finishup.adapters.keys.os_keyring import AutoUnlockPassphraseStore
    from finishup.cli.privacy_control import (
        decide_policy,
        decide_policy_with_local_reauthentication,
    )
    from finishup.config.load import load_config
    from finishup.config.paths import bundle_root

    config = load_config({}, os.environ, None)
    passphrase = AutoUnlockPassphraseStore(bundle_root(_data_dir=config.storage.data_dir)).load()
    if passphrase is None:
        return await decide_policy(proposal_id)
    return await decide_policy_with_local_reauthentication(proposal_id, passphrase)


def _confirmed_candidate(
    current: PrivacyPolicy,
    answers: PrivacySetupAnswers,
    prompt: str,
    *,
    default: bool,
) -> PrivacyPolicy | None:
    """Render the exact resulting boundary and take one explicit confirmation."""

    candidate = build_candidate_policy(current, answers, now=datetime.now(UTC))
    _render_review(candidate)
    return candidate if typer.confirm(prompt, default=default) else None


def _render_repository_authority(snapshot: PrivacySetupSnapshot) -> None:
    """Describe repository authority without rendering its commitment or local path."""

    typer.echo(
        "Current task statement disclosure: "
        + policy_task_statement_disclosure(snapshot.composed_policy)
    )
    typer.echo(
        "Current excerpt limits: " + policy_excerpt_limits_disclosure(snapshot.composed_policy)
    )
    typer.echo("Repository privacy authority:")
    if snapshot.grant_state == "missing":
        typer.echo("  External model review is off for this repository until you approve a grant.")
    else:
        typer.echo("  The current external-review permission applies to this repository.")
    if snapshot.migration_state == "legacy_route_available":
        typer.echo(
            "  A previously accepted machine policy can be narrowed to this known repository "
            "without reapproval or broader disclosure."
        )
    elif snapshot.migration_state == "first_repository_available":
        typer.echo(
            "  A previously accepted machine policy can be carried forward once to this first "
            "repository without reapproval or broader disclosure."
        )
    elif snapshot.migration_state == "consumed" and snapshot.grant_state == "granted":
        typer.echo(
            "  Existing permission was carried forward and narrowed to this repository; no new "
            "disclosure was approved."
        )
    typer.echo("")


def _choose_candidate(
    current: PrivacyPolicy,
    external: ProviderBinding | None,
    local: ProviderBinding | None,
    *,
    recipe_hint: PrivacyRecipe | None,
    offer_recommended: bool,
    credential_probe_authorized: bool,
    update_checks_override: bool | None,
    fallback: ProviderBinding | None = None,
) -> PrivacyPolicy | None:
    """Select the exact candidate policy, or ``None`` when the user declined outright.

    Three entry shapes, one exit: the recommendation, a named recipe, or the custom sections.
    Accepting the recommendation is a complete answer and asks nothing further; only ``custom``
    ever reaches field-level configuration.
    """

    if offer_recommended:
        recommended = recommended_privacy_recipe(external)
        _render_recipe_options(recommended=recommended)
        typer.echo("")
        typer.echo(f"Recommended policy: {_RECIPE_LABELS[recommended]}")
        why, tradeoff = _RECOMMENDATION_TRADEOFF[recommended]
        typer.echo(f"Why: {why}")
        typer.echo(tradeoff)
        answers = replace(
            _recipe_answers(recommended, current, external, fallback),
            credential_probe=credential_probe_authorized,
        )
        if update_checks_override is not None:
            answers = replace(answers, updates=update_checks_override)
        candidate = _confirmed_candidate(
            current,
            answers,
            "Use this recommended privacy policy?",
            default=True,
        )
        if candidate is not None:
            return candidate
        typer.echo("")
        typer.echo("Other privacy options:")
        recipe = _recipe_choice(recommended)
    elif recipe_hint is not None:
        recipe = recipe_hint
    else:
        recipe = _recipe_prompt(recipe_hint, recommended_privacy_recipe(external))
    if recipe == "custom":
        return _confirmed_candidate(
            current,
            replace(
                _ask_custom_answers(current, external, local, fallback),
                credential_probe=credential_probe_authorized,
            ),
            "Use this exact custom privacy policy?",
            default=False,
        )
    answers = replace(
        _recipe_answers(recipe, current, external, fallback),
        credential_probe=credential_probe_authorized,
    )
    if update_checks_override is not None:
        answers = replace(answers, updates=update_checks_override)
    return _confirmed_candidate(
        current,
        answers,
        f"Create this exact privacy proposal ({_RECIPE_LABELS[recipe]})?",
        default=False,
    )


async def run_privacy_setup(
    *,
    recipe_hint: PrivacyRecipe | None = None,
    offer_recommended: bool = False,
    credential_probe_authorized: bool = False,
    update_checks_override: bool | None = None,
    workspace_locator: Path | None = None,
    credential_heuristic: CredentialHeuristic | None = None,
) -> PrivacySetupReport:
    """Run the trusted questionnaire and apply only an explicitly approved draft.

    ``credential_heuristic`` makes the drafted grant carry that possible-credential filter
    setting (issue #982): ``finishup privacy credential-heuristic disable`` in a repository without a
    grant walks this same grant-creation ceremony instead of creating a grant on its own.

    ``update_checks_override`` carries a setup answer into a recommended or named recipe before
    its exact review. ``None`` preserves the recipe default. Custom still owns its section-5
    question. The override never skips candidate confirmation or the service decision ceremony.
    """

    if update_checks_override is not None and type(update_checks_override) is not bool:
        raise TypeError("privacy_setup_update_checks_override_invalid")

    if not _interactive_terminal():
        return PrivacySetupReport(
            "failed",
            "unknown",
            reason="local_terminal_required",
        )
    locator = Path.cwd() if workspace_locator is None else workspace_locator
    snapshot = await get_privacy_setup_snapshot(locator)
    current = snapshot.composed_policy
    _render_repository_authority(snapshot)
    external, local = _configured_bindings()
    try:
        candidate = _choose_candidate(
            current
            if credential_heuristic is None
            else replace(current, credential_heuristic=credential_heuristic),
            external,
            local,
            recipe_hint=recipe_hint,
            offer_recommended=offer_recommended,
            credential_probe_authorized=credential_probe_authorized,
            update_checks_override=update_checks_override,
            fallback=_configured_fallback_binding(),
        )
    except ValueError as error:
        return PrivacySetupReport(
            "failed",
            current.profile.value,
            reason=str(error),
            grant_state=snapshot.grant_state,
            migration_state=snapshot.migration_state,
        )
    if candidate is None:
        return PrivacySetupReport(
            "cancelled",
            current.profile.value,
            grant_state=snapshot.grant_state,
            migration_state=snapshot.migration_state,
        )
    if snapshot.grant_state == "granted" and _substantive_identity(
        candidate
    ) == _substantive_identity(current):
        return PrivacySetupReport(
            "unchanged",
            current.profile.value,
            grant_state=snapshot.grant_state,
            migration_state=snapshot.migration_state,
        )
    proposal_id = await _propose(
        candidate,
        snapshot.authority_digest,
        workspace_locator=locator,
    )
    if proposal_id is None:
        await _warn_if_agent_route_cannot_dispatch(candidate)
        _reconcile_host_admission(candidate, locator)
        return PrivacySetupReport(
            "configured",
            candidate.profile.value,
            grant_state="granted",
            migration_state=snapshot.migration_state,
        )
    typer.echo("")
    typer.echo("Final widening decision (trusted local ceremony)")
    decision = await _decide(proposal_id)
    status = getattr(decision, "status", None)
    if status == "committed":
        await _warn_if_agent_route_cannot_dispatch(candidate)
        _reconcile_host_admission(candidate, locator)
        return PrivacySetupReport(
            "configured",
            candidate.profile.value,
            proposal_id,
            grant_state="granted",
            migration_state=snapshot.migration_state,
        )
    return PrivacySetupReport(
        "cancelled",
        current.profile.value,
        proposal_id,
        "privacy_decision_not_approved" if status != "stale" else "privacy_proposal_stale",
        snapshot.grant_state,
        snapshot.migration_state,
    )


def credential_heuristic_candidate(
    current: PrivacyPolicy, setting: CredentialHeuristic, *, now: datetime
) -> PrivacyPolicy:
    """The exact successor of ``current`` that changes only the credential-heuristic setting.

    Every other disclosure dimension is copied unchanged, so the trusted ceremony renders this
    one line and nothing else (issue #982).
    """

    if type(current) is not PrivacyPolicy or type(setting) is not CredentialHeuristic:
        raise TypeError("privacy_credential_heuristic_candidate_invalid")
    now = now.replace(microsecond=(now.microsecond // 1000) * 1000)
    placeholder = replace(
        current,
        version=current.version + 1,
        policy_digest="sha256:" + "0" * 64,
        created_at=now,
        supersedes_policy_digest=current.policy_digest,
        credential_heuristic=setting,
    )
    identity = encode_privacy_policy_json(placeholder)
    identity.pop("policy_digest")
    return replace(placeholder, policy_digest=canonical_digest(cast(JsonValue, identity)))


async def _machine_effective_policy() -> PrivacyPolicy:
    from finishup.cli.app import build_service_client
    from finishup.cli.provider_status import machine_scope_request

    client = await build_service_client()
    try:
        raw = await client.privacy_get_effective(machine_scope_request())
    finally:
        await client.close()
    plain = cast(Mapping[str, JsonValue], raw)
    return decode_privacy_policy_canonical(canonical_encode(plain["policy"]))


async def _tighten_machine(candidate: PrivacyPolicy, expected_policy_digest: str) -> None:
    from finishup.cli.app import build_service_client

    client = await build_service_client()
    try:
        result = await client.privacy_tighten_policy(
            JsonObject(
                {
                    "expected_policy_digest": expected_policy_digest,
                    "candidate_policy": encode_privacy_policy_json(candidate),
                }
            )
        )
    finally:
        await client.close()
    if result.get("outcome") != "tightening_applied":
        raise ValueError("privacy_tightening_not_applied")


async def _propose_machine(candidate: PrivacyPolicy, expected_policy_digest: str) -> str | None:
    from finishup.cli.app import build_service_client

    client = await build_service_client()
    try:
        result = await client.privacy_propose_policy(
            JsonObject(
                {
                    "schema_version": "1.0.0",
                    "expected_policy_digest": expected_policy_digest,
                    "candidate_policy": encode_privacy_policy_json(candidate),
                }
            )
        )
    finally:
        await client.close()
    proposal_id = result.get("proposal_id")
    if result.get("outcome") == "decision_required" and type(proposal_id) is str:
        return proposal_id
    if result.get("outcome") == "tightening_applied":
        return None
    raise ValueError("privacy_setup_proposal_invalid")


async def _decided_report(
    proposal_id: str,
    candidate: PrivacyPolicy,
    current: PrivacyPolicy,
    snapshot: PrivacySetupSnapshot | None,
) -> PrivacySetupReport:
    typer.echo("")
    typer.echo("Final widening decision (trusted local ceremony)")
    decision = await _decide(proposal_id)
    status = getattr(decision, "status", None)
    grant = None if snapshot is None else snapshot.grant_state
    migration = None if snapshot is None else snapshot.migration_state
    if status == "committed":
        return PrivacySetupReport(
            "configured", candidate.profile.value, proposal_id, None, "granted", migration
        )
    return PrivacySetupReport(
        "cancelled",
        current.profile.value,
        proposal_id,
        "privacy_decision_not_approved" if status != "stale" else "privacy_proposal_stale",
        grant,
        migration,
    )


_DISABLE_NOTICE: Final = (
    "Turning off the possible-credential filter lets values that only look like passwords or "
    "tokens (for example `password = ...` or `api_token = ...`) be sent to the external AI "
    "reviewer as written. Local outputs keep the filter, and known credential shapes, private "
    "keys and URL passwords are always withheld."
)


async def run_credential_heuristic_change(
    setting: CredentialHeuristic,
    *,
    machine_default: bool = False,
    workspace_locator: Path | None = None,
) -> PrivacySetupReport:
    """Turn the possible-credential filter off or back on (issue #982 owner opt-out).

    The setting belongs to the current repository's grant (owner decision, 2026-10-07): a
    repository is "off" only where its own grant says off. Turning it **off** widens what the
    external reviewer may see, so it is proposed for this repository and applies only after the
    separately reauthenticated trusted-terminal decision; without a grant it walks the ordinary
    grant-creation ceremony with the filter off, and never creates a grant silently. Turning it
    back **on** narrows the grant and applies at once. ``machine_default`` changes the
    installation-wide default that a repository without a grant inherits instead; turning that
    off is likewise a widening that needs the trusted decision.
    """

    if type(setting) is not CredentialHeuristic:
        raise TypeError("privacy_credential_heuristic_invalid")
    disabling = setting is CredentialHeuristic.DISABLED
    if disabling and not _interactive_terminal():
        return PrivacySetupReport("failed", "unknown", reason="local_terminal_required")
    if machine_default:
        machine = await _machine_effective_policy()
        if machine.credential_heuristic is setting:
            return PrivacySetupReport("unchanged", machine.profile.value)
        candidate = credential_heuristic_candidate(machine, setting, now=datetime.now(UTC))
        if not disabling:
            await _tighten_machine(candidate, machine.policy_digest)
            return PrivacySetupReport("configured", candidate.profile.value)
        typer.echo(_DISABLE_NOTICE)
        typer.echo("This changes the installation-wide default for repositories without a grant.")
        proposal_id = await _propose_machine(candidate, machine.policy_digest)
        if proposal_id is None:
            return PrivacySetupReport("configured", candidate.profile.value)
        return await _decided_report(proposal_id, candidate, machine, None)
    locator = Path.cwd() if workspace_locator is None else workspace_locator
    snapshot = await get_privacy_setup_snapshot(locator)
    current = snapshot.composed_policy
    if snapshot.grant_state != "granted":
        if not disabling:
            # Nothing is granted, so nothing can leave for this repository; a later grant is
            # drafted from the installation-wide default.
            return PrivacySetupReport(
                "unchanged",
                current.profile.value,
                reason="repository_privacy_grant_missing",
                grant_state=snapshot.grant_state,
                migration_state=snapshot.migration_state,
            )
        typer.echo(_DISABLE_NOTICE)
        typer.echo(
            "This repository has no privacy grant yet; the filter setting becomes part of the "
            "grant you review and approve now."
        )
        return await run_privacy_setup(
            recipe_hint="assisted_review",
            offer_recommended=True,
            workspace_locator=locator,
            credential_heuristic=setting,
        )
    if current.credential_heuristic is setting:
        return PrivacySetupReport(
            "unchanged",
            current.profile.value,
            grant_state=snapshot.grant_state,
            migration_state=snapshot.migration_state,
        )
    candidate = credential_heuristic_candidate(current, setting, now=datetime.now(UTC))
    if disabling:
        typer.echo(_DISABLE_NOTICE)
    proposal_id = await _propose(candidate, snapshot.authority_digest, workspace_locator=locator)
    if proposal_id is None:
        return PrivacySetupReport(
            "configured",
            candidate.profile.value,
            grant_state=snapshot.grant_state,
            migration_state=snapshot.migration_state,
        )
    return await _decided_report(proposal_id, candidate, current, snapshot)
