"""Provider-free privacy setup, transition, and receipt-inspection use cases."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, fields, is_dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Final, Literal, cast

from finishup.domain.privacy import (
    AuthorizationScope,
    AuthorizationScopeKind,
    ChannelPolicy,
    ConversationReview,
    CredentialHeuristic,
    EgressChannel,
    PolicyOverlay,
    PrivacyPolicy,
    PrivacyPolicyChange,
    PrivacyPolicyChangeValue,
    PrivacyProfile,
    ProviderBinding,
    ProviderDataUseProfile,
    ReviewContextProfile,
    ReviewSelectionPolicy,
    conversation_review_widens,
    narrower_conversation_review,
    policy_field_omitted,
    sort_privacy_changes,
    validate_privacy_change_set,
)
from finishup.domain.values import validate_sha256_digest
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    HumanPolicyDecision,
    OutboundGatewayPort,
    PendingDisclosurePage,
    PolicyCommitResult,
    PolicyTransitionMember,
    PolicyTransitionProposal,
    PreparedPolicyTransition,
    PrivacyAuditPort,
    PrivacyPolicyStorePort,
    PrivacyReceiptAudience,
    PrivacyReceiptPage,
    PrivacyReceiptQuery,
    PrivacyReceiptView,
    ProviderReconciliation,
    RepositoryPrivacyAuthority,
)
from finishup.protocol.canonical import JsonValue, canonical_digest
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "AllowedBlockedExample",
    "CredentialHeuristicState",
    "credential_heuristic_state",
    "ChannelSetupChoice",
    "DecidePrivacyPolicyRequest",
    "GetPrivacyEffectiveRequest",
    "GetPrivacyReceiptRequest",
    "GetPrivacySetupRequest",
    "ListPrivacyReceiptsRequest",
    "PolicyDecisionRequired",
    "PolicyProposalResult",
    "PrivacyPolicyApplication",
    "PrivacyPolicyResult",
    "PrivacySetupView",
    "ProposePrivacyPolicyRequest",
    "ProviderDataUseSummary",
    "ReviewRecipeView",
    "TightenPrivacyPolicyRequest",
    "decide_privacy_policy",
    "is_privacy_tightening",
    "privacy_policy_changes",
    "privacy_get_effective",
    "privacy_get_setup",
    "privacy_propose_policy",
    "privacy_receipts_get",
    "privacy_pending_list",
    "privacy_receipts_list",
    "privacy_tighten_policy",
    "private_repository_baseline",
]

_SETUP_MESSAGES = frozenset({"begin", "answer", "review", "cancel"})
type PrivacyRecipe = Literal[
    "private", "metadata_only", "assisted_review", "expanded_review", "custom"
]


@dataclass(frozen=True, slots=True)
class GetPrivacySetupRequest:
    session_id: str
    message_type: Literal["begin", "answer", "review", "cancel"]
    sequence: int
    expires_at: datetime
    first_run: bool = False
    current_policy_digest: str | None = None
    current_policy_version: int | None = None
    recipe_hint: PrivacyRecipe | None = None
    repository_scope: AuthorizationScope | None = None

    def __post_init__(self) -> None:
        if type(self.session_id) is not str or not self.session_id:
            raise ValueError("privacy_setup_session_invalid")
        if self.message_type not in _SETUP_MESSAGES:
            raise ValueError("privacy_setup_message_invalid")
        if type(self.sequence) is not int or self.sequence < 0:
            raise ValueError("privacy_setup_sequence_invalid")
        if type(self.expires_at) is not datetime or self.expires_at.tzinfo is None:
            raise ValueError("privacy_setup_expiry_invalid")
        if type(self.first_run) is not bool:
            raise ValueError("privacy_setup_first_run_invalid")
        if self.first_run == (self.current_policy_digest is not None):
            raise ValueError("privacy_setup_policy_binding_invalid")
        if (self.current_policy_digest is None) != (self.current_policy_version is None):
            raise ValueError("privacy_setup_policy_binding_invalid")
        if self.current_policy_digest is not None:
            validate_sha256_digest(self.current_policy_digest)
        if self.current_policy_version is not None and (
            type(self.current_policy_version) is not int or self.current_policy_version <= 0
        ):
            raise ValueError("privacy_setup_policy_version_invalid")
        if self.repository_scope is not None and (
            type(self.repository_scope) is not AuthorizationScope
            or self.repository_scope.kind is not AuthorizationScopeKind.WORKSPACE
        ):
            raise ValueError("repository_privacy_scope_invalid")


@dataclass(frozen=True, slots=True)
class GetPrivacyEffectiveRequest:
    scope: AuthorizationScope

    def __post_init__(self) -> None:
        if type(self.scope) is not AuthorizationScope:
            raise TypeError("privacy_scope_invalid")


@dataclass(frozen=True, slots=True)
class ProposePrivacyPolicyRequest:
    expected_policy_digest: str
    candidate_policy: PrivacyPolicy
    authority_digest: str | None = None
    repository_scope: AuthorizationScope | None = None

    def __post_init__(self) -> None:
        validate_sha256_digest(self.expected_policy_digest)
        if type(self.candidate_policy) is not PrivacyPolicy:
            raise TypeError("candidate_policy_invalid")
        if self.authority_digest is not None:
            validate_sha256_digest(self.authority_digest)
        if self.repository_scope is not None and (
            type(self.repository_scope) is not AuthorizationScope
            or self.repository_scope.kind is not AuthorizationScopeKind.WORKSPACE
        ):
            raise TypeError("repository_privacy_scope_invalid")
        if (self.authority_digest is None) != (self.repository_scope is None):
            raise ValueError("repository_privacy_binding_invalid")


@dataclass(frozen=True, slots=True)
class TightenPrivacyPolicyRequest(ProposePrivacyPolicyRequest):
    pass


@dataclass(frozen=True, slots=True)
class DecidePrivacyPolicyRequest:
    prepared: PreparedPolicyTransition
    decision: HumanPolicyDecision
    human_authority: HumanAuthorityCapability

    def __post_init__(self) -> None:
        if (
            type(self.prepared) is not PreparedPolicyTransition
            or type(self.decision) is not HumanPolicyDecision
            or type(self.human_authority) is not HumanAuthorityCapability
        ):
            raise TypeError("privacy_policy_decision_invalid")


@dataclass(frozen=True, slots=True)
class ListPrivacyReceiptsRequest:
    query: PrivacyReceiptQuery = PrivacyReceiptQuery()

    def __post_init__(self) -> None:
        if type(self.query) is not PrivacyReceiptQuery:
            raise TypeError("privacy_receipt_query_invalid")


@dataclass(frozen=True, slots=True)
class GetPrivacyReceiptRequest:
    receipt_id: str

    def __post_init__(self) -> None:
        validate_id(IdKind.EGRESS_RECEIPT, self.receipt_id)


@dataclass(frozen=True, slots=True)
class ChannelSetupChoice:
    channel: EgressChannel
    enabled: bool
    capability_state: Literal["available", "unsupported"]


@dataclass(frozen=True, slots=True)
class AllowedBlockedExample:
    code: str
    allowed: bool


@dataclass(frozen=True, slots=True)
class ProviderDataUseSummary:
    profile: ProviderDataUseProfile
    recommendation_eligible: bool


@dataclass(frozen=True, slots=True)
class ReviewRecipeView:
    recipe: PrivacyRecipe
    privacy_profile: PrivacyProfile
    review_context_profile: ReviewContextProfile
    review_selection: ReviewSelectionPolicy


@dataclass(frozen=True, slots=True)
class PrivacySetupView:
    effective: EffectivePrivacyPolicy
    channel_choices: tuple[ChannelSetupChoice, ...]
    allowed_blocked_examples: tuple[AllowedBlockedExample, ...]
    recipes: tuple[ReviewRecipeView, ...]
    never_send_editable: Literal[False] = False
    authority: RepositoryPrivacyAuthority | None = None


@dataclass(frozen=True, slots=True)
class PolicyDecisionRequired:
    prepared: PreparedPolicyTransition
    privacy_proposal_id: str

    def __post_init__(self) -> None:
        if type(self.prepared) is not PreparedPolicyTransition:
            raise TypeError("prepared_policy_transition_invalid")
        validate_id(IdKind.PRIVACY_PROPOSAL, self.privacy_proposal_id)


@dataclass(frozen=True, slots=True)
class PrivacyPolicyResult:
    policy: PrivacyPolicy
    generation: int
    revoked_authorization_count: int
    closed_session_count: int
    provider_reconciliation: ProviderReconciliation


type PolicyProposalResult = PolicyDecisionRequired | PrivacyPolicyResult


@dataclass(frozen=True, slots=True)
class PrivacyPolicyApplication:
    policy_store: PrivacyPolicyStorePort
    audit: PrivacyAuditPort
    gateway: OutboundGatewayPort
    clock: ClockPort
    ids: IdPort
    setup_scope: AuthorizationScope
    proposal_ttl_seconds: int = 300

    def __post_init__(self) -> None:
        if type(self.setup_scope) is not AuthorizationScope:
            raise TypeError("privacy_setup_scope_invalid")
        if type(self.proposal_ttl_seconds) is not int or not 1 <= self.proposal_ttl_seconds <= 3600:
            raise ValueError("privacy_proposal_ttl_invalid")


@dataclass(frozen=True, slots=True)
class CredentialHeuristicState:
    """The possible-credential filter for the external reviewer, as every surface shows it.

    ``repository`` is what the current repository applies (its own grant decides, owner decision
    2026-10-07); ``machine_default`` is what a new grant is drafted from (issue #982).
    """

    repository: Literal["enforced", "disabled", "unknown"]
    machine_default: Literal["enforced", "disabled", "unknown"]


def _heuristic_token(value: CredentialHeuristic) -> Literal["enforced", "disabled"]:
    return "disabled" if value is CredentialHeuristic.DISABLED else "enforced"


def credential_heuristic_state(
    authority: RepositoryPrivacyAuthority,
) -> CredentialHeuristicState:
    """One derivation of the filter state from a repository authority snapshot (issue #982).

    A granted repository applies its own grant. A repository without a grant sends nothing to the
    external reviewer; when a migration is pending, report the grant the first check will create
    (the meet of the migration frontier and the installation row), and otherwise ``enforced``.
    """

    machine = authority.machine_policy
    machine_default: Literal["enforced", "disabled", "unknown"] = (
        "unknown" if machine is None else _heuristic_token(machine.credential_heuristic)
    )
    if authority.grant_state == "granted":
        return CredentialHeuristicState(
            _heuristic_token(authority.effective.policy.credential_heuristic), machine_default
        )
    if authority.migration_frontiers and machine is not None:
        outcomes = {
            frontier.meet(machine).credential_heuristic
            for frontier in authority.migration_frontiers
        }
        if outcomes == {CredentialHeuristic.DISABLED}:
            return CredentialHeuristicState("disabled", machine_default)
        if CredentialHeuristic.DISABLED in outcomes:
            # Which frontier carries forward depends on the task that checks first.
            return CredentialHeuristicState("unknown", machine_default)
    return CredentialHeuristicState("enforced", machine_default)


async def privacy_get_effective(
    app: PrivacyPolicyApplication, request: GetPrivacyEffectiveRequest
) -> EffectivePrivacyPolicy:
    return await app.policy_store.effective_policy(request.scope)


async def privacy_get_setup(
    app: PrivacyPolicyApplication, request: GetPrivacySetupRequest
) -> PrivacySetupView:
    authority = (
        None
        if request.repository_scope is None
        else await app.policy_store.repository_authority(request.repository_scope)
    )
    effective = (
        await app.policy_store.effective_policy(app.setup_scope)
        if authority is None
        else authority.effective
    )
    choices = tuple(
        ChannelSetupChoice(
            channel,
            next(p.enabled for p in effective.policy.channel_policies if p.channel is channel),
            "available" if channel is EgressChannel.LLM_INFERENCE else "unsupported",
        )
        for channel in sorted(EgressChannel, key=lambda value: value.value)
    )
    examples = tuple(
        AllowedBlockedExample(code, allowed)
        for code, allowed in (
            ("bounded_structural_metadata", True),
            ("declared_file_type", True),
            ("selected_evidence_excerpt", True),
            ("selected_task_description", True),
            ("complete_transcript", False),
            ("credentials", False),
            ("encryption_material", False),
            ("environment_variables", False),
            ("out_of_scope_content", False),
            ("unrelated_files", False),
        )
    )
    recipes = tuple(
        ReviewRecipeView(
            cast(PrivacyRecipe, name),
            profile,
            context,
            ReviewSelectionPolicy.for_profile(context),
        )
        # Ordered most-recommended first. ``assisted_review`` leads because the structural
        # recipes send no goal, obligations, claims, decisions or finding prose at all — a
        # reviewer given only a metadata spine cannot judge whether a claim is supported, so a
        # AI-powered review under those recipes is close to ceremonial. Leading with the recipe
        # that actually enables review is a presentation change only: nothing is enabled without
        # the user choosing it, and the first-run seed remains all-denied.
        for name, profile, context in (
            ("assisted_review", PrivacyProfile.MINIMAL_EXTERNAL, ReviewContextProfile.ASSISTED),
            ("expanded_review", PrivacyProfile.TRUSTED_PROVIDER, ReviewContextProfile.EXPANDED),
            (
                "metadata_only",
                PrivacyProfile.CONFIRM_EVERY_REQUEST,
                ReviewContextProfile.STRUCTURAL,
            ),
            ("private", PrivacyProfile.LOCAL_ONLY, ReviewContextProfile.STRUCTURAL),
        )
    )
    return PrivacySetupView(effective, choices, examples, recipes, False, authority)


def _llm_inference_enabled(policy: PrivacyPolicy) -> bool:
    return any(
        item.channel is EgressChannel.LLM_INFERENCE and item.enabled
        for item in policy.channel_policies
    )


def _machine_conversation_review(
    machine: PrivacyPolicy, candidate: PrivacyPolicy
) -> ConversationReview | None:
    """The installation row's conversation setting after a repository-bound proposal (ADR-049).

    The installation row is only the default a repository without its own grant inherits, so a
    repository's proposal never widens it: an explicit setting stays as it is. An unset row whose
    inference channel this proposal turns on would read as the released "every task" setting in
    every other repository (review round 2), so it takes the narrower of the repository's answer
    and the recommended hybrid: an "every task" answer never widens other repositories, and the
    hybrid default holds for them. A row whose inference channel was already on (an installation
    that predates the setting) keeps its released reading.
    """

    if machine.conversation_review is not None:
        return machine.conversation_review
    if _llm_inference_enabled(machine) or not _llm_inference_enabled(candidate):
        return None
    return narrower_conversation_review(
        candidate.effective_conversation_review, ConversationReview.LOCAL_AGENT_OPT_IN
    )


async def privacy_propose_policy(
    app: PrivacyPolicyApplication, request: ProposePrivacyPolicyRequest
) -> PolicyProposalResult:
    if (
        request.repository_scope is None
        and request.candidate_policy.effective_scope.kind is not AuthorizationScopeKind.MACHINE
    ):
        raise ValueError("repository_privacy_context_required")
    if request.repository_scope is not None:
        authority = await app.policy_store.repository_authority(request.repository_scope)
        if authority.authority_digest != request.authority_digest:
            raise ValueError("privacy_policy_stale")
        current = authority.effective
    else:
        authority = None
        current = await app.policy_store.effective_policy(request.candidate_policy.effective_scope)
    if current.effective_digest != request.expected_policy_digest:
        raise ValueError("privacy_policy_stale")
    if authority is None and _is_tightening(current.policy, request.candidate_policy):
        return await privacy_tighten_policy(
            app,
            TightenPrivacyPolicyRequest(request.expected_policy_digest, request.candidate_policy),
        )
    prepared_repository_candidate: PrivacyPolicy | None = None
    if authority is not None and authority.grant_policy is not None:
        exact_candidate = _policy_for_scope(
            request.candidate_policy,
            authority.scope,
            policy_id=authority.grant_policy.policy_id,
            version=authority.grant_policy.version + 1,
            supersedes=authority.grant_policy.policy_digest,
        )
        if _is_tightening(current.policy, exact_candidate) and _is_tightening(
            authority.grant_policy, exact_candidate
        ):
            async with app.gateway.authority_mutation_fence():
                commit = await app.policy_store.tighten(
                    authority.scope,
                    _overlay(exact_candidate),
                    authority.grant_policy.policy_digest,
                )
            return _result(commit, ProviderReconciliation(commit.generation, 0, 0, ()))
    if authority is not None and authority.grant_policy is None:
        repository_policy_id = app.ids.new(IdKind.PRIVACY_POLICY)
        repository_candidate = _policy_for_scope(
            request.candidate_policy,
            authority.scope,
            policy_id=repository_policy_id,
            version=1,
            supersedes=None,
        )
        prepared_repository_candidate = repository_candidate
        repository_baseline = private_repository_baseline(repository_candidate)
        if _is_tightening(repository_baseline, repository_candidate):
            async with app.gateway.authority_mutation_fence():
                commit = await app.policy_store.insert_repository_tightening(
                    authority.scope,
                    repository_candidate,
                    authority.authority_digest,
                )
            return _result(commit, ProviderReconciliation(commit.generation, 0, 0, ()))
    now = app.clock.now_utc()
    proposal_id = app.ids.new(IdKind.PRIVACY_PROPOSAL)
    candidate = request.candidate_policy
    members: tuple[PolicyTransitionMember, ...] = ()
    proposal_scope = candidate.effective_scope
    if authority is not None:
        proposal_scope = authority.scope
        machine_scope = AuthorizationScope(
            AuthorizationScopeKind.MACHINE, authority.scope.installation_id
        )
        machine = await app.policy_store.effective_policy(machine_scope)
        repository_candidate = _policy_for_scope(
            candidate,
            proposal_scope,
            policy_id=(
                cast(PrivacyPolicy, prepared_repository_candidate).policy_id
                if authority.grant_policy is None
                else authority.grant_policy.policy_id
            ),
            version=1 if authority.grant_policy is None else authority.grant_policy.version + 1,
            supersedes=(
                None if authority.grant_policy is None else authority.grant_policy.policy_digest
            ),
        )
        compound: list[PolicyTransitionMember] = []
        # The credential-heuristic opt-out belongs to the repository grant (owner decision,
        # 2026-10-07): a repository-bound proposal never moves the installation-wide default.
        # Nor does the conversation setting (ADR-049): see ``_machine_conversation_review``.
        machine_candidate = _policy_for_scope(
            replace(
                candidate,
                credential_heuristic=machine.policy.credential_heuristic,
                conversation_review=_machine_conversation_review(machine.policy, candidate),
            ),
            machine_scope,
            policy_id=machine.policy.policy_id,
            version=machine.policy.version + 1,
            supersedes=machine.policy.policy_digest,
        )
        if not _is_tightening(machine.policy, machine_candidate):
            compound.append(
                PolicyTransitionMember(
                    "replace",
                    machine_scope,
                    machine_candidate,
                    machine.generation,
                    machine.effective_digest,
                )
            )
        compound.append(
            PolicyTransitionMember(
                "insert" if authority.grant_state == "missing" else "replace",
                proposal_scope,
                repository_candidate,
                None if authority.grant_state == "missing" else authority.grant_generation,
                None if authority.grant_state == "missing" else authority.grant_policy_digest,
            )
        )
        members = tuple(compound)
        candidate = repository_candidate
    proposal = PolicyTransitionProposal(
        scope=proposal_scope,
        expected_generation=current.generation,
        proposed_policy=candidate,
        proposal_digest=canonical_digest(_policy_identity(candidate)),
        created_at=now,
        expires_at=now + timedelta(seconds=app.proposal_ttl_seconds),
        privacy_proposal_id=proposal_id,
        expected_policy_digest=request.expected_policy_digest,
        authority_digest=request.authority_digest,
        members=members,
    )
    prepared = await app.policy_store.prepare_transition(proposal)
    return PolicyDecisionRequired(prepared, proposal_id)


def private_repository_baseline(candidate: PrivacyPolicy) -> PrivacyPolicy:
    """Represent an absent repository grant as explicit Private/no-egress authority."""

    disabled_channels = tuple(
        ChannelPolicy(
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
        for channel in sorted(EgressChannel, key=lambda item: item.value.encode("ascii"))
    )
    return PrivacyPolicy(
        candidate.policy_id,
        candidate.version,
        candidate.policy_digest,
        PrivacyProfile.LOCAL_ONLY,
        ReviewContextProfile.STRUCTURAL,
        ReviewSelectionPolicy.for_profile(ReviewContextProfile.STRUCTURAL),
        False,
        False,
        candidate.effective_scope,
        disabled_channels,
        False,
        None,
        (),
        (),
        candidate.agent_context_categories,
        candidate.agent_context_data_classes,
        candidate.trusted_human_control_categories,
        candidate.trusted_human_control_data_classes,
        candidate.created_at,
        candidate.supersedes_policy_digest,
    )


async def privacy_tighten_policy(
    app: PrivacyPolicyApplication, request: TightenPrivacyPolicyRequest
) -> PrivacyPolicyResult:
    if request.candidate_policy.effective_scope.kind is not AuthorizationScopeKind.MACHINE:
        raise ValueError("repository_privacy_context_required")
    current = await app.policy_store.effective_policy(request.candidate_policy.effective_scope)
    if current.effective_digest != request.expected_policy_digest:
        raise ValueError("privacy_policy_stale")
    if not _is_tightening(current.policy, request.candidate_policy):
        raise ValueError("privacy_authority_required")
    async with app.gateway.authority_mutation_fence():
        commit = await app.policy_store.tighten(
            request.candidate_policy.effective_scope,
            _overlay(request.candidate_policy),
            request.expected_policy_digest,
        )
    unavailable = ProviderReconciliation(commit.generation, 0, 0, ())
    return _result(commit, unavailable)


async def decide_privacy_policy(
    app: PrivacyPolicyApplication, request: DecidePrivacyPolicyRequest
) -> PrivacyPolicyResult:
    if request.decision.approved:
        async with app.gateway.authority_mutation_fence():
            commit = await app.policy_store.commit_transition(request.prepared, request.decision)
    else:
        commit = await app.policy_store.commit_transition(request.prepared, request.decision)
    effective = EffectivePrivacyPolicy(
        commit.policy, commit.generation, commit.policy.policy_digest
    )
    reconciliation = (
        ProviderReconciliation(commit.generation, 0, 0, ())
        if commit.replayed
        else await app.gateway.reconcile_policy(effective, request.human_authority)
    )
    return _result(commit, reconciliation)


async def privacy_receipts_list(
    app: PrivacyPolicyApplication, request: ListPrivacyReceiptsRequest
) -> PrivacyReceiptPage:
    return await app.audit.list_receipts(
        request.query, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
    )


async def privacy_pending_list(app: PrivacyPolicyApplication) -> PendingDisclosurePage:
    """List the disclosure proposals a local human can still decide.

    Takes no query. A pending decision is either open or it is not, and every filter this could
    offer would be a way to describe proposals rather than to find one.
    """

    return await app.audit.list_pending_disclosures(PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL)


async def privacy_receipts_get(
    app: PrivacyPolicyApplication, request: GetPrivacyReceiptRequest
) -> PrivacyReceiptView | None:
    return await app.audit.get_receipt(
        request.receipt_id, PrivacyReceiptAudience.TRUSTED_LOCAL_CONTROL
    )


def _result(
    commit: PolicyCommitResult, reconciliation: ProviderReconciliation
) -> PrivacyPolicyResult:
    return PrivacyPolicyResult(
        commit.policy,
        commit.generation,
        commit.revoked_authorization_count,
        commit.closed_session_count,
        reconciliation,
    )


def _overlay(policy: PrivacyPolicy) -> PolicyOverlay:
    return PolicyOverlay(
        policy.effective_scope,
        policy.review_selection,
        policy.require_current_provider_data_use_evidence,
        policy.channel_policies,
        policy.local_model_categories,
        policy.local_model_data_classes,
        policy.agent_context_categories,
        policy.agent_context_data_classes,
        policy,
    )


def _scope_rank(value: str | None) -> int:
    # A channel that is off grants no scope at all, so it ranks narrower than every ceiling
    # and any ceiling a proposal gives it reads as a widening.
    if value is None:
        return 4
    return {"machine": 0, "workspace": 1, "task": 2, "request": 3}[value]


def is_privacy_tightening(current: PrivacyPolicy, candidate: PrivacyPolicy) -> bool:
    """True when ``candidate`` is a non-widening subset/equivalent of ``current``."""

    return _is_tightening(current, candidate)


def _enum_labels(values: tuple[Enum, ...]) -> PrivacyPolicyChangeValue:
    return PrivacyPolicyChangeValue.of_labels(tuple(str(item.value) for item in values))


def _scope_labels(scope: AuthorizationScope) -> PrivacyPolicyChangeValue:
    parts = [f"kind:{scope.kind.value}", f"installation:{scope.installation_id}"]
    for name, value in (
        ("workspace", scope.workspace_ref_commitment),
        ("task", scope.task_id),
        ("request", scope.request_id),
    ):
        if value is not None:
            parts.append(f"{name}:{value}")
    return PrivacyPolicyChangeValue.of_labels(tuple(parts))


def _binding_labels(binding: ProviderBinding | None) -> PrivacyPolicyChangeValue:
    """One label per binding field, never a concatenation.

    Every field is independently bounded at 128 bytes by its own domain validator, so joining
    the endpoint profile and its version into one label could exceed the label bound and make
    this raise — which the daemon turns into ``target_invalid``, leaving a human unable to
    approve a perfectly legitimate policy. Keeping the fields separate means the longest label
    a valid binding can produce is one prefix plus one field.
    """

    if binding is None:
        return PrivacyPolicyChangeValue.absent()
    return PrivacyPolicyChangeValue.of_labels(
        (
            f"provider:{binding.provider_id}",
            f"model:{binding.model_id}",
            f"endpoint:{binding.endpoint_profile_id}",
            f"endpoint_version:{binding.endpoint_profile_version}",
            f"transport:{binding.transport}",
        )
    )


def _append(
    changes: list[PrivacyPolicyChange],
    area: str,
    field: str,
    subject: str | None,
    before: PrivacyPolicyChangeValue,
    after: PrivacyPolicyChangeValue,
    widens: bool,
) -> None:
    """Record one dimension, silently skipping the dimensions that did not move."""

    if before == after:
        return
    changes.append(
        PrivacyPolicyChange(
            cast(
                Literal[
                    "global", "review", "channel", "local_model", "agent_context", "human_control"
                ],
                area,
            ),
            field,
            subject,
            before,
            after,
            widens,
        )
    )


# Every per-channel dimension, as (field, how to render one side, when it widens).
#
# The widening predicates read ``old`` directly even when that channel is off, because a
# disabled ``ChannelPolicy`` is canonically zeroed: empty category/class/purpose sets, no
# binding, and zero limits are exactly what a channel that is off permits. Only the two
# dimensions that have no meaningful zero — the scope ceiling, which is a real enum member
# either way, and the confirmation requirement, whose absence is not its removal — say so
# explicitly.
_CHANNEL_DIMENSIONS: Final[
    tuple[
        tuple[
            str,
            Callable[[ChannelPolicy], PrivacyPolicyChangeValue],
            Callable[[ChannelPolicy, ChannelPolicy], bool],
        ],
        ...,
    ]
] = (
    (
        "categories",
        lambda channel: _enum_labels(channel.allowed_categories),
        lambda new, old: not set(new.allowed_categories) <= set(old.allowed_categories),
    ),
    (
        "data_classes",
        lambda channel: _enum_labels(channel.allowed_data_classes),
        lambda new, old: not set(new.allowed_data_classes) <= set(old.allowed_data_classes),
    ),
    (
        "purposes",
        lambda channel: PrivacyPolicyChangeValue.of_labels(channel.allowed_purposes),
        lambda new, old: not set(new.allowed_purposes) <= set(old.allowed_purposes),
    ),
    (
        "provider",
        lambda channel: _binding_labels(channel.provider_binding),
        lambda new, old: (
            new.provider_binding is not None and new.provider_binding != old.provider_binding
        ),
    ),
    (
        # One more authorized destination is a widening of exactly that destination (#582);
        # dropping or keeping it is not.
        "fallback_provider",
        lambda channel: _binding_labels(channel.fallback_provider_binding),
        lambda new, old: (
            new.fallback_provider_binding is not None
            and new.fallback_provider_binding != old.fallback_provider_binding
        ),
    ),
    (
        "scope_ceiling",
        lambda channel: PrivacyPolicyChangeValue.of_labels((channel.scope_ceiling.value,)),
        lambda new, old: (
            _scope_rank(new.scope_ceiling.value)
            < _scope_rank(old.scope_ceiling.value if old.enabled else None)
        ),
    ),
    (
        "preview_required",
        lambda channel: PrivacyPolicyChangeValue.of_flag(channel.preview_required),
        lambda new, old: old.enabled and old.preview_required and not new.preview_required,
    ),
    (
        "max_bytes",
        lambda channel: PrivacyPolicyChangeValue.of_count(channel.max_bytes),
        lambda new, old: new.max_bytes > old.max_bytes,
    ),
    (
        "max_tokens",
        lambda channel: PrivacyPolicyChangeValue.of_count(channel.max_tokens),
        lambda new, old: new.max_tokens > old.max_tokens,
    ),
    (
        "authorization_ttl_seconds",
        lambda channel: PrivacyPolicyChangeValue.of_count(channel.authorization_ttl_seconds),
        lambda new, old: new.authorization_ttl_seconds > old.authorization_ttl_seconds,
    ),
)


def _channel_changes(
    changes: list[PrivacyPolicyChange], new: ChannelPolicy, old: ChannelPolicy
) -> None:
    if new.channel is not old.channel:
        raise ValueError("privacy_policy_channel_order_invalid")
    subject = new.channel.value
    _append(
        changes,
        "channel",
        "enabled",
        subject,
        PrivacyPolicyChangeValue.of_flag(old.enabled),
        PrivacyPolicyChangeValue.of_flag(new.enabled),
        new.enabled and not old.enabled,
    )
    # A channel that is off carries no ceiling at all, so each dimension reads ``absent`` on
    # that side rather than presenting a zeroed limit as a real one. Nothing widens on a
    # channel the proposal leaves off; the enablement change carries that case.
    for field, value_of, widens in _CHANNEL_DIMENSIONS:
        _append(
            changes,
            "channel",
            field,
            subject,
            value_of(old) if old.enabled else PrivacyPolicyChangeValue.absent(),
            value_of(new) if new.enabled else PrivacyPolicyChangeValue.absent(),
            new.enabled and widens(new, old),
        )


def _review_changes(
    changes: list[PrivacyPolicyChange], new: ReviewSelectionPolicy, old: ReviewSelectionPolicy
) -> None:
    _append(
        changes,
        "review",
        "sections",
        None,
        PrivacyPolicyChangeValue.of_labels(old.sections),
        PrivacyPolicyChangeValue.of_labels(new.sections),
        not set(new.sections) <= set(old.sections),
    )
    _append(
        changes,
        "review",
        "excerpt_kinds",
        None,
        PrivacyPolicyChangeValue.of_labels(old.excerpt_kinds),
        PrivacyPolicyChangeValue.of_labels(new.excerpt_kinds),
        not set(new.excerpt_kinds) <= set(old.excerpt_kinds),
    )
    _append(
        changes,
        "review",
        "relevance",
        None,
        PrivacyPolicyChangeValue.of_labels((old.relevance,)),
        PrivacyPolicyChangeValue.of_labels((new.relevance,)),
        new.relevance == "linked_then_in_scope" and old.relevance == "linked_subjects_only",
    )
    for field in ("include_finding_prose", "include_exact_command_text"):
        before = cast(bool, getattr(old, field))
        after = cast(bool, getattr(new, field))
        _append(
            changes,
            "review",
            field,
            None,
            PrivacyPolicyChangeValue.of_flag(before),
            PrivacyPolicyChangeValue.of_flag(after),
            after and not before,
        )
    for field in (
        "max_timeline_items",
        "max_assessments",
        "max_change_observations",
        "max_excerpts",
        "max_omissions",
        "max_excerpt_bytes",
        "max_total_excerpt_bytes",
    ):
        before_count = cast(int, getattr(old, field))
        after_count = cast(int, getattr(new, field))
        _append(
            changes,
            "review",
            field,
            None,
            PrivacyPolicyChangeValue.of_count(before_count),
            PrivacyPolicyChangeValue.of_count(after_count),
            after_count > before_count,
        )


def privacy_policy_changes(
    current: PrivacyPolicy, candidate: PrivacyPolicy
) -> tuple[PrivacyPolicyChange, ...]:
    """Every security-relevant field ``candidate`` moves, as ``before → after`` steps.

    This is the single source of truth for both halves of a policy transition: the classifier
    calls a proposal tightening exactly when no returned change has ``widens=True``, and the
    trusted approval ceremony renders these same records. Deriving the two from one comparison
    is the invariant — a widening the classifier recognizes can no longer be missing from the
    screen a human approves it on. Lineage-only fields (``version``, ``policy_digest``,
    ``created_at``, ``supersedes_policy_digest``, ``policy_id``) are excluded: they always
    differ on a fresh candidate and describe no disclosure boundary. Simultaneous tightenings
    are included so the human sees the complete substantive diff, not just its worst half.

    Returned most consequential widening first, then remaining widenings, then tightenings, in
    a total deterministic order.
    """

    if type(current) is not PrivacyPolicy or type(candidate) is not PrivacyPolicy:
        raise TypeError("privacy_policy_changes_invalid")
    changes: list[PrivacyPolicyChange] = []
    _append(
        changes,
        "global",
        "effective_scope",
        None,
        _scope_labels(current.effective_scope),
        _scope_labels(candidate.effective_scope),
        candidate.effective_scope != current.effective_scope,
    )
    _append(
        changes,
        "global",
        "network_egress",
        None,
        PrivacyPolicyChangeValue.of_flag(current.network_egress_permitted),
        PrivacyPolicyChangeValue.of_flag(candidate.network_egress_permitted),
        candidate.network_egress_permitted and not current.network_egress_permitted,
    )
    _append(
        changes,
        "global",
        "provider_data_use_evidence",
        None,
        PrivacyPolicyChangeValue.of_flag(current.require_current_provider_data_use_evidence),
        PrivacyPolicyChangeValue.of_flag(candidate.require_current_provider_data_use_evidence),
        current.require_current_provider_data_use_evidence
        and not candidate.require_current_provider_data_use_evidence,
    )
    # Turning the low-confidence credential heuristic off lets values it would have withheld
    # leave, so it is a widening that needs the trusted decision; turning it back on is a
    # tightening that applies directly (issue #982).
    _append(
        changes,
        "global",
        "credential_heuristic",
        None,
        PrivacyPolicyChangeValue.of_flag(current.credential_heuristic_enforced),
        PrivacyPolicyChangeValue.of_flag(candidate.credential_heuristic_enforced),
        current.credential_heuristic_enforced and not candidate.credential_heuristic_enforced,
    )
    # Conversations that start with AI-powered review, or an agent's switch that no longer waits
    # for the owner, need less of the owner: a widening through the trusted decision. Moving back
    # toward local conversations or owner approval is a tightening that applies directly
    # (ADR-049). The effective values are compared, so an unset field reads as released.
    current_conversations = current.effective_conversation_review
    candidate_conversations = candidate.effective_conversation_review
    _append(
        changes,
        "global",
        "conversation_review",
        None,
        PrivacyPolicyChangeValue.of_labels((current_conversations.value,)),
        PrivacyPolicyChangeValue.of_labels((candidate_conversations.value,)),
        conversation_review_widens(current_conversations, candidate_conversations),
    )
    _review_changes(changes, candidate.review_selection, current.review_selection)
    for new, old in zip(candidate.channel_policies, current.channel_policies, strict=True):
        _channel_changes(changes, new, old)
    _append(
        changes,
        "local_model",
        "enabled",
        None,
        PrivacyPolicyChangeValue.of_flag(current.local_model_enabled),
        PrivacyPolicyChangeValue.of_flag(candidate.local_model_enabled),
        candidate.local_model_enabled and not current.local_model_enabled,
    )
    _append(
        changes,
        "local_model",
        "binding",
        None,
        _binding_labels(current.local_model_binding if current.local_model_enabled else None),
        _binding_labels(candidate.local_model_binding if candidate.local_model_enabled else None),
        candidate.local_model_enabled
        and candidate.local_model_binding != current.local_model_binding,
    )
    for area, new_categories, old_categories, new_classes, old_classes in (
        (
            "local_model",
            candidate.local_model_categories,
            current.local_model_categories,
            candidate.local_model_data_classes,
            current.local_model_data_classes,
        ),
        (
            "agent_context",
            candidate.agent_context_categories,
            current.agent_context_categories,
            candidate.agent_context_data_classes,
            current.agent_context_data_classes,
        ),
        (
            "human_control",
            candidate.trusted_human_control_categories,
            current.trusted_human_control_categories,
            candidate.trusted_human_control_data_classes,
            current.trusted_human_control_data_classes,
        ),
    ):
        _append(
            changes,
            area,
            "categories",
            None,
            _enum_labels(old_categories),
            _enum_labels(new_categories),
            not set(new_categories) <= set(old_categories),
        )
        _append(
            changes,
            area,
            "data_classes",
            None,
            _enum_labels(old_classes),
            _enum_labels(new_classes),
            not set(new_classes) <= set(old_classes),
        )
    ordered = sort_privacy_changes(changes)
    validate_privacy_change_set(ordered)
    return ordered


def _is_tightening(current: PrivacyPolicy, candidate: PrivacyPolicy) -> bool:
    return not any(change.widens for change in privacy_policy_changes(current, candidate))


def _policy_identity(policy: PrivacyPolicy) -> JsonValue:
    return cast(JsonValue, _to_json(policy))


def _policy_for_scope(
    source: PrivacyPolicy,
    scope: AuthorizationScope,
    *,
    policy_id: str,
    version: int,
    supersedes: str | None,
) -> PrivacyPolicy:
    placeholder = replace(
        source,
        policy_id=policy_id,
        version=version,
        policy_digest="sha256:" + "0" * 64,
        effective_scope=scope,
        supersedes_policy_digest=supersedes,
    )
    identity = cast(dict[str, JsonValue], _policy_identity(placeholder))
    identity.pop("policy_digest")
    return replace(placeholder, policy_digest=canonical_digest(cast(JsonValue, identity)))


def _to_json(value: object) -> object:
    if value is None or type(value) in {bool, int, str}:
        return value
    if type(value) is bytes:
        return value.hex()
    if isinstance(value, Enum):
        return value.value
    if type(value) is datetime:
        return value.isoformat()
    if is_dataclass(value):
        return {
            field.name: _to_json(getattr(value, field.name))
            for field in fields(value)
            # Defaults that predate their fields are never written (issues #982, ADR-049), so
            # every policy, case and receipt from before them keeps its exact canonical bytes.
            if not policy_field_omitted(field.name, getattr(value, field.name))
        }
    if type(value) is tuple:
        return [_to_json(member) for member in cast(tuple[object, ...], value)]
    raise TypeError("privacy_policy_identity_invalid")
