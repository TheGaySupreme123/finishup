"""Central provider-free privacy and disclosure coordinator."""

from __future__ import annotations

import asyncio
import base64
from collections import Counter
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TYPE_CHECKING, cast

from finishup.adapters.privacy.local_enforcer import SecretScanRuleset
from finishup.domain.findings import SemanticDispatchKind
from finishup.domain.privacy import (
    REVIEW_PACKET_ITEM_ID,
    ApprovedLocalDisclosureCase,
    ApprovedLocalItem,
    ApprovedOutboundCase,
    AuthorizationScope,
    AuthorizationScopeKind,
    CandidateContext,
    ClassifiedContext,
    ConsentSource,
    ConversationReview,
    CredentialHeuristic,
    DataCategory,
    DataClass,
    DisclosureProposal,
    DisclosureProvenance,
    EgressAuthorization,
    EgressChannel,
    EgressOriginOperation,
    EgressReceipt,
    ForbiddenDataKind,
    HumanPrivacyDecision,
    LocalDisclosureApproved,
    LocalDisclosureBlocked,
    LocalDisclosureOmission,
    LocalDisclosureReceipt,
    LocalDisclosureSink,
    LocalDisclosureUnavailable,
    PreDispatchAuditDecision,
    PrivacyDecision,
    PrivacyOutcome,
    PrivacyPolicy,
    PrivacyProfile,
    PrivacyReason,
    ProviderBinding,
    ProviderDataUseProfile,
    ReceiptCounts,
    ReceiptPolicyBinding,
    ReceiptSecretScan,
    ReceiptSecretScanStage,
    ReceiptTransformations,
    ReviewSelectionPolicy,
    egress_origin_operation,
    external_review_credential_heuristic,
)
from finishup.domain.receipts import (
    SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES,
    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP,
)
from finishup.observability.logging import record_unexpected_exception_without_raising
from finishup.observability.privacy import redact_heuristic_spans
from finishup.observability.semantic_context import semantic_check_request
from finishup.ports.clock import ClockPort
from finishup.ports.ids import IdPort
from finishup.ports.privacy import (
    AgentProjectionRequest,
    DisclosureProposalRequest,
    EffectivePrivacyPolicy,
    HumanAuthorityCapability,
    HumanPrivacyControlPort,
    MinimizedDisclosure,
    OutboundGatewayPort,
    PendingHumanDecision,
    PrivacyAuditPort,
    PrivacyAuditState,
    PrivacyClassifierPort,
    PrivacyPolicyStorePort,
    RepositoryPrivacyAuthority,
)
from finishup.ports.semantic import (
    Deadline,
    SemanticResult,
    SemanticResultInvalid,
    SemanticResultLate,
    SemanticResultRefused,
    SemanticResultSuccess,
    SemanticResultTimeout,
    SemanticResultUnavailable,
)
from finishup.protocol.canonical import canonical_digest, canonical_encode, strict_json_parse
from finishup.protocol.ids import IdKind, validate_opaque_item_id
from finishup.protocol.redacted_values import (
    SemanticRedactedValue,
    validate_semantic_redacted_values,
)

if TYPE_CHECKING:
    from finishup.application.privacy_policy import PrivacyPolicyApplication
    from finishup.application.semantic_case import ReviewPacketDisclosure

__all__ = [
    "PrivacyCoordinator",
    "RepositoryGrantAdmission",
    "SemanticEgressAwaitingHuman",
    "SemanticEgressAttemptUnknown",
    "SemanticEgressBlocked",
    "SemanticEgressProviderOutcome",
    "SemanticEgressResult",
    "SemanticEgressSuccess",
    "advice_selection_is_current",
    "semantic_policy_refusal",
    "semantic_preview_required",
]

type LocalDisclosureResult = (
    LocalDisclosureApproved | LocalDisclosureBlocked | LocalDisclosureUnavailable
)


def _validate_withheld_item_ids(value: object) -> None:
    """Keep every in-process egress/recovery result on the shared opaque-ID contract."""

    if type(value) is not tuple:
        raise ValueError("semantic_withheld_item_ids_invalid")
    values = cast(tuple[object, ...], value)
    if len(values) > 64:
        raise ValueError("semantic_withheld_item_ids_invalid")
    if any(type(item_id) is not str for item_id in values):
        raise ValueError("semantic_withheld_item_ids_invalid")
    typed_values = cast(tuple[str, ...], values)
    if typed_values != tuple(sorted(set(typed_values), key=lambda item: item.encode("utf-8"))):
        raise ValueError("semantic_withheld_item_ids_invalid")
    for item_id in typed_values:
        try:
            validate_opaque_item_id(item_id)
        except ValueError as exc:
            raise ValueError("semantic_withheld_item_ids_invalid") from exc


def _classified_scan_match_count(classified: ClassifiedContext) -> int:
    """Count findings from the candidate scan without retaining matched content."""

    return sum(
        len(item.forbidden_findings) + len(item.heuristic_findings) for item in classified.items
    )


def _heuristic_only_item_ids(classified: ClassifiedContext) -> tuple[str, ...]:
    """Return opaque ids whose only finding is the bounded heuristic assignment signal."""

    return tuple(
        sorted(
            {
                item.candidate.item_id
                for item in classified.items
                if item.scope_valid and item.heuristic_findings and not item.forbidden_findings
            },
            key=str.encode,
        )
    )


def _minimized_scan_match_count(minimized: MinimizedDisclosure) -> int:
    """Count findings in the exact prepared case scan."""

    return len(set(minimized.forbidden_findings) | set(minimized.heuristic_findings))


def _transformation_count(summary: tuple[tuple[str, int], ...], name: str) -> int:
    """Read one bounded transformation count from durable proposal metadata."""

    for key, count in summary:
        if key == name:
            return count
    return 0


def _current_scanner_identity(
    classifier: PrivacyClassifierPort,
) -> tuple[str, str] | None:
    """Read the concrete scanner identity required to resume a prepared disclosure.

    A classifier implementation that predates the identity contract cannot prove that it would
    apply the same never-send rules.  Treat that as unavailable authority instead of silently
    accepting the proposal's historical profile.
    """

    resolver = getattr(classifier, "scanner_identity", None)
    if not callable(resolver):
        return None
    try:
        value = resolver()
    except Exception:
        return None
    if type(value) is not tuple:
        return None
    parts = cast(tuple[object, ...], value)
    if len(parts) != 2 or type(parts[0]) is not str or type(parts[1]) is not str:
        return None
    return cast(tuple[str, str], parts)


def _resume_scan_is_clean(
    classifier: PrivacyClassifierPort,
    prepared_bytes: bytes,
    credential_heuristic: CredentialHeuristic = CredentialHeuristic.ENFORCED,
) -> tuple[ForbiddenDataKind, ...] | None:
    """Scan the exact persisted transformed bytes with the current scanner.

    ``None`` means the scanner boundary itself was unavailable or malformed.  It is distinct from
    an empty clean result so a resume cannot turn a broken classifier into a successful dispatch.
    ``credential_heuristic`` is the owner policy's setting; resume already requires that policy
    to be exactly the one the proposal was prepared under (issue #982).
    """

    try:
        findings = (
            classifier.scan_exact_bytes(prepared_bytes)
            if credential_heuristic is CredentialHeuristic.ENFORCED
            else classifier.scan_exact_bytes(
                prepared_bytes, credential_heuristic=credential_heuristic
            )
        )
    except Exception:
        return None
    if type(findings) is not tuple or any(type(item) is not ForbiddenDataKind for item in findings):
        return None
    return findings


class RepositoryGrantAdmission(StrEnum):
    """Admission-locked repository authority outcome for check composition.

    ``MISSING`` is deliberately the sole nonterminal handoff: the coordinator observed an exactly
    bound, missing standing grant while still open. All other states are fail-closed so callers
    cannot turn an unavailable coordinator or malformed policy state into a trusted ceremony.
    """

    MISSING = "missing"
    GRANTED = "granted"
    UNAVAILABLE = "unavailable"


# This value crosses the privacy-policy boundary, so it must match the
# documented/recipe vocabulary and the stored provider-credential binding.
_SEMANTIC_PURPOSE = "semantic-review"
_CREDENTIAL_PROBE_PURPOSE = "credential-probe"
_MEDIA_TYPE = "application/json"
_SCHEMA_ID = "yoetz-semantic-case-1.0.0"
_SCAN = SecretScanRuleset()
# Breadth order, matching ``_scope_rank`` in ``finishup.application.privacy_policy``: a lower rank
# is a *broader* scope. ``machine`` is therefore the widest authorization ceiling a channel can
# carry and ``request`` the narrowest, which is why moving a ceiling from ``task`` to ``machine``
# is classified as ``scope_ceiling_broadened`` by the widen/tighten ceremony.
_SCOPE_KIND_RANK = {
    AuthorizationScopeKind.MACHINE: 0,
    AuthorizationScopeKind.WORKSPACE: 1,
    AuthorizationScopeKind.TASK: 2,
    AuthorizationScopeKind.REQUEST: 3,
}


def semantic_preview_required(policy: PrivacyPolicy) -> bool:
    """The same human-preview decision for foreground checks and background admission.

    ADR-049: where the owner chose that AI-powered review an agent turns on waits for them, every
    review asks the owner first, exactly like per-request confirmation (background advice, which
    no human can preview, is then refused here as well as by its own admission rule).
    """
    llm = next(c for c in policy.channel_policies if c.channel is EgressChannel.LLM_INFERENCE)
    return (
        policy.profile is PrivacyProfile.CONFIRM_EVERY_REQUEST
        or llm.preview_required
        or policy.effective_conversation_review is ConversationReview.LOCAL_OWNER_APPROVAL
    )


def advice_selection_is_current(candidate: CandidateContext, policy: PrivacyPolicy) -> bool:
    """Whether a background advice candidate was built for the policy now in force (#1019 r3).

    The service composes the advice envelope from the review-context profile it read before
    waiting for privacy admission. A profile tightened in between (Assisted to Structural) must
    not send the stale selection: the envelope must name the effective profile, and finding prose
    may travel only when the effective selection includes it. A malformed envelope is left to the
    assembler's own fail-closed checks.
    """

    if (
        any(item.category is DataCategory.FINDING_SUMMARY for item in candidate.items)
        and not policy.review_selection.include_finding_prose
    ):
        return False
    for item in candidate.items:
        if item.item_id != REVIEW_PACKET_ITEM_ID:
            continue
        try:
            envelope = strict_json_parse(item.plaintext)
        except (ValueError, TypeError, UnicodeDecodeError):
            return True
        if isinstance(envelope, dict):
            named = envelope.get("review_context_profile")
            if type(named) is str and named != policy.review_context_profile.value:
                return False
    return True


def conversation_review_refuses(policy: PrivacyPolicy, purpose: str) -> bool:
    """Whether the owner's explicit ``local_only`` refuses this LLM-inference purpose (ADR-049).

    The owner chose local checks only for every task: no AI-powered review (and so no background
    advice, which is review) leaves, whatever a check or a switch asked for. Enforced here, at the
    gateway, as well as when a check resolves its mode, so a failed setting read or a narrowing
    while a check is in flight cannot send a review. Only the explicit token refuses: a policy
    that predates the setting keeps its released behaviour, and the fixed-literal credential
    probe (no repository content) stays governed by its own consent.
    """

    return (
        policy.conversation_review is ConversationReview.LOCAL_ONLY and purpose == _SEMANTIC_PURPOSE
    )


def semantic_policy_refusal(
    policy: PrivacyPolicy,
    binding: ProviderBinding,
    purpose: str,
    scope_kind: AuthorizationScopeKind,
) -> tuple[PrivacyOutcome, PrivacyReason] | None:
    """The static policy leg of LLM-inference egress admission, or ``None`` when it admits.

    Pure over the effective policy: the destination, channel, exact provider binding, purpose, and
    scope-ceiling checks the semantic pipeline applies before classification. Readiness probes
    (background advice admission, #923) reuse it so they never call a route usable that dispatch
    would refuse; the pipeline stays the enforcing call site.
    """

    llm = next(
        item for item in policy.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
    )
    if policy.profile is PrivacyProfile.LOCAL_ONLY and binding.transport == "external":
        return PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.DESTINATION_NOT_ALLOWED
    if conversation_review_refuses(policy, purpose):
        return PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.POLICY_DENIED
    if not policy.network_egress_permitted or not llm.enabled:
        if binding.transport == "external":
            return PrivacyOutcome.CHANNEL_UNAVAILABLE, PrivacyReason.CHANNEL_UNAVAILABLE
    # Exact membership in the row's authorized destinations: the primary, plus the one
    # fallback the same approval named (#582). Never a prefix, wildcard, or provider-id match.
    if (
        llm.provider_binding is not None
        and binding.transport == "external"
        and binding not in llm.authorized_provider_bindings
    ):
        return PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.DESTINATION_NOT_ALLOWED
    if purpose not in llm.allowed_purposes:
        return PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.PURPOSE_NOT_ALLOWED
    # Block only a candidate whose scope is *broader* than the ceiling the channel commits to.
    # A narrower candidate (task under a workspace ceiling) is inside the consented authority,
    # which is the shipped assisted_review / expanded_review shape.
    if _SCOPE_KIND_RANK[scope_kind] < _SCOPE_KIND_RANK[llm.scope_ceiling]:
        return PrivacyOutcome.BLOCKED_BY_POLICY, PrivacyReason.SCOPE_MISMATCH
    return None


@dataclass(frozen=True, slots=True)
class SemanticEgressSuccess:
    """Terminal success: durable attempt receipt exists; judgment may steer a check."""

    request_id: str
    privacy_proposal_id: str
    authorization_id: str | None
    dispatch_kind: SemanticDispatchKind
    result: SemanticResultSuccess
    case_digest: str
    privacy_receipt_id: str | None = None
    request_commitment: str | None = None
    # What the exact prepared (bounded, minimized) review packet carried; None when that document
    # is not a readable review packet (issue #904).
    disclosure: ReviewPacketDisclosure | None = None
    # Opaque case item ids withheld by the low-confidence secret-assignment heuristic. The caller
    # can map these ids to authorized source references from its frozen case; no matched bytes or
    # user prose cross this boundary.
    withheld_item_ids: tuple[str, ...] = ()
    # A successful provider call may lack the exact provider-bound input manifest.  Keep the
    # bounded reason so the check can disclose provenance loss without substituting the composed
    # pre-admission manifest.
    provider_input_manifest_failure: str | None = None
    redacted_span_count: int = 0
    # PL2-1: bounded item refs and line numbers of replaced or withheld values, never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        _validate_withheld_item_ids(self.withheld_item_ids)
        validate_semantic_redacted_values(self.redacted_values)
        if self.provider_input_manifest_failure is not None and (
            self.provider_input_manifest_failure not in SEMANTIC_PROVIDER_INPUT_MANIFEST_FAILURES
        ):
            raise ValueError("provider_input_manifest_failure_invalid")
        if self.disclosure is not None and self.disclosure.provider_input_manifest is not None:
            if self.provider_input_manifest_failure is not None:
                raise ValueError("provider_input_manifest_failure_invalid")
        if type(self.redacted_span_count) is not int or self.redacted_span_count < 0:
            raise ValueError("semantic_redacted_span_count_invalid")


@dataclass(frozen=True, slots=True)
class SemanticEgressAwaitingHuman:
    """Nonterminal: exact prepared case awaits local human decision; no findings."""

    request_id: str
    privacy_proposal_id: str
    subject_digest: str
    expires_at: datetime
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # PL2-1: bounded item refs and line numbers of replaced or withheld values, never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        _validate_withheld_item_ids(self.withheld_item_ids)
        validate_semantic_redacted_values(self.redacted_values)
        if type(self.redacted_span_count) is not int or self.redacted_span_count < 0:
            raise ValueError("semantic_redacted_span_count_invalid")


@dataclass(frozen=True, slots=True)
class SemanticEgressAttemptUnknown:
    """Terminal recovery fact: an admitted attempt has no reusable result yet."""

    request_id: str
    privacy_proposal_id: str
    receipt_id: str | None = None
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # PL2-1: bounded item refs and line numbers of replaced or withheld values, never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        _validate_withheld_item_ids(self.withheld_item_ids)
        validate_semantic_redacted_values(self.redacted_values)
        if type(self.redacted_span_count) is not int or self.redacted_span_count < 0:
            raise ValueError("semantic_redacted_span_count_invalid")


@dataclass(frozen=True, slots=True)
class SemanticEgressBlocked:
    """Terminal pre-dispatch or human denial/expiry; never invents AI-powered findings."""

    request_id: str
    outcome: PrivacyOutcome
    reason: PrivacyReason
    privacy_proposal_id: str | None = None
    receipt_id: str | None = None
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # PL2-1: bounded item refs and line numbers of replaced or withheld values, never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        _validate_withheld_item_ids(self.withheld_item_ids)
        validate_semantic_redacted_values(self.redacted_values)
        if type(self.redacted_span_count) is not int or self.redacted_span_count < 0:
            raise ValueError("semantic_redacted_span_count_invalid")


@dataclass(frozen=True, slots=True)
class SemanticEgressProviderOutcome:
    """Terminal provider attempt that is not a usable success (refuse/timeout/invalid/…)."""

    request_id: str
    privacy_proposal_id: str
    authorization_id: str | None
    dispatch_kind: SemanticDispatchKind
    result: (
        SemanticResultRefused
        | SemanticResultTimeout
        | SemanticResultInvalid
        | SemanticResultLate
        | SemanticResultUnavailable
    )
    case_digest: str
    privacy_receipt_id: str | None = None
    request_commitment: str | None = None
    withheld_item_ids: tuple[str, ...] = ()
    redacted_span_count: int = 0
    # PL2-1: bounded item refs and line numbers of replaced or withheld values, never values.
    redacted_values: tuple[SemanticRedactedValue, ...] = ()

    def __post_init__(self) -> None:
        _validate_withheld_item_ids(self.withheld_item_ids)
        validate_semantic_redacted_values(self.redacted_values)
        if type(self.redacted_span_count) is not int or self.redacted_span_count < 0:
            raise ValueError("semantic_redacted_span_count_invalid")


type SemanticEgressResult = (
    SemanticEgressSuccess
    | SemanticEgressAwaitingHuman
    | SemanticEgressAttemptUnknown
    | SemanticEgressBlocked
    | SemanticEgressProviderOutcome
)


def _semantic_result_outcome(
    result: SemanticResult,
) -> tuple[PrivacyOutcome, PrivacyReason | None]:
    if type(result) is SemanticResultSuccess:
        return PrivacyOutcome.COMPLETED, None
    if type(result) is SemanticResultRefused:
        return PrivacyOutcome.PROVIDER_REFUSED, PrivacyReason.PROVIDER_REFUSED
    if type(result) is SemanticResultTimeout:
        return PrivacyOutcome.TIMEOUT, PrivacyReason.PROVIDER_TIMEOUT
    if type(result) is SemanticResultInvalid:
        return PrivacyOutcome.INVALID_RESPONSE, PrivacyReason.PROVIDER_INVALID_RESPONSE
    if type(result) is SemanticResultLate:
        return PrivacyOutcome.LATE, PrivacyReason.LATE
    if type(result) is SemanticResultUnavailable:
        return PrivacyOutcome.TRANSPORT_FAILED, PrivacyReason.TRANSPORT_FAILED
    raise TypeError("semantic_egress_result_invalid")


def _semantic_local_receipt(
    candidate: CandidateContext,
    effective: EffectivePrivacyPolicy,
    proposal: DisclosureProposal,
    minimized: MinimizedDisclosure,
    consent: ConsentSource,
    outcome: PrivacyOutcome,
    reason: PrivacyReason | None,
    finished_at: datetime,
    ids: IdPort,
) -> LocalDisclosureReceipt:
    included_count = len(minimized.included_item_ids)
    candidate_count = len(minimized.source_item_digests)
    omitted_count = max(0, candidate_count - included_count)
    return LocalDisclosureReceipt(
        "1.1.0",
        ids.new(IdKind.EGRESS_RECEIPT),
        candidate.request_id,
        proposal.privacy_proposal_id,
        LocalDisclosureSink.LOCAL_MODEL,
        outcome,
        finished_at,
        candidate.scope,
        candidate.purpose,
        ReceiptPolicyBinding(
            effective.policy.policy_id,
            effective.policy.version,
            effective.effective_digest,
            _scope_digest(candidate.scope),
        ),
        consent,
        minimized.approved_categories,
        minimized.blocked_categories,
        ReceiptCounts(
            candidate_count,
            included_count,
            omitted_count,
            included_count,
            omitted_count,
            minimized.byte_count,
            minimized.byte_count,
            minimized.token_count,
            None,
        ),
        ReceiptTransformations(
            omitted_count,
            minimized.redacted_span_count,
            omitted_count,
        ),
        ReceiptSecretScan(
            minimized.scanner_registry_version,
            minimized.scanner_profile_digest,
            len(set(minimized.forbidden_findings) | set(minimized.heuristic_findings)),
            not (minimized.forbidden_findings or minimized.heuristic_findings),
            ReceiptSecretScanStage.RENDERED_BODY,
        ),
        reason,
        1,
        withheld_item_ids=minimized.withheld_item_ids,
    )


@dataclass(frozen=True, slots=True)
class _LocalCeiling:
    categories: frozenset[DataCategory]
    data_classes: frozenset[DataClass]


class PrivacyCoordinator:
    """One central admission path for local disclosure and AI-powered review egress."""

    __slots__ = (
        "_audit",
        "_admission_lock",
        "_classifier",
        "_clock",
        "_close_lock",
        "_close_task",
        "_closed",
        "_data_use_resolver",
        "_gateway",
        "_human",
        "_human_authority",
        "_ids",
        "_policies",
        "_policy_app",
        "_service_generation",
        "_semantic_dispatch_guard",
    )

    def __init__(
        self,
        policies: PrivacyPolicyStorePort,
        classifier: PrivacyClassifierPort,
        audit: PrivacyAuditPort,
        gateway: OutboundGatewayPort,
        clock: ClockPort,
        ids: IdPort,
        *,
        service_generation: int = 1,
        human: HumanPrivacyControlPort | None = None,
        human_authority: HumanAuthorityCapability | None = None,
        data_use_resolver: Callable[[ProviderBinding], ProviderDataUseProfile | None] | None = None,
    ) -> None:
        if type(service_generation) is not int or service_generation <= 0:
            raise ValueError("privacy_service_generation_invalid")
        self._policies = policies
        self._classifier = classifier
        self._audit = audit
        self._admission_lock = asyncio.Lock()
        self._gateway = gateway
        self._clock = clock
        self._ids = ids
        self._service_generation = service_generation
        self._human = human
        self._human_authority = human_authority
        self._data_use_resolver = data_use_resolver
        self._policy_app: PrivacyPolicyApplication | None = None
        self._closed = False
        self._close_lock = asyncio.Lock()
        self._close_task: asyncio.Task[None] | None = None
        self._semantic_dispatch_guard: Callable[[], Awaitable[bool] | bool] | None = None

    @property
    def policy_application(self) -> PrivacyPolicyApplication | None:
        return self._policy_app

    def bind_policy_application(self, app: PrivacyPolicyApplication) -> None:
        self._policy_app = app

    async def activate_repository(self, scope: AuthorizationScope) -> bool:
        """Lazily activate only the exact repository authority named by a trusted task route."""

        async with self._admission_lock:
            if self._closed:
                return False
            return await self._activate_repository_admitted(scope) is not None

    async def admit_repository_grant(self, scope: AuthorizationScope) -> RepositoryGrantAdmission:
        """Classify and activate exact repository authority under the closure fence.

        This is the only API that may authorize the repository-setup continuation.  It shares the
        coordinator admission lock with ``close`` and AI-powered review dispatch, so a closed coordinator
        or a close racing this lookup is never reported as an actionable missing-grant handoff.
        """

        async with self._admission_lock:
            if self._closed:
                return RepositoryGrantAdmission.UNAVAILABLE
            authority = await self._repository_authority_admitted(scope)
            if authority is None:
                return RepositoryGrantAdmission.UNAVAILABLE
            if authority.grant_state == "missing":
                return RepositoryGrantAdmission.MISSING
            if authority.grant_state != "granted":
                return RepositoryGrantAdmission.UNAVAILABLE
            activated = await self._activate_repository_from_authority_admitted(authority, scope)
            return (
                RepositoryGrantAdmission.GRANTED
                if activated is not None
                else RepositoryGrantAdmission.UNAVAILABLE
            )

    async def evaluate_semantic(
        self,
        candidate: CandidateContext,
        deadline: Deadline,
        *,
        dispatch_guard: Callable[[], Awaitable[bool] | bool] | None = None,
    ) -> SemanticEgressResult:
        if type(candidate) is not CandidateContext or type(deadline) is not Deadline:
            raise TypeError("semantic_egress_arguments_invalid")
        async with self._admission_lock:
            if self._closed:
                return SemanticEgressBlocked(
                    candidate.request_id,
                    PrivacyOutcome.CHANNEL_UNAVAILABLE,
                    PrivacyReason.CHANNEL_UNAVAILABLE,
                )
            prior_guard = self._semantic_dispatch_guard
            self._semantic_dispatch_guard = dispatch_guard
            try:
                return await self._evaluate_semantic_admitted(candidate, deadline)
            finally:
                self._semantic_dispatch_guard = prior_guard

    async def resume(
        self,
        request_id: str,
        case_digest: str,
        deadline: Deadline,
        *,
        dispatch_guard: Callable[[], Awaitable[bool] | bool] | None = None,
    ) -> SemanticEgressResult:
        if (
            type(request_id) is not str
            or type(case_digest) is not str
            or type(deadline) is not Deadline
        ):
            raise TypeError("semantic_egress_resume_invalid")
        async with self._admission_lock:
            if self._closed:
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.CHANNEL_UNAVAILABLE,
                    PrivacyReason.CHANNEL_UNAVAILABLE,
                )
            prior_guard = self._semantic_dispatch_guard
            self._semantic_dispatch_guard = dispatch_guard
            try:
                return await self._resume_admitted(request_id, case_digest, deadline)
            finally:
                self._semantic_dispatch_guard = prior_guard

    async def recover_started_attempt(
        self,
        request_id: str,
        case_digest: str,
        deadline: Deadline,
        *,
        dispatch_guard: Callable[[], Awaitable[bool] | bool] | None = None,
    ) -> SemanticEgressResult | None:
        """Recover a started physical attempt without minting another authorization.

        ``None`` means the exact request/case has no durable disclosure reservation, so the
        caller may continue evaluating this same physical attempt. Any existing reservation is
        handled through the exact proposal/subject identity; an already-consumed reservation is
        terminally unknown and never re-enters the provider gateway.
        """

        if (
            type(request_id) is not str
            or type(case_digest) is not str
            or type(deadline) is not Deadline
        ):
            raise TypeError("semantic_egress_recovery_invalid")
        async with self._admission_lock:
            if self._closed:
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.CHANNEL_UNAVAILABLE,
                    PrivacyReason.CHANNEL_UNAVAILABLE,
                )
            prior_guard = self._semantic_dispatch_guard
            self._semantic_dispatch_guard = dispatch_guard
            try:
                state = await self._load_disclosure_attempt(request_id, case_digest)
                if state is None:
                    return None
                if state.status in {
                    "receipt_pending",
                    "attempt_completed",
                    "local_disclosure_pending",
                    "local_disclosure_completed",
                }:
                    withheld_item_ids = await self._withheld_item_ids_for_proposal(
                        state.reservation.privacy_proposal_id
                    )
                    redacted_span_count = await self._redacted_span_count_for_proposal(
                        state.reservation.privacy_proposal_id
                    )
                    redacted_values = await self._redacted_values_for_proposal(
                        state.reservation.privacy_proposal_id
                    )
                    return SemanticEgressAttemptUnknown(
                        request_id,
                        state.reservation.privacy_proposal_id,
                        state.receipt_id,
                        withheld_item_ids,
                        redacted_span_count,
                        redacted_values,
                    )
                return await self._resume_admitted(
                    request_id,
                    case_digest,
                    deadline,
                    loaded_state=state,
                )
            finally:
                self._semantic_dispatch_guard = prior_guard

    async def recover_started_request(self, request_id: str) -> SemanticEgressAttemptUnknown | None:
        """Report the terminal state of one started attempt by its request identity alone.

        A cancelled background advisory dispatch never observes the prepared case digest, but it
        owns the exact request identity it minted. ``None`` means no durable disclosure
        reservation reached the consume CAS for that request, so no authority was spent. A
        consumed reservation is terminally unknown: this never resumes, redispatches, mints an
        authorization, or converts the attempt into a success. An audit that cannot be read
        raises instead of answering ``None``: it cannot establish that no authority was spent,
        so the caller keeps the call's usage unknown (#923).
        """

        if type(request_id) is not str:
            raise TypeError("semantic_egress_recovery_invalid")
        async with self._admission_lock:
            state = await self._load_started_disclosure_attempt(request_id)
            if state is None or state.status not in {
                "receipt_pending",
                "attempt_completed",
                "local_disclosure_pending",
                "local_disclosure_completed",
            }:
                return None
            withheld_item_ids = await self._withheld_item_ids_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_span_count = await self._redacted_span_count_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_values = await self._redacted_values_for_proposal(
                state.reservation.privacy_proposal_id
            )
            return SemanticEgressAttemptUnknown(
                request_id,
                state.reservation.privacy_proposal_id,
                state.receipt_id,
                withheld_item_ids,
                redacted_span_count,
                redacted_values,
            )

    async def reconcile_started_attempts(
        self, consumed_before: datetime, *, limit: int = 64
    ) -> int:
        """Terminalize attempts left nonterminal by an earlier service generation.

        Bounded and idempotent startup reconciliation. The audit records the exact
        ``transport_failed/outcome_unknown`` receipt the admitted attempt already owed; no
        provider is re-entered and no authority is minted or restored.
        """

        if type(consumed_before) is not datetime or type(limit) is not int or limit < 1:
            raise TypeError("semantic_egress_reconcile_invalid")
        reconciler = getattr(self._audit, "reconcile_started_attempts", None)
        if not callable(reconciler):
            return 0
        typed_reconciler = cast(
            Callable[[datetime, int], Awaitable[int]],
            reconciler,
        )
        try:
            return await typed_reconciler(consumed_before, limit)
        except Exception as exc:  # noqa: BLE001 - startup reconciliation is never fatal
            record_unexpected_exception_without_raising(
                exc,
                component="privacy_egress",
                operation="audit_reconcile_started_attempts_failed",
            )
            return 0

    async def _load_started_disclosure_attempt(self, request_id: str) -> PrivacyAuditState | None:
        loader = getattr(self._audit, "load_started_disclosure_attempt", None)
        if not callable(loader):
            raise RuntimeError("privacy_audit_started_lookup_unavailable")
        typed_loader = cast(
            Callable[[str], Awaitable[PrivacyAuditState | None]],
            loader,
        )
        try:
            return await typed_loader(request_id)
        except Exception as exc:
            # Unreadable is not "never consumed": record it and let the caller keep the
            # attempt's usage unknown rather than reading this as proof nothing was sent (#923).
            record_unexpected_exception_without_raising(
                exc,
                component="privacy_egress",
                operation="audit_started_attempt_lookup_failed",
                request_id=request_id,
            )
            raise

    async def _load_disclosure_attempt(
        self, request_id: str, case_digest: str
    ) -> PrivacyAuditState | None:
        loader = getattr(self._audit, "load_disclosure_attempt", None)
        if callable(loader):
            typed_loader = cast(
                Callable[[str, str], Awaitable[PrivacyAuditState | None]],
                loader,
            )
            return await typed_loader(request_id, case_digest)
        raise ValueError("privacy_audit_attempt_lookup_unavailable")

    async def _load_disclosure_proposal(self, proposal_id: str) -> DisclosureProposal | None:
        try:
            proposal = await self._audit.load_disclosure_proposal(proposal_id)
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="privacy_egress",
                operation="audit_disclosure_proposal_lookup_failed",
            )
            raise
        return proposal if type(proposal) is DisclosureProposal else None

    async def _withheld_item_ids_for_proposal(self, proposal_id: str) -> tuple[str, ...]:
        """Recover bounded heuristic omission identities for terminal replay paths."""

        proposal = await self._load_disclosure_proposal(proposal_id)
        if proposal is None:
            raise RuntimeError("privacy_audit_proposal_unavailable")
        return proposal.withheld_item_ids

    async def _redacted_span_count_for_proposal(self, proposal_id: str) -> int:
        """Recover structural redaction accounting without reopening proposal plaintext."""

        proposal = await self._load_disclosure_proposal(proposal_id)
        if proposal is None:
            raise RuntimeError("privacy_audit_proposal_unavailable")
        return _transformation_count(proposal.transformation_summary, "redacted_spans")

    async def _redacted_values_for_proposal(
        self, proposal_id: str
    ) -> tuple[SemanticRedactedValue, ...]:
        """Recover the bounded PL2-1 item refs and lines persisted with the proposal."""

        proposal = await self._load_disclosure_proposal(proposal_id)
        if proposal is None:
            raise RuntimeError("privacy_audit_proposal_unavailable")
        return proposal.redacted_values

    async def _semantic_dispatch_is_current(self) -> bool:
        """Recheck a caller-owned content fence at the gateway boundary."""

        guard = self._semantic_dispatch_guard
        if guard is None:
            return True
        try:
            result = guard()
            if isinstance(result, Awaitable):
                result = await result
            return result is True
        except Exception:
            return False

    async def prepare_local_disclosure(self, candidate: CandidateContext) -> LocalDisclosureResult:
        if type(candidate) is not CandidateContext or candidate.local_sink is None:
            raise TypeError("local_disclosure_candidate_invalid")
        async with self._admission_lock:
            if self._closed:
                return LocalDisclosureUnavailable(candidate.request_id, candidate.local_sink)
            return await self._prepare_local_disclosure_admitted(candidate)

    async def _prepare_local_disclosure_admitted(
        self, candidate: CandidateContext
    ) -> LocalDisclosureResult:
        sink = candidate.local_sink
        assert sink is not None
        effective = await self._policies.effective_policy(candidate.scope)
        classified = self._classifier.classify(candidate, effective)
        decision = self._local_decision(classified, effective)
        if decision.outcome is not PrivacyOutcome.COMPLETED:
            return await self._complete_local_block(
                classified,
                effective,
                decision,
                scan_stage=ReceiptSecretScanStage.CANDIDATE,
                scan_match_count=_classified_scan_match_count(classified),
                withheld_item_ids=_heuristic_only_item_ids(classified),
            )
        minimized = self._classifier.minimize_and_scan(classified, decision)
        if minimized.forbidden_findings or minimized.heuristic_findings:
            forbidden = PrivacyDecision(
                (),
                minimized.blocked_categories,
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyReason.NEVER_SEND_DETECTED,
            )
            return await self._complete_local_block(
                classified,
                effective,
                forbidden,
                scan_stage=ReceiptSecretScanStage.CANDIDATE,
                scan_match_count=len(
                    set(minimized.forbidden_findings) | set(minimized.heuristic_findings)
                ),
                withheld_item_ids=minimized.withheld_item_ids,
            )
        if not minimized.included_item_ids and classified.items:
            if candidate.purpose == "client_result_projection":
                return await self._complete_agent_projection(classified, effective, minimized)
            empty = PrivacyDecision(
                (),
                minimized.blocked_categories,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT,
            )
            return await self._complete_local_block(
                classified,
                effective,
                empty,
                scan_stage=ReceiptSecretScanStage.CANDIDATE,
                scan_match_count=len(
                    set(minimized.forbidden_findings) | set(minimized.heuristic_findings)
                ),
                withheld_item_ids=minimized.withheld_item_ids,
            )
        if candidate.purpose == "client_result_projection":
            return await self._complete_agent_projection(classified, effective, minimized)
        task_id = candidate.scope.task_id
        if task_id is None:
            return LocalDisclosureUnavailable(candidate.request_id, sink)
        now = self._clock.now_utc()
        prepared = await self._audit.prepare_disclosure_proposal(
            DisclosureProposalRequest(
                privacy_proposal_id=self._ids.new(IdKind.PRIVACY_PROPOSAL),
                request_id=candidate.request_id,
                task_id=task_id,
                minimized=minimized,
                provider_binding=None,
                local_sink=sink,
                purpose=candidate.purpose,
                scope=candidate.scope,
                policy_id=effective.policy.policy_id,
                policy_version=effective.policy.version,
                policy_generation=effective.generation,
                policy_digest=effective.effective_digest,
                max_bytes=minimized.byte_count,
                max_tokens=minimized.token_count,
                expires_at=now + timedelta(seconds=60),
            )
        )
        proposal = prepared.proposal
        await self._audit.consume_local(
            prepared.reservation.privacy_proposal_id,
            proposal.prepared_case_digest,
            now,
        )
        receipt = self._local_receipt(
            classified,
            effective,
            proposal.privacy_proposal_id,
            minimized.approved_categories,
            minimized.blocked_categories,
            minimized.scanner_registry_version,
            minimized.scanner_profile_digest,
            len(minimized.forbidden_findings),
            PrivacyOutcome.COMPLETED,
            None,
            ConsentSource.BASELINE_POLICY,
            minimized.byte_count,
            minimized.token_count,
            len(minimized.included_item_ids),
            withheld_item_ids=minimized.withheld_item_ids,
            redacted_spans=minimized.redacted_span_count,
        )
        await self._audit.complete_local_disclosure(proposal.privacy_proposal_id, receipt)
        included = set(minimized.included_item_ids)
        approved_items = tuple(
            sorted(
                (
                    ApprovedLocalItem(
                        _pointer(item.candidate.item_id, item.candidate.origin_ref),
                        item.candidate.category,
                        (
                            redact_heuristic_spans(item.candidate.plaintext)[0]
                            if item.heuristic_findings
                            else item.candidate.plaintext
                        ),
                    )
                    for item in classified.items
                    if item.candidate.item_id in included
                ),
                key=lambda item: item.json_pointer.encode(),
            )
        )
        omissions = _omissions(classified, included)
        return LocalDisclosureApproved(
            proposal.privacy_proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            effective.effective_digest,
            proposal.proposal_commitment,
            approved_items,
            omissions,
            receipt,
        )

    async def close(self) -> None:
        async with self._admission_lock:
            async with self._close_lock:
                if self._close_task is None:
                    self._closed = True
                    self._close_task = asyncio.create_task(self._gateway.close())
                task = self._close_task
        await task

    async def _evaluate_semantic_admitted(
        self, candidate: CandidateContext, deadline: Deadline
    ) -> SemanticEgressResult:
        if candidate.channel is None or candidate.local_sink is not None:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.CHANNEL_UNAVAILABLE,
                PrivacyReason.CHANNEL_UNAVAILABLE,
            )
        if candidate.channel is not EgressChannel.LLM_INFERENCE:
            return await self._complete_semantic_predispatch(
                candidate,
                await self._policies.effective_policy(candidate.scope),
                PrivacyOutcome.CHANNEL_UNAVAILABLE,
                PrivacyReason.CHANNEL_UNAVAILABLE,
            )
        if candidate.purpose not in {_SEMANTIC_PURPOSE, _CREDENTIAL_PROBE_PURPOSE}:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.PURPOSE_NOT_ALLOWED,
            )
        if candidate.provider_binding is None or candidate.subject_digest is None:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.CHANNEL_UNAVAILABLE,
                PrivacyReason.CHANNEL_UNAVAILABLE,
            )
        if deadline.expired(self._clock.monotonic_seconds()):
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.TIMEOUT,
                PrivacyReason.DEADLINE_EXPIRED,
            )

        effective = await self._policies.effective_policy(candidate.scope)
        authority_digest: str | None = None
        if candidate.provider_binding.transport == "external":
            activated = await self._activate_repository_admitted(candidate.scope)
            if activated is None:
                return await self._complete_semantic_predispatch(
                    candidate,
                    effective,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                )
            effective, authority_digest = activated
        return await self._semantic_pipeline(
            candidate, effective, deadline, authority_digest=authority_digest
        )

    async def _activate_repository_admitted(
        self, scope: AuthorizationScope
    ) -> tuple[EffectivePrivacyPolicy, str] | None:
        if scope.kind not in {AuthorizationScopeKind.TASK, AuthorizationScopeKind.REQUEST}:
            return None
        try:
            authority = await self._policies.repository_authority(scope)
        except Exception:
            return None
        return await self._activate_repository_from_authority_admitted(authority, scope)

    async def _repository_authority_admitted(
        self, scope: AuthorizationScope
    ) -> RepositoryPrivacyAuthority | None:
        if scope.kind not in {AuthorizationScopeKind.TASK, AuthorizationScopeKind.REQUEST}:
            return None
        try:
            authority = await self._policies.repository_authority(scope)
        except Exception:
            return None
        if (
            type(authority) is not RepositoryPrivacyAuthority
            or authority.scope != scope
            or authority.repository_privacy_commitment != scope.workspace_ref_commitment
        ):
            return None
        return authority

    async def _activate_repository_from_authority_admitted(
        self, authority: RepositoryPrivacyAuthority, scope: AuthorizationScope
    ) -> tuple[EffectivePrivacyPolicy, str] | None:
        effective = authority.effective
        authority_digest = authority.authority_digest
        repository = authority.repository_privacy_commitment
        if (
            authority.grant_state != "granted"
            or type(effective) is not EffectivePrivacyPolicy
            or repository != scope.workspace_ref_commitment
        ):
            return None
        reconcile = getattr(self._gateway, "reconcile_repository_policy", None)
        human_authority = self._human_authority
        if reconcile is None or type(human_authority) is not HumanAuthorityCapability:
            return None
        try:
            await reconcile(
                effective,
                human_authority,
                repository_privacy_commitment=repository,
                authority_digest=authority_digest,
            )
        except Exception:
            return None
        return effective, authority_digest

    async def _repository_authority_is_current(
        self, scope: AuthorizationScope, expected_authority_digest: str
    ) -> bool:
        try:
            authority = await self._policies.repository_authority(scope)
        except Exception:
            return False
        return (
            authority.grant_state == "granted"
            and authority.repository_privacy_commitment == scope.workspace_ref_commitment
            and authority.authority_digest == expected_authority_digest
        )

    async def _resume_admitted(
        self,
        request_id: str,
        case_digest: str,
        deadline: Deadline,
        *,
        loaded_state: PrivacyAuditState | None = None,
    ) -> SemanticEgressResult:
        state = (
            loaded_state
            if loaded_state is not None
            else await self._load_disclosure_attempt(request_id, case_digest)
        )
        if state is None:
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
            )
        status = state.status
        if status in {"reserved", "awaiting_human"}:
            pending = await self._load_disclosure_proposal(state.reservation.privacy_proposal_id)
            if (
                pending is None
                or pending.prepared_case_digest != case_digest
                or pending.privacy_proposal_id != state.reservation.privacy_proposal_id
                or pending.request_id != state.reservation.request_id
            ):
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.AUDIT_FAILED,
                    PrivacyReason.AUDIT_FAILED,
                    privacy_proposal_id=state.reservation.privacy_proposal_id,
                )
            if pending.expires_at <= self._clock.now_utc():
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.APPROVAL_EXPIRED,
                    PrivacyReason.AUTHORIZATION_EXPIRED,
                    privacy_proposal_id=state.reservation.privacy_proposal_id,
                    withheld_item_ids=pending.withheld_item_ids,
                    redacted_span_count=_transformation_count(
                        pending.transformation_summary, "redacted_spans"
                    ),
                    redacted_values=pending.redacted_values,
                )
            return SemanticEgressAwaitingHuman(
                request_id,
                state.reservation.privacy_proposal_id,
                state.reservation.subject_digest,
                pending.expires_at,
                pending.withheld_item_ids,
                _transformation_count(pending.transformation_summary, "redacted_spans"),
                pending.redacted_values,
            )
        if status in {"denied", "decision_receipt_pending", "expired", "decision_completed"}:
            withheld_item_ids = await self._withheld_item_ids_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_span_count = await self._redacted_span_count_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_values = await self._redacted_values_for_proposal(
                state.reservation.privacy_proposal_id
            )
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.HUMAN_DENIED
                if status in {"denied", "decision_receipt_pending"}
                else PrivacyOutcome.APPROVAL_EXPIRED
                if status == "expired"
                else PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.HUMAN_DENIED
                if status in {"denied", "decision_receipt_pending"}
                else PrivacyReason.AUTHORIZATION_EXPIRED
                if status == "expired"
                else PrivacyReason.POLICY_DENIED,
                privacy_proposal_id=state.reservation.privacy_proposal_id,
                receipt_id=state.receipt_id,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if status in {"receipt_pending", "attempt_completed"}:
            # Attempt already consumed; automatic retry requires a fresh evaluate_semantic.
            withheld_item_ids = await self._withheld_item_ids_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_span_count = await self._redacted_span_count_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_values = await self._redacted_values_for_proposal(
                state.reservation.privacy_proposal_id
            )
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.APPROVAL_EXPIRED,
                PrivacyReason.AUTHORIZATION_REUSED,
                privacy_proposal_id=state.reservation.privacy_proposal_id,
                receipt_id=state.receipt_id,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if status not in {"reserved", "approved", "authorized"}:
            withheld_item_ids = await self._withheld_item_ids_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_span_count = await self._redacted_span_count_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_values = await self._redacted_values_for_proposal(
                state.reservation.privacy_proposal_id
            )
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=state.reservation.privacy_proposal_id,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if deadline.expired(self._clock.monotonic_seconds()):
            withheld_item_ids = await self._withheld_item_ids_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_span_count = await self._redacted_span_count_for_proposal(
                state.reservation.privacy_proposal_id
            )
            redacted_values = await self._redacted_values_for_proposal(
                state.reservation.privacy_proposal_id
            )
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.TIMEOUT,
                PrivacyReason.DEADLINE_EXPIRED,
                privacy_proposal_id=state.reservation.privacy_proposal_id,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        proposal = await self._load_disclosure_proposal(state.reservation.privacy_proposal_id)
        if (
            proposal is None
            or proposal.prepared_case_digest != case_digest
            or proposal.privacy_proposal_id != state.reservation.privacy_proposal_id
            or proposal.request_id != state.reservation.request_id
        ):
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=state.reservation.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids if proposal is not None else (),
                redacted_span_count=(
                    _transformation_count(proposal.transformation_summary, "redacted_spans")
                    if proposal is not None
                    else 0
                ),
                redacted_values=proposal.redacted_values if proposal is not None else (),
            )
        try:
            effective = await self._policies.effective_policy(proposal.scope)
        except Exception:
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=_transformation_count(
                    proposal.transformation_summary, "redacted_spans"
                ),
                redacted_values=proposal.redacted_values,
            )
        redacted_span_count = _transformation_count(
            proposal.transformation_summary, "redacted_spans"
        )
        redacted_values = proposal.redacted_values
        # A prepared proposal is a one-use authorization for one policy, scanner and active
        # route.  Replaying its bytes under a different authority would bypass the current
        # classification/minimization pass even when the packet still fits today's size limits.
        if (
            proposal.policy_version != effective.policy.version
            or proposal.policy_digest != effective.effective_digest
        ):
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if proposal.route_identity_digest is None or (
            proposal.purpose == _SEMANTIC_PURPOSE and not proposal.included_item_ids
        ):
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        scanner_identity = _current_scanner_identity(self._classifier)
        if scanner_identity is None or scanner_identity != (
            proposal.scanner_registry_version,
            proposal.scanner_profile_digest,
        ):
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        prepared_findings = _resume_scan_is_clean(
            self._classifier,
            proposal.prepared_bytes,
            external_review_credential_heuristic(
                effective.policy, proposal.provider_binding, local_sink=proposal.local_sink
            ),
        )
        if prepared_findings is None:
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if prepared_findings:
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyReason.NEVER_SEND_DETECTED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        binding = proposal.provider_binding
        if binding is None and proposal.local_sink is LocalDisclosureSink.LOCAL_MODEL:
            # Local AF_UNIX AI-powered review resume needs the standing local-model binding.
            binding = effective.policy.local_model_binding
        if binding is None:
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=_transformation_count(
                    proposal.transformation_summary, "redacted_spans"
                ),
                redacted_values=proposal.redacted_values,
            )
        channel = (
            EgressChannel.LLM_INFERENCE
            if proposal.provider_binding is not None or binding.transport == "local_af_unix"
            else None
        )
        candidate = CandidateContext(
            request_id=request_id,
            channel=channel,
            local_sink=None if channel is not None else proposal.local_sink,
            purpose=proposal.purpose,
            scope=proposal.scope,
            subject_digest=case_digest,
            provider_binding=binding,
            items=(),
        )
        minimized = MinimizedDisclosure(
            prepared_bytes=proposal.prepared_bytes,
            included_item_ids=proposal.included_item_ids,
            source_item_digests=proposal.source_item_digests,
            approved_categories=proposal.approved_categories,
            blocked_categories=proposal.blocked_categories,
            transformation_summary=proposal.transformation_summary,
            byte_count=len(proposal.prepared_bytes),
            token_count=proposal.max_tokens,
            case_digest=proposal.prepared_case_digest,
            scanner_registry_version=proposal.scanner_registry_version,
            scanner_profile_digest=proposal.scanner_profile_digest,
            forbidden_findings=prepared_findings,
            withheld_item_ids=proposal.withheld_item_ids,
            redacted_span_count=redacted_span_count,
            redacted_values=redacted_values,
        )
        authority_digest: str | None = None
        if binding.transport == "external":
            activated = await self._activate_repository_admitted(candidate.scope)
            if activated is None:
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=proposal.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
            effective, authority_digest = activated
            if (
                proposal.policy_version != effective.policy.version
                or proposal.policy_digest != effective.effective_digest
            ):
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.POLICY_DENIED,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=proposal.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
        if _exceeds_current_limits(proposal, effective):
            # A proposal prepared before the policy narrowed must not reach a provider on resume:
            # its excerpts and bytes answer to the policy in force now (issue #907 Phase 1b).
            return SemanticEgressBlocked(
                request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=proposal.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        if status == "authorized":
            auth_id = state.authorization_id
            if type(auth_id) is not str:
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.AUDIT_FAILED,
                    PrivacyReason.AUDIT_FAILED,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=proposal.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
            try:
                authorization = await self._audit.load_authorization(auth_id)
            except Exception:
                authorization = None
            if authorization is None:
                return SemanticEgressBlocked(
                    request_id,
                    PrivacyOutcome.AUDIT_FAILED,
                    PrivacyReason.AUDIT_FAILED,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=proposal.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
            return await self._dispatch_approved(
                candidate,
                effective,
                proposal,
                minimized,
                ConsentSource.PER_REQUEST_LOCAL_HUMAN,
                deadline,
                subject_digest=state.reservation.subject_digest,
                authorization=authorization,
                authority_digest=authority_digest,
            )
        return await self._dispatch_approved(
            candidate,
            effective,
            proposal,
            minimized,
            ConsentSource.PER_REQUEST_LOCAL_HUMAN,
            deadline,
            subject_digest=state.reservation.subject_digest,
            authority_digest=authority_digest,
        )

    async def _semantic_pipeline(
        self,
        candidate: CandidateContext,
        effective: EffectivePrivacyPolicy,
        deadline: Deadline,
        *,
        authority_digest: str | None = None,
    ) -> SemanticEgressResult:
        policy = effective.policy
        binding = candidate.provider_binding
        assert binding is not None

        if candidate.channel is not EgressChannel.LLM_INFERENCE:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.CHANNEL_UNAVAILABLE,
                PrivacyReason.CHANNEL_UNAVAILABLE,
            )

        refusal = semantic_policy_refusal(policy, binding, candidate.purpose, candidate.scope.kind)
        if refusal is not None:
            return await self._complete_semantic_predispatch(
                candidate, effective, refusal[0], refusal[1]
            )
        if (
            policy.require_current_provider_data_use_evidence
            and binding.transport == "external"
            and not self._data_use_evidence_current(binding)
        ):
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
            )

        # Background advice has no human to preview it and no continuation to resume. Refuse it
        # before classification, so no proposal is reserved and the receipt asserts no category
        # approval, even if the policy changed after the service's own preflight (#1019).
        if (
            egress_origin_operation(candidate.purpose, (i.item_id for i in candidate.items))
            is EgressOriginOperation.OBSERVATION_ADVICE
        ):
            if semantic_preview_required(policy):
                return await self._complete_semantic_predispatch(
                    candidate,
                    effective,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.POLICY_DENIED,
                )
            if not advice_selection_is_current(candidate, policy):
                # Built for a review-context profile that is no longer in force; the next
                # admission rebuilds it from the current policy (#1019 r3).
                return await self._complete_semantic_predispatch(
                    candidate,
                    effective,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                )

        classified = self._classifier.classify(candidate, effective)
        decision = self._semantic_decision(classified, effective, binding)
        if decision.outcome is not PrivacyOutcome.COMPLETED:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                decision.outcome,
                decision.reason or PrivacyReason.POLICY_DENIED,
                decision=decision,
                scan_stage=ReceiptSecretScanStage.CANDIDATE,
                scan_match_count=_classified_scan_match_count(classified),
                withheld_item_ids=_heuristic_only_item_ids(classified),
            )

        minimized = self._classifier.minimize_and_scan(classified, decision)
        # Re-run policy intersection after preparation.
        if binding.transport == "external":
            if authority_digest is None or not await self._repository_authority_is_current(
                candidate.scope, authority_digest
            ):
                return await self._complete_semantic_predispatch(
                    candidate,
                    effective,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                    decision=decision,
                    withheld_item_ids=minimized.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                    scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                    scan_match_count=_minimized_scan_match_count(minimized),
                )
            refreshed = await self._activate_repository_admitted(candidate.scope)
            if refreshed is None or refreshed[1] != authority_digest:
                return await self._complete_semantic_predispatch(
                    candidate,
                    effective,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                    decision=decision,
                    withheld_item_ids=minimized.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                    scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                    scan_match_count=_minimized_scan_match_count(minimized),
                )
            effective = refreshed[0]
        else:
            effective = await self._policies.effective_policy(candidate.scope)
        if conversation_review_refuses(effective.policy, candidate.purpose):
            # The owner narrowed to local only while this case was being prepared.
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )
        # The first classification is only a preflight. Policy, repository authority, and the
        # scanner profile may have changed while that case was being prepared, so re-run the
        # complete classifier/minimizer against the effective state immediately before reserving
        # disclosure. A scanner-profile drift is a bounded fail-closed policy result; it never
        # silently reuses a stale prepared manifest.
        preflight_scanner = (
            minimized.scanner_registry_version,
            minimized.scanner_profile_digest,
        )
        refreshed_classified = self._classifier.classify(candidate, effective)
        refreshed_decision = self._semantic_decision(refreshed_classified, effective, binding)
        if refreshed_decision.outcome is not PrivacyOutcome.COMPLETED:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                refreshed_decision.outcome,
                refreshed_decision.reason or PrivacyReason.POLICY_DENIED,
                decision=refreshed_decision,
                scan_stage=ReceiptSecretScanStage.CANDIDATE,
                scan_match_count=_classified_scan_match_count(refreshed_classified),
                withheld_item_ids=_heuristic_only_item_ids(refreshed_classified),
            )
        refreshed_minimized = self._classifier.minimize_and_scan(
            refreshed_classified, refreshed_decision
        )
        if (
            refreshed_minimized.scanner_registry_version,
            refreshed_minimized.scanner_profile_digest,
        ) != preflight_scanner:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                decision=refreshed_decision,
                withheld_item_ids=refreshed_minimized.withheld_item_ids,
                redacted_span_count=refreshed_minimized.redacted_span_count,
                redacted_values=refreshed_minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(refreshed_minimized),
            )
        minimized = refreshed_minimized
        decision = refreshed_decision
        # Concrete credentials and scanner saturation still block the whole case. A heuristic
        # that survives into the prepared bytes means the omission construction was violated, so
        # the final prepared case also fails closed.
        if minimized.forbidden_findings or minimized.heuristic_findings:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyReason.NEVER_SEND_DETECTED,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )
        if not minimized.included_item_ids:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.INSUFFICIENT_APPROVED_CONTEXT,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )
        # Channel ceilings are operator-visible policy dimensions; fail closed when exceeded.
        llm = next(
            item
            for item in effective.policy.channel_policies
            if item.channel is EgressChannel.LLM_INFERENCE
        )
        if llm.max_bytes > 0 and minimized.byte_count > llm.max_bytes:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )
        if llm.max_tokens > 0 and minimized.token_count > llm.max_tokens:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )
        # The approved excerpt limits are authoritative here too: a review packet with more
        # excerpts, or more excerpt bytes, than the effective policy approved is refused whole,
        # never trimmed to fit (issue #907 Phase 1b).
        if candidate.purpose == _SEMANTIC_PURPOSE and not _within_excerpt_limits(
            minimized.prepared_bytes, effective.policy.review_selection
        ):
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.POLICY_DENIED,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )

        task_id = candidate.scope.task_id
        if task_id is None:
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.SCOPE_MISMATCH,
                decision=decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
                scan_match_count=_minimized_scan_match_count(minimized),
            )

        now = self._clock.now_utc()
        local_sink = (
            LocalDisclosureSink.LOCAL_MODEL if binding.transport == "local_af_unix" else None
        )
        provider_binding = binding if binding.transport == "external" else None
        # Authorization ceilings bind policy ∩ case (never case size alone).
        auth_max_bytes = (
            minimized.byte_count if llm.max_bytes <= 0 else min(llm.max_bytes, minimized.byte_count)
        )
        auth_max_tokens = (
            1
            if candidate.purpose == _CREDENTIAL_PROBE_PURPOSE
            else (
                minimized.token_count
                if llm.max_tokens <= 0
                else min(llm.max_tokens, minimized.token_count)
            )
        )
        try:
            prepared = await self._audit.prepare_disclosure_proposal(
                DisclosureProposalRequest(
                    privacy_proposal_id=self._ids.new(IdKind.PRIVACY_PROPOSAL),
                    request_id=candidate.request_id,
                    task_id=task_id,
                    minimized=minimized,
                    provider_binding=provider_binding,
                    local_sink=local_sink,
                    purpose=candidate.purpose,
                    scope=candidate.scope,
                    policy_id=effective.policy.policy_id,
                    policy_version=effective.policy.version,
                    policy_generation=effective.generation,
                    policy_digest=effective.effective_digest,
                    max_bytes=auth_max_bytes,
                    max_tokens=auth_max_tokens,
                    expires_at=now
                    + timedelta(seconds=max(60, llm.authorization_ttl_seconds or 60)),
                )
            )
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="privacy_egress",
                operation="audit_prepare_failed",
                request_id=candidate.request_id,
            )
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )

        proposal = prepared.proposal
        preview_required = semantic_preview_required(policy)
        subject_digest = prepared.reservation.subject_digest
        if preview_required:
            return await self._handle_human_gate(
                candidate,
                effective,
                proposal,
                minimized,
                subject_digest,
                deadline,
                authority_digest=authority_digest,
                category_decision=decision,
            )
        return await self._dispatch_approved(
            candidate,
            effective,
            proposal,
            minimized,
            ConsentSource.BASELINE_POLICY,
            deadline,
            subject_digest=subject_digest,
            authority_digest=authority_digest,
        )

    async def _handle_human_gate(
        self,
        candidate: CandidateContext,
        effective: EffectivePrivacyPolicy,
        proposal: DisclosureProposal,
        minimized: MinimizedDisclosure,
        subject_digest: str,
        deadline: Deadline,
        *,
        authority_digest: str | None,
        category_decision: PrivacyDecision,
    ) -> SemanticEgressResult:
        if self._human is None:
            try:
                await self._audit.mark_awaiting_human(proposal.privacy_proposal_id)
            except Exception:
                pass
            return SemanticEgressAwaitingHuman(
                candidate.request_id,
                proposal.privacy_proposal_id,
                subject_digest,
                proposal.expires_at,
                minimized.withheld_item_ids,
                minimized.redacted_span_count,
                minimized.redacted_values,
            )
        try:
            decision = await self._human.request_disclosure_decision(proposal)
        except Exception:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        if type(decision) is PendingHumanDecision:
            try:
                await self._audit.mark_awaiting_human(proposal.privacy_proposal_id)
            except Exception:
                pass
            return SemanticEgressAwaitingHuman(
                decision.request_id,
                decision.privacy_proposal_id,
                subject_digest,
                decision.expires_at,
                minimized.withheld_item_ids,
                minimized.redacted_span_count,
                minimized.redacted_values,
            )
        if type(decision) is not HumanPrivacyDecision or not decision.approved:
            try:
                if type(decision) is HumanPrivacyDecision:
                    await self._audit.record_human_decision(proposal.privacy_proposal_id, decision)
            except Exception:
                pass
            return await self._complete_semantic_predispatch(
                candidate,
                effective,
                PrivacyOutcome.HUMAN_DENIED,
                PrivacyReason.HUMAN_DENIED,
                proposal_id=proposal.privacy_proposal_id,
                decision=category_decision,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
                scan_stage=ReceiptSecretScanStage.PREPARED_CASE,
            )
        try:
            await self._audit.record_human_decision(proposal.privacy_proposal_id, decision)
        except Exception:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        return await self._dispatch_approved(
            candidate,
            effective,
            proposal,
            minimized,
            decision.consent_source,
            deadline,
            subject_digest=subject_digest,
            authority_digest=authority_digest,
        )

    async def _dispatch_approved(
        self,
        candidate: CandidateContext,
        effective: EffectivePrivacyPolicy,
        proposal: DisclosureProposal,
        minimized: MinimizedDisclosure,
        consent: ConsentSource,
        deadline: Deadline,
        *,
        subject_digest: str,
        authorization: object | None = None,
        authority_digest: str | None = None,
    ) -> SemanticEgressResult:
        binding = candidate.provider_binding
        assert binding is not None
        now = self._clock.now_utc()
        if proposal.expires_at <= now:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.APPROVAL_EXPIRED,
                PrivacyReason.AUTHORIZATION_EXPIRED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        if deadline.expired(self._clock.monotonic_seconds()):
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.TIMEOUT,
                PrivacyReason.DEADLINE_EXPIRED,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        # A caller-owned retained-content fence may have changed while policy, audit, or
        # human-approval work awaited. Check before minting any provider authorization, then
        # check again immediately before the gateway call below to cover the remaining race.
        if not await self._semantic_dispatch_is_current():
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.SCOPE_MISMATCH,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )

        if binding.transport == "local_af_unix":
            local_case = ApprovedLocalDisclosureCase(
                self._ids.new(IdKind.OUTBOUND_CASE),
                candidate.request_id,
                proposal.privacy_proposal_id,
                proposal.prepared_bytes,
                _MEDIA_TYPE,
                minimized.included_item_ids or proposal.included_item_ids,
                proposal.approved_categories,
                proposal.blocked_categories,
                len(proposal.prepared_bytes),
                proposal.max_tokens,
                LocalDisclosureSink.LOCAL_MODEL,
                binding,
                candidate.purpose,
                effective.effective_digest,
                proposal.prepared_case_digest,
                minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
            )
            if not await self._semantic_dispatch_is_current():
                return SemanticEgressBlocked(
                    candidate.request_id,
                    PrivacyOutcome.BLOCKED_BY_POLICY,
                    PrivacyReason.SCOPE_MISMATCH,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=minimized.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
            try:
                result = await self._gateway.dispatch_local_semantic(local_case, deadline)
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="semantic_provider",
                    operation="semantic_provider_invocation_failed",
                    request_id=semantic_check_request.get() or candidate.request_id,
                )
                return SemanticEgressBlocked(
                    candidate.request_id,
                    PrivacyOutcome.TRANSPORT_FAILED,
                    PrivacyReason.OUTCOME_UNKNOWN,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=minimized.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
            outcome, reason = _semantic_result_outcome(result)
            receipt = _semantic_local_receipt(
                candidate,
                effective,
                proposal,
                minimized,
                consent,
                outcome,
                reason,
                self._clock.now_utc(),
                self._ids,
            )
            try:
                await self._audit.complete_local_disclosure(proposal.privacy_proposal_id, receipt)
            except Exception:
                pass
            return await self._map_provider_result(
                candidate.request_id,
                proposal.privacy_proposal_id,
                None,
                SemanticDispatchKind.LOCAL_MODEL,
                proposal.prepared_case_digest,
                subject_digest,
                result,
                prepared_bytes=proposal.prepared_bytes,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )

        if authority_digest is None or not await self._repository_authority_is_current(
            candidate.scope, authority_digest
        ):
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.SCOPE_MISMATCH,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )

        minted: EgressAuthorization
        if type(authorization) is EgressAuthorization:
            minted = authorization
        else:
            try:
                minted = await self._audit.authorize(
                    proposal.privacy_proposal_id, proposal.prepared_case_digest, now
                )
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="privacy_egress",
                    operation="audit_authorize_failed",
                    request_id=candidate.request_id,
                )
                return SemanticEgressBlocked(
                    candidate.request_id,
                    PrivacyOutcome.AUDIT_FAILED,
                    PrivacyReason.AUDIT_FAILED,
                    privacy_proposal_id=proposal.privacy_proposal_id,
                    withheld_item_ids=minimized.withheld_item_ids,
                    redacted_span_count=minimized.redacted_span_count,
                    redacted_values=minimized.redacted_values,
                )
        authorization = minted
        case = ApprovedOutboundCase(
            self._ids.new(IdKind.OUTBOUND_CASE),
            candidate.request_id,
            proposal.prepared_bytes,
            _MEDIA_TYPE,
            _SCHEMA_ID,
            minimized.included_item_ids,
            proposal.approved_categories,
            proposal.blocked_categories,
            len(proposal.prepared_bytes),
            proposal.max_tokens,
            binding,
            candidate.purpose,
            authorization.authorization_id,
            effective.effective_digest,
            proposal.prepared_case_digest,
            minimized.withheld_item_ids,
            redacted_span_count=minimized.redacted_span_count,
            credential_heuristic=external_review_credential_heuristic(effective.policy, binding),
        )
        if not await self._semantic_dispatch_is_current():
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.SCOPE_MISMATCH,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        try:
            result = await self._gateway.dispatch_external_semantic(case, authorization, deadline)
        except Exception as exc:
            record_unexpected_exception_without_raising(
                exc,
                component="semantic_provider",
                operation="semantic_provider_invocation_failed",
                request_id=semantic_check_request.get() or candidate.request_id,
            )
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.TRANSPORT_FAILED,
                PrivacyReason.OUTCOME_UNKNOWN,
                privacy_proposal_id=proposal.privacy_proposal_id,
                withheld_item_ids=minimized.withheld_item_ids,
                redacted_span_count=minimized.redacted_span_count,
                redacted_values=minimized.redacted_values,
            )
        dispatch_kind = (
            SemanticDispatchKind.EXTERNAL_RUNTIME_OAUTH
            if result.provenance.runtime_evidence is not None
            else SemanticDispatchKind.EXTERNAL
        )
        return await self._map_provider_result(
            candidate.request_id,
            proposal.privacy_proposal_id,
            authorization.authorization_id,
            dispatch_kind,
            proposal.prepared_case_digest,
            subject_digest,
            result,
            prepared_bytes=proposal.prepared_bytes,
            withheld_item_ids=minimized.withheld_item_ids,
            redacted_span_count=minimized.redacted_span_count,
            redacted_values=minimized.redacted_values,
        )

    async def _map_provider_result(
        self,
        request_id: str,
        privacy_proposal_id: str,
        authorization_id: str | None,
        dispatch_kind: SemanticDispatchKind,
        case_digest: str,
        subject_digest: str,
        result: SemanticResult,
        *,
        prepared_bytes: bytes | None = None,
        withheld_item_ids: tuple[str, ...] = (),
        redacted_span_count: int = 0,
        redacted_values: tuple[SemanticRedactedValue, ...] = (),
    ) -> SemanticEgressResult:
        receipt_id: str | None = None
        try:
            state = await self._audit.load(request_id, subject_digest)
            if state is not None:
                receipt_id = state.receipt_id
        except Exception:
            receipt_id = None
        request_commitment = getattr(result.provenance, "request_commitment", None)
        if type(result) is SemanticResultSuccess:
            from finishup.application.semantic_case import review_packet_disclosure_result

            disclosure_result = (
                None if prepared_bytes is None else review_packet_disclosure_result(prepared_bytes)
            )

            return SemanticEgressSuccess(
                request_id,
                privacy_proposal_id,
                authorization_id,
                dispatch_kind,
                result,
                case_digest,
                privacy_receipt_id=receipt_id,
                request_commitment=request_commitment,
                # What the provider actually received: the exact prepared bytes after envelope
                # bounding and privacy minimization, never the pre-minimization case.
                disclosure=None if disclosure_result is None else disclosure_result.disclosure,
                withheld_item_ids=tuple(sorted(set(withheld_item_ids), key=str.encode)),
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
                provider_input_manifest_failure=(
                    SEMANTIC_PROVIDER_INPUT_MANIFEST_MISSING_GAP
                    if disclosure_result is None
                    else disclosure_result.failure
                ),
            )
        if type(result) in {
            SemanticResultRefused,
            SemanticResultTimeout,
            SemanticResultInvalid,
            SemanticResultLate,
            SemanticResultUnavailable,
        }:
            return SemanticEgressProviderOutcome(
                request_id,
                privacy_proposal_id,
                authorization_id,
                dispatch_kind,
                result,  # type: ignore[arg-type]
                case_digest,
                privacy_receipt_id=receipt_id,
                request_commitment=request_commitment,
                withheld_item_ids=tuple(sorted(set(withheld_item_ids), key=str.encode)),
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        return SemanticEgressBlocked(
            request_id,
            PrivacyOutcome.TRANSPORT_FAILED,
            PrivacyReason.OUTCOME_UNKNOWN,
            privacy_proposal_id=privacy_proposal_id,
            receipt_id=receipt_id,
            withheld_item_ids=tuple(sorted(set(withheld_item_ids), key=str.encode)),
            redacted_span_count=redacted_span_count,
            redacted_values=redacted_values,
        )

    def _data_use_evidence_current(self, binding: ProviderBinding) -> bool:
        """True when the bound external profile has current recommendation-eligible data-use."""

        resolver = self._data_use_resolver
        if resolver is None:
            return False
        profile = resolver(binding)
        if type(profile) is not ProviderDataUseProfile:
            return False
        return profile.recommendation_eligible(self._clock.now_utc())

    def _semantic_decision(
        self,
        classified: ClassifiedContext,
        effective: EffectivePrivacyPolicy,
        binding: ProviderBinding,
    ) -> PrivacyDecision:
        policy = effective.policy
        llm = next(
            item for item in policy.channel_policies if item.channel is EgressChannel.LLM_INFERENCE
        )
        if binding.transport == "local_af_unix":
            if not policy.local_model_enabled:
                return PrivacyDecision(
                    (), (), PrivacyOutcome.CHANNEL_UNAVAILABLE, PrivacyReason.CHANNEL_UNAVAILABLE
                )
            ceiling = _LocalCeiling(
                frozenset(policy.local_model_categories),
                frozenset(policy.local_model_data_classes),
            )
        else:
            ceiling = _LocalCeiling(
                frozenset(llm.allowed_categories), frozenset(llm.allowed_data_classes)
            )
        if any(item.forbidden_findings for item in classified.items):
            return PrivacyDecision(
                (),
                tuple(
                    {
                        item.candidate.category
                        for item in classified.items
                        if item.forbidden_findings
                    }
                ),
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyReason.NEVER_SEND_DETECTED,
            )
        if any(not item.scope_valid for item in classified.items):
            return PrivacyDecision(
                (),
                tuple(
                    {item.candidate.category for item in classified.items if not item.scope_valid}
                ),
                PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
                PrivacyReason.CLASSIFICATION_UNCERTAIN,
            )
        approved = tuple(
            item.candidate.item_id
            for item in classified.items
            if item.candidate.category in ceiling.categories
            and item.data_class in ceiling.data_classes
            and item.data_class is not DataClass.SECRET_OR_CRYPTOGRAPHIC
            and item.scope_valid
            and not item.forbidden_findings
        )
        blocked = tuple(
            {
                item.candidate.category
                for item in classified.items
                if item.candidate.item_id not in approved
            }
        )
        if not approved and classified.items:
            return PrivacyDecision(
                (),
                blocked,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.CATEGORY_NOT_ALLOWED,
            )
        return PrivacyDecision(approved, blocked, PrivacyOutcome.COMPLETED, None)

    async def _complete_semantic_predispatch(
        self,
        candidate: CandidateContext,
        effective: EffectivePrivacyPolicy,
        outcome: PrivacyOutcome,
        reason: PrivacyReason,
        *,
        proposal_id: str | None = None,
        decision: PrivacyDecision | None = None,
        withheld_item_ids: tuple[str, ...] = (),
        redacted_span_count: int = 0,
        redacted_values: tuple[SemanticRedactedValue, ...] = (),
        scan_stage: ReceiptSecretScanStage = ReceiptSecretScanStage.NOT_RUN,
        scan_match_count: int = 0,
        scan_not_run_reason: PrivacyReason | None = None,
    ) -> SemanticEgressBlocked:
        now = self._clock.now_utc()
        pid = proposal_id or self._ids.new(IdKind.PRIVACY_PROPOSAL)
        binding = candidate.provider_binding
        destination: ProviderBinding | None = (
            binding if binding is not None and binding.transport == "external" else None
        )
        subject_digest = canonical_digest(
            {
                "outcome": outcome.value,
                "policy_digest": effective.effective_digest,
                "request_id": candidate.request_id,
                "channel": EgressChannel.LLM_INFERENCE.value,
            }
        )
        # Categories are a closed set of DataCategory values: unique and sorted for the
        # PreDispatchAuditDecision contract. Multiple case items may share one category.
        categories = tuple(
            sorted(
                {item.category for item in candidate.items},
                key=lambda value: str(value.value).encode("ascii"),
            )
        )
        # A request-level failure is not a category decision. Preserve only the classifier's
        # actual denial set; a missing/malformed envelope can discard approved content without
        # denying its category. Before classification, neither approval nor denial is asserted.
        blocked_categories = () if decision is None else decision.blocked_categories
        approved_ids = frozenset(() if decision is None else decision.approved_item_ids)
        blocked_count = sum(
            item.item_id not in approved_ids and item.category in blocked_categories
            for item in candidate.items
        )
        approved_categories = tuple(
            {item.category for item in candidate.items if item.item_id in approved_ids}
        )
        subject = PreDispatchAuditDecision(
            pid,
            candidate.request_id,
            EgressChannel.LLM_INFERENCE,
            None,
            candidate.purpose,
            candidate.scope,
            effective.policy.policy_id,
            effective.policy.version,
            effective.effective_digest,
            None if destination is None else canonical_digest({"binding": destination.provider_id}),
            categories,
            len(candidate.items),
            blocked_count,
            (),
            now,
            subject_digest,
            outcome,
            reason,
        )
        try:
            reservation = await self._audit.reserve(subject)
        except Exception:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=pid,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        if destination is None:
            # Structural channel/policy block without an exact external destination still receipts.
            destination = ProviderBinding(
                "unavailable",
                "unavailable",
                "unavailable",
                "1.0.0",
                "external",
            )
        receipt = EgressReceipt(
            "1.1.0",
            self._ids.new(IdKind.EGRESS_RECEIPT),
            candidate.request_id,
            pid,
            EgressChannel.LLM_INFERENCE,
            outcome,
            now,
            candidate.scope,
            candidate.purpose,
            destination,
            ReceiptPolicyBinding(
                effective.policy.policy_id,
                effective.policy.version,
                effective.effective_digest,
                _scope_digest(candidate.scope),
            ),
            ConsentSource.NONE,
            approved_categories,
            blocked_categories,
            ReceiptCounts(
                len(candidate.items),
                0,
                len(candidate.items),
                len(approved_ids),
                blocked_count,
                sum(len(item.plaintext) for item in candidate.items),
                0,
                None,
                None,
            ),
            ReceiptTransformations(len(candidate.items), redacted_span_count, blocked_count),
            ReceiptSecretScan(
                _SCAN.version,
                _SCAN.profile_digest,
                scan_match_count,
                scan_stage is not ReceiptSecretScanStage.NOT_RUN and scan_match_count == 0,
                scan_stage,
                (
                    (scan_not_run_reason or reason)
                    if scan_stage is ReceiptSecretScanStage.NOT_RUN
                    else None
                ),
                external_review_credential_heuristic(effective.policy, destination),
            ),
            reason,
            1,
            withheld_item_ids=withheld_item_ids,
            origin_operation=egress_origin_operation(
                candidate.purpose, (item.item_id for item in candidate.items)
            ),
        )
        try:
            await self._audit.complete_decision(reservation.privacy_proposal_id, receipt)
        except Exception:
            return SemanticEgressBlocked(
                candidate.request_id,
                PrivacyOutcome.AUDIT_FAILED,
                PrivacyReason.AUDIT_FAILED,
                privacy_proposal_id=pid,
                withheld_item_ids=withheld_item_ids,
                redacted_span_count=redacted_span_count,
                redacted_values=redacted_values,
            )
        return SemanticEgressBlocked(
            candidate.request_id,
            outcome,
            reason,
            privacy_proposal_id=pid,
            receipt_id=receipt.receipt_id,
            withheld_item_ids=withheld_item_ids,
            redacted_span_count=redacted_span_count,
            redacted_values=redacted_values,
        )

    def _local_decision(
        self, classified: ClassifiedContext, effective: EffectivePrivacyPolicy
    ) -> PrivacyDecision:
        sink = classified.candidate.local_sink
        assert sink is not None
        policy = effective.policy
        if not classified.items:
            return PrivacyDecision((), (), PrivacyOutcome.COMPLETED, None)
        is_projection = classified.candidate.purpose == "client_result_projection"
        if sink is LocalDisclosureSink.LOCAL_HUMAN_VIEW:
            ceiling = _LocalCeiling(
                frozenset(DataCategory),
                frozenset(
                    {
                        DataClass.PUBLIC_STRUCTURAL,
                        DataClass.ORDINARY_USER_CONTENT,
                        DataClass.SENSITIVE_CONFIDENTIAL,
                    }
                ),
            )
        elif sink is LocalDisclosureSink.AGENT_CONTEXT:
            ceiling = _LocalCeiling(
                frozenset(policy.agent_context_categories),
                frozenset(policy.agent_context_data_classes),
            )
        elif sink is LocalDisclosureSink.LOCAL_MODEL:
            if not policy.local_model_enabled:
                return PrivacyDecision(
                    (), (), PrivacyOutcome.CHANNEL_UNAVAILABLE, PrivacyReason.CHANNEL_UNAVAILABLE
                )
            ceiling = _LocalCeiling(
                frozenset(policy.local_model_categories),
                frozenset(policy.local_model_data_classes),
            )
        else:
            ceiling = _LocalCeiling(
                frozenset(policy.trusted_human_control_categories),
                frozenset(policy.trusted_human_control_data_classes),
            )
        if not is_projection and any(item.forbidden_findings for item in classified.items):
            return PrivacyDecision(
                (),
                tuple({item.candidate.category for item in classified.items}),
                PrivacyOutcome.BLOCKED_FORBIDDEN_DATA,
                PrivacyReason.NEVER_SEND_DETECTED,
            )
        if not is_projection and any(not item.scope_valid for item in classified.items):
            return PrivacyDecision(
                (),
                tuple(
                    {item.candidate.category for item in classified.items if not item.scope_valid}
                ),
                PrivacyOutcome.CLASSIFICATION_UNCERTAIN,
                PrivacyReason.CLASSIFICATION_UNCERTAIN,
            )
        approved = tuple(
            item.candidate.item_id
            for item in classified.items
            if (
                item.candidate.category in ceiling.categories
                or (
                    sink is LocalDisclosureSink.AGENT_CONTEXT
                    and item.provenance
                    in {
                        DisclosureProvenance.SELF_AUTHORED,
                        DisclosureProvenance.ENGINE_DERIVED_FROM_SELF_AUTHORED,
                    }
                )
            )
            and item.data_class in ceiling.data_classes
            and not (
                sink is LocalDisclosureSink.AGENT_CONTEXT
                and item.data_class is DataClass.SENSITIVE_CONFIDENTIAL
            )
            and item.data_class is not DataClass.SECRET_OR_CRYPTOGRAPHIC
            and item.scope_valid
            and not item.forbidden_findings
        )
        blocked = tuple(
            {
                item.candidate.category
                for item in classified.items
                if item.candidate.item_id not in approved
            }
        )
        if not approved and not is_projection:
            return PrivacyDecision(
                (),
                blocked,
                PrivacyOutcome.BLOCKED_BY_POLICY,
                PrivacyReason.CATEGORY_NOT_ALLOWED,
            )
        return PrivacyDecision(approved, blocked, PrivacyOutcome.COMPLETED, None)

    async def _complete_agent_projection(
        self,
        classified: ClassifiedContext,
        effective: EffectivePrivacyPolicy,
        minimized: MinimizedDisclosure,
    ) -> LocalDisclosureResult:
        candidate = classified.candidate
        sink = candidate.local_sink
        context = candidate.projection_audit_context
        assert sink is not None and context is not None
        proposal_id = self._ids.new(IdKind.PRIVACY_PROPOSAL)
        included = set(minimized.included_item_ids)
        approved_items = tuple(
            sorted(
                (
                    ApprovedLocalItem(
                        _pointer(item.candidate.item_id, item.candidate.origin_ref),
                        item.candidate.category,
                        (
                            redact_heuristic_spans(item.candidate.plaintext)[0]
                            if item.heuristic_findings
                            else item.candidate.plaintext
                        ),
                    )
                    for item in classified.items
                    if item.candidate.item_id in included
                ),
                key=lambda item: item.json_pointer.encode(),
            )
        )
        omissions = _omissions(classified, included)
        projected = canonical_encode(
            {
                "approved": [
                    {
                        "category": item.category.value,
                        "content_base64": base64.b64encode(item.bounded_bytes).decode("ascii"),
                        "pointer": item.json_pointer,
                    }
                    for item in approved_items
                ],
                "omissions": [
                    {
                        "category": item.category.value,
                        "pointer": item.json_pointer,
                        "reason": item.reason,
                    }
                    for item in omissions
                ],
                "schema": "yoetz.client-result-projection/1",
            }
        )
        receipt = self._local_receipt(
            classified,
            effective,
            proposal_id,
            minimized.approved_categories,
            minimized.blocked_categories,
            minimized.scanner_registry_version,
            minimized.scanner_profile_digest,
            sum(len(item.forbidden_findings) for item in classified.items)
            + len(minimized.forbidden_findings),
            PrivacyOutcome.COMPLETED,
            None,
            ConsentSource.BASELINE_POLICY,
            len(projected),
            minimized.token_count,
            len(included),
            withheld_item_ids=minimized.withheld_item_ids,
            redacted_spans=minimized.redacted_span_count,
        )
        field_decisions = tuple(
            sorted(
                (
                    (
                        _pointer(item.candidate.item_id, item.candidate.origin_ref),
                        item.candidate.category,
                        item.candidate.item_id in included,
                        (
                            None
                            if item.candidate.item_id in included
                            else "never_send_redacted"
                            if item.forbidden_findings
                            else "local_disclosure_not_authorized"
                        ),
                    )
                    for item in classified.items
                ),
                key=lambda value: value[0].encode(),
            )
        )
        try:
            completed = await self._audit.complete_agent_projection(
                AgentProjectionRequest(
                    proposal_id,
                    candidate.request_id,
                    context.rpc_id,
                    context.method,
                    context.service_instance_id,
                    context.service_generation,
                    context.original_request_id,
                    context.control_request_canonical,
                    candidate.scope,
                    candidate.scope.task_id,
                    context.route_identity_digest,
                    effective.policy.policy_id,
                    effective.policy.version,
                    effective.generation,
                    effective.effective_digest,
                    sink,
                    tuple(
                        sorted(
                            {
                                item.provenance
                                for item in classified.items
                                if item.provenance is not None
                            },
                            key=lambda value: value.value.encode(),
                        )
                    ),
                    context.internal_result_canonical,
                    projected,
                    field_decisions,
                    len(classified.items),
                    len(included),
                    len(classified.items) - len(included),
                    self._clock.now_utc(),
                ),
                receipt,
            )
        except Exception:
            return LocalDisclosureUnavailable(candidate.request_id, sink)
        return LocalDisclosureApproved(
            proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            effective.effective_digest,
            completed.subject.projection_commitment,
            approved_items,
            omissions,
            receipt,
        )

    async def _complete_local_block(
        self,
        classified: ClassifiedContext,
        effective: EffectivePrivacyPolicy,
        decision: PrivacyDecision,
        *,
        scan_stage: ReceiptSecretScanStage,
        scan_match_count: int,
        not_run_reason: PrivacyReason | None = None,
        withheld_item_ids: tuple[str, ...] = (),
    ) -> LocalDisclosureResult:
        candidate = classified.candidate
        sink = candidate.local_sink
        assert sink is not None
        now = self._clock.now_utc()
        proposal_id = self._ids.new(IdKind.PRIVACY_PROPOSAL)
        forbidden_counts = Counter(
            finding for item in classified.items for finding in item.forbidden_findings
        )
        subject_digest = canonical_digest(
            {
                "outcome": decision.outcome.value,
                "policy_digest": effective.effective_digest,
                "request_id": candidate.request_id,
                "sink": sink.value,
            }
        )
        subject = PreDispatchAuditDecision(
            proposal_id,
            candidate.request_id,
            None,
            sink,
            candidate.purpose,
            candidate.scope,
            effective.policy.policy_id,
            effective.policy.version,
            effective.effective_digest,
            None,
            tuple({item.candidate.category for item in classified.items}),
            len(classified.items),
            len(classified.items) - len(decision.approved_item_ids),
            tuple(sorted(forbidden_counts.items(), key=lambda item: item[0].value)),
            now,
            subject_digest,
            decision.outcome,
            decision.reason or PrivacyReason.POLICY_DENIED,
        )
        try:
            reservation = await self._audit.reserve(subject)
        except Exception:
            return LocalDisclosureUnavailable(candidate.request_id, sink)
        receipt = self._local_receipt(
            classified,
            effective,
            proposal_id,
            (),
            decision.blocked_categories,
            _SCAN.version,
            _SCAN.profile_digest,
            scan_match_count,
            decision.outcome,
            decision.reason,
            ConsentSource.NONE,
            0,
            0,
            0,
            scan_stage=scan_stage,
            not_run_reason=(
                not_run_reason if scan_stage is ReceiptSecretScanStage.NOT_RUN else None
            ),
            withheld_item_ids=withheld_item_ids,
        )
        await self._audit.complete_decision(reservation.privacy_proposal_id, receipt)
        omitted = _omissions(classified, set())
        return LocalDisclosureBlocked(
            proposal_id,
            candidate.request_id,
            sink,
            candidate.purpose,
            candidate.scope,
            effective.effective_digest,
            subject_digest,
            omitted,
            receipt,
        )

    def _local_receipt(
        self,
        classified: ClassifiedContext,
        effective: EffectivePrivacyPolicy,
        proposal_id: str,
        approved_categories: tuple[DataCategory, ...],
        blocked_categories: tuple[DataCategory, ...],
        scanner_version: str,
        scanner_digest: str,
        match_count: int,
        outcome: PrivacyOutcome,
        reason: PrivacyReason | None,
        consent: ConsentSource,
        final_bytes: int,
        tokens: int,
        included_count: int,
        scan_stage: ReceiptSecretScanStage = ReceiptSecretScanStage.PREPARED_CASE,
        not_run_reason: PrivacyReason | None = None,
        withheld_item_ids: tuple[str, ...] = (),
        redacted_spans: int = 0,
    ) -> LocalDisclosureReceipt:
        candidate = classified.candidate
        sink = candidate.local_sink
        assert sink is not None
        candidate_bytes = sum(len(item.candidate.plaintext) for item in classified.items)
        effective_not_run_reason = (
            not_run_reason or reason or PrivacyReason.POLICY_DENIED
            if scan_stage is ReceiptSecretScanStage.NOT_RUN
            else None
        )
        return LocalDisclosureReceipt(
            "1.1.0",
            self._ids.new(IdKind.EGRESS_RECEIPT),
            candidate.request_id,
            proposal_id,
            sink,
            outcome,
            self._clock.now_utc(),
            candidate.scope,
            candidate.purpose,
            ReceiptPolicyBinding(
                effective.policy.policy_id,
                effective.policy.version,
                effective.effective_digest,
                _scope_digest(candidate.scope),
            ),
            consent,
            approved_categories,
            blocked_categories,
            ReceiptCounts(
                len(classified.items),
                included_count,
                len(classified.items) - included_count,
                included_count,
                len(classified.items) - included_count,
                candidate_bytes,
                final_bytes,
                tokens,
                None,
            ),
            ReceiptTransformations(
                len(classified.items) - included_count,
                redacted_spans,
                len(classified.items) - included_count,
            ),
            ReceiptSecretScan(
                scanner_version,
                scanner_digest,
                match_count,
                scan_stage is not ReceiptSecretScanStage.NOT_RUN and match_count == 0,
                scan_stage,
                effective_not_run_reason,
                classified.credential_heuristic,
            ),
            reason,
            1,
            withheld_item_ids=withheld_item_ids,
        )


def _exceeds_current_limits(
    proposal: DisclosureProposal, effective: EffectivePrivacyPolicy
) -> bool:
    """Whether a stored review proposal is outside the excerpt limits or channel ceilings now."""

    if proposal.purpose != _SEMANTIC_PURPOSE:
        return False
    if not _within_excerpt_limits(proposal.prepared_bytes, effective.policy.review_selection):
        return True
    llm = next(
        (
            channel
            for channel in effective.policy.channel_policies
            if channel.channel is EgressChannel.LLM_INFERENCE
        ),
        None,
    )
    return llm is not None and (
        0 < llm.max_bytes < len(proposal.prepared_bytes) or 0 < llm.max_tokens < proposal.max_tokens
    )


def _within_excerpt_limits(prepared: bytes, selection: ReviewSelectionPolicy) -> bool:
    """Whether a prepared review packet stays inside the approved excerpt count and bytes.

    Counted off the exact bytes that would leave, from the packet's own ``excerpt`` rows; a
    document without item rows carries no excerpt. A document this cannot read is outside the
    limits: the check fails closed.
    """

    try:
        document = strict_json_parse(prepared)
    except Exception:  # noqa: BLE001 - any unreadable packet fails closed
        return False
    if not isinstance(document, dict):
        return False
    rows = cast(dict[str, object], document).get("items", [])
    if not isinstance(rows, list):
        return False
    sizes: list[int] = []
    for row in cast(list[object], rows):
        if not isinstance(row, dict):
            return False
        fields = cast(dict[str, object], row)
        if fields.get("section") != "excerpt":
            continue
        size = fields.get("content_bytes")
        if type(size) is not int:
            return False
        sizes.append(size)
    return (
        len(sizes) <= selection.max_excerpts
        and all(size <= selection.max_excerpt_bytes for size in sizes)
        and sum(sizes) <= selection.max_total_excerpt_bytes
    )


def _scope_digest(scope: AuthorizationScope) -> str:
    return canonical_digest(
        {
            "installation_id": scope.installation_id,
            "kind": scope.kind.value,
            "request_id": scope.request_id,
            "task_id": scope.task_id,
            "workspace_ref_commitment": scope.workspace_ref_commitment,
        }
    )


def _pointer(item_id: str, origin_ref: str) -> str:
    if origin_ref.startswith("/") and len(origin_ref) <= 256:
        return origin_ref
    escaped = item_id.replace("~", "~0").replace("/", "~1")
    return f"/{escaped}"


def _omissions(
    classified: ClassifiedContext, included: set[str]
) -> tuple[LocalDisclosureOmission, ...]:
    return tuple(
        sorted(
            (
                LocalDisclosureOmission(
                    _pointer(item.candidate.item_id, item.candidate.origin_ref),
                    item.candidate.category,
                    (
                        "never_send_redacted"
                        if item.forbidden_findings
                        else "local_disclosure_not_authorized"
                    ),
                )
                for item in classified.items
                if item.candidate.item_id not in included
            ),
            key=lambda item: item.json_pointer.encode(),
        )
    )
