"""Build observation AdviceSnapshot from envelopes, optional inspect, and AI-powered add-ons."""

from __future__ import annotations

import hashlib
import inspect
import re
import uuid
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Final, Protocol, cast

from yoetz.domain.findings import FINDING_KIND_TRAITS, FindingId, FindingKind, finding_id
from yoetz.domain.observation import (
    AdviceItem,
    AdviceSemanticState,
    AdviceSnapshot,
    ObservationEnvelope,
    ObservationLifecycle,
    ObservationStatus,
    ObservationStatusQuery,
)
from yoetz.domain.values import validate_sha256_digest
from yoetz.kernel.policies.observation_advice import (
    OBSERVATION_ADVICE_POLICY_ID,
    OBSERVATION_ADVICE_POLICY_VERSION,
    STANDING_MACHINE_ACTIONS,
    ObservationAdviceCandidate,
    ObservationAdviceContext,
    ObservationCheckFact,
    ObservationCompositionFact,
    ObservationInspectFact,
    advice_candidate_digest,
    evidence_basis_digest,
    observation_advice_findings,
)
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.coverage import (
    MAX_KNOWN_GAPS,
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)
from yoetz.protocol.errors import ProtocolValueError
from yoetz.protocol.ids import PREFIX_BY_KIND, IdKind

__all__ = [
    "ADVICE_SEMANTIC_DEFERRED_GAP",
    "ADVICE_SEMANTIC_DEFERRED_REASON",
    "ADVICE_SEMANTIC_PENDING_GAP",
    "ADVICE_SEMANTIC_UNREACHABLE_REASON",
    "ADVICE_SEMANTIC_UNAVAILABLE_GAP",
    "semantic_state_from_addon",
    "SemanticAdviceScheduler",
    "STANDING_MACHINE_ACTIONS",
    "ObservationAdviceBuildInput",
    "ObservationAdviceContextBuilder",
    "ObservationAdviceSemanticAddon",
    "SemanticAdvicePort",
    "advice_delivery_identity",
    "advice_items_for_ledger",
    "build_observation_advice_snapshot",
    "hook_advice_context",
    "minimized_semantic_evidence_packet",
    "validate_semantic_evidence_packet",
    "scoped_session_envelopes",
    "scoped_session_status",
    "select_advice_item",
    "select_standing_item",
    "should_reissue_advice",
    "stable_advice_finding_id",
]

_SUPPRESSION_DOMAIN: Final = b"yoetz/observation-advice-suppress/v1\x00"
_FINDING_DOMAIN: Final = b"yoetz/observation-advice-finding/v1\x00"
_DELIVERY_DOMAIN: Final = b"yoetz/observation-advice-delivery/v1\x00"
_MAX_ADVICE_EVIDENCE_REFS: Final = 16
_MAX_ADVICE_RANKED_FINDINGS: Final = 64
_ADVICE_EVIDENCE_REFS_TRUNCATED_GAP: Final = "advice_evidence_refs_truncated"
_ADVICE_RANKED_FINDINGS_TRUNCATED_GAP: Final = "advice_ranked_findings_truncated"
_ADVICE_SEMANTIC_OUTPUT_INVALID_GAP: Final = "advice_semantic_output_invalid"
_ADVICE_SEMANTIC_TEXT_TRUNCATED_GAP: Final = "advice_semantic_text_truncated"
_ADVICE_COVERAGE_GAPS_TRUNCATED_GAP: Final = "advice_coverage_gaps_truncated"
# Asynchronous AI-powered advice (#619): a durable attempt exists but has not reached a terminal
# state, or it terminated without validated output. Neither ever adds AI-powered review coverage.
ADVICE_SEMANTIC_PENDING_GAP: Final = "advice_semantic_pending"
ADVICE_SEMANTIC_UNAVAILABLE_GAP: Final = "advice_semantic_unavailable"
# Background review frequency bound (#888): the condition is eligible for review but the session's
# rate limit has not elapsed yet. No row exists and no provider was contacted; a later build
# (or the supervisor's scheduled revisit) admits it when allowed.
ADVICE_SEMANTIC_DEFERRED_GAP: Final = "advice_semantic_deferred"
_ADVICE_SEMANTIC_PENDING_REASON: Final = "pending"
ADVICE_SEMANTIC_DEFERRED_REASON: Final = "deferred"
# No reachable provider (#923): no endpoint bound, LLM-inference egress denied, the configured
# credential absent, or the task route not ACTIVE with a granted repository authority. Nothing is
# enqueued and no provider is contacted; the condition surfaces once as
# ``advice_semantic_unavailable`` and never as pending work.
ADVICE_SEMANTIC_UNREACHABLE_REASON: Final = "provider_unreachable"
_SEMANTIC_SUMMARY_FALLBACK: Final = "Model-derived observation note"
_SEMANTIC_DETAIL_FALLBACK: Final = "Additive AI-powered advice over minimized evidence"
_VALID_ADVICE_NEXT_ACTIONS: Final[frozenset[str]] = frozenset(
    {
        "resolve_failed_command",
        "rerun_approved_check",
        "provide_verification",
        "disclose_limitation",
        "address_subagent_finding",
        "revise_plan_scope",
        "refresh_observation",
        "connect_provider",
        "renew_provider_sign_in",
        "repair_semantic_provider",
        "update_yoetz",
        "attempt_semantic_dispatch",
        "reground_status",
    }
)
# Machine conditions derived from the service's own attempt outcomes (#819). Model-derived
# advice may never name them: an AI-powered note cannot claim the user must sign in or update.
_ATTEMPT_DERIVED_ACTIONS: Final[frozenset[str]] = frozenset(
    {"renew_provider_sign_in", "repair_semantic_provider", "update_yoetz"}
)

_RULE_SUMMARIES: Final[Mapping[str, str]] = {
    "failed_command_unresolved": "Unresolved failed command observed",
    "edit_after_successful_check": "Verification stale after later edit",
    "completion_without_verification": "Completion not supported by current evidence",
    "static_test_for_live_claim": "Static check does not support live claim",
    "subagent_finding_unaddressed": "Subagent finding remains unaddressed",
    "change_outside_plan": "Observed change outside declared plan scope",
    "observation_gap_or_stale": "Observation coverage is incomplete or stale",
    "provider_not_ready": "Configured provider is not ready",
    "semantic_sign_in_required": "AI-powered review needs the user to sign in to Codex again",
    "semantic_provider_attention": "AI-powered review needs the user to fix its provider",
    "semantic_claim_without_attempt": "AI-powered review claim lacks a recorded attempt",
    "install_into_yoetz_runtime": "A package install went into Yoetz's own runtime, not the task's",
    "install_into_private_env": "A package install went into an environment other than the task's interpreter",
    "write_outside_workspace": "A write landed outside the workspace",
}

_RULE_DETAILS: Final[Mapping[str, str]] = {
    "failed_command_unresolved": (
        "A tool result failed and neither a later passing run of the same command "
        "nor a completed edit followed it"
    ),
    "edit_after_successful_check": "A check that predates a later edit is no longer current verification",
    "completion_without_verification": "A completion claim lacks current admissible verification evidence",
    "static_test_for_live_claim": "Only static verification was observed for a live or wire claim",
    "subagent_finding_unaddressed": "A subagent reported a finding that parent work has not addressed",
    "change_outside_plan": "Changed-path evidence falls outside the declared plan digests",
    "observation_gap_or_stale": "Source lag, mapping, or drain gaps prevent complete observation",
    "provider_not_ready": "AI-powered review or provider binding is configured but not ready",
    "semantic_sign_in_required": "The last review attempt found the Codex evaluator signed out or its login expired",
    "semantic_provider_attention": "The last review attempt stopped for a provider cause only the user can repair",
    "semantic_claim_without_attempt": "An AI-powered review claim was observed without a matching attempt receipt",
    "install_into_yoetz_runtime": (
        "The installer resolved to the interpreter that runs Yoetz, which the task's own runs and "
        "its delivery do not use; install into the task's interpreter (or avoid the dependency) "
        "and verify with that interpreter"
    ),
    "install_into_private_env": (
        "The install went into another environment or a directory outside the workspace, not "
        "the task's interpreter, so the deliverable will not see it; install into the task's "
        "interpreter and verify with it"
    ),
    "write_outside_workspace": (
        "A file outside the workspace is not part of the delivered change; keep requested "
        "outputs in the workspace and do not let verification depend on files outside it"
    ),
}

# Cause-specific reasons for the attempt-derived rules, keyed by the kernel's detail token (#819).
_ATTENTION_DETAILS: Final[Mapping[str, str]] = {
    "semantic-attention:credential_rejected": "The last review attempt was rejected because the provider no longer accepts the stored credential; the user must replace it",
    "semantic-attention:access_denied": "The last review attempt was refused because this account or plan may not use the bound model or endpoint",
    "semantic-attention:quota_exhausted": "The last review attempt found the provider usage quota exhausted; reviews resume after the limit resets or the plan is raised",
    "semantic-attention:model_unavailable": "The last review attempt found the bound model or reasoning effort no longer offered to this account; setup must select an available one",
    "semantic-attention:runtime_update_required": "The last review attempt found the pinned evaluator runtime evidence expired; a newer Yoetz release is needed before reviews can run",
}

# Only lag, a drain backlog, an unavailable service, or a locked vault can recover within the
# session; a standing host-profile gap such as `unpaired_event` never does. The clause therefore
# never asks the agent to wait for, answer, or recheck a condition that cannot change (#911).
_REFRESH_OBSERVATION_HOOK_NEXT: Final = (
    "Run `yoetz observe status` from the host shell and wait only while it reports lag or a "
    "drain backlog. A gap that remains is a standing limitation: it needs no response or "
    "recheck and never blocks the receipt; disclose it there."
)
# Machine conditions are the user's to repair: the agent tells them now, offers a bounded
# subagent fix, and leaves sign-in, consent, and approval steps to the user (#819).
_MACHINE_ACTION_HOOK_NEXT: Final[Mapping[str, str]] = {
    "connect_provider": (
        "Tell the user now. Offer a subagent that runs `yoetz provider status` and follows "
        "its next command; the user approves any sign-in, credential, or privacy step."
    ),
    "renew_provider_sign_in": (
        "Tell the user now. Offer a subagent that reads `yoetz provider codex-subscription "
        "status --json`, then runs `yoetz provider codex-subscription setup` with its "
        "executable_path, codex_home and `--device-code`; the user completes sign-in. "
        "Then recheck."
    ),
    "repair_semantic_provider": (
        "Tell the user now. Offer a subagent that runs `yoetz provider status` and follows "
        "its next command; the user approves each step. Then recheck."
    ),
    "update_yoetz": (
        "Tell the user now. Offer a subagent that follows `yoetz upgrade`, then tell the user "
        "to start a fresh session; restart Codex, Claude Code, or Cursor only if activation requires it."
    ),
}


@dataclass(frozen=True, slots=True)
class ObservationAdviceSemanticAddon:
    """Additive AI-powered advice identities already privacy-gated upstream."""

    finding_ids: tuple[FindingId, ...]
    evidence_digest: str | None
    next_action: str | None = None
    summaries: tuple[str, ...] = ()
    details: tuple[str, ...] = ()
    provider_identity: str | None = None
    attempt_receipt: str | None = None
    failure_reason: str | None = None


def semantic_state_from_addon(
    addon: ObservationAdviceSemanticAddon | None,
    *,
    output_usable: bool = True,
) -> AdviceSemanticState:
    """Project recorded attempt status, never finding count (issue #742).

    ``output_usable`` is False when a succeeded attempt's output failed advice-side structural
    validation and left no usable finding; ADR-006 records that as ``failed`` (a terminal attempt
    without validated output), not ``ready``. With no reachable provider no attempt was
    requested, so the state is ``disabled`` (#923); the addon still carries the unavailable gap.
    """

    if addon is None or addon.failure_reason == ADVICE_SEMANTIC_UNREACHABLE_REASON:
        return "disabled"
    if addon.failure_reason is None:
        return "ready" if output_usable else "failed"
    if addon.failure_reason in {_ADVICE_SEMANTIC_PENDING_REASON, ADVICE_SEMANTIC_DEFERRED_REASON}:
        return "unavailable"
    return "failed"


class SemanticAdvicePort(Protocol):
    """Optional AI-powered advisor; never required for local correctness guidance."""

    def review(
        self,
        *,
        evidence_packet: Mapping[str, object],
    ) -> ObservationAdviceSemanticAddon | None: ...


class ObservationContextStore(Protocol):
    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]: ...

    async def status(self, query: ObservationStatusQuery) -> ObservationStatus: ...

    def load_advice_snapshot(self, workspace: str) -> AdviceSnapshot | None: ...


def scoped_session_envelopes(
    store: ObservationContextStore,
    workspace: str,
    session_commitment: str | None,
) -> tuple[ObservationEnvelope, ...]:
    """Mapped builds read the mapped session's envelopes, never the workspace's (#352).

    Stores that predate session-scoped listing (or an unmapped build with no
    session commitment) keep the workspace-wide behavior.
    """

    if session_commitment is not None:
        session_list = getattr(store, "list_envelopes_for_session", None)
        if callable(session_list):
            loaded = cast(
                Callable[[str, str], object],
                session_list,
            )(workspace, session_commitment)
            if type(loaded) is tuple:
                return cast(tuple[ObservationEnvelope, ...], loaded)
    return store.list_envelopes(workspace)


async def scoped_session_status(
    store: ObservationContextStore,
    workspace: str,
    session_commitment: str | None,
) -> ObservationStatus:
    """Mapped builds derive lifecycle/gap inputs for the mapped session only (#352)."""

    if session_commitment is not None:
        session_status = getattr(store, "status_for_session", None)
        if callable(session_status):
            loaded = await cast(
                Callable[[str, str], Awaitable[object]],
                session_status,
            )(workspace, session_commitment)
            if type(loaded) is ObservationStatus:
                return loaded
    return await store.status(ObservationStatusQuery(workspace))


type CallableFacts = Callable[[str], tuple[ObservationCheckFact, ...]]
type CallableInspect = Callable[[str], ObservationInspectFact | None]
type CallablePlans = Callable[[str], tuple[str, ...]]
type CallableSemantic = Callable[[str], ObservationAdviceSemanticAddon | None]
type CallableSemanticReview = Callable[
    [tuple[ObservationAdviceCandidate, ...], str, tuple[str, ...], str | None],
    ObservationAdviceSemanticAddon | None | Awaitable[ObservationAdviceSemanticAddon | None],
]
type CallableComposition = Callable[
    [], ObservationCompositionFact | None | Awaitable[ObservationCompositionFact | None]
]


class SemanticAdviceScheduler(Protocol):
    """Durable, store-aware AI-powered review that never dispatches on the hook path (#619)."""

    async def review(
        self,
        *,
        store: object,
        workspace: str,
        candidates: Sequence[ObservationAdviceCandidate],
        basis: str,
        gaps: Sequence[str],
        yoetz_session_id: str | None,
    ) -> ObservationAdviceSemanticAddon | None: ...


@dataclass(frozen=True, slots=True)
class ObservationAdviceBuildInput:
    envelopes: tuple[ObservationEnvelope, ...]
    lifecycle: ObservationLifecycle
    gaps: tuple[str, ...]
    lineage_refs: tuple[tuple[str, str], ...] = ()
    check_facts: tuple[ObservationCheckFact, ...] = ()
    inspect_fact: ObservationInspectFact | None = None
    composition: ObservationCompositionFact | None = None
    plan_path_digests: tuple[str, ...] = ()
    prior_snapshot: AdviceSnapshot | None = None
    semantic_addon: ObservationAdviceSemanticAddon | None = None
    has_real_observation: bool = False


@dataclass(frozen=True, slots=True)
class ObservationAdviceContextBuilder:
    """Load one coherent advice context from durable observation repositories.

    Optional verified facts are injected by their owning repositories; missing
    facts remain explicit coverage limitations rather than being invented from
    envelope shape.
    """

    check_facts: CallableFacts | None = None
    inspect_fact: CallableInspect | None = None
    # A callable composition is resolved on every build so standing provider
    # advice reflects current machine facts instead of a READY-time
    # snapshot (#265); a plain fact value stays supported for fixed contexts.
    composition: ObservationCompositionFact | CallableComposition | None = None
    plan_path_digests: CallablePlans | None = None
    semantic_addon: CallableSemantic | None = None
    semantic_review: CallableSemanticReview | None = None
    # Preferred over ``semantic_review`` when present: it receives the store so the durable
    # attempt row can be looked up or enqueued without any provider call in this build.
    semantic_scheduler: SemanticAdviceScheduler | None = None

    async def _resolve_composition(self) -> ObservationCompositionFact | None:
        if not callable(self.composition):
            return self.composition
        resolved = self.composition()
        if inspect.isawaitable(resolved):
            resolved = await resolved
        return resolved if type(resolved) is ObservationCompositionFact else None

    async def build(
        self,
        workspace: str,
        store: ObservationContextStore,
        *,
        yoetz_session_id: str | None = None,
        session_commitment: str | None = None,
        lineage_refs: tuple[tuple[str, str], ...] = (),
    ) -> AdviceSnapshot | None:
        # Task-scoped conditions come from the mapped session's own evidence and
        # current health. The workspace-wide aggregate remains the operator
        # surface (`yoetz observe status --workspace`) and the home of
        # deliberately workspace-standing machine conditions (composition
        # facts below); it is never a silent input to a mapped task snapshot.
        envelopes = scoped_session_envelopes(store, workspace, session_commitment)
        composition = await self._resolve_composition()
        status = await scoped_session_status(store, workspace, session_commitment)
        store_check_facts = getattr(store, "load_check_facts", None)
        checks: tuple[ObservationCheckFact, ...] = ()
        if self.check_facts is not None:
            checks = self.check_facts(workspace)
        elif callable(store_check_facts):
            loaded = store_check_facts(workspace)
            if type(loaded) is tuple:
                loaded_items = cast(tuple[object, ...], loaded)
                if all(type(item) is ObservationCheckFact for item in loaded_items):
                    checks = cast(tuple[ObservationCheckFact, ...], loaded_items)
        inspect_fact = None if self.inspect_fact is None else self.inspect_fact(workspace)
        plans = () if self.plan_path_digests is None else self.plan_path_digests(workspace)
        semantic: ObservationAdviceSemanticAddon | None = None
        if self.semantic_review is not None or self.semantic_scheduler is not None:
            context = ObservationAdviceContext(
                envelopes=envelopes,
                lifecycle=status.lifecycle,
                gaps=status.gaps,
                lineage_refs=lineage_refs,
                check_facts=checks,
                inspect_fact=inspect_fact,
                composition=composition,
                plan_path_digests=plans,
            )
            candidates = observation_advice_findings(context)
            basis = evidence_basis_digest(
                candidates,
                envelopes,
                extra={
                    "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
                    "lifecycle": status.lifecycle.value,
                    "coverage_gaps": _sorted_coverage_gaps(status.gaps),
                },
            )
            if self.semantic_scheduler is not None:
                # Durable, off-hook AI-powered advice (#619): look up or enqueue only. The scoped
                # status gaps travel with the row so the provider packet keeps them exactly.
                semantic = await self.semantic_scheduler.review(
                    store=store,
                    workspace=workspace,
                    candidates=candidates,
                    basis=basis,
                    gaps=status.gaps,
                    yoetz_session_id=yoetz_session_id,
                )
            elif self.semantic_review is not None:
                reviewed = self.semantic_review(candidates, basis, status.gaps, yoetz_session_id)
                if inspect.isawaitable(reviewed):
                    semantic = await reviewed
                else:
                    semantic = reviewed
        elif self.semantic_addon is not None:
            semantic = self.semantic_addon(workspace)
        prior: AdviceSnapshot | None = None
        session_load = getattr(store, "load_advice_snapshot_for_session", None)
        if callable(session_load) and type(yoetz_session_id) is str:
            loaded = session_load(workspace=workspace, yoetz_session_id=yoetz_session_id)
            if type(loaded) is AdviceSnapshot:
                prior = loaded
        if prior is None:
            prior = store.load_advice_snapshot(workspace)
        return build_observation_advice_snapshot(
            ObservationAdviceBuildInput(
                envelopes=envelopes,
                lifecycle=status.lifecycle,
                gaps=status.gaps,
                lineage_refs=lineage_refs,
                check_facts=checks,
                inspect_fact=inspect_fact,
                composition=composition,
                plan_path_digests=plans,
                prior_snapshot=prior,
                semantic_addon=semantic,
                has_real_observation=bool(envelopes),
            )
        )


def stable_advice_finding_id(rule_code: str, detail_token: str, evidence_digest: str) -> FindingId:
    """Allocate a deterministic UUIDv4-shaped finding id for observation advice."""

    material = _FINDING_DOMAIN + f"{rule_code}\0{detail_token}\0{evidence_digest}".encode()
    digest = hashlib.sha256(material).digest()
    raw = bytearray(digest[:16])
    raw[6] = (raw[6] & 0x0F) | 0x40
    raw[8] = (raw[8] & 0x3F) | 0x80
    return finding_id(PREFIX_BY_KIND[IdKind.FINDING] + str(uuid.UUID(bytes=bytes(raw))))


def _coverage(
    *,
    observation_qualified: bool,
    semantic: bool,
    gaps: Sequence[str],
    additional_gaps: Sequence[str] = (),
) -> Coverage:
    channels = (PublicationChannel.ENGINE_DERIVED,)
    authorship = AuthorshipAssurance.SERVICE_AUTHENTICATED
    observation = ArtifactObservation.PUBLISHED_ONLY
    if observation_qualified:
        channels = (PublicationChannel.HOOK_OBSERVED, PublicationChannel.ENGINE_DERIVED)
        authorship = AuthorshipAssurance.HARNESS_OBSERVED
        observation = ArtifactObservation.HOOK_OBSERVED
    checks = [CheckType.DETERMINISTIC]
    if semantic:
        checks.append(CheckType.SEMANTIC_MODEL_DERIVED)
    known = _bounded_coverage_gaps(gaps, additional_gaps)
    freshness = LedgerFreshness.PARTIAL if known else LedgerFreshness.CURRENT
    return Coverage(
        publication_channels=tuple(sorted(channels, key=lambda item: item.value.encode("ascii"))),
        authorship_assurance=authorship,
        artifact_observation=observation,
        evidence_immutability=EvidenceImmutability.CONTENT_DIGEST,
        ledger_freshness=freshness,
        check_types=tuple(sorted(checks, key=lambda item: item.value.encode("ascii"))),
        known_gaps=known,
    )


def _bounded_coverage_gaps(gaps: Sequence[str], additional_gaps: Sequence[str]) -> tuple[str, ...]:
    """Keep coverage gaps bounded while retaining an explicit overflow marker.

    Observation status normally supplies at most ``MAX_KNOWN_GAPS`` values. Advice
    projection can add its own honest truncation markers, so the union can exceed
    the wire bound even though neither input is malformed. Preserve all additive
    markers when possible and retain a fixed truncation marker when the union is
    too large. The complete gap set is committed in the snapshot's evidence basis
    digest, so the marker never silently drops coverage from the identity.
    """

    known = _sorted_coverage_gaps(gaps, additional_gaps)
    if len(known) <= MAX_KNOWN_GAPS:
        return known
    extra = tuple(
        sorted(
            {gap for gap in additional_gaps if gap and gap != _ADVICE_COVERAGE_GAPS_TRUNCATED_GAP},
            key=str.encode,
        )
    )
    known_without_marker = tuple(gap for gap in known if gap != _ADVICE_COVERAGE_GAPS_TRUNCATED_GAP)
    retained_extra = set(extra[: max(0, MAX_KNOWN_GAPS - 1)])
    remaining = max(0, MAX_KNOWN_GAPS - 1 - len(retained_extra))
    retained_base = tuple(gap for gap in known_without_marker if gap not in retained_extra)[
        :remaining
    ]
    return tuple(
        sorted(
            (*retained_extra, *retained_base, _ADVICE_COVERAGE_GAPS_TRUNCATED_GAP),
            key=str.encode,
        )
    )


def _sorted_coverage_gaps(
    gaps: Sequence[str], additional_gaps: Sequence[str] = ()
) -> tuple[str, ...]:
    """Return the complete local gap set before the wire bound."""

    return tuple(sorted({gap for gap in (*gaps, *additional_gaps) if gap}, key=str.encode))


def _suppression_identity(
    finding_ids: Sequence[FindingId],
    evidence_digest: str,
    next_action: str,
) -> str:
    material = _SUPPRESSION_DOMAIN + canonical_material(finding_ids, evidence_digest, next_action)
    digest = hashlib.sha256(material).hexdigest()
    return f"suppress-{digest[:48]}"


def canonical_material(
    finding_ids: Sequence[FindingId], evidence_digest: str, next_action: str
) -> bytes:
    joined = ",".join(str(item) for item in finding_ids)
    return f"{joined}\0{evidence_digest}\0{next_action}".encode()


def should_reissue_advice(
    prior: AdviceSnapshot | None,
    candidate: AdviceSnapshot,
    *,
    prior_severity: int | None = None,
    candidate_severity: int | None = None,
    unresolved_after_work: bool = False,
) -> bool:
    """Reissue when evidence changes, severity increases, or work left prior advice open."""

    if prior is None:
        return True
    # The attempt state is not part of the suppression identity or the evidence basis: a review
    # that completes with no findings and no evidence digest leaves both unchanged, and the stale
    # state would otherwise survive in the stored snapshot.
    if prior.semantic_attempt_state != candidate.semantic_attempt_state:
        return True
    if prior.suppression_identity == candidate.suppression_identity:
        return unresolved_after_work
    if prior.evidence_basis_digest != candidate.evidence_basis_digest:
        return True
    if (
        prior_severity is not None
        and candidate_severity is not None
        and candidate_severity < prior_severity
    ):
        # Lower priority number is higher severity in FindingKind traits.
        return True
    if unresolved_after_work:
        return True
    return prior.ranked_finding_ids != candidate.ranked_finding_ids


def _next_action(candidates: Sequence[ObservationAdviceCandidate]) -> str:
    if not candidates:
        return "reground_status"
    return candidates[0].next_action


def _freshness_frontier(envelopes: Sequence[ObservationEnvelope], evidence_digest: str) -> str:
    if not envelopes:
        return f"frontier-{evidence_digest.removeprefix('sha256:')[:24]}"
    last = envelopes[-1]
    return (
        f"frontier-g{last.cursor.source_generation}-"
        f"e{last.cursor.event_position}-"
        f"{evidence_digest.removeprefix('sha256:')[:16]}"
    )


def _item_from_candidate(
    candidate: ObservationAdviceCandidate,
    finding: FindingId,
    *,
    coverage: Coverage,
    freshness_frontier: str,
) -> AdviceItem:
    summary = _RULE_SUMMARIES.get(candidate.rule_code, "Observation advice finding")
    detail = _ATTENTION_DETAILS.get(candidate.detail_token) or _RULE_DETAILS.get(
        candidate.rule_code, "Evidence-linked observation finding"
    )
    return AdviceItem(
        finding_id=finding,
        rule_code=candidate.rule_code,
        priority=candidate.priority,
        summary=summary,
        detail=detail,
        recommended_next_action=candidate.next_action,
        # The kernel retains the complete evidence basis, while the durable
        # advice item follows the domain's 16-reference wire bound.  The
        # caller adds a coverage gap when this projection omits refs.
        evidence_refs=candidate.evidence_refs[:_MAX_ADVICE_EVIDENCE_REFS],
        coverage=coverage,
        freshness_frontier=freshness_frontier,
        origin="deterministic",
        condition_identity=_delivery_condition_identity(candidate),
    )


def _delivery_condition_identity(candidate: ObservationAdviceCandidate) -> str:
    """Hash the stable rule-specific condition without rolling evidence references."""

    material = canonical_encode(
        {
            "detail_token": candidate.detail_token,
            "rule_code": candidate.rule_code,
        }
    )
    return f"condition-{hashlib.sha256(material).hexdigest()[:48]}"


def _semantic_finding_entries(
    semantic: ObservationAdviceSemanticAddon,
    existing: Sequence[FindingId],
) -> tuple[tuple[tuple[int, FindingId], ...], bool]:
    """Normalize provider finding ids while retaining the source-field index."""

    raw_ids = semantic.finding_ids
    if type(raw_ids) is not tuple:
        return (), True
    seen = {str(item) for item in existing}
    entries: list[tuple[int, FindingId]] = []
    invalid = False
    for index, raw_finding in enumerate(cast(tuple[object, ...], raw_ids)):
        if type(raw_finding) is not str:
            invalid = True
            continue
        try:
            normalized = finding_id(raw_finding)
        except ProtocolValueError:
            invalid = True
            continue
        key = str(normalized)
        if key in seen:
            continue
        seen.add(key)
        entries.append((index, normalized))
    return tuple(entries), invalid


def _semantic_item(
    *,
    finding: FindingId,
    summary: object,
    detail: object,
    next_action: str,
    coverage: Coverage,
    freshness_frontier: str,
) -> tuple[AdviceItem | None, bool]:
    """Build one fenced AI-powered item, falling back on invalid provider text."""

    raw_summary = summary if type(summary) is str else _SEMANTIC_SUMMARY_FALLBACK
    raw_detail = detail if type(detail) is str else _SEMANTIC_DETAIL_FALLBACK
    invalid = type(summary) is not str or type(detail) is not str
    try:
        item = AdviceItem(
            finding_id=finding,
            rule_code="semantic-additive-review",
            priority=90,
            summary=raw_summary[:160],
            detail=raw_detail[:240],
            recommended_next_action=next_action,
            evidence_refs=("semantic:minimized",),
            coverage=coverage,
            freshness_frontier=freshness_frontier,
            origin="semantic_model_derived",
        )
        return item, invalid
    except ProtocolValueError:
        invalid = True
    try:
        return (
            AdviceItem(
                finding_id=finding,
                rule_code="semantic-additive-review",
                priority=90,
                summary=_SEMANTIC_SUMMARY_FALLBACK,
                detail=_SEMANTIC_DETAIL_FALLBACK,
                recommended_next_action="reground_status",
                evidence_refs=("semantic:minimized",),
                coverage=coverage,
                freshness_frontier=freshness_frontier,
                origin="semantic_model_derived",
            ),
            invalid,
        )
    except ProtocolValueError:
        return None, True


def _semantic_items(
    *,
    semantic_indexes: Sequence[int],
    semantic_ids: Sequence[FindingId],
    summaries: Sequence[object],
    details: Sequence[object],
    next_action: str,
    coverage: Coverage,
    freshness_frontier: str,
) -> tuple[list[AdviceItem], bool]:
    items: list[AdviceItem] = []
    invalid = False
    for index, finding in zip(semantic_indexes, semantic_ids, strict=True):
        summary = summaries[index] if index < len(summaries) else _SEMANTIC_SUMMARY_FALLBACK
        detail = details[index] if index < len(details) else _SEMANTIC_DETAIL_FALLBACK
        item, item_invalid = _semantic_item(
            finding=finding,
            summary=summary,
            detail=detail,
            next_action=next_action,
            coverage=coverage,
            freshness_frontier=freshness_frontier,
        )
        invalid = invalid or item_invalid
        if item is not None:
            items.append(item)
    return items, invalid


def _candidate_projection(
    candidates: Sequence[ObservationAdviceCandidate],
) -> tuple[tuple[ObservationAdviceCandidate, ...], tuple[FindingId, ...], bool, bool]:
    """Select the bounded local surface while retaining overflow facts."""

    candidate_overflow = len(candidates) > _MAX_ADVICE_RANKED_FINDINGS
    selected = tuple(candidates[:_MAX_ADVICE_RANKED_FINDINGS])
    evidence_ref_overflow = any(
        len(candidate.evidence_refs) > _MAX_ADVICE_EVIDENCE_REFS for candidate in candidates
    )
    finding_ids = tuple(
        stable_advice_finding_id(item.rule_code, item.detail_token, advice_candidate_digest(item))
        for item in selected
    )
    return selected, finding_ids, candidate_overflow, evidence_ref_overflow


def _semantic_invalid_fallback_candidate() -> ObservationAdviceCandidate:
    """Represent an invalid result carrying only AI-powered advice as bounded engine advice."""

    kind = FindingKind.LEDGER_STALE_OR_INCOMPLETE
    priority, _ = FINDING_KIND_TRAITS[kind]
    return ObservationAdviceCandidate(
        kind=kind,
        rule_code="observation_gap_or_stale",
        next_action="reground_status",
        evidence_refs=("advice:invalid",),
        priority=priority,
        detail_token="semantic-output-invalid",
    )


def build_observation_advice_snapshot(
    input_value: ObservationAdviceBuildInput,
) -> AdviceSnapshot | None:
    """Return an AdviceSnapshot, or None when there is nothing actionable to surface."""

    if type(input_value) is not ObservationAdviceBuildInput:
        raise ValueError("observation_advice_invalid")
    context = ObservationAdviceContext(
        envelopes=input_value.envelopes,
        lifecycle=input_value.lifecycle,
        gaps=input_value.gaps,
        lineage_refs=input_value.lineage_refs,
        check_facts=input_value.check_facts,
        inspect_fact=input_value.inspect_fact,
        composition=input_value.composition,
        plan_path_digests=input_value.plan_path_digests,
    )
    candidates = observation_advice_findings(context)
    # Keep the complete policy result for the evidence-basis digest, but only
    # materialize the domain's bounded ranked surface.  The policy result is
    # already deterministically ordered by severity/rule/cause, so this keeps
    # the highest-ranked conditions without making the cap depend on arrival
    # order or hash iteration.
    selected_candidates, finding_ids, candidate_overflow, evidence_ref_overflow = (
        _candidate_projection(candidates)
    )
    semantic = input_value.semantic_addon
    semantic_ids: tuple[FindingId, ...] = ()
    semantic_indexes: tuple[int, ...] = ()
    semantic_overflow = False
    semantic_invalid = False
    semantic_text_truncated = False
    semantic_summaries: tuple[object, ...] = ()
    semantic_details: tuple[object, ...] = ()
    semantic_evidence_digest: str | None = None
    # A durable attempt that has not finished, or finished without validated output, is a
    # coverage gap and never an AI-powered review check type (#619). The addon carries no finding ids in
    # either case, so the structural validation below cannot mistake it for provider output. A
    # condition with no reachable provider has no row at all and reads as unavailable, never
    # pending (#923).
    semantic_pending = (
        semantic is not None and semantic.failure_reason == _ADVICE_SEMANTIC_PENDING_REASON
    )
    semantic_deferred = (
        semantic is not None and semantic.failure_reason == ADVICE_SEMANTIC_DEFERRED_REASON
    )
    semantic_unavailable = (
        semantic is not None
        and semantic.failure_reason is not None
        and semantic.failure_reason
        not in {_ADVICE_SEMANTIC_PENDING_REASON, ADVICE_SEMANTIC_DEFERRED_REASON}
    )
    if semantic is not None:
        if semantic.next_action is not None and (
            type(semantic.next_action) is not str
            or semantic.next_action not in _VALID_ADVICE_NEXT_ACTIONS
            or semantic.next_action in _ATTEMPT_DERIVED_ACTIONS
        ):
            semantic_invalid = True
        if type(semantic.finding_ids) is not tuple:
            semantic_invalid = True
        if type(semantic.summaries) is tuple:
            semantic_summaries = cast(tuple[object, ...], semantic.summaries)
            semantic_text_truncated = semantic_text_truncated or any(
                type(value) is str and len(value) > 160 for value in semantic_summaries
            )
        else:
            semantic_invalid = True
        if type(semantic.details) is tuple:
            semantic_details = cast(tuple[object, ...], semantic.details)
            semantic_text_truncated = semantic_text_truncated or any(
                type(value) is str and len(value) > 240 for value in semantic_details
            )
        else:
            semantic_invalid = True
        if (
            type(semantic.finding_ids) is tuple
            and not semantic.finding_ids
            and (semantic_summaries or semantic_details)
        ):
            semantic_invalid = True
        if semantic.evidence_digest is not None:
            try:
                semantic_evidence_digest = validate_sha256_digest(semantic.evidence_digest)
            except ProtocolValueError:
                semantic_invalid = True
            else:
                semantic_evidence_digest = semantic.evidence_digest
    if semantic is not None and type(semantic.finding_ids) is tuple and semantic.finding_ids:
        # AI-powered add-ons are provider data rather than policy output, so
        # defensively deduplicate and fit them into the remaining ranked
        # surface.  A malformed oversized add-on must not turn a hook update
        # into a ProtocolValueError at AdviceSnapshot construction.
        unique_semantic, invalid_ids = _semantic_finding_entries(semantic, finding_ids)
        semantic_invalid = semantic_invalid or invalid_ids
        remaining = max(0, _MAX_ADVICE_RANKED_FINDINGS - len(finding_ids))
        semantic_overflow = len(unique_semantic) > remaining
        selected_semantic = unique_semantic[:remaining]
        semantic_indexes = tuple(index for index, _ in selected_semantic)
        semantic_ids = tuple(finding for _, finding in selected_semantic)
    if semantic is not None and semantic_invalid and not candidates and not semantic_ids:
        # A malformed response carrying only AI-powered advice cannot mint an additive finding.
        # Keep the actual lifecycle unchanged and use the existing local
        # gap rendering machinery for one actionable engine record.
        candidates = (_semantic_invalid_fallback_candidate(),)
        selected_candidates, finding_ids, candidate_overflow, evidence_ref_overflow = (
            _candidate_projection(candidates)
        )
    ranked = finding_ids + semantic_ids
    if not ranked:
        # Zero cooperative publications still yield observation-gap advice when empty/degraded.
        return None
    next_action = (
        semantic.next_action
        if semantic is not None and semantic.next_action is not None and not candidates
        else _next_action(candidates)
    )
    # AI-powered output uses the same closed action vocabulary as local advice. Validate
    # before building the snapshot: item-level fallback alone cannot protect the snapshot's
    # top-level recommended_next_action field. Without local candidates the action came from
    # the model, which may never name an attempt-derived repair (#819).
    if (
        type(next_action) is not str
        or next_action not in _VALID_ADVICE_NEXT_ACTIONS
        or (not candidates and next_action in _ATTEMPT_DERIVED_ACTIONS)
    ):
        next_action = "reground_status"
    observation_qualified = input_value.has_real_observation and (
        input_value.lifecycle is ObservationLifecycle.ACTIVE
    )
    qualification_partial = bool(input_value.envelopes) and not observation_qualified
    additional_gaps = tuple(
        gap
        for gap, present in (
            (
                _ADVICE_EVIDENCE_REFS_TRUNCATED_GAP,
                evidence_ref_overflow,
            ),
            (
                _ADVICE_RANKED_FINDINGS_TRUNCATED_GAP,
                candidate_overflow or semantic_overflow,
            ),
            (
                _ADVICE_SEMANTIC_OUTPUT_INVALID_GAP,
                semantic_invalid,
            ),
            (
                _ADVICE_SEMANTIC_TEXT_TRUNCATED_GAP,
                semantic_text_truncated,
            ),
            (
                ADVICE_SEMANTIC_PENDING_GAP,
                semantic_pending,
            ),
            (
                ADVICE_SEMANTIC_UNAVAILABLE_GAP,
                semantic_unavailable,
            ),
            (
                ADVICE_SEMANTIC_DEFERRED_GAP,
                semantic_deferred,
            ),
            (
                "observation_qualified_partial",
                qualification_partial,
            ),
        )
        if present
    )
    basis_extra: dict[str, JsonValue] = {
        "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
        "lifecycle": input_value.lifecycle.value,
        # Commit the complete pre-projection gap set even when Coverage must
        # retain only its bounded visible prefix plus a fixed truncation gap.
        "coverage_gaps": _sorted_coverage_gaps(input_value.gaps, additional_gaps),
    }
    if semantic_evidence_digest is not None:
        basis_extra["semantic_evidence"] = semantic_evidence_digest
    basis = evidence_basis_digest(candidates, input_value.envelopes, extra=basis_extra)
    coverage = _coverage(
        observation_qualified=observation_qualified,
        semantic=semantic is not None and bool(semantic_ids),
        gaps=input_value.gaps,
        additional_gaps=additional_gaps,
    )
    # Honest observation-qualified coverage: when envelopes exist but lifecycle is not active,
    # keep engine-derived coverage and include known gaps.
    if input_value.envelopes and not (
        input_value.has_real_observation and input_value.lifecycle is ObservationLifecycle.ACTIVE
    ):
        coverage = Coverage(
            publication_channels=coverage.publication_channels,
            authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
            artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
            evidence_immutability=coverage.evidence_immutability,
            ledger_freshness=LedgerFreshness.PARTIAL,
            check_types=coverage.check_types,
            known_gaps=coverage.known_gaps,
        )
    frontier = _freshness_frontier(input_value.envelopes, basis)
    semantic_items, semantic_item_invalid = _semantic_items(
        semantic_indexes=semantic_indexes,
        semantic_ids=semantic_ids,
        summaries=semantic_summaries,
        details=semantic_details,
        next_action=next_action,
        coverage=coverage,
        freshness_frontier=frontier,
    )
    if semantic_item_invalid and not semantic_invalid:
        # AdviceItem is the single source of truth for safe AI-powered text and
        # action tokens. Rebuild coverage and items after it rejects provider
        # output so the rejection remains visible as a bounded gap.
        semantic_invalid = True
        additional_gaps = (*additional_gaps, _ADVICE_SEMANTIC_OUTPUT_INVALID_GAP)
        basis_extra["coverage_gaps"] = _sorted_coverage_gaps(input_value.gaps, additional_gaps)
        basis = evidence_basis_digest(candidates, input_value.envelopes, extra=basis_extra)
        frontier = _freshness_frontier(input_value.envelopes, basis)
        coverage = _coverage(
            observation_qualified=observation_qualified,
            semantic=bool(semantic_ids),
            gaps=input_value.gaps,
            additional_gaps=additional_gaps,
        )
        if qualification_partial:
            coverage = Coverage(
                publication_channels=coverage.publication_channels,
                authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
                artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
                evidence_immutability=coverage.evidence_immutability,
                ledger_freshness=LedgerFreshness.PARTIAL,
                check_types=coverage.check_types,
                known_gaps=coverage.known_gaps,
            )
        semantic_items, _ = _semantic_items(
            semantic_indexes=semantic_indexes,
            semantic_ids=semantic_ids,
            summaries=semantic_summaries,
            details=semantic_details,
            next_action=next_action,
            coverage=coverage,
            freshness_frontier=frontier,
        )
    items: list[AdviceItem] = [
        _item_from_candidate(candidate, finding, coverage=coverage, freshness_frontier=frontier)
        for candidate, finding in zip(selected_candidates, finding_ids, strict=True)
    ]
    items.extend(semantic_items)
    suppression = _suppression_identity(ranked, basis, next_action)
    snapshot = AdviceSnapshot(
        ranked_finding_ids=ranked,
        evidence_basis_digest=basis,
        confidence_coverage=coverage,
        recommended_next_action=next_action,
        freshness_frontier=frontier,
        suppression_identity=suppression,
        ranked_items=tuple(items),
        semantic_attempt_state=semantic_state_from_addon(
            semantic, output_usable=bool(semantic_ids) or not semantic_invalid
        ),
    )
    if not should_reissue_advice(input_value.prior_snapshot, snapshot):
        return input_value.prior_snapshot
    return snapshot


def select_advice_item(snapshot: AdviceSnapshot, *, allow_standing: bool) -> AdviceItem | None:
    """Pick the item the hook channel should render on this event class.

    Falls through past standing machine conditions rather than suppressing the
    whole snapshot, so a cadence-gated provider_not_ready can never mask an
    actionable finding ranked below it.
    """

    if not snapshot.ranked_items:
        # Item-less snapshots render the frontier form; see hook_advice_context.
        return None
    for item in snapshot.ranked_items:
        if allow_standing or item.recommended_next_action not in STANDING_MACHINE_ACTIONS:
            return item
    return None


def select_standing_item(snapshot: AdviceSnapshot) -> AdviceItem | None:
    """Highest-ranked workspace-standing machine condition, if the snapshot has one."""

    if not snapshot.ranked_items:
        return None
    for item in snapshot.ranked_items:
        if item.recommended_next_action in STANDING_MACHINE_ACTIONS:
            return item
    return None


def advice_delivery_identity(snapshot: AdviceSnapshot, *, item: AdviceItem | None = None) -> str:
    """Identity of the *condition* the hook channel is reporting.

    Keyed on the stable content of the delivered item — rule code, next action,
    summary, detail — and on nothing that tracks the envelope stream.

    Two exclusions are load-bearing:

    - ``evidence_basis_digest`` (and the ``freshness_frontier`` derived from
      it) is computed over every retained envelope, so it churns on every tool
      call while the rendered text is byte-identical (#241).
    - ``evidence_refs`` are excluded for the same reason. A rule's refs may be
      a rolling window over the envelope stream rather than a stable citation:
      ``observation_gap_or_stale`` cites the last three envelope identities, so
      including the ref would move the identity on every hook and recreate
      exactly the storm this identity exists to stop. ``_static_for_live``,
      ``_subagent_unaddressed``, ``_semantic_without_attempt`` and
      ``_edits_after_check`` accumulate refs the same way.

    The delivered text still carries its evidence reference; only the dedup key
    elides it. Redelivering when a citation moves but the condition has not is
    noise; withholding when the condition itself changes cannot happen, because
    rule code, next action, summary and detail are all in the key.
    """

    top = item
    if top is None and snapshot.ranked_items:
        # Mirror hook_advice_context: an item-less call renders the top item.
        top = snapshot.ranked_items[0]
    condition: JsonValue
    if top is not None:
        condition = {
            "condition_identity": top.condition_identity or "",
            "detail": top.detail,
            "next_action": top.recommended_next_action,
            "rule_code": top.rule_code,
            "summary": top.summary,
        }
    else:
        # Item-less snapshots render the frontier form, whose every component
        # (frontier token, finding ids) moves with the envelope stream. The
        # recommended action is the only stable condition such a snapshot has.
        condition = {
            "detail": "",
            "next_action": snapshot.recommended_next_action,
            "rule_code": "",
            "summary": "",
        }
    material = _DELIVERY_DOMAIN + canonical_encode({"condition": condition})
    return f"deliver-{hashlib.sha256(material).hexdigest()[:48]}"


def _hook_next_sentence(next_action: str) -> str:
    """Render the hook next-step from a snapshot token.

    ``refresh_observation`` and the standing machine actions are kernel tokens, not
    MCP tools or CLI verbs; the snapshot field stays unchanged and only this human
    clause is mapped. Machine clauses ask the agent to tell the user and offer a
    subagent fix, because only the user can repair the installation (#819).
    """

    if next_action == "refresh_observation":
        return _REFRESH_OBSERVATION_HOOK_NEXT
    machine = _MACHINE_ACTION_HOOK_NEXT.get(next_action)
    if machine is not None:
        # Keep the token: guidance maps it to the exact repair.
        return f"Next: {next_action}. {machine}"
    return f"Next: {next_action}."


def hook_advice_context(snapshot: AdviceSnapshot, *, item: AdviceItem | None = None) -> str:
    """Highest-priority summary, reason, next action, and one evidence reference.

    ``item`` renders a specific ranked item instead of the top one; the default
    is byte-identical to the historical single-argument form.
    """

    top = item
    if top is None and snapshot.ranked_items:
        top = snapshot.ranked_items[0]
    if top is not None:
        ref = top.evidence_refs[0] if top.evidence_refs else "evidence:none"
        text = (
            f"Yoetz: {top.summary}. Reason: {top.detail}. "
            f"{_hook_next_sentence(top.recommended_next_action)} Evidence: {ref}."
        )
    else:
        findings = ",".join(str(entry) for entry in snapshot.ranked_finding_ids[:8])
        text = (
            f"Yoetz advice frontier {snapshot.freshness_frontier}: "
            f"next={snapshot.recommended_next_action}; findings={findings}."
        )
    return text[:512]


def advice_items_for_ledger(snapshot: AdviceSnapshot) -> tuple[AdviceItem, ...]:
    """Local items for task-ledger materialization (Agent A coordinator hook)."""

    return tuple(item for item in snapshot.ranked_items if item.origin == "deterministic")


def validate_semantic_evidence_packet(packet: Mapping[str, JsonValue]) -> None:
    """Only producer-owned structural fields may enter an advice review envelope (#1019)."""
    if set(packet) != {
        "format",
        "policy",
        "evidence_basis_digest",
        "coverage_gaps",
        "finding_summaries",
        "deterministic_rules",
    }:
        raise ValueError("observation_advice_packet_invalid")
    if (
        packet["format"] != "yoetz.observation-advice-semantic/1"
        or packet["policy"] != f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}"
    ):
        raise ValueError("observation_advice_packet_invalid")
    validate_sha256_digest(cast(str, packet["evidence_basis_digest"]))
    gaps, summaries, rules = (
        packet[key] for key in ("coverage_gaps", "finding_summaries", "deterministic_rules")
    )
    if (
        not isinstance(gaps, list)
        or len(gaps) > MAX_KNOWN_GAPS
        or any(
            type(gap) is not str or re.fullmatch(r"[a-z][a-z0-9_./:-]{0,127}", gap) is None
            for gap in gaps
        )
        or not isinstance(summaries, list)
        or len(summaries) > 16
        or any(type(summary) is not str for summary in summaries)
        or not isinstance(rules, list)
    ):
        raise ValueError("observation_advice_packet_invalid")
    for rule in rules:
        if not isinstance(rule, dict) or set(rule) != {
            "kind",
            "rule_code",
            "next_action",
            "evidence_ref_count",
            "summary",
        }:
            raise ValueError("observation_advice_packet_invalid")
        code, action, count = rule["rule_code"], rule["next_action"], rule["evidence_ref_count"]
        if (
            type(code) is not str
            or code not in _RULE_SUMMARIES
            or type(action) is not str
            or action not in _VALID_ADVICE_NEXT_ACTIONS
            or type(count) is not int
            or count < 0
            or rule["summary"] != _RULE_SUMMARIES[code]
        ):
            raise ValueError("observation_advice_packet_invalid")
        FindingKind(cast(str, rule["kind"]))


def minimized_semantic_evidence_packet(
    candidates: Sequence[ObservationAdviceCandidate],
    basis_digest: str,
    *,
    coverage_gaps: Sequence[str] = (),
    finding_summaries: Sequence[str] = (),
) -> dict[str, object]:
    """Build a minimized packet for optional AI-powered review (no repo/transcript/logs)."""

    return {
        "format": "yoetz.observation-advice-semantic/1",
        "policy": f"{OBSERVATION_ADVICE_POLICY_ID}/{OBSERVATION_ADVICE_POLICY_VERSION}",
        "evidence_basis_digest": basis_digest,
        "coverage_gaps": tuple(sorted({gap for gap in coverage_gaps if gap}, key=str.encode)),
        "finding_summaries": tuple(finding_summaries[:16]),
        "deterministic_rules": tuple(
            {
                "kind": item.kind.value,
                "rule_code": item.rule_code,
                "next_action": item.next_action,
                "evidence_ref_count": len(item.evidence_refs),
                "summary": _RULE_SUMMARIES.get(item.rule_code, "Observation advice finding"),
            }
            for item in candidates
        ),
    }
