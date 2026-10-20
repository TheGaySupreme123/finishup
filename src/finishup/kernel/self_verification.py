"""Which open findings the agent may close as ``self_verified`` (issue #984, ADR-034).

A *FinishUP limit* is anything FinishUP cannot show or prove: capture, redaction or observation loss,
review-packet limits, an unsupported content type, a clipped diff. When the agent has repaired a
finding and only a FinishUP limit keeps the repair unproven, the agent verifies the repair itself and
responds ``self_verified`` with how it verified it and its own recorded evidence. That answer is
terminal and disclosed; it never resolves the finding and never makes a receipt read clean.

Eligibility is decided from recorded checks only, never from response prose. It reads the
resolution reasons of the newest later check that could resolve the finding
(``finding_resolution.finding_resolution_attempt``: the newest check whose policy ran to completion
over the finding's subject and, for an AI-powered finding, completed a review; otherwise the newest
later check). The proof rules themselves are unchanged.

* ``finding_not_rechecked``: no check recorded after the finding tested a state that holds it. The
  agent repairs first and runs ``check``.
* ``finding_not_proof_limited``: the reasons show that FinishUP positively still sees the issue, or
  name work the agent can do:

  - ``finding_not_in_checked_frontier``, ``matching_policy_not_completed``,
    ``subject_outside_checked_scope`` (the check did not cover it; run a full check);
  - ``no_material_change_since_finding`` (nothing changed since the finding);
  - any ``coverage:<code>`` whose ``GAP_EFFECT_TABLE`` readiness group is agent-actionable,
    route-dependent or unknown, except a task fact that does not bear on this finding
    (``kernel.task_fact_scope``, tb4n2 P1-2: an obligation-scoped fact about another obligation,
    or ``edited_after_last_verification`` on a finding that is not about verification) (only a *standing* code is a FinishUP limit, so a new standing code
    becomes self-verifiable as soon as ``kernel/gap_effect.py`` classifies it);
  - ``issue_returned_again`` for a deterministic finding (the rule fired again);
  - for an AI-powered finding, ``issue_returned_again``, ``reviewer_verdict_still_present`` or
    ``reviewer_verdict_answered_not_fixed``, unless that same check also carries a *packet* limit
    (``semantic_packet_insufficient``, ``reviewer_assessment_incomplete``,
    ``finding_material_outside_reduced_review_scope`` or a packet-side ``coverage:`` code): a
    reviewer that saw a limited packet does not positively see the issue, but an unrelated capture
    loss never overrides one that saw the repair;
  - ``findings_suppressed`` (the ranking cap withheld findings) and a transient
    ``semantic_review_not_completed`` (only a durable review block is a FinishUP limit);
  - no reasons at all (the finding resolved, or the cause is not a recorded limit), or a check
    that is unreadable or whose returned findings are unreadable (FinishUP cannot tell whether the
    issue fired again; a new check answers it).

For an AI-powered finding the reviewer-side reasons come from that newest completed review, but
the work-side task facts (``kernel.task_facts``: planned verification, edits after verification,
requested outputs; and ``command_attempt_mismatch``) and ``no_material_change_since_finding`` (read
from each check's own pre-check projection) are recomputed by every check. When a newer check ran
the finding's policy over its subject without completing a review (for example, review skipped
after the reviewer twice could not assess the finding), those codes are read from that newer check
instead (V5, V7 #1118): a stale ``planned_verification_failed`` the agent has since cleared, or a
stale "no material change" after a repair recorded since (a shell command does not re-arm the
stopped review), no longer refuses ``self_verified`` forever while the review that recorded it can
never be repeated. A code the newer check still lists keeps refusing (unchanged work still refuses),
so nothing is settled without evidence.

Every other remaining reason is a FinishUP limit, so the finding is eligible. That includes
``observed_failure_not_rerun`` (#1104): FinishUP retires an observed failed command only when the
same command (alone, or as a segment run as is inside a passing ``&&`` chain) or a planned
verification later passes, so an agent that verified the repair another way says so with
``self_verified``. ``respond`` adds the
field rules (``response_fields_invalid``) and the terminal-state rule (``finding_terminal``).
"""

from __future__ import annotations

from typing import Final

from finishup.domain.events import CheckRecordedPayload, LedgerRecord
from finishup.domain.findings import FindingOrigin
from finishup.domain.values import EventId, FindingId
from finishup.kernel.finding_resolution import finding_resolution_attempt
from finishup.kernel.gap_effect import GAP_EFFECT_TABLE, GapClass
from finishup.kernel.projections import ProjectionState
from finishup.kernel.task_fact_scope import COMMAND_ATTEMPT_MISMATCH_GAP, scoped_resolution_reasons
from finishup.kernel.task_facts import TASK_FACT_GAPS
from finishup.protocol.models import SemanticReason, SemanticStatus

__all__ = [
    "FINDING_NOT_PROOF_LIMITED",
    "FINDING_NOT_RECHECKED",
    "disqualifying_reasons",
    "finding_proof_limited",
    "reasons_proof_limited",
    "self_verification_blocking_reasons",
    "self_verification_refusal",
]

FINDING_NOT_RECHECKED: Final = "finding_not_rechecked"
FINDING_NOT_PROOF_LIMITED: Final = "finding_not_proof_limited"

# Reasons that say the check did not cover the finding, or that nothing changed: agent work.
_AGENT_WORK_REASONS: Final = frozenset(
    {
        "finding_not_in_checked_frontier",
        "matching_policy_not_completed",
        "subject_outside_checked_scope",
        "no_material_change_since_finding",
        "check_unreadable",
        "returned_findings_unreadable",
        # The check's own ranking cap withheld findings (``ranking.py``): whether this issue fired
        # again is unknown until a check returns every finding, so it is not a FinishUP limit.
        "findings_suppressed",
    }
)
# What a reviewer (or a local rule) says when it positively still sees the issue.
_STILL_SEEN_REASONS: Final = frozenset(
    {
        "issue_returned_again",
        "reviewer_verdict_still_present",
        "reviewer_verdict_answered_not_fixed",
    }
)
# Review-side limits that make an AI-powered "still seen" ruling a limited one: the reviewer's
# packet itself could not show the repair. Only packet-side limits qualify; an unrelated capture or
# observation loss elsewhere in the case never overrides a reviewer that saw the repair and still
# sees the issue (adversarial review of #984).
_REVIEW_LIMIT_REASONS: Final = frozenset(
    {
        "semantic_packet_insufficient",
        "reviewer_assessment_incomplete",
        "finding_material_outside_reduced_review_scope",
    }
)
# Packet-side ``coverage:`` codes: what the review packet could not carry or show.
_PACKET_LIMIT_CODES: Final = frozenset(
    {
        "semantic_reference_scope_reduced",
        "semantic_review_refs_reduced",
        "semantic_case_content_over_item_limit",
        "semantic_case_finding_refs_over_limit",
        "semantic_case_capacity_exceeded",
        "semantic_included_refs_not_recorded",
        "semantic_prior_findings_over_limit",
        "semantic_review_item_withheld",
        "semantic_review_value_redacted",
        "semantic_review_skipped_insufficient_packet",
        "semantic_review_context_withheld",
        "content_redacted",
        "content_unselected",
        "truncated_payload",
        "check_time_change_truncated",
        "check_time_change_redacted",
        "check_time_change_unavailable",
    }
)
# An AI-powered review that did not complete is a FinishUP limit only when no retry can complete it
# (policy, privacy, configuration or a human decision). A timeout, a rate limit or an unavailable
# transport is transient: the agent runs ``check`` again.
_REVIEW_NOT_COMPLETED: Final = "semantic_review_not_completed"
_DURABLE_UNDELIVERABLE_STATUSES: Final = frozenset(
    {
        SemanticStatus.NOT_REQUESTED,
        SemanticStatus.NOT_CONFIGURED,
        SemanticStatus.BLOCKED_BY_POLICY,
        SemanticStatus.BLOCKED_FORBIDDEN_DATA,
        SemanticStatus.CLASSIFICATION_UNCERTAIN,
        SemanticStatus.HUMAN_DENIED,
        SemanticStatus.APPROVAL_EXPIRED,
    }
)
_COVERAGE_PREFIX: Final = "coverage:"


def _standing_coverage(reason: str) -> bool | None:
    """``True``/``False`` for a ``coverage:<code>`` reason by its class; ``None`` otherwise."""

    if not reason.startswith(_COVERAGE_PREFIX):
        return None
    row = GAP_EFFECT_TABLE.get(reason[len(_COVERAGE_PREFIX) :])
    return row is not None and row.readiness is GapClass.STANDING_LIMITATION


def _packet_limit(reason: str) -> bool:
    return reason in _REVIEW_LIMIT_REASONS or (
        reason.startswith(_COVERAGE_PREFIX)
        and reason[len(_COVERAGE_PREFIX) :] in _PACKET_LIMIT_CODES
    )


# The single token reported when a check recorded no reason at all (the finding resolved, or the
# cause is not a recorded limit): nothing names a FinishUP limit.
NO_RECORDED_LIMIT: Final = "no_recorded_limit"


def disqualifying_reasons(
    reasons: tuple[str, ...],
    origin: FindingOrigin,
    *,
    review_undeliverable: bool = False,
) -> tuple[str, ...]:
    """The resolution *reasons* that keep a finding of *origin* from being proof-limited.

    Empty exactly when the reasons name only FinishUP limits (``self_verified`` is allowed). The
    result is a subsequence of *reasons* in their recorded order, so ``respond`` can name the
    closed tokens that refused it (tb4n2 R5, issue #1023); a check with no reasons at all answers
    ``(NO_RECORDED_LIMIT,)``. ``review_undeliverable`` is true when that check's AI-powered
    review did not complete for a durable reason (policy, privacy, configuration, a human
    decision); without it, ``semantic_review_not_completed`` is transient agent work.
    """

    if not reasons:
        return (NO_RECORDED_LIMIT,)
    still_seen_blocks = origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED or not any(
        _packet_limit(reason) for reason in reasons
    )
    blocking: list[str] = []
    for reason in reasons:
        if (
            (reason == _REVIEW_NOT_COMPLETED and not review_undeliverable)
            or reason in _AGENT_WORK_REASONS
            or _standing_coverage(reason) is False
            or (reason in _STILL_SEEN_REASONS and still_seen_blocks)
        ):
            blocking.append(reason)
    return tuple(dict.fromkeys(blocking))


def reasons_proof_limited(
    reasons: tuple[str, ...],
    origin: FindingOrigin,
    *,
    review_undeliverable: bool = False,
) -> bool:
    """Whether a check's resolution *reasons* name only FinishUP limits for a finding of *origin*."""

    return not disqualifying_reasons(reasons, origin, review_undeliverable=review_undeliverable)


def self_verification_refusal(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> str | None:
    """The typed refusal for a ``self_verified`` answer to *finding_id*, or ``None`` if eligible.

    ``state`` and ``records`` are the projection and the exact record prefix it replays. Pure and
    replay-derived. Terminal to-do states and field rules are ``respond``'s, not this predicate's.
    """

    refusal, _blocking = _evaluate(state, finding_id, records)
    return refusal


def self_verification_blocking_reasons(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> tuple[str, ...]:
    """The closed reasons behind a ``finding_not_proof_limited`` refusal, in recorded order.

    Empty when the answer is not that refusal. Only resolution-reason tokens recorded by a check
    (``coverage:<code>`` and the fixed reason vocabulary) are returned, never prose.
    """

    refusal, blocking = _evaluate(state, finding_id, records)
    return blocking if refusal == FINDING_NOT_PROOF_LIMITED else ()


def _attempt_reasons(
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...],
    reasons: tuple[str, ...],
) -> tuple[str, ...]:
    """The resolution reasons eligibility reads for *finding_id*, and the refusal names.

    The one seam for per-finding scoping of task-wide ``coverage:`` codes (tb4n2 R4/P1-2): task
    facts about unrelated obligations (or a task-wide edit-after-verification fact on a finding that
    is not about verification) are dropped, so eligibility and the refusal's ``blocking_reasons``
    read the same scoped reasons and a refusal never names an unrelated task fact.
    """

    return scoped_resolution_reasons(reasons, state=state, finding_id=finding_id, records=records)


# Work-side codes every check recomputes; a newer check's view of them wins. The material-change
# reason is computed from each check's own pre-check projection, not by the reviewer (V7 #1118).
_REFRESHED_CODES: Final = frozenset(
    {
        *(_COVERAGE_PREFIX + code for code in (*TASK_FACT_GAPS, COMMAND_ATTEMPT_MISMATCH_GAP)),
        "no_material_change_since_finding",
    }
)


def _refreshed_reasons(
    state: ProjectionState,
    finding_id: FindingId,
    records: tuple[LedgerRecord, ...],
    origin: FindingOrigin,
    attempt_check: EventId,
    newest_check: EventId,
    reasons: tuple[str, ...],
) -> tuple[str, ...]:
    """*reasons* with their work-side codes read from a newer check that skipped the review (V5, V7)."""

    if origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED or attempt_check == newest_check:
        return reasons
    fresh = finding_resolution_attempt(state, finding_id, records, require_review=False)
    if fresh is None or not fresh.could_resolve or fresh.check_event_id == attempt_check:
        return reasons
    order = {row.event_id: index for index, row in enumerate(records)}
    if order.get(fresh.check_event_id, -1) <= order.get(attempt_check, -1):
        return reasons
    kept = tuple(reason for reason in reasons if reason not in _REFRESHED_CODES)
    current = tuple(reason for reason in fresh.reasons if reason in _REFRESHED_CODES)
    return tuple(dict.fromkeys((*kept, *current)))


def _evaluate(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> tuple[str | None, tuple[str, ...]]:
    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return FINDING_NOT_RECHECKED, ()
    attempt = finding_resolution_attempt(state, finding_id, records)
    if attempt is None or (
        not attempt.could_resolve and "finding_not_in_checked_frontier" in attempt.reasons
    ):
        return FINDING_NOT_RECHECKED, ()
    reasons = attempt.reasons
    if attempt.could_resolve:
        reasons = _refreshed_reasons(
            state,
            finding_id,
            records,
            record.payload.origin,
            attempt.check_event_id,
            attempt.newest_check_event_id,
            reasons,
        )
    check = next((row.payload for row in records if row.event_id == attempt.check_event_id), None)
    undeliverable = type(check) is CheckRecordedPayload and (
        check.semantic_status in _DURABLE_UNDELIVERABLE_STATUSES
        # A case over the disclosure capacity is refused again until the case changes (#1118):
        # rechecking the same state cannot complete the review, so it is a FinishUP limit.
        or (
            check.semantic_status is SemanticStatus.FAILED
            and check.semantic_reason is SemanticReason.CASE_CAPACITY_EXCEEDED
        )
    )
    blocking = disqualifying_reasons(
        _attempt_reasons(state, finding_id, records, reasons),
        record.payload.origin,
        review_undeliverable=undeliverable,
    )
    if blocking:
        return FINDING_NOT_PROOF_LIMITED, blocking
    return None, ()


def finding_proof_limited(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> bool:
    """True when only FinishUP limits keep a rechecked finding unproven (``self_verified`` allowed)."""

    return self_verification_refusal(state, finding_id, records) is None
