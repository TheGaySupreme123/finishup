"""Which open findings the agent may close as ``self_verified`` (issue #984, ADR-034).

A *Yoetz limit* is anything Yoetz cannot show or prove: capture, redaction or observation loss,
review-packet limits, an unsupported content type, a clipped diff. When the agent has repaired a
finding and only a Yoetz limit keeps the repair unproven, the agent verifies the repair itself and
responds ``self_verified`` with how it verified it and its own recorded evidence. That answer is
terminal and disclosed; it never resolves the finding and never makes a receipt read clean.

Eligibility is decided from recorded checks only, never from response prose. It reads the
resolution reasons of the newest later check that could resolve the finding
(``finding_resolution.finding_resolution_attempt``: the newest check whose policy ran to completion
over the finding's subject and, for an AI-powered finding, completed a review; otherwise the newest
later check). The proof rules themselves are unchanged.

* ``finding_not_rechecked``: no check recorded after the finding tested a state that holds it. The
  agent repairs first and runs ``check``.
* ``finding_not_proof_limited``: the reasons show that Yoetz positively still sees the issue, or
  name work the agent can do:

  - ``finding_not_in_checked_frontier``, ``matching_policy_not_completed``,
    ``subject_outside_checked_scope`` (the check did not cover it; run a full check);
  - ``no_material_change_since_finding`` (nothing changed since the finding);
  - any ``coverage:<code>`` whose ``GAP_CLASSIFICATION`` class is agent-actionable,
    route-dependent or unknown (only a *standing* code is a Yoetz limit, so a new standing code
    becomes self-verifiable as soon as ``kernel/closure_readiness.py`` classifies it);
  - ``issue_returned_again`` for a deterministic finding (the rule fired again);
  - for an AI-powered finding, ``issue_returned_again``, ``reviewer_verdict_still_present`` or
    ``reviewer_verdict_answered_not_fixed``, unless that same check also carries a review limit
    (``semantic_packet_insufficient``, ``reviewer_assessment_incomplete``,
    ``finding_material_outside_reduced_review_scope``, ``freshness_unproven`` or a standing
    ``coverage:`` code): a reviewer that saw a limited packet does not positively see the issue;
  - no reasons at all (the finding resolved, or the cause is not a recorded limit), or a check
    that is unreadable or whose returned findings are unreadable (Yoetz cannot tell whether the
    issue fired again; a new check answers it).

Every other remaining reason is a Yoetz limit, so the finding is eligible. ``respond`` adds the
field rules (``response_fields_invalid``) and the terminal-state rule (``finding_terminal``).
"""

from __future__ import annotations

from typing import Final

from yoetz.domain.events import LedgerRecord
from yoetz.domain.findings import FindingOrigin
from yoetz.domain.values import FindingId
from yoetz.kernel.closure_readiness import GAP_CLASSIFICATION, GapClass
from yoetz.kernel.finding_resolution import finding_resolution_attempt
from yoetz.kernel.projections import ProjectionState

__all__ = [
    "FINDING_NOT_PROOF_LIMITED",
    "FINDING_NOT_RECHECKED",
    "finding_proof_limited",
    "reasons_proof_limited",
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
# Review-side limits that make an AI-powered "still seen" ruling a limited one.
_REVIEW_LIMIT_REASONS: Final = frozenset(
    {
        "semantic_packet_insufficient",
        "reviewer_assessment_incomplete",
        "finding_material_outside_reduced_review_scope",
        "freshness_unproven",
    }
)
_COVERAGE_PREFIX: Final = "coverage:"


def _standing_coverage(reason: str) -> bool | None:
    """``True``/``False`` for a ``coverage:<code>`` reason by its class; ``None`` otherwise."""

    if not reason.startswith(_COVERAGE_PREFIX):
        return None
    code = reason[len(_COVERAGE_PREFIX) :]
    return GAP_CLASSIFICATION.get(code) is GapClass.STANDING_LIMITATION


def reasons_proof_limited(reasons: tuple[str, ...], origin: FindingOrigin) -> bool:
    """Whether a check's resolution *reasons* name only Yoetz limits for a finding of *origin*."""

    if not reasons:
        return False
    if any(reason in _AGENT_WORK_REASONS for reason in reasons):
        return False
    if any(_standing_coverage(reason) is False for reason in reasons):
        return False
    still_seen = any(reason in _STILL_SEEN_REASONS for reason in reasons)
    if still_seen:
        if origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED:
            return False
        review_limited = any(
            reason in _REVIEW_LIMIT_REASONS or _standing_coverage(reason) is True
            for reason in reasons
        )
        if not review_limited:
            return False
    return True


def self_verification_refusal(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> str | None:
    """The typed refusal for a ``self_verified`` answer to *finding_id*, or ``None`` if eligible.

    ``state`` and ``records`` are the projection and the exact record prefix it replays. Pure and
    replay-derived. Terminal to-do states and field rules are ``respond``'s, not this predicate's.
    """

    record = state.findings.get(finding_id)
    if record is None or record.payload is None:
        return FINDING_NOT_RECHECKED
    attempt = finding_resolution_attempt(state, finding_id, records)
    if attempt is None or (
        not attempt.could_resolve and "finding_not_in_checked_frontier" in attempt.reasons
    ):
        return FINDING_NOT_RECHECKED
    if not reasons_proof_limited(attempt.reasons, record.payload.origin):
        return FINDING_NOT_PROOF_LIMITED
    return None


def finding_proof_limited(
    state: ProjectionState, finding_id: FindingId, records: tuple[LedgerRecord, ...]
) -> bool:
    """True when only Yoetz limits keep a rechecked finding unproven (``self_verified`` allowed)."""

    return self_verification_refusal(state, finding_id, records) is None
