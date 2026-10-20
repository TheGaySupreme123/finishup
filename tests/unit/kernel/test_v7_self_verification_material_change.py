"""#1118 V7 F1: a repaired AI-powered finding is not stranded on a stale "no material change".

After two ``insufficient_packet`` reviews with nothing recorded in between, the last completed
review lists ``no_material_change_since_finding``. The agent then repairs through a shell command
(an ``ActionKind.COMMAND``, which does not re-arm the stopped review round) and records a passing
verification; the next check runs the local policy but skips the reviewer. That reason is a
work-side fact every check recomputes from its own pre-check projection, so the newer
policy-complete check supplies it, exactly like the task facts (V5). Unchanged work still refuses.

These replay real accepted events through the production reducers and historical proof
reconstruction; nothing in production is mocked.
"""

from __future__ import annotations

from dataclasses import replace

from builders.observed_runs import ObservedLedger
from builders.policy_cases import act, fnd
from finishup.domain.events import ActionKind, ActionRecordedPayload, EventSchema, ResultOutcome
from finishup.domain.findings import FindingOrigin
from finishup.kernel.finding_resolution import finding_resolution_attempt
from finishup.kernel.reducers import replay
from finishup.kernel.review_round import review_round_stopped
from finishup.kernel.self_verification import (
    FINDING_NOT_PROOF_LIMITED,
    self_verification_blocking_reasons,
    self_verification_refusal,
)
from unit.kernel import test_finding_resolution as fr

_NO_CHANGE = "no_material_change_since_finding"
_LOCAL_GAPS = ("semantic_review_not_requested", "semantic_review_skipped_insufficient_packet")


def _stopped_round() -> ObservedLedger:
    """An AI finding, then two reviews that could not assess the packet: the round stops."""

    ledger = ObservedLedger()
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(act(1), ActionKind.EDIT, "Initial work"),
        observed=False,
    )
    finding = replace(
        fr._finding(  # pyright: ignore[reportPrivateUsage]
            origin=FindingOrigin.SEMANTIC_MODEL_DERIVED, subject_refs=(ledger.records[-1].event_id,)
        ),
        subject_frontier=ledger.frontier,
    )
    ledger.append(EventSchema("finding_recorded", "1.3.0"), finding, observed=False)
    for _ in range(2):
        review = replace(
            fr._review_check(tested=ledger.frontier.sequence),  # pyright: ignore[reportPrivateUsage]
            subject_frontier=ledger.frontier,
            semantic_conclusion="insufficient_packet",
        )
        ledger.append(EventSchema("check_recorded", "1.3.0"), review, observed=False)
    assert review_round_stopped(ledger.prefix)
    return ledger


def _local_check(ledger: ObservedLedger) -> None:
    """A later check: the policy ran over the subject, the stopped review was skipped."""

    check = fr._check(  # pyright: ignore[reportPrivateUsage]
        tested=ledger.frontier.sequence,
        coverage=fr._coverage(gaps=_LOCAL_GAPS),  # pyright: ignore[reportPrivateUsage]
    )
    check = replace(check, subject_frontier=ledger.frontier)
    ledger.append(EventSchema("check_recorded", "1.2.0"), check, observed=False)


def test_a_shell_repair_after_the_round_stopped_is_self_verifiable() -> None:
    ledger = _stopped_round()
    stale = replay(ledger.prefix)
    assert self_verification_refusal(stale, fnd(1), ledger.prefix) == FINDING_NOT_PROOF_LIMITED
    assert _NO_CHANGE in self_verification_blocking_reasons(stale, fnd(1), ledger.prefix)
    # Repair through a shell command and a passing verification; the round stays stopped.
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(act(2), ActionKind.COMMAND, "Repair", command="python3 repair.py"),
        observed=False,
    )
    ledger.run("python3 verify.py", ResultOutcome.SUCCESS, exit_status=0, observed=False)
    _local_check(ledger)
    state = replay(ledger.prefix)
    assert review_round_stopped(ledger.prefix)
    review = finding_resolution_attempt(state, fnd(1), ledger.prefix)
    local = finding_resolution_attempt(state, fnd(1), ledger.prefix, require_review=False)
    assert review is not None and local is not None
    assert _NO_CHANGE in review.reasons
    assert _NO_CHANGE not in local.reasons
    assert self_verification_blocking_reasons(state, fnd(1), ledger.prefix) == ()
    assert self_verification_refusal(state, fnd(1), ledger.prefix) is None
    # Self-verification is an exit, never a resolution: the review's blockers still stand.
    assert review.reasons


def test_an_unchanged_check_after_the_round_stopped_still_refuses() -> None:
    ledger = _stopped_round()
    _local_check(ledger)
    state = replay(ledger.prefix)
    assert self_verification_refusal(state, fnd(1), ledger.prefix) == FINDING_NOT_PROOF_LIMITED
    assert _NO_CHANGE in self_verification_blocking_reasons(state, fnd(1), ledger.prefix)
