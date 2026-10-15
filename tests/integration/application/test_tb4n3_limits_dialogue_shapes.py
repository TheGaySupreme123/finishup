"""tb4n3 RC-1 and RC-7 end to end on the real ready composition (issues #1024 and #1030).

Every case drives the real check, respond, status and receipt operations with a hermetic reviewer
that returns the output a COMPLIANT reviewer gives (the P0-3 prompt text reached every tb4n3
review; the code side is what failed). The shapes are the recorded runs:

* ks S: the reviewer says a hidden accuracy cannot be produced here and asks for a stated limit;
* vpp S: the same concern comes back under another finding kind after the agent gave up;
* lake S and pretrain S (controls): an ``act`` demand is still agent work, and the rescue (the
  acknowledgement re-check sending the agent back, a later repair resolving the finding) holds;
  lake S's real finding was a limitation request the agent answered ``acknowledged_not_done``,
  which says the requirement is NOT met (owner decision 2026-10-12), so it stays unmet;
* cargo S and formal-crypto S: a rebuttal is never erased by a later acknowledgement, and the
  agent's own republish is not new material.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from builders.projection_workflow import frontier_json, request_base
from builders.start_application import protocol_id
from finishup.application.respond import RespondInternalResult
from finishup.domain.findings import FindingKind, FindingOrigin
from finishup.kernel.finding_todo import (
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo_state,
    premise_dispute_basis,
)
from finishup.kernel.limitation import limitation_disclosed_ids, limitation_requested_ids
from finishup.kernel.projections import projection_snapshot
from finishup.kernel.receipt_capacity import receipt_blocking_finding_count
from finishup.kernel.reducers import replay
from finishup.ports.ledger import FrozenCase
from finishup.ports.semantic import (
    ReviewerChallenge,
    ReviewerNextStep,
    SemanticJudgment,
)
from finishup.protocol.canonical import JsonValue
from finishup.protocol.errors import PublicOperationError
from finishup.protocol.models import PublishWorkRequest, RespondRequest
from integration.application import test_review_dialogue_workflow as W

pytestmark = pytest.mark.anyio

type _Script = Callable[[FrozenCase], SemanticJudgment]

_LIMIT = "state_unresolved_limitation"
_REASON = "The hidden accuracy reference is withheld by the task design; it cannot be checked here."


def _obligation(frozen: FrozenCase) -> str:
    return str(next(iter(frozen.case.projection.obligations)))


def _raise(kind: FindingKind, next_step: ReviewerNextStep, *extra: str) -> _Script:
    """A compliant reviewer challenge on the plan's obligation with the given next step."""

    def script(frozen: FrozenCase) -> SemanticJudgment:
        challenge = ReviewerChallenge(
            kind,
            "The required reference comparison is not established",
            tuple(sorted((_obligation(frozen), *extra))),
            "The packet shows no comparison against the reference.",
            "The reference may be withheld by the task design.",
            "Main agent: state what cannot be verified."
            if next_step == _LIMIT
            else "Main agent: do the comparison.",
            next_step,
            "Only the withheld reference would settle it.",
        )
        return SemanticJudgment("challenges_returned", (challenge,))

    return script


async def _respond(
    session: W._Session,
    frontier: object,
    finding_frontier: object,
    finding: object,
    seed: int,
    disposition: str,
    reason: str | None,
) -> RespondInternalResult:
    return await session.app.respond(
        RespondRequest.model_validate(
            W._respond_wire(
                session,
                cast(JsonValue, frontier),
                cast(JsonValue, finding_frontier),
                cast(W.Finding, finding),
                seed,
                disposition,
                reason,
            )
        )
    )


def _draft(
    event: str, schema: str, payload: dict[str, JsonValue], *, parents: list[str] | None = None
) -> dict[str, JsonValue]:
    return {
        "event_id": event,
        "schema": {"name": schema, "version": "1.0.0"},
        "occurred_at": "2026-09-28T12:10:00.000Z",
        "causal_parents": cast(JsonValue, parents or []),
        "payload": payload,
        "artifact_refs": [],
        "evidence_refs": [],
    }


async def _publish(
    session: W._Session, frontier: JsonValue, seed: int, drafts: list[dict[str, JsonValue]]
):
    return await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "event_drafts": drafts,
            }
        )
    )


def _semantic_findings(session: W._Session) -> tuple[str, ...]:
    return tuple(
        str(key)
        for key, row in W._live_projection(session.app).findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )


def _rebuilt_equals_live(session: W._Session) -> None:
    assert projection_snapshot(replay(W._records(session.app))) == projection_snapshot(
        W._live_projection(session.app)
    )


# --- (b1) ks S: a limitation request is a to-disclose item, one acknowledgement settles it --------


async def test_ks_s_a_limitation_request_is_not_work_and_one_acknowledgement_settles_it() -> None:
    seed = 9100
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, _LIMIT)])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    request = W._semantic(first)

    # The check is not action_required, and the item is not counted as receipt-blocking work.
    assert first.verdict.value == "insufficient_coverage"
    live = W._live_projection(session.app)
    assert request.challenge is not None and request.challenge.requested_next_step == _LIMIT
    assert receipt_blocking_finding_count(live) == 0
    assert finding_blocks_receipt(live, request.finding_id) is False
    assert limitation_requested_ids(live) == (request.finding_id,)

    # One acknowledgement with a reason settles it; no recorded resolution attempt is needed.
    at = frontier_json(first.result_frontier)
    recorded = await session.app.respond(
        RespondRequest.model_validate(
            W._respond_wire(session, at, at, request, seed + 20, "acknowledged", _REASON)
        )
    )
    assert recorded.closure_after is not None
    assert recorded.closure_after.limitation == "limitation_disclosed"
    assert recorded.closure_after.todo_state == "open"
    live = W._live_projection(session.app)
    assert limitation_disclosed_ids(live) == (request.finding_id,)
    assert limitation_requested_ids(live) == ()
    assert receipt_blocking_finding_count(live) == 0
    _rebuilt_equals_live(session)


async def test_ks_s_a_limitation_request_answered_not_done_is_an_unmet_requirement() -> None:
    """Owner decision 2026-10-12: the agent's answer decides what the request means.

    ``acknowledged_not_done`` says the requirement is NOT met, so it is not a verification limit:
    the finding blocks the receipt like any requirement acknowledged as not done, and the respond
    result says so (``closure_after.limitation``).
    """

    seed = 9150
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, _LIMIT)])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    request = W._semantic(first)
    at = frontier_json(first.result_frontier)
    recorded = await _respond(session, at, at, request, seed + 20, "acknowledged_not_done", _REASON)
    assert recorded.closure_after is not None
    assert recorded.closure_after.limitation == "limitation_acknowledged_not_done"
    assert recorded.closure_after.todo_state == "acknowledged_not_done"
    live = W._live_projection(session.app)
    assert finding_blocks_receipt(live, request.finding_id) is True
    assert receipt_blocking_finding_count(live) == 1
    assert limitation_disclosed_ids(live) == () and limitation_requested_ids(live) == ()
    _rebuilt_equals_live(session)

    # Taking it back with ``reopened`` returns it to something to disclose; the agent may then
    # state the limit instead.
    back = await _respond(
        session,
        frontier_json(recorded.result_frontier),
        at,
        request,
        seed + 30,
        "reopened",
        "It may be met but I cannot measure it here.",
    )
    assert back.closure_after is not None
    assert back.closure_after.limitation == "limitation_requested"
    disclosed = await _respond(
        session,
        frontier_json(back.result_frontier),
        at,
        request,
        seed + 40,
        "acknowledged",
        _REASON,
    )
    assert disclosed.closure_after is not None
    assert disclosed.closure_after.limitation == "limitation_disclosed"
    live = W._live_projection(session.app)
    assert receipt_blocking_finding_count(live) == 0
    assert limitation_disclosed_ids(live) == (request.finding_id,)


async def test_an_act_finding_still_needs_a_recorded_resolution_attempt_to_acknowledge() -> None:
    """The relaxation is for the reviewer's limitation request only (guard G1)."""

    seed = 9200
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, "act")])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    work = W._semantic(first)
    at = frontier_json(first.result_frontier)
    with pytest.raises(PublicOperationError) as refused:
        await session.app.respond(
            RespondRequest.model_validate(
                W._respond_wire(session, at, at, work, seed + 20, "acknowledged", _REASON)
            )
        )
    assert W._refusal(refused) == "resolution_attempt_required"
    assert first.verdict.value == "action_required"


# --- (d) vpp S: the same concern under another kind is recorded on the settled item ---------------


@pytest.mark.parametrize(
    ("disposition", "limitation", "blocking"),
    [
        ("acknowledged", "limitation_disclosed", 0),
        ("acknowledged_not_done", "limitation_acknowledged_not_done", 1),
    ],
)
async def test_vpp_s_one_concern_stays_one_finding_across_kinds_and_checks(
    disposition: str, limitation: str, blocking: int
) -> None:
    """Three ids for one private-reference concern became one, answered once.

    The fold is the same for both answers; what the answer means is not: ``acknowledged`` says the
    requirement may be met but cannot be verified here (disclosed, non-blocking) and
    ``acknowledged_not_done`` says it is not met (unmet, receipt-blocking).
    """

    seed = 9300
    reviewer = W._Reviewer(
        [
            _raise(FindingKind.TASK_REQUIREMENT_UNMET, _LIMIT),
            _raise(FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS, _LIMIT),
            _raise(FindingKind.TASK_REQUIREMENT_UNMET, _LIMIT),
        ]
    )
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    request = W._semantic(first)
    at = frontier_json(first.result_frontier)
    gave_up = await session.app.respond(
        RespondRequest.model_validate(
            W._respond_wire(session, at, at, request, seed + 20, disposition, _REASON)
        )
    )
    assert gave_up.closure_after is not None
    assert gave_up.closure_after.limitation == limitation

    second = await W._check(session, frontier_json(gave_up.result_frontier), seed + 30)
    assert second.findings == () or all(
        finding.origin is not FindingOrigin.SEMANTIC_MODEL_DERIVED for finding in second.findings
    )
    assert "semantic_restatements_suppressed" in second.coverage.known_gaps
    assert second.review_summary is not None
    assert "already settled" in second.review_summary
    assert "answer it there" not in second.review_summary

    third = await W._check(session, frontier_json(second.result_frontier), seed + 40)
    assert "semantic_restatements_suppressed" in third.coverage.known_gaps
    assert _semantic_findings(session) == (request.finding_id,)
    live = W._live_projection(session.app)
    assert live.findings[request.finding_id].settled_reraise_count == 2
    assert limitation_disclosed_ids(live) == ((request.finding_id,) if not blocking else ())
    assert receipt_blocking_finding_count(live) == blocking
    _rebuilt_equals_live(session)


async def test_a_self_verified_answer_folds_a_repeat_without_newer_material() -> None:
    """vpp S fnd_408c096e: a bookkeeping re-raise over ``self_verified`` minted a fresh finding.

    Changed from the #984 adversarial-review lock that a later sighting is always minted: with no
    concern-relevant newer material the repeat is recorded on the settled item (tb4n3 RC-7).
    """

    seed = 9400
    reviewer = W._Reviewer(
        [
            W._challenge_obligation,
            W._rule_first_finding_on_a_complete_packet(None),
            W._challenge_obligation,
        ],
        content_gaps={1: ("content_unselected",)},
    )
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    raised = W._semantic(first)
    at = frontier_json(first.result_frontier)
    result_id, repaired = await W._repair(session, at, seed + 20)
    evidence_id, evidenced = await W._artifact_evidence(session, repaired, seed + 30)
    second = await W._check(session, evidenced, seed + 40)
    recorded = await session.app.respond(
        RespondRequest.model_validate(
            W._self_verified_wire(
                session,
                frontier_json(second.result_frontier),
                at,
                raised,
                seed + 52,
                "Re-ran the suite myself; output recorded.",
                (evidence_id, result_id),
            )
        )
    )
    third = await W._check(session, frontier_json(recorded.result_frontier), seed + 60)
    assert not any(
        finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED for finding in third.findings
    )
    assert "semantic_restatements_suppressed" in third.coverage.known_gaps
    live = W._live_projection(session.app)
    assert _semantic_findings(session) == (raised.finding_id,)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.SELF_VERIFIED
    assert live.findings[raised.finding_id].settled_reraise_count == 1
    assert receipt_blocking_finding_count(live) == 0
    _rebuilt_equals_live(session)


# --- (b3) formal-crypto S: a concern that first appears in a re-raise folds onto the settled item --


def _raise_on(kind: FindingKind, next_step: ReviewerNextStep, *refs: str) -> _Script:
    """A compliant reviewer challenge citing exactly *refs* (sorted)."""

    def script(frozen: FrozenCase) -> SemanticJudgment:
        del frozen
        challenge = ReviewerChallenge(
            kind,
            "The required reference comparison is not established",
            tuple(sorted(refs)),
            "The packet shows no comparison against the reference.",
            "The reference may be withheld by the task design.",
            "Main agent: do the comparison.",
            next_step,
            "Only the withheld reference would settle it.",
        )
        return SemanticJudgment("challenges_returned", (challenge,))

    return script


async def _second_obligation(
    session: W._Session, frontier: JsonValue, seed: int
) -> tuple[str, JsonValue]:
    obligation = protocol_id("obl_", seed)
    published = await _publish(
        session,
        frontier,
        seed + 1,
        [
            _draft(
                protocol_id("evt_", seed + 2),
                "obligation_published",
                {
                    "obligation_id": obligation,
                    "description": "Cover the second reference vector.",
                    "acceptance_criteria": "The vector matches.",
                    "evidence_expectation": "A recorded test result.",
                    "requested_items": [{"item_kind": "change", "value": "vector"}],
                    "status": "open",
                },
            )
        ],
    )
    return obligation, frontier_json(published.result_frontier)


async def test_formal_crypto_s_a_concern_first_named_in_a_reraise_stays_one_finding() -> None:
    """formal-crypto S: five ids for one give-up. The second review re-raised the settled item
    with an obligation the first never named; the third named only that obligation. The settled
    item remembers what its re-raise cited, so the third folds instead of minting. (The second
    obligation exists before the agent's answer: an obligation published after it is new
    material about the concern and is minted, see the control below.)"""

    seed = 9900
    second_obligation = protocol_id("obl_", seed + 70)
    first_obligation = protocol_id("obl_", seed + 1)  # the session's own obligation id
    reviewer = W._Reviewer(
        [
            _raise_on(FindingKind.TASK_REQUIREMENT_UNMET, "act", first_obligation),
            _raise_on(
                FindingKind.TASK_REQUIREMENT_UNMET, "act", first_obligation, second_obligation
            ),
            _raise_on(FindingKind.TASK_REQUIREMENT_UNMET, "act", second_obligation),
        ]
    )
    session, frontier = await W._session(reviewer, seed)
    added, frontier = await _second_obligation(session, frontier, seed + 70)
    assert added == second_obligation
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)
    gave_up = await _respond(
        session, at, at, unmet, seed + 20, "acknowledged_not_done", "No solver is feasible."
    )
    second = await W._check(session, frontier_json(gave_up.result_frontier), seed + 30)
    assert _semantic_findings(session) == (unmet.finding_id,)
    live = W._live_projection(session.app)
    assert live.findings[unmet.finding_id].settled_reraise_count == 1
    assert second_obligation in live.findings[unmet.finding_id].absorbed_refs

    third = await W._check(session, frontier_json(second.result_frontier), seed + 40)
    assert "semantic_restatements_suppressed" in third.coverage.known_gaps
    assert _semantic_findings(session) == (unmet.finding_id,)
    live = W._live_projection(session.app)
    assert live.findings[unmet.finding_id].settled_reraise_count == 2
    _rebuilt_equals_live(session)


async def test_formal_crypto_s_control_a_different_obligation_alone_is_a_distinct_finding() -> None:
    """The fold is earned by the re-raise, not by the obligation being old: with no re-raise
    that cited it, a challenge naming only the second obligation is its own issue."""

    seed = 10000
    second_obligation = protocol_id("obl_", seed + 70)
    reviewer = W._Reviewer(
        [
            _raise_on(FindingKind.TASK_REQUIREMENT_UNMET, "act", protocol_id("obl_", seed + 1)),
            _raise_on(FindingKind.TASK_REQUIREMENT_UNMET, "act", second_obligation),
        ]
    )
    session, frontier = await W._session(reviewer, seed)
    _added, frontier = await _second_obligation(session, frontier, seed + 70)
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)
    gave_up = await _respond(
        session, at, at, unmet, seed + 20, "acknowledged_not_done", "No solver is feasible."
    )
    await W._check(session, frontier_json(gave_up.result_frontier), seed + 30)
    assert len(_semantic_findings(session)) == 2
    assert W._live_projection(session.app).findings[unmet.finding_id].absorbed_refs == ()


async def test_an_obligation_published_after_the_give_up_is_new_material_and_is_minted() -> None:
    """The other side of the rule: a requirement the plan gained after the agent's answer is a
    new sighting, not a repeat of the settled concern (introduced_frontier beats the answer)."""

    seed = 10100
    second_obligation = protocol_id("obl_", seed + 70)
    reviewer = W._Reviewer(
        [
            _raise_on(FindingKind.TASK_REQUIREMENT_UNMET, "act", protocol_id("obl_", seed + 1)),
            _raise_on(
                FindingKind.TASK_REQUIREMENT_UNMET,
                "act",
                protocol_id("obl_", seed + 1),
                second_obligation,
            ),
        ]
    )
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)
    gave_up = await _respond(
        session, at, at, unmet, seed + 20, "acknowledged_not_done", "No solver is feasible."
    )
    _added, after = await _second_obligation(
        session, frontier_json(gave_up.result_frontier), seed + 70
    )
    await W._check(session, after, seed + 30)
    assert len(_semantic_findings(session)) == 2


# --- controls: lake S and pretrain S ---------------------------------------------------------------


async def test_lake_s_control_an_act_demand_answered_not_done_stays_unmet() -> None:
    seed = 9500
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, "act")])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)
    await _respond(session, at, at, unmet, seed + 20, "acknowledged_not_done", "RMSE 2.0 stays.")
    live = W._live_projection(session.app)
    assert finding_todo_state(live, unmet.finding_id) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert finding_blocks_receipt(live, unmet.finding_id) is True
    assert receipt_blocking_finding_count(live) == 1
    assert limitation_disclosed_ids(live) == () and limitation_requested_ids(live) == ()


async def test_lake_s_a_limitation_request_answered_not_done_keeps_the_receipt_unresolved() -> None:
    """lake S ``fnd_8bdad2d0``: the real finding was a limitation request the agent answered
    ``acknowledged_not_done`` (accuracy really unmet). It stays an unmet requirement."""

    seed = 9550
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, _LIMIT)])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    request = W._semantic(first)
    at = frontier_json(first.result_frontier)
    await _respond(
        session, at, at, request, seed + 20, "acknowledged_not_done", "RMSE 2.0 stays unmet."
    )
    live = W._live_projection(session.app)
    assert finding_todo_state(live, request.finding_id) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert finding_blocks_receipt(live, request.finding_id) is True
    assert receipt_blocking_finding_count(live) == 1
    assert limitation_disclosed_ids(live) == () and limitation_requested_ids(live) == ()


async def test_pretrain_s_control_the_give_up_is_disputed_and_a_later_repair_resolves_it() -> None:
    """The ack re-check input survives, and the finding is no longer a one-way door."""

    seed = 9600
    reviewer = W._Reviewer(
        [
            _raise(FindingKind.TASK_REQUIREMENT_UNMET, "act"),
            _raise(FindingKind.TASK_REQUIREMENT_UNMET, "act"),
            W._no_challenges,
        ]
    )
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)
    gave_up = await _respond(
        session, at, at, unmet, seed + 20, "acknowledged_not_done", "The inputs cannot be found."
    )
    after_give_up = frontier_json(gave_up.result_frontier)
    second = await W._check(session, after_give_up, seed + 30)
    live = W._live_projection(session.app)
    # Re-raised after the give-up: the standing premise dispute the Stop gate challenges once.
    assert live.findings[unmet.finding_id].settled_reraise_count == 1
    assert premise_dispute_basis(live, unmet.finding_id) == "give_up_reraised"
    assert limitation_disclosed_ids(live) == ()
    assert _semantic_findings(session) == (unmet.finding_id,)

    # The agent goes back, recovers the inputs and records the repair; a clean review proves it.
    _result, repaired = await W._repair(session, frontier_json(second.result_frontier), seed + 40)
    third = await W._check(session, repaired, seed + 60)
    live = W._live_projection(session.app)
    assert finding_todo_state(live, unmet.finding_id) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_blocks_receipt(live, unmet.finding_id) is False
    assert receipt_blocking_finding_count(live) == 0
    receipt = await W._receipt(session, frontier_json(third.result_frontier), seed + 80, "json")
    assert receipt.conclusion != "unresolved_findings_remain"
    _rebuilt_equals_live(session)


# --- (b2) cargo S: a rebuttal stands over a later acknowledgement ---------------------------------


async def test_cargo_s_a_rebuttal_is_not_erased_by_a_later_acknowledgement() -> None:
    seed = 9700
    reviewer = W._Reviewer(
        [_raise(FindingKind.TASK_REQUIREMENT_UNMET, "act"), W._withdraw_first_finding]
    )
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    flagged = W._semantic(first)
    at = frontier_json(first.result_frontier)
    rejected = await _respond(
        session, at, at, flagged, seed + 20, "rejected", "The signature spans several lines."
    )
    # The agent, confused by the gate, then also acknowledges it with a recorded repair: the
    # rebuttal still stands.
    result_id, repaired = await W._repair(
        session,
        frontier_json(rejected.result_frontier),
        seed + 22,
    )
    wire = W._respond_wire(
        session,
        repaired,
        at,
        flagged,
        seed + 27,
        "acknowledged",
        "Added the signature evidence anyway.",
    )
    wire["evidence_refs"] = [result_id]
    acknowledged = await session.app.respond(RespondRequest.model_validate(wire))
    second = await W._check(session, frontier_json(acknowledged.result_frontier), seed + 30)
    live = W._live_projection(session.app)
    # The reviewer withdrew: accepted although the latest answer was an acknowledgement.
    assert finding_todo_state(live, flagged.finding_id) is FindingTodoState.REJECTION_ACCEPTED
    assert finding_blocks_receipt(live, flagged.finding_id) is False
    assert second.review_summary is None or "answer it there" not in second.review_summary
    _rebuilt_equals_live(session)


# --- reopened and the refusals that say what happened ----------------------------------------------


async def test_reopened_takes_a_give_up_back_and_every_refusal_names_the_way_out() -> None:
    seed = 9800
    reviewer = W._Reviewer([_raise(FindingKind.TASK_REQUIREMENT_UNMET, "act")])
    session, frontier = await W._session(reviewer, seed)
    first = await W._check(session, frontier, seed + 10)
    unmet = W._semantic(first)
    at = frontier_json(first.result_frontier)

    # Nothing to reopen on an open finding.
    with pytest.raises(PublicOperationError) as nothing:
        await _respond(session, at, at, unmet, seed + 15, "reopened", "I will do it.")
    assert W._refusal(nothing) == "response_fields_invalid"

    gave_up = await _respond(
        session, at, at, unmet, seed + 20, "acknowledged_not_done", "The inputs cannot be found."
    )
    after = frontier_json(gave_up.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await _respond(session, after, at, unmet, seed + 21, "rejected", "Changed my mind.")
    assert W._refusal(terminal) == "finding_terminal"
    assert "reopened" in terminal.value.message
    assert "answer it there" not in terminal.value.message

    reopened = await _respond(
        session, after, at, unmet, seed + 22, "reopened", "Recovered the inputs; doing the work."
    )
    assert reopened.closure_after is not None
    assert reopened.closure_after.todo_state == "open"
    live = W._live_projection(session.app)
    assert finding_todo_state(live, unmet.finding_id) is FindingTodoState.OPEN
    assert finding_blocks_receipt(live, unmet.finding_id) is True
    assert live.findings[unmet.finding_id].standing_position is None
    _rebuilt_equals_live(session)
