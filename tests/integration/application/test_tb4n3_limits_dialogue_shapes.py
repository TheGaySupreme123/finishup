"""tb4n3 RC-1 and RC-7 end to end on the real ready composition (issues #1024 and #1030).

Every case drives the real check, respond, status and receipt operations with a hermetic reviewer
that returns the output a COMPLIANT reviewer gives (the P0-3 prompt text reached every tb4n3
review; the code side is what failed). The shapes are the recorded runs:

* ks S: the reviewer says a hidden accuracy cannot be produced here and asks for a stated limit;
* vpp S: the same concern comes back under another finding kind after the agent gave up;
* lake S and pretrain S (controls): an ``act`` demand is still agent work, and the rescue (the
  acknowledgement re-check sending the agent back, a later repair resolving the finding) holds;
* cargo S and formal-crypto S: a rebuttal is never erased by a later acknowledgement, and the
  agent's own republish is not new material.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import cast

import pytest

from builders.projection_workflow import frontier_json, request_base
from builders.start_application import protocol_id
from integration.application import test_review_dialogue_workflow as W
from yoetz.domain.findings import FindingKind, FindingOrigin
from yoetz.kernel.finding_todo import (
    FindingTodoState,
    finding_blocks_receipt,
    finding_todo_state,
    premise_dispute_basis,
)
from yoetz.kernel.limitation import limitation_disclosed_ids, limitation_requested_ids
from yoetz.kernel.projections import projection_snapshot
from yoetz.kernel.receipt_capacity import receipt_blocking_finding_count
from yoetz.kernel.reducers import replay
from yoetz.ports.ledger import FrozenCase
from yoetz.ports.semantic import PriorFindingVerdict, ReviewerChallenge, SemanticJudgment
from yoetz.protocol.canonical import JsonValue
from yoetz.protocol.errors import PublicOperationError
from yoetz.protocol.models import PublishWorkRequest, RespondRequest

pytestmark = pytest.mark.anyio

type _Script = Callable[[FrozenCase], SemanticJudgment]

_LIMIT = "state_unresolved_limitation"
_REASON = "The hidden accuracy reference is withheld by the task design; it cannot be checked here."


def _obligation(frozen: FrozenCase) -> str:
    return str(next(iter(frozen.case.projection.obligations)))


def _raise(kind: FindingKind, next_step: str, *extra: str) -> _Script:
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
) -> object:
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


async def test_vpp_s_one_concern_stays_one_finding_across_kinds_and_checks() -> None:
    """Three ids for one private-reference concern became one, disclosed once."""

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
            W._respond_wire(session, at, at, request, seed + 20, "acknowledged_not_done", _REASON)
        )
    )
    assert gave_up.closure_after is not None
    assert gave_up.closure_after.limitation == "limitation_disclosed"

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
    assert limitation_disclosed_ids(live) == (request.finding_id,)
    assert receipt_blocking_finding_count(live) == 0
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
    after_give_up = frontier_json(gave_up.result_frontier)  # type: ignore[attr-defined]
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
    withdrawn = W._withdraw_first_finding

    def repeat_without_newer(frozen: FrozenCase) -> SemanticJudgment:
        finding = next(iter(frozen.case.projection.findings))
        return SemanticJudgment(
            "no_material_discrepancy", (), (PriorFindingVerdict(str(finding), "still_present", ()),)
        )

    del withdrawn
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
        seed + 22,  # type: ignore[attr-defined]
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
    second = await W._check(session, frontier_json(acknowledged.result_frontier), seed + 30)  # type: ignore[attr-defined]
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
    after = frontier_json(gave_up.result_frontier)  # type: ignore[attr-defined]
    with pytest.raises(PublicOperationError) as terminal:
        await _respond(session, after, at, unmet, seed + 21, "rejected", "Changed my mind.")
    assert W._refusal(terminal) == "finding_terminal"
    assert "reopened" in terminal.value.message
    assert "answer it there" not in terminal.value.message

    reopened = await _respond(
        session, after, at, unmet, seed + 22, "reopened", "Recovered the inputs; doing the work."
    )
    assert reopened.closure_after.todo_state == "open"  # type: ignore[attr-defined]
    live = W._live_projection(session.app)
    assert finding_todo_state(live, unmet.finding_id) is FindingTodoState.OPEN
    assert finding_blocks_receipt(live, unmet.finding_id) is True
    assert live.findings[unmet.finding_id].standing_position is None
    _rebuilt_equals_live(session)
