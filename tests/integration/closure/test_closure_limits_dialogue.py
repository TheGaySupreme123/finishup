"""Limitation requests (RC-1) and the answer lifecycle (RC-7) read as one verdict (tb4n3, ADR-046).

Each case drives the real operations through the closure-shape harness and asserts with
``assert_surfaces_agree`` that status (every view), the MCP text, the CLI, the terminal lines,
``closure_prepare``, the check's next step and the receipt (JSON, markdown, text) carry the same
conclusion and counters. The agent's answer decides what a limitation request means (owner
decision 2026-10-12): ``acknowledged`` says the requirement may be met but cannot be verified here
(a disclosed verification limit, ``insufficient_coverage``), ``acknowledged_not_done`` says it is NOT
met (an unmet requirement, ``unresolved_findings_remain``, lake S). The owner's guards: G1 an ``act`` challenge never qualifies as a
limitation, G2 the agent's own words never make one (the pretrain S rescue keeps its acknowledgement
re-check), G3 a limitation never touches ``declared_output_emptied`` (unit-tested on the kernel in
``test_tb4n3_dialogue_state``) and G4 a limitation is never clean.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import pytest

from builders.start_application import protocol_id
from integration.closure.test_closure_shapes import (
    _INSUFFICIENT,
    _UNRESOLVED,
    _actionable,
    _ai_finding,
    _begin,
    _challenge,
    _reviewer_finding,
    _Run,
    _surfaces,
    assert_surfaces_agree,
    receipt_artifact_1_3_0,  # noqa: F401  # pyright: ignore[reportUnusedImport]
)
from yoetz.cli.closure_gate import (
    ACCEPTANCE_RECHECK_ITEM,
    PREMISE_RECHECK_ITEM,
    closure_gate_from_readiness,
)
from yoetz.domain.findings import FindingKind
from yoetz.protocol.canonical import JsonValue

pytestmark = pytest.mark.anyio

_OBLIGATION = protocol_id("obl_", 7001)
_CLAIM = protocol_id("clm_", 7201)
_LIMIT = "state_unresolved_limitation"
_REASON = "The evaluator is hidden; I cannot measure it here."


async def _run_with(next_step: str, seed: int) -> tuple[_Run, Any]:
    script = ["challenge", "challenge", "challenge", "challenge"]
    run = await _begin(
        seed=seed,
        semantic="optional",
        evaluator=_challenge(
            _CLAIM,
            _OBLIGATION,
            kind=FindingKind.TASK_REQUIREMENT_UNMET,
            next_step=next_step,
            script=script,
        ),
    )
    checked = await _ai_finding(
        run, kind=FindingKind.TASK_REQUIREMENT_UNMET, next_step=next_step, script=script
    )
    return run, checked


async def _attempt(run: _Run, number: int = 7390) -> str:
    evidence = protocol_id("evd_", number)
    await run.publish(
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:05:00.000Z",
                "description": "I tried to establish it; the reference is not reachable here.",
            },
        )
    )
    return evidence


def _limit_decision(run: _Run) -> dict[str, JsonValue]:
    return run.draft(
        "decision_recorded",
        {
            "statement": f"Cannot be verified here.\nyoetz-verification-limit:{_OBLIGATION}",
            "rationale": "The reference is withheld by the task design.",
            "authority": "harness:codex",
            "affected_obligation_ids": [_OBLIGATION],
        },
    )


def _row(gathered: Any, finding_id: str) -> Any:
    return next(
        item for item in gathered.status["findings"].page.items if item.finding_id == finding_id
    )


async def test_a_limitation_request_is_to_disclose_never_blocking_work_on_every_surface() -> None:
    run, checked = await _run_with(_LIMIT, 81)
    finding = _reviewer_finding(checked)
    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.agent_actionable == ("findings_unanswered",)
    assert readiness.receipt_blocking_finding_count == "0"
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 0, 1), check=checked)
    row = _row(gathered, finding.finding_id)
    assert (row.closure_class, row.closure_basis) == ("agent_work", "limitation_requested")
    assert tuple(row.next_actions) == ("acknowledge",)
    # The receipt never tells the agent to repair the limit, and G4: it is never clean.
    text = gathered.receipts["text"].human_text
    assert "To disclose:" in text and "repair it, then check" not in text
    assert "Verification limits" not in text


async def test_the_check_text_asks_to_disclose_a_limitation_request_never_to_repair_it() -> None:
    """The check wire counts a pending limitation request under ``work_open_findings`` (no enum
    value for "to disclose"), so the CLI words that step from the items' closure basis: every
    agent-facing sentence must be true, and a limitation request is never repair work (Q4)."""

    from yoetz.application.check import check_internal_json
    from yoetz.cli.render import render_human_check
    from yoetz.protocol.models import (
        CheckFindingChecklistModel,
        CheckOverallNextModel,
        CheckSuccessModel,
        CoverageModel,
    )

    _, checked = await _run_with(_LIMIT, 87)
    finding = _reviewer_finding(checked)
    wire = check_internal_json(checked)
    overall = wire["overall_next"]
    assert isinstance(overall, Mapping)
    checklist = CheckFindingChecklistModel.model_validate(wire["finding_checklist"])
    assert checklist.next == "work_open_findings"
    assert [item.closure_basis for item in checklist.items if item.todo_state == "open"] == [
        "limitation_requested"
    ]
    model = CheckSuccessModel.model_construct(
        verdict="issue_detected",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        overall_next=CheckOverallNextModel.model_validate(dict(overall)),
        finding_checklist=checklist,
        children=None,
        advisory_notes=(),
        coverage=CoverageModel.model_construct(known_gaps=()),
    )
    text = render_human_check(model)
    assert "Disclose the named limitation requests" in text
    assert finding.finding_id in text
    assert "Repair" not in text and "repair the" not in text.lower()
    assert "no repair is needed" in text


@pytest.mark.parametrize(
    ("disposition", "conclusion", "counts", "klass", "basis"),
    [
        # May be met but cannot be verified here: a disclosed verification limit.
        (
            "acknowledged",
            _INSUFFICIENT,
            (0, 0, 0, 1, 0),
            "settled_disclosed",
            "limitation_disclosed",
        ),
        # Known not to be met (lake S ``fnd_8bdad2d0``): an unmet requirement, receipt unresolved.
        (
            "acknowledged_not_done",
            _UNRESOLVED,
            (0, 0, 1, 0, 0),
            "settled_unmet",
            "limitation_acknowledged_not_done",
        ),
    ],
)
async def test_the_agents_answer_decides_what_a_limitation_request_means_on_every_surface(
    disposition: str,
    conclusion: str,
    counts: tuple[int, int, int, int, int],
    klass: str,
    basis: str,
) -> None:
    run, checked = await _run_with(_LIMIT, 82)
    finding = _reviewer_finding(checked)
    attempt = await _attempt(run)
    await run.check_in("semantic_if_configured")
    await run.respond(
        finding.finding_id, checked.result_frontier, disposition, _REASON, evidence_refs=[attempt]
    )
    after = await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    # Either way the agent owes nothing more on the finding: it is settled (status says so).
    assert readiness.agent_actionable == ()
    assert readiness.state == "ready_with_limitations"
    assert_surfaces_agree(gathered, conclusion=conclusion, counts=counts, check=after)
    row = _row(gathered, finding.finding_id)
    assert (row.closure_class, row.closure_basis) == (klass, basis)
    # The check's continuation agrees with status: nothing to disclose or repair any more, and the
    # predicted conclusion is the one the receipt carries.
    assert after.finding_checklist is not None and after.overall_next is not None
    assert after.finding_checklist.next == "request_receipt"
    assert (after.overall_next.status, after.overall_next.action) == (
        "ready_with_limitations",
        "request_receipt",
    )
    document = gathered.receipts["json"].document
    disclosed: list[str] = document.get("limitation_disclosed_finding_ids") or []
    undone: list[str] = document.get("acknowledged_not_done_finding_ids") or []
    gate = closure_gate_from_readiness(
        readiness, frontier_sequence="9", frontier_digest="d", observation_pending=False
    )
    # G2: a limitation request is never a premise challenge, so the Stop gate never re-asks one;
    # the only re-check left is the announced acceptance re-read of the resolved obligation.
    assert gate is not None and gate.items == (ACCEPTANCE_RECHECK_ITEM,)
    if basis == "limitation_disclosed":
        # Disclosed, not "acknowledged, not done": it is not listed as an undone requirement.
        assert disclosed == [finding.finding_id] and not undone
        assert finding.finding_id not in tuple(readiness.acknowledged_not_done or ())
        for fmt in ("markdown", "text"):
            assert "Verification limits" in gathered.receipts[fmt].human_text
    else:
        # Unmet: listed with the requirements acknowledged as not done, never as a verification
        # limit, and the receipt keeps unresolved_findings_remain.
        assert not disclosed and undone == [finding.finding_id]
        assert finding.finding_id in tuple(readiness.acknowledged_not_done or ())
        for fmt in ("markdown", "text"):
            assert "Verification limits" not in gathered.receipts[fmt].human_text


async def test_a_verification_limit_decision_alone_discloses_the_request() -> None:
    run, checked = await _run_with(_LIMIT, 83)
    finding = _reviewer_finding(checked)
    await run.publish(_limit_decision(run))
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 1, 0))
    row = _row(gathered, finding.finding_id)
    assert (row.closure_class, row.closure_basis) == ("settled_disclosed", "limitation_disclosed")
    assert gathered.receipts["json"].document["limitation_disclosed_finding_ids"] == [
        finding.finding_id
    ]


async def test_a_decision_line_does_not_turn_an_acknowledged_not_done_answer_into_a_disclosure() -> (
    None
):
    """The agent said the requirement is NOT met; a verification-limit decision elsewhere does not
    change what that answer means. ``reopened`` then lets the agent state the limit instead."""

    run, checked = await _run_with(_LIMIT, 92)
    finding = _reviewer_finding(checked)
    await run.respond(finding.finding_id, checked.result_frontier, "acknowledged_not_done", _REASON)
    await run.publish(_limit_decision(run))
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    row = _row(gathered, finding.finding_id)
    assert (row.closure_class, row.closure_basis) == (
        "settled_unmet",
        "limitation_acknowledged_not_done",
    )
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(0, 0, 1, 0, 0))

    await run.respond(
        finding.finding_id, run.frontier, "reopened", "It may be met; I cannot measure it here."
    )
    await run.check_in("semantic_if_configured")
    reopened = await _surfaces(run)
    row = _row(reopened, finding.finding_id)
    assert (row.closure_class, row.closure_basis) == ("settled_disclosed", "limitation_disclosed")
    assert_surfaces_agree(reopened, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 1, 0))


async def test_g1_an_act_challenge_is_never_a_limitation_even_beside_the_decision_line() -> None:
    run, checked = await _run_with("act", 84)
    finding = _reviewer_finding(checked)
    await run.publish(_limit_decision(run))
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    row = _row(gathered, finding.finding_id)
    assert (
        row.closure_basis != "limitation_disclosed" and row.closure_basis != "limitation_requested"
    )
    assert row.closure_class == "agent_work"
    assert "receipt_findings_unresolved" in _actionable(gathered.status["compact"])
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(1, 0, 0, 0, 0))


async def test_g2_pretrain_s_an_act_finding_given_up_on_keeps_its_premise_recheck() -> None:
    """The agent's own "could not find it" never turns an ``act`` finding into a limitation: it
    stays an unmet requirement, the receipt is unresolved and the Stop gate still re-asks the
    premise once (the pretrain S rescue); ``reopened`` then takes the give-up back and the work is to do again."""

    run, checked = await _run_with("act", 85)
    finding = _reviewer_finding(checked)
    attempt = await _attempt(run)
    await run.check_in("semantic_if_configured")
    await run.respond(
        finding.finding_id,
        checked.result_frontier,
        "acknowledged_not_done",
        "I could not find it.",
        evidence_refs=[attempt],
    )
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert _row(gathered, finding.finding_id).closure_basis == "acknowledged_not_done_requirement"
    assert finding.finding_id in tuple(readiness.acknowledged_not_done or ())
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="9",
        frontier_digest="d",
        observation_pending=False,
    )
    assert "finding_premise_disputed" in tuple(readiness.standing_limitations or ())
    assert gate is not None and PREMISE_RECHECK_ITEM in gate.items
    assert not gathered.receipts["json"].document.get("limitation_disclosed_finding_ids")
    assert_surfaces_agree(gathered, conclusion=_UNRESOLVED, counts=(0, 0, 1, 0, 0))

    await run.respond(
        finding.finding_id, run.frontier, "reopened", "I will look again for the inputs."
    )
    reopened = await _surfaces(run)
    assert_surfaces_agree(reopened, conclusion=_UNRESOLVED, counts=(1, 0, 0, 0, 0))
    assert finding.finding_id not in tuple(
        reopened.status["compact"].closure_readiness.acknowledged_not_done or ()
    )


async def test_a_disclosed_limitation_is_not_open_work_in_the_check_continuation() -> None:
    """The to-do state of a disclosed limitation stays ``open``, but the class is settled.

    Status reads "ready with limitations"; the check's checklist ``next`` and overall
    continuation must agree instead of saying "Repair the open findings".
    """

    run, checked = await _run_with(_LIMIT, 88)
    finding = _reviewer_finding(checked)
    attempt = await _attempt(run)
    await run.check_in("semantic_if_configured")
    await run.respond(
        finding.finding_id,
        checked.result_frontier,
        "acknowledged",
        _REASON,
        evidence_refs=[attempt],
    )
    after = await run.check_in("semantic_if_configured")
    assert after.finding_checklist is not None and after.overall_next is not None
    assert [
        (item.todo_state, item.closure_basis)
        for item in after.finding_checklist.items
        if item.finding_id == finding.finding_id
    ] == [("open", "limitation_disclosed")]
    assert after.finding_checklist.next == "request_receipt"
    assert after.overall_next.action != "work_open_findings"
    assert after.overall_next.status in {"ready_with_limitations", "ready"}
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 1, 0), check=after)


async def test_a_limitation_request_cannot_be_acknowledged_without_a_reason() -> None:
    """Owner decision Q4: the disclosure is made "with reason"; a bare acknowledgement is refused,
    so the request stays something to disclose rather than becoming an answered, undisclosed one."""

    from yoetz.protocol.errors import PublicOperationError

    run, checked = await _run_with(_LIMIT, 89)
    finding = _reviewer_finding(checked)
    with pytest.raises(PublicOperationError) as refused:
        await run.respond(finding.finding_id, checked.result_frontier, "acknowledged")
    assert "reason" in str(refused.value).lower()
    gathered = await _surfaces(run)
    assert_surfaces_agree(gathered, conclusion=_INSUFFICIENT, counts=(0, 0, 0, 0, 1))


async def test_an_acknowledged_obligation_disclosed_as_external_is_listed_once_as_disclosed() -> (
    None
):
    """An obligation acknowledged as not done and also marked externally evaluated is counted
    disclosed by the closure classes; readiness must not also list it as "acknowledged not done"."""

    from typing import cast

    from integration.closure.test_closure_shapes import _obligation

    run, _ = await _run_with(_LIMIT, 90)
    draft = _obligation(
        run,
        1,
        status="acknowledged_not_done",
        acknowledged_not_done_reason="Only a hidden evaluator can measure it.",
    )
    cast(dict[str, JsonValue], draft["schema"])["version"] = "1.1.0"
    await run.publish(draft, _limit_decision(run))
    await run.check_in("semantic_if_configured")
    gathered = await _surfaces(run)
    readiness = gathered.status["compact"].closure_readiness
    assert readiness.obligation_counts is not None
    assert (
        readiness.obligation_counts.open,
        readiness.obligation_counts.acknowledged,
        readiness.obligation_counts.disclosed,
    ) == ("0", "0", "1")
    assert _OBLIGATION not in tuple(readiness.acknowledged_not_done or ())
    from yoetz.mcp.summaries import summary_for_status

    assert "acknowledged not done (not open)" not in summary_for_status(
        gathered.status["compact"].as_json()
    )
