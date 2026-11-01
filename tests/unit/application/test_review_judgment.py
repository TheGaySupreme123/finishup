"""Decision choices survive review silence, stay advisory, and carry the agent's answer (#1146)."""

# pyright: reportPrivateUsage=false
from __future__ import annotations

from dataclasses import replace

import pytest

from builders.observed_runs import ObservedLedger
from builders.policy_cases import finding_record, make_case, record
from finishup.application import semantic_case
from finishup.domain.events import ResponseRecordedPayload
from finishup.domain.findings import (
    FINDING_KIND_TRAITS,
    CheckVerdict,
    FindingKind,
    ResponseDisposition,
)
from finishup.domain.receipts import receipt_document_to_json, render_receipt_human
from finishup.kernel.closure_class import finding_closure
from finishup.kernel.finding_resolution import finding_is_resolved, qualifying_check_resolves
from finishup.kernel.projections import unanswered_finding_ids
from finishup.kernel.receipt_capacity import receipt_blocking_finding_count
from finishup.protocol.models import SemanticReason, SemanticStatus
from unit.application import test_semantic_case_prior_findings as prior
from unit.application import test_tb4n4_review_frame as frame
from unit.kernel import test_closure_class as closure
from unit.kernel import test_finding_resolution as resolution
from unit.kernel import test_receipt_builder as receipts


@pytest.mark.parametrize("phase", ["routine", "final"])
def test_decision_is_recorded_at_priority_three_and_cannot_request_a_repair(phase: str) -> None:
    ledger = ObservedLedger()
    frame._obligation(ledger)
    edit = ledger.edit()
    case = frame._case(ledger)
    source = str(case.projection.results[edit].source_event_id)
    challenge = replace(
        frame._challenge(FindingKind.DECISION_NEEDED, source, summary="Choose the reference"),
        requested_next_step="act",
    )
    review = frame._review(case, challenge, phase=phase)
    (candidate,) = review.candidates
    assert candidate.kind is FindingKind.DECISION_NEEDED
    assert candidate.priority == 3
    assert candidate.challenge is not None
    assert candidate.challenge.requested_next_step == "answer_question"
    assert FINDING_KIND_TRAITS[candidate.kind] == (3, False)
    assert review.rejected_by_reason == ()


@pytest.mark.parametrize(
    "answer",
    [
        None,
        ResponseDisposition.ACKNOWLEDGED,
        ResponseDisposition.REJECTED,
        ResponseDisposition.ACKNOWLEDGED_NOT_DONE,
    ],
)
def test_decision_never_counts_as_unmet_work_or_mandatory_response(
    answer: ResponseDisposition | None,
) -> None:
    finding = closure._finding(
        1, kind=FindingKind.DECISION_NEEDED, semantic=True, next_step="answer_question"
    )
    responses = (
        {} if answer is None else {finding.finding_id: closure._response(1, answer, reasoned=True)}
    )
    case = make_case(findings={finding.finding_id: finding_record(finding, 4)}, responses=responses)
    state = case.projection
    assert finding.finding_id in state.findings
    assert finding_closure(state, finding.finding_id) is None
    assert receipt_blocking_finding_count(state) == 0
    assert unanswered_finding_ids(state, ()) == frozenset()
    # Silence in a later, otherwise qualifying semantic check is not the agent's decision.
    check = resolution._check(
        semantic=(SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
    )
    assert not qualifying_check_resolves(finding, 4, check, frozenset(), proof_state=state)
    assert not finding_is_resolved(state, finding.finding_id)


@pytest.mark.parametrize(
    "disposition", [ResponseDisposition.ACKNOWLEDGED, ResponseDisposition.REJECTED]
)
@pytest.mark.parametrize("redacted", [False, True])
def test_reasoned_choice_reaches_the_next_packet_as_settled_without_claiming_repair(
    disposition: ResponseDisposition, redacted: bool
) -> None:
    finding = closure._finding(
        1, kind=FindingKind.DECISION_NEEDED, semantic=True, next_step="answer_question"
    )
    answer = ResponseRecordedPayload(
        finding.finding_id,
        finding.subject_frontier,
        disposition,
        "Keep the supplied reference: both validators agree with its dimensions.",
    )
    response = replace(record(answer, 6), redacted=redacted, payload=None if redacted else answer)
    case = make_case(
        findings={finding.finding_id: finding_record(finding, 4)},
        responses={finding.finding_id: response},
    )
    packet = prior._build(case)
    source_items = [item for item in packet.items if item.source_ref == str(finding.finding_id)]
    assert source_items
    content = " ".join(item.content.decode() for item in source_items)
    if redacted:
        assert "yoetz.settled-finding/1" not in content
        assert str(finding.finding_id) in packet.packet.prior_finding_refs
    else:
        assert "yoetz.settled-finding/1" in content
        assert "Keep the supplied reference" in content
        assert str(finding.finding_id) not in packet.packet.prior_finding_refs
    assert not finding_is_resolved(case.projection, finding.finding_id)


def test_acknowledgement_without_a_reason_does_not_settle_the_choice() -> None:
    finding = closure._finding(
        1, kind=FindingKind.DECISION_NEEDED, semantic=True, next_step="answer_question"
    )
    case = make_case(
        findings={finding.finding_id: finding_record(finding, 4)},
        responses={finding.finding_id: closure._response(1, ResponseDisposition.ACKNOWLEDGED)},
    )
    assert not semantic_case._decision_answered(case.projection, finding.finding_id)
    assert semantic_case._prior_finding_candidates(case.projection, case.allowed_ids)


@pytest.mark.parametrize("format", ["json", "markdown", "text"])
@pytest.mark.parametrize("answered", [False, True])
def test_decision_choice_and_destructive_cost_remain_visible_in_receipts(
    format: str, answered: bool
) -> None:
    finding = replace(
        closure._finding(
            1, kind=FindingKind.DECISION_NEEDED, semantic=True, next_step="answer_question"
        ),
        summary="Choose between the supplied and task-worded references.",
        detail="Destructive change: the swap loses the supplied reference's passing check. Compare both; you decide.",
    )
    check = receipts._check(
        CheckVerdict.NO_ISSUE_DETECTED,
        finding.coverage,
        semantic_provenance=finding.provenance,
        semantic_conclusion="challenges_returned",
        returned=(finding.finding_id,),
    )
    response = (
        ResponseRecordedPayload(
            finding.finding_id,
            finding.subject_frontier,
            ResponseDisposition.ACKNOWLEDGED,
            "Keep the supplied reference after comparing both validators.",
        )
        if answered
        else None
    )
    document = receipts._build(
        receipts._context(
            finding=finding,
            coverage=finding.coverage,
            check=check,
            response=response,
        )
    )
    if format == "json":
        import json

        rendered = json.dumps(receipt_document_to_json(document), default=dict)
    else:
        rendered = render_receipt_human(document, markdown=format == "markdown")
    assert finding.summary in rendered
    assert "Destructive change:" in rendered
    if answered:
        assert "AI-powered decision recorded" in rendered
        assert "Agent decision (self-reported): Keep the supplied reference" in rendered
    else:
        assert "AI-powered decision needed" in rendered
    assert document.findings[0].priority == 3
    assert document.findings[0].kind is FindingKind.DECISION_NEEDED


@pytest.mark.anyio
@pytest.mark.parametrize("withheld", [False, True])
async def test_declared_owner_admitted_input_roots_reach_the_reviewer_catalog(
    monkeypatch: pytest.MonkeyPatch, withheld: bool
) -> None:
    import json
    from typing import cast

    from finishup.application.reviewer_run import reviewer_catalog
    from finishup.ports.change_capture import SnapshotFile, TaskInputSnapshotSet
    from finishup.ports.runtime import TaskRuntime
    from finishup.service import ready_composition

    snapshot = TaskInputSnapshotSet(
        "task_start",
        (SnapshotFile("/shared/task/reference.txt", "/shared", b"supplied reference\n", 19),),
    )

    async def snapshots(_runtime: object, _request_id: object) -> tuple[TaskInputSnapshotSet, ...]:
        return (snapshot,)

    monkeypatch.setattr(ready_composition, "load_input_snapshots", snapshots)
    packet = prior._build(make_case())
    roots = await ready_composition._reviewer_read_roots(
        cast(TaskRuntime, object()),
        "request",
        packet,
        workspace_root="/workspace",
        outside=("/shared", "/unused"),
        inputs=("/shared/task", "/unadmitted/reference.txt"),
        protected=("/state",),
        withheld=("repository_excerpt",) if withheld else (),
        change_capture=None,
    )
    rows = json.loads(reviewer_catalog(roots, 3))["reviewer_catalog"]["read_file_roots"]
    if withheld:
        assert rows == []
    else:
        assert [row["root_id"] for row in rows] == ["w1", "o1", "s1"]
        assert rows[1]["covers"] == ["task"]
        assert rows[1]["standing"] == "outside_input_mutable"
        assert rows[2]["covers"] == ["task/reference.txt"]
        assert rows[2]["baseline"] == "task_start"
        assert all("unadmitted" not in str(row) for row in rows)
        assert roots[1].excluded == ("/workspace", "/state")
