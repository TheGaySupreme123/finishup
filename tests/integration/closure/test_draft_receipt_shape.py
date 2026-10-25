"""The draft receipt before the final receipt (issue #975, ADR-046 amendment).

TB4 agents ended on "Request the receipt" and only the receipt showed what was missing. On a ready
readiness, check and status now carry a draft of what the receipt will say: the receipt's own
predicted conclusion and reasons, each quoted task criterion classified by what the record links
to it, the open fix-or-decline items, the tracked advice with no recorded response and the
limitations the receipt will disclose. Every surface prints it labelled as records, not
correctness, the Stop gate never continues the agent for it, and the draft's conclusion is the
receipt's.
"""

# pyright: reportPrivateUsage=false

from __future__ import annotations

from dataclasses import replace
from typing import Any, cast

import pytest

import integration.application.test_respond_status_receipt as h
from builders.start_application import protocol_id, start_request
from finishup.application import check_change
from finishup.application.check import FinalSemanticEvaluation, check_internal_json
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.cli.render import render_closure_readiness_lines, render_human_status
from finishup.kernel.task_facts import RequestedOutputState
from finishup.mcp.summaries import summary_for_check, summary_for_status
from finishup.ports.semantic import SemanticJudgment, VerifiedReviewItem
from finishup.protocol.canonical import JsonValue
from finishup.protocol.models import StartRequest
from integration.closure.test_closure_shapes import (
    _NO_FINDINGS,
    _obligation,
    _public,
    _Run,
    _surfaces,
    assert_surfaces_agree,
)

pytestmark = pytest.mark.anyio

_OBLIGATION = protocol_id("obl_", 7001)
_WRITE = "The tool must write out.txt."
_SORTED = "Every row must be sorted by id."
_TASK = f"{_WRITE} {_SORTED}"
_LABEL = "Draft receipt (records, not correctness): "


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(autouse=True)
def receipt_artifact_1_3_0(monkeypatch: pytest.MonkeyPatch) -> None:
    from finishup.domain.receipts import SchemaVersionEntry

    original = h._versions

    def versions() -> Any:
        return replace(
            original(),
            schema_versions=(SchemaVersionEntry("receipts/receipt-document", "1.3.0"),),
        )

    monkeypatch.setattr(h, "_versions", versions)


def _not_supported_reviewer() -> Any:
    """A review that approves, with one verified row not_supported on the obligation (#1162)."""

    async def evaluate(
        frozen: object,
        findings: object,
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> object:
        succeeded = cast(FinalSemanticEvaluation, await h._semantic_succeeds(frozen, findings))
        return replace(
            succeeded,
            judgment=SemanticJudgment(
                "no_material_discrepancy",
                (),
                verified=(
                    VerifiedReviewItem(
                        "out.txt is written", "not_supported", (_OBLIGATION,), _WRITE
                    ),
                ),
            ),
            provider_input_text_by_ref={_OBLIGATION: (_WRITE,)},
        )

    return evaluate


async def _ready_run(monkeypatch: pytest.MonkeyPatch, seed: int) -> _Run:
    """A resolved obligation on the agent's word, an unchanged output and one tracked note."""

    unchanged = RequestedOutputState(
        "inside", exists=True, changed=False, size_bytes=120, lines=4, relative="out.txt"
    )

    async def states(**_kwargs: object) -> dict[tuple[object, int], RequestedOutputState]:
        return {(_OBLIGATION, 0): unchanged}

    monkeypatch.setattr(check_change, "requested_output_states", states)
    app, runtime, _ = h._build_app(
        seed_offset=seed, semantic="optional", semantic_evaluator=_not_supported_reviewer()
    )
    request = start_request(seed, title="Write the report").model_dump(
        mode="json", by_alias=True, exclude_none=True
    )
    request["task_statement"] = _TASK
    started = await app.start(StartRequest.model_validate(request))
    run = _Run(app, runtime, started)
    # The obligation names the event that recorded the statement, so the plan maps the task.
    ledger, _objects = runtime.resources[started.task_id]
    (opened, *_rest) = [record async for record in ledger.load_events(started.session_id)]
    evidence = protocol_id("evd_", 7301)
    item = {"item_kind": "file", "value": "/app/out.txt", "role": "output"}
    criteria: dict[str, JsonValue] = {
        "acceptance_criteria": _WRITE,
        "requested_items": [item],
        "source_refs": [str(opened.event_id)],
    }
    plan = run.draft(
        "plan_published",
        {"plan_version": 1, "summary": "The plan", "obligation_refs": [_OBLIGATION]},
    )
    await run.publish(_obligation(run, 1, **criteria), plan)
    await run.publish(
        run.draft(
            "action_recorded",
            {
                "action_id": protocol_id("act_", 7101),
                "action_kind": "other",
                "description": "Wrote the output",
                "obligation_refs": [_OBLIGATION],
                "attempted_items": ["/app/out.txt"],
            },
        ),
        run.draft(
            "result_recorded",
            {
                "result_id": protocol_id("res_", 7400),
                "action_id": protocol_id("act_", 7101),
                "outcome": "success",
                "summary": "Wrote the output.",
            },
        ),
        run.draft(
            "evidence_recorded",
            {
                "evidence_id": evidence,
                "evidence_kind": "test_result",
                "strength": "metadata_only",
                "observed_at": "2026-09-28T12:00:00.000Z",
                "description": "The output was produced.",
            },
        ),
        _obligation(run, 1, status="resolved", resolution_evidence_refs=[evidence], **criteria),
        run.draft(
            "claim_recorded",
            {
                "claim_id": protocol_id("clm_", 7201),
                "claim_kind": "completion",
                "statement": "The output is delivered.",
                "supporting_refs": [evidence],
                "obligation_refs": [_OBLIGATION],
                "limitation_refs": [],
                "supersedes_claim_refs": [],
            },
        ),
    )
    return run


async def test_a_ready_check_and_status_show_the_draft_receipt_on_every_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run = await _ready_run(monkeypatch, 120_975)
    checked = await run.check_in("semantic_if_configured")
    assert not checked.findings, [(f.kind, f.subject_refs) for f in checked.findings]

    gathered = await _surfaces(run)
    compact = gathered.status["compact"].closure_readiness
    assert compact.state == "ready_with_limitations", compact.agent_actionable
    draft = compact.draft_receipt
    assert draft is not None
    predicted = compact.predicted_receipt
    assert predicted is not None
    # ADR-046: the draft is the prediction, and the receipt reads what the draft said.
    assert draft.conclusion == predicted.conclusion
    assert draft.reasons == tuple(reason.code for reason in predicted.reasons)
    assert_surfaces_agree(gathered, conclusion=predicted.conclusion, counts=_NO_FINDINGS)

    # Criteria: the obligation's criterion rests on the agent's word only; the other task
    # sentence has nothing linked to it, and it is listed first.
    rows = {
        (row.task_criterion_excerpt or row.obligation_criterion_excerpt): row
        for row in draft.criteria
    }
    assert rows[_SORTED].standing == "none" and rows[_SORTED].source == "task_statement"
    assert rows[_WRITE].standing == "agent_claim_only"
    assert protocol_id("clm_", 7201) in rows[_WRITE].refs
    assert draft.criteria[0].standing == "none"
    assert (draft.criteria_counts.none, draft.criteria_counts.agent_claim_only) == ("1", "1")
    assert draft.criteria_counts.linked_pass_current == "0"
    # The open fix-or-decline item, the unanswered tracked note and the disclosed limitations.
    assert draft.fix_or_decline_count == "1"
    assert compact.correctness_advisory_counts is not None
    assert draft.advice_unanswered_count == compact.correctness_advisory_counts.no_recorded_response
    (advisory_id,) = draft.advice_unanswered
    assert "requested_output_unchanged" in draft.limitations

    # Every surface prints it, labelled, with ids; never a Stop item.
    status = gathered.status["compact"]
    public = _public(status)
    for text in (
        summary_for_status(status.as_json()),
        render_human_status(public),
        "\n".join(render_closure_readiness_lines(public.closure_readiness)),
    ):
        assert _LABEL + predicted.conclusion in text, text
        assert "1 agent claim only (" in text and "1 none" in text, text
        assert "fix or decline: 1" in text, text
        assert advisory_id in text, text
    lines = render_closure_readiness_lines(public.closure_readiness)
    assert any(_SORTED in line and line.lstrip().startswith("none:") for line in lines), lines
    assert (
        closure_gate_from_readiness(
            public.closure_readiness,
            frontier_sequence="7",
            frontier_digest="sha256:" + "d" * 64,
            observation_pending=False,
        )
        is None
    )

    # The check that made the state ready carries the same draft in its readiness and its text.
    assert checked.closure_readiness is not None
    wire = check_internal_json(checked)
    attached = cast(dict[str, Any], wire["closure_readiness"])["draft_receipt"]
    assert attached["conclusion"] == predicted.conclusion
    assert attached["label"] == "draft_records_not_correctness"
    assert _LABEL in summary_for_check(wire)


async def test_no_draft_while_work_remains() -> None:
    from integration.closure.test_closure_shapes import _action, _begin, _plan

    run = await _begin(seed=120_976)
    await run.publish(_obligation(run, 1), _plan(run, 1), _action(run, 1))
    gathered = await _surfaces(run, receipts=False)
    for view, status in gathered.status.items():
        readiness = status.closure_readiness
        assert readiness.state == "action_required", view
        assert readiness.draft_receipt is None, view
        assert _LABEL not in summary_for_status(status.as_json()), view
