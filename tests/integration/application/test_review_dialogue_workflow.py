"""The review dialogue survives the real ledger and reaches the next review (issue #905).

These cases run the real ready composition with a hermetic reviewer: a challenge becomes an
AI-powered finding whose challenge fields are recorded on the ledger (``finding_recorded/1.3.0``),
the agent answers it, and the next check's review case carries that finding, what the reviewer
asked, and the answer in the prior-findings section. A projection rebuilt from the recorded events
reads exactly what the live projection holds.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from typing import Any, cast

import pytest

from builders.projection_workflow import (
    ProjectionCase,
    build_projection_application,
    frontier_json,
    project_case,
    request_base,
)
from builders.review_manifests import provider_bound_manifest
from builders.start_application import protocol_id, start_request
from yoetz.application.check import FinalSemanticEvaluation, check_internal_json
from yoetz.application.semantic_case import build_semantic_case, semantic_case_packet_view
from yoetz.application.service import Application
from yoetz.domain.events import CheckRecordedPayload, EventSchema, LedgerRecord
from yoetz.domain.findings import (
    Finding,
    FindingKind,
    FindingOrigin,
    SemanticDispatchKind,
    SemanticProvenance,
)
from yoetz.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
from yoetz.kernel.finding_resolution import finding_resolution_explanation
from yoetz.kernel.finding_todo import FindingTodoState, finding_todo, finding_todo_state
from yoetz.kernel.projections import ProjectionState, projection_snapshot
from yoetz.kernel.receipt_capacity import receipt_blocking_finding_count
from yoetz.kernel.reducers import replay
from yoetz.mcp.summaries import summary_for_check
from yoetz.ports.control import ControlMethod
from yoetz.ports.ledger import CheckCommitResult, FrozenCase
from yoetz.ports.semantic import (
    MissingForAssessment,
    PriorFindingVerdict,
    ReviewerChallenge,
    SamplingParams,
    SemanticCase,
    SemanticJudgment,
)
from yoetz.protocol.canonical import JsonValue, strict_json_parse
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.models import (
    CheckRequest,
    PublishWorkRequest,
    ReceiptRequest,
    RespondRequest,
    SemanticReason,
    SemanticStatus,
    StatusFindingsPageModel,
    StatusRequest,
)

pytestmark = pytest.mark.anyio

_DIGEST = "sha256:" + "7" * 64
type _Evaluator = Callable[..., Awaitable[FinalSemanticEvaluation]]


def _provenance(seed: int) -> SemanticProvenance:
    return SemanticProvenance(
        provider="fake",
        endpoint_profile_id="fake",
        endpoint_profile_version="1.0.0",
        model="fake/model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(128),
        latency_ms=1,
        semantic_attempt_id=protocol_id("att_", seed),
        dispatch_kind=SemanticDispatchKind.EXTERNAL,
        privacy_receipt_id=protocol_id("egr_", seed + 1),
        status=SemanticStatus.SUCCEEDED,
        reason=SemanticReason.SEMANTIC_COMPLETED,
        provider_request_id=f"fake-dialogue-{seed}",
        egress_authorization_id=protocol_id("aut_", seed + 2),
        request_commitment="hmac-sha256:" + "b" * 64,
    )


_DISCREPANCY = "The completion claim covers an obligation whose exact-version check is open."


def _challenge(
    *refs: str, summary: str = "Required llvmlite 0.46.0 verification remains open"
) -> ReviewerChallenge:
    return ReviewerChallenge(
        FindingKind.COMPLETION_WITH_OPEN_OBLIGATIONS,
        summary,
        tuple(sorted(refs)),
        _DISCREPANCY,
        "The package index may be unreachable from this sandbox.",
        "Make one concrete authorized attempt to obtain llvmlite 0.46.0, then run the tests.",
        "act",
        "The recorded install failure may already be the authorized attempt.",
    )


@dataclass
class _Reviewer:
    """A hermetic reviewer that records the case it was shown and answers from a script."""

    answers: list[Callable[[FrozenCase], SemanticJudgment]]
    cases: list[SemanticCase] = field(default_factory=lambda: [])
    seed: int = 2600
    # Case content gaps the composing evaluator reports per round (issue #907 budget cuts).
    content_gaps: dict[int, tuple[str, ...]] = field(default_factory=lambda: {})

    async def __call__(
        self,
        frozen: FrozenCase,
        findings: tuple[Finding, ...],
        runtime: object | None = None,
        lineage_evaluation: object | None = None,
    ) -> FinalSemanticEvaluation:
        del runtime, lineage_evaluation
        self.cases.append(
            build_semantic_case(
                case_id=protocol_id("cas_", self.seed + len(self.cases)),
                frozen_case=frozen.case,
                dependency_digest=frozen.lease.dependency_digest,
                findings=findings,
                review_context_profile=ReviewContextProfile.GOAL_AWARE,
                review_selection=ReviewSelectionPolicy.for_profile(ReviewContextProfile.GOAL_AWARE),
                policy_id=protocol_id("pvy_", self.seed),
                policy_version="1",
            )
        )
        judgment = self.answers[len(self.cases) - 1](frozen)
        # Report the packet exactly as the production composition does, so the rulings are
        # fenced to what this reviewer was shown.
        view = semantic_case_packet_view(self.cases[-1])
        return FinalSemanticEvaluation(
            SemanticStatus.SUCCEEDED,
            SemanticReason.SEMANTIC_COMPLETED,
            judgment=judgment,
            provenance=_provenance(self.seed + 10 * len(self.cases)),
            case_prior_finding_refs=view.prior_finding_refs,
            case_citable_refs=view.citable_refs,
            case_content_gaps=self.content_gaps.get(len(self.cases) - 1, ()),
            provider_input_manifest=provider_bound_manifest(),
        )


def _challenge_obligation(frozen: FrozenCase) -> SemanticJudgment:
    obligation = next(iter(frozen.case.projection.obligations))
    return SemanticJudgment("challenges_returned", (_challenge(str(obligation)),))


def _records(app: Application) -> tuple[LedgerRecord, ...]:
    runtime = cast(Any, app.runtime)
    ledger, _objects = next(iter(runtime.resources.values()))
    return tuple(ledger._state.records)  # pyright: ignore[reportPrivateUsage]


def _live_projection(app: Application) -> ProjectionState:
    runtime = cast(Any, app.runtime)
    ledger, _objects = next(iter(runtime.resources.values()))
    return cast(ProjectionState, ledger._state.projection)  # pyright: ignore[reportPrivateUsage]


@dataclass(frozen=True, slots=True)
class _Session:
    app: Application
    session_id: str
    writer_id: str
    obligation_id: str
    task_id: str = ""


async def _session(
    reviewer: _Reviewer, seed: int, *, attempt_budget: int | None = None
) -> tuple[_Session, JsonValue]:
    app, _policy = await build_projection_application("optional", seed=seed, max_findings=5)
    app = replace(app, semantic_evaluator=reviewer)
    if attempt_budget is not None:
        app = replace(
            app,
            verification_policy=replace(
                app.verification_policy, finding_attempt_budget=attempt_budget
            ),
        )
    started = await app.start(start_request(seed, title="Converging review dialogue"))
    obligation_id = protocol_id("obl_", seed + 1)
    obligation_event = protocol_id("evt_", seed + 2)
    published = await app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 3)),
                "session_id": started.session_id,
                "writer_id": started.writer_id,
                "expected_frontier": frontier_json(started.frontier),
                "event_drafts": [
                    {
                        "event_id": obligation_event,
                        "schema": {"name": "obligation_published", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "obligation_id": obligation_id,
                            "description": "Verify the stencil change with llvmlite 0.46.0.",
                            "acceptance_criteria": "Stencil tests pass on llvmlite 0.46.0.",
                            "evidence_expectation": "A recorded test result.",
                            "requested_items": [{"item_kind": "change", "value": "stencil"}],
                            "status": "open",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    # Issue #1046: no AI-powered review runs before the first material edit, so
                    # the dialogue starts once the work has begun.
                    {
                        "event_id": protocol_id("evt_", seed + 6),
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:00:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": protocol_id("act_", seed + 7),
                            "action_kind": "edit",
                            "description": "Changed the stencil kernel.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    session = _Session(app, started.session_id, started.writer_id, obligation_id, started.task_id)
    return session, frontier_json(published.result_frontier)


async def _check(session: _Session, frontier: JsonValue, seed: int) -> CheckCommitResult:
    checked = await session.app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "mode": "semantic_required",
                "max_findings": "5",
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


def _semantic(checked: CheckCommitResult) -> Finding:
    return next(
        finding
        for finding in checked.findings
        if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )


async def test_challenge_fields_are_recorded_and_carried_into_the_next_review() -> None:
    seed = 2700
    reviewer = _Reviewer([_challenge_obligation, _challenge_obligation])
    session, frontier = await _session(reviewer, seed)

    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    rows = [
        row
        for row in _records(session.app)
        if row.schema.name == "finding_recorded"
        and isinstance(row.payload, Finding)
        and row.payload.finding_id == raised.finding_id
    ]
    assert [row.schema for row in rows] == [EventSchema("finding_recorded", "1.3.0")]
    recorded = cast(Finding, rows[0].payload)
    assert recorded.challenge is not None
    assert recorded.challenge.discrepancy == _DISCREPANCY
    assert recorded.challenge.requested_next_step == "act"
    # Local findings carry no dialogue fields, so their recorded bytes are unchanged.
    assert all(
        row.payload.challenge is None and row.payload.related_finding_ids == ()
        for row in _records(session.app)
        if row.schema.name == "finding_recorded"
        and isinstance(row.payload, Finding)
        and row.payload.origin is FindingOrigin.DETERMINISTIC
    )

    responded = await session.app.respond(
        RespondRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 20)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier_json(first.result_frontier),
                "finding_id": raised.finding_id,
                "finding_frontier": frontier_json(first.result_frontier),
                "disposition": "rejected",
                "reason": "Two exact-version installation attempts already failed on the index.",
            }
        )
    )
    await _check(session, frontier_json(responded.result_frontier), seed + 30)

    second_case = reviewer.cases[1]
    structural = next(
        item for item in second_case.items if item.item_id == f"prior-finding-{raised.finding_id}"
    )
    row = cast(Mapping[str, JsonValue], strict_json_parse(structural.content))
    assert row["challenge_fields"] == "recorded"
    assert row["requested_next_step"] == "act"
    assert cast(Mapping[str, JsonValue], row["response"])["disposition"] == "rejected"
    texts = {item.item_id: item.content.decode("utf-8") for item in second_case.items}
    assert texts[f"prior-finding-discrepancy-{raised.finding_id}"] == _DISCREPANCY
    assert "already failed" in texts[f"prior-finding-response-{raised.finding_id}"]

    # A projection rebuilt from the recorded events reads exactly what the live one holds.
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


async def _repair(session: _Session, frontier: JsonValue, seed: int) -> tuple[str, JsonValue]:
    """Publish the repair and its regression result, as the kea agent did after check 2."""

    action_id = protocol_id("act_", seed)
    result_id = protocol_id("res_", seed + 1)
    action_event = protocol_id("evt_", seed + 2)
    published = await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 3)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "event_drafts": [
                    {
                        "event_id": action_event,
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:05:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": action_id,
                            "action_kind": "edit",
                            "description": "Encode Map keys with their type before joining.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 4),
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:05:01.000Z",
                        "causal_parents": [action_event],
                        "payload": {
                            "result_id": result_id,
                            "action_id": action_id,
                            "outcome": "success",
                            "summary": "Map keys 1 and '1' now have distinct dependency strings.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    return result_id, frontier_json(published.result_frontier)


def _rule_first_finding(
    verdict: str, *, cite_repair: bool
) -> Callable[[FrozenCase], SemanticJudgment]:
    def answer(frozen: FrozenCase) -> SemanticJudgment:
        projection = frozen.case.projection
        finding = next(
            key
            for key, row in projection.findings.items()
            if row.payload is not None
            and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        )
        newest = max(projection.results.items(), key=lambda pair: pair[1].source_frontier)[0]
        refs = (str(newest),) if cite_repair else ()
        # provider-judgment 1.1.0 requires every insufficient_packet to name what was missing.
        return SemanticJudgment(
            "insufficient_packet",
            (),
            (PriorFindingVerdict(str(finding), verdict, refs),),  # type: ignore[arg-type]
            missing_for_assessment=(
                MissingForAssessment("verification_output", (str(newest),), "run output absent"),
            ),
        )

    return answer


@pytest.mark.parametrize("cite_repair", [True, False])
async def test_a_cited_fixed_ruling_closes_a_repaired_finding_under_an_insufficient_packet(
    cite_repair: bool,
) -> None:
    """kea fnd_866db2dd end to end: raised, repaired with a regression, then ruled fixed.

    The recheck's packet as a whole is ``insufficient_packet``. With the repair cited the finding
    resolves on that check and says why; a ``fixed`` citing nothing newer is only
    ``unassessable``, leaves the finding open, and is disclosed on the check.
    """

    seed = 2800 + (0 if cite_repair else 100)
    reviewer = _Reviewer(
        [_challenge_obligation, _rule_first_finding("fixed", cite_repair=cite_repair)]
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    _result, repaired = await _repair(session, frontier_json(first.result_frontier), seed + 20)
    second = await _check(session, repaired, seed + 40)

    assert "semantic_packet_insufficient" in second.coverage.known_gaps
    check_rows = [row for row in _records(session.app) if row.schema.name == "check_recorded"]
    recorded = cast(CheckRecordedPayload, check_rows[-1].payload)
    live = _live_projection(session.app)
    resolved_by = live.findings[raised.finding_id].resolved_by_check_event_id
    if cite_repair:
        assert check_rows[-1].schema == EventSchema("check_recorded", "1.4.0")
        assert [item.verdict for item in recorded.prior_finding_verdicts] == ["fixed"]
        assert resolved_by == check_rows[-1].event_id
        explanation = finding_resolution_explanation(live, raised.finding_id, _records(session.app))
        assert "ruled it fixed" in explanation
    else:
        assert [item.verdict for item in recorded.prior_finding_verdicts] == ["unassessable"]
        assert "semantic_prior_verdicts_unsupported" in second.coverage.known_gaps
        assert resolved_by is None
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


def _rule_first_finding_on_a_complete_packet(
    verdict: str | None,
) -> Callable[[FrozenCase], SemanticJudgment]:
    def answer(frozen: FrozenCase) -> SemanticJudgment:
        projection = frozen.case.projection
        finding = next(
            key
            for key, row in projection.findings.items()
            if row.payload is not None
            and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        )
        newest = max(projection.results.items(), key=lambda pair: pair[1].source_frontier)[0]
        rulings = (
            () if verdict is None else (PriorFindingVerdict(str(finding), verdict, (str(newest),)),)  # type: ignore[arg-type]
        )
        return SemanticJudgment("no_material_discrepancy", (), rulings)

    return answer


@pytest.mark.parametrize("verdict", ["fixed", None])
async def test_budget_cut_excerpts_block_silence_but_not_a_cited_fixed_ruling(
    verdict: str | None,
) -> None:
    """Issue #907: the repair check's packet cut excerpts (``content_unselected``).

    The finding was raised before the cut, so its baseline lacks the gap. A cited ``fixed``
    ruling assessed it on material the reviewer was shown and closes it; silence does not
    (intentional: a selection gap still blocks closing an AI-powered finding by silence).
    """

    seed = 3000 + (0 if verdict == "fixed" else 100)
    reviewer = _Reviewer(
        [_challenge_obligation, _rule_first_finding_on_a_complete_packet(verdict)],
        content_gaps={1: ("content_unselected",)},
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    assert "content_unselected" not in raised.coverage.known_gaps
    _result, repaired = await _repair(session, frontier_json(first.result_frontier), seed + 20)
    second = await _check(session, repaired, seed + 40)

    assert "content_unselected" in second.coverage.known_gaps
    live = _live_projection(session.app)
    resolved_by = live.findings[raised.finding_id].resolved_by_check_event_id
    check_rows = [row for row in _records(session.app) if row.schema.name == "check_recorded"]
    if verdict == "fixed":
        assert resolved_by == check_rows[-1].event_id
    else:
        assert resolved_by is None
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


# Issue #905 slice 4: terminal states. ``acknowledged_not_done`` and ``rejection_accepted`` are final,
# never re-reviewed, and reach the receipt in their own sections; ``respond`` records nothing more.


def _respond_wire(
    session: _Session,
    frontier: JsonValue,
    finding_frontier: JsonValue,
    finding: Finding,
    seed: int,
    disposition: str,
    reason: str | None,
) -> dict[str, JsonValue]:
    wire: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed)),
        "session_id": session.session_id,
        "writer_id": session.writer_id,
        "expected_frontier": frontier,
        "finding_id": finding.finding_id,
        "finding_frontier": finding_frontier,
        "disposition": disposition,
    }
    if reason is not None:
        wire["reason"] = reason
    return wire


def _no_challenges(_frozen: FrozenCase) -> SemanticJudgment:
    return SemanticJudgment("no_material_discrepancy", ())


async def _receipt(session: _Session, frontier: JsonValue, seed: int, fmt: str) -> Any:
    return await session.app.receipt(
        ReceiptRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "task_id": session.task_id,
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "format": fmt,
                "include": "standard",
                "redaction_profile": "full_local",
            }
        )
    )


async def test_acknowledged_not_done_is_final_never_rereviewed_and_never_clean() -> None:
    """numba fnd_01c5aaf7: the agent says it will not do it, with a reason, and that is final."""

    seed = 3000
    reviewer = _Reviewer([_challenge_obligation, _no_challenges])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)

    # A missing reason is refused by the request contract; a blank one by respond, typed.
    with pytest.raises(ValueError):
        RespondRequest.model_validate(
            _respond_wire(session, at, at, raised, seed + 20, "acknowledged_not_done", None)
        )
    with pytest.raises(PublicOperationError) as blank:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(session, at, at, raised, seed + 21, "acknowledged_not_done", "   ")
            )
        )
    assert blank.value.code is PublicErrorCode.INVALID_REQUEST
    assert blank.value.safe_details is not None
    assert blank.value.safe_details["reason_code"] == "response_fields_invalid"

    reason = "llvmlite 0.46.0 is not installable in this sandbox; out of scope for this task."
    wire = _respond_wire(session, at, at, raised, seed + 22, "acknowledged_not_done", reason)
    recorded = await session.app.respond(RespondRequest.model_validate(wire))
    assert recorded.response.disposition == "acknowledged_not_done"
    response_rows = [row for row in _records(session.app) if row.schema.name == "response_recorded"]
    assert [row.schema for row in response_rows] == [EventSchema("response_recorded", "1.1.0")]

    # A replayed respond is a no-op: same answer, nothing appended.
    count = len(_records(session.app))
    replayed = await session.app.respond(RespondRequest.model_validate(wire))
    assert replayed.accepted_event == recorded.accepted_event
    assert len(_records(session.app)) == count

    # Terminal is final: a later response records nothing and says why, typed.
    after = frontier_json(recorded.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(session, after, at, raised, seed + 23, "rejected", "Changed mind.")
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"
    assert len(_records(session.app)) == count

    # The next review is not asked about it again, and the item stays not done.
    second = await _check(session, after, seed + 30)
    assert f"prior-finding-{raised.finding_id}" not in {
        item.item_id for item in reviewer.cases[1].items
    }
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.ACKNOWLEDGED_NOT_DONE
    assert receipt_blocking_finding_count(live) >= 1

    json_receipt = await _receipt(session, frontier_json(second.result_frontier), seed + 40, "json")
    assert json_receipt.conclusion == "unresolved_findings_remain"
    document = cast(Mapping[str, JsonValue], json_receipt.document)
    assert document["acknowledged_not_done_finding_ids"] == [raised.finding_id]
    for fmt in ("markdown", "text"):
        rendered = await _receipt(
            session, frontier_json(second.result_frontier), seed + 41 + len(fmt), fmt
        )
        assert "Acknowledged, not done" in cast(str, rendered.human_text)
        assert raised.finding_id in cast(str, rendered.human_text)
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


def _withdraw_first_finding(frozen: FrozenCase) -> SemanticJudgment:
    projection = frozen.case.projection
    finding = next(
        key
        for key, row in projection.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    # ``insufficient_packet`` keeps the ordinary absence proof from resolving it, so only the
    # withdrawal speaks.
    return SemanticJudgment(
        "insufficient_packet", (), (PriorFindingVerdict(str(finding), "withdrawn", ()),)
    )


async def test_a_withdrawn_reasoned_rejection_latches_rejection_accepted() -> None:
    """termenv 34ddb7af: a reasoned rejection the reviewer withdraws stops blocking, disclosed."""

    seed = 3100
    reviewer = _Reviewer([_challenge_obligation, _withdraw_first_finding])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    rejected = await session.app.respond(
        RespondRequest.model_validate(
            _respond_wire(
                session, at, at, raised, seed + 20, "rejected", "The task statement excludes it."
            )
        )
    )
    blocking_before = receipt_blocking_finding_count(_live_projection(session.app))
    second = await _check(session, frontier_json(rejected.result_frontier), seed + 30)

    live = _live_projection(session.app)
    check_row = [row for row in _records(session.app) if row.schema.name == "check_recorded"][-1]
    record = live.findings[raised.finding_id]
    assert record.resolved_by_check_event_id is None
    assert record.rejection_accepted_by_check_event_id == check_row.event_id
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.REJECTION_ACCEPTED
    assert receipt_blocking_finding_count(live) == blocking_before - 1

    after = frontier_json(second.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(session, after, at, raised, seed + 40, "acknowledged", None)
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"
    json_receipt = await _receipt(session, after, seed + 50, "json")
    document = cast(Mapping[str, JsonValue], json_receipt.document)
    assert document["rejection_accepted_finding_ids"] == [raised.finding_id]
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


def _withdraw_first_finding_assessably(frozen: FrozenCase) -> SemanticJudgment:
    projection = frozen.case.projection
    finding = next(
        key
        for key, row in projection.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    # An assessable review that does not return the issue, over changed state: on its own the
    # ordinary absence proof would resolve it. The explicit ``withdrawn`` must still win.
    return SemanticJudgment(
        "no_material_discrepancy", (), (PriorFindingVerdict(str(finding), "withdrawn", ()),)
    )


async def test_an_assessable_withdrawn_ruling_on_a_rejection_reads_rejection_accepted() -> None:
    """PR #943 review P1: the reviewer's explicit ``withdrawn`` outranks the silent absence proof.

    Raise, reject with a reason, change material state, then an assessable review that does not
    return the issue and rules it ``withdrawn``. The same check would prove it absent, but the
    item's one final state is ``rejection_accepted`` on every surface: projection, status
    findings view and CLI text, the check's checklist and MCP text, and every receipt format.
    """

    from yoetz.cli.render import render_human_check, render_human_status
    from yoetz.mcp.summaries import summary_for_status
    from yoetz.protocol.models import (
        CheckFindingChecklistModel,
        CheckSuccessModel,
        CoverageModel,
        StatusResultModel,
        StatusSuccessModel,
    )

    seed = 3600
    reviewer = _Reviewer([_challenge_obligation, _withdraw_first_finding_assessably])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    rejected = await session.app.respond(
        RespondRequest.model_validate(
            _respond_wire(
                session, at, at, raised, seed + 20, "rejected", "The task statement excludes it."
            )
        )
    )
    _result, repaired = await _repair(session, frontier_json(rejected.result_frontier), seed + 30)
    second = await _check(session, repaired, seed + 50)

    live = _live_projection(session.app)
    check_row = [row for row in _records(session.app) if row.schema.name == "check_recorded"][-1]
    recorded = cast(CheckRecordedPayload, check_row.payload)
    assert recorded.semantic_conclusion == "no_material_discrepancy"
    assert [item.verdict for item in recorded.prior_finding_verdicts] == ["withdrawn"]
    assert raised.finding_id not in recorded.returned_finding_ids
    record = live.findings[raised.finding_id]
    assert record.rejection_accepted_by_check_event_id == check_row.event_id
    assert record.resolved_by_check_event_id is None
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.REJECTION_ACCEPTED
    assert "Rejection accepted" in finding_resolution_explanation(
        live, raised.finding_id, _records(session.app)
    )
    assert receipt_blocking_finding_count(live) == 0

    # The check's own checklist and its MCP text agree.
    checklist = second.finding_checklist
    assert checklist is not None
    row = next(item for item in checklist.items if item.finding_id == raised.finding_id)
    assert row.todo_state == "rejection_accepted"
    assert (checklist.counts.rejection_accepted, checklist.counts.verified_resolved) == (1, 0)
    wire = check_internal_json(second)
    # The bounded MCP text leads with the task continuation (#963); it agrees with the finding-only
    # checklist, and the to-do counts ride along only while the summary has room for them.
    summary = summary_for_check(wire)
    assert cast(Mapping[str, JsonValue], wire["finding_checklist"])["next"] == "request_receipt"
    assert "overall next: request_receipt" in summary
    if "to-do:" in summary:
        assert "verified 0, not done 0, rejection accepted 1" in summary
    # CLI text of the same checklist wire (the rest of the check is not under test here).
    checked = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        finding_checklist=CheckFindingChecklistModel.model_validate(wire["finding_checklist"]),
        children=None,
        advisory_notes=(),
        coverage=CoverageModel.model_construct(known_gaps=()),
    )
    assert f"[-] F-1 {raised.finding_id} rejection_accepted" in render_human_check(checked)

    # Status findings view and its CLI/TUI text.
    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 60)),
        "session_id": session.session_id,
        "writer_id": session.writer_id,
        "view": "findings",
        "limit": "100",
    }
    status = await session.app.status(StatusRequest.model_validate(status_body))
    assert isinstance(status.page, StatusFindingsPageModel)
    status_row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert status_row.todo_state == "rejection_accepted"
    assert status_row.resolved is False
    # The client-projected wire the CLI and the terminal interface both render.
    projected = await project_case(
        session.app,
        ProjectionCase("status/findings-terminal", ControlMethod.STATUS, status_body, status),
        seed + 65,
    )
    success = StatusResultModel.model_validate(projected).root
    assert isinstance(success, StatusSuccessModel)
    text = render_human_status(success)
    assert f"[-] F-1 {raised.finding_id} rejection_accepted" in text
    assert "verified_resolved" not in text
    assert "rejection accepted 1" in summary_for_status(projected)

    # Every receipt format names it as a rejection accepted, never as resolved.
    after = frontier_json(second.result_frontier)
    json_receipt = await _receipt(session, after, seed + 70, "json")
    document = cast(Mapping[str, JsonValue], json_receipt.document)
    assert document["rejection_accepted_finding_ids"] == [raised.finding_id]
    for fmt in ("markdown", "text"):
        rendered = await _receipt(session, after, seed + 71 + len(fmt), fmt)
        human = cast(str, rendered.human_text)
        assert "Rejection accepted" in human
        assert raised.finding_id in human
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


def _still_present_first_finding(frozen: FrozenCase) -> SemanticJudgment:
    projection = frozen.case.projection
    finding = next(
        key
        for key, row in projection.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    obligation = next(iter(projection.obligations))
    return SemanticJudgment(
        "no_material_discrepancy",
        (),
        (PriorFindingVerdict(str(finding), "still_present", (str(obligation),)),),
    )


async def test_review_rounds_count_toward_the_budget_and_never_close_or_throttle() -> None:
    """Each later review that leaves an item open is one round; the budget only asks, never acts."""

    seed = 3200
    reviewer = _Reviewer(
        [_challenge_obligation, _still_present_first_finding, _still_present_first_finding]
    )
    session, frontier = await _session(reviewer, seed, attempt_budget=2)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    second = await _check(session, frontier_json(first.result_frontier), seed + 20)
    third = await _check(session, frontier_json(second.result_frontier), seed + 30)
    assert len(reviewer.cases) == 3  # every check ran its review; nothing was throttled

    # The check result carries the to-do list; at the budget it asks for a decision, never acts.
    assert first.finding_checklist is not None
    assert first.finding_checklist.next == "work_open_findings"
    checklist = third.finding_checklist
    assert checklist is not None and checklist.attempt_budget == 2
    row = next(item for item in checklist.items if item.finding_id == raised.finding_id)
    assert (row.todo_state, row.review_rounds) == ("open", 2)
    assert checklist.next == "decide_at_budget"
    wire = check_internal_json(third)
    assert cast(Mapping[str, JsonValue], wire["finding_checklist"])["next"] == "decide_at_budget"
    summary = summary_for_check(wire)
    assert "at budget 2" in summary and "next: decide_at_budget" in summary

    status = await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 40)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "findings",
                "limit": "100",
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    assert status.page.attempt_budget == "2"
    status_row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert (status_row.todo_state, status_row.review_rounds) == ("open", "2")

    live = _live_projection(session.app)
    todo = finding_todo(live, raised.finding_id, attempt_budget=2)
    assert todo.review_rounds == 2
    assert todo.state is FindingTodoState.OPEN
    assert todo.budget_reached
    assert not finding_todo(live, raised.finding_id).budget_reached  # default budget 5
    # Still open: the budget never closes or acknowledges anything on the agent's behalf.
    assert live.findings[raised.finding_id].resolved_by_check_event_id is None
    assert live.responses.get(raised.finding_id) is None
    assert third.result_frontier.sequence > second.result_frontier.sequence
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


async def test_three_restatements_become_one_item() -> None:
    """numba x3: the same challenge on unchanged material is seen again and suppressed."""

    seed = 3300
    reviewer = _Reviewer([_challenge_obligation] * 3)
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    second = await _check(session, frontier_json(first.result_frontier), seed + 20)
    third = await _check(session, frontier_json(second.result_frontier), seed + 30)

    semantic_rows = [
        row
        for row in _records(session.app)
        if row.schema.name == "finding_recorded"
        and isinstance(row.payload, Finding)
        and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    ]
    assert [cast(Finding, row.payload).finding_id for row in semantic_rows] == [raised.finding_id]
    for later in (second, third):
        assert "semantic_restatements_suppressed" in later.coverage.known_gaps
        assert "semantic_challenges_rejected" not in later.coverage.known_gaps
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.OPEN
    # Each suppressed restatement is recorded on the one item as still present: two rounds.
    assert live.findings[raised.finding_id].review_rounds == 2
    checks = [row for row in _records(session.app) if row.schema.name == "check_recorded"]
    assert [
        [
            (str(item.finding_id), item.verdict)
            for item in cast(Any, row.payload).prior_finding_verdicts
        ]
        for row in checks[1:]
    ] == [[(raised.finding_id, "still_present")]] * 2
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


async def test_a_re_raise_after_verified_resolution_mints_a_successor() -> None:
    """Done stays done; the problem found again after a cited ``fixed`` is a new item (D1).

    Raise, repair, a cited ``fixed`` resolves it; the next review raises the same challenge on the
    same unchanged obligation. The resolved row keeps its proof and a successor row is minted
    and blocks, instead of the re-raise being swallowed as a restatement.
    """

    seed = 3400
    reviewer = _Reviewer(
        [
            _challenge_obligation,
            _rule_first_finding("fixed", cite_repair=True),
            _challenge_obligation,
        ]
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    _result, repaired = await _repair(session, frontier_json(first.result_frontier), seed + 20)
    second = await _check(session, repaired, seed + 40)
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.VERIFIED_RESOLVED
    assert receipt_blocking_finding_count(live) == 0

    third = await _check(session, frontier_json(second.result_frontier), seed + 60)
    successor = _semantic(third)
    assert successor.finding_id != raised.finding_id
    assert "semantic_restatements_suppressed" not in third.coverage.known_gaps
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_todo_state(live, successor.finding_id) is FindingTodoState.OPEN
    assert receipt_blocking_finding_count(live) == 1
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


async def test_a_checklist_read_failure_never_strands_the_committed_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """D2: the checklist is additive context; any failure reading it drops only the list."""

    from yoetz.application import check as check_module

    def broken(*_args: object, **_kwargs: object) -> object:
        raise RuntimeError("checklist read failed")

    seed = 3500
    reviewer = _Reviewer([_challenge_obligation])
    session, frontier = await _session(reviewer, seed)
    monkeypatch.setattr(check_module, "build_finding_checklist", broken)
    checked = await _check(session, frontier, seed + 10)
    assert checked.outcome == "committed"
    assert checked.finding_checklist is None
    assert _semantic(checked).finding_id in _live_projection(session.app).findings


def _re_raise_first_finding(frozen: FrozenCase) -> SemanticJudgment:
    """The reviewer answers the agent's rebuttal by re-raising and naming the finding (#980)."""

    projection = frozen.case.projection
    finding = next(
        key
        for key, row in projection.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    obligation = next(iter(projection.obligations))
    challenge = replace(
        _challenge(str(obligation), summary="The verification is still not attempted"),
        restates=str(finding),
    )
    return SemanticJudgment("challenges_returned", (challenge,))


def _no_discrepancy(_frozen: FrozenCase) -> SemanticJudgment:
    return SemanticJudgment("no_material_discrepancy", ())


async def test_every_rebuttal_and_the_reviewers_answer_reach_the_next_review() -> None:
    """TB4 tb4n1 D5/D7b: a re-raise of a rebutted finding stays one item, and the next packet
    shows the agent's rebuttal and how the dialogue ended.

    Issue #1020 (ADR-040): the re-raise cites only the obligation, recorded before the agent's
    reasoned rejection, so it is the standing disagreement ``disputed_after_rebuttal``: final, no
    review round, no further answer accepted, and carried to the next packet as a nameable,
    non-rulable settled row with the agent's rebuttal."""

    from yoetz.application.semantic_case import SETTLED_FINDING_ITEM_PREFIX

    seed = 3300
    reviewer = _Reviewer([_challenge_obligation, _re_raise_first_finding, _no_discrepancy])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    rebutted = await session.app.respond(
        RespondRequest.model_validate(
            _respond_wire(session, at, at, raised, seed + 20, "rejected", "Already attempted.")
        )
    )
    second = await _check(session, frontier_json(rebutted.result_frontier), seed + 30)
    # No new finding: the re-raise was recorded on the rebutted item.
    assert not [
        finding
        for finding in second.findings
        if finding.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        and finding.finding_id != raised.finding_id
    ]
    live = _live_projection(session.app)
    semantic_ids = [
        key
        for key, row in live.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    ]
    assert semantic_ids == [raised.finding_id]
    record = live.findings[raised.finding_id]
    assert (record.review_rounds, record.rebuttal_count) == (0, 1)
    assert record.last_reviewer_verdict == "disputed_after_rebuttal"
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.DISPUTED_AFTER_REBUTTAL

    after = frontier_json(second.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(session, after, at, raised, seed + 40, "rejected", "Still attempted.")
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"
    await _check(session, after, seed + 50)
    structural = next(
        item
        for item in reviewer.cases[2].items
        if item.item_id == f"{SETTLED_FINDING_ITEM_PREFIX}{raised.finding_id}"
    )
    row = cast(Mapping[str, JsonValue], strict_json_parse(structural.content))
    assert row["disposition"] == "rejected"
    assert row["rulable"] is False
    assert not any(
        item.item_id == f"prior-finding-{raised.finding_id}" for item in reviewer.cases[2].items
    )
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


# Issue #984 (ADR-034): a repair only a Yoetz limit keeps unproven is answered ``self_verified``.
# The agent says how it verified it and cites its own recorded evidence; the item is final,
# never re-reviewed, not agent work, and never lets the receipt read clean.


async def _artifact_evidence(
    session: _Session, frontier: JsonValue, seed: int
) -> tuple[str, JsonValue]:
    """A digest-only artifact evidence row, the shape an image or binary deliverable gets."""

    evidence_id = protocol_id("evd_", seed)
    published = await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 1)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "event_drafts": [
                    {
                        "event_id": protocol_id("evt_", seed + 2),
                        "schema": {"name": "evidence_recorded", "version": "1.1.0"},
                        "occurred_at": "2026-09-28T12:06:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "evidence_id": evidence_id,
                            "evidence_kind": "artifact",
                            "strength": "content_digest",
                            "content_digest": "sha256:" + "5" * 64,
                            "observed_at": "2026-09-28T12:06:00.000Z",
                            "description": "The rendered chart the agent inspected itself.",
                            "digest_binding": {
                                "subject": "artifact_bytes",
                                "content_availability": "digest_only",
                                "byte_count": 4096,
                                "provenance": "caller_asserted",
                            },
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    }
                ],
            }
        )
    )
    return evidence_id, frontier_json(published.result_frontier)


def _self_verified_wire(
    session: _Session,
    frontier: JsonValue,
    finding_frontier: JsonValue,
    finding: Finding,
    seed: int,
    reason: str,
    evidence: tuple[str, ...],
) -> dict[str, JsonValue]:
    wire = _respond_wire(
        session, frontier, finding_frontier, finding, seed, "self_verified", reason
    )
    if evidence:
        wire["evidence_refs"] = list(evidence)
    return wire


def _refusal(error: pytest.ExceptionInfo[PublicOperationError]) -> str:
    assert error.value.code is PublicErrorCode.INVALID_REQUEST
    assert error.value.safe_details is not None
    return cast(str, error.value.safe_details["reason_code"])


async def test_self_verified_closes_a_repair_only_a_yoetz_limit_keeps_unproven() -> None:
    """tb4n1: the recheck's packet budget cut excerpts, so Yoetz could not prove the repair."""

    seed = 3400
    reviewer = _Reviewer(
        [_challenge_obligation, _rule_first_finding_on_a_complete_packet(None), _no_challenges],
        content_gaps={1: ("content_unselected",)},
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    result_id, repaired = await _repair(session, at, seed + 20)
    evidence_id, evidenced = await _artifact_evidence(session, repaired, seed + 30)
    reason = "Re-ran the stencil suite on llvmlite 0.46.0 myself; 42 passed (result and image)."

    # Repaired but not rechecked: repair, then check first.
    with pytest.raises(PublicOperationError) as early:
        await session.app.respond(
            RespondRequest.model_validate(
                _self_verified_wire(
                    session, evidenced, at, raised, seed + 35, reason, (result_id, evidence_id)
                )
            )
        )
    assert _refusal(early) == "finding_not_rechecked"

    second = await _check(session, evidenced, seed + 40)
    assert "content_unselected" in second.coverage.known_gaps
    after = frontier_json(second.result_frontier)
    live = _live_projection(session.app)
    assert live.findings[raised.finding_id].resolved_by_check_event_id is None

    # No evidence is refused by the request contract; a blank reason by respond, typed.
    with pytest.raises(ValueError):
        RespondRequest.model_validate(
            _self_verified_wire(session, after, at, raised, seed + 50, reason, ())
        )
    with pytest.raises(PublicOperationError) as blank:
        await session.app.respond(
            RespondRequest.model_validate(
                _self_verified_wire(session, after, at, raised, seed + 51, "  ", (result_id,))
            )
        )
    assert _refusal(blank) == "response_fields_invalid"

    # Any recorded evidence id counts, including a digest-only artifact row.
    wire = _self_verified_wire(
        session, after, at, raised, seed + 52, reason, (evidence_id, result_id)
    )
    recorded = await session.app.respond(RespondRequest.model_validate(wire))
    assert recorded.response.disposition == "self_verified"
    assert recorded.response.reason == reason
    assert {item.reference_id for item in recorded.response.evidence} == {evidence_id, result_id}
    response_rows = [row for row in _records(session.app) if row.schema.name == "response_recorded"]
    assert [row.schema for row in response_rows] == [EventSchema("response_recorded", "1.1.0")]

    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.SELF_VERIFIED
    assert live.findings[raised.finding_id].resolved_by_check_event_id is None
    explanation = finding_resolution_explanation(live, raised.finding_id, _records(session.app))
    assert explanation.startswith("Self-verified by the agent")

    # Final: another answer records nothing.
    responded = frontier_json(recorded.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(
                    session, responded, at, raised, seed + 53, "acknowledged_not_done", "No."
                )
            )
        )
    assert _refusal(terminal) == "finding_terminal"

    # Not re-reviewed, not agent work, disclosed.
    third = await _check(session, responded, seed + 60)
    assert f"prior-finding-{raised.finding_id}" not in {
        item.item_id for item in reviewer.cases[2].items
    }
    final = frontier_json(third.result_frontier)
    status = await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 70)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "findings",
                "limit": "100",
                "filter": {"include_resolved": True},
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert (row.todo_state, row.disposition, row.resolved) == (
        "self_verified",
        "self_verified",
        False,
    )
    readiness = status.closure_readiness
    assert readiness.standing_limitations is not None
    assert "finding_self_verified" in readiness.standing_limitations
    assert readiness.agent_actionable is not None
    assert readiness.receipt_blocking_finding_count == "0"
    assert "receipt_findings_unresolved" not in readiness.agent_actionable
    assert "receipt_findings_unresolved" not in readiness.blocking_conditions

    json_receipt = await _receipt(session, final, seed + 80, "json")
    # At best insufficient_coverage: Yoetz never reads the agent's own verification as clean.
    assert json_receipt.conclusion == "insufficient_coverage"
    document = cast(Mapping[str, JsonValue], json_receipt.document)
    assert document["self_verified_finding_ids"] == [raised.finding_id]
    for fmt in ("markdown", "text"):
        rendered = await _receipt(session, final, seed + 81 + len(fmt), fmt)
        text = cast(str, rendered.human_text)
        assert "Self-verified by the agent; Yoetz could not prove the repair" in text
        assert raised.finding_id in text
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


async def _failing_run(session: _Session, frontier: JsonValue, seed: int) -> tuple[str, JsonValue]:
    """Publish a run that did not succeed: the material that can show a problem remains."""

    action_id = protocol_id("act_", seed)
    result_id = protocol_id("res_", seed + 1)
    action_event = protocol_id("evt_", seed + 2)
    published = await session.app.publish_work(
        PublishWorkRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 3)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "event_drafts": [
                    {
                        "event_id": action_event,
                        "schema": {"name": "action_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:20:00.000Z",
                        "causal_parents": [],
                        "payload": {
                            "action_id": action_id,
                            "action_kind": "other",
                            "description": "Re-ran the stencil tests after the repair.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                    {
                        "event_id": protocol_id("evt_", seed + 4),
                        "schema": {"name": "result_recorded", "version": "1.0.0"},
                        "occurred_at": "2026-09-28T12:20:01.000Z",
                        "causal_parents": [action_event],
                        "payload": {
                            "result_id": result_id,
                            "action_id": action_id,
                            "outcome": "failure",
                            "summary": "Two stencil cases fail on llvmlite 0.46.0.",
                        },
                        "artifact_refs": [],
                        "evidence_refs": [],
                    },
                ],
            }
        )
    )
    return result_id, frontier_json(published.result_frontier)


def _challenge_obligation_citing_the_newest_failure(frozen: FrozenCase) -> SemanticJudgment:
    projection = frozen.case.projection
    obligation = next(iter(projection.obligations))
    failure = max(
        (
            (key, row)
            for key, row in projection.results.items()
            if row.payload is not None and row.payload.outcome.value == "failure"
        ),
        key=lambda pair: pair[1].source_frontier,
    )[0]
    return SemanticJudgment("challenges_returned", (_challenge(str(obligation), str(failure)),))


async def test_a_reviewer_restating_a_self_verified_issue_with_newer_material_mints_a_new_finding() -> (
    None
):
    """A later positive sighting is never hidden under ``self_verified`` (adversarial review).

    ``self_verified`` is final only because Yoetz could not see the repair. A reviewer that raises
    the same issue again with concern-relevant material newer than the agent's answer (here a run
    that failed after it) is a new sighting: it is minted as a new open finding the agent must
    answer. tb4n3 RC-7 changed the other half: a repeat citing nothing newer is recorded on the
    settled item instead (``test_a_self_verified_answer_folds_a_repeat_without_newer_material``).
    """

    seed = 4400
    reviewer = _Reviewer(
        [
            _challenge_obligation,
            _rule_first_finding_on_a_complete_packet(None),
            _challenge_obligation_citing_the_newest_failure,
        ],
        content_gaps={1: ("content_unselected",)},
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    result_id, repaired = await _repair(session, at, seed + 20)
    evidence_id, evidenced = await _artifact_evidence(session, repaired, seed + 30)
    second = await _check(session, evidenced, seed + 40)
    after = frontier_json(second.result_frontier)
    recorded = await session.app.respond(
        RespondRequest.model_validate(
            _self_verified_wire(
                session,
                after,
                at,
                raised,
                seed + 52,
                "Re-ran the suite myself; output recorded.",
                (evidence_id, result_id),
            )
        )
    )
    _failure, failed = await _failing_run(
        session, frontier_json(recorded.result_frontier), seed + 55
    )
    third = await _check(session, failed, seed + 60)
    successor = _semantic(third)
    assert successor.finding_id != raised.finding_id
    assert "semantic_restatements_suppressed" not in third.coverage.known_gaps
    live = _live_projection(session.app)
    # The successor cites more than the original (the failing run), so it is a different issue:
    # the check that raised it no longer returns the original, and a qualifying check that tested
    # the work after the self_verified answer proves the original absent (the reverse edge).
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.VERIFIED_RESOLVED
    assert finding_todo_state(live, successor.finding_id) is FindingTodoState.OPEN
    assert receipt_blocking_finding_count(live) == 1
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(live)


async def test_self_verified_is_refused_while_a_complete_review_still_sees_the_issue() -> None:
    """A reviewer with no packet limit ruled it still present: that is not a Yoetz limit."""

    seed = 3500
    reviewer = _Reviewer([_challenge_obligation, _still_present_first_finding])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    result_id, repaired = await _repair(session, at, seed + 20)
    second = await _check(session, repaired, seed + 40)
    count = len(_records(session.app))
    with pytest.raises(PublicOperationError) as refused:
        await session.app.respond(
            RespondRequest.model_validate(
                _self_verified_wire(
                    session,
                    frontier_json(second.result_frontier),
                    at,
                    raised,
                    seed + 50,
                    "I checked it myself.",
                    (result_id,),
                )
            )
        )
    assert _refusal(refused) == "finding_not_proof_limited"
    assert "acknowledged_not_done only if you truly will not" in refused.value.message
    assert len(_records(session.app)) == count
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.OPEN


async def test_formal_crypto_repeat_over_a_reasoned_rebuttal_is_a_standing_disagreement() -> None:
    """Issue #1020 (ADR-040, TB4 tb4n2 formal-crypto S): the reviewer repeats a finding the agent
    rejected with a reason, citing nothing newer. Yoetz records ``disputed_after_rebuttal``: final,
    not agent work, never a review round, and named on every surface; the receipt discloses it
    and cannot read clean."""

    from yoetz.cli.render import render_human_check, render_human_status
    from yoetz.mcp.summaries import summary_for_status
    from yoetz.protocol.models import (
        CheckFindingChecklistModel,
        CheckSuccessModel,
        CoverageModel,
        StatusResultModel,
        StatusSuccessModel,
    )

    seed = 4100
    reviewer = _Reviewer(
        [_challenge_obligation, _still_present_first_finding, _still_present_first_finding]
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    rejected = await session.app.respond(
        RespondRequest.model_validate(
            _respond_wire(
                session,
                at,
                at,
                raised,
                seed + 20,
                "rejected",
                "Fixed benchmark parameters bound the input domain; the general case holds there.",
            )
        )
    )
    second = await _check(session, frontier_json(rejected.result_frontier), seed + 30)

    live = _live_projection(session.app)
    check_row = [row for row in _records(session.app) if row.schema.name == "check_recorded"][-1]
    recorded = cast(CheckRecordedPayload, check_row.payload)
    assert [item.verdict for item in recorded.prior_finding_verdicts] == ["disputed_after_rebuttal"]
    record = live.findings[raised.finding_id]
    assert record.disputed_after_rebuttal_by_check_event_id == check_row.event_id
    assert record.review_rounds == 0
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.DISPUTED_AFTER_REBUTTAL
    assert "Disputed after rebuttal" in finding_resolution_explanation(
        live, raised.finding_id, _records(session.app)
    )
    assert receipt_blocking_finding_count(live) == 0

    checklist = second.finding_checklist
    assert checklist is not None
    row = next(item for item in checklist.items if item.finding_id == raised.finding_id)
    assert row.todo_state == "disputed_after_rebuttal"
    assert checklist.counts.disputed_after_rebuttal == 1
    assert checklist.next == "request_receipt"
    wire = check_internal_json(second)
    checked = CheckSuccessModel.model_construct(
        verdict="no_issue_detected",
        semantic_status="succeeded",
        semantic_reason="semantic_completed",
        semantic_provenance=None,
        findings=(),
        suppressed_count="0",
        finding_checklist=CheckFindingChecklistModel.model_validate(wire["finding_checklist"]),
        children=None,
        advisory_notes=(),
        coverage=CoverageModel.model_construct(known_gaps=()),
    )
    human_check = render_human_check(checked)
    assert f"[d] F-1 {raised.finding_id} disputed_after_rebuttal" in human_check
    assert "disputed after rebuttal 1" in human_check

    # A further repeat changes nothing: still final, still no round.
    third = await _check(session, frontier_json(second.result_frontier), seed + 40)
    live = _live_projection(session.app)
    assert live.findings[raised.finding_id].review_rounds == 0
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.DISPUTED_AFTER_REBUTTAL

    status_body: dict[str, JsonValue] = {
        **request_base(protocol_id("req_", seed + 60)),
        "session_id": session.session_id,
        "writer_id": session.writer_id,
        "view": "findings",
        "limit": "100",
    }
    status = await session.app.status(StatusRequest.model_validate(status_body))
    assert isinstance(status.page, StatusFindingsPageModel)
    status_row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert status_row.todo_state == "disputed_after_rebuttal"
    assert status_row.resolved is False
    projected = await project_case(
        session.app,
        ProjectionCase("status/findings-terminal", ControlMethod.STATUS, status_body, status),
        seed + 65,
    )
    success = StatusResultModel.model_validate(projected).root
    assert isinstance(success, StatusSuccessModel)
    assert f"[d] F-1 {raised.finding_id} disputed_after_rebuttal" in render_human_status(success)
    assert "disputed after rebuttal 1" in summary_for_status(projected)

    after = frontier_json(third.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(
                    session, after, at, raised, seed + 70, "acknowledged_not_done", "Giving up."
                )
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"

    json_receipt = await _receipt(session, after, seed + 80, "json")
    document = cast(Mapping[str, JsonValue], json_receipt.document)
    assert document["disputed_after_rebuttal_finding_ids"] == [raised.finding_id]
    assert document["conclusion"] != "no_unresolved_deterministic_findings"
    for fmt in ("markdown", "text"):
        rendered = await _receipt(session, after, seed + 81 + len(fmt), fmt)
        human = cast(str, rendered.human_text)
        assert "Disputed after rebuttal" in human
        assert raised.finding_id in human
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


async def test_a_self_verified_refusal_names_the_recorded_blocking_reasons() -> None:
    """tb4n2 R5 (issue #1023): the refusal says what disqualified it and the way out.

    The refusal carries the recorded resolution-reason tokens in ``safe_details`` and names them,
    a next step and the ``yoetz-verification-limit:`` exit in its message, so the agent need not
    retry ``self_verified`` blind.
    """

    seed = 3600
    reviewer = _Reviewer([_challenge_obligation, _still_present_first_finding])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    result_id, repaired = await _repair(session, at, seed + 20)
    second = await _check(session, repaired, seed + 40)
    with pytest.raises(PublicOperationError) as refused:
        await session.app.respond(
            RespondRequest.model_validate(
                _self_verified_wire(
                    session,
                    frontier_json(second.result_frontier),
                    at,
                    raised,
                    seed + 50,
                    "I checked it myself.",
                    (result_id,),
                )
            )
        )
    assert _refusal(refused) == "finding_not_proof_limited"
    details = refused.value.safe_details
    blocking = cast(tuple[str, ...], details["blocking_reasons"])
    assert blocking
    assert "reviewer_verdict_still_present" in blocking
    message = refused.value.message
    assert all(token in message for token in blocking)
    assert "yoetz-verification-limit:" in message
    assert "the check still sees the issue" in message
    assert "I checked it myself." not in message


def _rule_first_finding_citing_the_repair_event(
    verdict: str,
) -> Callable[[FrozenCase], SemanticJudgment]:
    """kv-live-surgery S check 343: the closing reviewer supports the repair, citing the result by
    the event that recorded it (``evt_3318a99d`` for ``res_fc7a82cf``), as the packet offers it."""

    def answer(frozen: FrozenCase) -> SemanticJudgment:
        projection = frozen.case.projection
        finding = next(
            key
            for key, row in projection.findings.items()
            if row.payload is not None
            and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
        )
        newest = max(projection.results.values(), key=lambda row: row.source_frontier)
        refs = (str(newest.source_event_id),)
        return SemanticJudgment(
            "no_material_discrepancy",
            (),
            (PriorFindingVerdict(str(finding), verdict, refs),),  # type: ignore[arg-type]
        )

    return answer


async def test_kv_repair_acknowledged_then_ruled_fixed_by_its_event_ends_verified_resolved() -> (
    None
):
    """tb4n5 follow-up of #1046, kv-live-surgery S ``fnd_c96c2b9f`` end to end.

    The reviewer raised the finding; the agent published the repair result, then answered
    ``acknowledged`` with a reason citing it (a standing position since #1030); the next review
    ruled ``fixed`` citing the result's ``evt_`` id. Before: the ruling was judged unsupported
    (only ``evd_``/``res_`` counted), converted into ``disputed_after_rebuttal`` because the repair
    preceded the answer, and the terminal row still told the agent to repair or self-verify. Now
    the real ruling admission resolves the event, the finding ends ``verified_resolved`` with no
    ``semantic_prior_verdicts_unsupported``, the row carries no next action, and a further answer
    is refused.
    """

    seed = 4700
    reviewer = _Reviewer(
        [_challenge_obligation, _rule_first_finding_citing_the_repair_event("fixed")]
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    repair, repaired = await _repair(session, at, seed + 20)
    acknowledged = await session.app.respond(
        RespondRequest.model_validate(
            {
                **_respond_wire(
                    session,
                    repaired,
                    at,
                    raised,
                    seed + 30,
                    "acknowledged",
                    "Agreed; the active post-v2 throughput run is now recorded.",
                ),
                "evidence_refs": [repair],
            }
        )
    )
    second = await _check(session, frontier_json(acknowledged.result_frontier), seed + 40)

    check_row = [row for row in _records(session.app) if row.schema.name == "check_recorded"][-1]
    recorded = cast(CheckRecordedPayload, check_row.payload)
    live = _live_projection(session.app)
    repair_event = str(live.results[cast(Any, repair)].source_event_id)
    assert [(item.verdict, item.cited_refs) for item in recorded.prior_finding_verdicts] == [
        ("fixed", (repair_event,))
    ]
    assert "semantic_prior_verdicts_unsupported" not in second.coverage.known_gaps
    record = live.findings[raised.finding_id]
    assert record.disputed_after_rebuttal_by_check_event_id is None
    assert record.resolved_by_check_event_id == check_row.event_id
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.VERIFIED_RESOLVED
    explanation = finding_resolution_explanation(live, raised.finding_id, _records(session.app))
    assert "ruled it fixed" in explanation
    assert "repair it, then check" not in explanation

    status = await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 50)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "findings",
                "limit": "100",
                "filter": {"include_resolved": True},
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert row.resolved is True
    assert row.todo_state == "verified_resolved"
    assert row.next_actions == ("none",)
    assert "self_verified" not in str(row.detail)

    after = frontier_json(second.result_frontier)
    with pytest.raises(PublicOperationError) as terminal:
        await session.app.respond(
            RespondRequest.model_validate(
                _respond_wire(session, after, at, raised, seed + 60, "acknowledged", "Done.")
            )
        )
    assert terminal.value.safe_details is not None
    assert terminal.value.safe_details["reason_code"] == "finding_terminal"
    # tb4n5: 4 of 7 refusals were this harmless repeat; the hint says nothing is owed.
    assert "proved the issue absent, so it needs no answer" in terminal.value.message
    assert "Do not retry" in terminal.value.message
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )


async def test_an_acknowledged_finding_held_open_without_newer_material_is_a_quiet_dispute() -> (
    None
):
    """No-repeat protection holds (owner, 2026-10-13: an acknowledgement may count as a
    rebuttal): a reviewer that keeps an acknowledged finding open citing nothing newer than the
    answer latches ``disputed_after_rebuttal``. The terminal row says so and gives no impossible
    instruction (tb4n5 kv: "repair it, then check" and ``self_verified`` on a final item)."""

    seed = 4800
    reviewer = _Reviewer([_challenge_obligation, _still_present_first_finding])
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    attempt, attempted = await _repair(session, at, seed + 15)
    acknowledged = await session.app.respond(
        RespondRequest.model_validate(
            {
                **_respond_wire(
                    session,
                    attempted,
                    at,
                    raised,
                    seed + 20,
                    "acknowledged",
                    "Agreed; one more install attempt is recorded.",
                ),
                "evidence_refs": [attempt],
            }
        )
    )
    await _check(session, frontier_json(acknowledged.result_frontier), seed + 30)
    live = _live_projection(session.app)
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.DISPUTED_AFTER_REBUTTAL
    explanation = finding_resolution_explanation(live, raised.finding_id, _records(session.app))
    assert explanation.startswith("Disputed after rebuttal: the agent answered it with a reason")
    assert "takes no further response" in explanation
    assert "repair it, then check" not in explanation
    assert "self_verified" not in explanation
    status = await session.app.status(
        StatusRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed + 40)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "view": "findings",
                "limit": "100",
            }
        )
    )
    assert isinstance(status.page, StatusFindingsPageModel)
    row = next(item for item in status.page.items if item.finding_id == raised.finding_id)
    assert row.todo_state == "disputed_after_rebuttal"
    assert row.next_actions == ("none",)
    assert "repair it, then check" not in str(row.detail)
    assert "self_verified" not in str(row.detail)


def _unassessable_first_finding(frozen: FrozenCase) -> SemanticJudgment:
    projection = frozen.case.projection
    finding = next(
        key
        for key, row in projection.findings.items()
        if row.payload is not None and row.payload.origin is FindingOrigin.SEMANTIC_MODEL_DERIVED
    )
    return SemanticJudgment(
        "no_material_discrepancy",
        (),
        (PriorFindingVerdict(str(finding), "unassessable", ()),),
    )


async def _default_check(session: _Session, frontier: JsonValue, seed: int) -> CheckCommitResult:
    checked = await session.app.check(
        CheckRequest.model_validate(
            {
                **request_base(protocol_id("req_", seed)),
                "session_id": session.session_id,
                "writer_id": session.writer_id,
                "expected_frontier": frontier,
                "max_findings": "5",
            }
        )
    )
    assert type(checked) is CheckCommitResult, f"unexpected nonterminal check: {type(checked)}"
    return checked


async def test_a_finding_the_reviewer_keeps_unassessable_stops_the_round_and_stays_open() -> None:
    """Codex check of fix/n5-findings (P2): an honest ``unassessable`` stays an open round, so a
    reviewer that cannot judge an answered finding was asked again at every check (8 provider
    calls, 7 rounds). After two such rulings in a row with no edit, later checks skip the review
    and say why; the finding is never resolved or disputed by it, stays unresolved, and every
    receipt format discloses both."""

    seed = 4900
    reviewer = _Reviewer(
        [_challenge_obligation]
        + [_unassessable_first_finding] * 2
        + [_no_challenges] * 5  # never reached: the round stopped
    )
    session, frontier = await _session(reviewer, seed)
    first = await _check(session, frontier, seed + 10)
    raised = _semantic(first)
    at = frontier_json(first.result_frontier)
    repair, repaired = await _repair(session, at, seed + 15)
    answered = await session.app.respond(
        RespondRequest.model_validate(
            {
                **_respond_wire(
                    session,
                    repaired,
                    at,
                    raised,
                    seed + 20,
                    "acknowledged",
                    "Agreed; the install attempt is now recorded.",
                ),
                "evidence_refs": [repair],
            }
        )
    )
    frontier = frontier_json(answered.result_frontier)
    for round_seed in (seed + 30, seed + 40):
        checked = await _default_check(session, frontier, round_seed)
        assert checked.semantic_status is SemanticStatus.SUCCEEDED
        frontier = frontier_json(checked.result_frontier)
    assert len(reviewer.cases) == 3
    # The round is exhausted: later checks skip the review instead of asking again.
    for round_seed in (seed + 50, seed + 60, seed + 70):
        checked = await _default_check(session, frontier, round_seed)
        assert checked.semantic_status is SemanticStatus.NOT_REQUESTED
        assert "semantic_review_skipped_insufficient_packet" in checked.coverage.known_gaps
        frontier = frontier_json(checked.result_frontier)
    assert len(reviewer.cases) == 3

    live = _live_projection(session.app)
    record = live.findings[raised.finding_id]
    assert record.disputed_after_rebuttal_by_check_event_id is None
    assert record.resolved_by_check_event_id is None
    assert finding_todo_state(live, raised.finding_id) is FindingTodoState.OPEN
    for offset, fmt in enumerate(("json", "markdown", "text")):
        receipt = await _receipt(session, frontier, seed + 80 + offset, fmt)
        assert receipt.conclusion == "unresolved_findings_remain", fmt
        assert "semantic_review_skipped_insufficient_packet" in receipt.coverage.known_gaps, fmt
        if fmt != "json":
            human = cast(str, receipt.human_text)
            assert raised.finding_id in human, fmt
    assert projection_snapshot(replay(_records(session.app))) == projection_snapshot(
        _live_projection(session.app)
    )
