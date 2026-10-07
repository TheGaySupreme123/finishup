"""Completion needs an answerable signal: statement mapping and observed corroboration (TB4 pilot).

The TB4 pilot (2026-10-05) showed an agent miss a stated requirement, resolve its own coarse
obligations with its own evidence, and reach a receipt while the only relevant signal was an
advisory coverage note. These vectors lock the two promoted, agent-actionable findings: a task
statement that no effective obligation cites, and a completion claim that cites no hook-observed
verification run made after the latest observed edit. Both are structural; no prose is read.
"""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.policy_cases import (
    BASE_COVERAGE,
    act,
    claim_record,
    clm,
    evd,
    evidence_record,
    evt,
    make_case,
    obl,
    obligation_record,
    plan_record,
    record,
    res,
)
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    ClaimKind,
    ClaimRecordedPayloadV1_1,
    DecisionRecordedPayload,
    EvidenceKind,
    EvidenceRecordedPayload,
    NoObligationsReason,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    ResultOutcome,
    ResultRecordedPayload,
    encode_payload,
)
from yoetz.domain.findings import FindingKind
from yoetz.domain.task_statement import (
    TASK_STATEMENT_SCOPE_EMPTY_SUMMARY,
    RecordedTaskStatement,
)
from yoetz.domain.values import ResultId, actor_id, object_id, timestamp_from_string
from yoetz.kernel.closure_readiness import GapClass, classify_gap
from yoetz.kernel.deterministic_checks import (
    DeterministicCase,
    FindingBasisRef,
    build_task_statement_unmapped_assessment,
)
from yoetz.kernel.plan_drift import (
    INSTRUCTION_REQUIREMENT_UNMAPPED_GAP,
    OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP,
    PLAN_DRIFT_ADVISORY_GAPS,
    PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP,
)
from yoetz.kernel.policies.work_integrity import work_integrity_findings
from yoetz.kernel.projections import DecisionProjectionRecord, ProjectionRecord
from yoetz.protocol.canonical import canonical_digest
from yoetz.protocol.coverage import Coverage, EvidenceImmutability, PublicationChannel

_STATEMENT_EVENT = evt(1)


def _statement() -> RecordedTaskStatement:
    return RecordedTaskStatement(
        "Fix the planner; over-limit loads must not clear.", evt(1), "session_opened", 1
    )


def _obligation(
    number: int,
    *,
    cites: bool,
    status: ObligationStatus = ObligationStatus.OPEN,
    evidence: tuple[str, ...] = (),
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obl(number),
        "Requirement",
        "A result",
        status,
        source_refs=(_STATEMENT_EVENT,) if cites else (),
        resolution_evidence_refs=evidence,  # pyright: ignore[reportArgumentType]
    )


def _statement_case(
    *obligations: ObligationPublishedPayload, empty_reason: bool = False
) -> DeterministicCase:
    plan = (
        PlanPublishedPayload(1, "Plan", (), (), NoObligationsReason.SINGLE_ATOMIC_CHANGE)
        if empty_reason
        else PlanPublishedPayload(1, "Plan", tuple(item.obligation_id for item in obligations))
    )
    case = make_case(
        plans={1: plan_record(plan, 2)},
        obligations={
            item.obligation_id: obligation_record(item, 10 + index)
            for index, item in enumerate(obligations)
        },
        extra_refs=(_STATEMENT_EVENT,),
    )
    return replace(case, task_statement=_statement())


def test_unmapped_statement_raises_an_actionable_finding_naming_the_statement_event() -> None:
    assessment = build_task_statement_unmapped_assessment(
        _statement_case(_obligation(1, cites=False), _obligation(2, cites=False))
    )

    assert assessment is not None
    candidate = assessment.candidate
    assert candidate.kind is FindingKind.TASK_REQUIREMENT_UNMET
    assert candidate.subject_refs == (_STATEMENT_EVENT,)
    assert candidate.policy_id == "research-evidence"
    assert candidate.summary == (
        "No obligation in the current plan cites the recorded task statement."
    )
    assert f"source_refs [{_STATEMENT_EVENT}]" in candidate.detail
    assert "plan_revised" in candidate.detail
    assert "A check rerun without that plan change returns this finding again." in candidate.detail
    # Fixed repository wording plus structural ids only: the statement text never appears.
    assert "over-limit" not in candidate.detail


def test_one_statement_sourced_obligation_clears_the_unmapped_finding() -> None:
    case = _statement_case(_obligation(1, cites=False), _obligation(2, cites=True))

    assert build_task_statement_unmapped_assessment(case) is None


def test_no_statement_keeps_its_behaviour_and_empty_scope_is_quiet_mid_task() -> None:
    """No statement never raises; an empty or undeclared scope raises only at completion (D3)."""

    without_statement = replace(_statement_case(_obligation(1, cites=False)), task_statement=None)
    empty_scope = _statement_case(empty_reason=True)
    no_plan = replace(make_case(extra_refs=(_STATEMENT_EVENT,)), task_statement=_statement())

    assert build_task_statement_unmapped_assessment(without_statement) is None
    # Mid-task, before any completion claim: neither form fires.
    assert build_task_statement_unmapped_assessment(empty_scope) is None
    assert build_task_statement_unmapped_assessment(no_plan) is None
    # No statement stays quiet even at completion.
    assert (
        build_task_statement_unmapped_assessment(
            replace(_with_completion(_statement_case(empty_reason=True)), task_statement=None)
        )
        is None
    )


def _with_completion(case: DeterministicCase, *, edit: bool = False) -> DeterministicCase:
    claims = {clm(1): claim_record(_claim(), 90)}
    actions = (
        {act(70): record(ActionRecordedPayload(act(70), ActionKind.EDIT, "Edit"), 70)}
        if edit
        else {}
    )
    rebuilt = make_case(
        plans=dict(case.projection.plans),
        obligations=dict(case.projection.obligations),
        actions=actions,
        claims=claims,
        extra_refs=(_STATEMENT_EVENT,),
    )
    return replace(rebuilt, task_statement=case.task_statement)


def _with_decision(case: DeterministicCase, statement: str) -> DeterministicCase:
    decision = DecisionRecordedPayload(
        statement, "The user asked a question only.", actor_id("agent:1")
    )
    row = DecisionProjectionRecord(
        payload=decision,
        payload_digest=canonical_digest(encode_payload(decision)),
        redacted=False,
        source_event_id=evt(95),
        source_frontier=95,
    )
    return replace(case, projection=replace(case.projection, decisions={evt(95): row}))


@pytest.mark.parametrize("empty_reason", (True, False))
def test_completion_on_an_empty_or_undeclared_scope_raises_an_answerable_finding(
    empty_reason: bool,
) -> None:
    """The core guarantee: a completion claim never stands on an undecomposed request (D3)."""

    base = (
        _statement_case(empty_reason=True)
        if empty_reason
        else replace(make_case(extra_refs=(_STATEMENT_EVENT,)), task_statement=_statement())
    )
    assessment = build_task_statement_unmapped_assessment(_with_completion(base))

    assert assessment is not None
    candidate = assessment.candidate
    assert candidate.kind is FindingKind.TASK_REQUIREMENT_UNMET
    assert candidate.subject_refs == (_STATEMENT_EVENT,)
    assert candidate.summary == TASK_STATEMENT_SCOPE_EMPTY_SUMMARY
    assert f"source_refs [{_STATEMENT_EVENT}]" in candidate.detail
    assert f"yoetz-no-material-work:{_STATEMENT_EVENT}" in candidate.detail
    assert "over-limit" not in candidate.detail


def test_a_no_material_work_decision_answers_the_empty_scope_unless_work_was_edited() -> None:
    marker = f"No material work.\nyoetz-no-material-work:{_STATEMENT_EVENT}"
    decided = _with_decision(_with_completion(_statement_case(empty_reason=True)), marker)
    contradicted = _with_decision(
        _with_completion(_statement_case(empty_reason=True), edit=True), marker
    )
    wrong_event = _with_decision(
        _with_completion(_statement_case(empty_reason=True)),
        f"yoetz-no-material-work:{evt(2)}",
    )
    prose_only = _with_decision(
        _with_completion(_statement_case(empty_reason=True)),
        f"The request needs no material work (yoetz-no-material-work:{_STATEMENT_EVENT}).",
    )

    unchanged = {"workspace_changed": False}
    assert build_task_statement_unmapped_assessment(decided, **unchanged) is None
    # A task that edited files did material work: the decision is contradicted.
    assert build_task_statement_unmapped_assessment(contradicted, **unchanged) is not None
    assert build_task_statement_unmapped_assessment(wrong_event, **unchanged) is not None
    assert build_task_statement_unmapped_assessment(prose_only, **unchanged) is not None


def test_a_no_material_work_decision_does_not_survive_shell_only_file_changes() -> None:
    """Shell writes are command actions, so the check-time capture must witness no change."""

    marker = f"No material work.\nyoetz-no-material-work:{_STATEMENT_EVENT}"
    decided = _with_decision(_with_completion(_statement_case(empty_reason=True)), marker)
    assert not any(
        row.payload is not None and row.payload.action_kind is ActionKind.EDIT
        for row in decided.projection.actions.values()
    )

    # The capture shows a changed path although no edit action was recorded: finding kept.
    changed = build_task_statement_unmapped_assessment(decided, workspace_changed=True)
    assert changed is not None
    assert changed.candidate.summary == TASK_STATEMENT_SCOPE_EMPTY_SUMMARY
    # No capture available: the decision is not honoured (fail closed), including by default.
    assert build_task_statement_unmapped_assessment(decided, workspace_changed=None) is not None
    assert build_task_statement_unmapped_assessment(decided) is not None
    # A genuine no-change task still clears with the decision.
    assert build_task_statement_unmapped_assessment(decided, workspace_changed=False) is None


def test_an_obligation_citing_an_equivalent_statement_event_maps_the_statement() -> None:
    """A re-attach repeating the unchanged statement must not orphan earlier mappings (D2)."""

    resumed = evt(3)
    obligation = ObligationPublishedPayload(
        obl(1), "Requirement", "A result", ObligationStatus.OPEN, source_refs=(_STATEMENT_EVENT,)
    )
    case = make_case(
        plans={1: plan_record(PlanPublishedPayload(1, "Plan", (obl(1),)), 2)},
        obligations={obl(1): obligation_record(obligation, 10)},
        extra_refs=(_STATEMENT_EVENT, resumed),
    )
    text = _statement().text
    equivalent = RecordedTaskStatement(
        text, resumed, "session_resumed", 3, equivalent_event_ids=(_STATEMENT_EVENT, resumed)
    )
    amended = RecordedTaskStatement("A different request.", resumed, "session_resumed", 3)

    assert (
        build_task_statement_unmapped_assessment(replace(case, task_statement=equivalent)) is None
    )
    assert (
        build_task_statement_unmapped_assessment(replace(case, task_statement=amended)) is not None
    )


def test_only_the_unmapped_statement_gap_is_agent_actionable() -> None:
    assert PLAN_DRIFT_ADVISORY_GAPS == {
        PLAN_UNREFINED_BEFORE_FIRST_EDIT_GAP,
        OBLIGATION_EVIDENCE_STALE_AFTER_SCOPE_EDIT_GAP,
    }
    flags = {"semantic_review_required": False, "semantic_review_current": False}
    assert classify_gap(INSTRUCTION_REQUIREMENT_UNMAPPED_GAP, **flags) is GapClass.AGENT_ACTIONABLE
    for code in PLAN_DRIFT_ADVISORY_GAPS:
        assert classify_gap(code, **flags) is GapClass.STANDING_LIMITATION


# --- observed corroboration of a completion claim ------------------------------------------

_HOOK = Coverage(
    publication_channels=(PublicationChannel.HOOK_OBSERVED,),
    authorship_assurance=BASE_COVERAGE.authorship_assurance,
    artifact_observation=BASE_COVERAGE.artifact_observation,
    evidence_immutability=BASE_COVERAGE.evidence_immutability,
    ledger_freshness=BASE_COVERAGE.ledger_freshness,
    check_types=BASE_COVERAGE.check_types,
    known_gaps=(),
)


def _observed_edit(number: int) -> ActionRecordedPayload:
    return ActionRecordedPayload(act(number), ActionKind.EDIT, "Edit (tool apply_patch)")


def _observed_command(number: int, runner: str | None = "test") -> ActionRecordedPayload:
    suffix = "" if runner is None else f" (runner {runner})"
    return ActionRecordedPayload(
        act(number),
        ActionKind.COMMAND,
        f"Command (tool Bash){suffix}",
        command="omitted:structural",
    )


def _result(number: int, outcome: ResultOutcome = ResultOutcome.SUCCESS) -> ResultRecordedPayload:
    return ResultRecordedPayload(res(number), act(number), outcome)


def _claim(
    *support: str, limitations: tuple[str, ...] = (), obligations: tuple[str, ...] = ()
) -> ClaimRecordedPayloadV1_1:
    return ClaimRecordedPayloadV1_1(
        claim_id=clm(1),
        claim_kind=ClaimKind.COMPLETION,
        statement="Done.",
        supporting_refs=support,  # pyright: ignore[reportArgumentType]
        obligation_refs=obligations,  # pyright: ignore[reportArgumentType]
        limitation_refs=limitations,  # pyright: ignore[reportArgumentType]
        supersedes_claim_refs=(),
    )


def _corroboration_case(
    *,
    edits: tuple[int, ...] = (),
    commands: tuple[tuple[int, str | None, ResultOutcome], ...] = (),
    cooperative_result: int | None = None,
    claim: ClaimRecordedPayloadV1_1,
    obligations: tuple[ObligationPublishedPayload, ...] = (),
) -> DeterministicCase:
    """Observed edits/commands at the given frontiers; the claim is recorded at frontier 90."""

    actions = {act(number): record(_observed_edit(number), number) for number in edits}
    results: dict[ResultId, ProjectionRecord[ResultRecordedPayload]] = {}
    observed: set[FindingBasisRef] = {evt(number) for number in edits}
    for number, runner, outcome in commands:
        actions[act(number)] = record(_observed_command(number, runner), number)
        results[res(number)] = record(_result(number, outcome), number + 1)
        observed.update({evt(number), evt(number + 1)})
    if cooperative_result is not None:
        actions[act(cooperative_result)] = record(
            ActionRecordedPayload(
                act(cooperative_result), ActionKind.COMMAND, "Ran tests", command="pytest"
            ),
            cooperative_result,
        )
        results[res(cooperative_result)] = record(
            _result(cooperative_result), cooperative_result + 1
        )
    plan = PlanPublishedPayload(1, "Plan", tuple(item.obligation_id for item in obligations))
    return make_case(
        plans={1: plan_record(plan, 2)},
        obligations={
            item.obligation_id: obligation_record(item, 80 + index)
            for index, item in enumerate(obligations)
        },
        actions=actions,
        results=results,
        claims={clm(1): claim_record(claim, 90)},
        coverage_overrides={ref: _HOOK for ref in observed},
    )


def _uncorroborated(case: DeterministicCase) -> list[str]:
    return [
        assessment.candidate.summary
        for assessment in work_integrity_findings(case)
        if assessment.candidate.kind is FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE
        and any(
            fact.fact_code == "observed_verification_uncited"
            for fact in assessment.basis.observed_facts
        )
    ]


def test_self_generated_verification_after_the_last_edit_stays_admissible() -> None:
    """tb4n1 E7: self-generated evidence stays allowed (#977 item 5, ADR-033).

    TB4 cargo shape: observed edits and test runs, and the claim cites the agent's own command
    result published after the last observed edit. In tb4n1 this fired in 2 D and 6 S attempts
    (rs-archive D, payments D, pretrain S, sglang S, ...) and asked for citation bookkeeping only.
    """

    case = _corroboration_case(
        edits=(20,),
        commands=((30, "test", ResultOutcome.SUCCESS),),
        cooperative_result=60,
        claim=_claim(res(60)),
    )

    assert _uncorroborated(case) == []


def test_self_generated_verification_before_a_later_edit_is_actionable() -> None:
    """The fact the rule keeps: no verification, observed or self-published, after the last edit."""

    case = _corroboration_case(
        edits=(20, 70),
        commands=((30, "test", ResultOutcome.SUCCESS),),
        cooperative_result=60,
        claim=_claim(res(60)),
    )

    findings = [
        assessment
        for assessment in work_integrity_findings(case)
        if assessment.candidate.kind is FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE
    ]
    assert len(findings) == 1
    candidate = findings[0].candidate
    assert candidate.subject_refs == (clm(1),)
    assert "status view=results" in candidate.detail
    assert f"supersedes_claim_refs [{clm(1)}]" in candidate.detail
    assert "A check rerun alone returns this finding again" in candidate.detail
    assert "Self-asserted evidence is not" not in candidate.detail


def test_claim_citing_an_observed_run_after_the_last_edit_is_quiet() -> None:
    case = _corroboration_case(
        edits=(20,),
        commands=((30, "test", ResultOutcome.SUCCESS),),
        cooperative_result=60,
        claim=_claim(res(30), res(60)),
    )

    assert _uncorroborated(case) == []


def test_observed_run_cited_through_a_resolved_obligation_is_quiet() -> None:
    resolved = _obligation(1, cites=True, status=ObligationStatus.RESOLVED, evidence=(res(30),))
    case = _corroboration_case(
        edits=(20,),
        commands=((30, None, ResultOutcome.SUCCESS),),
        claim=_claim(obl(1), obligations=(obl(1),)),
        obligations=(resolved,),
    )

    assert _uncorroborated(case) == []


def test_run_before_a_later_edit_or_an_exploration_run_does_not_corroborate() -> None:
    stale = _corroboration_case(
        edits=(20, 40),
        commands=((30, "test", ResultOutcome.SUCCESS),),
        claim=_claim(res(30)),
    )
    exploration = _corroboration_case(
        edits=(20,),
        commands=((30, "exploration", ResultOutcome.SUCCESS),),
        claim=_claim(res(30)),
    )

    assert len(_uncorroborated(stale)) == 1
    assert len(_uncorroborated(exploration)) == 1


def test_disclosed_failing_observed_run_counts_as_corroboration() -> None:
    case = _corroboration_case(
        edits=(20,),
        commands=((30, "test", ResultOutcome.FAILURE),),
        cooperative_result=60,
        claim=_claim(res(60), limitations=(res(30),)),
    )

    assert _uncorroborated(case) == []


def test_no_hook_observation_keeps_the_rule_silent() -> None:
    case = _corroboration_case(cooperative_result=60, claim=_claim(res(60)))

    assert _uncorroborated(case) == []


def _captured(number: int) -> EvidenceRecordedPayload:
    return EvidenceRecordedPayload(
        evidence_id=evd(number),
        evidence_kind=EvidenceKind.TEST_RESULT,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-10-05T12:00:00.000Z"),
        captured_object_id=object_id(f"obj_10000000-0000-4000-8000-0000000000{number:02d}"),
        content_digest="sha256:" + "a" * 64,
    )


def _with_captured_output(
    base: DeterministicCase, *, linked_from: int | None, captured_at: int = 50
) -> DeterministicCase:
    """Add hook-captured output, linked from result ``linked_from`` when given."""

    results = dict(base.projection.results)
    if linked_from is not None:
        row = results[res(linked_from)]
        assert row.payload is not None
        results[res(linked_from)] = record(
            replace(row.payload, evidence_refs=(evd(captured_at),)), row.source_frontier
        )
    observed: dict[FindingBasisRef, Coverage] = {
        ref: coverage
        for ref, coverage in base.coverage_by_ref.items()
        if PublicationChannel.HOOK_OBSERVED in coverage.publication_channels
    }
    observed[evt(captured_at)] = _HOOK
    return make_case(
        plans=dict(base.projection.plans),
        actions=dict(base.projection.actions),
        results=results,
        evidence={evd(captured_at): evidence_record(_captured(captured_at), captured_at)},
        claims=dict(base.projection.claims),
        coverage_overrides=observed,
    )


def test_captured_output_of_a_verification_run_after_the_last_edit_is_quiet() -> None:
    """Native output a verification run links corroborates at that run's frontier (R2)."""

    def case_with(edit_at: int) -> DeterministicCase:
        base = _corroboration_case(
            edits=(edit_at,),
            commands=((40, "test", ResultOutcome.SUCCESS),),
            claim=_claim(evd(50)),
        )
        return _with_captured_output(base, linked_from=40)

    assert _uncorroborated(case_with(20)) == []
    assert len(_uncorroborated(case_with(45))) == 1


def test_only_verification_class_captures_corroborate() -> None:
    """A standalone capture, an edit's own output, or an exploration run's output is not a run."""

    standalone = _with_captured_output(
        _corroboration_case(edits=(20,), claim=_claim(evd(50))), linked_from=None
    )
    exploration = _with_captured_output(
        _corroboration_case(
            edits=(20,),
            commands=((40, "exploration", ResultOutcome.SUCCESS),),
            claim=_claim(evd(50)),
        ),
        linked_from=40,
    )
    edit_output = _corroboration_case(edits=(20,), claim=_claim(evd(50)))
    edit_result = ResultRecordedPayload(res(20), act(20), ResultOutcome.SUCCESS)
    edit_output = _with_captured_output(
        make_case(
            plans=dict(edit_output.projection.plans),
            actions=dict(edit_output.projection.actions),
            results={res(20): record(edit_result, 21)},
            claims=dict(edit_output.projection.claims),
            coverage_overrides={evt(20): _HOOK, evt(21): _HOOK},
        ),
        linked_from=20,
    )

    for case in (standalone, exploration, edit_output):
        assert len(_uncorroborated(case)) == 1


def test_an_outcome_less_verification_run_corroborates_but_never_triggers() -> None:
    """A long run whose host stated no outcome still shows a run after the edit (R1/R2)."""

    cited = _corroboration_case(
        edits=(20,),
        commands=((40, "test", ResultOutcome.UNKNOWN),),
        claim=_claim(res(40)),
    )
    no_edit = _corroboration_case(
        commands=((40, "test", ResultOutcome.UNKNOWN),),
        cooperative_result=60,
        claim=_claim(res(60)),
    )

    assert _uncorroborated(cited) == []
    assert _uncorroborated(no_edit) == []


def test_hook_captured_evidence_alone_keeps_the_rule_silent() -> None:
    """Captured evidence corroborates a claim but never makes the rule apply on its own.

    Codex states no outcome for a shell post and an unpaired post becomes captured evidence only,
    so a task whose hooks observed no edit and no verification run (the #913 bandit B shape) has
    nothing a completion claim could be asked to cite.
    """

    unpaired = EvidenceRecordedPayload(
        evidence_id=evd(50),
        evidence_kind=EvidenceKind.OTHER,
        strength=EvidenceImmutability.IMMUTABLE_SNAPSHOT,
        observed_at=timestamp_from_string("2026-10-05T12:00:00.000Z"),
        captured_object_id=object_id("obj_10000000-0000-4000-8000-000000000050"),
        content_digest="sha256:" + "a" * 64,
    )
    base = _corroboration_case(cooperative_result=60, claim=_claim(res(60)))
    case = make_case(
        plans=dict(base.projection.plans),
        actions=dict(base.projection.actions),
        results=dict(base.projection.results),
        evidence={evd(50): evidence_record(unpaired, 50)},
        claims=dict(base.projection.claims),
        coverage_overrides={evt(50): _HOOK},
    )

    assert _uncorroborated(case) == []
