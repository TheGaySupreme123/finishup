"""Issue #1143: input changes demand reruns; unknown relationships ask instead."""

# pyright: reportPrivateUsage=false

import json
from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.application.check import CheckScope, _freshness_candidate, run_deterministic_policies
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ResultOutcome,
)
from finishup.domain.findings import FINDING_KIND_TRAITS, Finding, ResponseDisposition
from finishup.domain.values import claim_id, evidence_id, finding_id, timestamp_from_string
from finishup.domain.workspace_effect import workspace_path_identity
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.kernel.policies.work_integrity import _verification_questions
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key, task_fact_signals
from finishup.kernel.verification_freshness import verification_freshness
from finishup.protocol.coverage import EvidenceImmutability


@pytest.fixture(autouse=True)
def key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def manifest(
    ledger: ObservedLedger,
    run: str,
    *,
    complete: bool = True,
    inputs: tuple[str, ...] = ("src/control.py", "config.json", "data.csv"),
) -> None:
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id(f"evd_00000000-0000-4000-8000-{len(ledger.records):012d}"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-21T12:00:00.000Z"),
            reference=f"finishup-verification-inputs/v1:{run}",
            description=json.dumps(
                {
                    "inputs": list(inputs),
                    "outputs": ["evidence.json"],
                    "complete": complete,
                }
            ),
        ),
        observed=False,
    )


def changed(ledger: ObservedLedger, path: str, *, observed: bool = True) -> None:
    ledger.run(
        "python update.py",
        ResultOutcome.SUCCESS,
        runner="other",
        observed=observed,
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
        workspace_changed_entries=(workspace_path_identity(INSTALLATION_KEY, path),),
    )


def case_for(ledger: ObservedLedger):
    return build_deterministic_case(replay(ledger.prefix), ledger.prefix, CaseAvailabilityFacts())


@pytest.mark.parametrize("path", ["evidence.json", "other.txt"])
def test_outputs_and_unrelated_changes_do_not_stale_a_known_input_set(path: str) -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    changed(ledger, path)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert not {
        "planned_verification_stale",
        "edited_after_last_verification",
        "verification_rerun_question",
    } & set(facts.codes)
    assert not _verification_questions(case_for(ledger))


def test_evidence_output_does_not_require_a_complete_dependency_claim() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run, complete=False)
    changed(ledger, "evidence.json")
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)


@pytest.mark.parametrize("path", ["src/control.py", "config.json", "data.csv"])
def test_changed_verification_input_is_stale_and_named(path: str) -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    changed(ledger, path)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert {"planned_verification_stale", "edited_after_last_verification"} <= set(facts.codes)
    case = case_for(ledger)
    assert case.verification_freshness is not None
    assert case.verification_freshness[0].changes == (f"{path}: verification input changed",)
    restored = deterministic_case_from_json(deterministic_case_to_json(case))
    assert restored == case
    questions = _verification_questions(replace(restored, verification_advisory=True))
    assert len(questions) == 1
    rendered = _freshness_candidate(questions[0].candidate, case)
    assert path in rendered.detail
    assert "non-blocking" in rendered.detail


def test_unknown_inputs_ask_without_a_staleness_assertion() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    changed(ledger, "unrecorded.py")
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_rerun_question" in facts.codes
    assert not {"planned_verification_stale", "edited_after_last_verification"} & set(facts.codes)
    questions = _verification_questions(case_for(ledger))
    assert len(questions) == 1
    assert FINDING_KIND_TRAITS[questions[0].candidate.kind][1] is False


def test_ai_question_accepts_a_reasoned_respond_answer_and_new_change_reasks() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    changed(ledger, "config.json")
    case = replace(case_for(ledger), verification_advisory=True)
    candidate = _verification_questions(case)[0].candidate
    identifier = finding_id("fnd_00000000-0000-4000-8000-000000001143")
    finding = Finding(
        identifier,
        candidate.kind,
        candidate.origin,
        candidate.priority,
        candidate.summary,
        candidate.detail,
        candidate.subject_refs,
        candidate.policy_id,
        candidate.policy_version,
        candidate.subject_frontier,
        candidate.coverage,
        candidate.provenance,
    )
    ledger.append(EventSchema("finding_recorded", "1.0.0"), finding, observed=False)
    ledger.respond(
        identifier,
        ResponseDisposition.ACKNOWLEDGED,
        reason="Rerun not needed: the changed configuration affects reporting only; the tested controller inputs are unchanged.",
    )
    assert not _verification_questions(replace(case_for(ledger), verification_advisory=True))
    changed(ledger, "data.csv")
    assert len(_verification_questions(replace(case_for(ledger), verification_advisory=True))) == 1


def test_rerun_supersedes_the_old_question() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    changed(ledger, "config.json")
    ledger.passes("pytest -q")
    assert not _verification_questions(case_for(ledger))


def test_cooperative_comparison_cannot_prove_a_changed_input() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    changed(ledger, "config.json", observed=False)
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)


def test_local_input_change_blocks_but_ai_route_asks() -> None:
    from finishup.kernel.closure_readiness import derive_closure_readiness
    from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    changed(ledger, "src/control.py")
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000001143"),
            ClaimKind.COMPLETION,
            "The controller passed the test",
            (run,),
        ),
        observed=False,
    )
    case = case_for(ledger)
    assert len(_uncorroborated_completion_findings(case)) == 1
    assert not _uncorroborated_completion_findings(replace(case, verification_advisory=True))
    assert not _uncorroborated_completion_findings(
        replace(
            case,
            verification_advisory=True,
            verification_freshness=None,
        )
    )
    assessments, executions = run_deterministic_policies(
        case,
        CheckScope((), ()),
        ("work-integrity/0.3.0",),
        verification_advisory=True,
    )
    assert all(execution.reason == "completed" for execution in executions)
    questions = [item for item in assessments if "rerun needed" in item.candidate.summary]
    assert len(questions) == 1
    assert "src/control.py" in _freshness_candidate(questions[0].candidate, case).detail
    gaps = ("planned_verification_stale", "edited_after_last_verification")
    local = derive_closure_readiness((), gaps, None, semantic_review_required=False)
    ai = derive_closure_readiness((), gaps, None, semantic_review_required=True)
    assert set(gaps) <= set(local.agent_actionable)
    assert not set(gaps) & set(ai.agent_actionable)


def test_many_changes_preserve_bounded_lineage_and_latest_question_identity() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    for _ in range(20):
        changed(ledger, "src/control.py")
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "planned_verification_stale" in facts.codes
    assert all(len(item.source_event_ids) <= 8 for item in facts.lineage)
    case = case_for(ledger)
    before = _verification_questions(replace(case, verification_advisory=True))[0]
    changed(ledger, "src/control.py")
    after = _verification_questions(replace(case_for(ledger), verification_advisory=True))[0]
    assert before.candidate.subject_refs != after.candidate.subject_refs


def test_late_changed_annotation_reasks_without_moving_the_call_frontier() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    result = ledger.run("python update.py", ResultOutcome.SUCCESS, workspace_effect="changed")
    before = _verification_questions(case_for(ledger))[0]
    ledger.annotate_workspace_effect(result, "unavailable")
    after = _verification_questions(case_for(ledger))[0]
    assert before.candidate.subject_refs != after.candidate.subject_refs
    ledger.passes("pytest -q")
    ledger.annotate_workspace_effect(result, "changed", scopes=("workspace",))
    assert not _verification_questions(case_for(ledger))


def test_conflicting_input_declarations_ask_instead_of_asserting_staleness() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run)
    manifest(ledger, run, inputs=("other.py",))
    changed(ledger, "config.json")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert len(rows) == 1 and rows[0].state == "unknown"


def test_only_the_verification_whose_input_changed_is_stale() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest tests_a.py", "pytest tests_b.py")
    first = ledger.passes("pytest tests_a.py")
    manifest(ledger, first, inputs=("source_a.py",))
    second = ledger.passes("pytest tests_b.py")
    manifest(ledger, second, inputs=("source_b.py",))
    changed(ledger, "source_a.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.run_ref, row.state) for row in rows] == [(first, "stale")]


def test_a_late_outcome_correction_does_not_move_the_verification_past_an_edit() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.run("pytest -q", ResultOutcome.UNKNOWN)
    manifest(ledger, run)
    changed(ledger, "config.json")
    ledger.correct_outcome(run, ResultOutcome.SUCCESS, exit_status=0)
    # The original run declaration still names its logical result. A correction cannot turn
    # missing dependency knowledge into a current verification at its later delivery frontier.
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert (
        "verification_rerun_question" in facts.codes or "planned_verification_stale" in facts.codes
    )


@pytest.mark.parametrize("path", ["/outside/input.json", "node_modules/pkg/deep/input.json"])
def test_opaque_manifest_input_cannot_borrow_a_workspace_noop_proof(path: str) -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run, inputs=(path,))
    ledger.run(
        "cat saved.json > evidence.json",
        ResultOutcome.SUCCESS,
        write_scope="workspace",
        workspace_effect="unchanged",
    )
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert len(rows) == 1 and rows[0].state == "unknown"
