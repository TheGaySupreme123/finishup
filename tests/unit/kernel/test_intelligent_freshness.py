"""Issue #1143: input changes demand reruns; unknown relationships ask instead."""

# pyright: reportPrivateUsage=false

import json
from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger, observed_receipt
from finishup.application.check import CheckScope, _freshness_candidate, run_deterministic_policies
from finishup.domain.events import (
    ClaimKind,
    ClaimRecordedPayload,
    EventSchema,
    EvidenceKind,
    EvidenceRecordedPayload,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    RequestedItemRole,
    ResultOutcome,
    ResultRecordedPayload,
    ResultVerification,
    VerificationDataSource,
    encode_payload,
)
from finishup.domain.findings import FINDING_KIND_TRAITS, Finding, ResponseDisposition
from finishup.domain.values import (
    ResultId,
    claim_id,
    evidence_id,
    finding_id,
    obligation_id,
    result_id,
    timestamp_from_string,
)
from finishup.domain.verification_coverage import verification_coverage_lines
from finishup.domain.workspace_effect import (
    result_summary_with_workspace_effect,
    workspace_path_identity,
)
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.kernel.policies.work_integrity import _verification_questions
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import register_command_identity_key, task_fact_signals
from finishup.kernel.verification_coverage import build_verification_coverage
from finishup.kernel.verification_freshness import verification_freshness, verification_tracked_runs
from finishup.protocol.canonical import canonical_digest
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
    outputs: tuple[str, ...] = ("evidence.json",),
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
                    "outputs": list(outputs),
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


def producing_run(ledger: ObservedLedger, command: str, *paths: str) -> ResultId:
    """A verification run whose own trusted comparison records that it wrote *paths*."""

    return ledger.run(
        command,
        ResultOutcome.SUCCESS,
        exit_status=0,
        runner="test",
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
        workspace_changed_entries=tuple(
            sorted(workspace_path_identity(INSTALLATION_KEY, path) for path in paths)
        ),
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
    run = producing_run(ledger, "pytest -q", "evidence.json")
    manifest(ledger, run, complete=False)
    changed(ledger, "evidence.json")
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)


def test_an_output_the_verification_never_wrote_cannot_hide_a_later_edit() -> None:
    """PR #1167 review: an output exemption covers only bytes the verification itself produced.

    A pre-existing source file listed only as an output under ``complete: false`` stays a possible
    input: editing it later asks instead of passing silently.
    """

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000001167"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-21T12:00:00.000Z"),
            reference=f"finishup-verification-inputs/v1:{run}",
            description=json.dumps(
                {"inputs": [], "outputs": ["src/control.py"], "complete": False}
            ),
        ),
        observed=False,
    )
    changed(ledger, "src/control.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.state, row.basis) for row in rows] == [("unknown", "declared")]
    assert rows[0].changes == ('"src/control.py" added, removed or modified',)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_rerun_question" in facts.codes
    assert "verification_inputs_caller_asserted" not in facts.codes


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
    assert case.verification_freshness[0].changes == (
        f'"{path}" changed: a recorded verification input',
    )
    assert case.verification_freshness[0].basis == "complete"
    assert case.verification_freshness[0].label == "pytest -q"
    restored = deterministic_case_from_json(deterministic_case_to_json(case))
    assert restored == case
    questions = _verification_questions(replace(restored, verification_advisory=True))
    assert len(questions) == 1
    rendered = _freshness_candidate(questions[0].candidate, case)
    assert f'"{path}" changed: a recorded verification input' in rendered.detail
    assert f'verification {run} (requested command "pytest -q")' in rendered.detail
    assert "caller-asserted complete input declaration" in rendered.detail
    assert "does not block closure" in rendered.detail


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
    """A late annotation joins its call's change at the call's frontier (AI route: it asks).

    The change names no path, so on the local route the verification is stale; on the AI route
    the same row is the rerun question, and the late annotation re-asks with its own subject.
    After a rerun, another late annotation of the old call does not reopen the question.
    """

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    result = ledger.run("python update.py", ResultOutcome.SUCCESS, workspace_effect="changed")
    assert [row.state for row in case_for(ledger).verification_freshness or ()] == ["stale"]
    before = _verification_questions(replace(case_for(ledger), verification_advisory=True))[0]
    ledger.annotate_workspace_effect(result, "unavailable")
    after = _verification_questions(replace(case_for(ledger), verification_advisory=True))[0]
    assert before.candidate.subject_refs != after.candidate.subject_refs
    ledger.passes("pytest -q")
    ledger.annotate_workspace_effect(result, "changed", scopes=("workspace",))
    assert not _verification_questions(replace(case_for(ledger), verification_advisory=True))


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
    # The second run's own complete declaration says it does not read source_a.py: it stays
    # current, and the reliance on that caller assertion is disclosed rather than hidden.
    assert [(row.run_ref, row.state) for row in rows] == [(first, "stale"), (second, "current")]
    assert not rows[0].caller_asserted and rows[1].caller_asserted
    assert rows[1].changes == (
        '"source_a.py" changed outside the caller-asserted complete input list',
    )


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
    (row,) = verification_freshness(replay(ledger.prefix), ledger.prefix)
    # The no-op proof covers only the compared workspace: the input outside it may have changed,
    # and FinishUP cannot place the write, so the run stays stale and says why.
    assert row.state == "stale"
    assert row.changes == (
        "1 later rewrite(s) left the compared workspace unchanged, but a verification input lies"
        " outside what the comparison covers; FinishUP cannot tell whether that touched this"
        " verification's inputs",
    )


# --- PR #1167 review: per-verification scopes, honest wording, caller assertions --------------


def obligation_with(
    ledger: ObservedLedger,
    number: int,
    *items: tuple[RequestedItemKind, str, RequestedItemRole | None],
) -> None:
    """Publish one obligation requesting *items* and a plan naming every obligation so far."""

    identifier = obligation_id(f"obl_00000000-0000-4000-8000-{number:012d}")
    ledger.append(
        EventSchema("obligation_published", "1.1.0"),
        ObligationPublishedPayload(
            obligation_id=identifier,
            description="Deliver",
            evidence_expectation="Tests",
            status=ObligationStatus.OPEN,
            requested_items=tuple(
                RequestedItem(kind, value, role=role) for kind, value, role in items
            ),
        ),
        observed=False,
    )
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(
            number,
            "Deliver",
            tuple(
                obligation_id(f"obl_00000000-0000-4000-8000-{n:012d}") for n in range(1, number + 1)
            ),
        ),
        observed=False,
    )


_COMMAND = (RequestedItemKind.COMMAND, "pytest -q", None)
_SRC_DIRECTORY = (RequestedItemKind.DIRECTORY, "src", RequestedItemRole.INPUT)


@pytest.mark.parametrize("scoped", [True, False])
def test_a_directory_input_does_not_disable_another_verifications_output_exemption(
    scoped: bool,
) -> None:
    """A requested ``src/`` directory input beside a complete per-run manifest (Cursor, #1167).

    The manifest-covered verification's own evidence output stays quiet whether the directory is
    requested by that verification's obligation or by a command-less, task-level obligation.
    """

    ledger = ObservedLedger()
    if scoped:
        obligation_with(ledger, 1, _COMMAND, _SRC_DIRECTORY)
    else:
        obligation_with(ledger, 1, _COMMAND)
        obligation_with(ledger, 2, _SRC_DIRECTORY)
    run = producing_run(ledger, "pytest -q", "evidence.json")
    manifest(ledger, run)
    changed(ledger, "evidence.json")
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert not {
        "verification_rerun_question",
        "planned_verification_stale",
        "edited_after_last_verification",
        "verification_inputs_caller_asserted",
    } & set(facts.codes)
    # A known file input on the same task still goes stale and is named.
    changed(ledger, "src/control.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [row.state for row in rows] == ["stale"]
    assert rows[0].changes == ('"src/control.py" changed: a recorded verification input',)


def test_a_scoped_directory_input_still_asks_about_an_unnamed_change() -> None:
    ledger = ObservedLedger()
    obligation_with(ledger, 1, _COMMAND, _SRC_DIRECTORY)
    run = producing_run(ledger, "pytest -q", "evidence.json")
    manifest(ledger, run)
    changed(ledger, "src/other.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [row.state for row in rows] == ["unknown"]
    assert "a requested input directory may contain the changed path" in rows[0].changes


def test_a_task_level_directory_input_still_bounds_an_undeclared_verification() -> None:
    ledger = ObservedLedger()
    obligation_with(ledger, 1, _COMMAND)
    obligation_with(ledger, 2, _SRC_DIRECTORY)
    producing_run(ledger, "pytest -q", "evidence.json")
    ledger.run(
        "python write_docs.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_write_scopes=("docs",),
        workspace_changed_entries=(workspace_path_identity(INSTALLATION_KEY, "src/README.md"),),
    )
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.state, row.basis) for row in rows] == [("unknown", "undeclared")]


def test_an_unobservable_input_of_another_verification_does_not_poison_this_one() -> None:
    ledger = ObservedLedger()
    obligation_with(
        ledger,
        1,
        _COMMAND,
        (RequestedItemKind.COMMAND, "pytest other", None),
    )
    obligation_with(
        ledger,
        2,
        (RequestedItemKind.COMMAND, "make lint", None),
        (RequestedItemKind.FILE, "/outside/lint.toml", RequestedItemRole.INPUT),
    )
    run = producing_run(ledger, "pytest -q", "evidence.json")
    manifest(ledger, run, complete=False)
    changed(ledger, "evidence.json")
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)


def test_a_complete_declaration_with_no_inputs_never_silences_an_edit() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run, inputs=())
    changed(ledger, "src/control.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.state, row.basis) for row in rows] == [("unknown", "declared")]
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_rerun_question" in facts.codes
    assert "verification_inputs_caller_asserted" not in facts.codes


def test_a_complete_declaration_that_omits_an_edited_file_is_accepted_and_disclosed() -> None:
    """ADR-042 accepts the caller's complete assertion; every surface discloses the reliance."""

    from finishup.domain.receipts import receipt_document_to_json, render_receipt_human
    from finishup.kernel.closure_readiness import derive_closure_readiness

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run, inputs=("src/control.py",))
    changed(ledger, "src/other.py")
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.state, row.basis) for row in rows] == [("current", "complete")]
    assert rows[0].caller_asserted
    assert rows[0].changes == (
        "1 unnamed changed path(s) outside the caller-asserted complete input list",
    )
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_inputs_caller_asserted" in facts.codes
    assert not {
        "verification_rerun_question",
        "planned_verification_stale",
        "edited_after_last_verification",
    } & set(facts.codes)
    assert not _verification_questions(case_for(ledger))
    readiness = derive_closure_readiness((), facts.codes, None, semantic_review_required=False)
    assert "verification_inputs_caller_asserted" not in readiness.agent_actionable
    receipt = observed_receipt(ledger, extra_gaps=facts.codes)
    rendered = [
        json.dumps(receipt_document_to_json(receipt)),
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ]
    for text in rendered:
        assert "verification_inputs_caller_asserted" in text


def test_a_complete_declaration_discloses_reliance_only_when_it_set_a_change_aside() -> None:
    """A question about an unplaceable path sets nothing aside: no caller-assertion disclosure.

    The run's command also requests a ``src`` directory input, so a keyed change the record does
    not name may lie inside it and asks. Only a named change outside the complete declaration is
    set aside on the caller's assertion, and only then is the reliance disclosed.
    """

    ledger = ObservedLedger()
    obligation_with(ledger, 1, _COMMAND, _SRC_DIRECTORY)
    run = ledger.passes("pytest -q")
    manifest(ledger, run, inputs=("src/control.py",))
    changed(ledger, "src/helper.py")
    (row,) = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert (row.state, row.basis) == ("unknown", "complete")
    assert not row.caller_asserted
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_rerun_question" in facts.codes
    assert "verification_inputs_caller_asserted" not in facts.codes

    changed(ledger, "evidence.json")
    (row,) = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert (row.state, row.basis) == ("unknown", "complete")
    assert row.caller_asserted
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert {"verification_rerun_question", "verification_inputs_caller_asserted"} <= set(
        facts.codes
    )


def test_an_undeclared_change_says_so_and_names_what_the_record_names() -> None:
    """The Cursor smoke: no declaration, an evidence write and a source edit (#1167 review).

    The question never claims that inputs were declared, names the verification and its requested
    command, names a changed path the record names, and counts keyed-only identities honestly.
    """

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000001168"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-21T12:00:00.000Z"),
            reference="evidence.json",
            description="Verifier evidence",
        ),
        observed=False,
    )
    changed(ledger, "evidence.json")
    changed(ledger, "src/control.py")
    case = case_for(ledger)
    assert case.verification_freshness is not None
    (row,) = case.verification_freshness
    assert (row.state, row.basis, row.label) == ("unknown", "undeclared", "pytest -q")
    assert row.changes == (
        '"evidence.json" added, removed or modified',
        "1 changed workspace path(s) not named anywhere in the task record (only keyed"
        " identities were observed)",
    )
    (question,) = _verification_questions(case)
    rendered = _freshness_candidate(question.candidate, case).detail
    assert "input roles are declared" not in rendered
    assert "path unavailable" not in rendered
    assert f'verification {run} (requested command "pytest -q")' in rendered
    assert "no usable input declaration is recorded for it" in rendered
    assert '"evidence.json" added, removed or modified' in rendered


def test_the_ai_review_asks_about_freshness_only_when_a_verification_has_later_changes() -> None:
    """The advisory freshness question joins the review only when it has something to weigh."""

    from finishup.application.semantic_case import (
        FRESHNESS_REVIEW_QUESTION,
        review_question_set,
        verification_freshness_asked,
    )

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    assert not verification_freshness_asked(case_for(ledger))
    assert FRESHNESS_REVIEW_QUESTION not in review_question_set("final")
    ledger.edit()
    assert verification_freshness_asked(case_for(ledger))
    assert FRESHNESS_REVIEW_QUESTION in review_question_set("final", freshness=True)


def test_receipts_never_claim_an_input_changed_for_an_edit_finishup_cannot_place() -> None:
    """An edit-tool edit records no path; the shared sentences say so (#1167 review finding 3)."""

    from finishup.domain.receipts import receipt_document_to_json, render_receipt_human

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    ledger.edit()
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert {"planned_verification_stale", "edited_after_last_verification"} <= set(facts.codes)
    receipt = observed_receipt(ledger, extra_gaps=facts.codes)
    for text in (
        json.dumps(receipt_document_to_json(receipt)),
        render_receipt_human(receipt, markdown=True),
        render_receipt_human(receipt, markdown=False),
    ):
        assert "an edit FinishUP could not place" in text
        assert "A recorded input changed after" not in text
        assert "A recorded verification input changed after" not in text


def test_a_declared_directory_input_makes_the_declaration_partial_and_asks() -> None:
    """``src/`` names a directory: an edit inside it is never set aside (#1167 review finding 5)."""

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = ledger.passes("pytest -q")
    manifest(ledger, run, inputs=("src/", "tests/"))
    changed(ledger, "src/app.py")
    (row,) = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert (row.state, row.basis) == ("unknown", "declared")
    assert not row.caller_asserted
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_rerun_question" in facts.codes
    assert "verification_inputs_caller_asserted" not in facts.codes


def test_reliance_on_a_complete_declaration_is_disclosed_for_a_cited_earlier_run() -> None:
    """The run a claim cites need not be the latest one (#1167 review finding 6)."""

    ledger = ObservedLedger()
    run = ledger.run(
        "pytest -q tests/test_a.py", ResultOutcome.SUCCESS, exit_status=0, runner="test"
    )
    manifest(ledger, run, inputs=("tests/test_a.py",))
    changed(ledger, "src/app.py")
    ledger.run("ruff check docs/", ResultOutcome.SUCCESS, exit_status=0, runner="lint")
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000001168"),
            ClaimKind.COMPLETION,
            "The change is complete and verified.",
            (run,),
        ),
        observed=False,
    )
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.run_ref, row.state, row.caller_asserted) for row in rows] == [
        (run, "current", True)
    ]
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert "verification_inputs_caller_asserted" in facts.codes


def test_one_verifications_outside_input_keeps_the_no_op_proof_for_the_others() -> None:
    """The byte-identical proof is withdrawn only for runs with an unseen input (finding 8)."""

    ledger = ObservedLedger()
    obligation_with(ledger, 1, _COMMAND)
    obligation_with(
        ledger,
        2,
        (RequestedItemKind.COMMAND, "make lint", None),
        (RequestedItemKind.FILE, "/outside/lint.toml", RequestedItemRole.INPUT),
    )
    ledger.passes("pytest -q")
    lint = ledger.passes("make lint")
    ledger.run(
        "cat saved.json > evidence.json",
        ResultOutcome.SUCCESS,
        write_scope="workspace",
        workspace_effect="unchanged",
    )
    rows = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert [(row.run_ref, row.state) for row in rows] == [(lint, "stale")]
    assert rows[0].changes == (
        "1 later rewrite(s) left the compared workspace unchanged, but a verification input lies"
        " outside what the comparison covers; FinishUP cannot tell whether that touched this"
        " verification's inputs",
    )


def test_the_review_packet_carries_freshness_detail_without_names() -> None:
    """Requested commands and changed paths never leave as finding prose (#1167 review, 10).

    The local finding names them for the agent; the review packet's finding detail counts them,
    so they reach the reviewer only through the obligation and evidence items' own categories.
    """

    from finishup.application.check import _freshness_candidates, allocate_findings
    from finishup.application.semantic_case import build_semantic_case
    from finishup.domain.privacy import ReviewContextProfile, ReviewSelectionPolicy
    from finishup.protocol.ids import IdKind, new_id

    class _Ids:
        def new(self, kind: IdKind) -> str:
            return new_id(kind)

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    manifest(ledger, ledger.passes("pytest -q"), complete=False, inputs=("src/control.py",))
    changed(ledger, "src/control.py")
    case = replace(case_for(ledger), verification_advisory=True)
    assessments, _ = run_deterministic_policies(case, CheckScope((), ()), ("work-integrity/0.3.0",))
    findings = allocate_findings(_Ids(), _freshness_candidates(assessments, case))
    question = next(f for f in findings if f.summary.startswith("Is a verification rerun"))
    assert '"src/control.py"' in question.detail and '"pytest -q"' in question.detail
    profile = ReviewContextProfile.EXPANDED
    semantic = build_semantic_case(
        case_id="cas_10000000-0000-4000-8000-000000001167",
        frozen_case=case,
        dependency_digest="sha256:" + "b" * 64,
        findings=findings,
        review_context_profile=profile,
        review_selection=ReviewSelectionPolicy.for_profile(profile),
        policy_id="pvy_10000000-0000-4000-8000-000000000001",
        policy_version="1",
    )
    (detail,) = (
        item
        for item in semantic.items
        if item.section == "deterministic_detail" and item.source_ref == str(question.finding_id)
    )
    text = detail.content.decode("utf-8")
    assert "src/control.py" not in text and "pytest -q" not in text
    assert "1 named change(s) withheld here" in text


def _cite(ledger: ObservedLedger, *refs: str) -> None:
    ledger.append(
        EventSchema("claim_recorded", "1.0.0"),
        ClaimRecordedPayload(
            claim_id("clm_00000000-0000-4000-8000-000000002167"),
            ClaimKind.COMPLETION,
            "The change is complete and verified.",
            tuple(sorted(refs)),  # pyright: ignore[reportArgumentType]
        ),
        observed=False,
    )


@pytest.mark.parametrize(
    "history",
    [
        "own_write",
        "own_output_rewritten_complete",
        "own_output_rewritten_partial",
        "two_runs_write_the_output",
        "no_op_beside_another_runs_outside_input",
        "untracked_run_own_write",
    ],
)
def test_a_claim_citing_a_current_verification_is_corroborated(history: str) -> None:
    """The claim rule judges a cited run exactly as the task facts do (#1167 review, round 2).

    A verification whose own outputs, or a byte-identical rewrite, followed it is current in the
    task facts, so a completion claim citing it is corroborated; a run's own write is never a
    later edit against itself, whether or not freshness tracks the run.
    """

    from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings

    ledger = ObservedLedger()
    cited: list[str] = []
    if history == "no_op_beside_another_runs_outside_input":
        obligation_with(ledger, 1, _COMMAND)
        obligation_with(
            ledger,
            2,
            (RequestedItemKind.COMMAND, "make lint", None),
            (RequestedItemKind.FILE, "/outside/lint.toml", RequestedItemRole.INPUT),
        )
        cited.append(ledger.passes("pytest -q"))
        ledger.run(
            "cat saved.json > evidence.json",
            ResultOutcome.SUCCESS,
            write_scope="workspace",
            workspace_effect="unchanged",
        )
    elif history == "untracked_run_own_write":
        cited.append(
            ledger.run(
                "python check_solution.py",
                ResultOutcome.SUCCESS,
                exit_status=0,
                runner="other",
                workspace_effect="changed",
                workspace_write_scopes=("workspace",),
                workspace_changed_entries=(workspace_path_identity(INSTALLATION_KEY, "out.json"),),
            )
        )
    else:
        run = producing_run(ledger, "pytest -q", "evidence.json")
        cited.append(run)
        if history != "own_write":
            manifest(
                ledger, run, complete=history != "own_output_rewritten_partial", inputs=("app.py",)
            )
        if history == "two_runs_write_the_output":
            second = producing_run(ledger, "pytest -q tests/test_b.py", "evidence.json")
            manifest(ledger, second, inputs=("app.py",))
            cited.append(second)
        elif history != "own_write":
            changed(ledger, "evidence.json")
    _cite(ledger, *cited)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert not {
        "planned_verification_stale",
        "edited_after_last_verification",
        "verification_rerun_question",
    } & set(facts.codes)
    assert not _uncorroborated_completion_findings(case_for(ledger))


def test_a_claim_citing_a_stale_verification_is_still_uncorroborated() -> None:
    """The same rule still rejects a cited run a recorded input change made stale."""

    from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings

    ledger = ObservedLedger()
    run = producing_run(ledger, "pytest -q", "evidence.json")
    manifest(ledger, run, inputs=("app.py",))
    changed(ledger, "app.py")
    _cite(ledger, run)
    assert (
        "edited_after_last_verification"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    assert len(_uncorroborated_completion_findings(case_for(ledger))) == 1


def test_a_declared_output_directory_covers_the_runs_own_named_writes() -> None:
    """``reports/`` covers a file the run wrote there once the record names it (#1167 review).

    The agent's evidence reference names ``reports/x.json``; the run's own trusted comparison
    wrote it, so its later rewrite is quiet and the list stays complete.
    """

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    run = producing_run(ledger, "pytest -q", "reports/x.json")
    manifest(ledger, run, inputs=("src/app.py",), outputs=("reports/",))
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id("evd_00000000-0000-4000-8000-000000002168"),
            EvidenceKind.OTHER,
            EvidenceImmutability.METADATA_ONLY,
            timestamp_from_string("2026-10-21T12:00:00.000Z"),
            reference="reports/x.json",
            description="Verifier report",
        ),
        observed=False,
    )
    changed(ledger, "reports/x.json")
    assert not verification_freshness(replay(ledger.prefix), ledger.prefix)
    facts = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert not {
        "planned_verification_stale",
        "edited_after_last_verification",
        "verification_rerun_question",
        "verification_inputs_caller_asserted",
    } & set(facts.codes)


@pytest.mark.parametrize("output", ["reports/", "./"])
def test_an_output_directory_never_covers_an_unplaced_own_write(output: str) -> None:
    """A ``--fix`` run rewrote a source FinishUP cannot name (#1167 final check, finding 1).

    Its location is unknown, so neither ``reports/`` nor the workspace root covers it: a later
    change to it asks the input-aware question instead of passing silently.
    """

    ledger = ObservedLedger()
    run = ledger.run(
        "ruff check --fix src",
        ResultOutcome.SUCCESS,
        exit_status=0,
        runner="lint",
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
        workspace_changed_entries=tuple(
            sorted(
                workspace_path_identity(INSTALLATION_KEY, path)
                for path in ("src/app.py", "reports/x.json")
            )
        ),
    )
    manifest(ledger, run, complete=False, inputs=("pyproject.toml",), outputs=(output,))
    changed(ledger, "src/app.py")
    (row,) = verification_freshness(replay(ledger.prefix), ledger.prefix)
    assert (row.state, row.basis) == ("unknown", "declared")
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


_COVERAGE_QUOTE = "Every prediction must meet the bound"


def _coverage_run(
    ledger: ObservedLedger,
    *,
    command: str = "pytest -q",
    produced: str | None = None,
    observed: bool = True,
    runner: str = "test",
    failing: int = 0,
    cases: int = 7,
) -> ResultId:
    action = ledger.begin(command, observed=observed, runner=runner)
    ref = result_id(str(action).replace("act_", "res_"))
    ledger.append(
        EventSchema("result_recorded", "1.1.0"),
        ResultRecordedPayload(
            ref,
            action,
            ResultOutcome.FAILURE if failing else ResultOutcome.SUCCESS,
            exit_status=1 if failing else 0,
            summary=result_summary_with_workspace_effect(
                "Observed result",
                "changed" if produced else "unchanged",
                ("workspace",),
                (workspace_path_identity(INSTALLATION_KEY, produced),) if produced else (),
            ),
            verification=ResultVerification(
                _COVERAGE_QUOTE, VerificationDataSource.TASK_PUBLIC, cases, failing, "worst", True
            ),
        ),
        observed=observed,
    )
    return ref


@pytest.mark.parametrize(
    ("change", "expected"),
    [
        ("none", "current"),
        ("input", "stale"),
        ("disjoint", "current"),
        ("output", "current"),
        ("noop", "current"),
        ("undeclared", "unknown"),
        ("outside", "unknown"),
        ("directory", "unknown"),
        ("unplaced", "stale"),
        ("unavailable", "stale"),
    ],
)
def test_coverage_uses_the_same_per_run_freshness_live_and_frozen(
    change: str, expected: str
) -> None:
    ledger = ObservedLedger()
    run = _coverage_run(ledger, produced="evidence.json" if change == "output" else None)
    if change != "undeclared":
        manifest(
            ledger,
            run,
            inputs=("/outside/input.json",)
            if change == "outside"
            else ("src/",)
            if change == "directory"
            else ("src/control.py",),
            complete=change != "output",
        )
    if change == "noop":
        ledger.run(
            "cat saved.json > evidence.json",
            ResultOutcome.SUCCESS,
            write_scope="workspace",
            workspace_effect="unchanged",
        )
    elif change == "unplaced":
        ledger.edit()
    elif change == "unavailable":
        ledger.run("python update.py", ResultOutcome.SUCCESS, workspace_effect="unavailable")
    elif change != "none":
        changed(
            ledger,
            "src/control.py"
            if change == "input"
            else "evidence.json"
            if change == "output"
            else "other.py",
        )
    case = deterministic_case_from_json(deterministic_case_to_json(case_for(ledger)))
    live = build_verification_coverage(
        case.projection, ledger.prefix, task_statement=_COVERAGE_QUOTE
    )
    frozen = build_verification_coverage(
        case.projection,
        task_statement=_COVERAGE_QUOTE,
        unchanged_action_ids=case.verification_unchanged_action_ids,
        workspace_verification_edit_frontier=case.workspace_verification_edit_frontier,
        freshness=case.verification_freshness,
        tracked_runs=case.verification_tracked_runs,
    )
    assert live == frozen
    row = live.criteria[0]
    witness = row.witnesses[0]
    assert (witness.result_id, witness.freshness, witness.stale) == (
        run,
        expected,
        expected == "stale",
    )
    assert ("stale" in row.flags) is (expected == "stale")
    assert witness.tuned_on_these_cases is True and witness.data_source == "task_public"
    assert {"public_only", "own_or_tuned_only"} <= set(row.flags)
    assert f"freshness={expected}" in "\n".join(verification_coverage_lines(live))
    # Replaying an old frozen case has no new judgment, even beside current live records.
    legacy = build_verification_coverage(
        case.projection,
        task_statement=_COVERAGE_QUOTE,
        unchanged_action_ids=case.verification_unchanged_action_ids,
        workspace_verification_edit_frontier=case.workspace_verification_edit_frontier,
        freshness=None,
        tracked_runs=(),
    )
    assert legacy.criteria[0].witnesses[0].freshness == "legacy"
    assert "legacy latest-edit candidate" in "\n".join(verification_coverage_lines(legacy))


@pytest.mark.parametrize("citation", ["none", "result", "evidence"])
def test_tracked_set_is_exactly_the_retained_runs_not_omitted_older_duplicates(
    citation: str,
) -> None:
    ledger = ObservedLedger()
    evidence = evidence_id("evd_00000000-0000-4000-8000-000000009994")
    old = _coverage_run(ledger, failing=2)
    manifest(ledger, old)
    changed(ledger, "src/control.py")
    latest = _coverage_run(ledger, cases=3)
    projection = replay(ledger.prefix)
    row = projection.results[old]
    assert row.payload is not None
    refs = {
        "result": old,
        "evidence": evidence,
    }
    if citation != "none":
        _cite(ledger, refs[citation])
        projection = replay(ledger.prefix)
    if citation == "evidence":
        # Exercise the existing attached-evidence citation path on the pure projection;
        # ObservedLedger's envelope builder intentionally has no result-evidence parameter.
        payload = replace(row.payload, evidence_refs=(evidence,))
        projection = replace(
            projection,
            results={
                **projection.results,
                old: replace(
                    row, payload=payload, payload_digest=canonical_digest(encode_payload(payload))
                ),
            },
        )
    tracked = verification_tracked_runs(projection, ledger.prefix)
    rows = verification_freshness(projection, ledger.prefix)
    assert set(tracked) == ({latest} if citation == "none" else {old, latest})
    assert {item.run_ref for item in rows} == (set() if citation == "none" else {old})
    view = build_verification_coverage(projection, ledger.prefix, task_statement=_COVERAGE_QUOTE)
    # Different case counts/provenance cannot supersede failures. The omitted old failure is
    # still shown, but absent judgment is legacy, never a claim it is current.
    witness = next(item for item in view.criteria[0].witnesses if item.result_id == old)
    assert witness.failing == 2
    assert witness.freshness == ("legacy" if citation == "none" else "stale")
    # Base cases persisted every eligible result, including the unjudged duplicate. Do not
    # interpret that overinclusive inventory as a current verdict when replaying its packet.
    frozen = build_verification_coverage(
        projection,
        task_statement=_COVERAGE_QUOTE,
        freshness=rows,
        tracked_runs=tuple(sorted((old, latest))),
        workspace_verification_edit_frontier=5,
    )
    frozen_witness = next(item for item in frozen.criteria[0].witnesses if item.result_id == old)
    assert frozen_witness.freshness == witness.freshness


def test_retention_uses_first_result_position_and_does_not_let_a_late_correction_win() -> None:
    ledger = ObservedLedger()
    action = ledger.begin("pytest -q", runner="test")
    # A different invocation starts later but finishes first. Result order, not action order,
    # controls the latest retained run, matching the freshness engine's existing predicate.
    earlier_result = ledger.passes("pytest -q")
    later_result = ledger.end(action, ResultOutcome.UNKNOWN)
    assert verification_tracked_runs(replay(ledger.prefix), ledger.prefix) == (later_result,)
    changed(ledger, "config.json")
    newest_run = ledger.passes("pytest -q")
    correction = ledger.correct_outcome(later_result, ResultOutcome.SUCCESS, exit_status=0)
    projection = replay(ledger.prefix)
    assert earlier_result != later_result != newest_run
    assert verification_tracked_runs(projection, ledger.prefix) == (newest_run,)
    _cite(ledger, correction)
    projection = replay(ledger.prefix)
    assert set(verification_tracked_runs(projection, ledger.prefix)) == {newest_run, correction}
    assert [
        (row.run_ref, row.state) for row in verification_freshness(projection, ledger.prefix)
    ] == [(correction, "unknown")]


@pytest.mark.parametrize(
    "kind", ["unobserved", "untracked", "unreadable_result", "unreadable_action", "pending"]
)
def test_no_current_verdict_for_unjudged_runs(kind: str) -> None:
    ledger = ObservedLedger()
    run = _coverage_run(
        ledger, observed=kind != "unobserved", runner="other" if kind == "untracked" else "test"
    )
    changed(ledger, "src/control.py")
    projection = replay(ledger.prefix)
    row = projection.results[run]
    assert row.payload is not None
    if kind == "unreadable_result":
        projection = replace(projection, results={run: replace(row, payload=None, redacted=True)})
    elif kind == "unreadable_action":
        ref = row.payload.action_id
        projection = replace(
            projection,
            actions={
                **projection.actions,
                ref: replace(projection.actions[ref], payload=None, redacted=True),
            },
        )
    elif kind == "pending":
        projection = replace(
            projection,
            results={ref: value for ref, value in projection.results.items() if ref != run},
        )
    assert run not in verification_tracked_runs(projection, ledger.prefix)
    assert not verification_freshness(projection, ledger.prefix)
    view = build_verification_coverage(projection, ledger.prefix, task_statement=_COVERAGE_QUOTE)
    assert all(witness.freshness == "legacy" for row in view.criteria for witness in row.witnesses)


def test_coverage_display_cap_cannot_shrink_closure_freshness() -> None:
    from finishup.kernel.policies.work_integrity import _uncorroborated_completion_findings

    ledger = ObservedLedger()
    runs = [
        _coverage_run(ledger, command=f"pytest tests/test_{number}.py", failing=1)
        for number in range(5)
    ]
    for run in runs:
        manifest(ledger, run)
    changed(ledger, "src/control.py")
    _cite(ledger, runs[0])
    case = case_for(ledger)
    view = build_verification_coverage(
        case.projection, ledger.prefix, task_statement=_COVERAGE_QUOTE
    )
    row = view.criteria[0]
    assert len(row.witnesses) == 3 and row.omitted_witnesses == 2
    assert row.unresolved_failing_runs == 5
    assert runs[0] not in {witness.result_id for witness in row.witnesses}
    assert len(case.verification_tracked_runs) == len(case.verification_freshness or ()) == 5
    assert _uncorroborated_completion_findings(case)


def test_a_fresh_failure_keeps_source_tuning_and_failed_case_visibility() -> None:
    ledger = ObservedLedger()
    run = _coverage_run(ledger, failing=2)
    view = build_verification_coverage(
        replay(ledger.prefix), ledger.prefix, task_statement=_COVERAGE_QUOTE
    )
    row = view.criteria[0]
    witness = row.witnesses[0]
    assert (witness.result_id, witness.freshness, witness.stale) == (run, "current", False)
    assert (witness.data_source, witness.tuned_on_these_cases, witness.worst) == (
        "task_public",
        True,
        "worst",
    )
    assert row.unresolved_failing_runs == 1 and "failing_cases" in row.flags
