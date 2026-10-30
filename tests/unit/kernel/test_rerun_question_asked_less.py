"""#1241 D9/D10: the rerun question is asked less, never counted as work, and its answer shows."""

# pyright: reportPrivateUsage=false

from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger, observed_receipt
from finishup.domain.events import ActionKind, ActionRecordedPayload, EventSchema, ResultOutcome
from finishup.domain.findings import Finding, ResponseDisposition
from finishup.domain.freshness_question import (
    FRESHNESS_QUESTION_SUMMARY,
    bounded_agent_reason,
    is_freshness_question,
)
from finishup.domain.receipts import ReceiptSectionKey
from finishup.domain.values import action_id, finding_id
from finishup.domain.workspace_effect import workspace_path_identity
from finishup.kernel.deterministic_checks import (
    CaseAvailabilityFacts,
    build_deterministic_case,
    deterministic_case_from_json,
    deterministic_case_to_json,
)
from finishup.kernel.policies.work_integrity import _verification_questions
from finishup.kernel.projections import unanswered_finding_ids
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    PLANNED_VERIFICATION_AGENT_LINKED_GAP,
    register_command_identity_key,
    task_fact_signals,
)
from finishup.protocol.coverage import (
    ArtifactObservation,
    AuthorshipAssurance,
    CheckType,
    Coverage,
    EvidenceImmutability,
    LedgerFreshness,
    PublicationChannel,
)

_REASON = (
    "Rerun not needed: the shell write only regenerated   the coverage report;\n"
    "the tested sources and configuration are unchanged."
)
# The receipt helper records no check; a question recorded for it carries the receipt's coverage.
_RECEIPT_COVERAGE = Coverage(
    publication_channels=(PublicationChannel.ENGINE_DERIVED,),
    authorship_assurance=AuthorshipAssurance.SERVICE_AUTHENTICATED,
    artifact_observation=ArtifactObservation.PUBLISHED_ONLY,
    evidence_immutability=EvidenceImmutability.METADATA_ONLY,
    ledger_freshness=LedgerFreshness.PARTIAL,
    check_types=(CheckType.NONE,),
    known_gaps=("check_not_recorded",),
)


@pytest.fixture(autouse=True)
def key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _placed_change(ledger: ObservedLedger, path: str) -> None:
    ledger.run(
        "python update.py",
        ResultOutcome.SUCCESS,
        runner="other",
        workspace_effect="changed",
        workspace_write_scopes=("workspace",),
        workspace_changed_entries=(workspace_path_identity(INSTALLATION_KEY, path),),
    )


def _case(ledger: ObservedLedger, *, advisory: bool = False):
    case = build_deterministic_case(replay(ledger.prefix), ledger.prefix, CaseAvailabilityFacts())
    return replace(case, verification_advisory=advisory) if advisory else case


def _record_question(
    ledger: ObservedLedger, number: int, *, coverage: Coverage | None = None
) -> Finding:
    candidate = _verification_questions(_case(ledger))[0].candidate
    finding = Finding(
        finding_id(f"fnd_00000000-0000-4000-8000-{number:012d}"),
        candidate.kind,
        candidate.origin,
        candidate.priority,
        candidate.summary,
        candidate.detail,
        candidate.subject_refs,
        candidate.policy_id,
        candidate.policy_version,
        candidate.subject_frontier,
        candidate.coverage if coverage is None else coverage,
        candidate.provenance,
    )
    ledger.append(EventSchema("finding_recorded", "1.0.0"), finding, observed=False)
    return finding


def test_only_the_latest_run_of_each_planned_verification_is_asked_about() -> None:
    """Matching command text no longer decides it: an older, superseded tool run is not asked."""

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("ruff check .")
    ledger.passes("pytest -q")
    _placed_change(ledger, "notes/scratch.txt")
    questions = _verification_questions(_case(ledger))
    # Before #1241 the ruff run (the latest of its own command) was asked about too.
    assert len(questions) == 1
    ruff_events = {
        str(row.source_event_id)
        for row in replay(ledger.prefix).results.values()
        if row.payload is not None and "ruff" in (row.payload.summary or "")
    }
    assert not ruff_events & set(questions[0].candidate.subject_refs)


def test_an_older_run_is_not_asked_about_when_the_latest_verification_is_current() -> None:
    """D9: "latest" is the latest verification overall, not the latest run with later changes.

    An unrequested, uncited test run followed by a change and then a lint run with nothing after
    it: the latest verification is current, so nothing is asked, as the task facts agree.
    """

    ledger = ObservedLedger()
    ledger.passes("pytest -q")
    _placed_change(ledger, "notes/scratch.txt")
    ledger.passes("ruff check .")
    assert not _verification_questions(_case(ledger))
    assert (
        "verification_rerun_question"
        not in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    # The latest verification with a later change is still asked about.
    _placed_change(ledger, "notes/other.txt")
    assert len(_verification_questions(_case(ledger))) == 1


def _linked_ledger() -> tuple[ObservedLedger, str]:
    """A planned ``pytest -q`` the agent ran through a script and linked to the command (#1209).

    The linked run decides the planned verification like a direct match (ADR-033), a later change
    may touch its inputs, and a later lint run, current, is the latest verification overall. The
    linked run matches no requested command (no freshness label) and no claim cites it. Returns
    the ledger and the linked run's result event.
    """

    ledger = ObservedLedger()
    obligation = ledger.plan("pytest -q")
    linked = ledger.run("bash ci/suite.sh", ResultOutcome.SUCCESS, exit_status=0, runner="other")
    observed_action, result_event = ledger.events_of(linked)
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000b001"),
            ActionKind.COMMAND,
            "Ran the planned suite through the CI script",
            command="pytest -q",
            obligation_refs=(obligation,),
            attempted_items=("pytest -q",),
        ),
        observed=False,
        causal_parents=(observed_action,),
    )
    _placed_change(ledger, "notes/scratch.txt")
    ledger.passes("ruff check .")
    return ledger, str(result_event)


def test_an_agent_linked_run_is_asked_about_and_its_answer_clears_the_marker() -> None:
    """#1241 D9 x #1209: the obligation's rerun marker always has a question an answer clears.

    A run the agent linked to a planned command is the agent's account citing it, so it is asked
    about. Before, the obligation-level ``verification_rerun_question`` stood for that run while no
    question was asked, so no answer could ever clear it.
    """

    ledger, linked_event = _linked_ledger()
    signals = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    assert PLANNED_VERIFICATION_AGENT_LINKED_GAP in signals.codes
    assert ("verification_rerun_question", None) not in signals.markers
    assert any(code == "verification_rerun_question" for code, _ in signals.markers)
    case = _case(ledger)
    (question,) = _verification_questions(case)
    assert linked_event in question.candidate.subject_refs
    # Frozen with the case, so a recovered check asks the same question.
    restored = deterministic_case_from_json(deterministic_case_to_json(case))
    assert restored == case and restored.verification_linked_runs
    assert _verification_questions(restored) == [question]
    recorded = _record_question(ledger, 1244)
    ledger.respond(recorded.finding_id, ResponseDisposition.ACKNOWLEDGED, reason=_REASON)
    assert not _verification_questions(_case(ledger))
    assert (
        "verification_rerun_question"
        not in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def _rerun_markers(ledger: ObservedLedger) -> set[tuple[str, str | None]]:
    signals = task_fact_signals(replay(ledger.prefix), ledger.prefix)
    return {marker for marker in signals.markers if marker[0] == "verification_rerun_question"}


def test_the_latest_verification_the_task_wide_marker_reads_is_asked_about() -> None:
    """#1241 D9: "the latest verification overall" is the run the task-wide marker reads.

    An unrequested test run goes unknown after a change, then the agent runs the planned command
    through a script and links it (#1209). The linked run is not a verification-class run, so the
    task facts' latest verification stays the test run and its task-wide marker stands. Before,
    the question set took the latest tracked run (the linked one, current) as the latest overall
    and asked nothing, so no answer could clear that marker.
    """

    ledger = ObservedLedger()
    obligation = ledger.plan("make verify")
    tested = ledger.passes("pytest -q")
    _placed_change(ledger, "notes/scratch.txt")
    linked = ledger.run("bash ci/suite.sh", ResultOutcome.SUCCESS, exit_status=0, runner="other")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000b002"),
            ActionKind.COMMAND,
            "Ran the planned check through the CI script",
            command="make verify",
            obligation_refs=(obligation,),
            attempted_items=("make verify",),
        ),
        observed=False,
        causal_parents=(ledger.events_of(linked)[0],),
    )
    assert _rerun_markers(ledger) == {("verification_rerun_question", None)}
    (question,) = _verification_questions(_case(ledger))
    assert str(ledger.events_of(tested)[1]) in question.candidate.subject_refs
    recorded = _record_question(ledger, 1245)
    ledger.respond(recorded.finding_id, ResponseDisposition.ACKNOWLEDGED, reason=_REASON)
    assert not _verification_questions(_case(ledger))
    assert not _rerun_markers(ledger)


def test_a_run_matching_two_requested_commands_is_asked_about_for_both() -> None:
    """#1241 D9: the latest run of each requested command is asked about, not of its first label.

    One run matches both requested commands (``pytest -q -x`` is a ``pytest -q`` run too) and
    takes only the first as its freshness label. A later ``pytest -q tests/`` run is the latest
    of that label, so the first run was never the latest of any label, yet it decides the
    ``pytest -q -x`` item and the obligation's marker reads it: before, the answer covered only
    the later run and the marker stood with no question left to answer.
    """

    ledger = ObservedLedger()
    obligation = ledger.plan("pytest -q", "pytest -q -x")
    both = ledger.passes("pytest -q -x")
    later = ledger.passes("pytest -q tests/")
    _placed_change(ledger, "notes/scratch.txt")
    assert ("verification_rerun_question", obligation) in _rerun_markers(ledger)
    case = _case(ledger)
    assert case.verification_freshness is not None
    labels = {row.run_ref: row.label for row in case.verification_freshness}
    assert labels == {both: "pytest -q", later: "pytest -q"}
    (question,) = _verification_questions(case)
    for run in (both, later):
        assert str(ledger.events_of(run)[1]) in question.candidate.subject_refs
    recorded = _record_question(ledger, 1246)
    ledger.respond(recorded.finding_id, ResponseDisposition.ACKNOWLEDGED, reason=_REASON)
    assert not _verification_questions(_case(ledger))
    assert not _rerun_markers(ledger)


def test_runs_that_share_one_change_set_share_one_question() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q", "mypy src")
    ledger.passes("pytest -q")
    ledger.passes("mypy src")
    _placed_change(ledger, "build/report.txt")
    questions = _verification_questions(_case(ledger))
    assert len(questions) == 1
    assert questions[0].candidate.summary == FRESHNESS_QUESTION_SUMMARY


def test_the_question_is_never_unanswered_work_and_an_answer_stands_until_a_new_change() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    _placed_change(ledger, "build/report.txt")
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    question = _record_question(ledger, 1241)
    assert is_freshness_question(question)
    # D10: visible, answerable, never counted as unanswered work (check never counted it).
    assert question.finding_id not in unanswered_finding_ids(replay(ledger.prefix), ledger.prefix)
    ledger.respond(question.finding_id, ResponseDisposition.ACKNOWLEDGED, reason=_REASON)
    projection = replay(ledger.prefix)
    assert not _verification_questions(_case(ledger))
    # The reasoned answer replaces the standing marker.
    assert "verification_rerun_question" not in task_fact_signals(projection, ledger.prefix).codes
    # A change the answer did not cover asks again, once.
    _placed_change(ledger, "src/app.py")
    assert len(_verification_questions(_case(ledger))) == 1
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )


def test_the_receipt_shows_the_agents_bounded_reason_in_place_of_the_question() -> None:
    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    _placed_change(ledger, "build/report.txt")
    question = _record_question(ledger, 1242, coverage=_RECEIPT_COVERAGE)
    ledger.respond(question.finding_id, ResponseDisposition.ACKNOWLEDGED, reason=_REASON)
    after = observed_receipt(ledger)
    section = next(
        section
        for section in after.sections
        if section.key is ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS
    )
    expected = (
        "Verification rerun question answered (self-reported, non-blocking) "
        f"{question.finding_id}: rerun not needed: {bounded_agent_reason(_REASON)}"
    )
    assert expected in section.items
    assert "\n" not in bounded_agent_reason(_REASON) and "   " not in bounded_agent_reason(_REASON)


def test_a_rejected_question_is_not_shown_as_answered_on_the_receipt() -> None:
    """Only the answer that settles the question reads as one: a rejection does not (#1143).

    The kernel still asks and keeps the standing marker, so the receipt must not also say the
    question was answered and a rerun is not needed.
    """

    ledger = ObservedLedger()
    ledger.plan("pytest -q")
    ledger.passes("pytest -q")
    _placed_change(ledger, "build/report.txt")
    question = _record_question(ledger, 1243, coverage=_RECEIPT_COVERAGE)
    ledger.respond(question.finding_id, ResponseDisposition.REJECTED, reason=_REASON)
    assert _verification_questions(_case(ledger))
    assert (
        "verification_rerun_question"
        in task_fact_signals(replay(ledger.prefix), ledger.prefix).codes
    )
    section = next(
        section
        for section in observed_receipt(ledger).sections
        if section.key is ReceiptSectionKey.FINDINGS_AND_DISPOSITIONS
    )
    assert not any(
        item.startswith("Verification rerun question answered") for item in section.items
    )


def test_a_long_reason_is_bounded_to_one_line() -> None:
    reason = bounded_agent_reason("word " * 200)
    assert len(reason.encode("utf-8")) <= 240 and reason.endswith("...")
    assert bounded_agent_reason("é" * 300).endswith("...")
