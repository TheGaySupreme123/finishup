"""What a reviewer challenge is about, decided from recorded facts (issues #1042 and #1043).

Each case replays a hook-observed ledger the way the observation coordinator writes it
(``builders.observed_runs``) and asks the pure predicates of ``kernel.review_frame``. The tb4n4
shapes: an ``action_without_result`` about the in-flight ``check`` call (FinishUP's own capture), and
interleaved-vigenere S, where the agent's own oversized stress run failed while the task's sample
verification passed.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from finishup.domain.findings import FindingKind
from finishup.domain.values import EventId, ObligationId, ResultId, action_id, obligation_id
from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
from finishup.kernel.observed_failures import (
    observed_action_description,
    observed_event_ids_from_records,
)
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.review_frame import (
    PLANNED_VERIFICATION_DOUBT_GAPS,
    agent_probe_only,
    finishup_process_state_only,
    local_rule_owned,
)
from finishup.kernel.task_facts import agent_linked_run_events, register_command_identity_key

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_SAMPLE = "python3 solve.py --check sample_input.txt"
_STRESS = "python3 stress.py --streams 12 --seed-lengths 9-32"


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _obligation(
    ledger: ObservedLedger,
    obligation: ObligationId = _OBLIGATION,
    *,
    command: str | None = None,
    status: ObligationStatus = ObligationStatus.OPEN,
) -> None:
    items = () if command is None else (RequestedItem(RequestedItemKind.COMMAND, command),)
    ledger.append(
        EventSchema("obligation_published", "1.0.0"),
        ObligationPublishedPayload(
            obligation_id=obligation,
            description="Decrypt the interleaved streams",
            evidence_expectation="The sample decrypts",
            status=status,
            requested_items=items,
            resolution_evidence_refs=(),
        ),
        observed=False,
    )


def _plan(ledger: ObservedLedger, *obligations: ObligationId) -> None:
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", tuple(sorted(obligations))),
        observed=False,
    )


def _state(ledger: ObservedLedger) -> tuple[ProjectionState, frozenset[EventId]]:
    prefix = ledger.prefix
    return replay(prefix), observed_event_ids_from_records(prefix)


def _result_event(state: ProjectionState, result: ResultId) -> str:
    return str(state.results[result].source_event_id)


def _case_gaps(ledger: ObservedLedger) -> frozenset[str]:
    prefix = ledger.prefix
    case = build_deterministic_case(replay(prefix), prefix, CaseAvailabilityFacts())
    return frozenset(gap.code for gap in case.gaps)


# --- FinishUP's own capture and process state (#1042 item 2) ---------------------------------------


def test_an_action_without_result_about_the_check_in_flight_is_finishup_state() -> None:
    """tb4n4: the reviewer saw the ``check`` call's own pre-tool observation (its result is
    recorded after the check freezes) and raised ``action_without_result`` on it."""

    ledger = ObservedLedger()
    check_call = action_id("act_00000000-0000-4000-8000-000000000101")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            check_call,
            ActionKind.OTHER,
            observed_action_description("Observed other via Codex hook", "mcp__finishup__check"),
        ),
        observed=True,
    )
    state, observed = _state(ledger)
    event = str(state.actions[check_call].source_event_id)

    for kind in (FindingKind.ACTION_WITHOUT_RESULT, FindingKind.LEDGER_STALE_OR_INCOMPLETE):
        assert finishup_process_state_only(state, kind, (event,), observed) is True


def test_an_observed_call_without_a_result_is_capture_state_only_for_that_kind() -> None:
    ledger = ObservedLedger()
    pending = action_id("act_00000000-0000-4000-8000-000000000102")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            pending,
            ActionKind.COMMAND,
            observed_action_description("Observed command via Codex hook", "exec_command"),
            command="omitted:structural",
        ),
        observed=True,
    )
    state, observed = _state(ledger)
    event = str(state.actions[pending].source_event_id)

    # Pairing a hook observation with its result is FinishUP's capture, never the agent's account.
    assert finishup_process_state_only(state, FindingKind.ACTION_WITHOUT_RESULT, (event,), observed)
    # Any other kind about the same run is about the work.
    assert not finishup_process_state_only(
        state, FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE, (event,), observed
    )


def test_agent_published_actions_claims_and_obligations_are_never_process_state() -> None:
    """An agent-published action is never FinishUP's capture, but its pairing with a result is the
    local rule's ledger fact (tb4n5 follow-up of #1042): ``local_rule_owned``, not process state.
    Claims and obligations alone are neither."""

    ledger = ObservedLedger()
    published = action_id("act_00000000-0000-4000-8000-000000000103")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            published,
            ActionKind.COMMAND,
            # The agent may write the hook's spelling into its own description; it is not trusted.
            observed_action_description("Ran tests", "mcp__finishup__check"),
            command="pytest -q",
        ),
        observed=False,
    )
    _obligation(ledger)
    state, observed = _state(ledger)
    event = str(state.actions[published].source_event_id)

    kind = FindingKind.ACTION_WITHOUT_RESULT
    assert not finishup_process_state_only(state, kind, (event,), observed)
    assert not finishup_process_state_only(state, kind, (str(_OBLIGATION),), observed)
    assert not finishup_process_state_only(state, kind, (), observed)
    # The pairing gap of an unpaired action is the local rule's, for agent-published actions too.
    assert local_rule_owned(state, kind, (event,))
    # An obligation beside it carries a requirement or planned-verification concern: kept.
    assert not local_rule_owned(state, kind, (event, str(_OBLIGATION)))
    # The cited action is not an orphan result, so the other label proves nothing either.
    assert not local_rule_owned(state, FindingKind.RESULT_WITHOUT_ACTION, (event,))
    # An obligation or nothing names no action or result: the challenge is kept.
    assert not local_rule_owned(state, kind, (str(_OBLIGATION),))
    assert not local_rule_owned(state, kind, ())
    # Every other kind about the same action is about the work and is kept.
    for other in (
        FindingKind.FAILED_WORK_OMITTED,
        FindingKind.CLAIM_WITHOUT_ADMISSIBLE_EVIDENCE,
        FindingKind.TASK_REQUIREMENT_UNMET,
        FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED,
    ):
        assert not local_rule_owned(state, other, (event,))


def test_output_a_failed_run_cites_is_a_failure_concern_not_a_pairing_gap() -> None:
    from builders.policy_cases import record
    from finishup.domain.events import (
        EvidenceKind,
        EvidenceRecordedPayload,
        ResultOutcome,
        ResultRecordedPayload,
    )
    from finishup.domain.values import evidence_id, result_id, timestamp_from_string
    from finishup.protocol.coverage import EvidenceImmutability

    ledger = ObservedLedger()
    unpaired = action_id("act_00000000-0000-4000-8000-000000000106")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(unpaired, ActionKind.EDIT, "Rewrote the engine"),
        observed=False,
    )
    output = evidence_id("evd_00000000-0000-4000-8000-000000000107")
    ledger.append(
        EventSchema("evidence_recorded", "1.0.0"),
        EvidenceRecordedPayload(
            evidence_id=output,
            evidence_kind=EvidenceKind.COMMAND_OUTPUT,
            strength=EvidenceImmutability.METADATA_ONLY,
            observed_at=timestamp_from_string("2026-10-12T21:40:00.000Z"),
            description="Run output",
        ),
        observed=False,
    )
    state, _observed = _state(ledger)
    refs = (
        str(state.actions[unpaired].source_event_id),
        str(state.evidence[output].source_event_id),
    )
    kind = FindingKind.ACTION_WITHOUT_RESULT
    assert local_rule_owned(state, kind, refs)
    other = action_id("act_00000000-0000-4000-8000-000000000108")
    failed = ResultRecordedPayload(
        result_id("res_00000000-0000-4000-8000-000000000108"),
        other,
        ResultOutcome.FAILURE,
        evidence_refs=(output,),
    )
    with_failure = replace(state, results={failed.result_id: record(failed, state.frontier)})
    assert not local_rule_owned(with_failure, kind, refs)


def test_an_unreadable_or_unknown_subject_keeps_a_pairing_challenge() -> None:
    ledger = ObservedLedger()
    published = action_id("act_00000000-0000-4000-8000-000000000105")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(published, ActionKind.EDIT, "Rewrote the engine"),
        observed=False,
    )
    state, _observed = _state(ledger)
    event = str(state.actions[published].source_event_id)
    unknown = "evt_99999999-9999-4999-8999-999999999999"
    kind = FindingKind.ACTION_WITHOUT_RESULT
    assert not local_rule_owned(state, kind, (event, unknown))
    assert not local_rule_owned(state, kind, ("obl_99999999-9999-4999-8999-999999999999",))
    redacted = dict(state.actions)
    redacted[published] = replace(redacted[published], payload=None, redacted=True)
    assert not local_rule_owned(replace(state, actions=redacted), kind, (event,))


def test_a_real_observed_run_beside_the_check_call_keeps_the_challenge() -> None:
    ledger = ObservedLedger()
    failed = ledger.fail("pytest -q")
    check_call = action_id("act_00000000-0000-4000-8000-000000000104")
    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            check_call,
            ActionKind.OTHER,
            observed_action_description("Observed other via Codex hook", "mcp__finishup__check"),
        ),
        observed=True,
    )
    state, observed = _state(ledger)
    refs = (_result_event(state, failed), str(state.actions[check_call].source_event_id))

    assert not finishup_process_state_only(state, FindingKind.FAILED_WORK_OMITTED, refs, observed)


# --- The agent's own probe beyond the task's declared verification (#1043 item 3) ---------------


def _vigenere(*, sample_passes: bool = True) -> tuple[ObservedLedger, str, str, str]:
    """interleaved-vigenere S: the sample verification passes, the agent's stress run fails.

    Returns the ledger and the result events of the edit, the sample run and the stress run.
    """

    ledger = ObservedLedger()
    _obligation(ledger, command=_SAMPLE)
    _plan(ledger, _OBLIGATION)
    edited = ledger.edit()
    sample = ledger.passes(_SAMPLE) if sample_passes else ledger.fail(_SAMPLE)
    failed = ledger.fail(_STRESS)
    state, _observed = _state(ledger)
    return (
        ledger,
        _result_event(state, edited),
        _result_event(state, sample),
        _result_event(state, failed),
    )


def test_a_requirement_resting_only_on_the_agents_own_stress_run_is_its_own_criterion() -> None:
    ledger, _edit, _sample, stress_event = _vigenere()
    state, observed = _state(ledger)
    gaps = _case_gaps(ledger)

    assert agent_probe_only(
        state,
        FindingKind.TASK_REQUIREMENT_UNMET,
        (str(_OBLIGATION), stress_event),
        observed=observed,
        case_gap_codes=gaps,
    )
    # Only a task-requirement challenge is routed.
    assert not agent_probe_only(
        state,
        FindingKind.CODE_DEFECT,
        (stress_event,),
        observed=observed,
        case_gap_codes=gaps,
    )


def test_the_tasks_own_verification_run_is_never_the_agents_probe() -> None:
    ledger, _edit, sample, stress_event = _vigenere()
    state, observed = _state(ledger)

    for refs in ((sample,), (sample, stress_event)):
        assert not agent_probe_only(
            state,
            FindingKind.TASK_REQUIREMENT_UNMET,
            refs,
            observed=observed,
            case_gap_codes=_case_gaps(ledger),
        )


def test_a_failing_declared_verification_keeps_the_task_requirement() -> None:
    ledger, _edit, _sample, stress_event = _vigenere(sample_passes=False)
    state, observed = _state(ledger)
    gaps = _case_gaps(ledger)
    assert "planned_verification_failed" in gaps

    assert not agent_probe_only(
        state,
        FindingKind.TASK_REQUIREMENT_UNMET,
        (stress_event,),
        observed=observed,
        case_gap_codes=gaps,
    )


def test_no_declared_verification_or_no_identity_key_keeps_the_task_requirement() -> None:
    ledger = ObservedLedger()
    _obligation(ledger)
    _plan(ledger, _OBLIGATION)
    failed = ledger.fail(_STRESS)
    state, observed = _state(ledger)
    event = _result_event(state, failed)
    kind = FindingKind.TASK_REQUIREMENT_UNMET

    # The task supplied no verification FinishUP can see, so nothing says the run is beyond it.
    assert not agent_probe_only(
        state, kind, (event,), observed=observed, case_gap_codes=_case_gaps(ledger)
    )

    probe, _edit, _sample, stress_event = _vigenere()
    probe_state, probe_observed = _state(probe)
    gaps = _case_gaps(probe)
    register_command_identity_key(None)
    # Observed commands are stored only as keyed commitments: without the key, nothing matches.
    assert not agent_probe_only(
        probe_state, kind, (stress_event,), observed=probe_observed, case_gap_codes=gaps
    )


def test_an_edit_among_the_cited_work_keeps_the_task_requirement() -> None:
    ledger, edited, _sample, stress_event = _vigenere()
    state, observed = _state(ledger)
    gaps = _case_gaps(ledger)
    kind = FindingKind.TASK_REQUIREMENT_UNMET

    # The deliverable's own edit is the work, not a probe.
    assert not agent_probe_only(
        state, kind, (stress_event, edited), observed=observed, case_gap_codes=gaps
    )
    # A later edit makes the declared verification stale, so it no longer holds on the record.
    ledger.edit()
    later_state, later_observed = _state(ledger)
    later_gaps = _case_gaps(ledger)
    assert "planned_verification_stale" in later_gaps
    assert not agent_probe_only(
        later_state, kind, (stress_event,), observed=later_observed, case_gap_codes=later_gaps
    )
    # A challenge that cites no run at all rests on nothing the agent ran.
    assert not agent_probe_only(
        state, kind, (str(_OBLIGATION),), observed=observed, case_gap_codes=gaps
    )


def test_a_run_the_agent_linked_to_a_requested_command_is_the_declared_verification() -> None:
    """Review of #1043 x #1049: the task facts accept a PL6-3 link (a cooperative command action
    naming the requested value in ``attempted_items`` with the observed run as its causal parent)
    as that obligation's planned verification, so the predicate never calls that run a probe
    beyond it. Links it cannot read answer ``False``."""

    ledger = ObservedLedger()
    _obligation(ledger, command=_SAMPLE)
    _plan(ledger, _OBLIGATION)
    ledger.edit()
    alternative = ledger.passes("./run_tests.sh --all")
    ledger.passes(_SAMPLE)
    state, observed = _state(ledger)
    alternative_result = state.results[alternative].payload
    assert alternative_result is not None
    alternative_action = state.actions[alternative_result.action_id].source_event_id
    alternative_event = _result_event(state, alternative)
    kind = FindingKind.TASK_REQUIREMENT_UNMET
    # Unlinked, the run is the agent's own probe beyond the declared verification.
    assert agent_probe_only(
        state, kind, (alternative_event,), observed=observed, case_gap_codes=_case_gaps(ledger)
    )

    ledger.append(
        EventSchema("action_recorded", "1.0.0"),
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000a002"),
            ActionKind.COMMAND,
            "The full suite run is the sample check",
            command=_SAMPLE,
            attempted_items=(_SAMPLE,),
        ),
        observed=False,
        causal_parents=(alternative_action,),
    )
    state, observed = _state(ledger)
    gaps = _case_gaps(ledger)
    assert not gaps & PLANNED_VERIFICATION_DOUBT_GAPS
    links = agent_linked_run_events(state, ledger.prefix)
    assert links == frozenset({alternative_action})
    for refs in (
        (alternative_event,),
        (str(alternative_action),),
        (str(_OBLIGATION), alternative_event),
    ):
        assert not agent_probe_only(
            state, kind, refs, observed=observed, case_gap_codes=gaps, linked=links
        )
    assert not agent_probe_only(
        state, kind, (alternative_event,), observed=observed, case_gap_codes=gaps, linked=None
    )
