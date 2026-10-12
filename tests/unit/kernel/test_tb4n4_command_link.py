"""tb4n4 kv (issue #1049): an agent-linked run is a disclosed equivalence, never a mismatch.

The kv attempt declared the protocol command ``VERSION`` (a message its key-value server answers)
as a requested ``command`` item. No hook-observed shell command is ``VERSION``, so the planned
verification read ``planned_verification_not_observed``, whose own sentence tells the agent to link
the run that executed it: a cooperative ``action_recorded`` of kind ``command`` naming the exact
value in ``attempted_items`` and the observed run in ``causal_parents`` (PL6-3, ADR-033). The task
facts accept that link and disclose it; ``command_attempts`` then compared the same linked run
with ``VERSION`` and reported ``asserted_observed_mismatch``, an agent-actionable gap that also
refused every ``self_verified`` answer, and no publication could clear it. The agent looped.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
)
from yoetz.domain.values import EventId, ObligationId, ResultId, action_id, obligation_id
from yoetz.kernel.command_attempts import closure_command_gaps, command_attempts
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    PLANNED_VERIFICATION_AGENT_LINKED_GAP,
    PLANNED_VERIFICATION_NOT_OBSERVED_GAP,
    register_command_identity_key,
    task_fact_signals,
)

_OBLIGATION: ObligationId = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OBLIGATION_SCHEMA = EventSchema("obligation_published", "1.0.0")
_ACTION_SCHEMA = EventSchema("action_recorded", "1.0.0")
# What the kv agent ran to send the protocol command to the server under test.
_CLIENT_RUN = "printf 'VERSION\\n' | nc 127.0.0.1 7000"


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _obligation(
    status: ObligationStatus, resolution: tuple[ResultId, ...] = ()
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=_OBLIGATION,
        description="The server answers VERSION with its protocol version",
        evidence_expectation="An observed client exchange",
        status=status,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "VERSION"),),
        resolution_evidence_refs=resolution,
    )


def _kv_ledger(kind: ActionKind) -> tuple[ObservedLedger, ResultId]:
    """The kv shape: the obligation, the plan, the client run, the agent's link, the resolution."""

    ledger = ObservedLedger()
    ledger.append(_OBLIGATION_SCHEMA, _obligation(ObligationStatus.OPEN), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    result = ledger.passes(_CLIENT_RUN)
    observed_action: EventId = ledger.records[-2].event_id
    ledger.append(
        _ACTION_SCHEMA,
        ActionRecordedPayload(
            action_id("act_00000000-0000-4000-8000-00000000a001"),
            kind,
            "Sent VERSION to the server through the client",
            command="VERSION" if kind is ActionKind.COMMAND else None,
            attempted_items=("VERSION",),
        ),
        observed=False,
        causal_parents=(observed_action,),
    )
    ledger.append(
        _OBLIGATION_SCHEMA, _obligation(ObligationStatus.RESOLVED, (result,)), observed=False
    )
    return ledger, result


def test_the_planned_verification_reads_the_link_as_run_and_discloses_it() -> None:
    ledger, _result = _kv_ledger(ActionKind.COMMAND)
    codes = set(task_fact_signals(replay(ledger.prefix), ledger.prefix).codes)
    assert PLANNED_VERIFICATION_AGENT_LINKED_GAP in codes
    assert PLANNED_VERIFICATION_NOT_OBSERVED_GAP not in codes


def test_the_agent_linked_run_is_uncorroborated_not_a_mismatch() -> None:
    ledger, _result = _kv_ledger(ActionKind.COMMAND)
    state = replay(ledger.prefix)
    (attempt,) = command_attempts(state, ledger.prefix, _OBLIGATION)
    assert attempt.relation == "unknown"
    assert attempt.asserted_action_ids == ("act_00000000-0000-4000-8000-00000000a001",)
    # The standing disclosure, never the agent-actionable gap that refused self_verified.
    assert closure_command_gaps(state, ledger.prefix) == (
        (_OBLIGATION, "command_attempt_uncorroborated"),
    )


def test_a_non_command_assertion_of_another_run_stays_a_mismatch() -> None:
    """Only the PL6-3 link declares an equivalence; copying the value onto an edit does not."""

    ledger, _result = _kv_ledger(ActionKind.EDIT)
    state = replay(ledger.prefix)
    (attempt,) = command_attempts(state, ledger.prefix, _OBLIGATION)
    assert attempt.relation == "asserted_observed_mismatch"
    assert closure_command_gaps(state, ledger.prefix) == (
        (_OBLIGATION, "command_attempt_mismatch"),
    )
