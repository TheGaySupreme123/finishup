"""Obligation-level ``acknowledged_not_done`` (issue #997, ADR-032 slice C).

tb4n1: 31 of 38 blocker attempts named obligations, because an agent that would not finish one
obligation had no honest exit except a blocker. ``obligation_published`` 1.1.0 records that the
agent will not do it, with a reason; the obligation leaves the open work list and the receipt
discloses it as not done, never clean. A later publication reopens or resolves it.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import replace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from yoetz.domain.events import (
    OBLIGATION_SCHEMA_VERSION,
    EventSchema,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
    RequestedItem,
    RequestedItemKind,
    decode_payload,
    encode_payload,
)
from yoetz.domain.values import evidence_id, obligation_id
from yoetz.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from yoetz.kernel.reducers import replay
from yoetz.kernel.task_facts import (
    acknowledged_obligation_ids,
    open_effective_obligations,
    register_command_identity_key,
    task_fact_signals,
)
from yoetz.protocol.errors import ProtocolValueError

_OBLIGATION = obligation_id("obl_00000000-0000-4000-8000-000000000001")
_OTHER = obligation_id("obl_00000000-0000-4000-8000-000000000002")
_V1 = EventSchema("obligation_published", "1.0.0")
_V11 = EventSchema("obligation_published", OBLIGATION_SCHEMA_VERSION)
_REASON = "The cruise-altitude policy is the task owner's decision; reported in my answer."


def _payload(
    obligation: str, status: ObligationStatus, *, reason: str | None = None
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=obligation_id(obligation),
        description="Synthetic obligation",
        evidence_expectation="Observed run",
        status=status,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        acknowledged_not_done_reason=reason,
    )


def _ledger() -> ObservedLedger:
    ledger = ObservedLedger()
    for obligation in (_OBLIGATION, _OTHER):
        ledger.append(_V1, _payload(obligation, ObligationStatus.OPEN), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION, _OTHER)),
        observed=False,
    )
    return ledger


def _acknowledge(ledger: ObservedLedger, obligation: str = _OBLIGATION) -> None:
    ledger.append(
        _V11,
        _payload(obligation, ObligationStatus.ACKNOWLEDGED_NOT_DONE, reason=_REASON),
        observed=False,
    )


@pytest.fixture(autouse=True)
def installation_key() -> object:
    register_command_identity_key(INSTALLATION_KEY)
    yield None
    register_command_identity_key(None)


def test_the_event_version_is_a_pure_function_of_the_status() -> None:
    acknowledged = _payload(_OBLIGATION, ObligationStatus.ACKNOWLEDGED_NOT_DONE, reason=_REASON)
    wire = encode_payload(acknowledged)
    assert decode_payload(_V11, wire) == acknowledged
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1, wire)
    with pytest.raises(ProtocolValueError):
        decode_payload(_V11, encode_payload(_payload(_OBLIGATION, ObligationStatus.OPEN)))
    # 1.0.0 bytes of an open obligation are unchanged: no reason key appears.
    assert "acknowledged_not_done_reason" not in cast(
        Mapping[str, object], encode_payload(_payload(_OBLIGATION, ObligationStatus.OPEN))
    )


@pytest.mark.parametrize("reason", [None, "", "   "])
def test_an_acknowledgement_needs_a_reason(reason: str | None) -> None:
    with pytest.raises(ProtocolValueError):
        _payload(_OBLIGATION, ObligationStatus.ACKNOWLEDGED_NOT_DONE, reason=reason)


def test_a_reason_belongs_only_to_an_acknowledgement() -> None:
    with pytest.raises(ProtocolValueError):
        _payload(_OBLIGATION, ObligationStatus.OPEN, reason=_REASON)


def test_an_acknowledged_obligation_is_not_done_not_open_and_not_work() -> None:
    ledger = _ledger()
    prefix = ledger.prefix
    before = set(task_fact_signals(replay(prefix), prefix).markers)
    assert any(obligation == _OBLIGATION for _code, obligation in before)

    _acknowledge(ledger)
    prefix = ledger.prefix
    projection = replay(prefix)
    assert open_effective_obligations(projection) == (_OTHER,)
    assert acknowledged_obligation_ids(projection) == frozenset({_OBLIGATION})
    markers = set(task_fact_signals(projection, prefix).markers)
    # No planned-verification fact is reported for the acknowledged obligation.
    assert not any(obligation == _OBLIGATION for _code, obligation in markers)

    facts = replace(closure_readiness_facts(projection, prefix), check_applicability="applicable")
    assert facts.acknowledged_obligation_ids == (_OBLIGATION,)
    partly = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    assert partly.state == "action_required"
    assert partly.acknowledged_not_done == (_OBLIGATION,)

    _acknowledge(ledger, _OTHER)
    prefix = ledger.prefix
    facts = replace(
        closure_readiness_facts(replay(prefix), prefix), check_applicability="applicable"
    )
    done = derive_closure_readiness((), (), facts, semantic_review_required=False)
    assert done.state == "ready_with_limitations"
    assert done.agent_actionable == ()
    assert done.acknowledged_not_done == (_OBLIGATION, _OTHER)
    assert done.acknowledged_not_done_count == 2


@pytest.mark.parametrize("later", [ObligationStatus.OPEN, ObligationStatus.RESOLVED])
def test_a_later_publication_reopens_or_resolves_it(later: ObligationStatus) -> None:
    ledger = _ledger()
    _acknowledge(ledger)
    payload = ObligationPublishedPayload(
        obligation_id=_OBLIGATION,
        description="Synthetic obligation",
        evidence_expectation="Observed run",
        status=later,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        resolution_evidence_refs=(
            (evidence_id("evd_00000000-0000-4000-8000-000000000001"),)
            if later is ObligationStatus.RESOLVED
            else ()
        ),
    )
    ledger.append(_V1, payload, observed=False)
    projection = replay(ledger.prefix)
    assert acknowledged_obligation_ids(projection) == frozenset()
    assert (_OBLIGATION in open_effective_obligations(projection)) is (
        later is ObligationStatus.OPEN
    )


def test_reducer_transition_table() -> None:
    from yoetz.kernel import reducers

    table = reducers._OBLIGATION_TRANSITIONS  # pyright: ignore[reportPrivateUsage]
    ack, opened, resolved = (
        ObligationStatus.ACKNOWLEDGED_NOT_DONE,
        ObligationStatus.OPEN,
        ObligationStatus.RESOLVED,
    )
    assert (opened, ack) in table and (ack, opened) in table and (ack, resolved) in table
    assert (resolved, ack) not in table and (resolved, opened) not in table


def test_no_requested_item_finding_for_an_acknowledged_obligation() -> None:
    from yoetz.domain.findings import FindingKind
    from yoetz.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
    from yoetz.kernel.policies.work_integrity import work_integrity_findings

    def never_attempted(ledger: ObservedLedger) -> set[str]:
        records = ledger.prefix
        case = build_deterministic_case(replay(records), records, CaseAvailabilityFacts())
        return {
            ref
            for item in work_integrity_findings(case, absent_outputs=frozenset())
            if item.candidate.kind is FindingKind.REQUESTED_ITEM_NEVER_ATTEMPTED
            for ref in item.candidate.subject_refs
        }

    ledger = _ledger()
    ledger.edit()
    assert {_OBLIGATION, _OTHER} <= never_attempted(ledger)
    _acknowledge(ledger)
    remaining = never_attempted(ledger)
    assert _OBLIGATION not in remaining
    assert _OTHER in remaining


def test_resolved_is_final_an_acknowledgement_never_reopens_it() -> None:
    """Agreed semantics with L6: ``resolved`` is final; a later acknowledgement is refused."""

    from yoetz.kernel import reducers

    ledger = _ledger()
    resolved = ObligationPublishedPayload(
        obligation_id=_OBLIGATION,
        description="Synthetic obligation",
        evidence_expectation="Observed run",
        status=ObligationStatus.RESOLVED,
        requested_items=(RequestedItem(RequestedItemKind.COMMAND, "pytest -q"),),
        resolution_evidence_refs=(evidence_id("evd_00000000-0000-4000-8000-000000000001"),),
    )
    ledger.append(_V1, resolved, observed=False)
    _acknowledge(ledger)
    with pytest.raises(reducers.ObligationResolutionMismatch):
        replay(ledger.prefix)


def test_l6_counting_regime_lists_an_acknowledged_obligation_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L6's projection counts acknowledged_not_done as open: readiness still lists it once."""

    from types import SimpleNamespace

    from yoetz.cli.closure_gate import closure_gate_from_readiness
    from yoetz.kernel import closure_readiness

    ledger = _ledger()
    _acknowledge(ledger)
    _acknowledge(ledger, _OTHER)
    prefix = ledger.prefix
    projection = replay(prefix)

    def l6_open(state: object) -> tuple[str, ...]:
        del state
        return (_OBLIGATION, _OTHER)

    monkeypatch.setattr(closure_readiness, "open_effective_obligations", l6_open)
    facts = replace(closure_readiness_facts(projection, prefix), check_applicability="applicable")
    assert facts.open_obligation_ids == ()
    readiness = derive_closure_readiness(
        ("obligations_open",), (), facts, semantic_review_required=False
    )
    assert readiness.state == "ready_with_limitations"
    assert "obligations_open" not in readiness.agent_actionable
    assert readiness.acknowledged_not_done == (_OBLIGATION, _OTHER)
    assert readiness.acknowledged_not_done_count == 2

    # The gate never names the projection's open count as open work in that regime.
    view = SimpleNamespace(
        state="action_required",
        agent_actionable=("obligations_open",),
        open_obligation_count="3",
        receipt_blocking_finding_count="0",
        acknowledged_not_done=(_OBLIGATION, _OTHER),
        blocked_obligations=(),
    )
    gate = closure_gate_from_readiness(
        view, frontier_sequence="5", frontier_digest="d", observation_pending=False
    )
    assert gate is not None
    assert "Remaining: some open obligation(s)" in gate.text
