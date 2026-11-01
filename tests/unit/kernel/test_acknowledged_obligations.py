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
from finishup.domain.events import (
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
from finishup.domain.values import evidence_id, obligation_id
from finishup.kernel.closure_readiness import closure_readiness_facts, derive_closure_readiness
from finishup.kernel.reducers import replay
from finishup.kernel.task_facts import (
    acknowledged_obligation_ids,
    open_effective_obligations,
    register_command_identity_key,
    task_fact_signals,
)
from finishup.protocol.errors import ProtocolValueError

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


def test_the_acknowledged_status_needs_1_1_0_which_also_admits_a_plain_obligation() -> None:
    acknowledged = _payload(_OBLIGATION, ObligationStatus.ACKNOWLEDGED_NOT_DONE, reason=_REASON)
    wire = encode_payload(acknowledged)
    assert decode_payload(_V11, wire) == acknowledged
    with pytest.raises(ProtocolValueError):
        decode_payload(_V1, wire)
    # Issue #1023: 1.1.0 is a superset, so a plain open obligation is admitted there too.
    plain = _payload(_OBLIGATION, ObligationStatus.OPEN)
    assert decode_payload(_V11, encode_payload(plain)) == plain
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
    from finishup.kernel import reducers

    table = reducers._OBLIGATION_TRANSITIONS  # pyright: ignore[reportPrivateUsage]
    ack, opened, resolved = (
        ObligationStatus.ACKNOWLEDGED_NOT_DONE,
        ObligationStatus.OPEN,
        ObligationStatus.RESOLVED,
    )
    assert (opened, ack) in table and (ack, opened) in table and (ack, resolved) in table
    # tb4n2 R2 (#1022, ADR-041): a resolution is not latched; it is never re-resolved in place.
    assert (resolved, ack) in table and (resolved, opened) in table
    assert (resolved, resolved) not in table and (opened, opened) not in table


def test_no_requested_item_finding_for_an_acknowledged_obligation() -> None:
    from finishup.domain.findings import FindingKind
    from finishup.kernel.deterministic_checks import CaseAvailabilityFacts, build_deterministic_case
    from finishup.kernel.policies.work_integrity import work_integrity_findings

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
    # tb4n2 E4 (P1-7): an observed edit names no obligation, so "never attempted" waits for a
    # completion claim (or work published on that obligation).
    assert never_attempted(ledger) == set()
    ledger.claim()
    assert {_OBLIGATION, _OTHER} <= never_attempted(ledger)
    _acknowledge(ledger)
    remaining = never_attempted(ledger)
    assert _OBLIGATION not in remaining
    assert _OTHER in remaining


def test_a_resolution_that_no_longer_holds_can_be_acknowledged() -> None:
    """tb4n2 R2 (#1022, ADR-041) replaces L6's "resolved is final": a resolved obligation whose
    work no longer holds is acknowledged as not done; re-resolving it in place stays refused."""

    from finishup.kernel import reducers

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
    payload = replay(ledger.prefix).obligations[_OBLIGATION].payload
    assert payload is not None and payload.status is ObligationStatus.ACKNOWLEDGED_NOT_DONE
    ledger.append(_V1, resolved, observed=False)
    ledger.append(_V1, resolved, observed=False)
    with pytest.raises(reducers.ObligationResolutionMismatch):
        replay(ledger.prefix)


def test_l6_counting_regime_lists_an_acknowledged_obligation_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """L6's projection counts acknowledged_not_done as open: readiness still lists it once."""

    from types import SimpleNamespace

    from finishup.cli.closure_gate import closure_gate_from_readiness
    from finishup.kernel import closure_readiness

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


def _gate_view(**fields: object) -> object:
    from types import SimpleNamespace

    from builders.gate_readiness import ack_recheck

    base: dict[str, object] = {
        "state": "ready_with_limitations",
        "agent_actionable": (),
        "standing_limitations": (),
        "acknowledged_not_done": (_OBLIGATION,),
        "acknowledged_obligation_count": "1",
        "open_obligation_count": "0",
        "receipt_blocking_finding_count": "0",
        "blocked_obligations": (),
        # tb4n3 RC-8: the gate asks the re-checks status announces.
        "rechecks": (ack_recheck(str(_OBLIGATION)),),
    }
    base.update(fields)
    return SimpleNamespace(**base)


def test_the_gate_challenges_each_acknowledged_obligation_once() -> None:
    """Review item 1: one acknowledgement must not end the work silently (mirrors blockers)."""

    from finishup.cli.closure_gate import (
        ACKNOWLEDGEMENT_RECHECK_ITEM,
        ClosureGate,
        closure_gate_from_readiness,
    )

    def gate(
        view: object, *, reasked_blockers: frozenset[str] = frozenset(), active_stop: bool = False
    ) -> ClosureGate | None:
        return closure_gate_from_readiness(
            view,
            frontier_sequence="9",
            frontier_digest="d",
            observation_pending=False,
            reasked_blockers=reasked_blockers,
            active_stop=active_stop,
        )

    first = gate(_gate_view())
    assert first is not None
    assert first.items == (ACKNOWLEDGEMENT_RECHECK_ITEM,)
    assert first.blocker_keys == (f"ack:{_OBLIGATION}",)
    text = first.text
    assert "Repair first" in text and _OBLIGATION in text and len(text) <= 2_000
    # Asked once; also on an active Stop, like a blocker re-check.
    assert gate(_gate_view(), reasked_blockers=frozenset({f"ack:{_OBLIGATION}"})) is None
    assert gate(_gate_view(), active_stop=True) is not None
    # An acknowledgement status does not announce is not asked (tb4n3 RC-8).
    assert gate(_gate_view(rechecks=())) is None


def test_an_ordinary_gate_never_offers_acknowledgement_as_an_exit() -> None:
    """Review item 4: the last resort appears only once a blocker was challenged."""

    from finishup.cli.closure_gate import closure_gate_from_readiness

    view = _gate_view(
        state="action_required",
        agent_actionable=("obligations_open",),
        acknowledged_not_done=(),
        acknowledged_obligation_count="0",
        open_obligation_count="2",
    )
    gate = closure_gate_from_readiness(
        view, frontier_sequence="9", frontier_digest="d", observation_pending=False
    )
    assert gate is not None
    assert "acknowledged_not_done" not in gate.text
    assert "Remaining: 2 open obligation(s)" in gate.text


def test_check_totals_count_an_acknowledged_obligation_once() -> None:
    from finishup.domain.check_totals import render_check_totals

    totals = {
        "obligations": {
            "declared": "3",
            "resolved": "1",
            "open": "1",
            "unreadable": "0",
            "with_evidence": "1",
            "scope_known": "1",
        },
        "requested_items": {"attempted": "0", "unattempted": "0"},
        "commands": {
            key: "0"
            for key in (
                "observed",
                "failed",
                "unknown",
                "live_failed",
                "retired_by_rerun",
                "disclosed_not_rerun_green",
            )
        },
    }
    from finishup.domain.check_totals import CHECK_TOTAL_KEYS

    for group in ("evidence", "findings", "test_edits"):
        totals[group] = dict.fromkeys(CHECK_TOTAL_KEYS[group], "0")
    rendered = render_check_totals(totals)
    assert "1 open, 1 acknowledged not done, 0 unreadable" in rendered


def test_a_claim_on_only_acknowledged_obligations_can_be_withdrawn() -> None:
    """Codex review 3 (#1022): the honest replacement of a claim whose every obligation is now
    acknowledged as not done names none; an overlapping scope is still required otherwise."""

    from finishup.domain.events import ClaimKind, ClaimRecordedPayloadV1_1
    from finishup.domain.values import claim_id
    from finishup.kernel.reducers import ClaimRevisionMismatch

    old = claim_id("clm_00000000-0000-4000-8000-000000000001")
    new = claim_id("clm_00000000-0000-4000-8000-000000000002")
    claim_v11 = EventSchema("claim_recorded", "1.1.0")

    def claim(key: object, refs: tuple[object, ...], supersedes: tuple[object, ...] = ()) -> None:
        ledger.append(
            claim_v11,
            ClaimRecordedPayloadV1_1(
                claim_id=key,  # type: ignore[arg-type]
                claim_kind=ClaimKind.COMPLETION,
                statement="Claim",
                supporting_refs=(),
                obligation_refs=refs,  # type: ignore[arg-type]
                supersedes_claim_refs=supersedes,  # type: ignore[arg-type]
            ),
            observed=False,
        )

    ledger = _ledger()
    claim(old, (_OBLIGATION,))
    _acknowledge(ledger)
    claim(new, (), (old,))
    state = replay(ledger.prefix)
    assert state.claims[old].superseded_by_claim_id == new

    ledger = _ledger()
    claim(old, (_OBLIGATION,))
    claim(new, (), (old,))
    with pytest.raises(ClaimRevisionMismatch):
        replay(ledger.prefix)
