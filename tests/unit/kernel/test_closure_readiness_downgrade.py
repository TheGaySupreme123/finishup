"""An honest downgrade is not challenged by the acknowledgement re-check (ADR-033, owner decision D1).

Status invites exactly one move for a flagged resolution whose output does not meet its criteria:
republish it ``acknowledged_not_done``. Before D1 the acceptance-invite memory exempted that
acknowledgement from the acknowledgement re-check; that memory is no longer written, so the
exemption is replay-derived instead: the effective publication is ``acknowledged_not_done`` and the
one right before it is ``resolved``. An acknowledgement of work never claimed is still re-checked
once (#997), and an unreadable prior publication fails toward asking.
"""

from __future__ import annotations

from collections.abc import Iterator
from types import SimpleNamespace
from typing import cast

import pytest

from builders.observed_runs import INSTALLATION_KEY, ObservedLedger
from finishup.cli.closure_gate import closure_gate_from_readiness
from finishup.domain.events import (
    EventSchema,
    LedgerRecord,
    ObligationPublishedPayload,
    ObligationStatus,
    PlanPublishedPayload,
)
from finishup.domain.values import ObligationId, ResultId, obligation_id
from finishup.kernel.closure_readiness import (
    _downgraded_from_resolved,  # pyright: ignore[reportPrivateUsage]
    closure_readiness_facts,
)
from finishup.kernel.closure_verdict import Recheck, rechecks_from_closures
from finishup.kernel.reducers import replay

_OBLIGATION: ObligationId = obligation_id("obl_00000000-0000-4000-8000-00000000f001")
_SCHEMA = EventSchema("obligation_published", "1.1.0")
_REASON = "The output does not meet its acceptance criteria."


@pytest.fixture(autouse=True)
def installation_key() -> Iterator[None]:
    from finishup.kernel.task_facts import register_command_identity_key

    register_command_identity_key(INSTALLATION_KEY)
    yield
    register_command_identity_key(None)


def _published(
    status: ObligationStatus, resolution: tuple[ResultId, ...] = ()
) -> ObligationPublishedPayload:
    return ObligationPublishedPayload(
        obligation_id=_OBLIGATION,
        description="Deliver the requested output",
        evidence_expectation="A recorded run",
        status=status,
        resolution_evidence_refs=resolution,
        acknowledged_not_done_reason=(
            _REASON if status is ObligationStatus.ACKNOWLEDGED_NOT_DONE else None
        ),
    )


def _ledger(*statuses: ObligationStatus) -> ObservedLedger:
    ledger = ObservedLedger()
    ledger.append(_SCHEMA, _published(ObligationStatus.OPEN), observed=False)
    ledger.append(
        EventSchema("plan_published", "1.0.0"),
        PlanPublishedPayload(1, "Plan", (_OBLIGATION,)),
        observed=False,
    )
    run = ledger.passes("pytest -q")
    for status in statuses:
        resolution = (run,) if status is ObligationStatus.RESOLVED else ()
        ledger.append(_SCHEMA, _published(status, resolution), observed=False)
    return ledger


def _rechecks(ledger: ObservedLedger) -> tuple[Recheck, ...]:
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.obligation_closures is not None
    return rechecks_from_closures(facts.obligation_closures, facts, acknowledged_count=1)


def _acknowledgements(rechecks: tuple[Recheck, ...]) -> list[Recheck]:
    return [row for row in rechecks if row.kind == "acknowledgement"]


def test_resolved_then_acknowledged_is_not_rechecked() -> None:
    ledger = _ledger(ObligationStatus.RESOLVED, ObligationStatus.ACKNOWLEDGED_NOT_DONE)
    state = replay(ledger.prefix)
    facts = closure_readiness_facts(state, ledger.prefix)
    assert facts.downgraded_obligation_ids == (_OBLIGATION,)
    assert _acknowledgements(_rechecks(ledger)) == []


@pytest.mark.parametrize(
    "statuses",
    (
        # Work never claimed: the acknowledgement is still asked about once (#997).
        (ObligationStatus.ACKNOWLEDGED_NOT_DONE,),
        # Reopened first: the acknowledgement does not directly follow a resolution.
        (
            ObligationStatus.RESOLVED,
            ObligationStatus.OPEN,
            ObligationStatus.ACKNOWLEDGED_NOT_DONE,
        ),
    ),
)
def test_an_acknowledgement_that_is_not_a_downgrade_is_rechecked_once(
    statuses: tuple[ObligationStatus, ...],
) -> None:
    ledger = _ledger(*statuses)
    state = replay(ledger.prefix)
    assert closure_readiness_facts(state, ledger.prefix).downgraded_obligation_ids == ()
    asked = _acknowledgements(_rechecks(ledger))
    assert [row.subjects for row in asked] == [(str(_OBLIGATION),)]


def test_an_unreadable_prior_publication_fails_toward_asking() -> None:
    ledger = _ledger(ObligationStatus.RESOLVED, ObligationStatus.ACKNOWLEDGED_NOT_DONE)
    state = replay(ledger.prefix)
    records = ledger.prefix
    assert _downgraded_from_resolved(state, records, (_OBLIGATION,)) == (_OBLIGATION,)
    resolved_at = max(
        index
        for index, row in enumerate(records)
        if isinstance(row.payload, ObligationPublishedPayload)
        and row.payload.status is ObligationStatus.RESOLVED
    )
    holed = (*records[:resolved_at], _hole(records[resolved_at]), *records[resolved_at + 1 :])
    assert _downgraded_from_resolved(state, holed, (_OBLIGATION,)) == ()
    # A hole whose locator names no obligation may be anyone's, so it breaks the chain too.
    anonymous = _hole(records[resolved_at], anonymous=True)
    holed = (*records[:resolved_at], anonymous, *records[resolved_at + 1 :])
    assert _downgraded_from_resolved(state, holed, (_OBLIGATION,)) == ()


def _hole(record: LedgerRecord, *, anonymous: bool = False) -> LedgerRecord:
    """*record* with an unreadable payload; *anonymous* also drops its locator's logical key."""

    locator = SimpleNamespace(logical_key=None) if anonymous else record.projection_locator
    hole = SimpleNamespace(
        schema=record.schema, ledger=record.ledger, payload=None, projection_locator=locator
    )
    return cast(LedgerRecord, hole)


@pytest.mark.parametrize("readable", (True, False))
def test_an_unrelated_publication_after_a_downgrade_keeps_the_exemption(readable: bool) -> None:
    ledger = _ledger(ObligationStatus.RESOLVED, ObligationStatus.ACKNOWLEDGED_NOT_DONE)
    other = obligation_id("obl_00000000-0000-4000-8000-00000000f002")
    ledger.append(
        _SCHEMA,
        ObligationPublishedPayload(
            obligation_id=other,
            description="Another output",
            evidence_expectation="A recorded run",
            status=ObligationStatus.OPEN,
        ),
        observed=False,
    )
    records = ledger.prefix
    state = replay(records)
    assert records[-1].projection_locator.logical_key == other
    if not readable:
        # A redacted or key-unavailable publication is attributed through its locator, as the
        # reducer does: it does not break another obligation's chain.
        records = (*records[:-1], _hole(records[-1]))
    assert _downgraded_from_resolved(state, records, (_OBLIGATION,)) == (_OBLIGATION,)


def test_the_gate_fed_the_kernels_rechecks_over_a_downgrade_lets_the_agent_stop() -> None:
    rechecks = _rechecks(_ledger(ObligationStatus.RESOLVED, ObligationStatus.ACKNOWLEDGED_NOT_DONE))
    readiness = SimpleNamespace(
        state="ready_with_limitations",
        agent_actionable=(),
        standing_limitations=(),
        acknowledged_not_done=(str(_OBLIGATION),),
        acknowledged_not_done_count="1",
        rechecks=rechecks,
    )
    gate = closure_gate_from_readiness(
        readiness,
        frontier_sequence="9",
        frontier_digest="sha256:" + "a" * 64,
        observation_pending=False,
    )
    assert gate is None
    # The control: the same readiness with an acknowledgement of work never claimed is asked.
    asked = _rechecks(_ledger(ObligationStatus.ACKNOWLEDGED_NOT_DONE))
    control = closure_gate_from_readiness(
        SimpleNamespace(**{**vars(readiness), "rechecks": asked}),
        frontier_sequence="9",
        frontier_digest="sha256:" + "a" * 64,
        observation_pending=False,
    )
    assert control is not None
