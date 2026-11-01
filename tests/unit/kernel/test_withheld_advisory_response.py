"""#1190 (owner decision B): a withheld advisory response never makes its own check stale."""

from __future__ import annotations

from dataclasses import fields

from builders.replay import replay_records
from finishup.domain.events import EventSchema, LedgerChain, LedgerRecord
from finishup.domain.values import EventId, event_id
from finishup.kernel.correctness_advisories import withheld_response_check
from finishup.kernel.reducers import invalidates_recorded_check, replay

_CHECK = "evt_20000002-0000-4000-8000-000000000011"
_OLDER = "evt_20000002-0000-4000-8000-000000000003"


def _withheld(parents: tuple[str, ...], *, version: str = "1.1.0") -> LedgerRecord:
    template = next(
        record
        for record in replay_records("all-event-families")
        if record.schema.name == "decision_recorded"
    )
    clone = object.__new__(type(template))
    for field in fields(type(template)):
        object.__setattr__(clone, field.name, getattr(template, field.name))
    object.__setattr__(clone, "schema", EventSchema("decision_recorded", version))
    object.__setattr__(clone, "payload", None)
    object.__setattr__(clone, "causal_parents", tuple(event_id(item) for item in parents))
    chain = object.__new__(LedgerChain)
    for field in fields(LedgerChain):
        object.__setattr__(chain, field.name, getattr(template.ledger, field.name))
    object.__setattr__(chain, "ingestion_sequence", 90)
    object.__setattr__(clone, "ledger", chain)
    return clone


def _stales(record: LedgerRecord, check: EventId | None) -> bool:
    return invalidates_recorded_check(
        record,
        40,
        (),
        limitation_finding_ids=frozenset(),
        projection=replay(()),
        check_event_id=check,
    )


def test_a_withheld_answer_to_the_judged_check_keeps_it_current() -> None:
    answer = _withheld((_CHECK,))
    assert withheld_response_check(answer) == _CHECK
    assert not _stales(answer, event_id(_CHECK))
    # Without the judged check's identity, or for a later check, the unreadable-record rule holds.
    assert _stales(answer, None)
    assert _stales(answer, event_id(_OLDER))


def test_other_withheld_shapes_keep_the_conservative_rule() -> None:
    check = event_id(_CHECK)
    # A released 1.0.0 decision cannot carry an advisory response.
    assert _stales(_withheld((_CHECK,), version="1.0.0"), check)
    # An advisory response names exactly its check as its only parent.
    assert _stales(_withheld((_CHECK, _OLDER)), check)
    assert _stales(_withheld(()), check)
