"""tb4n1 D3 (issue #983): the AI-powered review round stops after one insufficient-packet retry."""

from __future__ import annotations

from copy import copy
from types import SimpleNamespace
from typing import cast

from builders.policy_cases import act
from builders.replay import replay_records
from yoetz.domain.events import (
    ActionKind,
    ActionRecordedPayload,
    CheckRecordedPayload,
    LedgerRecord,
)
from yoetz.kernel.review_round import review_round_stopped
from yoetz.protocol.models import SemanticStatus

_CHECK = next(
    record.payload
    for record in replay_records("all-event-families")
    if type(record.payload) is CheckRecordedPayload
)


def _check(conclusion: str | None, status: SemanticStatus = SemanticStatus.SUCCEEDED) -> object:
    # Only the two fields the rule reads differ; bypass the status/reason pairing validation.
    payload = copy(_CHECK)
    object.__setattr__(payload, "semantic_status", status)
    object.__setattr__(payload, "semantic_conclusion", conclusion)
    return SimpleNamespace(schema=SimpleNamespace(name="check_recorded"), payload=payload)


def _action(kind: ActionKind) -> object:
    payload = ActionRecordedPayload(
        act(9), kind, "x", command="pytest" if kind is ActionKind.COMMAND else None
    )
    return SimpleNamespace(schema=SimpleNamespace(name="action_recorded"), payload=payload)


def _stopped(*records: object) -> bool:
    return review_round_stopped(cast(tuple[LedgerRecord, ...], records))


def test_two_insufficient_reviews_in_a_row_stop_the_round_even_when_nothing_was_named() -> None:
    """retro-console-soc: 12 of 13 closing reviews were insufficient_packet."""

    assert not _stopped(_check("insufficient_packet"))
    assert _stopped(_check("insufficient_packet"), _check("insufficient_packet"))
    # Publishing evidence (feeding the reviewer) does not re-arm the round.
    assert _stopped(
        _check("insufficient_packet"),
        _check("insufficient_packet"),
        _action(ActionKind.COMMAND),
    )


def test_an_edit_or_an_assessed_review_re_arms_the_round() -> None:
    assert not _stopped(
        _check("insufficient_packet"), _check("insufficient_packet"), _action(ActionKind.EDIT)
    )
    assert not _stopped(
        _check("insufficient_packet"), _action(ActionKind.EDIT), _check("insufficient_packet")
    )
    assert not _stopped(_check("insufficient_packet"), _check("no_material_discrepancy"))
    # After the edit re-armed it, two more insufficient reviews stop it again.
    assert _stopped(
        _check("insufficient_packet"),
        _check("insufficient_packet"),
        _action(ActionKind.EDIT),
        _check("insufficient_packet"),
        _check("insufficient_packet"),
    )


def test_checks_without_a_completed_review_neither_count_nor_reset() -> None:
    skipped = _check(None, SemanticStatus.NOT_REQUESTED)
    assert _stopped(_check("insufficient_packet"), skipped, _check("insufficient_packet"), skipped)
