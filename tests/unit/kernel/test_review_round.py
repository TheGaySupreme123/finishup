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


def test_edits_re_arm_the_round_at_most_until_the_task_cap() -> None:
    """tb4n1 review: retro-console-soc's writes were shell commands; lake/html/medical edited
    between checks, so the edit re-arm alone never stopped those loops."""

    edit = _action(ActionKind.EDIT)
    insufficient = _check("insufficient_packet")
    assert not _stopped(insufficient, edit, insufficient, edit, insufficient)
    assert _stopped(insufficient, edit, insufficient, edit, insufficient, edit, insufficient)
    # The newest completed review assessed the work: never stopped.
    assert not _stopped(
        insufficient, insufficient, insufficient, insufficient, _check("challenges_returned")
    )


# --- tb4n5 follow-up of #1046: a finding the reviewer keeps unassessable stops the round ---------


def _ruled(*verdicts: tuple[int, str], conclusion: str = "no_material_discrepancy") -> object:
    from builders.policy_cases import fnd
    from yoetz.domain.findings import PriorFindingVerdictRecord

    record = cast(SimpleNamespace, _check(conclusion))
    object.__setattr__(
        record.payload,
        "prior_finding_verdicts",
        tuple(PriorFindingVerdictRecord(fnd(number), verdict, ()) for number, verdict in verdicts),
    )
    return record


def _exhausted(*records: object) -> frozenset[object]:
    from yoetz.kernel.review_round import unassessable_review_exhausted

    return cast(
        frozenset[object],
        unassessable_review_exhausted(cast(tuple[LedgerRecord, ...], records)),
    )


def test_two_unassessable_rulings_in_a_row_on_one_finding_stop_the_round() -> None:
    """Codex check of fix/n5-findings: an unassessable ruling stays an open round, so without this
    a reviewer that cannot judge one answered finding was asked again at every check."""

    from builders.policy_cases import fnd

    one = _ruled((1, "unassessable"))
    assert not _stopped(one)
    assert _stopped(one, _ruled((1, "unassessable")))
    assert _exhausted(one, _ruled((1, "unassessable"))) == {fnd(1)}
    # Evidence or responses do not re-arm it; a skipped (not completed) check neither counts nor
    # resets.
    skipped = _check(None, SemanticStatus.NOT_REQUESTED)
    assert _stopped(one, _action(ActionKind.COMMAND), skipped, _ruled((1, "unassessable")))
    # A review that did not rule on it neither counts nor ends the run.
    assert _stopped(one, _ruled((2, "fixed")), _ruled((1, "unassessable")))


def test_another_ruling_or_an_edit_re_arms_and_four_in_a_row_is_the_hard_cap() -> None:
    assert not _stopped(_ruled((1, "unassessable")), _ruled((1, "still_present")))
    assert not _stopped(_ruled((1, "still_present")), _ruled((1, "unassessable")))
    assert not _stopped(
        _ruled((1, "unassessable")), _action(ActionKind.EDIT), _ruled((1, "unassessable"))
    )
    # Different findings never add up.
    assert not _stopped(_ruled((1, "unassessable")), _ruled((2, "unassessable")))
    # Edits re-arm it only until four unassessable rulings in a row on the same finding.
    runs: list[object] = []
    for _ in range(3):
        runs.extend((_ruled((1, "unassessable")), _action(ActionKind.EDIT)))
    assert not _stopped(*runs[:-1])
    assert _stopped(*runs, _ruled((1, "unassessable")))
