"""Current completion scope is derived only from the readable plan chain."""

from __future__ import annotations

import pytest

from finishup.domain.events import (
    NoObligationsReason,
    ObligationChange,
    ObligationChangeKind,
    PlanPublishedPayload,
    PlanRevisedPayload,
    encode_payload,
)
from finishup.domain.values import event_id, obligation_id
from finishup.kernel.plan_scope import current_plan_scope
from finishup.kernel.projections import PlanProjectionRecord
from finishup.protocol.canonical import canonical_digest


def _event(tail: int) -> str:
    return f"evt_00000000-0000-4000-8000-{tail:012d}"


def _obligation(tail: int) -> str:
    return f"obl_00000000-0000-4000-8000-{tail:012d}"


def _record(
    payload: PlanPublishedPayload | PlanRevisedPayload | None,
    *,
    frontier: int,
) -> PlanProjectionRecord:
    digest = "sha256:" + "0" * 64 if payload is None else canonical_digest(encode_payload(payload))
    return PlanProjectionRecord(
        payload=payload,
        payload_digest=digest,
        redacted=payload is None,
        source_event_id=event_id(_event(frontier)),
        source_frontier=frontier,
    )


def test_no_plan_is_known_but_has_no_declaration() -> None:
    scope = current_plan_scope({})

    assert scope.has_plan is False
    assert scope.readable is True
    assert scope.current_plan_event_id is None
    assert scope.effective_obligation_refs == ()
    assert scope.declared_obligation_count is None
    assert scope.no_obligations_reason is None


@pytest.mark.parametrize("reason", tuple(NoObligationsReason))
def test_empty_plan_preserves_each_closed_reason(reason: NoObligationsReason) -> None:
    scope = current_plan_scope(
        {
            1: _record(
                PlanPublishedPayload(1, "Atomic task.", (), no_obligations_reason=reason),
                frontier=1,
            )
        }
    )

    assert scope.has_plan is True
    assert scope.readable is True
    assert scope.effective_obligation_refs == ()
    assert scope.declared_obligation_count == 0
    assert scope.no_obligations_reason is reason


def test_revisions_apply_effective_references_and_restate_reason() -> None:
    first = obligation_id(_obligation(1))
    second = obligation_id(_obligation(2))
    third = obligation_id(_obligation(3))
    plans = {
        1: _record(
            PlanPublishedPayload(1, "Initial.", (first,)),
            frontier=1,
        ),
        2: _record(
            PlanRevisedPayload(
                2,
                1,
                "Carry another obligation.",
                "Expanded.",
                (ObligationChange(second, ObligationChangeKind.CARRIED),),
            ),
            frontier=2,
        ),
        3: _record(
            PlanRevisedPayload(
                3,
                2,
                "Replace the first obligation.",
                "Replacement.",
                (
                    ObligationChange(
                        first,
                        ObligationChangeKind.SUPERSEDED,
                        reason="Replacement owns the scope.",
                        replacement_obligation_ids=(third,),
                    ),
                ),
            ),
            frontier=3,
        ),
        4: _record(
            PlanRevisedPayload(
                4,
                3,
                "Remove the remaining obligations.",
                "No obligations remain.",
                (
                    ObligationChange(
                        second,
                        ObligationChangeKind.WAIVED,
                        reason="No longer material.",
                    ),
                    ObligationChange(
                        third,
                        ObligationChangeKind.WAIVED,
                        reason="No longer material.",
                    ),
                ),
                no_obligations_reason=NoObligationsReason.NO_MATERIAL_CHANGE,
            ),
            frontier=4,
        ),
        5: _record(
            PlanRevisedPayload(
                5,
                4,
                "Replace the empty-scope declaration.",
                "Still empty with a different declaration.",
                (),
                no_obligations_reason=NoObligationsReason.SINGLE_ATOMIC_CHANGE,
            ),
            frontier=5,
        ),
        6: _record(
            PlanRevisedPayload(
                6,
                5,
                "Restate without a declaration.",
                "Still empty.",
                (),
            ),
            frontier=6,
        ),
    }

    before_replace = current_plan_scope({key: value for key, value in plans.items() if key < 5})
    assert before_replace.effective_obligation_refs == ()
    assert before_replace.no_obligations_reason is NoObligationsReason.NO_MATERIAL_CHANGE

    before_clear = current_plan_scope({key: value for key, value in plans.items() if key < 6})
    assert before_clear.effective_obligation_refs == ()
    assert before_clear.no_obligations_reason is NoObligationsReason.SINGLE_ATOMIC_CHANGE

    after_clear = current_plan_scope(plans)
    assert after_clear.effective_obligation_refs == ()
    assert after_clear.declared_obligation_count == 0
    assert after_clear.no_obligations_reason is None
    assert after_clear.current_plan_event_id == event_id(_event(6))


def test_next_version_plan_published_restates_scope_after_revisions() -> None:
    first = obligation_id(_obligation(1))
    second = obligation_id(_obligation(2))
    third = obligation_id(_obligation(3))
    scope = current_plan_scope(
        {
            1: _record(PlanPublishedPayload(1, "Initial.", (first,)), frontier=1),
            2: _record(
                PlanRevisedPayload(
                    2,
                    1,
                    "Carry second.",
                    "Expanded.",
                    (ObligationChange(second, ObligationChangeKind.CARRIED),),
                ),
                frontier=2,
            ),
            3: _record(
                PlanRevisedPayload(3, 2, "Restate.", "Still expanded.", ()),
                frontier=3,
            ),
            4: _record(
                PlanPublishedPayload(4, "Full scope restatement.", (first, second, third)),
                frontier=4,
            ),
        }
    )

    assert scope.readable is True
    assert scope.current_plan_event_id == event_id(_event(4))
    assert scope.effective_obligation_refs == (first, second, third)
    assert scope.declared_obligation_count == 3


def test_plan_published_restatement_requires_exact_next_version() -> None:
    first = obligation_id(_obligation(1))
    scope = current_plan_scope(
        {
            1: _record(PlanPublishedPayload(1, "Initial.", (first,)), frontier=1),
            3: _record(PlanPublishedPayload(3, "Skipped version.", (first,)), frontier=3),
        }
    )

    assert scope.readable is False
    assert scope.current_plan_event_id == event_id(_event(3))
    assert scope.effective_obligation_refs is None


@pytest.mark.parametrize(
    "plans,gaps",
    (
        ({1: _record(None, frontier=1)}, ()),
        (
            {
                1: _record(
                    PlanPublishedPayload(1, "Initial.", ()),
                    frontier=1,
                ),
                3: _record(
                    PlanRevisedPayload(3, 2, "Disconnected.", "Unreadable.", ()),
                    frontier=2,
                ),
            },
            (),
        ),
        (
            {},
            ("unknown_event:evt_00000000-0000-4000-8000-000000000009:plan_revised@1.0.1",),
        ),
    ),
)
def test_unreadable_plan_scope_never_becomes_zero(
    plans: dict[int, PlanProjectionRecord], gaps: tuple[str, ...]
) -> None:
    scope = current_plan_scope(plans, gaps)

    assert scope.has_plan is True
    assert scope.readable is False
    assert scope.effective_obligation_refs is None
    assert scope.declared_obligation_count is None
    assert scope.no_obligations_reason is None
