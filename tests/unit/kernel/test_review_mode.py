"""A task's review mode: its owner setting, its switches, and why it runs local (ADR-049)."""

from __future__ import annotations

from dataclasses import replace

import pytest

from builders.observed_runs import ObservedLedger
from finishup.domain.events import DecisionRecordedPayload, EventSchema, ReviewMode
from finishup.domain.privacy import ConversationReview
from finishup.domain.values import EventId, actor_id
from finishup.kernel.projections import ProjectionState
from finishup.kernel.reducers import replay
from finishup.kernel.review_mode import (
    ReviewModeSwitch,
    conversation_review_mode,
    conversation_review_mode_from_switches,
    review_mode_switches,
)

_AUTHORITY = actor_id("harness:agent")


def _switch(
    ledger: ObservedLedger,
    mode: ReviewMode | None,
    *,
    supersedes: EventId | None = None,
) -> EventId:
    """Append one decision; a ``mode`` makes it a 1.1.0 review-mode switch."""

    return ledger.append(
        EventSchema("decision_recorded", "1.0.0" if mode is None else "1.1.0"),
        DecisionRecordedPayload(
            statement="Switch this task's review mode.",
            rationale="Synthetic rationale.",
            authority=_AUTHORITY,
            supersedes_event_id=supersedes,
            review_mode=mode,
        ),
        observed=False,
    )


def _projection(*modes: ReviewMode) -> tuple[ProjectionState, tuple[EventId, ...]]:
    ledger = ObservedLedger()
    ids = tuple(_switch(ledger, mode) for mode in modes)
    return replay(ledger.records), ids


@pytest.mark.parametrize(
    ("setting", "expected"),
    [
        (ConversationReview.LOCAL_ONLY, ReviewMode.LOCAL),
        (ConversationReview.LOCAL_OWNER_APPROVAL, ReviewMode.LOCAL),
        (ConversationReview.LOCAL_AGENT_OPT_IN, ReviewMode.LOCAL),
        (ConversationReview.AI_POWERED, ReviewMode.AI_POWERED),
        # An unreadable setting keeps the released behaviour: review in every task.
        (None, ReviewMode.AI_POWERED),
    ],
)
def test_every_task_starts_in_its_owner_settings_mode(
    setting: ConversationReview | None, expected: ReviewMode
) -> None:
    projection, _ = _projection()
    resolved = conversation_review_mode(projection, setting, setting_explicit=True)
    assert resolved.mode is expected
    assert resolved.requested is expected
    assert resolved.switches == ()
    assert resolved.local_reason == (
        "conversation_default" if expected is ReviewMode.LOCAL else None
    )


def test_an_agent_switch_turns_review_on_and_a_later_one_turns_it_back_off() -> None:
    projection, (on,) = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection, ConversationReview.LOCAL_AGENT_OPT_IN, setting_explicit=True
    )
    assert resolved.mode is ReviewMode.AI_POWERED
    assert resolved.latest_switch is not None
    assert resolved.latest_switch.event_id == on
    assert resolved.latest_switch.authority == _AUTHORITY
    assert not resolved.owner_approval_required

    projection, (on, off) = _projection(ReviewMode.AI_POWERED, ReviewMode.LOCAL)
    resolved = conversation_review_mode(
        projection, ConversationReview.LOCAL_AGENT_OPT_IN, setting_explicit=True
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.local_reason == "switched_to_local"
    assert [switch.event_id for switch in resolved.switches] == [on, off]
    assert [switch.sequence for switch in resolved.switches] == [1, 2]


def test_owner_approval_runs_the_review_but_waits_for_the_owner() -> None:
    projection, _ = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection, ConversationReview.LOCAL_OWNER_APPROVAL, setting_explicit=True
    )
    assert resolved.mode is ReviewMode.AI_POWERED
    assert resolved.owner_approval_required


@pytest.mark.parametrize("available", [True, False])
def test_an_explicit_local_only_owner_refuses_agent_opt_in(available: bool) -> None:
    projection, _ = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection,
        ConversationReview.LOCAL_ONLY,
        ai_review_available=available,
        setting_explicit=True,
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.requested is ReviewMode.AI_POWERED
    assert resolved.local_reason == "owner_local_only"


def test_a_released_policy_without_review_says_review_is_not_set_up() -> None:
    """Unset and inference off reads as local only, but the owner never chose it."""

    projection, _ = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection, ConversationReview.LOCAL_ONLY, ai_review_available=False
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.local_reason == "ai_review_not_set_up"


def test_opting_in_where_nothing_is_set_up_stays_local() -> None:
    projection, _ = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection,
        ConversationReview.LOCAL_AGENT_OPT_IN,
        ai_review_available=False,
        setting_explicit=True,
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.local_reason == "ai_review_not_set_up"


def test_a_strict_route_keeps_an_opted_in_task_local_with_its_own_reason() -> None:
    projection, _ = _projection(ReviewMode.AI_POWERED)
    resolved = conversation_review_mode(
        projection,
        ConversationReview.LOCAL_AGENT_OPT_IN,
        setting_explicit=True,
        route_allows_review=False,
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.local_reason == "route_local_only"


def test_the_released_ai_powered_setting_keeps_its_honest_unavailable_review() -> None:
    """Under ``ai_powered`` nothing is downgraded: an unavailable review stays a required gap."""

    projection, _ = _projection()
    resolved = conversation_review_mode(
        projection,
        ConversationReview.AI_POWERED,
        ai_review_available=False,
        route_allows_review=False,
    )
    assert resolved.mode is ReviewMode.AI_POWERED
    assert resolved.local_reason is None


def test_a_redacted_switch_switches_nothing() -> None:
    projection, (on,) = _projection(ReviewMode.AI_POWERED)
    record = projection.decisions[on]
    redacted = replace(
        projection,
        decisions={**projection.decisions, on: replace(record, payload=None, redacted=True)},
    )
    assert review_mode_switches(redacted) == ()
    resolved = conversation_review_mode(
        redacted, ConversationReview.LOCAL_AGENT_OPT_IN, setting_explicit=True
    )
    assert resolved.mode is ReviewMode.LOCAL
    assert resolved.local_reason == "conversation_default"


def test_a_superseded_switch_is_withdrawn() -> None:
    ledger = ObservedLedger()
    on = _switch(ledger, ReviewMode.AI_POWERED)
    # A later plain decision that supersedes the switch withdraws it; the task is default again.
    _switch(ledger, None, supersedes=on)
    projection = replay(ledger.records)
    assert review_mode_switches(projection) == ()
    resolved = conversation_review_mode(
        projection, ConversationReview.LOCAL_AGENT_OPT_IN, setting_explicit=True
    )
    assert resolved.mode is ReviewMode.LOCAL


def test_a_plain_decision_is_no_switch() -> None:
    ledger = ObservedLedger()
    _switch(ledger, None)
    assert review_mode_switches(replay(ledger.records)) == ()


def test_resolution_from_switches_matches_the_projection_reading() -> None:
    projection, _ = _projection(ReviewMode.AI_POWERED, ReviewMode.LOCAL, ReviewMode.AI_POWERED)
    switches = review_mode_switches(projection)
    assert all(type(switch) is ReviewModeSwitch for switch in switches)
    assert [switch.mode for switch in switches] == [
        ReviewMode.AI_POWERED,
        ReviewMode.LOCAL,
        ReviewMode.AI_POWERED,
    ]
    for setting in ConversationReview:
        assert conversation_review_mode(
            projection, setting, setting_explicit=True
        ) == conversation_review_mode_from_switches(switches, setting, setting_explicit=True)
