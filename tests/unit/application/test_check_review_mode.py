"""How one check resolves its task's review mode, and what it records (ADR-049)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, Literal

import pytest

from builders.observed_runs import ObservedLedger
from finishup.application.check import (
    _resolve_check_review_mode,  # pyright: ignore[reportPrivateUsage]
)
from finishup.domain.events import CheckReviewMode, DecisionRecordedPayload, EventSchema, ReviewMode
from finishup.domain.privacy import ConversationReview
from finishup.domain.values import EventId, actor_id
from finishup.kernel.reducers import replay
from finishup.kernel.review_mode import ConversationReviewContext
from finishup.protocol.models import CheckRequest

_REQUEST: dict[str, Any] = {
    "protocol_version": "0.1",
    "schema_version": "1.0.0",
    "request_id": "req_00000000-0000-4000-8000-000000000001",
    "session_id": "ses_00000000-0000-4000-8000-000000000001",
    "writer_id": "wri_00000000-0000-4000-8000-000000000001",
    "expected_frontier": {"sequence": "0", "head_digest": "genesis"},
    "actor": {"actor_id": "harness:agent", "actor_type": "harness"},
    "client": {"kind": "cooperative_agent", "version": "0.1.0", "integration": "cooperative_mcp"},
}


def _request(mode: str, *, final_review: bool = False) -> CheckRequest:
    body = {**_REQUEST, "mode": mode, **({"final_review": True} if final_review else {})}
    return CheckRequest.model_validate(body)


def _frozen(*modes: ReviewMode) -> tuple[Any, tuple[EventId, ...]]:
    ledger = ObservedLedger()
    ids = tuple(
        ledger.append(
            EventSchema("decision_recorded", "1.1.0"),
            DecisionRecordedPayload(
                statement="Switch review.",
                rationale="Synthetic.",
                authority=actor_id("harness:agent"),
                review_mode=mode,
            ),
            observed=False,
        )
        for mode in modes
    )
    return SimpleNamespace(case=SimpleNamespace(projection=replay(ledger.records))), ids


def _resolve(
    mode: str,
    context: ConversationReviewContext | None,
    *switches: ReviewMode,
    explicit: bool = False,
    route: Literal["policy", "strict"] = "policy",
    final_review: bool = False,
    review_used: bool = False,
    review_enabled: bool = True,
) -> tuple[str | None, CheckReviewMode | None, str | None, tuple[EventId, ...]]:
    frozen, ids = _frozen(*switches)
    request, recorded, override = _resolve_check_review_mode(
        _request(mode, final_review=final_review),
        mode_explicit=explicit,
        frozen=frozen,
        context=context,
        route_profile=route,
        review_used=review_used,
        review_enabled=review_enabled,
    )
    return request.mode, recorded, override, ids


_HYBRID = ConversationReviewContext(ConversationReview.LOCAL_AGENT_OPT_IN, True, True)


def test_without_a_context_nothing_changes_and_nothing_is_recorded() -> None:
    assert _resolve("semantic_required", None)[:3] == ("semantic_required", None, None)


@pytest.mark.parametrize(
    "context",
    [
        ConversationReviewContext(ConversationReview.AI_POWERED, True, False),
        ConversationReviewContext(ConversationReview.LOCAL_ONLY, False, False),
    ],
)
def test_a_policy_that_predates_the_setting_keeps_released_checks(
    context: ConversationReviewContext,
) -> None:
    """Upgrade rule: no owner choice and no switch, so the released check runs unrecorded."""

    assert _resolve("semantic_required", context)[:3] == ("semantic_required", None, None)


def test_a_new_hybrid_task_checks_locally_on_a_route_that_did_not_require_review() -> None:
    mode, recorded, override, _ = _resolve("semantic_required", _HYBRID)
    assert mode == "deterministic_only"
    assert override == "optional"
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")


def test_an_opted_in_task_requests_review_and_names_its_switch() -> None:
    mode, recorded, override, (switch,) = _resolve(
        "semantic_if_configured", _HYBRID, ReviewMode.AI_POWERED
    )
    assert mode == "semantic_if_configured"
    assert override is None
    assert recorded == CheckReviewMode(
        ReviewMode.AI_POWERED, "conversation_switch", switch_event_id=switch
    )


def test_switching_back_runs_local_and_names_the_later_switch() -> None:
    mode, recorded, override, (_on, off) = _resolve(
        "semantic_required", _HYBRID, ReviewMode.AI_POWERED, ReviewMode.LOCAL
    )
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "conversation_switch", None, off)


def test_a_legacy_policy_task_that_opts_in_without_review_set_up_stays_local() -> None:
    context = ConversationReviewContext(ConversationReview.LOCAL_ONLY, False, False)
    mode, recorded, override, (switch,) = _resolve(
        "semantic_required", context, ReviewMode.AI_POWERED
    )
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(
        ReviewMode.LOCAL, "conversation_switch", "ai_review_not_set_up", switch
    )


def test_an_explicit_local_only_owner_keeps_an_opted_in_task_local() -> None:
    context = ConversationReviewContext(ConversationReview.LOCAL_ONLY, False, True)
    _mode, recorded, _override, _ = _resolve("semantic_required", context, ReviewMode.AI_POWERED)
    assert recorded is not None
    assert recorded.local_reason == "owner_local_only"


def test_a_strict_route_keeps_an_opted_in_task_local() -> None:
    mode, recorded, override, _ = _resolve(
        "semantic_required", _HYBRID, ReviewMode.AI_POWERED, route="strict"
    )
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded is not None
    assert recorded.local_reason == "route_local_only"


def test_an_explicit_review_request_is_that_checks_own_request() -> None:
    mode, recorded, override, _ = _resolve("semantic_required", _HYBRID, explicit=True)
    assert (mode, override) == ("semantic_required", None)
    assert recorded == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")


def test_an_explicit_required_review_under_owner_local_only_stays_an_honest_gap() -> None:
    """The owner forbids the review; the requirement still bounds the result."""

    context = ConversationReviewContext(ConversationReview.LOCAL_ONLY, True, True)
    mode, recorded, override, _ = _resolve("semantic_required", context, explicit=True)
    assert (mode, override) == ("deterministic_only", "required")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request", "owner_local_only")
    mode, _recorded, override, _ = _resolve("semantic_if_configured", context, explicit=True)
    assert (mode, override) == ("deterministic_only", "optional")


def test_an_explicit_local_check_in_a_local_task_is_no_missing_review() -> None:
    mode, recorded, override, _ = _resolve("deterministic_only", _HYBRID, explicit=True)
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request")
    # In an AI-powered task an explicit local check keeps the configured requirement.
    _mode, _recorded, override, _ = _resolve(
        "deterministic_only", _HYBRID, ReviewMode.AI_POWERED, explicit=True
    )
    assert override is None


@pytest.mark.parametrize("explicit", [True, False])
def test_under_every_task_a_switch_to_local_keeps_the_required_review(explicit: bool) -> None:
    """Review round 1 (P2-1): explicit ``ai_powered`` and the released reading.

    The no-mode check keeps its configured mode and verification policy (no override), so a
    missing review stays the bounding gap it was; the recorded mode names the owner's setting,
    not the agent's switch.
    """

    context = ConversationReviewContext(ConversationReview.AI_POWERED, True, explicit)
    mode, recorded, override, _ = _resolve(
        "semantic_required", context, ReviewMode.AI_POWERED, ReviewMode.LOCAL
    )
    assert (mode, override) == ("semantic_required", None)
    assert recorded == CheckReviewMode(ReviewMode.AI_POWERED, "conversation_default")
    # A check that names local checks runs local but cannot lower the requirement either.
    mode, recorded, override, _ = _resolve(
        "deterministic_only", context, ReviewMode.LOCAL, explicit=True
    )
    assert (mode, override) == ("deterministic_only", None)
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request")


def test_the_closing_review_of_a_task_that_switched_back_runs_ai_powered() -> None:
    """Review round 1 (P2-2a): the Stop gate's ``final_review: true`` with no mode is honoured."""

    mode, recorded, override, _ = _resolve(
        "semantic_required",
        _HYBRID,
        ReviewMode.AI_POWERED,
        ReviewMode.LOCAL,
        final_review=True,
        review_used=True,
    )
    assert (mode, override) == ("semantic_required", None)
    assert recorded == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")


def test_the_closing_review_after_one_requested_review_runs_ai_powered() -> None:
    """Review round 1 (P2-2b): no switch, one check that named an AI-powered mode."""

    mode, recorded, override, _ = _resolve(
        "semantic_if_configured", _HYBRID, final_review=True, review_used=True
    )
    assert (mode, override) == ("semantic_if_configured", None)
    assert recorded == CheckReviewMode(ReviewMode.AI_POWERED, "check_request")


def test_a_final_check_in_a_task_that_never_used_review_stays_local() -> None:
    mode, recorded, override, _ = _resolve("semantic_required", _HYBRID, final_review=True)
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "conversation_default")
    # A routine check after review was used stays in the task's mode.
    mode, _recorded, _override, _ = _resolve("semantic_required", _HYBRID, review_used=True)
    assert mode == "deterministic_only"


def test_the_closing_review_under_owner_local_only_stays_local_and_says_why() -> None:
    context = ConversationReviewContext(ConversationReview.LOCAL_ONLY, True, True)
    mode, recorded, override, _ = _resolve(
        "semantic_required", context, final_review=True, review_used=True
    )
    # The recorded reason makes the closing review undeliverable rather than owed forever.
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request", "owner_local_only")


def test_an_explicit_review_request_on_a_strict_route_records_the_route() -> None:
    mode, recorded, override, _ = _resolve(
        "semantic_if_configured", _HYBRID, explicit=True, route="strict"
    )
    assert (mode, override) == ("semantic_if_configured", None)
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request", "route_local_only")


def test_review_turned_off_in_the_verification_settings_is_not_called_a_switch_back() -> None:
    mode, recorded, override, (switch,) = _resolve(
        "deterministic_only", _HYBRID, ReviewMode.AI_POWERED, review_enabled=False
    )
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(
        ReviewMode.LOCAL, "conversation_switch", "review_disabled", switch
    )


def test_an_unreadable_setting_fails_closed() -> None:
    """Review round 1 (P3): a failed read runs no review a no-mode check did not ask for.

    The configured requirement still decides (no override), so a required review stays a
    bounding gap; a check that named its mode keeps it and the gateway enforces the policy.
    """

    frozen, _ = _frozen()
    request, recorded, override = _resolve_check_review_mode(
        _request("semantic_required"), mode_explicit=False, frozen=frozen, context="unreadable"
    )
    assert (request.mode, recorded, override) == ("deterministic_only", None, None)
    request, recorded, override = _resolve_check_review_mode(
        _request("semantic_required"), mode_explicit=True, frozen=frozen, context="unreadable"
    )
    assert (request.mode, recorded, override) == ("semantic_required", None, None)


def test_the_closing_review_with_review_turned_off_says_it_cannot_run() -> None:
    mode, recorded, override, _ = _resolve(
        "deterministic_only",
        _HYBRID,
        ReviewMode.AI_POWERED,
        ReviewMode.LOCAL,
        final_review=True,
        review_used=True,
        review_enabled=False,
    )
    assert (mode, override) == ("deterministic_only", "optional")
    assert recorded == CheckReviewMode(ReviewMode.LOCAL, "check_request", "review_disabled")
