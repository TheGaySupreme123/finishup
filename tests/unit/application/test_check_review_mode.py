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


def _request(mode: str) -> CheckRequest:
    return CheckRequest.model_validate({**_REQUEST, "mode": mode})


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
) -> tuple[str | None, CheckReviewMode | None, str | None, tuple[EventId, ...]]:
    frozen, ids = _frozen(*switches)
    request, recorded, override = _resolve_check_review_mode(
        _request(mode),
        mode_explicit=explicit,
        frozen=frozen,
        context=context,
        route_profile=route,
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
