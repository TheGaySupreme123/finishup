"""Issue #582: the closed engagement rule and per-endpoint accounting as pure functions."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from finishup.application.semantic_attempts import (
    FALLBACK_PRIMARY_FAILURE_LIMIT,
    SemanticAttemptAccounting,
    SemanticEndpointAttempts,
    SemanticEndpointPlan,
    SemanticFallbackPlan,
    attempt_accounting_from_rows,
    attempt_accounting_to_json,
    endpoint_role_for_ordinal,
    is_fallback_licensing_outcome,
)
from finishup.ports.ledger import SemanticAttemptRecord, SemanticJobRecord
from finishup.ports.objects import ObjectKind, ObjectMetadata, ObjectRef
from finishup.protocol.models import VALID_SEMANTIC_REASONS, SemanticReason, SemanticStatus

_JOB = "job_40000000-0000-4000-8000-000000000001"
_LICENSING = (
    SemanticReason.PROVIDER_TIMEOUT,
    SemanticReason.TRANSPORT_UNAVAILABLE,
    SemanticReason.PROVIDER_RATE_LIMITED,
    SemanticReason.PROVIDER_QUOTA_EXHAUSTED,
)


def _primary(max_retries: int = 2) -> SemanticEndpointPlan:
    return SemanticEndpointPlan(
        "primary", "openai-codex", "gpt-5.6-sol", "codex-chatgpt-subscription", "1.0.0", max_retries
    )


def _fallback(max_retries: int = 2) -> SemanticEndpointPlan:
    return SemanticEndpointPlan(
        "fallback",
        "fireworks",
        "accounts/fireworks/models/minimax-m3",
        "fireworks-responses",
        "1.0.0",
        max_retries,
    )


def _plan(
    *,
    primary_retries: int = 2,
    fallback_retries: int = 2,
    predispatch: SemanticReason | None = None,
) -> SemanticFallbackPlan:
    return SemanticFallbackPlan(_primary(primary_retries), _fallback(fallback_retries), predispatch)


def _rows(*codes: SemanticReason | None) -> tuple[SemanticAttemptRecord, ...]:
    return tuple(
        SemanticAttemptRecord(
            _JOB,
            f"att_40000000-0000-4000-8000-{ordinal:012x}",
            ordinal,
            f"req_40000000-0000-4000-8000-{ordinal:012x}",
            "started" if code is None else "expired",
            code,
            None,
        )
        for ordinal, code in enumerate(codes, start=1)
    )


def _failed_job(
    attempt_count: int, terminal_code: SemanticReason = SemanticReason.RETRY_BUDGET_EXHAUSTED
) -> SemanticJobRecord:
    case_ref = ObjectRef(
        "obj_40000000-0000-4000-8000-000000000001",
        2,
        "hmac-sha256:" + "d" * 64,
        "sha256:" + "e" * 64,
        "yoetz-object/1",
        "bmk-1",
        ObjectMetadata(
            ObjectKind.SEMANTIC_CASE,
            "application/json",
            "tsk_40000000-0000-4000-8000-000000000001",
            datetime(2026, 1, 1, tzinfo=UTC),
        ),
    )
    return SemanticJobRecord(
        _JOB,
        "wri_40000000-0000-4000-8000-000000000001",
        "req_40000000-0000-4000-8000-000000000001",
        "sha256:" + "a" * 64,
        case_ref,
        "failed",
        attempt_count,
        None,
        None,
        None,
        None,
        None,
        None,
        terminal_code,
        datetime(2026, 1, 1, tzinfo=UTC),
    )


def test_the_fallback_licensing_set_is_exactly_the_could_not_serve_classes() -> None:
    assert FALLBACK_PRIMARY_FAILURE_LIMIT == 2
    licensed = {
        (status, reason)
        for status, reasons in VALID_SEMANTIC_REASONS.items()
        for reason in reasons
        if is_fallback_licensing_outcome(status, reason)
    }
    assert licensed == {
        (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT),
        (SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE),
        (SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_RATE_LIMITED),
        (SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED),
    }
    # A licensing reason paired with a status it does not belong to is not licensing.
    assert not is_fallback_licensing_outcome(SemanticStatus.FAILED, SemanticReason.PROVIDER_TIMEOUT)


def test_endpoint_plan_is_closed_over_role_identity_and_budget() -> None:
    assert _primary(99).budget == 3
    assert _fallback(0).budget == 1
    with pytest.raises(ValueError, match="semantic_endpoint_plan_invalid"):
        SemanticEndpointPlan(
            cast(str, "secondary"),  # type: ignore[arg-type]
            "fireworks",
            "m",
            "fireworks-responses",
            "1.0.0",
            1,
        )
    for field in ("provider_id", "model_id", "endpoint_profile_id", "endpoint_profile_version"):
        values: dict[str, object] = {
            "role": "fallback",
            "provider_id": "fireworks",
            "model_id": "m",
            "endpoint_profile_id": "fireworks-responses",
            "endpoint_profile_version": "1.0.0",
            "max_retries": 1,
        }
        values[field] = ""
        with pytest.raises(ValueError, match="semantic_endpoint_plan_invalid"):
            SemanticEndpointPlan(**values)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_retries_invalid"):
        _primary(-1)


def test_fallback_plan_requires_one_primary_then_one_fallback() -> None:
    plan = _plan(predispatch=SemanticReason.CREDENTIAL_UNAVAILABLE)
    assert plan.endpoint("primary") is plan.primary
    assert plan.endpoint("fallback") is plan.fallback
    with pytest.raises(ValueError, match="semantic_fallback_plan_invalid"):
        SemanticFallbackPlan(_fallback(), _primary())
    with pytest.raises(ValueError, match="semantic_fallback_plan_invalid"):
        SemanticFallbackPlan(_primary(), _primary())
    with pytest.raises(ValueError, match="semantic_fallback_plan_invalid"):
        SemanticFallbackPlan(cast(SemanticEndpointPlan, object()), _fallback())
    with pytest.raises(ValueError, match="semantic_fallback_plan_invalid"):
        SemanticFallbackPlan(
            _primary(), _fallback(), cast(SemanticReason, "credential_unavailable")
        )


def test_endpoint_attempts_and_accounting_reject_inconsistent_slices() -> None:
    with pytest.raises(ValueError, match="semantic_attempt_accounting_invalid"):
        SemanticEndpointAttempts(
            "primary", "p", "m", "e", "1.0.0", 1, (), None, "credential_unavailable"
        )
    with pytest.raises(ValueError, match="semantic_attempt_accounting_invalid"):
        SemanticEndpointAttempts("primary", "p", "m", "e", "1.0.0", -1, (), None, None)
    with pytest.raises(ValueError, match="semantic_attempt_accounting_invalid"):
        SemanticEndpointAttempts("primary", "p", "m", "e", "1.0.0", 1, (("x", 0),), None, None)
    with pytest.raises(ValueError, match="semantic_attempt_accounting_invalid"):
        SemanticAttemptAccounting(
            0, None, False, (), cast(tuple[SemanticEndpointAttempts, ...], (object(),))
        )
    with pytest.raises(ValueError, match="semantic_attempt_accounting_invalid"):
        SemanticAttemptAccounting(
            0, None, False, (), cast(tuple[SemanticEndpointAttempts, ...], [])
        )


@pytest.mark.parametrize("first", _LICENSING[:3], ids=lambda reason: reason.value)
def test_one_transient_failure_keeps_the_primary_two_engage_the_fallback(
    first: SemanticReason,
) -> None:
    plan = _plan()
    assert endpoint_role_for_ordinal(_rows(first), plan, 2) == "primary"
    for second in _LICENSING[:3]:
        assert endpoint_role_for_ordinal(_rows(first, second), plan, 3) == "fallback"
    # A content-shaped code between them does not count toward the limit.
    assert (
        endpoint_role_for_ordinal(_rows(first, SemanticReason.RESPONSE_CONTENT_INVALID), plan, 3)
        == "primary"
    )


def test_quota_exhaustion_and_a_spent_primary_budget_engage_on_their_own() -> None:
    assert endpoint_role_for_ordinal(
        _rows(SemanticReason.PROVIDER_QUOTA_EXHAUSTED), _plan(), 2
    ) == ("fallback")
    # Primary max_retries=0: one licensing failure already exhausts the primary's own budget.
    assert (
        endpoint_role_for_ordinal(
            _rows(SemanticReason.PROVIDER_TIMEOUT), _plan(primary_retries=0), 2
        )
        == "fallback"
    )
    # A started row without a code holds its slot without deciding anything.
    assert endpoint_role_for_ordinal(_rows(SemanticReason.PROVIDER_TIMEOUT, None), _plan(), 3) == (
        "primary"
    )


def test_role_reads_only_the_rows_before_the_ordinal_and_never_returns() -> None:
    plan = _plan()
    rows = _rows(
        SemanticReason.PROVIDER_TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    assert endpoint_role_for_ordinal(rows, plan, 3) == "fallback"
    assert endpoint_role_for_ordinal(rows, plan, 4) == "fallback"
    # Rows at or after the ordinal are invisible to it.
    assert endpoint_role_for_ordinal(rows, plan, 2) == "primary"
    assert endpoint_role_for_ordinal(
        (), _plan(predispatch=SemanticReason.CREDENTIAL_UNAVAILABLE), 1
    ) == ("fallback")
    assert endpoint_role_for_ordinal(rows, None, 1) == "primary"
    with pytest.raises(ValueError, match="attempt_ordinal_invalid"):
        endpoint_role_for_ordinal(rows, plan, 0)


def test_accounting_from_rows_splits_the_slices_along_the_same_walk() -> None:
    rows = _rows(
        SemanticReason.TRANSPORT_UNAVAILABLE,
        SemanticReason.PROVIDER_RATE_LIMITED,
        SemanticReason.PROVIDER_TIMEOUT,
    )
    plan = _plan(fallback_retries=0)
    accounting = attempt_accounting_from_rows(_failed_job(3), rows, max_retries=2, fallback=plan)

    assert accounting.attempted_count == 3
    # Budget after engagement: two primary attempts spent plus the fallback's own single slot.
    assert accounting.exhausted is True
    assert accounting.terminal_reason_counts == (
        ("provider_rate_limited", 1),
        ("provider_timeout", 1),
        ("transport_unavailable", 1),
    )
    primary, fallback = accounting.endpoint_attempts
    assert primary == SemanticEndpointAttempts(
        "primary",
        "openai-codex",
        "gpt-5.6-sol",
        "codex-chatgpt-subscription",
        "1.0.0",
        2,
        (("provider_rate_limited", 1), ("transport_unavailable", 1)),
        "provider_rate_limited",
        None,
    )
    assert fallback == SemanticEndpointAttempts(
        "fallback",
        "fireworks",
        "accounts/fireworks/models/minimax-m3",
        "fireworks-responses",
        "1.0.0",
        1,
        (("provider_timeout", 1),),
        "provider_timeout",
        None,
    )
    encoded = attempt_accounting_to_json(accounting)
    endpoints = cast(tuple[dict[str, object], ...], encoded["endpoint_attempts"])
    assert len(endpoints) == 2
    assert set(endpoints[1]) == {
        "role",
        "provider_id",
        "model_id",
        "endpoint_profile_id",
        "endpoint_profile_version",
        "attempted_count",
        "terminal_reason_counts",
        "last_terminal_reason",
        "predispatch_reason",
    }
    assert endpoints[1]["terminal_reason_counts"] == ({"reason": "provider_timeout", "count": 1},)


def test_accounting_before_engagement_uses_the_primary_budget_alone() -> None:
    rows = _rows(SemanticReason.PROVIDER_TIMEOUT, SemanticReason.RESPONSE_CONTENT_INVALID)
    accounting = attempt_accounting_from_rows(
        _failed_job(2, SemanticReason.RESPONSE_CONTENT_INVALID),
        rows,
        max_retries=2,
        fallback=_plan(),
    )
    assert accounting.exhausted is False
    primary, fallback = accounting.endpoint_attempts
    assert primary.attempted_count == 2
    assert primary.last_terminal_reason == "response_content_invalid"
    assert fallback.attempted_count == 0
    assert fallback.last_terminal_reason is None


def test_accounting_without_a_plan_is_unchanged() -> None:
    rows = _rows(SemanticReason.PROVIDER_TIMEOUT, SemanticReason.RETRY_BUDGET_EXHAUSTED)
    plain = attempt_accounting_from_rows(_failed_job(2), rows, max_retries=1)
    explicit = attempt_accounting_from_rows(_failed_job(2), rows, max_retries=1, fallback=None)
    assert plain == explicit
    assert plain.endpoint_attempts == ()
    assert plain.exhausted is True
    assert "endpoint_attempts" not in attempt_accounting_to_json(plain)
