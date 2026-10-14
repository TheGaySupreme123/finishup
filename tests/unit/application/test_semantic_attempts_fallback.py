"""Issue #582: the primary/fallback endpoint pair inside one durable AI-powered review job.

The fake ledger and scripted dispatch come from ``test_semantic_attempts``; this file only adds a
second scripted dispatch for the fallback endpoint and reads which one each ordinal reached.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from types import SimpleNamespace
from typing import cast

import pytest

from finishup.application.semantic_attempts import (
    SemanticAttemptAccounting,
    SemanticAttemptDispatch,
    SemanticAttemptUsage,
    SemanticEndpointPlan,
    SemanticFallbackPlan,
    attempt_accounting_to_json,
    endpoint_role_for_ordinal,
    run_durable_semantic_attempts,
)
from finishup.domain.findings import SemanticFailureClass
from finishup.ports.ledger import AttemptOutcome, SemanticAttemptHandle, SemanticAttemptRecord
from finishup.ports.semantic import Deadline
from finishup.protocol.models import SemanticReason, SemanticStatus
from unit.application.test_semantic_attempts import (
    _ATT1,  # pyright: ignore[reportPrivateUsage]
    _ATT2,  # pyright: ignore[reportPrivateUsage]
    _ATT3,  # pyright: ignore[reportPrivateUsage]
    _INVALID,  # pyright: ignore[reportPrivateUsage]
    _JOB,  # pyright: ignore[reportPrivateUsage]
    _SUCCESS,  # pyright: ignore[reportPrivateUsage]
    _async_noop,  # pyright: ignore[reportPrivateUsage]
    _build_tuple,  # pyright: ignore[reportPrivateUsage]
    _Eval,  # pyright: ignore[reportPrivateUsage]
    _FakeLedger,  # pyright: ignore[reportPrivateUsage]
    _lease,  # pyright: ignore[reportPrivateUsage]
    _publish_response,  # pyright: ignore[reportPrivateUsage]
    _queued_job,  # pyright: ignore[reportPrivateUsage]
    _run,  # pyright: ignore[reportPrivateUsage]
)

_ATT4 = "att_40000000-0000-4000-8000-000000000004"
_ATT5 = "att_40000000-0000-4000-8000-000000000005"

_TRANSPORT = _Eval(SemanticStatus.UNAVAILABLE, SemanticReason.TRANSPORT_UNAVAILABLE)
_TIMEOUT = _Eval(SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
_QUOTA = _Eval(SemanticStatus.UNAVAILABLE, SemanticReason.PROVIDER_QUOTA_EXHAUSTED)
_UNKNOWN = _Eval(SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN)
_REFUSED = _Eval(SemanticStatus.REFUSED, SemanticReason.PROVIDER_REFUSED)
_SCHEMA_INVALID = _Eval(SemanticStatus.INVALID, SemanticReason.RESPONSE_SCHEMA_INVALID)


def _plan(
    *,
    primary_retries: int = 2,
    fallback_retries: int = 2,
    predispatch: SemanticReason | None = None,
) -> SemanticFallbackPlan:
    return SemanticFallbackPlan(
        SemanticEndpointPlan(
            "primary",
            "openai-codex",
            "gpt-5.6-sol",
            "codex-chatgpt-subscription",
            "1.0.0",
            primary_retries,
        ),
        SemanticEndpointPlan(
            "fallback",
            "fireworks",
            "accounts/fireworks/models/minimax-m3",
            "fireworks-responses",
            "1.0.0",
            fallback_retries,
        ),
        predispatch,
    )


@dataclass(frozen=True, slots=True)
class _Outcome:
    status: SemanticStatus
    reason: SemanticReason
    accounting: SemanticAttemptAccounting
    primary: tuple[str, ...]
    fallback: tuple[str, ...]
    sleeps: tuple[float, ...]


async def _run_paired(
    ledger: _FakeLedger,
    primary_script: list[_Eval],
    fallback_script: list[_Eval],
    *,
    plan: SemanticFallbackPlan,
    max_retries: int | None = None,
) -> _Outcome:
    primary_calls: list[str] = []
    fallback_calls: list[str] = []
    sleeps: list[float] = []

    async def dispatch(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        primary_calls.append(handle.attempt_id)
        assert primary_script, "primary_dispatch_past_script"
        return primary_script.pop(0)

    async def dispatch_fallback(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        fallback_calls.append(handle.attempt_id)
        assert fallback_script, "fallback_dispatch_past_script"
        return fallback_script.pop(0)

    async def sleep(delay: float) -> None:
        sleeps.append(delay)

    result = cast(
        tuple[SemanticStatus, SemanticReason, SemanticAttemptAccounting],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=plan.primary.max_retries if max_retries is None else max_retries,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=_publish_response,
            sleep=sleep,
            build_final=_build_tuple,
            fallback=plan,
            dispatch_fallback=dispatch_fallback,
        ),
    )
    return _Outcome(
        result[0],
        result[1],
        result[2],
        tuple(primary_calls),
        tuple(fallback_calls),
        tuple(sleeps),
    )


def _row(attempt_id: str, ordinal: int, reason: SemanticReason) -> SemanticAttemptRecord:
    return SemanticAttemptRecord(
        _JOB,
        attempt_id,
        ordinal,
        f"req_40000000-0000-4000-8000-{ordinal:012x}",
        "expired",
        reason,
        None,
    )


@pytest.mark.anyio
async def test_two_primary_transport_failures_engage_the_fallback_which_succeeds() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(ledger, [_TRANSPORT, _TRANSPORT], [_SUCCESS], plan=_plan())

    assert outcome.primary == (_ATT1, _ATT2)
    assert outcome.fallback == (_ATT3,)
    assert (outcome.status, outcome.reason) == (
        SemanticStatus.SUCCEEDED,
        SemanticReason.SEMANTIC_COMPLETED,
    )
    assert ledger.selected == _ATT3
    assert ledger.job.state == "succeeded"
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.EXPIRED, SemanticReason.TRANSPORT_UNAVAILABLE),
        (_ATT2, AttemptOutcome.EXPIRED, SemanticReason.TRANSPORT_UNAVAILABLE),
        (_ATT3, AttemptOutcome.RESPONSE_DURABLE, None),
    ]
    # A fallback is a different endpoint: no transient backoff before it.
    assert all(delay == 0.0 for delay in outcome.sleeps)

    accounting = outcome.accounting
    assert accounting.attempted_count == 3
    assert accounting.selected_attempt_id == _ATT3
    assert accounting.exhausted is False
    assert accounting.terminal_reason_counts == (("transport_unavailable", 2),)
    primary = accounting.endpoint("primary")
    fallback = accounting.endpoint("fallback")
    assert primary is not None and fallback is not None
    assert primary.attempted_count == 2
    assert primary.last_terminal_reason == "transport_unavailable"
    assert primary.terminal_reason_counts == (("transport_unavailable", 2),)
    assert primary.predispatch_reason is None
    assert (primary.provider_id, primary.model_id) == ("openai-codex", "gpt-5.6-sol")
    assert fallback.attempted_count == 1
    assert fallback.last_terminal_reason is None
    assert fallback.terminal_reason_counts == ()
    assert (fallback.provider_id, fallback.endpoint_profile_id) == (
        "fireworks",
        "fireworks-responses",
    )


@pytest.mark.anyio
async def test_one_primary_quota_exhaustion_engages_the_fallback_immediately() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(ledger, [_QUOTA], [_SUCCESS], plan=_plan())

    assert outcome.primary == (_ATT1,)
    assert outcome.fallback == (_ATT2,)
    assert outcome.status is SemanticStatus.SUCCEEDED
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.EXPIRED, SemanticReason.PROVIDER_QUOTA_EXHAUSTED),
        (_ATT2, AttemptOutcome.RESPONSE_DURABLE, None),
    ]
    primary = outcome.accounting.endpoint("primary")
    assert primary is not None
    assert primary.attempted_count == 1
    assert primary.last_terminal_reason == "provider_quota_exhausted"


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("script", "expected", "primary_attempts"),
    (
        ([_INVALID, _INVALID], _INVALID, 2),
        ([_SCHEMA_INVALID], _SCHEMA_INVALID, 1),
        ([_REFUSED], _REFUSED, 1),
    ),
    ids=("response_content_invalid", "response_schema_invalid", "provider_refused"),
)
async def test_content_shaped_primary_failures_never_reach_the_fallback(
    script: list[_Eval], expected: _Eval, primary_attempts: int
) -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(ledger, script, [_SUCCESS], plan=_plan())

    assert outcome.fallback == ()
    assert len(outcome.primary) == primary_attempts
    assert (outcome.status, outcome.reason) == (expected.status, expected.reason)
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is expected.reason
    fallback = outcome.accounting.endpoint("fallback")
    assert fallback is not None
    assert fallback.attempted_count == 0
    primary = outcome.accounting.endpoint("primary")
    assert primary is not None
    assert primary.attempted_count == primary_attempts
    assert primary.last_terminal_reason == expected.reason.value


@pytest.mark.anyio
async def test_outcome_unknown_never_engages_the_fallback() -> None:
    # The primary may in fact have served; asking a second endpoint would double-dispatch.
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(ledger, [_UNKNOWN], [_SUCCESS], plan=_plan())

    assert outcome.primary == (_ATT1,)
    assert outcome.fallback == ()
    assert (outcome.status, outcome.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.OUTCOME_UNKNOWN,
    )
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.FAILED, SemanticReason.OUTCOME_UNKNOWN),
    ]
    assert ledger.job.terminal_code is SemanticReason.OUTCOME_UNKNOWN


@pytest.mark.anyio
@pytest.mark.parametrize(
    "failure_class",
    (SemanticFailureClass.AUTHENTICATION, SemanticFailureClass.AUTHORIZATION),
)
@pytest.mark.parametrize("primary_retries", (0, 2), ids=("no_retry_budget", "retry_budget"))
async def test_a_rejected_primary_credential_never_engages_the_fallback(
    failure_class: SemanticFailureClass, primary_retries: int
) -> None:
    # Issue #742: the public reason is the transport catch-all, which licenses the fallback, but
    # the adapter's class says the provider refused this binding. With no retry budget the walk
    # engages on the first licensing failure, so only the class veto keeps the case on one
    # endpoint; with a budget, the retry veto must end the job the same way.
    rejected = _Eval(
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
        provenance=SimpleNamespace(failure_class=failure_class),
    )
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(
        ledger, [rejected], [_SUCCESS], plan=_plan(primary_retries=primary_retries)
    )

    assert outcome.primary == (_ATT1,)
    assert outcome.fallback == ()
    assert (outcome.status, outcome.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.TRANSPORT_UNAVAILABLE,
    )
    assert ledger.outcomes == [
        (_ATT1, AttemptOutcome.FAILED, SemanticReason.TRANSPORT_UNAVAILABLE),
    ]
    assert ledger.job.state == "failed"
    fallback = outcome.accounting.endpoint("fallback")
    assert fallback is not None
    assert fallback.attempted_count == 0


@pytest.mark.anyio
async def test_a_single_fallback_failure_keeps_its_exact_reason_under_its_own_budget() -> None:
    # fallback max_retries=0: exactly one fallback attempt, and its own reason survives — it
    # never inherits the primary's spent budget as ``retry_budget_exhausted``.
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(
        ledger,
        [_TRANSPORT, _TRANSPORT],
        [_TIMEOUT, _SUCCESS],
        plan=_plan(primary_retries=2, fallback_retries=0),
    )

    assert outcome.primary == (_ATT1, _ATT2)
    assert outcome.fallback == (_ATT3,)
    assert (outcome.status, outcome.reason) == (
        SemanticStatus.TIMEOUT,
        SemanticReason.PROVIDER_TIMEOUT,
    )
    assert ledger.outcomes is not None
    assert ledger.outcomes[-1] == (_ATT3, AttemptOutcome.FAILED, SemanticReason.PROVIDER_TIMEOUT)
    assert ledger.job.state == "failed"
    assert ledger.job.terminal_code is SemanticReason.PROVIDER_TIMEOUT
    assert outcome.accounting.attempted_count == 3
    assert outcome.accounting.exhausted is True
    fallback = outcome.accounting.endpoint("fallback")
    assert fallback is not None
    assert fallback.attempted_count == 1
    assert fallback.last_terminal_reason == "provider_timeout"


@pytest.mark.anyio
async def test_the_fallback_budget_is_its_own_not_the_primary_remainder() -> None:
    # Primary spent all three of its attempts; the fallback still gets its full three.
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(
        ledger,
        [_TRANSPORT, _TRANSPORT],
        [_TIMEOUT, _TIMEOUT, _TIMEOUT, _SUCCESS],
        plan=_plan(primary_retries=2, fallback_retries=2),
    )

    assert outcome.primary == (_ATT1, _ATT2)
    assert outcome.fallback == (_ATT3, _ATT4, _ATT5)
    assert (outcome.status, outcome.reason) == (
        SemanticStatus.UNAVAILABLE,
        SemanticReason.RETRY_BUDGET_EXHAUSTED,
    )
    assert outcome.accounting.attempted_count == 5
    assert outcome.accounting.exhausted is True
    fallback = outcome.accounting.endpoint("fallback")
    assert fallback is not None
    assert fallback.attempted_count == 3
    # The exhausting attempt is closed with the mapped exhaustion code, exactly as the
    # single-endpoint loop closes its own last attempt.
    assert fallback.terminal_reason_counts == (
        ("provider_timeout", 2),
        ("retry_budget_exhausted", 1),
    )
    assert fallback.last_terminal_reason == "retry_budget_exhausted"


@pytest.mark.anyio
async def test_role_is_derived_from_durable_rows_across_a_replay() -> None:
    # Two primary transport failures are already durable and the job is queued again; a fresh
    # loop with no memory of them must send the resumed attempt to the fallback.
    rows = (
        _row(_ATT1, 1, SemanticReason.TRANSPORT_UNAVAILABLE),
        _row(_ATT2, 2, SemanticReason.TRANSPORT_UNAVAILABLE),
    )
    plan = _plan()
    assert endpoint_role_for_ordinal(rows, plan, 1) == "primary"
    assert endpoint_role_for_ordinal(rows, plan, 2) == "primary"
    assert endpoint_role_for_ordinal(rows, plan, 3) == "fallback"

    ledger = _FakeLedger(_queued_job(attempt_count=2), _lease())
    assert ledger.attempts is not None
    for row in rows:
        ledger.attempts[row.attempt_id] = row
    outcome = await _run_paired(ledger, [], [_SUCCESS], plan=plan)

    assert outcome.primary == ()
    assert outcome.fallback == (_ATT3,)
    assert outcome.status is SemanticStatus.SUCCEEDED
    assert outcome.accounting.attempted_count == 3
    primary = outcome.accounting.endpoint("primary")
    fallback = outcome.accounting.endpoint("fallback")
    assert primary is not None and fallback is not None
    assert (primary.attempted_count, fallback.attempted_count) == (2, 1)


@pytest.mark.anyio
async def test_replay_after_a_durable_quota_row_resumes_on_the_fallback() -> None:
    ledger = _FakeLedger(_queued_job(attempt_count=1), _lease())
    assert ledger.attempts is not None
    ledger.attempts[_ATT1] = _row(_ATT1, 1, SemanticReason.PROVIDER_QUOTA_EXHAUSTED)
    outcome = await _run_paired(ledger, [], [_SUCCESS], plan=_plan())

    assert outcome.primary == ()
    assert outcome.fallback == (_ATT2,)
    assert outcome.status is SemanticStatus.SUCCEEDED


@pytest.mark.anyio
async def test_primary_predispatch_reason_sends_the_first_attempt_to_the_fallback() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    outcome = await _run_paired(
        ledger,
        [],
        [_SUCCESS],
        plan=_plan(predispatch=SemanticReason.CREDENTIAL_UNAVAILABLE),
    )

    assert outcome.primary == ()
    assert outcome.fallback == (_ATT1,)
    assert outcome.status is SemanticStatus.SUCCEEDED
    primary = outcome.accounting.endpoint("primary")
    fallback = outcome.accounting.endpoint("fallback")
    assert primary is not None and fallback is not None
    assert primary.attempted_count == 0
    assert primary.predispatch_reason == "credential_unavailable"
    assert primary.last_terminal_reason is None
    assert fallback.attempted_count == 1
    assert fallback.predispatch_reason is None
    encoded = attempt_accounting_to_json(outcome.accounting)
    endpoints = cast(tuple[dict[str, object], ...], encoded["endpoint_attempts"])
    assert [item["role"] for item in endpoints] == ["primary", "fallback"]
    assert endpoints[0]["predispatch_reason"] == "credential_unavailable"
    assert endpoints[0]["attempted_count"] == 0


async def _start(
    ledger: _FakeLedger,
    *,
    fallback: SemanticFallbackPlan,
    dispatch_fallback: SemanticAttemptDispatch | None,
    max_retries: int,
) -> None:
    async def dispatch(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_not_expected")

    await run_durable_semantic_attempts(
        ledger=ledger,
        lease=ledger.lease,
        job=ledger.job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
        max_retries=max_retries,
        now_monotonic=lambda: 0.0,
        dispatch=dispatch,
        publish_success_response=_publish_response,
        sleep=lambda _: _async_noop(),
        build_final=_build_tuple,
        fallback=fallback,
        dispatch_fallback=dispatch_fallback,
    )


@pytest.mark.anyio
async def test_a_fallback_plan_requires_its_dispatch_and_a_matching_primary_budget() -> None:
    async def dispatch_fallback(handle: SemanticAttemptHandle, attempt_deadline: Deadline) -> _Eval:
        raise AssertionError("dispatch_fallback_not_expected")

    ledger = _FakeLedger(_queued_job(), _lease())
    with pytest.raises(ValueError, match="semantic_fallback_dispatch_missing"):
        await _start(ledger, fallback=_plan(), dispatch_fallback=None, max_retries=2)
    with pytest.raises(ValueError, match="semantic_fallback_dispatch_missing"):
        await _start(
            ledger,
            fallback=cast(SemanticFallbackPlan, object()),
            dispatch_fallback=dispatch_fallback,
            max_retries=2,
        )
    with pytest.raises(ValueError, match="semantic_fallback_budget_mismatch"):
        await _start(
            ledger,
            fallback=_plan(primary_retries=2),
            dispatch_fallback=dispatch_fallback,
            max_retries=1,
        )
    # Every refusal happens before the ledger is touched.
    assert ledger.renew_count == 0
    assert ledger.claim_calls == 0
    assert ledger.job.state == "queued"


@pytest.mark.anyio
async def test_without_a_plan_the_accounting_is_the_single_endpoint_shape() -> None:
    ledger = _FakeLedger(_queued_job(), _lease())
    status, reason, accounting = await _run(ledger, [_TRANSPORT, _SUCCESS], max_retries=2)

    assert (status, reason) == (SemanticStatus.SUCCEEDED, SemanticReason.SEMANTIC_COMPLETED)
    assert accounting.endpoint_attempts == ()
    assert accounting.endpoint("primary") is None
    assert accounting.endpoint("fallback") is None
    assert accounting == SemanticAttemptAccounting(
        attempted_count=2,
        selected_attempt_id=_ATT2,
        exhausted=False,
        terminal_reason_counts=(("transport_unavailable", 1),),
        attempt_usages=(
            SemanticAttemptUsage(_ATT1, 1, None),
            SemanticAttemptUsage(_ATT2, 2, None),
        ),
    )
    assert "endpoint_attempts" not in attempt_accounting_to_json(accounting)
    assert ledger.attempts is not None
    assert endpoint_role_for_ordinal(tuple(ledger.attempts.values()), None, 7) == "primary"
