"""A task-local wait cannot prove an expired physical attempt was never admitted."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from finishup.application.semantic_attempts import run_durable_semantic_attempts
from finishup.ports.semantic import Deadline
from finishup.protocol.models import SemanticReason, SemanticStatus
from unit.application import test_semantic_attempts as attempts
from unit.application import test_semantic_attempts_fallback as paired


@pytest.mark.anyio
@pytest.mark.parametrize("resumed", (False, True))
async def test_expired_attempt_preserves_uncertainty_despite_stale_wait(resumed: bool) -> None:
    ledger = attempts._FakeLedger(attempts._queued_job(), attempts._lease())  # pyright: ignore[reportPrivateUsage]
    if resumed:
        waiting = attempts._AwaitingEval(  # pyright: ignore[reportPrivateUsage]
            SemanticStatus.AWAITING_HUMAN,
            SemanticReason.HUMAN_APPROVAL_REQUIRED,
            attempts._Continuation(  # pyright: ignore[reportPrivateUsage]
                "ppr_40000000-0000-4000-8000-000000000005",
                attempts._ExpiresAt(datetime(2030, 1, 1, tzinfo=UTC)),  # pyright: ignore[reportPrivateUsage]
            ),
        )
        await attempts._run(ledger, [waiting], max_retries=1)  # pyright: ignore[reportPrivateUsage]
        assert ledger.disclosure_waits

    provider_ids = tuple(ledger.provider_ids or ())
    attempt_ids = tuple(ledger.attempt_ids or ())

    async def forbidden_dispatch(*args: object) -> attempts._Eval:  # pyright: ignore[reportPrivateUsage]
        raise AssertionError("expired replay must not re-enter admission or call a provider")

    result = await run_durable_semantic_attempts(
        ledger=ledger,
        lease=ledger.lease,
        job=ledger.job,
        deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1.0),
        max_retries=1,
        now_monotonic=lambda: 2.0,
        dispatch=forbidden_dispatch,
        dispatch_fallback=forbidden_dispatch,
        fallback=paired._plan(primary_retries=1),  # pyright: ignore[reportPrivateUsage]
        publish_success_response=attempts._publish_response,  # pyright: ignore[reportPrivateUsage]
        sleep=lambda _: attempts._async_noop(),  # pyright: ignore[reportPrivateUsage]
        build_final=attempts._build_tuple,  # pyright: ignore[reportPrivateUsage]
    )

    assert isinstance(result, tuple)
    assert result[:2] == (
        (SemanticStatus.UNAVAILABLE, SemanticReason.OUTCOME_UNKNOWN)
        if resumed
        else (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)
    )
    assert tuple(ledger.provider_ids or ()) == provider_ids
    assert tuple(ledger.attempt_ids or ()) == attempt_ids
    assert ledger.job.state == "failed"
