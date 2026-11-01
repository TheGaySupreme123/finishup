"""A review that times out or ends with its outcome unknown is not a FinishUP fault.

``_map_egress_to_final`` raised ``invalid_semantic_provenance`` for a blocked timeout, a blocked
transport failure (a gateway call that raised, or the reviewer conversation's deadline or lost
lease) and an unknown attempt: each of those pairs needs the attempt's provenance, and a refusal
carries none. The durable runner caught the raise and recorded ``failed/coordinator_failure``,
which names a FinishUP fault and drops the conversation's reviewer record.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import cast

import pytest

from finishup.application.check import FinalSemanticEvaluation
from finishup.application.egress import (
    SemanticEgressAttemptUnknown,
    SemanticEgressAwaitingHuman,
    SemanticEgressBlocked,
    SemanticEgressReply,
    SemanticEgressResult,
)
from finishup.application.reviewer_loop import ReviewOutcome
from finishup.application.reviewer_run import (
    ReviewerRun,
    _terminal,  # pyright: ignore[reportPrivateUsage]
)
from finishup.application.semantic_attempts import (
    SemanticAttemptAccounting,
    is_retriable_semantic_outcome,
    run_durable_semantic_attempts,
)
from finishup.domain.findings import SamplingParams, SemanticDispatchKind
from finishup.domain.privacy import PrivacyOutcome, PrivacyReason
from finishup.domain.reviewer_reads import ReviewerRecord
from finishup.ports.ledger import SemanticAttemptHandle
from finishup.ports.semantic import Deadline, ProviderAttemptProvenance, SemanticResultReply
from finishup.protocol.models import SemanticReason, SemanticStatus
from finishup.service.ready_composition import (
    _map_egress_to_final,  # pyright: ignore[reportPrivateUsage]
    _with_reviewer,  # pyright: ignore[reportPrivateUsage]
)
from unit.application import test_semantic_attempts as attempts

_DIGEST = "sha256:" + "a" * 64
_REQUEST = "req_71000000-0000-4000-8000-000000000001"
_PROPOSAL = "ppr_71000000-0000-4000-8000-000000000001"
_RECEIPT = "egr_71000000-0000-4000-8000-000000000001"
_ATTEMPT = "att_71000000-0000-4000-8000-000000000001"
_ITEM = "evt_71000000-0000-4000-8000-000000000001"
_RECORD = ReviewerRecord(1, (), "deadline", None)
_NOT_CERTIFIED = (SemanticStatus.UNAVAILABLE, SemanticReason.RECEIPT_PERSISTENCE_UNKNOWN)
_TIMED_OUT = (SemanticStatus.TIMEOUT, SemanticReason.PROVIDER_TIMEOUT)


def _sent_exchange() -> SemanticEgressReply:
    """Exchange 1 of a conversation: sent under its own receipt and answered with a read."""

    provenance = ProviderAttemptProvenance(
        provider="provider",
        endpoint_profile_id="endpoint",
        endpoint_profile_version="1.0.0",
        model="model",
        sdk_version="1.0.0",
        prompt_digest=_DIGEST,
        schema_digest=_DIGEST,
        policy_digest=_DIGEST,
        privacy_policy_digest=_DIGEST,
        sampling_params=SamplingParams(1),
        latency_ms=1,
        status=SemanticStatus.SUCCEEDED,
    )
    return SemanticEgressReply(
        SemanticResultReply({"action": "read_file"}, provenance),
        {
            "request_id": _REQUEST,
            "privacy_proposal_id": _PROPOSAL,
            "authorization_id": "aut_71000000-0000-4000-8000-000000000001",
            "dispatch_kind": SemanticDispatchKind.EXTERNAL,
            "case_digest": _DIGEST,
            "privacy_receipt_id": _RECEIPT,
            "request_commitment": "hmac-sha256:" + "b" * 64,
            "withheld_item_ids": (),
            "redacted_span_count": 0,
            "redacted_values": (),
        },
        None,
        None,
    )


def _blocked_timeout() -> SemanticEgressBlocked:
    return SemanticEgressBlocked(_REQUEST, PrivacyOutcome.TIMEOUT, PrivacyReason.DEADLINE_EXPIRED)


def _awaiting() -> SemanticEgressAwaitingHuman:
    return SemanticEgressAwaitingHuman(
        _REQUEST, _PROPOSAL, _DIGEST, datetime(2030, 1, 1, tzinfo=UTC)
    )


def _gateway_raised() -> SemanticEgressBlocked:
    return SemanticEgressBlocked(
        _REQUEST,
        PrivacyOutcome.TRANSPORT_FAILED,
        PrivacyReason.OUTCOME_UNKNOWN,
        privacy_proposal_id=_PROPOSAL,
        dispatch_attempted=True,
    )


def _final(result: SemanticEgressResult) -> FinalSemanticEvaluation:
    """The real mapping, then the conversation's record, exactly as the durable dispatch does."""

    return _with_reviewer(
        _map_egress_to_final(result, attempt_id=_ATTEMPT),
        ReviewerRun(result, _RECORD, frozenset(), {}, {}),
    )


@pytest.mark.parametrize(
    "result",
    (
        _blocked_timeout(),
        SemanticEgressBlocked(_REQUEST, PrivacyOutcome.TIMEOUT, PrivacyReason.PROVIDER_TIMEOUT),
        _gateway_raised(),
        SemanticEgressBlocked(
            _REQUEST,
            PrivacyOutcome.TRANSPORT_FAILED,
            PrivacyReason.TRANSPORT_FAILED,
            withheld_item_ids=(_ITEM,),
        ),
        SemanticEgressBlocked(
            _REQUEST, PrivacyOutcome.TRANSPORT_FAILED, PrivacyReason.PROVIDER_UNAVAILABLE
        ),
        SemanticEgressAttemptUnknown(_REQUEST, _PROPOSAL, withheld_item_ids=(_ITEM,)),
    ),
    ids=(
        "deadline_expired",
        "timeout",
        "gateway_raised",
        "transport_failed",
        "provider_unavailable",
        "attempt_unknown",
    ),
)
def test_an_outcome_with_no_attempt_to_certify_is_recorded_without_a_fault(
    result: SemanticEgressResult,
) -> None:
    final = _final(result)
    # Timeout and transport pairs need provenance a refusal does not carry, so the pair is the
    # one the provenance rules leave; it is never retried, so nothing of unknown fate is resent.
    assert (final.status, final.reason) == _NOT_CERTIFIED
    assert final.provenance is None
    assert not is_retriable_semantic_outcome(final.status, final.reason)
    assert final.reviewer is _RECORD
    assert final.semantic_withheld_item_ids == getattr(result, "withheld_item_ids", ())


@pytest.mark.parametrize(
    ("reason", "results", "expected"),
    (
        # Nothing of this run was sent: the deadline passed first, or an earlier run of the job
        # left a step this run cannot account for.
        ("deadline", (), _NOT_CERTIFIED),
        ("interrupted", (), _NOT_CERTIFIED),
        # Exchange 1 was sent; exchange 2 met the deadline before it was. The conversation timed
        # out after a sent exchange, under that exchange's provenance.
        ("reviewer_exchange_not_sent", ("sent", "timeout"), _TIMED_OUT),
        ("deadline", ("sent", "awaiting"), _TIMED_OUT),
        # Exchange 2's gateway call raised, or the step store refused: its fate is unknown.
        ("reviewer_exchange_not_sent", ("sent", "gateway_raised"), _NOT_CERTIFIED),
        ("step_refused", ("sent",), _NOT_CERTIFIED),
    ),
)
def test_a_conversation_without_a_conclusion_keeps_its_record_and_names_no_fault(
    reason: str, results: tuple[str, ...], expected: tuple[SemanticStatus, SemanticReason]
) -> None:
    build = {
        "sent": _sent_exchange,
        "timeout": _blocked_timeout,
        "awaiting": _awaiting,
        "gateway_raised": _gateway_raised,
    }
    outcome = ReviewOutcome("incomplete", None, reason, (), 2, frozenset(), {})
    terminal = _terminal(outcome, [build[name]() for name in results], _REQUEST, None)
    final = _final(terminal)
    assert (final.status, final.reason) == expected
    assert final.reviewer is _RECORD
    if expected == _TIMED_OUT:
        assert final.provenance is not None
        assert final.provenance.privacy_receipt_id == _RECEIPT
        assert (final.provenance.status, final.provenance.reason) == _TIMED_OUT
    else:
        assert final.provenance is None


@pytest.mark.anyio
@pytest.mark.parametrize(
    ("results", "expected"),
    ((("timeout",), _NOT_CERTIFIED), (("sent", "timeout"), _TIMED_OUT)),
)
async def test_the_durable_runner_records_the_outcome_and_the_reviewer_record(
    results: tuple[str, ...], expected: tuple[SemanticStatus, SemanticReason]
) -> None:
    """End to end through the durable attempt runner, as the check's review job runs it."""

    build = {"sent": _sent_exchange, "timeout": _blocked_timeout}
    ledger = attempts._FakeLedger(  # pyright: ignore[reportPrivateUsage]
        attempts._queued_job(),  # pyright: ignore[reportPrivateUsage]
        attempts._lease(),  # pyright: ignore[reportPrivateUsage]
    )

    async def dispatch(
        handle: SemanticAttemptHandle, deadline: Deadline
    ) -> FinalSemanticEvaluation:
        del handle, deadline
        outcome = ReviewOutcome(
            "incomplete", None, "reviewer_exchange_not_sent", (), 2, frozenset(), {}
        )
        return _final(_terminal(outcome, [build[name]() for name in results], _REQUEST, None))

    def build_final(
        status: SemanticStatus,
        reason: SemanticReason,
        evaluation: object | None,
        accounting: SemanticAttemptAccounting,
    ) -> object:
        del accounting
        return status, reason, evaluation

    status, reason, evaluation = cast(
        tuple[SemanticStatus, SemanticReason, object | None],
        await run_durable_semantic_attempts(
            ledger=ledger,
            lease=ledger.lease,
            job=ledger.job,
            deadline=Deadline(datetime(2030, 1, 1, tzinfo=UTC), 1000.0),
            max_retries=0,
            now_monotonic=lambda: 0.0,
            dispatch=dispatch,
            publish_success_response=attempts._publish_response,  # pyright: ignore[reportPrivateUsage]
            sleep=lambda _: attempts._async_noop(),  # pyright: ignore[reportPrivateUsage]
            build_final=build_final,
        ),
    )
    assert (status, reason) == expected
    assert type(evaluation) is FinalSemanticEvaluation
    assert evaluation.reviewer is _RECORD
    assert ledger.job.terminal_code is expected[1]
