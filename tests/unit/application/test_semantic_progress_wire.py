"""Structural semantic-progress wire projection (issue #571 item A2)."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from finishup.application.status import semantic_progress_wire
from finishup.ports.ledger import SemanticProgressRecord
from finishup.protocol.models import (
    SEMANTIC_PROGRESS_PHASE_RANK,
    SemanticProgressPhase,
    SemanticReason,
    StatusOperationPageModel,
    StatusSemanticProgressModel,
)

_JOB = "job_00000000-0000-4000-8000-000000005710"
_QUEUED = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
_DEADLINE = _QUEUED + timedelta(seconds=900)


def _record(**overrides: object) -> SemanticProgressRecord:
    values: dict[str, object] = {
        "job_id": _JOB,
        "attempt_ordinal": 1,
        "phase": SemanticProgressPhase.PROVIDER_SAMPLING,
        "phase_entered_at": _QUEUED + timedelta(seconds=3),
        "queued_at": _QUEUED,
        "deadline_at": _DEADLINE,
    }
    values.update(overrides)
    return SemanticProgressRecord(**values)  # type: ignore[arg-type]


def test_phase_order_is_the_documented_execution_order() -> None:
    assert [phase.value for phase in SemanticProgressPhase] == [
        "queued",
        "case_admitted",
        "runtime_starting",
        "account_model_validation",
        "provider_sampling",
        "response_validation",
        "cleanup",
        "terminal",
    ]
    assert [SEMANTIC_PROGRESS_PHASE_RANK[phase] for phase in SemanticProgressPhase] == list(
        range(1, 9)
    )


def test_active_progress_reports_elapsed_and_remaining_at_one_observation_time() -> None:
    observed = _QUEUED + timedelta(seconds=42, microseconds=123_456)
    wire = semantic_progress_wire(_record(), observed)

    assert wire == {
        "phase": "provider_sampling",
        "attempt_ordinal": "1",
        "queued_at": "2026-09-22T12:00:00.000Z",
        "phase_entered_at": "2026-09-22T12:00:03.000Z",
        "deadline_at": "2026-09-22T12:15:00.000Z",
        "observed_at": "2026-09-22T12:00:42.123Z",
        "elapsed_ms": "42123",
        "remaining_ms": "857877",
        "condition": "active",
    }
    StatusSemanticProgressModel.model_validate(wire)


def test_past_deadline_without_a_terminal_row_is_overdue_not_terminal() -> None:
    wire = semantic_progress_wire(_record(), _DEADLINE + timedelta(seconds=5))

    assert wire["condition"] == "overdue"
    assert wire["remaining_ms"] == "0"
    assert wire["phase"] == "provider_sampling"
    assert "terminal_outcome" not in wire
    StatusSemanticProgressModel.model_validate(wire)


def test_terminal_progress_freezes_elapsed_at_the_terminal_time() -> None:
    record = _record(
        phase=SemanticProgressPhase.TERMINAL,
        phase_entered_at=_QUEUED + timedelta(seconds=40),
        terminal_outcome="failed",
        terminal_reason=SemanticReason.PROVIDER_TIMEOUT,
    )
    wire = semantic_progress_wire(record, _QUEUED + timedelta(hours=2))

    assert wire["elapsed_ms"] == "40000"
    assert wire["condition"] == "terminal"
    assert (wire["terminal_outcome"], wire["terminal_reason"]) == ("failed", "provider_timeout")
    assert "remaining_ms" not in wire
    StatusSemanticProgressModel.model_validate(wire)


@pytest.mark.parametrize(
    "overrides",
    (
        {"condition": "terminal"},
        {"condition": "overdue"},
        {"remaining_ms": "0"},
        {"phase": "terminal"},
        {"terminal_reason": "provider_timeout"},
        {"attempt_ordinal": "0"},
        {"phase": "thinking"},
        {"reasoning": "hidden"},
    ),
)
def test_wire_model_rejects_inconsistent_or_open_progress(overrides: dict[str, str]) -> None:
    wire = semantic_progress_wire(_record(), _QUEUED + timedelta(seconds=42))
    wire.update(overrides)
    with pytest.raises(ValidationError):
        StatusSemanticProgressModel.model_validate(wire)


def test_progress_is_only_admitted_on_check_pages() -> None:
    progress = semantic_progress_wire(_record(), _QUEUED + timedelta(seconds=1))
    page = {
        "operation_request_id": "req_00000000-0000-4000-8000-000000005711",
        "found": True,
        "state": "pending",
        "operation_kind": "check",
        "semantic_progress": progress,
    }
    assert StatusOperationPageModel.model_validate(page).semantic_progress is not None
    for update in (
        {"operation_kind": "publish_work", "state": "complete"},
        {"state": "quarantined"},
    ):
        with pytest.raises(ValidationError):
            StatusOperationPageModel.model_validate({**page, **update})


def test_record_rejects_open_or_contradictory_terminal_state() -> None:
    with pytest.raises(ValueError):
        _record(phase=SemanticProgressPhase.TERMINAL)
    with pytest.raises(ValueError):
        _record(terminal_outcome="failed", terminal_reason=SemanticReason.PROVIDER_TIMEOUT)
    with pytest.raises(ValueError):
        _record(attempt_ordinal=0)
    with pytest.raises(ValueError):
        _record(queued_at=_QUEUED + timedelta(microseconds=1))
