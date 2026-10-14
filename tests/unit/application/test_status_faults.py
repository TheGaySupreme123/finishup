"""Stage classification for status faults that are not the caller's fault (#840)."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

import pytest

import yoetz.observability.diagnostics as diagnostics
from yoetz.application.projects import ProjectCommandError
from yoetz.application.status_faults import (
    StatusFault,
    StatusFaultStage,
    classify_status_fault,
    fault_source,
    record_status_member_unavailable,
    status_stage,
)
from yoetz.domain.coordination import CoordinationError, CoordinationErrorCode
from yoetz.protocol.errors import PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, validate_id

_REQUEST_ID = "req_00000000-0000-4000-8000-000000000840"
_CANARY = "canary-status-fault"


@pytest.fixture(autouse=True)
def _ring(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:  # pyright: ignore[reportUnusedFunction]
    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    return tmp_path


def _records() -> tuple[Mapping[str, object], ...]:
    return diagnostics.lookup_diagnostic_records(request_id=_REQUEST_ID)


def _raised_in(stage: StatusFaultStage, message: str | None = None) -> StatusFault:
    """Tag a real ``yoetz`` failure whose value carries the canary."""

    try:
        with status_stage(stage, message):
            validate_id(IdKind.TASK, _CANARY)
    except StatusFault as fault:
        return fault
    raise AssertionError("stage did not tag the fault")


@pytest.mark.parametrize(
    ("stage", "code", "message"),
    [
        (
            StatusFaultStage.REPLAY,
            PublicErrorCode.STORAGE_CORRUPT,
            "The stored task state could not be read for status.",
        ),
        (
            StatusFaultStage.MODEL,
            PublicErrorCode.INTERNAL_ERROR,
            "The status projection produced an invalid row.",
        ),
        (
            StatusFaultStage.DIGEST,
            PublicErrorCode.INTERNAL_ERROR,
            "The status snapshot identity could not be computed.",
        ),
        (
            StatusFaultStage.PROJECTION,
            PublicErrorCode.INTERNAL_ERROR,
            "The status projection failed.",
        ),
    ],
)
def test_each_stage_has_one_typed_public_error_and_a_joined_record(
    stage: StatusFaultStage, code: PublicErrorCode, message: str
) -> None:
    fault = _raised_in(stage)

    error = classify_status_fault(fault, view="project", request_id=_REQUEST_ID)

    assert error.code is code
    assert error.code is not PublicErrorCode.INVALID_REQUEST
    assert error.message == message
    assert error.retryable is False
    assert error.correlation_id is not None
    assert error.safe_details == {"phase": stage.value}
    (record,) = _records()
    assert record["correlation_id"] == error.correlation_id
    assert record["component"] == "application.status"
    assert record["operation"] == f"status_project_{stage.value}_failed"
    assert record["phase"] == stage.value
    # The class token and origin describe the original exception, not the stage marker: the
    # origin is the yoetz frame that raised, never the stage boundary that tagged it.
    assert record["reason"] == "exception_protocol_value_error"
    origin = record["origin"]
    assert type(origin) is str and origin.startswith("yoetz.protocol.")
    assert _CANARY not in repr(record)


@pytest.mark.parametrize(
    ("exc", "reason"),
    [
        (CoordinationError(CoordinationErrorCode.INVALID), "exception_coordination_error"),
        (ProjectCommandError(CoordinationErrorCode.INVALID), "exception_project_command_error"),
    ],
)
def test_untagged_coordination_value_errors_are_internal_projection_failures(
    exc: Exception, reason: str
) -> None:
    """Both subclass ValueError; neither is caller input, and both have a reviewed token."""

    error = classify_status_fault(exc, view="project", request_id=_REQUEST_ID)

    assert error.code is PublicErrorCode.INTERNAL_ERROR
    (record,) = _records()
    assert record["operation"] == "status_project_projection_failed"
    assert record["reason"] == reason


def test_existing_fixed_wording_is_kept_without_reading_the_exception() -> None:
    fault = _raised_in(StatusFaultStage.REPLAY, "The task ledger is unreadable.")

    error = classify_status_fault(fault, view="candidate_findings", request_id=_REQUEST_ID)

    assert error.code is PublicErrorCode.STORAGE_CORRUPT
    assert error.message == "The task ledger is unreadable."
    (record,) = _records()
    assert record["operation"] == "status_candidate_findings_replay_failed"


def test_stage_boundaries_pass_public_errors_and_inner_stages_through() -> None:
    public = PublicOperationError(PublicErrorCode.SESSION_CONFLICT, "Inconsistent.", False)
    with pytest.raises(PublicOperationError) as caught:
        with status_stage(StatusFaultStage.MODEL):
            raise public
    assert caught.value is public

    with pytest.raises(StatusFault) as nested:
        with status_stage(StatusFaultStage.PROJECTION):
            with status_stage(StatusFaultStage.REPLAY):
                raise TypeError(_CANARY)
    # The innermost named stage wins; an enclosing stage never reclassifies it.
    assert nested.value.stage is StatusFaultStage.REPLAY
    assert not isinstance(nested.value, ValueError)
    assert _records() == ()


def test_degraded_member_is_always_joinable_by_request_id() -> None:
    # An unbound public error (for example a member route inconsistency) gets one record.
    record_status_member_unavailable(
        PublicOperationError(PublicErrorCode.STORAGE_CORRUPT, "Inconsistent.", False),
        request_id=_REQUEST_ID,
    )
    # A tagged fault records its classified stage.
    record_status_member_unavailable(_raised_in(StatusFaultStage.MODEL), request_id=_REQUEST_ID)
    records = _records()
    assert [(item["operation"], item["reason"]) for item in records] == [
        ("status_project_member_unavailable", "storage_corrupt"),
        ("status_project_model_failed", "exception_protocol_value_error"),
    ]

    # A public error that already carries a recorded id is not recorded twice.
    bound = classify_status_fault(
        _raised_in(StatusFaultStage.REPLAY), view="project", request_id=_REQUEST_ID
    )
    before = len(_records())
    record_status_member_unavailable(bound, request_id=_REQUEST_ID)
    assert len(_records()) == before
    assert _CANARY not in repr(_records())


def test_fault_source_unwraps_only_a_tagged_marker() -> None:
    """Secondary readers that record a broad failure describe the defect, not the boundary."""

    fault = _raised_in(StatusFaultStage.MODEL)
    assert fault_source(fault) is fault.__cause__
    assert type(fault_source(fault)).__name__ == "ProtocolValueError"
    plain = ValueError(_CANARY)
    assert fault_source(plain) is plain
