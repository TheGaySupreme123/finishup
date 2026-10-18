"""Durable owner-only diagnostic ring for correlation-id follow-up."""

from __future__ import annotations

import json
import stat
from datetime import UTC, datetime
from pathlib import Path

import pytest

from builders.clock import frozen_clock
from finishup.config.models import LoggingConfig
from finishup.observability.diagnostics import (
    append_diagnostic_record,
    diagnostic_log_path,
    lookup_diagnostic_records,
)
from finishup.observability.logging import (
    LogMode,
    configure_logging,
    exception_origin,
    record_bounded_counts_without_raising,
    record_bounded_event_without_raising,
    record_classified_exception_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.protocol.ids import IdKind, validate_id

_CORRELATION = "err_aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
_REQUEST = "req_bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
_NOW = datetime(2026, 7, 27, 12, 0, 0, tzinfo=UTC)


def test_append_and_lookup_round_trip(tmp_path: Path) -> None:
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="publish_work_response_projection_failed",
        reason="exception_runtime_error",
        request_id=_REQUEST,
        root=tmp_path,
        now=_NOW,
    )
    path = diagnostic_log_path(root=tmp_path)
    assert path.is_file()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    raw = path.read_text(encoding="ascii")
    line = json.loads(raw)
    assert line == {
        "timestamp": "2026-07-27T12:00:00.000Z",
        "correlation_id": _CORRELATION,
        "component": "service.daemon",
        "operation": "publish_work_response_projection_failed",
        "reason": "exception_runtime_error",
        "request_id": _REQUEST,
    }
    # No payload / exception / path leakage surface.
    assert "traceback" not in raw
    assert "RuntimeError" not in raw
    assert "payload" not in raw

    found = lookup_diagnostic_records(_CORRELATION, root=tmp_path)
    assert len(found) == 1
    assert found[0]["correlation_id"] == _CORRELATION
    assert found[0]["request_id"] == _REQUEST


def test_lookup_miss_returns_empty(tmp_path: Path) -> None:
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="publish_work_response_projection_failed",
        reason="exception_runtime_error",
        root=tmp_path,
        now=_NOW,
    )
    assert (
        lookup_diagnostic_records("err_00000000-0000-4000-8000-000000000099", root=tmp_path) == ()
    )


def test_size_cap_keeps_suffix(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "_MAX_FILE_BYTES", 400)
    for index in range(30):
        append_diagnostic_record(
            correlation_id=f"err_{index:08x}-0000-4000-8000-000000000000",
            component="service.daemon",
            operation="publish_work_response_projection_failed",
            reason="exception_runtime_error",
            request_id=_REQUEST,
            root=tmp_path,
            now=_NOW,
        )
    path = diagnostic_log_path(root=tmp_path)
    size = path.stat().st_size
    assert size <= 400 + 200  # one record may overshoot until the next trim
    text = path.read_text(encoding="ascii")
    assert "err_00000000-0000-4000-8000-000000000000" not in text
    assert text.count("\n") >= 1


def test_record_unexpected_exception_writes_durable_sink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(
        LoggingConfig(level="error"),  # type: ignore[arg-type]
        LogMode.SERVICE,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )
    correlation_id = record_unexpected_exception_without_raising(
        RuntimeError("must-not-leak"),
        component="service.daemon",
        operation="publish_work_response_projection_failed",
        request_id=_REQUEST,
    )
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["reason"] == "exception_runtime_error"
    assert found[0]["request_id"] == _REQUEST
    err = capsys.readouterr().err
    assert "must-not-leak" not in err
    assert correlation_id in err


def test_record_classified_exception_writes_public_error_not_internal_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(
        LoggingConfig(level="debug"),  # type: ignore[arg-type]
        LogMode.SERVICE,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )
    correlation_id = ""
    try:
        validate_id(IdKind.REQUEST, "not-a-request-id")
    except Exception as exc:
        correlation_id = record_classified_exception_without_raising(
            exc,
            component="application.receipt",
            operation="receipt_object_read",
            request_id=_REQUEST,
        )
    assert correlation_id.startswith("err_")
    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["reason"] == "exception_protocol_value_error"
    assert found[0]["operation"] == "receipt_object_read"
    assert found[0]["component"] == "application.receipt"
    origin = found[0].get("origin")
    assert type(origin) is str
    assert origin.startswith("finishup.protocol")
    err = capsys.readouterr().err
    assert "public_error" in err
    assert "internal_error" not in err
    assert "not-a-request-id" not in err


def test_unexpected_exception_records_a_bounded_finishup_origin() -> None:
    """An unexpected exception must say *where* in our code it came from.

    Keeping only the exception class made the production ``status(view=operation)`` AttributeError
    undiagnosable: a dozen guarded call sites raise the same class, so the class alone cannot
    point at any of them and the only route to a fix is a reproduction the durable diagnostic
    exists precisely to avoid needing.
    """

    origin: str | None = None
    try:
        validate_id(IdKind.REQUEST, "not-a-request-id")
    except Exception as exc:
        origin = exception_origin(exc)

    assert origin is not None
    module, _, lineno = origin.partition(":")
    assert module.startswith("finishup.")
    assert lineno.isdigit()


def test_origin_names_our_frame_not_the_caller_that_caught_it() -> None:
    """The location is where our code raised, not the test frame that observed it."""

    origin: str | None = None
    try:
        validate_id(IdKind.REQUEST, "still-not-valid")
    except Exception as exc:
        origin = exception_origin(exc)

    assert origin is not None
    # The test module is not a ``finishup`` module, so it must never be the reported origin.
    assert not origin.startswith("tests")
    assert origin.startswith("finishup.protocol")


def test_origin_is_absent_for_exceptions_with_no_finishup_frame() -> None:
    """Third-party and traceback-less exceptions report nothing rather than a foreign path."""

    assert exception_origin(ValueError("never raised, so no traceback")) is None


def test_diagnostic_origin_is_rejected_unless_it_is_a_finishup_source_location(
    tmp_path: Path,
) -> None:
    """The written field can only ever be a finishup module and a line number.

    The frame walk reads only the module name and traceback line, and the allowlist independently
    guarantees a filesystem path or a user value can never reach the durable record.
    """

    correlation_id = "err_00000000-0000-4000-8000-0000000000f1"
    append_diagnostic_record(
        correlation_id=correlation_id,
        component="service.daemon",
        operation="status_read_projection_failed",
        reason="exception_attribute_error",
        origin="finishup/application/status.py:12",
        root=tmp_path,
    )
    records = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(records) == 1
    assert records[0]["origin"] == "unavailable"

    good = "err_00000000-0000-4000-8000-0000000000f2"
    append_diagnostic_record(
        correlation_id=good,
        component="service.daemon",
        operation="status_read_projection_failed",
        reason="exception_attribute_error",
        origin="finishup.application.status:1097",
        root=tmp_path,
    )
    assert lookup_diagnostic_records(good, root=tmp_path)[0]["origin"] == (
        "finishup.application.status:1097"
    )

    bare = "err_00000000-0000-4000-8000-0000000000f3"
    append_diagnostic_record(
        correlation_id=bare,
        component="service.daemon",
        operation="status_read_projection_failed",
        reason="exception_attribute_error",
        origin="finishup:12",
        root=tmp_path,
    )
    assert lookup_diagnostic_records(bare, root=tmp_path)[0]["origin"] == "finishup:12"


@pytest.mark.parametrize(
    ("origin", "kept"),
    [
        # Records written before the rename name the legacy package (ADR-048).
        ("yoetz.application.status:1097", True),
        ("yoetz:12", True),
        ("finishup.application.status:1097", True),
        ("yoetzz.application:12", False),
        ("finishupx:12", False),
        ("legacy.yoetz.status:12", False),
        ("yoetz/application/status.py:12", False),
    ],
)
def test_diagnostic_origin_accepts_the_legacy_package_name_only(
    tmp_path: Path, origin: str, kept: bool
) -> None:
    correlation_id = "err_00000000-0000-4000-8000-0000000000f4"
    append_diagnostic_record(
        correlation_id=correlation_id,
        component="service.daemon",
        operation="status_read_projection_failed",
        reason="exception_attribute_error",
        origin=origin,
        root=tmp_path,
    )
    records = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert records[0]["origin"] == (origin if kept else "unavailable")


def test_bounded_counts_reach_the_durable_ring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Loop-health counters are useless on stderr alone; the ring is what an operator reads."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(
        LoggingConfig(level="error"),  # type: ignore[arg-type]
        LogMode.SERVICE,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )

    correlation_id = record_bounded_counts_without_raising(
        component="service.daemon",
        operation="control_plane_saturation_entered",
        outcome="event_loop_lag",
        counts={"duration_ms": 12_345, "operation_count": 7, "phase": "projection"},
    )

    found = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert len(found) == 1
    assert found[0]["operation"] == "control_plane_saturation_entered"
    assert found[0]["reason"] == "event_loop_lag"
    assert found[0]["duration_ms"] == 12_345
    assert found[0]["operation_count"] == 7
    assert found[0]["phase"] == "projection"


def test_bounded_event_context_is_fenced_and_reaches_the_ring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """tb4n2 NEW-8: an abandoned response write carries closed, bounded control context."""

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(
        LoggingConfig(level="error"),  # type: ignore[arg-type]
        LogMode.SERVICE,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )

    correlation_id = record_bounded_event_without_raising(
        component="service.daemon",
        operation="control_response_write",
        reason="connection_failed",
        request_id="req_00000000-0000-4000-8000-000000000001",
        context={
            "control_method": "observation_ingest",
            "client_kind": "cli",
            "duration_ms": 812,
            # Not context: a bound identity field and two unknown or hostile names are dropped.
            "reason": "overridden",
            "path": "/home/user/secret",
            "body": "secret",
        },
    )
    (record,) = lookup_diagnostic_records(correlation_id, root=tmp_path)
    assert record["reason"] == "connection_failed"
    assert record["control_method"] == "observation_ingest"
    assert record["client_kind"] == "cli"
    assert record["duration_ms"] == 812
    assert record["request_id"] == "req_00000000-0000-4000-8000-000000000001"
    assert "secret" not in json.dumps(record)

    hostile = record_bounded_event_without_raising(
        component="service.daemon",
        operation="control_response_write",
        reason="connection_failed",
        context={"control_method": "/etc/passwd", "duration_ms": -1},
    )
    (fenced,) = lookup_diagnostic_records(hostile, root=tmp_path)
    assert fenced["control_method"] == "unavailable"
    assert fenced["duration_ms"] == "unavailable"


@pytest.mark.parametrize(
    "field",
    (
        "semantic_capture_parts_resolved",
        "semantic_diff_parts_resolved",
        "semantic_excerpts_selected",
        "semantic_diff_excerpts_selected",
        "semantic_excerpt_bytes_selected",
        "semantic_excerpt_count_approved",
        "semantic_excerpt_byte_approved",
        "semantic_excerpt_count_limit",
        "semantic_excerpt_count_cut_for_case_bound",
        "semantic_excerpt_byte_limit",
        "semantic_excerpt_ceiling_rounds",
        "semantic_check_change_parts_selected",
        "semantic_edit_evidence_in_case",
        "semantic_task_input_candidates",
        "semantic_task_input_excerpts_selected",
        "semantic_task_input_listings",
        "semantic_task_input_outside_candidates",
        "semantic_task_inputs_outside_not_admitted",
        "semantic_task_inputs_read",
    ),
)
def test_packet_composition_diagnostics_admit_counts_but_not_content(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
) -> None:
    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    correlation = record_bounded_counts_without_raising(
        component="semantic_composition",
        operation="semantic_case_built",
        outcome="built",
        counts={field: 17, "raw_patch": "PRIVATE_CODE_CANARY"},
        request_id=_REQUEST,
    )
    found = lookup_diagnostic_records(correlation, root=tmp_path)
    assert found[0][field] == 17
    record_bounded_counts_without_raising(
        component="semantic_composition",
        operation="semantic_case_built",
        outcome="built",
        counts={field: "PRIVATE_CODE_CANARY"},
        request_id=_REQUEST,
    )
    assert "PRIVATE_CODE_CANARY" not in diagnostic_log_path(root=tmp_path).read_text()


def test_review_outcome_counters_survive_stderr_and_the_durable_ring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The check path's review counters reach both sinks, not only the logger's name list.

    A name the logger admits but the value fence does not know is dropped on both sinks without a
    trace; ADR-040 names these counts as the attribution evidence for a run (#1042, #1043, #1047,
    #1020). The accounting record is the largest the judgment schema allows (three challenges, so
    at most three rejection reasons), so it also proves the record fits the ring's line cap.
    """

    import finishup.observability.diagnostics as diagnostics

    monkeypatch.setattr(diagnostics, "log_dir", lambda: tmp_path)
    configure_logging(
        LoggingConfig(level="info"),  # type: ignore[arg-type]
        LogMode.SERVICE,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )
    accounting: dict[str, object] = {
        "semantic_conclusion": "challenges_returned",
        "semantic_challenges_returned": 3,
        "semantic_candidates_accepted": 3,
        "semantic_challenges_rejected": 3,
        "semantic_rejected_routine_completeness": 1,
        "semantic_rejected_subject_refs_over_limit": 1,
        "semantic_rejected_yoetz_process_state": 1,
        "semantic_review_refs_reduced": 67,
        "semantic_review_snippets_rejected": 67,
        "semantic_restatements_suppressed": 3,
        "semantic_challenges_advisory": 2,
        "semantic_agent_criteria": 3,
        "semantic_prior_rulings_set_aside": 16,
        "semantic_rulings_disputed_after_rebuttal": 16,
        "semantic_findings_selected": 3,
        "semantic_findings_suppressed": 3,
    }
    follow_up: dict[str, object] = {
        "semantic_follow_up_round": 3,
        "semantic_follow_up_items": 8,
        "semantic_follow_up_refs_added": 5,
        "semantic_follow_up_parts_added": 4,
    }
    emitted = {
        record_bounded_counts_without_raising(
            component="check",
            operation=operation,
            outcome="succeeded",
            request_id=_REQUEST,
            counts=counts,
        ): counts
        for operation, counts in (
            ("semantic_review_accounting", accounting),
            ("semantic_review_follow_up", follow_up),
        )
    }
    stderr = {
        line["correlation_id"]: line
        for line in (json.loads(raw) for raw in capsys.readouterr().err.splitlines() if raw)
    }
    for correlation, counts in emitted.items():
        (ring,) = lookup_diagnostic_records(correlation, root=tmp_path)
        for name, value in counts.items():
            assert ring.get(name) == value, name
            assert stderr[correlation].get(name) == value, name

    # The newly fenced names stay closed integers: content in their place reaches neither sink.
    admitted = (
        "semantic_rejected_routine_completeness",
        "semantic_rejected_yoetz_process_state",
        "semantic_challenges_advisory",
        "semantic_agent_criteria",
        "semantic_rulings_disputed_after_rebuttal",
        *follow_up,
    )
    hostile = record_bounded_counts_without_raising(
        component="check",
        operation="semantic_review_follow_up",
        outcome="succeeded",
        counts=dict.fromkeys(admitted, "PRIVATE_CODE_CANARY"),
    )
    (fenced,) = lookup_diagnostic_records(hostile, root=tmp_path)
    assert {name: fenced.get(name) for name in admitted} == dict.fromkeys(admitted, "unavailable")
    assert "PRIVATE_CODE_CANARY" not in diagnostic_log_path(root=tmp_path).read_text()
    assert "PRIVATE_CODE_CANARY" not in capsys.readouterr().err
