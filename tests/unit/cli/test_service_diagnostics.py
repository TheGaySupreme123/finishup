"""CLI read surface for durable diagnostic records."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from finishup.cli.app import app
from finishup.observability.diagnostics import append_diagnostic_record

_CORRELATION = "err_cccccccc-cccc-4ccc-8ccc-cccccccccccc"
_NOW = datetime(2026, 7, 27, 15, 30, 0, tzinfo=UTC)
_RUNNER = CliRunner()


def test_service_diagnostics_resolves_correlation_id(tmp_path: Path, monkeypatch: object) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.observability.diagnostics.log_dir",
        lambda: tmp_path,
    )
    append_diagnostic_record(
        correlation_id=_CORRELATION,
        component="service.daemon",
        operation="publish_work_response_projection_failed",
        reason="exception_runtime_error",
        request_id="req_dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        root=tmp_path,
        now=_NOW,
    )
    result = _RUNNER.invoke(
        app,
        ["service", "diagnostics", "--correlation-id", _CORRELATION, "--json"],
    )
    assert result.exit_code == 0
    assert _CORRELATION in result.stdout
    assert "exception_runtime_error" in result.stdout
    assert "publish_work_response_projection_failed" in result.stdout


def test_service_diagnostics_unknown_correlation_exits_one(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr(  # type: ignore[attr-defined]
        "finishup.observability.diagnostics.log_dir",
        lambda: tmp_path,
    )
    result = _RUNNER.invoke(
        app,
        [
            "service",
            "diagnostics",
            "--correlation-id",
            "err_00000000-0000-4000-8000-000000000001",
            "--json",
        ],
    )
    assert result.exit_code == 1


def test_request_selector_joins_multiple_failure_stages(
    tmp_path: Path, monkeypatch: object
) -> None:
    monkeypatch.setattr("finishup.observability.diagnostics.log_dir", lambda: tmp_path)  # type: ignore[attr-defined]
    request = "req_dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    for suffix, operation in [
        (1, "semantic_attempt_dispatch_entered_failed"),
        (2, "semantic_terminalize_attempt_failed"),
    ]:
        append_diagnostic_record(
            correlation_id=f"err_00000000-0000-4000-8000-{suffix:012d}",
            component="semantic_attempts",
            operation=operation,
            reason="exception_runtime_error",
            request_id=request,
            root=tmp_path,
            now=_NOW,
        )
    result = _RUNNER.invoke(app, ["service", "diagnostics", "--request-id", request, "--json"])
    assert result.exit_code == 0
    assert "semantic_attempt_dispatch_entered_failed" in result.stdout
    assert "semantic_terminalize_attempt_failed" in result.stdout
    assert request in result.stdout
    invalid = _RUNNER.invoke(
        app,
        [
            "service",
            "diagnostics",
            "--request-id",
            request,
            "--correlation-id",
            _CORRELATION,
            "--json",
        ],
    )
    assert invalid.exit_code != 0
