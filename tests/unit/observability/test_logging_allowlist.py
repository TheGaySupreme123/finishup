from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import cast

import pytest

from builders.clock import frozen_clock
from finishup.config.models import LoggingConfig
from finishup.domain.findings import RUNTIME_FAILURE_STAGES, SemanticFailureClass
from finishup.observability.logging import (
    LogMode,
    configure_logging,
    get_logger,
    record_bounded_event_without_raising,
    record_fatal_exception_without_raising,
    record_unexpected_exception_without_raising,
)
from finishup.protocol.ids import IdKind, validate_id

_NOW = datetime(2026, 7, 19, 12, 34, 56, 789000, tzinfo=UTC)
_REQUEST_ID = "req_11111111-1111-4111-8111-111111111111"
_CORRELATION_ID = "err_22222222-2222-4222-8222-222222222222"
_HASH = "hmac-sha256:" + "3" * 64
_SQLITE_HASH = "sha256:" + "4" * 64
_CANARY = "YZH1-SUPER-SECRET-CANARY"


@pytest.fixture(autouse=True)
def _restore_process_logging() -> Iterator[None]:  # pyright: ignore[reportUnusedFunction]
    root = logging.getLogger()
    root_handlers = tuple(root.handlers)
    root_level = root.level
    last_resort = logging.lastResort
    raise_exceptions = logging.raiseExceptions
    existing_loggers = {
        name: (tuple(logger.handlers), logger.propagate, logger.level)
        for name, logger in logging.root.manager.loggerDict.items()
        if isinstance(logger, logging.Logger)
    }
    yield
    root.handlers.clear()
    root.handlers.extend(root_handlers)
    root.setLevel(root_level)
    logging.lastResort = last_resort
    logging.raiseExceptions = raise_exceptions
    for name, state in existing_loggers.items():
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.handlers.extend(state[0])
        logger.propagate = state[1]
        logger.setLevel(state[2])


def _configure(mode: LogMode = LogMode.SERVICE, *, level: str = "debug") -> None:
    configure_logging(
        LoggingConfig(level=cast("str", level)),  # type: ignore[arg-type]
        mode,
        clock=frozen_clock(utc=_NOW, monotonic=0.0),
    )


def _records(stderr: str) -> list[dict[str, object]]:
    return [cast(dict[str, object], json.loads(line)) for line in stderr.splitlines() if line]


def test_allowlisted_fields_are_preserved(capsys: pytest.CaptureFixture[str]) -> None:
    _configure()
    get_logger("application.service").info(
        "request_finished",
        correlation_id=_CORRELATION_ID,
        session_id_hash=_HASH,
        request_id=_REQUEST_ID,
        duration_ms=17,
        outcome="completed",
        reason="request_completed",
        engine_version="0.1.0",
        policy_version="0.1.0",
        sqlite_source_id_hash=_SQLITE_HASH,
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert _records(captured.err) == [
        {
            "timestamp": "2026-07-19T12:34:56.789Z",
            "level": "info",
            "component": "application.service",
            "operation": "request_finished",
            "correlation_id": _CORRELATION_ID,
            "session_id_hash": _HASH,
            "request_id": _REQUEST_ID,
            "duration_ms": 17,
            "outcome": "completed",
            "reason": "request_completed",
            "engine_version": "0.1.0",
            "policy_version": "0.1.0",
            "sqlite_source_id_hash": _SQLITE_HASH,
        }
    ]


@pytest.mark.parametrize(
    "reason",
    [*(failure.value for failure in SemanticFailureClass), "unclassified"],
)
def test_semantic_provider_unavailable_diagnostic_tokens_are_accepted(
    reason: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure()

    record_bounded_event_without_raising(
        component="semantic_composition",
        operation="semantic_provider_attempt_unavailable",
        reason=reason,
    )

    records = _records(capsys.readouterr().err)
    assert len(records) == 1
    assert records[0]["operation"] == "semantic_provider_attempt_unavailable"
    assert records[0]["reason"] == reason


def test_payload_and_secret_fields_are_redacted(capsys: pytest.CaptureFixture[str]) -> None:
    _configure()
    logger = get_logger("application.service")
    with pytest.raises(AssertionError, match="log_field_not_allowlisted"):
        logger.error("request_failed", payload=_CANARY)
    with pytest.raises(AssertionError, match="log_field_not_allowlisted"):
        logger.error("request_failed", credential=_CANARY)
    assert _CANARY not in capsys.readouterr().err


def test_non_finishup_logger_names_are_suppressed_or_formed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure(LogMode.MCP_STDIO)
    dependency = logging.getLogger("openai.responses")
    dependency.error("provider payload %s", _CANARY)
    dependency.critical("provider critical", exc_info=(RuntimeError, RuntimeError(_CANARY), None))

    captured = capsys.readouterr()
    assert captured.out == ""
    assert _CANARY not in captured.err
    records = _records(captured.err)
    assert len(records) == 2
    for record in records:
        assert set(record) == {
            "timestamp",
            "level",
            "component",
            "operation",
            "correlation_id",
        }
        assert record["component"] == "sdk"
        assert record["operation"] == "filtered_record"
        validate_id(IdKind.CORRELATION, record["correlation_id"])


def test_log_record_shapes_are_bounded(capsys: pytest.CaptureFixture[str]) -> None:
    _configure(level="warning")
    get_logger("service.lifecycle").debug("hidden_debug", outcome="completed")
    get_logger("service.lifecycle").warning(
        "startup_gate",
        duration_ms=2**53 - 1,
        outcome="unavailable",
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    lines = captured.err.splitlines()
    assert len(lines) == 1
    assert len(lines[0].encode("ascii")) <= 4_096
    assert list(_records(captured.err)[0]) == [
        "timestamp",
        "level",
        "component",
        "operation",
        "duration_ms",
        "outcome",
    ]


class _HostileException(RuntimeError):
    def __str__(self) -> str:
        raise AssertionError("exception stringified")

    def __repr__(self) -> str:
        raise AssertionError("exception represented")


def test_exception_objects_are_never_formatted_or_captured(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure()
    hostile = _HostileException(_CANARY)
    correlation_id = record_unexpected_exception_without_raising(hostile)
    record_fatal_exception_without_raising(hostile)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert _CANARY not in captured.err
    validate_id(IdKind.CORRELATION, correlation_id)
    records = _records(captured.err)
    assert [record["operation"] for record in records] == [
        "unexpected_exception",
        "fatal_exception",
    ]
    assert all(record["outcome"] == "internal_error" for record in records)
    # An unreviewed class name is never rendered, however well-formed it looks.
    assert records[0]["reason"] == "exception_unavailable"


@pytest.mark.parametrize("mode", [LogMode.SERVICE, LogMode.CONFIDENTIAL_HELPER])
def test_service_and_confidential_helper_filters_are_exact(
    mode: LogMode,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure(mode)
    logging.getLogger("anyio").error(
        "YZH1 preview %s",
        "YZS1 binding " + _CANARY,
        exc_info=(RuntimeError, _HostileException(_CANARY), None),
        stack_info=True,
    )
    captured = capsys.readouterr()
    assert captured.out == ""
    assert _CANARY not in captured.err
    assert "YZH1" not in captured.err
    assert "YZS1" not in captured.err
    assert len(logging.getLogger().handlers) == 1
    assert not isinstance(logging.getLogger().handlers[0], logging.FileHandler)
    assert _records(captured.err)[0]["component"] == "sdk"


def test_exception_reason_comes_only_from_the_reviewed_registry(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A class name can carry caller data, so only reviewed names may reach a sink."""

    _configure()
    leaky = type("LeakedSecret_hunter2", (Exception,), {})

    record_unexpected_exception_without_raising(leaky(), component="mcp.bridge")

    records = _records(capsys.readouterr().err)
    assert len(records) == 1
    assert records[0]["reason"] == "exception_unavailable"
    assert "hunter2" not in json.dumps(records[0])


def test_reviewed_exception_types_keep_their_fixed_reason(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure()

    record_unexpected_exception_without_raising(RuntimeError("boom"), component="mcp.bridge")

    records = _records(capsys.readouterr().err)
    assert records[0]["reason"] == "exception_runtime_error"
    assert "boom" not in json.dumps(records[0])


def test_unexpected_exception_record_carries_the_caller_request_id(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The daemon and bridge records for one failed call join on this exact field."""

    _configure()

    correlation_id = record_unexpected_exception_without_raising(
        RuntimeError("boom"),
        component="service.daemon",
        operation="check_internal_error",
        request_id=_REQUEST_ID,
    )

    records = _records(capsys.readouterr().err)
    assert records[0]["request_id"] == _REQUEST_ID
    assert records[0]["correlation_id"] == correlation_id
    assert records[0]["operation"] == "check_internal_error"


@pytest.mark.parametrize("reason", sorted(RUNTIME_FAILURE_STAGES))
def test_semantic_provider_invalid_stage_tokens_are_accepted(
    reason: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _configure()

    record_bounded_event_without_raising(
        component="semantic_composition",
        operation="semantic_provider_attempt_invalid",
        reason=reason,
    )

    records = _records(capsys.readouterr().err)
    assert len(records) == 1
    assert records[0]["operation"] == "semantic_provider_attempt_invalid"
    assert records[0]["reason"] == reason
