"""Structured, allowlisted, stderr-only process logging."""

from __future__ import annotations

import json
import logging
import re
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from enum import Enum
from threading import Lock
from typing import Final, cast

from finishup.config.models import LoggingConfig
from finishup.domain.values import format_rfc3339_millis
from finishup.observability.exception_reasons import exception_reason as _exception_reason
from finishup.observability.privacy import (
    assert_plaintext_safe,
    redact_diagnostic_value,
)
from finishup.ports.clock import ClockPort
from finishup.protocol.ids import IdKind, new_id, validate_id

__all__ = [
    "LogMode",
    "StructuredLogger",
    "configure_logging",
    "get_logger",
    "exception_origin",
    "record_bounded_counts_without_raising",
    "record_bounded_event_without_raising",
    "record_classified_exception_without_raising",
    "record_fatal_exception_without_raising",
    "record_public_error_without_raising",
    "record_unexpected_exception_without_raising",
]

_FIELD_ORDER: Final = (
    "timestamp",
    "level",
    "component",
    "operation",
    "correlation_id",
    "session_id_hash",
    "request_id",
    "duration_ms",
    "outcome",
    "reason",
    "reason_code",
    "phase",
    "origin",
    "engine_version",
    "policy_version",
    "sqlite_source_id_hash",
    "semantic_conclusion",
    "semantic_challenges_returned",
    "semantic_candidates_accepted",
    "semantic_challenges_rejected",
    "semantic_rejected_hidden_source_claim",
    "semantic_rejected_local_rule_owned",
    "semantic_rejected_ref_not_carried",
    "semantic_rejected_ref_outside_case",
    "semantic_rejected_routine_completeness",
    "semantic_rejected_snippet_invalid",
    "semantic_rejected_subject_refs_over_limit",
    "semantic_rejected_yoetz_process_state",
    "semantic_challenges_advisory",
    "semantic_agent_criteria",
    "semantic_review_refs_reduced",
    "semantic_review_snippets_rejected",
    "semantic_restatements_suppressed",
    "semantic_prior_rulings_set_aside",
    "semantic_rulings_disputed_after_rebuttal",
    "semantic_findings_selected",
    "semantic_findings_suppressed",
    # One in-check reviewer follow-up round (#1047).
    "semantic_follow_up_round",
    "semantic_follow_up_items",
    "semantic_follow_up_refs_added",
    "semantic_follow_up_parts_added",
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
    # #1118: a capacity refusal's rendered disclosure size and the limit it
    # exceeded (integers only, never content).
    "semantic_disclosure_attempted_bytes",
    "semantic_disclosure_limit_bytes",
    "semantic_disclosure_attempted_tokens",
    "semantic_disclosure_limit_tokens",
    "semantic_excerpt_attempted_bytes",
    "semantic_excerpt_limit_bytes",
    "semantic_excerpt_attempted_excerpts",
    "semantic_excerpt_limit_excerpts",
    "semantic_excerpt_total_attempted_bytes",
    "semantic_excerpt_total_limit_bytes",
    "semantic_check_change_parts_selected",
    "semantic_edit_evidence_in_case",
    # Issue #1102: task-input pilot counters (integers only, never a path).
    "semantic_task_input_candidates",
    "semantic_task_input_excerpts_selected",
    "semantic_task_input_listings",
    "semantic_task_input_outside_candidates",
    "semantic_task_inputs_outside_not_admitted",
    "semantic_task_inputs_read",
    # Admits the loop-health connection count into _CALLER_FIELDS/_COUNT_FIELDS below, so a
    # bounded-counts caller can report how much work was in flight during a stall.
    "operation_count",
    # Closed control-plane identity for a response write the peer abandoned (tb4n2 NEW-8).
    "control_method",
    "client_kind",
)
_FIELD_SET: Final = frozenset(_FIELD_ORDER)
_CALLER_FIELDS: Final = _FIELD_SET - {"timestamp", "level", "component", "operation"}
# Fields a bounded-counts caller may supply. The identity fields the emitter binds itself are
# excluded so a caller can never pass the same keyword twice.
_COUNT_FIELDS: Final = _CALLER_FIELDS - {"correlation_id", "request_id", "outcome"}
# Extra structural context a bounded event may carry; the identity and reason fields it binds
# itself are excluded so a caller can never pass the same keyword twice.
_CONTEXT_FIELDS: Final = _COUNT_FIELDS - {"reason", "origin", "reason_code", "phase"}
_STRUCTURAL_MARKER: Final = "_finishup_structured_record"
_STRUCTURAL_FIELDS: Final = "_finishup_structured_fields"
_COMPONENT_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$", re.ASCII)
# Python identifiers only: an attribute name is a symbol from our source, never a value.
_ATTRIBUTE_NAME: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$", re.ASCII)
_MAX_RECORD_BYTES: Final = 4_096
_FALLBACK_CORRELATION: Final = "err_00000000-0000-4000-8000-000000000000"

_LEVEL_BY_NAME: Final = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
}

_configured_lock = Lock()
_handler: _StructuredStderrHandler | None = None
_clock: ClockPort | None = None
_dropped_warning_emitted = False


class LogMode(str, Enum):  # noqa: UP042 - frozen process-mode vocabulary
    SERVICE = "service"
    CLI = "cli"
    MCP_STDIO = "mcp_stdio"
    CONFIDENTIAL_HELPER = "confidential_helper"


class _SystemClock:
    def now_utc(self) -> datetime:
        now = datetime.now(UTC)
        return now.replace(microsecond=(now.microsecond // 1_000) * 1_000)

    def monotonic_seconds(self) -> float:
        # Logging uses only UTC metadata; the method completes ClockPort without another clock API.
        return 0.0


def _new_correlation() -> str:
    try:
        return new_id(IdKind.CORRELATION)
    except BaseException:
        return _FALLBACK_CORRELATION


def _caller_correlation(correlation_id: str | None) -> str:
    """Keep a valid caller-minted correlation id; mint a fresh one otherwise."""

    if correlation_id is None:
        return _new_correlation()
    try:
        return validate_id(IdKind.CORRELATION, correlation_id)
    except BaseException:
        return _new_correlation()


def _level_name(level_number: int) -> str:
    if level_number >= logging.ERROR:
        return "error"
    if level_number >= logging.WARNING:
        return "warning"
    if level_number >= logging.INFO:
        return "info"
    return "debug"


class _StructuralFilter(logging.Filter):
    """Destroy every unstructured message before it reaches a formatter or sink."""

    def filter(self, record: logging.LogRecord) -> bool:
        marker = getattr(record, _STRUCTURAL_MARKER, False)
        fields = getattr(record, _STRUCTURAL_FIELDS, None)
        if marker is True and type(fields) is dict:
            safe_fields = cast(dict[str, object], fields)
        else:
            safe_fields = {
                "component": "sdk",
                "operation": "filtered_record",
                "correlation_id": _new_correlation(),
            }
        # These assignments intentionally erase the original object graph without formatting it.
        record.msg = ""
        record.args = ()
        record.exc_info = None
        record.exc_text = None
        record.stack_info = None
        setattr(record, _STRUCTURAL_MARKER, True)
        setattr(record, _STRUCTURAL_FIELDS, safe_fields)
        return True


class _StructuredStderrHandler(logging.Handler):
    """A formatter-free handler that resolves stderr only at emission time."""

    def __init__(self, *, level: int, clock: ClockPort) -> None:
        super().__init__(level=level)
        self._clock = clock
        self.addFilter(_StructuralFilter())

    def set_clock(self, clock: ClockPort) -> None:
        self._clock = clock

    def emit(self, record: logging.LogRecord) -> None:
        try:
            source = getattr(record, _STRUCTURAL_FIELDS, None)
            if type(source) is not dict:
                return
            fields = cast(dict[str, object], source)
            output: dict[str, object] = {
                "timestamp": format_rfc3339_millis(self._clock.now_utc()),
                "level": _level_name(record.levelno),
            }
            for name in _FIELD_ORDER[2:]:
                if name not in fields:
                    continue
                value = redact_diagnostic_value(name, fields[name])
                if value is not None:
                    output[name] = value
            encoded = json.dumps(
                output,
                ensure_ascii=True,
                separators=(",", ":"),
            ).encode("ascii")
            if len(encoded) > _MAX_RECORD_BYTES:
                return
            assert_plaintext_safe(encoded, "structured_log")
            sys.stderr.write(encoded.decode("ascii") + "\n")
            sys.stderr.flush()
        except BaseException:
            return


class StructuredLogger:
    """Bounded logger with no generic message/argument surface."""

    __slots__ = ("_component", "_logger")

    def __init__(self, component: str) -> None:
        if type(component) is not str or _COMPONENT_PATTERN.fullmatch(component) is None:
            raise ValueError("log_component_invalid")
        self._component = component
        self._logger = logging.getLogger(f"finishup.{component}")

    def debug(self, operation: str, **fields: object) -> None:
        self._emit(logging.DEBUG, operation, fields)

    def info(self, operation: str, **fields: object) -> None:
        self._emit(logging.INFO, operation, fields)

    def warning(self, operation: str, **fields: object) -> None:
        self._emit(logging.WARNING, operation, fields)

    def error(self, operation: str, **fields: object) -> None:
        self._emit(logging.ERROR, operation, fields)

    def _emit(self, level: int, operation: str, fields: Mapping[str, object]) -> None:
        if type(operation) is not str or _COMPONENT_PATTERN.fullmatch(operation) is None:
            raise ValueError("log_operation_invalid")
        unknown = tuple(name for name in fields if name not in _CALLER_FIELDS)
        if unknown:
            if __debug__:
                raise AssertionError("log_field_not_allowlisted")
            _record_dropped_field_once()

        safe: dict[str, object] = {"component": self._component, "operation": operation}
        for name in _CALLER_FIELDS:
            if name not in fields or fields[name] is None:
                continue
            value = redact_diagnostic_value(name, fields[name])
            safe[name] = value
        try:
            self._logger.log(
                level,
                "",
                extra={_STRUCTURAL_MARKER: True, _STRUCTURAL_FIELDS: safe},
            )
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            return


def _record_dropped_field_once() -> None:
    global _dropped_warning_emitted
    if _dropped_warning_emitted:
        return
    _dropped_warning_emitted = True
    try:
        StructuredLogger("observability").warning(
            "field_rejected",
            outcome="log_field_dropped",
        )
    except BaseException:
        return


def _remove_existing_handlers() -> None:
    loggers: list[logging.Logger] = [logging.getLogger()]
    for candidate in logging.root.manager.loggerDict.values():
        if isinstance(candidate, logging.Logger):
            loggers.append(candidate)
    for logger in loggers:
        for existing in tuple(logger.handlers):
            logger.removeHandler(existing)
        if logger is not logging.getLogger():
            logger.propagate = True


def configure_logging(
    config: LoggingConfig,
    mode: LogMode,
    *,
    clock: ClockPort | None = None,
) -> None:
    """Install one stderr-only structural sink and sanitize all dependency records."""

    global _clock, _handler
    if type(mode) is not LogMode:
        raise TypeError("log_mode_invalid")
    selected_clock = clock if clock is not None else _SystemClock()
    level = _LEVEL_BY_NAME[config.level]
    with _configured_lock:
        _remove_existing_handlers()
        handler = _StructuredStderrHandler(level=level, clock=selected_clock)
        root = logging.getLogger()
        root.setLevel(level)
        root.addHandler(handler)
        logging.lastResort = handler
        logging.raiseExceptions = False
        _clock = selected_clock
        _handler = handler


def get_logger(component: str) -> StructuredLogger:
    """Return a structured logger for one reviewed constant component identity."""

    return StructuredLogger(component)


def exception_origin(exc: BaseException) -> str | None:
    """Return the innermost ``finishup`` frame as ``module:lineno``, or ``None``.

    Retaining only the exception class made a production ``AttributeError`` undiagnosable: the
    class alone cannot distinguish which of a dozen guarded call sites raised, so the only route
    to a fix was reproducing it, and the whole point of a durable diagnostic is that you cannot.

    This is deliberately the narrowest thing that closes that gap. It reads the module from
    ``frame.f_globals["__name__"]`` and the line from ``traceback.tb_lineno`` in our own frames
    only — never ``f_locals``, never ``str(exc)`` — and the result must still satisfy the
    ``origin`` allowlist pattern before it is written, so the field can carry a source location
    and nothing else. Frames from stdlib or dependencies are skipped rather than reported.
    """

    try:
        module: str | None = None
        lineno = 0
        seen: set[int] = set()
        current: BaseException | None = exc
        while current is not None and id(current) not in seen:
            seen.add(id(current))
            traceback = current.__traceback__
            while traceback is not None:
                frame = traceback.tb_frame
                name = frame.f_globals.get("__name__")
                if type(name) is str and (name == "finishup" or name.startswith("finishup.")):
                    module = name
                    lineno = traceback.tb_lineno
                traceback = traceback.tb_next
            if module is not None:
                break
            current = current.__cause__ or current.__context__
        if module is None or not 0 < lineno < 1_000_000:
            return None
        location = f"{module}:{lineno}"
        # One source line can contain several attribute accesses, so the location alone still
        # leaves an AttributeError ambiguous. ``AttributeError.name`` is the identifier the
        # interpreter looked up — a symbol from our own source, never a value — so appending it
        # resolves the ambiguity without widening what the record can carry. The allowlist
        # pattern below still has to accept the result.
        attribute = getattr(exc, "name", None) if isinstance(exc, AttributeError) else None
        if type(attribute) is str and _ATTRIBUTE_NAME.fullmatch(attribute):
            return f"{location}#{attribute}"
        return location
    except BaseException:
        return None


def record_unexpected_exception_without_raising(
    exc: BaseException,
    *,
    component: str = "process_boundary",
    operation: str = "unexpected_exception",
    request_id: str | None = None,
    phase: str | None = None,
    correlation_id: str | None = None,
    reason_code: str | None = None,
) -> str:
    """Emit bounded structural identity for an unexpected internal exception.

    ``request_id`` is the caller's own already-public request identity. Passing it lets the
    service-side and bridge-side records for one failed call be joined exactly, instead of
    guessing from method and timestamp when two calls overlap.

    ``correlation_id`` is an id another process minted and will look up (a service spawned on
    demand records its startup failure under the id its spawner passed, #1040); an invalid one is
    replaced by a fresh id, which is returned either way. ``reason_code`` is the exception's own
    closed refusal token when it carries one but is still reported as unexpected (an endpoint or
    storage refusal that stops service startup); the sinks gate it like any other token.

    In addition to stderr, a durable owner-only diagnostic line is written under ``log_dir()`` so
    a public ``correlation_id`` remains resolvable when harnesses swallow process stderr.
    """

    correlation_id = _caller_correlation(correlation_id)
    reason = _exception_reason(exc)
    origin = exception_origin(exc)
    try:
        get_logger(component).error(
            operation,
            correlation_id=correlation_id,
            request_id=request_id,
            outcome="internal_error",
            reason=reason,
            origin=origin,
            reason_code=reason_code,
            phase=phase,
        )
    except BaseException:
        pass
    try:
        from finishup.observability.diagnostics import append_diagnostic_record

        append_diagnostic_record(
            correlation_id=correlation_id,
            component=component,
            operation=operation,
            reason=reason,
            request_id=request_id,
            origin=origin,
            reason_code=reason_code,
            phase=phase,
        )
    except BaseException:
        pass
    return correlation_id


def record_bounded_event_without_raising(
    *,
    component: str,
    operation: str,
    reason: str,
    request_id: str | None = None,
    context: Mapping[str, object] | None = None,
) -> str:
    """Emit bounded structural identity for a reviewed non-exception event.

    AI-powered review declining to dispatch is an expected operating state, not an unexpected
    exception, so it has no ``_exception_reason`` source; the caller passes the already-bounded
    reason token it is simultaneously reporting on the operation's own result channel. Both
    tokens are reviewed literals at the call site, and the sinks re-validate them against the
    same field allowlists as an exception record. The durable owner-only line is what makes the
    outcome resolvable when harnesses swallow process stderr.

    ``context`` adds bounded structural fields (closed tokens and integers under allowlisted
    names such as ``control_method``, ``client_kind`` or ``duration_ms``); a name the sinks do not
    allowlist, or one this function binds itself, is dropped, and every value passes the same
    fence as any other field.
    """

    return _record_bounded_without_raising(
        component=component,
        operation=operation,
        reason=reason,
        outcome="not_dispatched",
        request_id=request_id,
        context=context,
    )


def record_classified_exception_without_raising(
    exc: BaseException,
    *,
    component: str,
    operation: str,
    request_id: str | None = None,
    phase: str | None = None,
    reason_code: str | None = None,
    correlation_id: str | None = None,
) -> str:
    """Record a public classified failure with bounded exception identity.

    Unlike ``record_unexpected_exception_without_raising``, this is not an internal last-resort:
    ``outcome`` is ``public_error`` so a wire ``correlation_id`` stays joinable to a class-name
    token and optional ``finishup`` origin without collapsing the failure into ``internal_error``.
    The sinks still never record ``str(exc)``, paths, or object ids. ``reason_code`` is the
    exception's own closed refusal token, when it carries one; ``correlation_id`` is a
    caller-minted id, as for ``record_unexpected_exception_without_raising``.
    """

    return _record_bounded_without_raising(
        component=component,
        operation=operation,
        reason=_exception_reason(exc),
        outcome="public_error",
        request_id=request_id,
        origin=exception_origin(exc),
        reason_code=reason_code,
        phase=phase,
        correlation_id=correlation_id,
    )


def record_public_error_without_raising(
    *,
    component: str,
    operation: str,
    reason: str,
    request_id: str | None = None,
    reason_code: str | None = None,
) -> str:
    """Mint the correlation id a public error will carry, and make that exact id resolvable.

    A correlation id is only worth printing if whoever is handed one can find the failure behind
    it. Boundaries that minted an id straight into a wire envelope wrote no sink record at all, so
    every such id resolved to nothing: the 2026-08-10 dogfood surfaced four agent-facing ids that
    appear zero times in either sink, and the underlying failure was findable only by collating
    timestamps against ``request_id``.

    This serves the deterministic public failures — invalid request, pending operation, locked
    vault — that state something true, never raise an unexpected exception, and so never reach
    ``record_unexpected_exception_without_raising``. A boundary that already holds an id another
    sink recorded must reuse that id and must not call this: two ids for one failure is the same
    defect in a different shape.
    """

    return _record_bounded_without_raising(
        component=component,
        operation=operation,
        reason=reason,
        outcome="public_error",
        request_id=request_id,
        reason_code=reason_code,
    )


def _record_bounded_without_raising(
    *,
    component: str,
    operation: str,
    reason: str,
    outcome: str,
    request_id: str | None,
    origin: str | None = None,
    reason_code: str | None = None,
    phase: str | None = None,
    context: Mapping[str, object] | None = None,
    correlation_id: str | None = None,
) -> str:
    """Mint one correlation id and write it to both sinks. Never raises to callers."""

    correlation_id = _caller_correlation(correlation_id)
    extra: dict[str, object] = {}
    if context is not None:
        try:
            extra = {
                name: value
                for name, value in context.items()
                if type(name) is str and name in _CONTEXT_FIELDS
            }
        except BaseException:
            extra = {}
    try:
        get_logger(component).warning(
            operation,
            correlation_id=correlation_id,
            request_id=request_id,
            outcome=outcome,
            reason=reason,
            origin=origin,
            reason_code=reason_code,
            phase=phase,
            **extra,
        )
    except BaseException:
        pass
    try:
        from finishup.observability.diagnostics import append_diagnostic_record

        append_diagnostic_record(
            correlation_id=correlation_id,
            component=component,
            operation=operation,
            reason=reason,
            request_id=request_id,
            origin=origin,
            reason_code=reason_code,
            phase=phase,
            counts=extra or None,
        )
    except BaseException:
        pass
    return correlation_id


def record_bounded_counts_without_raising(
    *,
    component: str,
    operation: str,
    outcome: str,
    counts: Mapping[str, object],
    request_id: str | None = None,
    correlation_id: str | None = None,
) -> str:
    """Emit bounded structural counters for a reviewed non-exception event.

    Some outcomes are only legible as arithmetic: an AI-powered review that returned three challenges
    and produced no findings is not an error on any single call, so nothing raises and nothing is
    logged, and the loss is invisible. ``counts`` carries integers and closed tokens under names
    the sinks already allowlist; anything else is dropped there, exactly as for any other record.
    The durable owner-only line matters because MCP-spawned services swallow stderr, which is where
    this would otherwise be the only trace.
    """

    if correlation_id is None:
        correlation_id = _new_correlation()
    else:
        try:
            validate_id(IdKind.CORRELATION, correlation_id)
        except BaseException:
            correlation_id = _new_correlation()
    # Excluding the names bound directly below is load-bearing, not tidiness: a caller that put
    # ``outcome`` (or a correlation/request id) in ``counts`` would hand the logger the same
    # keyword twice, and the TypeError is swallowed by the guard below — the record would vanish
    # exactly where this function exists to make something visible.
    fields = {name: value for name, value in counts.items() if name in _COUNT_FIELDS}
    try:
        get_logger(component).info(
            operation,
            correlation_id=correlation_id,
            request_id=request_id,
            outcome=outcome,
            **fields,
        )
    except BaseException:
        pass
    try:
        from finishup.observability.diagnostics import append_diagnostic_record

        append_diagnostic_record(
            correlation_id=correlation_id,
            component=component,
            operation=operation,
            reason=outcome,
            request_id=request_id,
            counts=fields,
        )
    except BaseException:
        pass
    return correlation_id


def record_fatal_exception_without_raising(exc: BaseException) -> None:
    """Best-effort fatal-boundary structural logging with no exception inspection."""

    del exc
    try:
        get_logger("process_boundary").error(
            "fatal_exception",
            correlation_id=_new_correlation(),
            outcome="internal_error",
        )
    except BaseException:
        pass
