"""Owner-only durable diagnostic records for correlation-id follow-up.

Stderr is the primary structured sink, but MCP-spawned services swallow it. These records live
under ``log_dir()`` so an operator (or plan-05 reproduction) can resolve a public ``err_…`` id
without relying on harness capture.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from threading import Lock
from typing import Final, cast

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms do not host the service
    fcntl = None  # type: ignore[assignment]

from finishup.config.paths import ensure_owner_only_dir, log_dir
from finishup.domain.values import format_rfc3339_millis
from finishup.observability.privacy import assert_plaintext_safe, redact_diagnostic_value
from finishup.protocol.ids import IdKind, validate_id

__all__ = [
    "DIAGNOSTIC_FILENAME",
    "append_diagnostic_record",
    "diagnostic_log_path",
    "lookup_diagnostic_records",
]

DIAGNOSTIC_FILENAME: Final = "service.diagnostics.jsonl"
_MAX_RECORD_BYTES: Final = 1_024
_MAX_FILE_BYTES: Final = 256 * 1_024
_FIELD_ORDER: Final = (
    "timestamp",
    "correlation_id",
    "component",
    "operation",
    "reason",
    "reason_code",
    "phase",
    "origin",
    "request_id",
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
    # #1245 (D22): which sections ceiling planning dropped, and the agent-account rows kept
    # (integers only, never content).
    "semantic_section_dropped_goal",
    "semantic_section_dropped_obligations",
    "semantic_section_dropped_claims",
    "semantic_section_dropped_timeline",
    "semantic_obligation_rows_selected",
    "semantic_claim_rows_selected",
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
    # #1230: excerpts a disclosure-time fit left out (integers only).
    "semantic_excerpts_unselected_at_disclosure",
    "semantic_check_change_parts_selected",
    "semantic_edit_evidence_in_case",
    # Issue #1102: task-input pilot counters (integers only, never a path).
    "semantic_task_input_candidates",
    "semantic_task_input_excerpts_selected",
    "semantic_task_input_listings",
    "semantic_task_input_outside_candidates",
    "semantic_task_inputs_outside_not_admitted",
    "semantic_task_inputs_read",
    # Loop-health counters. Both are already fenced as integers by redact_diagnostic_value; only
    # this projection list was missing them, so a saturation record reached stderr and then
    # vanished from the durable ring an operator actually reads.
    "duration_ms",
    "operation_count",
    "codex_event_control_count",
    "codex_event_wire_bytes",
    "codex_event_control_bytes",
    "codex_event_telemetry_count",
    "codex_event_telemetry_bytes",
    "codex_event_delta_count",
    "codex_event_delta_bytes",
    "codex_event_intermediate_count",
    "codex_event_intermediate_bytes",
    # #1172: per-exchange prompt-cache telemetry (provider-reported token counts and one
    # closed miss label, never content).
    "reviewer_exchange_index",
    "reviewer_model_requests",
    "reviewer_input_tokens",
    "reviewer_cached_input_tokens",
    "reviewer_cache_write_input_tokens",
    "reviewer_output_tokens",
    "reviewer_prefix_tokens",
    "reviewer_prefix_cached_tokens",
    "reviewer_cache_miss",
    # Closed control-plane identity of an abandoned response write (tb4n2 NEW-8).
    "control_method",
    "client_kind",
)
_lock = Lock()


def diagnostic_log_path(*, root: Path | None = None) -> Path:
    """Return the owner-only diagnostic ring path under the platform log directory."""

    base = log_dir() if root is None else root
    return base / DIAGNOSTIC_FILENAME


def append_diagnostic_record(
    *,
    correlation_id: str,
    component: str,
    operation: str,
    reason: str,
    request_id: str | None = None,
    origin: str | None = None,
    reason_code: str | None = None,
    phase: str | None = None,
    counts: Mapping[str, object] | None = None,
    root: Path | None = None,
    now: datetime | None = None,
) -> None:
    """Append one bounded diagnostic line. Best-effort; never raises to callers."""

    try:
        record = _build_record(
            correlation_id=correlation_id,
            component=component,
            operation=operation,
            reason=reason,
            request_id=request_id,
            origin=origin,
            reason_code=reason_code,
            phase=phase,
            counts=counts,
            now=now,
        )
        if record is None:
            return
        encoded = json.dumps(record, ensure_ascii=True, separators=(",", ":")).encode("ascii")
        if len(encoded) > _MAX_RECORD_BYTES:
            return
        assert_plaintext_safe(encoded, "diagnostic_record")
        path = diagnostic_log_path(root=root)
        _append_line(path, encoded + b"\n")
    except BaseException:
        return


def lookup_diagnostic_records(
    correlation_id: str | None = None,
    *,
    request_id: str | None = None,
    root: Path | None = None,
) -> tuple[Mapping[str, object], ...]:
    """Return every durable record matching one correlation id, oldest first."""

    if (correlation_id is None) == (request_id is None):
        raise ValueError("diagnostic_selector_invalid")
    if correlation_id is not None:
        validate_id(IdKind.CORRELATION, correlation_id)
    if request_id is not None:
        validate_id(IdKind.REQUEST, request_id)
    path = diagnostic_log_path(root=root)
    if not path.is_file() or path.is_symlink():
        return ()
    matches: list[Mapping[str, object]] = []
    with path.open("rb") as handle:
        for raw in handle:
            line = raw.strip()
            if not line:
                continue
            try:
                parsed: object = json.loads(line.decode("ascii"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if type(parsed) is not dict:
                continue
            source = cast(dict[str, object], parsed)
            if correlation_id is not None and source.get("correlation_id") != correlation_id:
                continue
            if request_id is not None and source.get("request_id") != request_id:
                continue
            matches.append(_public_view(source))
    return tuple(matches)


def _build_record(
    *,
    correlation_id: str,
    component: str,
    operation: str,
    reason: str,
    request_id: str | None,
    origin: str | None,
    reason_code: str | None,
    phase: str | None,
    counts: Mapping[str, object] | None,
    now: datetime | None,
) -> dict[str, object] | None:
    try:
        validate_id(IdKind.CORRELATION, correlation_id)
    except BaseException:
        return None
    instant = now if now is not None else datetime.now(UTC)
    # Structural timestamps are millisecond-quantized (same rule as the stderr sink clock).
    instant = instant.replace(microsecond=(instant.microsecond // 1_000) * 1_000)
    timestamp = format_rfc3339_millis(instant)
    raw: dict[str, object] = {
        "timestamp": timestamp,
        "correlation_id": correlation_id,
        "component": component,
        "operation": operation,
        "reason": reason,
    }
    if request_id is not None:
        raw["request_id"] = request_id
    if origin is not None:
        raw["origin"] = origin
    if reason_code is not None:
        raw["reason_code"] = reason_code
    if phase is not None:
        raw["phase"] = phase
    if counts is not None:
        # Only names already in _FIELD_ORDER survive the projection below, and each still passes
        # the same value fence as every other field: a caller cannot widen the record from here.
        for name, value in counts.items():
            if type(name) is str and name not in raw:
                raw[name] = value
    output: dict[str, object] = {}
    for name in _FIELD_ORDER:
        if name not in raw:
            continue
        value = redact_diagnostic_value(name, raw[name])
        if value is None:
            if name in {"correlation_id", "component", "operation", "reason", "timestamp"}:
                return None
            continue
        output[name] = value
    return output


def _public_view(source: Mapping[str, object]) -> Mapping[str, object]:
    output: dict[str, object] = {}
    for name in _FIELD_ORDER:
        if name not in source:
            continue
        value = redact_diagnostic_value(name, source[name])
        if value is not None:
            output[name] = value
    return output


def _prepare_parent(parent: Path) -> None:
    """Prefer the private-local gate; fall back to a best-effort owner-only mkdir."""

    try:
        ensure_owner_only_dir(parent)
        return
    except BaseException:
        # Tests and unusual layouts (symlinked temp roots) still need a durable record. File mode
        # is enforced on the open descriptor below.
        pass
    parent.mkdir(parents=True, exist_ok=True)
    try:
        parent.chmod(0o700)
    except OSError:
        return


def _append_line(path: Path, line: bytes) -> None:
    _prepare_parent(path.parent)
    flags = os.O_RDWR | os.O_CREAT
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    with _lock:
        descriptor = os.open(path, flags, 0o600)
        try:
            _lock_file(descriptor)
            os.fchmod(descriptor, 0o600)
            os.lseek(descriptor, 0, os.SEEK_END)
            os.write(descriptor, line)
            try:
                size = os.fstat(descriptor).st_size
            except OSError:
                size = 0
            if size > _MAX_FILE_BYTES:
                # Same flocked descriptor: trim cannot race concurrent appends from other
                # processes (daemon / MCP / CLI share this ring on POSIX via fcntl.flock).
                _trim_descriptor(descriptor)
        finally:
            os.close(descriptor)


def _lock_file(descriptor: int) -> None:
    """Exclusive advisory lock when fcntl is available (POSIX hosts of this service)."""

    if fcntl is None:
        return
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
    except OSError:
        return


def _trim_descriptor(descriptor: int) -> None:
    """Rewrite the ring under an already-held exclusive lock on ``descriptor``."""

    try:
        size = os.fstat(descriptor).st_size
    except OSError:
        return
    if size <= _MAX_FILE_BYTES:
        return
    os.lseek(descriptor, 0, os.SEEK_SET)
    raw = os.read(descriptor, size)
    if len(raw) <= _MAX_FILE_BYTES:
        return
    # Drop whole lines from the front until under the cap.
    keep_from = len(raw) - _MAX_FILE_BYTES
    newline = raw.find(b"\n", keep_from)
    trimmed = raw[newline + 1 :] if newline != -1 else raw[-_MAX_FILE_BYTES:]
    os.lseek(descriptor, 0, os.SEEK_SET)
    os.ftruncate(descriptor, 0)
    os.write(descriptor, trimmed)
    try:
        os.fchmod(descriptor, 0o600)
    except OSError:
        return
