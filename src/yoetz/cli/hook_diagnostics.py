"""Owner-private, payload-free diagnostics for degraded Codex hook delivery."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Lock
from typing import Final, cast

from yoetz.cli.hook_timing import hook_pass_timing_summary
from yoetz.config.paths import (
    PathSafetyError,
    ensure_owner_only_dir,
    existing_owner_only_dir,
    state_dir,
)
from yoetz.domain.observation import (
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestResult,
    ObservationSource,
)
from yoetz.domain.values import JsonObject, JsonValue, validate_commitment
from yoetz.ports.control_reasons import CONTROL_ERROR_REASONS
from yoetz.protocol.ids import IdKind, validate_id

try:
    import fcntl
except ImportError:  # pragma: no cover - supported hook hosts are POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "hook_diagnostic_summary",
    "record_hook_diagnostic",
    "record_hook_timing",
    "record_store_lock_event",
]

_MAX_DIAGNOSTIC_BYTES: Final = 64 * 1024
_FILE_NAME: Final = "hook-diagnostics.jsonl"
_LOCK_NAME: Final = ".hook-diagnostics.lock"
_EVENTS: Final = frozenset(
    {
        "SessionStart",
        "SessionEnd",
        "Stop",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PermissionDenied",
        "PermissionRequest",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
        "observe",
        "drain",
        # Not a host hook event: the MCP bridge's own startup, which is the only place
        # a process can compare its serving route against the applied-route record
        # without paying for a host subprocess (issue #537).
        "mcp_serve",
    }
)
_CONTROL_REASONS: Final = CONTROL_ERROR_REASONS
_REASONS: Final = frozenset(
    {
        *(item.value for item in ObservationGapCode),
        *("control_" + reason for reason in _CONTROL_REASONS),
        "drain_diagnostic_unavailable",
        "invalid_session",
        "observe",
        "outbox_overflow",
        "service_unavailable",
        "service_incompatible",
        "vault_locked",
        "mapping_missing",
        "mapping_stale",
        "observation_disabled",
        "paused",
        "timeout",
        "drain_budget_exhausted",
        "drain_lease_contended",
        "drain_preflight_failed",
        # A structural defect in the buffered admission account refused this
        # hook's pre-flush. Before this token the failure reached the outer
        # handler as the bare `observe` reason, so a permanently wedged flush
        # was indistinguishable from any other hook fault (issue #753).
        "admission_flush_invalid",
        # A teardown hook could not persist its session end. The hook stays
        # fail-open, so this is the only record that the session and any
        # temporary selection override are still active (issue #843).
        "session_end_unrecorded",
        # One host event refused at stdin ingress for exceeding
        # ``MAX_HOOK_STDIN_BYTES``, named per host because the reading process
        # is the only thing that still knows which host it was: the body was
        # never parsed, so hook payload identity (tool name, session, paths) is
        # unavailable. Before these, an oversized Cursor write was recorded as
        # the generic `cursor_payload_invalid`, a Codex one degraded to the bare
        # `observe` token, and a Claude Code one recorded nothing at all
        # (issue #667).
        "codex_payload_too_large",
        "claude_payload_too_large",
        "cursor_payload_too_large",
        # Cursor retained a structural identity for one hook body over the
        # trusted cap and inside the skim cap. Content was not captured. Codex
        # and Claude Code do not skim, so they have no sibling of this reason
        # (issue #667).
        "cursor_payload_content_omitted",
        "auto_attach_retry_failed",
        # Why a consented SessionStart (or its turn-boundary retry) produced no
        # mapping (#459). Before these, every auto-attach failure collapsed to a
        # silent None, so an invalid request was indistinguishable from a
        # daemon that was merely still starting.
        "auto_attach_workspace_unbound",
        "auto_attach_request_invalid",
        "auto_attach_conflict",
        "auto_attach_refused",
        "auto_attach_result_invalid",
        "auto_attach_mapping_write_failed",
        "auto_attach_recovery_busy",
        "auto_attach_binding_ambiguous",
        "privacy_authority_required",
        "runtime_gate_contended",
        "runtime_gate_unsafe",
        "stdout_write_failed",
        # Cursor's vendor envelope uses fractional millisecond durations. A
        # malformed or otherwise unsafe host payload is fail-open, but must be
        # distinguishable from a hook that never ran (#593).
        "cursor_payload_invalid",
        # Workspace binding outcomes for every host ingress (#420/#435): an
        # explicit locator that cannot be canonicalized, and a canonical
        # locator that carries no active consent. Without them a dropped hook
        # is indistinguishable from a hook that never fired.
        "workspace_unconsented",
        "workspace_unresolvable",
        "cursor_session_ambiguous",
        # Storage outcomes of a session status read, lowercase of the public
        # error code so the hook advisory, this file, and `observe status`
        # share one vocabulary (#338).
        "storage_corrupt",
        "storage_unsafe",
        # A resume/compact status read that the daemon's repository fence
        # refused (issue #578): the hook connection carried no workspace
        # locator, or the locator resolved to a different repository than the
        # mapped task's route. Neither means the mapping is stale, so neither
        # may be reported as `mapping_stale`.
        "status_workspace_unbound",
        "status_workspace_mismatch",
        # Where a refused status probe got its repository locator (issue #659):
        # the rendered `--workspace`, the host payload's session cwd, the hook's
        # own cwd, no context at all, or a supplied context that could not be
        # canonicalized. Recorded only beside a fence refusal.
        "locator_source_explicit",
        "locator_source_host_payload",
        "locator_source_cwd",
        "locator_absent",
        "locator_unresolvable",
        # A scoped successful `start` post-hook that produced no mapping
        # (issue #581): the host result was not in an admitted shape, its ids
        # failed validation, or the mapping write failed. Before these the
        # bind failed silently and observation kept routing to the old task.
        "start_bind_unparsed",
        "start_bind_invalid_ids",
        "start_bind_child_lane_unbound",
        "start_bind_deferred",
        "start_bind_write_failed",
        # A Codex callback's own transcript proved it came from a delegated child but could not
        # name that child for the callback's session, or contradicted the host child alias
        # (issue #841). The callback stays an explicit attribution gap, never parent work.
        "child_transcript_identity_conflict",
        # Observability only: the end-to-end hook budget is a contract, not an
        # enforcement point. Aborting mid-hook would drop ingest.
        "hook_budget_exceeded",
        "hook_followup_deferred",
        # The Stop-time closure gate (#977): it continued the agent once, closure needed no
        # action, it already fired at this frontier, the host loop guard was set, too little of
        # the Stop budget was left for the status read, or the read failed.
        "closure_gate_continued",
        "closure_gate_not_required",
        "closure_gate_repeat_suppressed",
        "closure_gate_loop_guard",
        "closure_gate_budget_exhausted",
        "closure_gate_unavailable",
        # The delivered continuation also re-asked a recorded blocker once (#977), or its
        # once-per-frontier/once-per-blocker memory could not be written.
        "closure_gate_blocker_rechecked",
        "closure_gate_memory_unwritten",
        # A Stop the host had already continued this turn still re-asked a blocker published
        # since the last gate, once, within the per-turn cap (#985).
        "closure_gate_active_stop_rechecked",
        "hook_slo_breached",
        # A host's automatic tool-call reviewer (Claude Code auto mode) denied a
        # scoped AI-powered ``check`` before Yoetz received it, or a permission
        # rule / another hook did (issue #467). Host tool-call authorization,
        # not a Yoetz AI-powered review result: no AI-powered review status can be inferred.
        "host_auto_review_denied",
        "host_permission_rule_denied",
        # What the same ``PermissionDenied`` hook then said about the hold (issue #857): the
        # grant was confirmed first-hand and the session's one retry was offered; the grant was
        # confirmed but the retry was already spent, the denial came from the owner's own rule,
        # or the host produced no verdict; the retry ledger could not be written so no retry was
        # emitted; or the grant could not be confirmed inside the hook deadline. Payload-free.
        "host_denial_retry_offered",
        "host_denial_retry_exhausted",
        "host_denial_retry_unrecorded",
        "host_denial_grant_unconfirmed",
        # The durable applied route and the live host registration disagree:
        # policy was applied but the host now serves strict (or vice versa),
        # so a fresh Codex process is still on the old route (issue #537).
        "registration_drift",
        # A bounded wait for the shared observation-store lock expired in this
        # pass, and a critical section that held the lock unusually long
        # (issue #689). Both come with a `store_lock` row naming the holder's
        # role and store phase; before these a timeout surfaced as the generic
        # `observe` token or, at workspace resolution, as `workspace_unconsented`.
        "store_lock_timeout",
        "store_lock_long_hold",
    }
)
_STAGES: Final = frozenset(
    {
        "advice",
        "drain",
        "import",
        "store",
        # Formerly unwindowed regions of the pass (#310/#311): workspace
        # resolution and the consent probe before the store window opens, and
        # advice selection, the stdout write and the delivery commit after
        # the drain window closes. Together with 'import' and 'store' they
        # partition the pass, and 'unattributed' names whatever they miss.
        "deliver",
        "resolve",
        "unattributed",
        # Store sub-stage attribution (#290): parse+hydrate of the state file,
        # canonical encode of every size projection and save, and the fsync'd
        # atomic write. The remainder of 'store' is mutation time. Lock wait
        # (#310) is queueing behind another process, not work, and spans the
        # whole pass rather than partitioning any one window.
        "store_encode",
        "store_hydrate",
        "store_lock_hold",
        "store_lock_wait",
        "store_write",
        "total",
    }
)
_MAX_STAGE_MS: Final = 3_600_000
# Closed ownership vocabulary shared with the observation store's lock
# (#689). Phases are store operation names, validated to one token shape.
_STORE_LOCK_ROLES: Final = frozenset(
    {"cli", "coordinator", "hook", "local", "service", "spool_replay", "sweep", "unknown"}
)
_STORE_LOCK_SCOPES: Final = frozenset({"thread", "process"})
_STORE_LOCK_ROW_KEYS: Final = frozenset(
    {
        "event",
        "holder_held_ms",
        "holder_phase",
        "holder_role",
        "holder_waiting",
        "kind",
        "phase",
        "reason",
        "role",
        "scope",
        "ts",
        "waited_ms",
    }
)
# The newest store-lock rows reported beside the reason tallies.
_STORE_LOCK_SUMMARY_ROWS: Final = 16
# The retained file spans days, so an all-time tally reports a failure that was
# diagnosed and fixed two days ago exactly like one happening right now (#310).
# Every count is therefore paired with a recent-window count, and every extreme
# with the moment it was observed, so a reader can date what it is looking at.
_RECENT_WINDOW_SECONDS: Final = 3_600
_SYNC_FALLBACK_PATH: Final = "sync_fallback_spool"
_SYNC_FALLBACK_HARD_CAP_MS: Final = 500
_thread_lock = Lock()


def _closed(value: object, allowed: frozenset[str], fallback: str) -> str:
    if type(value) is str and value in allowed:
        return value
    return fallback


def _render(moment: datetime) -> str:
    return (
        moment.astimezone(UTC)
        .replace(microsecond=(moment.microsecond // 1000) * 1000)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _timestamp() -> str:
    return _render(datetime.now(UTC))


def _parse_timestamp(value: str) -> datetime | None:
    """Return the recorded moment, or None when the row's stamp is unreadable."""

    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


def record_hook_diagnostic(
    reason: str,
    event: str,
    *,
    candidate_count: int | None = None,
    _state: Path | None = None,
) -> None:
    """Append one bounded structural hook failure record, rotating one prior file."""

    row: dict[str, object] = {
        "event": _closed(event, _EVENTS, "unknown_event"),
        "reason": _closed(reason, _REASONS, "unknown_reason"),
        "ts": _timestamp(),
    }
    if (
        reason == "auto_attach_binding_ambiguous"
        and type(candidate_count) is int
        and 2 <= candidate_count <= 1_000_000
    ):
        row["candidate_count"] = candidate_count
    _append_row(row, _state=_state)


def _store_lock_phase_valid(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 64
        and value.isascii()
        and value[0].isalpha()
        and value.islower()
        and all(character.isalnum() or character == "_" for character in value)
    ) or value == "unknown"


def _bounded_ms(value: object) -> int | None:
    if type(value) is not int or value < 0:
        return None
    return min(value, _MAX_STAGE_MS)


def record_store_lock_event(
    event: str,
    lock_event: object,
    *,
    _state: Path | None = None,
) -> bool:
    """Append one payload-free store-lock ownership row for a hook pass (#689).

    ``lock_event`` is the store's ``ObservationStoreLockEvent``. Only closed
    roles, validated phase tokens, a scope, booleans and bounded millisecond
    counts are kept; a malformed event records nothing.
    """

    kind = getattr(lock_event, "kind", None)
    role = getattr(lock_event, "role", None)
    phase = getattr(lock_event, "phase", None)
    if type(role) is not str or role not in _STORE_LOCK_ROLES or not _store_lock_phase_valid(phase):
        return False
    row: dict[str, object] = {
        "event": _closed(event, _EVENTS, "unknown_event"),
        "kind": "store_lock",
        "phase": phase,
        "role": role,
        "ts": _timestamp(),
        "holder_role": None,
        "holder_phase": None,
        "holder_held_ms": None,
        "holder_waiting": None,
        "scope": None,
        "waited_ms": None,
    }
    if kind == "timeout":
        timeout = getattr(lock_event, "timeout", None)
        holder_role = getattr(timeout, "holder_role", None)
        holder_phase = getattr(timeout, "holder_phase", None)
        scope = getattr(timeout, "scope", None)
        waiting = getattr(timeout, "holder_waiting", None)
        if (
            type(holder_role) is not str
            or holder_role not in _STORE_LOCK_ROLES
            or not _store_lock_phase_valid(holder_phase)
            or type(scope) is not str
            or scope not in _STORE_LOCK_SCOPES
            or type(waiting) is not bool
        ):
            return False
        row.update(
            {
                "reason": "store_lock_timeout",
                "holder_role": holder_role,
                "holder_phase": holder_phase,
                "holder_held_ms": _bounded_ms(getattr(timeout, "holder_held_ms", None)),
                "holder_waiting": waiting,
                "scope": scope,
                "waited_ms": _bounded_ms(getattr(timeout, "waited_ms", None)),
            }
        )
    elif kind == "long_hold":
        held = _bounded_ms(getattr(lock_event, "held_ms", None))
        if held is None:
            return False
        row.update({"reason": "store_lock_long_hold", "holder_held_ms": held})
    else:
        return False
    return _append_row(row, _state=_state)


def _store_lock_row(row: Mapping[str, object]) -> JsonObject | None:
    """Validate one retained store-lock row read back from the mutable file."""

    if frozenset(row) != _STORE_LOCK_ROW_KEYS or row.get("kind") != "store_lock":
        return None
    # The file is mutable: reject containers before any set membership lookup.
    if any(type(row.get(key)) is not str for key in ("reason", "event", "role")):
        return None
    reason = row.get("reason")
    if reason not in {"store_lock_timeout", "store_lock_long_hold"}:
        return None
    if row.get("event") not in _EVENTS and row.get("event") != "unknown_event":
        return None
    if row.get("role") not in _STORE_LOCK_ROLES or not _store_lock_phase_valid(row.get("phase")):
        return None
    stamp = row.get("ts")
    if type(stamp) is not str or _parse_timestamp(stamp) is None:
        return None
    held = row.get("holder_held_ms")
    if held is not None and _bounded_ms(held) != held:
        return None
    if reason == "store_lock_timeout":
        waited = row.get("waited_ms")
        if (
            type(row.get("holder_role")) is not str
            or row.get("holder_role") not in _STORE_LOCK_ROLES
            or not _store_lock_phase_valid(row.get("holder_phase"))
            or type(row.get("scope")) is not str
            or row.get("scope") not in _STORE_LOCK_SCOPES
            or type(row.get("holder_waiting")) is not bool
            or (waited is not None and _bounded_ms(waited) != waited)
        ):
            return None
    elif held is None or any(
        row.get(key) is not None
        for key in ("holder_role", "holder_phase", "holder_waiting", "scope", "waited_ms")
    ):
        return None
    return JsonObject(cast(dict[str, JsonValue], dict(row)))


def record_drain_failure(
    failure: ObservationIngestResult,
    envelope: ObservationEnvelope,
    disposition: str,
    *,
    _state: Path | None,
) -> bool:
    """Keep bounded causal facts; source identity is a commitment, never raw input."""

    from yoetz.application.observation_drain import ObservationControlFailure

    control = failure if isinstance(failure, ObservationControlFailure) else None
    reason = failure.reason
    correlation = None if control is None else control.correlation_id
    stage = "typed_ingest" if control is None else control.failure_stage
    try:
        session = validate_commitment(envelope.session_commitment)
        source = validate_commitment(envelope.cursor.last_source_commitment)
        if correlation is not None:
            validate_id(IdKind.CORRELATION, correlation)
        if control is not None and control.control_reason not in _CONTROL_REASONS:
            return False
        if reason not in _REASONS or stage not in {
            "control",
            "request_encode",
            "response_decode",
            "typed_ingest",
        }:
            return False
        if disposition not in {"retry", "quarantine"}:
            return False
    except ValueError, TypeError:
        return False
    return _append_row(
        {
            "kind": "drain_failure",
            "event": "drain",
            "ts": _timestamp(),
            "reason": reason,
            "control_reason": None if control is None else control.control_reason,
            "control_retryable": None if control is None else control.control_retryable,
            "stage": stage,
            "disposition": disposition,
            "correlation_id": correlation,
            "session_commitment": session,
            "source_commitment": source,
            "source": envelope.source.value,
            "generation": envelope.cursor.source_generation,
            "position": envelope.cursor.event_position,
        },
        _state=_state,
    )


def _append_row(row: dict[str, object], *, _state: Path | None) -> bool:
    root = state_dir() if _state is None else _state
    directory = root / "observation"
    path = directory / _FILE_NAME
    rotated = directory / f"{_FILE_NAME}.1"
    lock_path = directory / _LOCK_NAME
    line = json.dumps(row, separators=(",", ":"), sort_keys=True).encode("utf-8") + b"\n"
    try:
        ensure_owner_only_dir(directory)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        with _thread_lock:
            lock_descriptor = os.open(lock_path, flags, 0o600)
            try:
                os.fchmod(lock_descriptor, 0o600)
                if fcntl is not None:
                    fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
                if path.is_symlink() or rotated.is_symlink():
                    return False
                try:
                    size = path.lstat().st_size
                except FileNotFoundError:
                    size = 0
                if size + len(line) > _MAX_DIAGNOSTIC_BYTES:
                    rotated.unlink(missing_ok=True)
                    if path.exists():
                        if size <= _MAX_DIAGNOSTIC_BYTES:
                            os.replace(path, rotated)
                            rotated_descriptor = os.open(
                                rotated,
                                os.O_RDONLY
                                | getattr(os, "O_CLOEXEC", 0)
                                | getattr(os, "O_NOFOLLOW", 0),
                            )
                            try:
                                os.fchmod(rotated_descriptor, 0o600)
                            finally:
                                os.close(rotated_descriptor)
                        else:
                            path.unlink()
                descriptor = os.open(
                    path,
                    os.O_WRONLY
                    | os.O_APPEND
                    | os.O_CREAT
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                )
                try:
                    os.fchmod(descriptor, 0o600)
                    written = 0
                    while written < len(line):
                        written += os.write(descriptor, line[written:])
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            finally:
                os.close(lock_descriptor)
    except OSError, PathSafetyError, ValueError:
        return False
    return True


def record_hook_timing(
    event: str,
    *,
    ms: int,
    stages: Mapping[str, int],
    path: str | None = None,
    _state: Path | None = None,
) -> None:
    """Append one bounded end-to-end timing row for a hook pass.

    Emitted only over budget, at session boundaries, or on a legacy spool
    hard-cap breach: the diagnostics file is 64 KiB with one rotation, and a
    per-hook row would halve the retained failure-reason window. The typical
    cost of every pass lives in the separate ``hook_timing`` aggregate (#915).
    """

    bounded = {
        name: max(0, min(int(value), _MAX_STAGE_MS))
        for name, value in stages.items()
        if name in _STAGES and type(value) is int and not isinstance(value, bool)
    }
    row: dict[str, object] = {
        "event": _closed(event, _EVENTS, "unknown_event"),
        "kind": "timing",
        "ms": max(0, min(int(ms), _MAX_STAGE_MS)),
        "stages": dict(sorted(bounded.items())),
        "ts": _timestamp(),
    }
    if path in {"sync_fallback_spool", "async_host", "ordinary_sync"}:
        row["path"] = path
    _append_row(row, _state=_state)


@dataclass(slots=True)
class _Recency:
    """One reason's tally paired with the span of moments it actually covers."""

    count: int = 0
    recent: int = 0
    first: datetime | None = None
    last: datetime | None = None

    def observe(self, moment: datetime | None, *, fresh: bool) -> None:
        self.count += 1
        if fresh:
            self.recent += 1
        if moment is None:
            return
        if self.first is None or moment < self.first:
            self.first = moment
        if self.last is None or moment > self.last:
            self.last = moment

    def as_json(self) -> JsonObject:
        return JsonObject(
            {
                "count": self.count,
                "first_seen": None if self.first is None else _render(self.first),
                "last_seen": None if self.last is None else _render(self.last),
                "recent": self.recent,
            }
        )


def _empty_recent_values() -> list[int]:
    return []


def _empty_timings_by_path() -> dict[str, _Timings]:
    return {}


@dataclass(slots=True)
class _Timings:
    """Timing rows, kept datable so a one-off extreme is not read as the norm."""

    count: int = 0
    recent: int = 0
    last_ms: int | None = None
    max_ms: int | None = None
    max_at: datetime | None = None
    recent_max_ms: int | None = None
    recent_values: list[int] = field(default_factory=_empty_recent_values)
    by_path: dict[str, _Timings] = field(default_factory=_empty_timings_by_path)

    def observe(
        self,
        ms: int,
        moment: datetime | None,
        *,
        fresh: bool,
        path: str | None = None,
    ) -> None:
        self.count += 1
        self.last_ms = ms
        if self.max_ms is None or ms > self.max_ms:
            self.max_ms = ms
            self.max_at = moment
        if not fresh:
            return
        self.recent += 1
        self.recent_values.append(ms)
        if self.recent_max_ms is None or ms > self.recent_max_ms:
            self.recent_max_ms = ms
        if path is not None:
            self.by_path.setdefault(path, _Timings()).observe(ms, moment, fresh=True)

    def _recent_p95_ms(self) -> int | None:
        if not self.recent_values:
            return None
        ordered = sorted(self.recent_values)
        # Nearest-rank p95 intentionally fails closed: a single retained
        # sample is its own p95, rather than looking healthy by interpolation.
        return ordered[(95 * len(ordered) + 99) // 100 - 1]

    def as_json(self) -> JsonObject:
        return JsonObject(
            {
                "count": self.count,
                "last_ms": self.last_ms,
                "max_ms": self.max_ms,
                "max_ts": None if self.max_at is None else _render(self.max_at),
                "recent_count": self.recent,
                "recent_max_ms": self.recent_max_ms,
                "recent_p95_ms": self._recent_p95_ms(),
                "paths": JsonObject(
                    {
                        path: JsonObject(
                            {
                                "count": item.count,
                                "recent_count": item.recent,
                                "recent_p95_ms": item._recent_p95_ms(),
                                # Spool rows are hard-cap breaches only since #915, so a p95
                                # over them is no reading of the 250 ms target; that target is
                                # read against every pass in ``pass_timings``.
                                "p95_target_ms": None,
                                "hard_cap_ms": _SYNC_FALLBACK_HARD_CAP_MS
                                if path == _SYNC_FALLBACK_PATH
                                else None,
                                "recent_hard_cap_breach_count": sum(
                                    value > _SYNC_FALLBACK_HARD_CAP_MS
                                    for value in item.recent_values
                                )
                                if path == _SYNC_FALLBACK_PATH
                                else 0,
                            }
                        )
                        for path, item in sorted(self.by_path.items(), key=lambda item: item[0])
                    }
                ),
            }
        )


def _read_rows(
    directory: Path,
) -> tuple[
    list[dict[str, str]],
    list[tuple[int, str, str | None]],
    list[JsonObject],
    list[JsonObject],
]:
    """Return retained failure, timing, drain and store-lock rows, oldest file first."""

    rows: list[dict[str, str]] = []
    timings: list[tuple[int, str, str | None]] = []
    attempts: list[JsonObject] = []
    locks: list[JsonObject] = []
    try:
        # A status read never creates the observation directory it reports on.
        if not existing_owner_only_dir(directory):
            return [], [], [], []
        for path in (
            directory / f"{_FILE_NAME}.1",
            directory / _FILE_NAME,
        ):
            if path.is_symlink():
                continue
            try:
                facts = path.lstat()
                if (
                    facts.st_uid != os.geteuid()
                    or facts.st_mode & 0o077
                    or facts.st_size <= 0
                    or facts.st_size > _MAX_DIAGNOSTIC_BYTES
                ):
                    continue
                raw = path.read_bytes()
            except FileNotFoundError:
                continue
            for line in raw.splitlines():
                try:
                    parsed: object = json.loads(line)
                except UnicodeError, json.JSONDecodeError:
                    continue
                if type(parsed) is not dict:
                    continue
                row = cast(dict[str, object], parsed)
                if row.get("kind") == "store_lock":
                    lock_row = _store_lock_row(row)
                    if lock_row is not None:
                        locks.append(lock_row)
                        # The reason also counts toward the ordinary tallies, so a
                        # contended store is visible where every other failure is.
                        rows.append(
                            {
                                "event": cast(str, row["event"]),
                                "reason": cast(str, row["reason"]),
                                "ts": cast(str, row["ts"]),
                            }
                        )
                    continue
                if row.get("kind") == "drain_failure":
                    allowed = {
                        "kind",
                        "event",
                        "ts",
                        "reason",
                        "control_reason",
                        "control_retryable",
                        "stage",
                        "disposition",
                        "correlation_id",
                        "session_commitment",
                        "source_commitment",
                        "source",
                        "generation",
                        "position",
                    }
                    if set(row) != allowed:
                        continue
                    # Files are mutable local input: validate every projected value.
                    try:
                        reason = row["control_reason"]
                        if reason is None:
                            if (
                                row["reason"] not in _REASONS
                                or row["stage"] != "typed_ingest"
                                or row["control_retryable"] is not None
                            ):
                                continue
                        elif type(reason) is not str or reason not in _CONTROL_REASONS:
                            continue
                        elif (
                            row["reason"] != "control_" + reason
                            or type(row["control_retryable"]) is not bool
                        ):
                            continue
                        if row["event"] != "drain":
                            continue
                        for key in ("session_commitment", "source_commitment"):
                            validate_commitment(cast(str, row[key]))
                        if row["correlation_id"] is not None:
                            validate_id(IdKind.CORRELATION, cast(str, row["correlation_id"]))
                        if row["stage"] not in {
                            "control",
                            "request_encode",
                            "response_decode",
                            "typed_ingest",
                        }:
                            continue
                        if row["disposition"] not in {"retry", "quarantine"}:
                            continue
                        if row["source"] not in {item.value for item in ObservationSource}:
                            continue
                        if any(
                            type(row[key]) is not int or not 0 <= cast(int, row[key]) <= 2**53 - 1
                            for key in ("generation", "position")
                        ):
                            continue
                        if type(row["ts"]) is not str or _parse_timestamp(row["ts"]) is None:
                            continue
                        attempts.append(JsonObject(cast(dict[str, JsonValue], row)))
                    except ValueError, TypeError:
                        continue
                    continue
                if set(row) in (
                    {"event", "kind", "ms", "stages", "ts"},
                    {"event", "kind", "ms", "stages", "ts", "path"},
                ):
                    # Timing rows are a second shape on the same file; they must
                    # never inflate the failure-reason counts.
                    total = row.get("ms")
                    stamp = row.get("ts")
                    path_value = row.get("path")
                    if (
                        row.get("kind") == "timing"
                        and type(total) is int
                        and type(stamp) is str
                        and (
                            path_value is None
                            or path_value in {"sync_fallback_spool", "async_host", "ordinary_sync"}
                        )
                    ):
                        timings.append((total, stamp, cast(str | None, path_value)))
                    continue
                keys = set(row)
                if keys == {"event", "reason", "ts", "candidate_count"}:
                    candidate_count = row["candidate_count"]
                    if (
                        row["reason"] != "auto_attach_binding_ambiguous"
                        or type(candidate_count) is not int
                        or not 2 <= candidate_count <= 1_000_000
                    ):
                        continue
                elif keys != {"event", "reason", "ts"}:
                    continue
                if any(type(row.get(key)) is not str for key in ("event", "reason", "ts")):
                    continue
                rows.append(
                    {
                        "event": cast(str, row["event"]),
                        "reason": cast(str, row["reason"]),
                        "ts": cast(str, row["ts"]),
                    }
                )
    except OSError, PathSafetyError:
        return [], [], [], []
    return rows, timings, attempts, locks


def hook_diagnostic_summary(
    *,
    _state: Path | None = None,
    _now: datetime | None = None,
) -> JsonObject:
    """Return a bounded structural summary of the current and rotated diagnostics.

    Every tally is reported twice — over everything retained, and over the last
    `window_seconds` — and every count carries the span it covers, so a reader
    can tell a live failure from one that was fixed days ago (#310).

    ``pass_timings`` is the separate bounded aggregate over every hook pass
    (#915); ``timings`` stays the over-budget and session-boundary rows.
    """

    root = state_dir() if _state is None else _state
    rows, timings, attempts, locks = _read_rows(root / "observation")
    now = datetime.now(UTC) if _now is None else _now.astimezone(UTC)
    horizon = now - timedelta(seconds=_RECENT_WINDOW_SECONDS)
    overall = _Recency()
    reasons: dict[str, _Recency] = {}
    for row in rows:
        moment = _parse_timestamp(row["ts"])
        # An unreadable stamp is never counted as recent: an undatable row is
        # exactly the thing this summary must stop presenting as live.
        fresh = moment is not None and horizon <= moment <= now
        overall.observe(moment, fresh=fresh)
        reasons.setdefault(row["reason"], _Recency()).observe(moment, fresh=fresh)
    timing = _Timings()
    for total, stamp, path in timings:
        moment = _parse_timestamp(stamp)
        timing.observe(
            total,
            moment,
            fresh=moment is not None and horizon <= moment <= now,
            path=path,
        )
    last = rows[-1] if rows else None
    return JsonObject(
        {
            "drain_failures": tuple(attempts[-32:]),
            "drain_failure_retained_count": len(attempts),
            "drain_failure_history_complete": False,
            "count": overall.count,
            "first_seen": None if overall.first is None else _render(overall.first),
            "last_event": None if last is None else last["event"],
            "last_reason": None if last is None else last["reason"],
            "last_seen": None if overall.last is None else _render(overall.last),
            "reasons": JsonObject(
                {
                    name: tally.as_json()
                    for name, tally in sorted(reasons.items(), key=lambda item: item[0].encode())
                }
            ),
            "recent_count": overall.recent,
            # Newest payload-free ownership facts for lock timeouts and long
            # holds: which role and store phase held the lock, and for how long.
            "store_lock_events": tuple(locks[-_STORE_LOCK_SUMMARY_ROWS:]),
            "pass_timings": hook_pass_timing_summary(_state=_state, _now=_now),
            "timings": timing.as_json(),
            "window_seconds": _RECENT_WINDOW_SECONDS,
        }
    )
