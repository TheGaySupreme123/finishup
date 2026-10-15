"""Replay public-safe observation workloads against an isolated local store.

This benchmark measures the current observation boundary before a selection
policy is applied.  It deliberately uses synthetic labels and digests only:
the capture figures are *eligible-content byte estimates*, not native capture
or proof that plaintext was retained.  The harness never starts a service,
opens a vault, reads a user session, or exports a transcript.

Example::

    uv run python scripts/benchmark_observation_selection.py \
        --revision e56f7d0a873281ea05c95a0bcb8eb348d65cce4a

The count values are candidate queue targets from issue #687.  They are input
workload sizes in this baseline; the current 512-row limit is reported
separately and is never changed by the harness.
"""

from __future__ import annotations

import argparse
import json
import os
import resource
import shutil
import subprocess
import tempfile
import time
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, cast

import finishup.adapters.integrations.observation_local as local_mod
from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.adapters.integrations.observation_local import (
    LocalObservationStore,
    self_observation_deliverable,
)
from finishup.domain.observation import (
    ObservationEnvelope,
    ObservationIngestDisposition,
    ObservationSource,
    ObservationStatusQuery,
)
from finishup.domain.values import JsonObject, JsonValue, Timestamp

if TYPE_CHECKING:
    from finishup.domain.observation_settings import ObservationSelection

BASELINE_REVISION: Final = "e56f7d0a873281ea05c95a0bcb8eb348d65cce4a"
CANDIDATE_QUEUE_TARGETS: Final = (512, 2_048, 8_192)
DEFAULT_FANOUT: Final = 8
CHANGED_PATHS_DIGEST: Final = "sha256:" + "e" * 64
COMMAND_DIGEST: Final = "sha256:" + "f" * 64
SELECTION_FENCE: Final = "sha256:" + "1" * 64
SELECTION_TASK_ID: Final = "tsk_00000000-0000-4000-8000-000000000687"
SELECTION_SESSION_ID: Final = "ses_00000000-0000-4000-8000-000000000687"
SELECTION_WRITER_ID: Final = "wri_00000000-0000-4000-8000-000000000687"
SELECTION_AUTHORITY_GENERATION: Final = "sha256:" + "2" * 64
BENCHMARK_TIMESTAMP: Final = Timestamp("2026-01-01T00:00:00.000Z")
PROTECTED_CLASSES: Final = (
    "failed_read",
    "denial",
    "cancellation",
    "mutation",
    "negative_verification",
    "retry_recovery",
    "closure_mutation",
    "unknown_operation",
    "ambiguous_operation",
    "nonzero_read",
)


@dataclass(frozen=True, slots=True)
class SyntheticEvent:
    """One structural-only hook event and its capture-cost proxy."""

    event_index: int
    call_index: int
    phase: str
    session_id: str
    source: ObservationSource
    category: str
    tool_name: str
    success: bool
    capture_proxy_bytes: int
    fields: Mapping[str, JsonValue]

    @property
    def call_id(self) -> str:
        return f"bench687-call-{self.call_index:08d}"

    def hook_payload(self) -> dict[str, JsonValue]:
        payload: dict[str, JsonValue] = {
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "tool_call_id": self.call_id,
            "correlation_id": self.call_id,
            "duration_ms": 2,
        }
        if self.source is ObservationSource.CLAUDE_HOOK:
            payload["capability_profile_id"] = "claude-code-cli-local-project-2.1.241"
        elif self.source is ObservationSource.CURSOR_HOOK:
            payload["capability_profile_id"] = "cursor-ide-3.17.8"
        if self.phase == "PostToolUse" or not self.success:
            payload["success"] = self.success
        payload.update(self.fields)
        return payload


def _call_shape(call_index: int) -> tuple[str, str, bool, int, dict[str, JsonValue]]:
    """Return a conservative, repeatable synthetic operation shape.

    Every twentieth-ish call is intentionally a protected or adversarial
    category.  No category is selected based on a user-controlled label.
    """

    family = call_index % 24
    if family < 12:
        return "routine_success", ("read_file", "search", "list_dir")[family % 3], True, 256, {}
    if family == 12:
        return (
            "failed_read",
            "read_file",
            False,
            512,
            {
                "exit_status": 1,
                "result_status": "failed",
            },
        )
    if family == 13:
        return (
            "denial",
            "shell",
            False,
            384,
            {
                "denied": True,
                "permission_decision": "deny",
            },
        )
    if family == 14:
        return "cancellation", "shell", False, 384, {"result_status": "cancelled"}
    if family == 15:
        return (
            "mutation",
            "write_file",
            True,
            1_024,
            {
                "action": "edit",
                "changed_paths_digest": CHANGED_PATHS_DIGEST,
            },
        )
    if family == 16:
        return (
            "negative_verification",
            "pytest",
            False,
            768,
            {
                "action": "check",
                "exit_status": 1,
                "result_status": "failed",
            },
        )
    if family == 17:
        attempt = 1 if call_index % 48 == 17 else 2
        return (
            "retry_recovery",
            "read_file",
            attempt == 2,
            512,
            {
                "attempt": attempt,
                "exit_status": 0 if attempt == 2 else 1,
                # Keep recovery protected: an otherwise successful retry is
                # still a retry/recovery boundary, so the partial outcome fact
                # must prevent routine summarization.
                "result_status": "partial" if attempt == 2 else "failed",
            },
        )
    if family == 18:
        return "closure_routine", "mcp__finishup__status", True, 0, {}
    if family == 19:
        return (
            "closure_mutation",
            "mcp__finishup__check",
            True,
            0,
            {
                "action": "check",
                "result_status": "success",
            },
        )
    if family == 20:
        return (
            "unknown_operation",
            "mystery_tool",
            True,
            640,
            {
                "mapping_hint": "unknown-tool",
            },
        )
    if family == 21:
        return (
            "ambiguous_operation",
            "shell",
            True,
            640,
            {
                "command_digest": COMMAND_DIGEST,
                "mapping_hint": "ambiguous-shell",
            },
        )
    if family == 22:
        return (
            "nonzero_read",
            "read_file",
            False,
            512,
            {
                "exit_status": 2,
                "result_status": "failed",
            },
        )
    return "routine_success", "search", True, 256, {}


def _host_source(host: str) -> ObservationSource:
    sources = {
        "codex": ObservationSource.CODEX_HOOK,
        "claude": ObservationSource.CLAUDE_HOOK,
        "cursor": ObservationSource.CURSOR_HOOK,
    }
    try:
        return sources[host]
    except KeyError as exc:
        raise ValueError("host must be codex, claude, or cursor") from exc


def synthetic_events(
    count: int,
    *,
    fanout: int = DEFAULT_FANOUT,
    host: str = "codex",
) -> tuple[SyntheticEvent, ...]:
    """Build deterministic hook-shaped events with bounded public-safe fields."""

    if type(count) is not int or isinstance(count, bool) or count < 1:
        raise ValueError("count must be a positive integer")
    if type(fanout) is not int or isinstance(fanout, bool) or fanout < 1:
        raise ValueError("fanout must be a positive integer")
    source = _host_source(host)
    result: list[SyntheticEvent] = []
    for event_index in range(count):
        call_index = event_index // 2
        phase = "PreToolUse" if event_index % 2 == 0 else "PostToolUse"
        category, tool_name, success, capture_bytes, fields = _call_shape(call_index)
        result.append(
            SyntheticEvent(
                event_index=event_index,
                call_index=call_index,
                phase=phase,
                session_id=f"bench687-session-{call_index % fanout:04d}",
                source=source,
                category=category,
                tool_name=tool_name,
                success=success,
                capture_proxy_bytes=capture_bytes if phase == "PostToolUse" else 0,
                fields=fields,
            )
        )
    return tuple(result)


def _percentile(values: Sequence[float], percentile: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, int(round((len(ordered) - 1) * percentile))))
    return ordered[index]


def latency_summary(values: Sequence[float]) -> dict[str, float]:
    """Return tail timings in milliseconds without exposing event content."""

    if not values:
        return {"count": 0.0, "p50_ms": 0.0, "p95_ms": 0.0, "p99_ms": 0.0, "max_ms": 0.0}
    return {
        "count": float(len(values)),
        "p50_ms": _percentile(values, 0.50),
        "p95_ms": _percentile(values, 0.95),
        "p99_ms": _percentile(values, 0.99),
        "max_ms": max(values),
    }


def _rss_bytes() -> int:
    value = int(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss)
    return value if os.uname().sysname == "Darwin" else value * 1_024


def _store_limit(name: str, fallback: int) -> int:
    """Read a diagnostic limit without making it part of the public store API."""

    value = getattr(local_mod, name, fallback)
    return int(value) if type(value) is int and not isinstance(value, bool) else fallback


def _benchmark_temp_root(base_dir: Path | None = None) -> Path:
    """Create one canonical, owner-only root for a replay workload.

    ``/tmp`` is a symlink on macOS and ``/private/tmp`` is not portable to
    Linux. Resolve the platform-provided temporary directory before creating
    the leaf so the local store's path-safety check sees a symlink-free path.
    ``base_dir`` is an explicit test seam and is never taken from a workload
    payload.
    """

    base = Path(tempfile.gettempdir()) if base_dir is None else base_dir
    canonical_base = base.expanduser().resolve()
    root = Path(tempfile.mkdtemp(prefix="yz687-observation-", dir=canonical_base))
    root.chmod(0o700)
    return root


def _effective_capture_role(
    classification: Any,
    event: SyntheticEvent,
    *,
    focused: bool,
) -> str:
    """Map conservative classification facts to the selected detail contract.

    The classifier intentionally reports ``none`` for routine pre-events and
    proven routine post-events because Focused retention omits their optional
    content.  Detailed retention permits those optional arms after the
    selection gate.  Codex's native hook contract has no input-content
    consumer, so its routine pre-events remain ``none`` even in Detailed.
    This helper reports that *eligible* role for accounting; the harness still
    never invokes native extraction or retains plaintext.
    """

    role = classification.content_role.value
    if focused:
        return role
    if (
        classification.routine_candidate
        and event.phase == "PreToolUse"
        and event.source is not ObservationSource.CODEX_HOOK
    ):
        return "tool_input"
    if classification.proven_routine_success and event.phase == "PostToolUse":
        return "tool_output"
    return role


def _selection_api() -> tuple[Any, Any, Any, Any, Any]:
    """Load the optional post-baseline selected-admission API on demand."""

    try:
        from finishup.adapters.integrations.observation_admission import build_routine_read_summary
        from finishup.domain.observation_selection import classify_observation
        from finishup.domain.observation_settings import (
            ObservationCapacityProfile,
            ObservationDetailProfile,
            ObservationSelection,
        )
    except ImportError as exc:
        raise RuntimeError(
            "selected admission is unavailable at the requested baseline revision"
        ) from exc
    return (
        build_routine_read_summary,
        classify_observation,
        ObservationCapacityProfile,
        ObservationDetailProfile,
        ObservationSelection,
    )


def selection_matrix() -> tuple[ObservationSelection, ...]:
    """Return all six independently selectable detail/capacity combinations."""

    _summary, _classify, capacity_profile, detail_profile, selection_type = _selection_api()
    return tuple(
        selection_type(detail, capacity)
        for detail in (detail_profile.FOCUSED, detail_profile.DETAILED)
        for capacity in (
            capacity_profile.STANDARD,
            capacity_profile.LARGER,
            capacity_profile.LARGEST,
        )
    )


def _current_revision(checkout: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=checkout,
            check=True,
            capture_output=True,
            text=True,
        )
    except OSError, subprocess.CalledProcessError:
        return "unknown"
    return completed.stdout.strip() or "unknown"


def _sum_spool_bytes(root: Path) -> int:
    spool_root = root / "hook-spool"
    return sum(
        path.stat().st_size
        for path in (*spool_root.glob("*.jsonl"), *spool_root.glob("*.draining"))
        if path.is_file()
    )


def _state_size(root: Path) -> int:
    return max(
        (
            path.stat().st_size
            for path in (root / "observation" / "workspaces").glob("*.json")
            if path.is_file()
        ),
        default=0,
    )


def _safe_envelope(
    *,
    session_commitment: str,
    event: SyntheticEvent,
    position: int,
    payload: Mapping[str, object],
    key_material: bytes,
    selection_route: bool,
) -> ObservationEnvelope:
    # Use the production hook mapper so the benchmark exercises the same
    # service-owned routine marker and host-specific source identity as a real
    # adapter.  The mapper keeps prose out of the envelope and never reads the
    # synthetic workspace path.
    from finishup.cli.observe_hooks import map_hook_payload_to_envelope

    envelope = map_hook_payload_to_envelope(
        event.phase,
        cast(Mapping[str, JsonValue], dict(payload)),
        session_commitment=session_commitment,
        event_ordinal=position,
        key_material=key_material,
        source_generation=1,
        source=event.source,
    )
    if selection_route:
        # Selected summaries require a complete owner route. These fixed,
        # synthetic IDs stand in for an already-authorized disposable route;
        # they do not come from host input and cannot retarget an actual task.
        envelope = replace(
            envelope,
            structural_payload=JsonObject(
                {
                    **envelope.structural_payload,
                    "selection_task_id": SELECTION_TASK_ID,
                    "selection_session_id": SELECTION_SESSION_ID,
                    "selection_writer_id": SELECTION_WRITER_ID,
                    "selection_authority_generation": SELECTION_AUTHORITY_GENERATION,
                }
            ),
        )
    return envelope


def run_workload(
    count: int,
    *,
    fanout: int = DEFAULT_FANOUT,
    host: str = "codex",
    revision: str = BASELINE_REVISION,
    checkout: Path | None = None,
    selection: ObservationSelection | None = None,
) -> dict[str, Any]:
    """Run one isolated replay and return public-safe metrics."""

    if type(count) is not int or isinstance(count, bool) or count < 1:
        raise ValueError("count must be a positive integer")
    if type(fanout) is not int or isinstance(fanout, bool) or fanout < 1:
        raise ValueError("fanout must be a positive integer")
    checkout = Path.cwd() if checkout is None else checkout
    events = synthetic_events(count, fanout=fanout, host=host)
    root = _benchmark_temp_root()
    workspace_path = root / "workspace"
    workspace_path.mkdir(mode=0o700)
    writes: list[tuple[str, int]] = []
    original_atomic_write = getattr(local_mod, "_atomic_write")

    def tracked_atomic_write(path: Path, payload: bytes) -> None:
        original_atomic_write(path, payload)
        writes.append((path.suffix, len(payload)))

    setattr(local_mod, "_atomic_write", tracked_atomic_write)
    process_started = time.process_time_ns()
    wall_started = time.perf_counter_ns()
    try:
        store = LocalObservationStore(_state=root)
        workspace = store.workspace_commitment(str(workspace_path))
        store.grant_consent(workspace, BENCHMARK_TIMESTAMP)
        sessions = {
            raw: store.bind_codex_session(workspace, raw)
            for raw in sorted({event.session_id for event in events})
        }
        spool = HookSpool(_state=root)
        key_material = store.key_material()
        selection_api = None if selection is None else _selection_api()
        if selection_api is not None:
            # Owner authorization is represented only in this disposable state.
            # Session scope keeps each host lane explicit when a future store
            # enforces capacity from the selected setting.
            set_session_selection = getattr(store, "set_session_selection", None)
            if not callable(set_session_selection):
                raise RuntimeError("selected admission requires session selection settings")
            for session in sessions.values():
                set_session_selection(
                    workspace,
                    session,
                    selection,
                    set_at=BENCHMARK_TIMESTAMP,
                )
        if selection_api is not None:
            assert selection is not None
            summary_builder, classify, _capacity_profile, detail_profile, _selection_type = (
                selection_api
            )
            focused_selection = selection.detail is detail_profile.FOCUSED
        else:
            summary_builder = classify = detail_profile = None
            focused_selection = False
        # Setup writes (key, consent, and bindings) are excluded from workload totals.
        writes.clear()
        for key in store.stage_timings_ms:
            store.stage_timings_ms[key] = 0.0

        hook_latencies: list[float] = []
        hook_success_count = 0
        for event in events:
            started = time.perf_counter_ns()
            if spool.append(
                workspace=str(workspace_path),
                event_name=event.phase,
                payload=event.hook_payload(),
            ):
                hook_success_count += 1
            hook_latencies.append((time.perf_counter_ns() - started) / 1_000_000)
        spool_bytes = _sum_spool_bytes(root)

        event_by_call_phase = {(event.call_id, event.phase): event for event in events}
        accepted_by_class: Counter[str] = Counter()
        ingest_rejected_by_reason: Counter[str] = Counter()
        outbox_admitted_by_class: Counter[str] = Counter()
        outbox_rejected_by_reason: Counter[str] = Counter()
        capture_calls_by_class: Counter[str] = Counter()
        capture_bytes_by_class: Counter[str] = Counter()
        ingest_latencies: list[float] = []
        outbox_latencies: list[float] = []
        replay_batch_latencies: list[float] = []
        selected_delivered_by_class: Counter[str] = Counter()
        selected_capture_roles: Counter[str] = Counter()
        selected_commit_failures = 0
        selected_self_suppressed = 0
        selected_flush_ok = True
        selected_deliveries_attempted = 0
        selected_capture_candidate_bytes_by_role: Counter[str] = Counter()
        event_by_identity: dict[str, str] = {}
        positions: defaultdict[str, int] = defaultdict(int)
        claimed_records = 0
        claim_batches = 0
        while spool.has_pending(workspace):
            batch_started = time.perf_counter_ns()
            with spool.claim(workspace, limit=64) as rows:
                claim_batches += 1
                if not rows:
                    raise RuntimeError("synthetic spool claim made no progress")
                claimed_records += len(rows)
                for row in rows:
                    raw_session = row.payload.get("session_id")
                    call_id = row.payload.get("tool_call_id")
                    if type(raw_session) is not str or type(call_id) is not str:
                        raise RuntimeError("synthetic spool payload missing identity")
                    event = event_by_call_phase[(call_id, row.event_name)]
                    session = sessions[raw_session]
                    positions[raw_session] += 1
                    envelope = _safe_envelope(
                        session_commitment=session,
                        event=event,
                        position=positions[raw_session],
                        payload=row.payload,
                        key_material=key_material,
                        selection_route=selection_api is not None,
                    )
                    event_by_identity[envelope.source_identity] = event.category
                    capture_calls_by_class[event.category] += 1
                    capture_bytes_by_class[event.category] += event.capture_proxy_bytes
                    raw_payload = cast(Mapping[str, Any], dict(row.payload))
                    selected_plan = None
                    deliverable = self_observation_deliverable(
                        event.phase, cast(Mapping[str, JsonValue], raw_payload)
                    )
                    if selection_api is not None:
                        assert classify is not None
                        classification = classify(raw_payload, event.phase)
                        capture_role = _effective_capture_role(
                            classification,
                            event,
                            focused=focused_selection,
                        )
                        selected_capture_roles[capture_role] += 1
                        if capture_role != "none":
                            selected_capture_candidate_bytes_by_role[capture_role] += (
                                event.capture_proxy_bytes
                            )
                        if deliverable:
                            assert summary_builder is not None
                            selected_plan = store.prepare_selected_admission(
                                workspace,
                                raw_session,
                                envelope,
                                fence=SELECTION_FENCE,
                                focused=focused_selection,
                                routine_candidate=classification.routine_candidate,
                                proven_routine_success=classification.proven_routine_success,
                                summary_builder=summary_builder,
                            )
                        else:
                            selected_self_suppressed += 1
                    started_ingest = time.perf_counter_ns()
                    with store.batched(workspace):
                        result, admitted = store.ingest_with_pairing(
                            envelope,
                            workspace_commitment=workspace,
                            pairing_mode=(
                                "paired"
                                if event.source is ObservationSource.CODEX_HOOK
                                else "post_only"
                            ),
                            correlation_id=call_id,
                            source=event.source,
                            session_commitment=session,
                            source_generation=1,
                            is_pre_event=event.phase == "PreToolUse",
                            is_post_event=event.phase == "PostToolUse",
                        )
                        ingest_latencies.append(
                            (time.perf_counter_ns() - started_ingest) / 1_000_000
                        )
                        if result.disposition is ObservationIngestDisposition.ACCEPTED:
                            accepted_by_class[event.category] += 1
                            if selection_api is None and deliverable:
                                started_outbox = time.perf_counter_ns()
                                overflow = store.enqueue_outbox(workspace, raw_session, admitted)
                                outbox_latencies.append(
                                    (time.perf_counter_ns() - started_outbox) / 1_000_000
                                )
                                if overflow is None:
                                    outbox_admitted_by_class[event.category] += 1
                                else:
                                    outbox_rejected_by_reason[overflow] += 1
                            elif selection_api is not None and selected_plan is not None:
                                selected_deliveries_attempted += len(selected_plan.deliveries)
                                started_outbox = time.perf_counter_ns()
                                committed = store.commit_selected_admission(
                                    workspace,
                                    selected_plan,
                                    incoming=admitted,
                                    newly_observed=True,
                                    replayable=True,
                                )
                                outbox_latencies.append(
                                    (time.perf_counter_ns() - started_outbox) / 1_000_000
                                )
                                if not committed:
                                    selected_commit_failures += 1
                                    outbox_rejected_by_reason["selected_admission_rejected"] += 1
                                else:
                                    for _, delivery in selected_plan.deliveries:
                                        if delivery.event_kind == "RoutineReadSummary":
                                            selected_delivered_by_class["routine_summary"] += 1
                                            outbox_admitted_by_class["routine_summary"] += 1
                                        else:
                                            category = event_by_identity.get(
                                                delivery.source_identity, "protected_unknown"
                                            )
                                            selected_delivered_by_class[category] += 1
                                            outbox_admitted_by_class[category] += 1
                        else:
                            ingest_rejected_by_reason[
                                result.reason or result.disposition.value
                            ] += 1
            replay_batch_latencies.append((time.perf_counter_ns() - batch_started) / 1_000_000)

        selection_accounting: Mapping[str, Any] | None = None
        selection_runtime: Mapping[str, Any] | None = None
        if selection_api is not None:
            assert summary_builder is not None
            selected_flush_ok = store.flush_selected_admission(
                workspace,
                summary_builder=summary_builder,
                force=True,
            )
            if not selected_flush_ok:
                selected_commit_failures += 1
            selection_accounting = cast(
                Mapping[str, Any], dict(store.selection_accounting(workspace))
            )
            runtime_status = getattr(store, "selection_runtime_status", None)
            if callable(runtime_status):
                runtime_value = runtime_status(workspace, next(iter(sessions.values())))
                if isinstance(runtime_value, Mapping):
                    runtime_mapping = cast(Mapping[str, Any], runtime_value)
                    selection_runtime = {
                        key: runtime_mapping.get(key)
                        for key in (
                            "selected_mode",
                            "effective_mode",
                            "selected_capacity",
                            "effective_capacity",
                            "selection_origin",
                            "pressure_state",
                            "content_allowed",
                            "admission_allowed",
                            "queue_count",
                            "queue_bytes",
                        )
                    }

        status_latencies: list[float] = []
        for _ in range(3):
            started_status = time.perf_counter_ns()
            store.status(ObservationStatusQuery(workspace))
            status_latencies.append((time.perf_counter_ns() - started_status) / 1_000_000)

        state_writes = [item for item in writes if item[0] == ".json"]
        pending_outbox_rows = len(store.list_pending_outbox_rows(workspace))
        attempted_by_class = Counter(event.category for event in events)
        process_cpu_ms = (time.process_time_ns() - process_started) / 1_000_000
        wall_ms = (time.perf_counter_ns() - wall_started) / 1_000_000
        return {
            "revision": revision,
            "candidate_queue_target": count,
            "fanout": fanout,
            "host": host,
            "selection": (
                None
                if selection is None
                else {
                    "detail": selection.detail.value,
                    "capacity": int(selection.capacity),
                    "queue_target": selection.queue_count,
                    "capacity_enforcement": "owner session selection is persisted in disposable state and enforced by the store",
                    "capacity_enforced": selection_runtime is not None,
                    "runtime_status": selection_runtime,
                    "capture_extraction_executed": False,
                    "capture_roles_by_event": dict(selected_capture_roles),
                    "capture_candidate_events": sum(
                        count for role, count in selected_capture_roles.items() if role != "none"
                    ),
                    "capture_candidate_bytes_by_role": dict(
                        selected_capture_candidate_bytes_by_role
                    ),
                    "capture_candidate_bytes": sum(
                        selected_capture_candidate_bytes_by_role.values()
                    ),
                    "self_observation_suppressed": selected_self_suppressed,
                    "deliveries_attempted": selected_deliveries_attempted,
                    "deliveries_by_class": dict(selected_delivered_by_class),
                    "commit_failures": selected_commit_failures,
                    "replayable_rejections": outbox_rejected_by_reason.get(
                        "selected_admission_rejected", 0
                    ),
                    "flush_ok": selected_flush_ok,
                    "accounting": selection_accounting,
                }
            ),
            "baseline_limits": {
                "outbox_rows": _store_limit("_MAX_OUTBOX", 512),
                "state_bytes": _store_limit("_MAX_STATE_BYTES", 1_048_576),
                "open_pre": _store_limit("_MAX_OPEN_PRE", 256),
                "retained_envelopes": _store_limit("_MAX_ENVELOPES", 256),
            },
            "workload": {
                "attempted_event_count": count,
                "claimed_event_count": claimed_records,
                "attempted_by_class": dict(attempted_by_class),
                "protected_classes_indivisible": list(PROTECTED_CLASSES),
            },
            "hook": {
                "append_success_count": hook_success_count,
                "structural_spool_bytes": spool_bytes,
                "append_latency_ms": latency_summary(hook_latencies),
                "replay_batches": claim_batches,
                "replay_batch_latency_ms": latency_summary(replay_batch_latencies),
            },
            "capture_proxy": {
                "native_capture_executed": False,
                "plaintext_retained": False,
                "meaning": "eligible-content byte estimate only; no native capture or plaintext ran",
                "calls_by_class": dict(capture_calls_by_class),
                "eligible_bytes_by_class": dict(capture_bytes_by_class),
                "eligible_bytes_total": sum(capture_bytes_by_class.values()),
            },
            "admission": {
                "accepted_by_class": dict(accepted_by_class),
                "ingest_rejected_by_reason": dict(ingest_rejected_by_reason),
                "outbox_admitted_by_class": dict(outbox_admitted_by_class),
                "outbox_rejected_by_reason": dict(outbox_rejected_by_reason),
                "pending_outbox_rows": pending_outbox_rows,
                "ingest_latency_ms": latency_summary(ingest_latencies),
                "outbox_latency_ms": latency_summary(outbox_latencies),
            },
            "storage": {
                "state_file_final_bytes": _state_size(root),
                "state_write_count": len(state_writes),
                "state_write_bytes": sum(item[1] for item in state_writes),
                "state_max_serialized_bytes": max((item[1] for item in state_writes), default=0),
                "store_stage_ms": dict(store.stage_timings_ms),
            },
            "control": {"status_latency_ms": latency_summary(status_latencies)},
            "process": {
                "wall_ms": wall_ms,
                "cpu_ms": process_cpu_ms,
                "peak_rss_bytes": _rss_bytes(),
            },
        }
    finally:
        setattr(local_mod, "_atomic_write", original_atomic_write)
        shutil.rmtree(root)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--counts",
        nargs="+",
        type=int,
        default=list(CANDIDATE_QUEUE_TARGETS),
        help="synthetic hook-event counts (default: 512 2048 8192)",
    )
    parser.add_argument("--fanout", type=int, default=DEFAULT_FANOUT)
    parser.add_argument(
        "--hosts",
        nargs="+",
        choices=("codex", "claude", "cursor"),
        default=["codex"],
        help="synthetic host lanes to replay (default: codex)",
    )
    parser.add_argument(
        "--revision",
        default=BASELINE_REVISION,
        help="revision label for the report; defaults to issue #687's baseline",
    )
    parser.add_argument(
        "--checkout",
        type=Path,
        default=Path.cwd(),
        help="checkout used only to label the report when --revision is omitted",
    )
    parser.add_argument(
        "--selection-matrix",
        action="store_true",
        help="run Focused/Detailed x Standard/Larger/Largest through selected admission",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.fanout < 1 or any(count < 1 for count in args.counts):
        raise SystemExit("--counts and --fanout must be positive")
    revision = args.revision
    if revision == "auto":
        revision = _current_revision(args.checkout)
    if args.selection_matrix:
        selections = selection_matrix()
        results = [
            run_workload(
                count,
                fanout=args.fanout,
                host=host,
                revision=revision,
                checkout=args.checkout,
                selection=selection,
            )
            for count in args.counts
            for host in args.hosts
            for selection in selections
        ]
    else:
        results = [
            run_workload(
                count,
                fanout=args.fanout,
                host=host,
                revision=revision,
                checkout=args.checkout,
            )
            for count in args.counts
            for host in args.hosts
        ]
    report = {
        "schema": "yoetz.observation-selection-benchmark/1",
        "revision": revision,
        "checkout_revision_observed": _current_revision(args.checkout),
        "fanout": args.fanout,
        "hosts": args.hosts,
        "results": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
