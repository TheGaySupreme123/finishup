"""Owner-private local observation consent, binding, and structural ingest state.

This store backs hook and ``yoetz observe`` controls when the service observation
handlers are unavailable. It retains allowlisted structure and commitments only —
never transcript prose or raw workspace paths.
"""

from __future__ import annotations

import base64
import contextlib
import dataclasses
import errno
import functools
import hashlib
import json
import os
import re
import stat
import sys
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Generator, Iterable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from types import MappingProxyType
from typing import Concatenate, Final, TypeVar, cast

from yoetz.adapters.integrations.observation_admission import (
    ROUTINE_SUMMARY_INVALID_GAP,
    AdmissionBuffer,
    AdmissionPlan,
    SummaryBuilder,
    SummaryRefusal,
    admission_buffer_from_json,
    admission_buffer_to_json,
    flush_admission,
    plan_admission,
)
from yoetz.config.paths import PathSafetyError, ensure_owner_only_dir, state_dir
from yoetz.domain.observation import (
    CAPTURE_HANDOFF_RECONCILE_AGE_MS,
    OBSERVATION_BACKPRESSURE_REASON,
    AdviceItem,
    AdviceSnapshot,
    CaptureHandoffRetirementReason,
    CaptureHandoffRetirementStage,
    ObservationCaptureBacklog,
    ObservationControlCommand,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestResult,
    ObservationLifecycle,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatus,
    ObservationStatusQuery,
    advice_snapshot_from_json,
    advice_snapshot_to_json,
    observation_cursor_from_json,
    observation_cursor_to_json,
    observation_envelope_from_json,
    observation_envelope_to_json,
    observation_selection_route,
    workspace_commitment_from_path,
)
from yoetz.domain.observation_budget import (
    BUDGET_POLICY_VERSION,
    BUDGET_VALIDATION_STATUS,
    LARGEST_SUPPORTED_QUEUE_COUNT,
    STATE_DOCUMENT_CEILING_BYTES,
    AdmissionLossCause,
    BudgetLimits,
    BudgetUsage,
    CapacityProfile,
    ObservationCapacity,
    ObservationMode,
    PressureDimension,
    PressureEvaluation,
    PressureSnapshot,
    PressureState,
    evaluate_pressure,
    no_cap_support,
)
from yoetz.domain.observation_loss import ObservationSelectionLoss
from yoetz.domain.observation_profiles import (
    is_content_capture_profile,
    validate_content_capture_profile,
)
from yoetz.domain.observation_read_protection import (
    DEFAULT_READ_PROTECTION_TTL_SECONDS,
    MAX_READ_PROTECTION_COUNT,
    MAX_READ_PROTECTIONS,
    ReadProtection,
    read_protection_attempt_identity,
    read_protection_from_json,
    read_protection_to_json,
    validate_read_protection_reference,
)
from yoetz.domain.observation_selection import ROUTINE_READ_TOOLS, SHELL_TOOLS
from yoetz.domain.observation_settings import (
    DEFAULT_OBSERVATION_SELECTION,
    EFFECTIVE_BUDGET_SCHEMA,
    ObservationSelection,
    ObservationSelectionResolution,
    ObservationSelectionRuntimeStatus,
    ObservationSelectionSetting,
    ObservationSelectionSettings,
    observation_selection_runtime_status_from_json,
    observation_selection_settings_from_json,
    observation_selection_settings_to_json,
    resolve_observation_selection,
)
from yoetz.domain.values import (
    Frontier,
    JsonObject,
    JsonValue,
    Timestamp,
    timestamp_from_datetime,
    validate_commitment,
    validate_sha256_digest,
)
from yoetz.ports.integrations import YOETZ_WORKFLOW_TOOL_NAMES, observation_pairing_contract
from yoetz.ports.observation_errors import ObservationStoreLockTimeout
from yoetz.protocol.canonical import (
    MAX_JSON_DEPTH,
    CanonicalFragment,
    canonical_digest,
    canonical_encode,
    canonical_fragment,
    container_levels,
    ensure_canonical_value,
    strict_json_parse,
)
from yoetz.protocol.canonical import JsonValue as ParsedJsonValue
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.protocol.ids import IdKind, validate_id

try:
    import fcntl
except ImportError:  # pragma: no cover - the Yoetz service is hosted on POSIX
    fcntl = None  # type: ignore[assignment]

__all__ = [
    "HOOK_MAPPING_VERSION",
    "AdviceDelivery",
    "CaptureHandoffStructuralState",
    "FrontierMotionNotice",
    "LocalConsentGrant",
    "LocalConsentTransition",
    "LocalContentCaptureAuthority",
    "LocalObservationConsent",
    "LocalObservationStore",
    "ObservationOutboxRow",
    "ObservationStoreLockEvent",
    "ObservationStoreLockTimeout",
    "PendingSessionLifecycle",
    "ReadProtection",
    "STREAM_MAPPING_VERSION",
    "UnpairedScopeNotice",
    "YOETZ_OWNED_TOOL_NAMES",
    "YOETZ_READ_TOOL_NAMES",
    "YOETZ_TOOL_NAMES",
    "observation_dir",
    "observation_store_lock_deadline",
    "observation_store_lock_remaining",
    "observation_store_lock_scope",
    "self_observation_deliverable",
    "session_commitment_from_codex_id",
    "set_observation_store_lock_reporter",
    "set_observation_store_lock_role",
    "workspace_commitment_for_path",
]

HOOK_MAPPING_VERSION: Final = "codex-obs-hook/1.0.0"
# 1.3.0: a stream cursor is paired with the exact rollout profile its generation's header
# admitted; cursors persisted under 1.2.0 carry no profile and replay from the header (#568).
STREAM_MAPPING_VERSION: Final = "codex-obs-stream/1.4.0"
_KEY_BYTES: Final = 32
_MAX_STATE_BYTES: Final = 1_048_576
# Keep an unpatched copy of the standard bound for compatibility with tests
# and for deciding when an existing expanded-profile file is a durable
# occupancy ceiling.  ``_MAX_STATE_BYTES`` remains the compatibility seam
# used by the standard profile's bounded-store tests.
_DEFAULT_STATE_BYTES: Final = 1_048_576
_MAX_LEGACY_STATE_BYTES: Final = 36 * 1_048_576
_MAX_ENVELOPES: Final = 256
_MAX_DEDUP: Final = 4_096
_MAX_OPEN_PRE: Final = 256
# A pre event is an accepted pairing identity, but its post may be lost by a
# host crash.  Keep that identity long enough for normal hook/retry delivery;
# after the deadline it is accounted for as an incomplete pairing gap so a
# missing post cannot pin pressure forever.
_OPEN_PRE_TTL_MS: Final = 600_000
# Keep true paired-profile orphan identities separate from the aggregate gap
# history.  A valid pair in another source/session/generation must not clear
# one of these conditions.
_MAX_UNPAIRED_SCOPES: Final = 256
_MAX_CODEX_TOOL_HOOK_ENTRIES: Final = 256
_MAX_PENDING_ROLLOUT_TOKEN: Final = 128
# Undecided rollout tool items (#910). Past the soft bound the stream reconciler
# delivers the oldest with ``unpaired_event``; the hard bound only guards the
# state file and records the loss as a session gap.
MAX_PENDING_ROLLOUT_ITEMS: Final = 64
_MAX_PENDING_ROLLOUT_ITEMS_HARD: Final = 4 * MAX_PENDING_ROLLOUT_ITEMS
_MAX_OUTBOX: Final = 512
# The largest selected profile is the hard local JSON ceiling.  Profile
# specific limits come from the pure budget policy below; the standard value
# continues to derive from the long-standing compatibility constant.  The
# ceiling itself is owned by the budget policy so disclosures and the store
# cannot drift (#828).
_MAX_EXPANDED_STATE_BYTES: Final = STATE_DOCUMENT_CEILING_BYTES
_MAX_PENDING_LIFECYCLES: Final = 256
_MAX_PENDING_CONSENT_PROJECTS: Final = 256
_MAX_QUARANTINE: Final = 512
# Quarantined detail is a diagnostic aid, not the durable record; entries this
# stale are pure per-hook parse/encode tax (#211). Age-expired detail folds
# into the same aggregate eviction evidence as count/byte-cap evictions.
_MAX_QUARANTINE_AGE_DAYS: Final = 14
# A stream partial is a pure read-cache: the unterminated tail of the source
# JSONL, held so the next reconcile need not reread it. The reader seeks to
# the committed cursor and rereads the tail whenever the partial is absent,
# so dropping one costs a bounded reread, never observation loss. It is
# therefore bounded per entry and shed before any durable row when the state
# file approaches its cap (#289).
#
# The bound is the session reader's own read chunk
# (``codex_session_stream._MAX_READ_CHUNK``) and may not go below it. The
# reader assembles a source line across passes by holding its prefix here, so
# a bound smaller than one chunk makes any line longer than a chunk
# unassemblable: the hold is dropped, the next pass rereads the identical
# chunk, and the cursor never advances again for that session. Measured on a
# real Codex corpus, 648 of 1.54M rollout lines exceed 256 KiB, so the stall
# is reachable. Not imported, to keep this module free of a cycle with the
# reader that imports it; ``test_observation_state_bounds`` fences the drift.
_MAX_STREAM_PARTIAL_BYTES: Final = 262_144
_MAX_STREAM_CALL_TOOLS: Final = 256
# Parse-cache entry bound: hooks touch one workspace, the daemon's sweep loop
# touches all of them — without a cap the daemon would retain a parsed object
# graph per workspace forever.
_MAX_STATE_CACHE_ENTRIES: Final = 8
_MAX_HOOK_SEQUENCES: Final = 256
_MAX_FRONTIER_MOTION_NOTICES: Final = 256
# Session keyed replay/tombstone indexes are bounded independently of the
# envelope and outbox ceilings. A host can create ended sessions without
# retaining any envelopes, so the byte cap alone must not bound these maps.
_MAX_SESSION_REPLAY_KEYS: Final = 256
# Raw host-session to commitment bindings are a separate admission surface.
# They may be removed only through the durable ended-and-drained lifecycle
# authority below; an active child lane must never be silently forgotten just
# to stay within the state bound.
_MAX_CODEX_SESSION_BINDINGS: Final = 256
_MAX_SESSION_GAP_CODES: Final = 8
# One refused routine-read summary per lane is enough to name the cause; the
# lane is drained on the first refusal, so this bound is never reached by a
# repeating failure, only by many distinct ones.
_MAX_SUMMARY_REFUSALS: Final = 16
# A loss lane names at most this many lost pre/post pairing commitments. A lane
# that loses more paired inputs than this falls back to the conservative
# route-wide inheritance (every later input of the lane carries the loss).
_MAX_LOSS_PAIRINGS: Final = 16
# Structural ids that name a host call. The first three identify the call an
# input belongs to; ``parent_tool_call_id`` names the call that spawned it.
_LOSS_CALL_KEYS: Final = ("tool_use_id", "tool_call_id", "correlation_id")
_LOSS_RELATED_CALL_KEYS: Final = (*_LOSS_CALL_KEYS, "parent_tool_call_id")
# Retired native capture handoffs are named, not counted anonymously: each
# entry records the retirement stage, the ticket state, and why its structural
# row could no longer consume it (#836). Older entries roll off; the total
# retirement count is kept separately.
_MAX_CAPTURE_HANDOFF_RETIREMENTS: Final = 16
_CAPTURE_HANDOFF_STAGES: Final = frozenset(item.value for item in CaptureHandoffRetirementStage)
_CAPTURE_HANDOFF_REASONS: Final = frozenset(item.value for item in CaptureHandoffRetirementReason)
_MAX_CAPTURE_BACKLOG_ROUTES: Final = 256
_MAX_CAPTURE_TICKET_RESERVATIONS: Final = 512
_MAX_CAPTURE_CONTENT_BYTES: Final = 128 * 1024 * 1024
_CAPTURE_BOOTSTRAP_SCHEMA: Final = "yoetz.capture-reservation-bootstrap/1"
_MAX_SAFE_INTEGER: Final = 9_007_199_254_740_991
_SessionMapValue = TypeVar("_SessionMapValue")
# Wall/monotonic drift tolerated before persisted monotonic samples are treated
# as belonging to a different boot epoch (and therefore fenced off).
_EPOCH_TOLERANCE_SECONDS: Final = 2.0
_OUTBOX_REASON_RE: Final = re.compile(r"^[a-z][a-z0-9_]{0,127}$", re.ASCII)
_CAPTURE_BACKLOG_ROUTE_RE: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$", re.ASCII)
_UNKNOWN_CAPTURE_BACKLOG_ROUTE: Final = "_unknown"
_OBSERVATION_GAP_CODES: Final = frozenset(item.value for item in ObservationGapCode)
_RUNTIME_GATE_SCHEMA: Final = "yoetz.observation-runtime-gate/1"
_RUNTIME_GATE_NAME: Final = "runtime-gate.json"
_MAX_RUNTIME_GATE_BYTES: Final = 256
# A legacy runtime-gate marker has no persisted nonce.  It remains readable,
# but it can never be confused with a nonce emitted by the current writer.
_LEGACY_RUNTIME_GATE_GENERATION: Final = "sha256:" + "0" * 64
_PAIRING_PROVENANCE_SCHEMAS: Final = (
    "yoetz.observation-local/11",
    "yoetz.observation-local/12",
    "yoetz.observation-local/13",
    "yoetz.observation-local/14",
    "yoetz.observation-local/15",
)
_RETENTION_PROVENANCE_SCHEMAS: Final = _PAIRING_PROVENANCE_SCHEMAS
# Never a legal character in an event-kind token. An interim build stamped
# hook timing after the kind as ``<kind>|<...>``; the reader below still trims
# it so such a value can never be mistaken for an event kind.
_OPEN_PRE_SEPARATOR: Final = "|"
_LOCAL_OUTBOX_OVERFLOW_GAP: Final = "_local_outbox_overflow"
_PENDING_ATTEMPT_LIMIT_GAP: Final = "pending_attempt_limit"
_PENDING_ATTEMPT_EXPIRED_GAP: Final = "pending_attempt_expired"
_LOCAL_STREAM_PARTIAL_DROPPED_GAP: Final = "_local_stream_partial_dropped"
_LOCAL_DEDUP_EVICTED_GAP: Final = "_local_dedup_evicted"
_LOCAL_ENVELOPE_RETENTION_GAP: Final = "_local_envelope_retention"
_LEGACY_STREAM_PARTIAL_DROPPED_SESSION: Final = "_legacy_unknown"
_STORE_LOCK_TIMEOUT_SECONDS: Final = 2.0
_STORE_LOCK_POLL_SECONDS: Final = 0.01
# Fraction of the state bound a save must leave free before an eviction gap is
# treated as healed (#310).
_STATE_HEADROOM_DIVISOR: Final = 8
# Fixed room kept for loss accounting and lifecycle writes while accepted rows
# exceed a lowered selection. It is not scaled by any profile, and it ends with
# the over-target transition (#843).
_OVER_TARGET_ACCOUNTING_RESERVE_BYTES: Final = _DEFAULT_STATE_BYTES // _STATE_HEADROOM_DIVISOR

# Yoetz's own MCP tools as Codex spells them (bare registry name or the
# ``mcp__yoetz__`` server prefix). Derived from the one registry tuple so this
# set cannot drift from the tools the bridge actually serves (#564 found the
# hand-written predecessor missing ``read_guidance``).
YOETZ_TOOL_NAMES: Final = frozenset(
    f"{prefix}{name}" for prefix in ("", "mcp__yoetz__") for name in YOETZ_WORKFLOW_TOOL_NAMES
)
# Every host spelling of a Yoetz-owned tool: Codex ``mcp__yoetz__``, Claude
# Code's plugin scope ``mcp__plugin_yoetz_yoetz__`` (host_admission), and the
# Cursor ``server:tool`` forms for the external and plugin-bundled server names.
_YOETZ_TOOL_PREFIXES: Final = (
    "",
    "mcp__yoetz__",
    "mcp__plugin_yoetz_yoetz__",
    "yoetz:",
    "plugin-yoetz-yoetz:",
)
YOETZ_OWNED_TOOL_NAMES: Final = frozenset(
    f"{prefix}{name}" for prefix in _YOETZ_TOOL_PREFIXES for name in YOETZ_WORKFLOW_TOOL_NAMES
)
# Yoetz tools that only read Yoetz's own state. Their result is a projection the
# service already holds, so a successful call is not distinct evidence.
_YOETZ_READ_TOOL_BASENAMES: Final = ("status", "receipt", "read_guidance")
YOETZ_READ_TOOL_NAMES: Final = frozenset(
    f"{prefix}{name}" for prefix in _YOETZ_TOOL_PREFIXES for name in _YOETZ_READ_TOOL_BASENAMES
)
_SELF_OBSERVATION_PHASES: Final = frozenset({"PreToolUse", "PostToolUse"})
_SUCCESS_RESULT_STATUS: Final = frozenset({"complete", "completed", "ok", "success", "succeeded"})


def _explicit_host_failure(structural: Mapping[str, JsonValue]) -> bool:
    """True when the host stated any failure or denial fact for the call.

    Mirrors the materializer's rule that an explicit failure signal wins over
    any success signal: ``success=false``, ``denied=true``, a non-zero
    ``exit_status``, a ``result_status`` outside the closed success vocabulary,
    or Claude Code's ``PostToolUseFailure`` label. A payload with no outcome
    fact is not a failure.
    """

    if structural.get("success") is False or structural.get("denied") is True:
        return True
    exit_status = structural.get("exit_status")
    if type(exit_status) is int and not isinstance(exit_status, bool) and exit_status != 0:
        return True
    result_status = structural.get("result_status")
    if type(result_status) is str and result_status.lower() not in _SUCCESS_RESULT_STATUS:
        return True
    return structural.get("action") == "claude_mcp_failure"


def self_observation_deliverable(phase: str, structural: Mapping[str, JsonValue]) -> bool:
    """Decide whether a hook or stream tool observation carries distinct evidence (#564).

    Every Yoetz tool call the agent makes fires host hooks (and lands in the
    Codex session stream) exactly like any other tool, so Yoetz observing its
    own ``status``/``respond``/``check`` traffic produced two outbox rows plus a
    content capture per call, while the same hook process was trying to drain
    that outbox: the workflow starved its own delivery. The service already
    holds the authoritative record of every Yoetz-owned call it served, so an
    observation of one is distinct evidence only when it says something the
    service cannot know from serving the call:

    - any tool that is not Yoetz-owned: always deliverable (unchanged);
    - an explicit host failure or denial of a Yoetz-owned call: deliverable,
      whatever the tool or phase;
    - the pre-event of a Yoetz-owned call: retained in the local observation
      store only (pairing bookkeeping is unaffected; a delivered post-event
      still materializes the action);
    - the post-event of a Yoetz-owned *read* (``status``, ``receipt``,
      ``read_guidance``) without a stated failure: retained locally only, the
      result is a projection of Yoetz's own state;
    - the post-event of a Yoetz-owned *mutation* (``start``, ``publish_work``,
      ``check``, ``respond``): deliverable, one row per call.

    The envelope is always ingested into the bounded local store first; this
    governs only outbox delivery, so nothing is dropped from local evidence.
    """

    tool = structural.get("tool_name")
    if type(tool) is not str or tool not in YOETZ_OWNED_TOOL_NAMES:
        return True
    if phase not in _SELF_OBSERVATION_PHASES:
        return True
    if _explicit_host_failure(structural):
        return True
    if phase == "PreToolUse":
        return False
    return tool not in YOETZ_READ_TOOL_NAMES


_SESSION_DOMAIN: Final = b"yoetz/observation-session/v1\x00"


# Payload-free ownership vocabulary for the shared store lock (#689). A role
# names which kind of process or service worker held or waited for the lock; a
# phase names the store operation (a code identifier from this module or its
# callers, never a value). Both are closed to the diagnostic token grammar.
_STORE_LOCK_ROLES: Final = frozenset(
    {
        "cli",
        "coordinator",
        "hook",
        "local",
        "service",
        "spool_replay",
        "sweep",
        "unknown",
    }
)
# The service's store-owning worker pools name their threads; mapping the
# prefix to a role separates a sweep hop from a coordinator hop inside one
# process without recording any thread-specific value.
_STORE_LOCK_THREAD_ROLES: Final = (
    ("yoetz-obs-sweep", "sweep"),
    ("yoetz-obs-local", "coordinator"),
    ("yoetz-hook-spool", "spool_replay"),
)
_STORE_LOCK_PHASE_PATTERN: Final = re.compile(r"[a-z][a-z0-9_]{0,63}", re.ASCII)
_STORE_LOCK_STAMP_MAX_BYTES: Final = 256
# A hold at least this long is reported to the process's lock reporter with its
# phase, so the expensive critical section is attributable without a timeout.
_STORE_LOCK_LONG_HOLD_SECONDS: Final = 1.0
_STORE_LOCK_PROCESS_ROLE: list[str] = ["local"]
_STORE_LOCK_CONTEXT = threading.local()


def _store_lock_phase(name: object) -> str:
    """Normalize a code identifier to one bounded diagnostic token."""

    if type(name) is not str:
        return "unknown"
    token = name.lower().lstrip("_")
    return token if _STORE_LOCK_PHASE_PATTERN.fullmatch(token) else "unknown"


def _store_lock_role() -> str:
    """Return this thread's closed ownership role."""

    thread_name = threading.current_thread().name
    for prefix, role in _STORE_LOCK_THREAD_ROLES:
        if thread_name.startswith(prefix):
            return role
    scoped = getattr(_STORE_LOCK_CONTEXT, "role", None)
    if type(scoped) is str:
        return scoped
    return _STORE_LOCK_PROCESS_ROLE[0]


def set_observation_store_lock_role(role: str) -> None:
    """Name this process's store-lock role (``hook``, ``service`` or ``cli``)."""

    if type(role) is not str or role not in _STORE_LOCK_ROLES:
        raise ValueError("observation_store_lock_role_invalid")
    _STORE_LOCK_PROCESS_ROLE[0] = role


@contextlib.contextmanager
def observation_store_lock_deadline(deadline: float | None) -> Generator[None]:
    """Bound every store-lock wait in this thread by one ``time.monotonic`` deadline.

    The two-second per-acquisition cap stays in force; this only shortens it.
    A hook pass or a sweep that has spent its budget therefore fails one
    acquisition fast instead of queueing a fresh two seconds per call, so the
    complete invocation, not each call, is what the budget bounds (#689).
    Nested scopes keep the earlier deadline.
    """

    previous = cast(float | None, getattr(_STORE_LOCK_CONTEXT, "deadline", None))
    effective = previous
    if deadline is not None:
        effective = deadline if previous is None else min(previous, deadline)
    _STORE_LOCK_CONTEXT.deadline = effective
    try:
        yield
    finally:
        _STORE_LOCK_CONTEXT.deadline = previous


def observation_store_lock_remaining() -> float | None:
    """Return the seconds left under this thread's lock deadline, if one is set."""

    deadline = cast(float | None, getattr(_STORE_LOCK_CONTEXT, "deadline", None))
    return None if deadline is None else deadline - time.monotonic()


@dataclass(frozen=True, slots=True)
class ObservationStoreLockEvent:
    """One payload-free lock ownership observation for a process reporter."""

    kind: str  # "timeout" or "long_hold"
    role: str
    phase: str
    held_ms: int | None = None
    timeout: ObservationStoreLockTimeout | None = None


_STORE_LOCK_REPORTER: list[Callable[[ObservationStoreLockEvent], None] | None] = [None]


def set_observation_store_lock_reporter(
    reporter: Callable[[ObservationStoreLockEvent], None] | None,
) -> Callable[[ObservationStoreLockEvent], None] | None:
    """Install this process's lock-event sink; return the previous one.

    The store never chooses a sink itself: hooks record into their bounded hook
    diagnostics and the service into its diagnostic ring. Reporter failures
    are swallowed so observability can never fail a store operation.
    """

    previous = _STORE_LOCK_REPORTER[0]
    _STORE_LOCK_REPORTER[0] = reporter
    return previous


@contextlib.contextmanager
def observation_store_lock_scope(
    *,
    role: str | None = None,
    reporter: Callable[[ObservationStoreLockEvent], None] | None = None,
) -> Generator[None]:
    """Attribute and report this thread's store-lock activity for one bounded scope.

    A hook pass names itself and records its own lock events into hook
    diagnostics without replacing the process sink: the service replays legacy
    spool records through the same pass on one of its own threads.
    """

    if role is not None and role not in _STORE_LOCK_ROLES:
        raise ValueError("observation_store_lock_role_invalid")
    previous_role = getattr(_STORE_LOCK_CONTEXT, "role", None)
    previous_reporter = getattr(_STORE_LOCK_CONTEXT, "reporter", None)
    if role is not None:
        _STORE_LOCK_CONTEXT.role = role
    if reporter is not None:
        _STORE_LOCK_CONTEXT.reporter = reporter
    try:
        yield
    finally:
        _STORE_LOCK_CONTEXT.role = previous_role
        _STORE_LOCK_CONTEXT.reporter = previous_reporter


def _report_store_lock_event(event: ObservationStoreLockEvent) -> None:
    reporter = cast(
        Callable[[ObservationStoreLockEvent], None] | None,
        getattr(_STORE_LOCK_CONTEXT, "reporter", None),
    )
    if reporter is None:
        reporter = _STORE_LOCK_REPORTER[0]
    if reporter is None:
        return
    with contextlib.suppress(Exception):
        reporter(event)


class _LockedWriteRequired(BaseException):  # noqa: N818 - internal control flow
    """A lock-free committed read reached a write and must rerun under the lock.

    A ``BaseException`` so no ``except Exception`` between the write and the
    enclosing :meth:`LocalObservationStore._read` can swallow it and silently
    skip the write.
    """


_OPTIMISTIC_READS = threading.local()


def _optimistic_read_depth() -> int:
    return cast(int, getattr(_OPTIMISTIC_READS, "depth", 0))


def _read_mostly[**ParamsT, ResultT](
    method: Callable[Concatenate[LocalObservationStore, ParamsT], ResultT],
) -> Callable[Concatenate[LocalObservationStore, ParamsT], ResultT]:
    """Serve a read-mostly store method without queueing for the store lock.

    The method body uses :meth:`LocalObservationStore._reading` where it once
    took the lock. It runs against the committed document first; only if it
    reaches a write (a legacy repair, an expiring setting) does it rerun under
    the lock, so the write and the reads it depends on stay one transaction.
    """

    @functools.wraps(method)
    def wrapper(
        self: LocalObservationStore, *args: ParamsT.args, **kwargs: ParamsT.kwargs
    ) -> ResultT:
        return self._read(lambda: method(self, *args, **kwargs))  # pyright: ignore[reportPrivateUsage]

    return wrapper


class _StoreLockState:
    def __init__(self) -> None:
        self.thread_lock = threading.RLock()
        self.depth = 0
        self.descriptor: int | None = None
        # The thread that holds ``thread_lock`` at depth one, with the facts a
        # timed-out waiter reports. ``flock_held`` is False while that owner is
        # still queueing for the cross-process flock.
        self.owner: int | None = None
        self.owner_role = "unknown"
        self.owner_phase = "unknown"
        self.owner_since = 0.0
        self.flock_held = False


_STORE_LOCK_REGISTRY_GUARD = threading.Lock()
_STORE_LOCK_REGISTRY: dict[str, _StoreLockState] = {}


def _read_lock_stamp(descriptor: int) -> tuple[str, str, int | None]:
    """Return the flock holder's stamped role, phase and hold time, if legible."""

    try:
        raw = os.pread(descriptor, _STORE_LOCK_STAMP_MAX_BYTES, 0)
        parsed = json.loads(raw.decode("ascii")) if raw else None
    except OSError, UnicodeDecodeError, ValueError:
        return "unknown", "unknown", None
    if type(parsed) is not dict:
        return "unknown", "unknown", None
    stamp = cast(dict[str, object], parsed)
    role = stamp.get("role")
    phase = stamp.get("phase")
    since = stamp.get("since_ms")
    held: int | None = None
    if type(since) is int and since >= 0:
        held = max(0, int(time.monotonic() * 1000) - since)
    return (
        role if type(role) is str and role in _STORE_LOCK_ROLES else "unknown",
        _store_lock_phase(phase),
        held,
    )


class _InterprocessStoreLock:
    """Reentrant process-local lock plus POSIX serialization across hook/daemon.

    Ownership is observable without payloads (#689): the depth-one holder of
    the flock stamps its role, store phase and ``time.monotonic`` start (a
    system-wide clock on the supported POSIX hosts) into the lock file, and
    clears it on release. A waiter whose bounded wait expires reads that stamp,
    or the in-process owner facts, into :class:`ObservationStoreLockTimeout`.
    """

    def __init__(self, path: Path, *, waits_ms: MutableMapping[str, float] | None = None) -> None:
        self._path = path
        # Queueing behind another process is real hook wall time that no stage
        # window could see: the wait lands inside and outside the timed 'store'
        # window alike, so it accumulates here, once per acquisition, wherever
        # in the pass it happens (#310/#311). Reentrant acquisitions return
        # immediately and contribute ~0. Hold time accumulates as 'lock_hold'
        # so a pass can tell its own critical section from its queueing (#689).
        self._waits_ms = waits_ms
        key = str(path.absolute())
        with _STORE_LOCK_REGISTRY_GUARD:
            self._state = _STORE_LOCK_REGISTRY.setdefault(key, _StoreLockState())

    def held_by_current_thread(self) -> bool:
        """Return whether this thread already owns the process-local store lock."""

        return self._state.owner == threading.get_ident()

    def __enter__(self) -> _InterprocessStoreLock:
        return self.enter(sys._getframe(1).f_code.co_name)  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]

    def enter(
        self, phase: str, *, prepare: Callable[[], None] | None = None
    ) -> _InterprocessStoreLock:
        """Acquire under one bounded deadline, naming the store operation.

        ``prepare`` runs once the process-local lock is held and before the
        cross-process flock is requested: in-process callers keep their arrival
        order, while other processes never wait on it. Its duration is neither
        charged to the flock wait budget nor reported as queueing.
        """

        started = time.monotonic()
        token = _store_lock_phase(phase)
        prepared: list[float] = [0.0]
        try:
            return self._acquire(started, token, prepare, prepared)
        except ObservationStoreLockTimeout as timeout:
            # Reported once every lock this attempt took has been released.
            _report_store_lock_event(
                ObservationStoreLockEvent(
                    kind="timeout",
                    role=_store_lock_role(),
                    phase=token,
                    timeout=timeout,
                )
            )
            raise
        finally:
            if self._waits_ms is not None:
                # Recorded on the timeout path too: a pass that waited two
                # seconds and then failed spent those seconds queueing.
                waited = time.monotonic() - started - prepared[0]
                self._waits_ms["lock_wait"] = self._waits_ms.get("lock_wait", 0.0) + max(
                    0.0, waited * 1000
                )

    def _deadline(self, started: float) -> float:
        deadline = started + _STORE_LOCK_TIMEOUT_SECONDS
        bound = cast(float | None, getattr(_STORE_LOCK_CONTEXT, "deadline", None))
        return deadline if bound is None else min(deadline, bound)

    def _timeout(
        self,
        scope: str,
        started: float,
        *,
        descriptor: int | None = None,
    ) -> ObservationStoreLockTimeout:
        waited_ms = max(0, int((time.monotonic() - started) * 1000))
        state = self._state
        if descriptor is not None:
            role, holder_phase, held = _read_lock_stamp(descriptor)
            waiting = False
        else:
            # Unsynchronized reads of the in-process owner's facts: at worst
            # they describe the previous owner, which is still the thread the
            # waiter queued behind.
            role = state.owner_role
            holder_phase = state.owner_phase
            since = state.owner_since
            held = None if since <= 0.0 else max(0, int((time.monotonic() - since) * 1000))
            waiting = not state.flock_held
        return ObservationStoreLockTimeout(
            scope=scope,
            waited_ms=waited_ms,
            holder_role=role,
            holder_phase=holder_phase,
            holder_held_ms=held,
            holder_waiting=waiting,
        )

    def _acquire(
        self,
        started: float,
        phase: str,
        prepare: Callable[[], None] | None = None,
        prepared: list[float] | None = None,
    ) -> _InterprocessStoreLock:
        state = self._state
        deadline = self._deadline(started)
        if not state.thread_lock.acquire(timeout=max(0.0, deadline - time.monotonic())):
            raise self._timeout("thread", started)
        if state.depth == 0:
            state.owner = threading.get_ident()
            state.owner_role = _store_lock_role()
            state.owner_phase = phase
            state.owner_since = time.monotonic()
            state.flock_held = False
            flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor: int | None = None
            try:
                # Preparation already owns the thread lock. Interruptions must unwind it
                # just like a failed flock acquisition, or every later writer stays blocked.
                if prepare is not None:
                    began = time.monotonic()
                    try:
                        with contextlib.suppress(Exception):
                            prepare()
                    finally:
                        spent = time.monotonic() - began
                        if prepared is not None:
                            prepared[0] = spent
                    # Preparation is not queueing: the flock keeps its full wait,
                    # still bounded by any caller deadline in scope.
                    bound = cast(float | None, getattr(_STORE_LOCK_CONTEXT, "deadline", None))
                    deadline = started + _STORE_LOCK_TIMEOUT_SECONDS + spent
                    if bound is not None:
                        deadline = min(deadline, bound)
                descriptor = os.open(self._path, flags, 0o600)
                os.fchmod(descriptor, 0o600)
                if fcntl is not None:
                    while True:
                        try:
                            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                            break
                        except OSError as exc:
                            if exc.errno not in {errno.EACCES, errno.EAGAIN}:
                                raise
                            remaining = deadline - time.monotonic()
                            if remaining <= 0:
                                raise self._timeout(
                                    "process", started, descriptor=descriptor
                                ) from exc
                            time.sleep(min(_STORE_LOCK_POLL_SECONDS, remaining))
                acquired = time.monotonic()
                state.owner_since = acquired
                state.flock_held = True
                with contextlib.suppress(OSError):
                    stamp = json.dumps(
                        {
                            "phase": phase,
                            "role": state.owner_role,
                            "since_ms": int(acquired * 1000),
                        },
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("ascii")
                    os.pwrite(descriptor, stamp, 0)
                    os.ftruncate(descriptor, len(stamp))
            except BaseException:
                if descriptor is not None:
                    os.close(descriptor)
                state.owner = None
                state.flock_held = False
                state.thread_lock.release()
                raise
            assert descriptor is not None
            state.descriptor = descriptor
        state.depth += 1
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        state = self._state
        long_hold: ObservationStoreLockEvent | None = None
        try:
            state.depth -= 1
            if state.depth == 0:
                descriptor = state.descriptor
                state.descriptor = None
                held = time.monotonic() - state.owner_since
                if held >= _STORE_LOCK_LONG_HOLD_SECONDS:
                    long_hold = ObservationStoreLockEvent(
                        kind="long_hold",
                        role=state.owner_role,
                        phase=state.owner_phase,
                        held_ms=int(held * 1000),
                    )
                state.owner = None
                state.flock_held = False
                if self._waits_ms is not None:
                    self._waits_ms["lock_hold"] = self._waits_ms.get("lock_hold", 0.0) + held * 1000
                if descriptor is not None:
                    try:
                        with contextlib.suppress(OSError):
                            os.ftruncate(descriptor, 0)
                        if fcntl is not None:
                            fcntl.flock(descriptor, fcntl.LOCK_UN)
                    finally:
                        os.close(descriptor)
        finally:
            state.thread_lock.release()
        if long_hold is not None:
            # Reported after release so a slow sink never extends the hold.
            _report_store_lock_event(long_hold)


def _error(code: PublicErrorCode, message: str, *, retryable: bool) -> PublicOperationError:
    return PublicOperationError(code, message, retryable)


def _now() -> Timestamp:
    current = datetime.now(UTC)
    stamp = current.replace(microsecond=(current.microsecond // 1000) * 1000)
    return timestamp_from_datetime(stamp)


def _ensure_dir(path: Path) -> None:
    try:
        ensure_owner_only_dir(path)
    except PathSafetyError:
        if not path.is_dir() or path.is_symlink():
            raise
        mode = path.stat().st_mode & 0o777
        if mode != 0o700:
            raise


def observation_dir(*, _state: Path | None = None) -> Path:
    """Return the private observation state directory under the Yoetz state root."""

    root = state_dir() if _state is None else _state
    path = root / "observation"
    _ensure_dir(root)
    _ensure_dir(path)
    return path


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.{os.urandom(8).hex()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short_write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise


def _read_bytes(path: Path, *, maximum: int) -> bytes | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        size = path.stat().st_size
        if size <= 0 or size > maximum:
            return None
        data = path.read_bytes()
        if len(data) > maximum:
            return None
        return data
    except OSError:
        return None


@dataclass(frozen=True, slots=True)
class AdviceDelivery:
    """One hook-channel advice delivery: the snapshot, the rendered item, its text."""

    snapshot: AdviceSnapshot
    item: AdviceItem | None
    delivery_identity: str
    text: str


@dataclass(frozen=True, slots=True)
class FrontierMotionNotice:
    """One bounded, one-shot notice that the observation writer moved a task frontier."""

    from_sequence: int
    to_sequence: int
    head_digest: str
    observation_record_count: int
    task_id: str
    # Persistence-only LRU clock. It is deliberately excluded from notice
    # equality and delivery identity: touching an entry must not change the
    # bytes the hook already peeked.
    recency_ordinal: int = dataclasses.field(default=0, compare=False, repr=False)

    def __post_init__(self) -> None:
        if (
            type(self.from_sequence) is not int
            or type(self.to_sequence) is not int
            or type(self.observation_record_count) is not int
            or type(self.task_id) is not str
            or type(self.recency_ordinal) is not int
            or not self.task_id
            or not 0 <= self.from_sequence < self.to_sequence <= _MAX_SAFE_INTEGER
            or not 1 <= self.observation_record_count <= self.to_sequence - self.from_sequence
            or not 0 <= self.recency_ordinal <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        validate_sha256_digest(self.head_digest)

    @property
    def delivery_identity(self) -> str:
        return canonical_digest(
            JsonObject(
                {
                    "from_sequence": self.from_sequence,
                    "head_digest": self.head_digest,
                    "observation_record_count": self.observation_record_count,
                    "task_id": self.task_id,
                    "to_sequence": self.to_sequence,
                }
            )
        )


def _clamp_frontier_motion_notice(
    notice: FrontierMotionNotice, delivered_to: int
) -> FrontierMotionNotice | None:
    """Drop or trim a candidate so it describes only motion past ``delivered_to``."""

    if notice.to_sequence <= delivered_to:
        return None
    if notice.from_sequence >= delivered_to:
        return notice
    remainder_span = notice.to_sequence - delivered_to
    original_span = notice.to_sequence - notice.from_sequence
    if notice.observation_record_count == original_span:
        remainder_count = remainder_span
    else:
        delivered_span = delivered_to - notice.from_sequence
        remainder_count = min(
            max(notice.observation_record_count - delivered_span, 1),
            remainder_span,
        )
    return FrontierMotionNotice(
        delivered_to,
        notice.to_sequence,
        notice.head_digest,
        remainder_count,
        notice.task_id,
    )


@dataclass(frozen=True, slots=True)
class _FrontierMotionDelivered:
    """One lineage-bound delivered mark with a persistence-stable LRU clock."""

    task_id: str
    to_sequence: int
    head_digest: str
    recency_ordinal: int

    def __post_init__(self) -> None:
        if (
            type(self.task_id) is not str
            or not self.task_id
            or type(self.to_sequence) is not int
            or not 1 <= self.to_sequence <= _MAX_SAFE_INTEGER
            or type(self.recency_ordinal) is not int
            or not 0 <= self.recency_ordinal <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        validate_sha256_digest(self.head_digest)


@dataclass(frozen=True, slots=True)
class LocalObservationConsent:
    workspace_commitment: str
    granted_at: Timestamp
    revoked_at: Timestamp | None = None
    paused: bool = False
    # Structural observation consent predates native ordinary-work capture.
    # ``None`` is therefore meaningful: old grants must never be widened by a
    # reader that learns about content profiles later.
    content_capture_profiles: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        profiles = self.content_capture_profiles
        if type(profiles) is not tuple or len(profiles) > 2:
            raise ProtocolValueError("invalid_event_value_type")
        if any(not is_content_capture_profile(profile) for profile in profiles):
            raise ProtocolValueError("invalid_event_value_type")
        if tuple(sorted(set(profiles), key=str.encode)) != profiles:
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def active(self) -> bool:
        return self.revoked_at is None and not self.paused


class LocalConsentTransition(StrEnum):
    """What one structural grant did to a workspace's local consent."""

    GRANTED = "granted"  # no prior consent, or a fresh grant after revocation
    RESUMED = "resumed"  # a live paused consent became active again
    UPDATED = "updated"  # an explicit content-profile set replaced the live arms
    UNCHANGED = "unchanged"  # already effective; the content fence did not advance


_ADMISSION_LOSS_CAUSES: Final = frozenset(item.value for item in AdmissionLossCause)


@dataclass(frozen=True, slots=True)
class LocalConsentGrant:
    """The consent a grant left in force and how it got there."""

    transition: LocalConsentTransition
    consent: LocalObservationConsent


@dataclass(frozen=True, slots=True)
class CaptureHandoffStructuralState:
    """Which structural rows could still consume a native capture handoff.

    A handoff is keyed by ``(source, session_commitment, source_identity)``.
    ``pending`` holds rows still waiting in the delivery outbox or the selected
    admission buffer; ``quarantined`` maps a terminally refused row to its
    closed reason code.  A handoff whose key is in neither set has no
    structural row left that can consume it.  The snapshot carries no payload.
    """

    pending: frozenset[tuple[str, str, str]]
    quarantined: Mapping[tuple[str, str, str], str]


@dataclass(frozen=True, slots=True)
class LocalContentCaptureAuthority:
    """The current local fence for the retained-content arm.

    This snapshot contains no plaintext. Its generation and exact profile set
    are read under the owner-private local-store lock and are rechecked by the
    AI-powered review service immediately before it opens an object or dispatches a
    packet. The local store remains authoritative while task-bundle consent
    propagation is pending.
    """

    workspace_commitment: str
    generation: str
    active: bool
    revoked: bool
    runtime_enabled: bool
    profiles: tuple[str, ...]

    def __post_init__(self) -> None:
        try:
            object.__setattr__(
                self,
                "workspace_commitment",
                validate_commitment(self.workspace_commitment),
            )
            validate_sha256_digest(self.generation)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if (
            type(self.generation) is not str
            or type(self.active) is not bool
            or type(self.revoked) is not bool
            or type(self.runtime_enabled) is not bool
            or type(self.profiles) is not tuple
            or len(self.profiles) > 2
            or any(not is_content_capture_profile(profile) for profile in self.profiles)
            or tuple(sorted(set(self.profiles), key=str.encode)) != self.profiles
        ):
            raise ProtocolValueError("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class ObservationOutboxRow:
    """One bounded structural-delivery row; never contains plaintext content."""

    codex_session_id: str
    envelope: ObservationEnvelope
    attempts: int = 0
    last_reason: str | None = None
    last_attempt_at: Timestamp | None = None
    consecutive_reason_attempts: int = 0

    @property
    def row_identity(self) -> str:
        return canonical_digest(
            cast(
                JsonValue,
                {
                    "codex_session_id": self.codex_session_id,
                    "envelope": _envelope_fragment(self.envelope),
                },
            )
        )

    def __post_init__(self) -> None:
        if type(self.codex_session_id) is not str or not self.codex_session_id:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.envelope) is not ObservationEnvelope:
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.attempts) is not int
            or isinstance(self.attempts, bool)
            or not 0 <= self.attempts <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.last_reason is not None and (
            type(self.last_reason) is not str
            or _OUTBOX_REASON_RE.fullmatch(self.last_reason) is None
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.last_attempt_at is not None and type(self.last_attempt_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if (
            type(self.consecutive_reason_attempts) is not int
            or isinstance(self.consecutive_reason_attempts, bool)
            or not 0 <= self.consecutive_reason_attempts <= self.attempts
        ):
            raise ProtocolValueError("invalid_event_value_type")


@dataclass(frozen=True, slots=True)
class PendingSessionLifecycle:
    """One durable host-session lifecycle operation waiting for its lock.

    The target generation is frozen when the hook captures the event.  That
    makes retries idempotent: a later worker can distinguish an already
    applied operation from a still-pending one without inferring intent from
    the current ended flag alone.
    """

    codex_session_id: str
    session_commitment: str
    event_kind: str
    target_generation: int
    clear_mapping: bool = False

    def __post_init__(self) -> None:
        if (
            type(self.codex_session_id) is not str
            or not 1 <= len(self.codex_session_id) <= 128
            or "/" in self.codex_session_id
            or "\\" in self.codex_session_id
            or "\0" in self.codex_session_id
            or not self.codex_session_id.isascii()
            or not all(0x21 <= ord(char) <= 0x7E for char in self.codex_session_id)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.session_commitment) is not str or not re.fullmatch(
            r"hmac-sha256:[0-9a-f]{64}", self.session_commitment
        ):
            raise ProtocolValueError("invalid_commitment")
        if self.event_kind not in {"SessionStart", "SessionEnd"}:
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.target_generation) is not int
            or isinstance(self.target_generation, bool)
            or not 1 <= self.target_generation <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.clear_mapping) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if self.clear_mapping and self.event_kind != "SessionStart":
            raise ProtocolValueError("invalid_event_value_type")

    @property
    def operation_id(self) -> str:
        """Stable identity for retries, independent of the target generation."""

        return canonical_digest(
            JsonObject(
                {
                    "codex_session_id": self.codex_session_id,
                    "session_commitment": self.session_commitment,
                    "event_kind": self.event_kind,
                    "clear_mapping": self.clear_mapping,
                }
            )
        )


@dataclass
class _GapState:
    first_seen: Timestamp
    last_seen: Timestamp
    active: bool = True


@dataclass(frozen=True, slots=True)
class _CodeModeCell:
    """Tool-hook bookkeeping for one Codex code-mode ``exec`` cell (#917).

    ``hook_clock_at_start`` is the store's tool-hook clock when the stream read
    the cell's call, which is always held. The cell's output is kept local only
    when a tool hook of the same session was ingested after that read and
    before a complete stream pass that still did not see the output (see
    ``_ToolHookSession.settled``); the decision, once made, is replayed
    unchanged.
    """

    hook_clock_at_start: int
    output_local: bool | None
    touched: int


@dataclass(frozen=True, slots=True)
class _ToolHookSession:
    """Codex tool-hook stamps for one host session (#917).

    ``touched`` is the store's tool-hook clock at the session's latest tool
    hook. ``settled`` is the latest ``touched`` value captured at the start of a
    stream pass that then read the rollout completely: every tool hook up to it
    fired before any row that pass did not see was written. A hook that fired
    while a code-mode cell was open and before its output was written can only
    be that cell's nested call; a hook ingested after the output was written (the
    next cell's) never settles before the output is read.
    """

    count: int
    touched: int
    settled: int = 0


def _code_mode_cell_key(session_commitment: str, call_id: str) -> str:
    return canonical_digest(
        JsonObject(
            {
                "kind": "codex-code-mode-cell",
                "session_commitment": session_commitment,
                "call_id": call_id,
            }
        )
    )


@dataclass(frozen=True, slots=True)
class UnpairedScopeNotice:
    """One not-yet-delivered standing-limitation notice for a new orphan scope (#917).

    A scope is one (source, host session, source generation) lane that has at
    least one paired-profile orphan post. The notice is informational only: it
    is never a finding and needs no response. A delivered scope is not announced
    again, across restart and resume, while it is retained; the bounded map
    forgets the oldest delivered scope to admit a new one, so a scope pushed out
    by 256 newer scopes can be announced again (the aggregate gap stays
    disclosed either way).
    """

    lane: str
    source: str
    session_commitment: str
    source_generation: int
    delivered: bool = False
    # Announcement order; the oldest delivered notice is the one a full map forgets.
    ordinal: int = 0


def _unpaired_notice_lane(
    *, source: ObservationSource, session_commitment: str, source_generation: int
) -> str:
    return canonical_digest(
        JsonObject(
            {
                "kind": "observation-orphan-scope",
                "source": source.value,
                "session_commitment": session_commitment,
                "source_generation": source_generation,
            }
        )
    )


def _unpaired_notices_from_json(raw: object) -> dict[str, UnpairedScopeNotice]:
    """Read the bounded notice map, dropping any malformed entry."""

    notices: dict[str, UnpairedScopeNotice] = {}
    if not isinstance(raw, Mapping):
        return notices
    for lane, value in cast(Mapping[object, object], raw).items():
        if type(lane) is not str or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, object], value)
        source = entry.get("source")
        session = entry.get("session_commitment")
        generation = entry.get("source_generation")
        delivered = entry.get("delivered")
        ordinal = entry.get("ordinal", 0)
        if (
            type(source) is not str
            or source not in {item.value for item in ObservationSource}
            or type(session) is not str
            or not session
            or type(generation) is not int
            or generation < 0
            or type(delivered) is not bool
            or type(ordinal) is not int
            or ordinal < 0
        ):
            continue
        if lane != _unpaired_notice_lane(
            source=ObservationSource(source),
            session_commitment=session,
            source_generation=generation,
        ):
            continue
        notices[lane] = UnpairedScopeNotice(lane, source, session, generation, delivered, ordinal)
        if len(notices) >= _MAX_UNPAIRED_SCOPES:
            break
    return notices


def _bounded_counter(raw: object) -> int:
    return raw if type(raw) is int and 0 <= raw <= _MAX_SAFE_INTEGER else 0


def _codex_tool_hooks_from_json(raw: object) -> dict[str, _ToolHookSession]:
    hooks: dict[str, _ToolHookSession] = {}
    if not isinstance(raw, Mapping):
        return hooks
    for session, value in cast(Mapping[object, object], raw).items():
        if type(session) is not str or not session or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, object], value)
        count = _bounded_counter(entry.get("count"))
        touched = _bounded_counter(entry.get("touched"))
        # An entry written before ``settled`` existed settles nothing yet: its
        # earlier hooks count for a cell only after a later complete pass.
        settled = min(_bounded_counter(entry.get("settled")), touched)
        if count:
            hooks[session] = _ToolHookSession(count, touched, settled)
    return dict(
        sorted(hooks.items(), key=lambda item: item[1].touched)[-_MAX_CODEX_TOOL_HOOK_ENTRIES:]
    )


def _pending_rollout_item_token(value: object) -> bool:
    return type(value) is str and 0 < len(value) <= _MAX_PENDING_ROLLOUT_TOKEN


@dataclass(frozen=True, slots=True)
class PendingRolloutItem:
    """One rollout tool item read before any hook post it pairs with (#910).

    The structural envelope is kept beside the envelope ring so its outcome can
    still be delivered, with ``unpaired_event``, when the ring or this bounded
    account forgets the item before a hook post decides it.
    """

    session_commitment: str
    codex_session_id: str
    envelope: ObservationEnvelope
    touched: int
    # Workspace reconciles survived while the item's session stored no new hook
    # or stream row, and that session's activity mark when last compared.
    idle_reconciles: int = 0
    activity: str = ""

    @property
    def source_identity(self) -> str:
        return self.envelope.source_identity


def _pending_rollout_items_from_json(raw: object) -> dict[str, PendingRolloutItem]:
    items: dict[str, PendingRolloutItem] = {}
    if not isinstance(raw, Mapping):
        return items
    for identity, value in cast(Mapping[object, object], raw).items():
        if not _pending_rollout_item_token(identity) or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, object], value)
        session = entry.get("session")
        host_session = entry.get("codex_session_id")
        raw_envelope = entry.get("envelope")
        if (
            not _pending_rollout_item_token(session)
            or not _pending_rollout_item_token(host_session)
            or not isinstance(raw_envelope, Mapping)
        ):
            continue
        try:
            envelope = observation_envelope_from_json(
                JsonObject(cast(Mapping[str, JsonValue], raw_envelope))
            )
        except ProtocolValueError, TypeError, ValueError:
            continue
        if envelope.source_identity != identity or envelope.session_commitment != session:
            continue
        activity = entry.get("activity")
        items[cast(str, identity)] = PendingRolloutItem(
            cast(str, session),
            cast(str, host_session),
            envelope,
            _bounded_counter(entry.get("touched")),
            _bounded_counter(entry.get("idle_reconciles")),
            activity if type(activity) is str and len(activity) <= 256 else "",
        )
    return dict(
        sorted(items.items(), key=lambda item: item[1].touched)[-_MAX_PENDING_ROLLOUT_ITEMS_HARD:]
    )


def _evicted_open_call_key(session_commitment: str, call_id: str) -> str:
    return canonical_digest(
        JsonObject(
            {
                "kind": "codex-evicted-open-call",
                "session_commitment": session_commitment,
                "call_id": call_id,
            }
        )
    )


def _evicted_open_calls_from_json(raw: object) -> dict[str, tuple[str, str, str, int]]:
    calls: dict[str, tuple[str, str, str, int]] = {}
    if not isinstance(raw, Mapping):
        return calls
    for key, value in cast(Mapping[object, object], raw).items():
        if type(key) is not str or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, object], value)
        session = entry.get("session")
        commitment = entry.get("commitment")
        call_id = entry.get("call_id")
        if not all(_pending_rollout_item_token(item) for item in (session, commitment, call_id)):
            continue
        if key != _evicted_open_call_key(cast(str, session), cast(str, call_id)):
            continue
        calls[key] = (
            cast(str, session),
            cast(str, commitment),
            cast(str, call_id),
            _bounded_counter(entry.get("touched")),
        )
    return dict(sorted(calls.items(), key=lambda item: item[1][3])[-_MAX_CODEX_TOOL_HOOK_ENTRIES:])


def _code_mode_cells_from_json(raw: object) -> dict[str, _CodeModeCell]:
    cells: dict[str, _CodeModeCell] = {}
    if not isinstance(raw, Mapping):
        return cells
    for key, value in cast(Mapping[object, object], raw).items():
        if type(key) is not str or not key or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, object], value)
        start = entry.get("hook_clock_at_start")
        local = entry.get("output_local")
        touched = _bounded_counter(entry.get("touched"))
        if local is not None and type(local) is not bool:
            continue
        if start is None:
            # The earlier count format (``hooks_at_start``/``pre_withheld``) is
            # migrated, never dropped: a dropped open cell would deliver its
            # output beside its nested hooks. A held call is decided at its output
            # from the clock stamped when it was noted (``touched``, which no
            # later hook precedes); a call that format already delivered keeps
            # its output deliverable, as that format would have.
            withheld = entry.get("pre_withheld")
            if type(withheld) is not bool:
                continue
            if local is None and not withheld:
                local = False
            start = touched
        if type(start) is not int or not 0 <= start <= _MAX_SAFE_INTEGER:
            continue
        cells[key] = _CodeModeCell(start, local, touched)
    return dict(
        sorted(cells.items(), key=lambda item: item[1].touched)[-_MAX_CODEX_TOOL_HOOK_ENTRIES:]
    )


@dataclass(frozen=True, slots=True)
class _OpenPre:
    """Durable identity for an accepted pre event awaiting its post.

    Older local states stored only the event kind.  The optional timestamps
    keep those states readable while every new entry records the original
    receipt and a wall-clock deadline.  Pairing scope is copied from the
    envelope so a restart or a reused host correlation id cannot extend the
    wrong pending attempt.
    """

    event_kind: str
    source: ObservationSource | None
    session_commitment: str | None
    source_generation: int | None
    correlation_id: str
    receipt_time: Timestamp | None
    deadline: Timestamp | None

    def __post_init__(self) -> None:
        if (
            type(self.event_kind) is not str
            or not 1 <= len(self.event_kind) <= 128
            or _OPEN_PRE_SEPARATOR in self.event_kind
            or not self.event_kind.isascii()
            or not all(0x21 <= ord(char) <= 0x7E for char in self.event_kind)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.source) is not ObservationSource and self.source is not None:
            raise ProtocolValueError("invalid_event_enum")
        scoped = self.source is not None
        if scoped != (self.session_commitment is not None and self.source_generation is not None):
            raise ProtocolValueError("invalid_event_value_type")
        if self.session_commitment is not None:
            validate_commitment(self.session_commitment)
        if self.source_generation is not None and (
            type(self.source_generation) is not int
            or isinstance(self.source_generation, bool)
            or not 1 <= self.source_generation <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.correlation_id) is not str
            or not 1 <= len(self.correlation_id) <= 128
            or not self.correlation_id.isascii()
            or not all(0x21 <= ord(char) <= 0x7E for char in self.correlation_id)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.receipt_time is not None and type(self.receipt_time) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if self.deadline is not None and type(self.deadline) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if (
            self.receipt_time is None
            and self.deadline is not None
            or self.receipt_time is not None
            and self.deadline is None
        ):
            raise ProtocolValueError("invalid_timestamp")
        if (
            self.receipt_time is not None
            and self.deadline is not None
            and self.deadline < self.receipt_time
        ):
            raise ProtocolValueError("invalid_timestamp")


def _open_pre_deadline(receipt_time: Timestamp | None) -> Timestamp | None:
    if receipt_time is None:
        return None
    try:
        return timestamp_from_datetime(
            receipt_time.as_datetime() + timedelta(milliseconds=_OPEN_PRE_TTL_MS)
        )
    except OverflowError, ProtocolValueError, ValueError:
        return None


def _open_pre_to_json(value: _OpenPre) -> JsonObject:
    return JsonObject(
        {
            "event_kind": value.event_kind,
            "source": None if value.source is None else value.source.value,
            "session_commitment": value.session_commitment,
            "source_generation": value.source_generation,
            "correlation_id": value.correlation_id,
            "receipt_time": None if value.receipt_time is None else value.receipt_time.wire,
            "deadline": None if value.deadline is None else value.deadline.wire,
        }
    )


def _safe_timestamp(value: object) -> Timestamp | None:
    if type(value) is not str:
        return None
    try:
        return Timestamp(value)
    except ProtocolValueError, TypeError, ValueError:
        return None


def _open_pre_from_json(
    raw: object,
    *,
    key: str,
    legacy_receipt_time: Timestamp | None,
) -> _OpenPre | None:
    """Decode one current typed entry or upgrade a legacy event-kind value."""

    if type(raw) is str:
        event_kind = raw.split(_OPEN_PRE_SEPARATOR, 1)[0]
        receipt_time = legacy_receipt_time
        try:
            return _OpenPre(
                event_kind=event_kind,
                source=None,
                session_commitment=None,
                source_generation=None,
                correlation_id=key,
                receipt_time=receipt_time,
                deadline=_open_pre_deadline(receipt_time),
            )
        except ProtocolValueError, TypeError, ValueError:
            return None
    if not isinstance(raw, Mapping):
        return None
    row = cast(Mapping[str, JsonValue], raw)
    event_kind = row.get("event_kind")
    correlation_id = row.get("correlation_id", key)
    source_raw = row.get("source")
    session_commitment = row.get("session_commitment")
    source_generation = row.get("source_generation")
    if type(event_kind) is not str or type(correlation_id) is not str:
        return None
    if session_commitment is not None and type(session_commitment) is not str:
        return None
    if source_generation is not None and type(source_generation) is not int:
        return None
    source: ObservationSource | None
    if source_raw is None:
        source = None
    elif type(source_raw) is str:
        try:
            source = ObservationSource(source_raw)
        except ValueError, TypeError:
            return None
    else:
        return None
    receipt_time = _safe_timestamp(row.get("receipt_time")) or legacy_receipt_time
    deadline = _safe_timestamp(row.get("deadline"))
    if receipt_time is not None and deadline is None:
        deadline = _open_pre_deadline(receipt_time)
    try:
        return _OpenPre(
            event_kind=event_kind,
            source=source,
            session_commitment=session_commitment,
            source_generation=source_generation,
            correlation_id=correlation_id,
            receipt_time=receipt_time,
            deadline=deadline,
        )
    except ProtocolValueError, TypeError, ValueError:
        return None


def _open_pre_map_from_json(
    raw: object,
    *,
    legacy_receipt_time: Timestamp | None,
) -> dict[str, _OpenPre]:
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, _OpenPre] = {}
    for key, value in cast(Mapping[object, object], raw).items():
        if (
            type(key) is not str
            or not 1 <= len(key) <= 128
            or not key.isascii()
            or not all(0x21 <= ord(char) <= 0x7E for char in key)
        ):
            continue
        entry = _open_pre_from_json(
            value,
            key=key,
            legacy_receipt_time=legacy_receipt_time,
        )
        if entry is not None:
            result[key] = entry
        if len(result) >= _MAX_OPEN_PRE:
            break
    return result


@dataclass(frozen=True, slots=True)
class _CaptureBacklogSnapshot:
    """Bounded, task-scoped capture backlog feedback cached locally.

    The local store may know only the routes that have reported recently.  It
    therefore keeps this per-task snapshot separate from workspace authority
    and carries an explicit scope flag on the enclosing state rather than
    presenting the sum as a workspace-global measurement.
    """

    count: int
    byte_count: int
    oldest_receipt_time: Timestamp | None
    observed_at: Timestamp
    # A complete task inventory may carry the durable ticket identities that
    # its aggregate already includes.  Partial legacy reports leave this
    # empty, so central reservations remain conservatively additive.
    accounted_ticket_ids: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if (
            type(self.count) is not int
            or isinstance(self.count, bool)
            or not 0 <= self.count <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.byte_count) is not int
            or isinstance(self.byte_count, bool)
            or not 0 <= self.byte_count <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.oldest_receipt_time is not None and type(self.oldest_receipt_time) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if self.count == 0 and self.oldest_receipt_time is not None:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.observed_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if type(self.accounted_ticket_ids) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        if len(self.accounted_ticket_ids) > _MAX_CAPTURE_TICKET_RESERVATIONS:
            raise ProtocolValueError("invalid_event_value_type")
        if len(self.accounted_ticket_ids) > self.count:
            raise ProtocolValueError("invalid_event_value_type")
        previous: str | None = None
        for ticket_id in self.accounted_ticket_ids:
            try:
                normalized = validate_sha256_digest(ticket_id)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise ProtocolValueError("invalid_event_value_type") from exc
            if normalized != ticket_id or (
                previous is not None and ticket_id.encode("ascii") <= previous.encode("ascii")
            ):
                raise ProtocolValueError("invalid_event_value_type")
            previous = ticket_id


@dataclass(frozen=True, slots=True)
class _CaptureReservation:
    """One central workspace capture reservation held across task bundles."""

    ticket_id: str
    task_id: str
    byte_count: int
    reserved_at: Timestamp
    needs_reconcile: bool = True

    def __post_init__(self) -> None:
        try:
            validate_sha256_digest(self.ticket_id)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if (
            type(self.task_id) is not str
            or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(self.task_id) is None
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(self.byte_count) is not int
            or isinstance(self.byte_count, bool)
            or not 0 <= self.byte_count <= _MAX_CAPTURE_CONTENT_BYTES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.reserved_at) is not Timestamp or type(self.needs_reconcile) is not bool:
            raise ProtocolValueError("invalid_event_value_type")


def _capture_reservation_key(ticket_id: str, task_id: str) -> str:
    """Derive a bounded key from the authenticated ticket/task pair."""

    return canonical_digest(JsonObject({"task_id": task_id, "ticket_id": ticket_id}))


@dataclass(frozen=True, slots=True)
class _CaptureBootstrap:
    """Proof that a complete task inventory was accounted before reservations opened."""

    proof: str
    observed_at: Timestamp
    route_count: int

    def __post_init__(self) -> None:
        try:
            validate_sha256_digest(self.proof)
        except (ProtocolValueError, TypeError, ValueError) as exc:
            raise ProtocolValueError("invalid_event_value_type") from exc
        if type(self.observed_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if (
            type(self.route_count) is not int
            or isinstance(self.route_count, bool)
            or not 0 <= self.route_count <= _MAX_CAPTURE_BACKLOG_ROUTES
        ):
            raise ProtocolValueError("invalid_event_value_type")


def _capture_bootstrap_proof(
    workspace: str, snapshots: Mapping[str, _CaptureBacklogSnapshot]
) -> str:
    """Digest the route set from one complete read.

    The per-route counts are live feedback and change after every durable
    ticket mutation.  Keeping them out of this identity lets a complete
    inventory remain valid while those counters are refreshed; adding a new
    route still invalidates the proof through its opaque task id.
    """

    routes = tuple(sorted(snapshots, key=str.encode))
    return canonical_digest(
        JsonObject(
            {
                "schema": _CAPTURE_BOOTSTRAP_SCHEMA,
                "workspace": workspace,
                "routes": routes,
            }
        )
    )


@dataclass
class _WorkspaceState:
    consent: LocalObservationConsent | None = None
    session_workspaces: dict[str, str] | None = None
    cursors: dict[str, ObservationCursor] | None = None
    dedup: set[str] | None = None
    # ``dedup`` remains a set for compatibility with older state and callers,
    # while insertion order plus lane attribution makes bounded eviction
    # deterministic and session-aware.
    dedup_order: list[str] | None = None
    dedup_lanes: dict[str, str] | None = None
    envelopes: list[ObservationEnvelope] | None = None
    # True once bounded retention has discarded any envelope.  Historical
    # gap reconciliation must never claim completeness after that point.
    envelopes_truncated: bool = False
    # Per-session retention gaps keep one busy lane from being attributed to
    # every sibling sharing this workspace.
    session_gaps: dict[str, set[str]] | None = None
    gaps: dict[str, _GapState] | None = None
    unsupported_events: set[str] | None = None
    last_receipt: Timestamp | None = None
    advice_frontier: str | None = None
    advice_snapshot: AdviceSnapshot | None = None
    last_advice_suppression: str | None = None
    session_advice: dict[str, AdviceSnapshot] | None = None
    session_advice_suppression: dict[str, str] | None = None
    frontier_motion_notices: dict[str, FrontierMotionNotice] | None = None
    # Last delivered frontier identity per Codex session. Survives notice
    # deletion so a replayed append cannot re-announce already-delivered motion.
    frontier_motion_delivered: dict[str, _FrontierMotionDelivered] | None = None
    frontier_motion_recency: int = 0
    open_pre: dict[str, _OpenPre] | None = None
    unpaired_scopes: set[str] | None = None
    # One informational notice per new (source, session, generation) orphan
    # scope, keyed by that lane; kept after delivery so a scope is announced once.
    unpaired_notices: dict[str, UnpairedScopeNotice] | None = None
    # Per host session: Codex tool-hook inputs admitted and a recency stamp; and
    # per code-mode cell: the tool-hook count at its call (#917). Both maps are
    # bounded and forget the least recently touched entry, which only makes that
    # session's or cell's wrapper deliverable again.
    codex_tool_hooks: dict[str, _ToolHookSession] | None = None
    code_mode_cells: dict[str, _CodeModeCell] | None = None
    codex_tool_hook_clock: int = 0
    # Per rollout tool item read before any hook post it pairs with (#910): its
    # source identity -> its account, stamped on the clock above. A later hook
    # post or the turn's end decides it (see MAX_PENDING_ROLLOUT_ITEMS).
    pending_rollout_items: dict[str, PendingRolloutItem] | None = None
    # Codex tool calls whose ``PreToolUse`` left the envelope ring (#910): key ->
    # (host session, command commitment, call id, recency). The rollout pairing
    # replay starts with them open; a call's evicted post or its session's
    # ``Stop``/``SessionEnd`` forgets it.
    evicted_open_calls: dict[str, tuple[str, str, str, int]] | None = None
    # True when a state was written by a pre-/11 reader that could not retain
    # scoped pairing provenance. It is deliberately sticky: a later save must
    # not turn unknown history into proof that a gap was false.
    pairing_state_unknown: bool = False
    stream_cursors: dict[str, ObservationCursor] | None = None
    stream_partials: dict[str, bytes] | None = None
    stream_call_tools: dict[str, dict[str, str]] | None = None
    stream_call_tool_generations: dict[str, int] | None = None
    stream_source_identities: dict[str, str] | None = None
    # Exact rollout profile id the current source generation's header admitted, per session.
    # Absent while a generation is unadmitted; a cursor with admitted events and no profile is
    # replayed from its header rather than parsed under a guessed vocabulary.
    stream_profiles: dict[str, str] | None = None
    stream_partial_dropped_sessions: set[str] | None = None
    hook_sequences: dict[str, int] | None = None
    # Workspace high-water mark for hook ordinals. An evicted session must not
    # restart at one when it returns.
    hook_sequence_clock: int = 0
    last_stream_reconcile_mono_ms: int | None = None
    last_hook_receipt_mono_ms: int | None = None
    last_successful_drain_mono_ms: int | None = None
    # Boot/process epoch (wall - monotonic) the monotonic samples above belong
    # to. Samples are only comparable to a live clock within the same epoch;
    # after a restart or reboot they are fenced off (see `_epoch_matches`).
    monotonic_epoch: float | None = None
    pending_outbox: list[ObservationOutboxRow] | None = None
    admission_buffer: AdmissionBuffer = dataclasses.field(default_factory=AdmissionBuffer)
    selection_epoch: int = 0
    selection_observed_count: int = 0
    selection_admitted_count: int = 0
    selection_delivered_count: int = 0
    selection_summarized_input_count: int = 0
    selection_omitted_count: int = 0
    selection_summarized_count: int = 0
    selection_rejected_count: int = 0
    selection_loss_commitment: str | None = None
    selection_loss_ranges: tuple[JsonObject, ...] = ()
    selection_last_loss_notice_ms: int | None = None
    selection_loss_notice_pending: bool = False
    selection_reported_loss_lanes: tuple[str, ...] = ()
    # Per-lane loss detail kept beside ``selection_loss_ranges`` (whose exact
    # shape is a wire contract): the closed refusal causes and the bounded
    # pairing commitments that bound which later inputs inherit the loss
    # (tb4n1 B3). A lane without a valid detail keeps route-wide inheritance.
    selection_loss_details: tuple[JsonObject, ...] = ()
    # Bounded, deduplicated account of every buffered lane whose routine-read
    # summary the builder refused. The members were admitted individually with
    # a `routine_summary_invalid` gap, so this names the cause once instead of
    # letting an anonymous sweep exception repeat every minute (issue #753).
    selection_summary_refusals: tuple[JsonObject, ...] = ()
    selection_summary_refusal_notice_pending: bool = False
    # Bounded, payload-free account of retired native capture handoffs (#836):
    # the stage, ticket state, and reason that let a retained ticket stop
    # holding capture pressure. The count covers entries that rolled off.
    capture_handoff_retirements: tuple[JsonObject, ...] = ()
    capture_handoff_retired_count: int = 0
    # Ticket identities stay bounded by the active-ticket ceiling so an
    # accounting commit can be replayed after a crash between recording and
    # ticket retirement without incrementing the loss count twice.
    capture_handoff_retirement_ids: tuple[str, ...] = ()
    # An accounted ticket stays bound to its task route until the destructive
    # retirement and reservation release have been confirmed.  This is
    # separate from the bounded history because legacy tickets may have no
    # central reservation to pin their replay identity.
    capture_handoff_retirement_pending: dict[str, str] | None = None
    # (codex_session_id, envelope, reason, quarantined_at). The timestamp is
    # store-authored at quarantine time so the age bound measures time *in*
    # quarantine, never the (possibly much older) envelope receipt time.
    quarantine: list[tuple[str, ObservationEnvelope, str, Timestamp]] | None = None
    codex_session_bindings: dict[str, str] | None = None
    storage_corrupt_sessions: set[str] | None = None
    ended_sessions: set[str] | None = None
    session_generations: dict[str, int] | None = None
    ended_session_generations: dict[str, int] | None = None
    pending_lifecycles: list[PendingSessionLifecycle] | None = None
    # A consent revoke is a two-store operation. Persist its token and
    # generation plan until the service-owned project fence is applied.
    pending_consent_revocation: str | None = None
    pending_consent_projects: dict[str, int] | None = None
    # Opaque, durable nonce for the native content-consent arm.  This is
    # separate from the human-readable consent fields because those fields
    # can return to an earlier value (pause/resume and disable/enable).  A
    # fresh nonce on every real authority transition prevents that ABA from
    # revalidating an old AI-powered review case.
    content_capture_epoch: str | None = None
    quarantine_evicted_count: int = 0
    quarantine_reclaimed_count: int = 0
    quarantine_evicted_commitment: str | None = None
    quarantine_evicted_first: Timestamp | None = None
    quarantine_evicted_last: Timestamp | None = None
    trusted_policy_digest: str | None = None
    trusted_policy_mac: str | None = None
    # Owner-selected detail/capacity settings.  This is separate from consent
    # and privacy authority: a setting never grants content or egress.
    selection_settings: ObservationSelectionSettings | None = None
    # Explicit read-retention scopes are structural-only hints. Each row is
    # fenced to the consent generation and host-session generation that
    # created it; it never carries or grants content authority.
    read_protections: list[ReadProtection] | None = None
    # Per-task capture backlog feedback.  This is deliberately distinct from
    # workspace consent, outbox state, and structural queue capacity: the map
    # is a bounded cache of route reports, never a workspace-global claim.
    capture_backlogs: dict[str, _CaptureBacklogSnapshot] | None = None
    # Central reservations are the workspace-global admission fence for the
    # coordinator's native capture lane. They survive a crash until READY
    # reconciles the corresponding task ticket inventory.
    capture_reservations: dict[str, _CaptureReservation] | None = None
    capture_backlog_scope_unknown: bool = False
    # The proof is distinct from route feedback. Legacy state and partial task
    # reads never enable a new central reservation; only a complete ready
    # inventory may mint this marker.
    capture_reservation_bootstrap: _CaptureBootstrap | None = None
    # Per-session pressure state is the only mutable part of hysteresis; the
    # pure domain evaluator remains the authority for every transition.
    pressure_snapshots: dict[str, PressureSnapshot] | None = None

    def __post_init__(self) -> None:
        if self.selection_settings is None:
            self.selection_settings = ObservationSelectionSettings()
        elif type(self.selection_settings) is not ObservationSelectionSettings:
            raise ProtocolValueError("invalid_event_value_type")
        if self.session_workspaces is None:
            self.session_workspaces = {}
        if self.cursors is None:
            self.cursors = {}
        if self.dedup is None:
            self.dedup = set()
        if self.dedup_order is None:
            self.dedup_order = []
        if self.dedup_lanes is None:
            self.dedup_lanes = {}
        if self.envelopes is None:
            self.envelopes = []
        if type(self.envelopes_truncated) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if self.gaps is None:
            self.gaps = {}
        if self.session_gaps is None:
            self.session_gaps = {}
        if self.unsupported_events is None:
            self.unsupported_events = set()
        if self.open_pre is None:
            self.open_pre = {}
        if self.unpaired_scopes is None:
            self.unpaired_scopes = set()
        if self.unpaired_notices is None:
            self.unpaired_notices = {}
        if self.codex_tool_hooks is None:
            self.codex_tool_hooks = {}
        if self.code_mode_cells is None:
            self.code_mode_cells = {}
        if self.pending_rollout_items is None:
            self.pending_rollout_items = {}
        if self.evicted_open_calls is None:
            self.evicted_open_calls = {}
        if type(self.pairing_state_unknown) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if self.stream_cursors is None:
            self.stream_cursors = {}
        if self.stream_partials is None:
            self.stream_partials = {}
        if self.stream_call_tools is None:
            self.stream_call_tools = {}
        if self.stream_call_tool_generations is None:
            self.stream_call_tool_generations = {}
        if self.stream_source_identities is None:
            self.stream_source_identities = {}
        if self.stream_profiles is None:
            self.stream_profiles = {}
        if self.stream_partial_dropped_sessions is None:
            self.stream_partial_dropped_sessions = set()
        if self.hook_sequences is None:
            self.hook_sequences = {}
        if (
            type(self.hook_sequence_clock) is not int
            or not 0 <= self.hook_sequence_clock <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.pending_outbox is None:
            self.pending_outbox = []
        if self.quarantine is None:
            self.quarantine = []
        if self.codex_session_bindings is None:
            self.codex_session_bindings = {}
        if self.storage_corrupt_sessions is None:
            self.storage_corrupt_sessions = set()
        if self.ended_sessions is None:
            self.ended_sessions = set()
        if self.session_generations is None:
            self.session_generations = {}
        if self.ended_session_generations is None:
            self.ended_session_generations = {}
        if self.pending_lifecycles is None:
            self.pending_lifecycles = []
        if (
            self.pending_consent_projects is not None
            and type(self.pending_consent_projects) is not dict
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if self.session_advice is None:
            self.session_advice = {}
        if self.session_advice_suppression is None:
            self.session_advice_suppression = {}
        if self.frontier_motion_notices is None:
            self.frontier_motion_notices = {}
        if self.frontier_motion_delivered is None:
            self.frontier_motion_delivered = {}
        if self.capture_backlogs is None:
            self.capture_backlogs = {}
        elif type(self.capture_backlogs) is not dict:
            raise ProtocolValueError("invalid_event_value_type")
        if self.capture_reservations is None:
            self.capture_reservations = {}
        elif type(self.capture_reservations) is not dict:
            raise ProtocolValueError("invalid_event_value_type")
        if self.read_protections is None:
            self.read_protections = []
        elif type(self.read_protections) is not list or any(
            type(item) is not ReadProtection for item in self.read_protections
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if len(self.read_protections) > MAX_READ_PROTECTIONS:
            raise ProtocolValueError("invalid_event_value_type")
        if type(self.capture_backlog_scope_unknown) is not bool:
            raise ProtocolValueError("invalid_event_value_type")
        if self.pressure_snapshots is None:
            self.pressure_snapshots = {}
        elif type(self.pressure_snapshots) is not dict:
            raise ProtocolValueError("invalid_event_value_type")


def _cursor_key(source: ObservationSource, session_commitment: str) -> str:
    return f"{source.value}:{session_commitment}"


def _pairing_key(
    *,
    source: ObservationSource,
    session_commitment: str,
    source_generation: int,
    correlation_id: str,
) -> str:
    """Scope a pre/post identity to its source lane and generation.

    Host call ids are only meaningful inside the source session and source
    generation that issued them.  Hashing the tuple keeps the state key
    bounded even when a host's correlation spelling contains separators.
    """

    return canonical_digest(
        JsonObject(
            {
                "kind": "observation-pairing",
                "source": source.value,
                "session_commitment": session_commitment,
                "source_generation": source_generation,
                "correlation_id": correlation_id,
            }
        )
    )


def _orphan_scope_key(
    *,
    source: ObservationSource,
    session_commitment: str,
    source_generation: int,
    source_identity: str,
) -> str:
    """Return the durable identity for one accepted orphan post event."""

    return canonical_digest(
        JsonObject(
            {
                "kind": "observation-orphan",
                "source": source.value,
                "session_commitment": session_commitment,
                "source_generation": source_generation,
                "source_identity": source_identity,
            }
        )
    )


def _profile_harness(source: ObservationSource) -> str:
    if source is ObservationSource.CLAUDE_HOOK:
        return "claude"
    if source is ObservationSource.CURSOR_HOOK:
        return "cursor"
    return "codex"


def _envelope_pairing_contract(
    envelope: ObservationEnvelope,
) -> tuple[str, str]:
    profile_id = envelope.structural_payload.get("capability_profile_id")
    return observation_pairing_contract(
        _profile_harness(envelope.source), profile_id if type(profile_id) is str else None
    )


def _envelope_pairing_correlation(
    envelope: ObservationEnvelope, correlation_kind: str
) -> str | None:
    """Derive the pairing identity from the admitted structural payload."""

    structural = envelope.structural_payload
    if correlation_kind == "none":
        return None
    for key in ("tool_use_id", "tool_call_id"):
        value = structural.get(key)
        if type(value) is str and value:
            return value
    if correlation_kind == "generation_id":
        return None
    for key in ("correlation_id", "parent_tool_call_id"):
        value = structural.get(key)
        if type(value) is str and value:
            return value
    return None


def _is_post_only_profile(envelope: ObservationEnvelope) -> bool:
    """Recognize only an exact, reviewed post-only host/profile cell."""

    mode, _correlation = _envelope_pairing_contract(envelope)
    return mode == "post_only"


def _loss_pairing_keys(envelope: ObservationEnvelope, keys: tuple[str, ...]) -> frozenset[str]:
    """Commit the host call ids named by ``keys`` to lane-scoped pairing digests."""

    structural = envelope.structural_payload
    result: set[str] = set()
    for key in keys:
        value = structural.get(key)
        if type(value) is str and value:
            result.add(
                _pairing_key(
                    source=envelope.source,
                    session_commitment=envelope.session_commitment,
                    source_generation=envelope.cursor.source_generation,
                    correlation_id=value,
                )
            )
    return frozenset(result)


def _loss_own_pairing_keys(envelope: ObservationEnvelope) -> frozenset[str]:
    """The calls a lost input belonged to: its pre/post partner shares one."""

    return _loss_pairing_keys(envelope, _LOSS_CALL_KEYS)


def _loss_related_pairing_keys(envelope: ObservationEnvelope) -> frozenset[str]:
    """The calls a later input belongs to or was spawned by."""

    return _loss_pairing_keys(envelope, _LOSS_RELATED_CALL_KEYS)


def _loss_details_by_lane(state: _WorkspaceState) -> dict[str, JsonObject]:
    return {cast(str, item["lane"]): item for item in state.selection_loss_details}


def _bounded_loss_pairings(entry: JsonObject, detail: JsonObject | None) -> frozenset[str] | None:
    """Return the pairings a lane's loss is bounded to, or None for route-wide."""

    if detail is None or detail.get("scope") != "paired_inputs":
        return None
    if detail.get("count") != entry.get("count"):
        return None
    return frozenset(cast(tuple[str, ...], detail["pairings"]))


def _loss_details_from_json(raw: object, lanes: set[str]) -> tuple[JsonObject, ...]:
    """Decode per-lane loss detail strictly; anything invalid is dropped.

    A dropped detail is never a weaker claim: its lane falls back to the
    route-wide inheritance that predates the detail.
    """

    if not isinstance(raw, (list, tuple)):
        return ()
    result: dict[str, JsonObject] = {}
    for item in cast(Sequence[object], raw)[:64]:
        if not isinstance(item, Mapping):
            continue
        row = cast(Mapping[str, object], item)
        lane = row.get("lane")
        count = row.get("count")
        cause = row.get("cause")
        causes = row.get("causes")
        scope = row.get("scope")
        pairings = row.get("pairings")
        if (
            type(lane) is not str
            or lane not in lanes
            or lane in result
            or type(count) is not int
            or not 1 <= count <= _MAX_SAFE_INTEGER
            or type(cause) is not str
            or cause not in _ADMISSION_LOSS_CAUSES
            or not isinstance(causes, Mapping)
            or scope not in {"paired_inputs", "route"}
            or not isinstance(pairings, (list, tuple))
        ):
            continue
        cause_map = cast(Mapping[object, object], causes)
        if len(cause_map) > len(_ADMISSION_LOSS_CAUSES) or not all(
            type(key) is str
            and key in _ADMISSION_LOSS_CAUSES
            and type(value) is int
            and 1 <= value <= _MAX_SAFE_INTEGER
            for key, value in cause_map.items()
        ):
            continue
        pairing_items = tuple(cast(Sequence[object], pairings))
        if len(pairing_items) > _MAX_LOSS_PAIRINGS or len(set(pairing_items)) != len(pairing_items):
            continue
        valid_pairings: list[str] = []
        for pairing in pairing_items:
            if type(pairing) is not str:
                break
            try:
                validate_sha256_digest(pairing)
            except ProtocolValueError, TypeError, ValueError:
                break
            valid_pairings.append(pairing)
        else:
            result[lane] = JsonObject(
                {
                    "lane": lane,
                    "count": count,
                    "cause": cause,
                    "causes": JsonObject(
                        {
                            cast(str, key): cast(int, value)
                            for key, value in sorted(
                                cause_map.items(), key=lambda kv: cast(str, kv[0])
                            )
                        }
                    ),
                    "scope": scope,
                    "pairings": tuple(valid_pairings) if scope == "paired_inputs" else (),
                }
            )
    return tuple(result[key] for key in sorted(result, key=str.encode))


def _load_session_advice(raw: object) -> dict[str, AdviceSnapshot]:
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, AdviceSnapshot] = {}
    for key, value in cast(Mapping[str, JsonValue], raw).items():
        if type(key) is not str or not isinstance(value, Mapping):
            continue
        try:
            result[key] = advice_snapshot_from_json(
                JsonObject(cast(Mapping[str, JsonValue], value))
            )
        except ProtocolValueError, TypeError, ValueError:
            continue
    return result


def _pressure_snapshots_to_json(
    snapshots: Mapping[str, PressureSnapshot],
) -> JsonObject:
    """Encode the bounded per-session hysteresis map deterministically."""

    return JsonObject(
        {
            key: JsonObject(
                {
                    "state": snapshot.state.value,
                    "since_ms": snapshot.since_ms,
                    "low_since_ms": snapshot.low_since_ms,
                    "transition_identity": snapshot.transition_identity,
                }
            )
            for key, snapshot in sorted(snapshots.items(), key=lambda item: item[0].encode())
        }
    )


def _load_pressure_snapshots(raw: object) -> dict[str, PressureSnapshot]:
    """Load at most the bounded set of valid, commitment-keyed snapshots."""

    if not isinstance(raw, Mapping):
        return {}
    loaded: dict[str, PressureSnapshot] = {}
    for key, value in sorted(
        cast(Mapping[str, JsonValue], raw).items(), key=lambda item: str(item[0]).encode()
    ):
        if (
            type(key) is not str
            or len(loaded) >= _MAX_HOOK_SEQUENCES
            or not isinstance(value, Mapping)
        ):
            continue
        try:
            validate_commitment(key)
            row = cast(Mapping[str, JsonValue], value)
            raw_state = row.get("state")
            raw_since = row.get("since_ms")
            raw_low = row.get("low_since_ms")
            raw_identity = row.get("transition_identity")
            if (
                type(raw_state) is not str
                or type(raw_since) is not int
                or isinstance(raw_since, bool)
                or raw_since < 0
                or (
                    raw_low is not None
                    and (
                        type(raw_low) is not int or isinstance(raw_low, bool) or raw_low < raw_since
                    )
                )
                or (raw_identity is not None and type(raw_identity) is not str)
            ):
                continue
            loaded[key] = PressureSnapshot(
                PressureState(raw_state),
                raw_since,
                raw_low,
                raw_identity,
            )
        except ProtocolValueError, TypeError, ValueError:
            continue
    return loaded


def _bounded_count(raw: object) -> int:
    """Read a persisted non-negative counter, treating a malformed value as zero."""

    if type(raw) is not int or not 0 <= raw <= _MAX_SAFE_INTEGER:
        return 0
    return raw


def _capture_handoff_retirement_valid(entry: Mapping[str, JsonValue]) -> bool:
    """Keep only closed-vocabulary, payload-free retirement diagnostics."""

    quarantine_reason = entry.get("quarantine_reason")
    ticket_id = entry.get("ticket_id")
    age_ms = entry.get("age_ms")
    retired_at = entry.get("retired_at")
    try:
        if type(retired_at) is not str:
            return False
        Timestamp(retired_at)
    except ProtocolValueError, TypeError, ValueError:
        return False
    if ticket_id is not None:
        try:
            if type(ticket_id) is not str or validate_sha256_digest(ticket_id) != ticket_id:
                return False
        except ProtocolValueError, TypeError, ValueError:
            return False
    return (
        entry.get("stage") in _CAPTURE_HANDOFF_STAGES
        and entry.get("reason") in _CAPTURE_HANDOFF_REASONS
        and entry.get("ticket_state") in {"staging", "pending"}
        and entry.get("source") in {item.value for item in ObservationSource}
        and type(entry.get("task_id")) is str
        and _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(cast(str, entry.get("task_id"))) is not None
        and type(age_ms) is int
        and 0 <= age_ms <= _MAX_SAFE_INTEGER
        and (
            quarantine_reason is None
            or (
                type(quarantine_reason) is str
                and _OUTBOX_REASON_RE.fullmatch(quarantine_reason) is not None
            )
        )
    )


def _capture_handoff_retirement_ids_from_json(raw: object) -> tuple[str, ...]:
    """Decode bounded ticket identities used to make retirement accounting idempotent."""

    if not isinstance(raw, (list, tuple)):
        return ()
    identities: list[str] = []
    for item in cast(Sequence[object], raw)[-_MAX_CAPTURE_TICKET_RESERVATIONS:]:
        if type(item) is not str:
            continue
        try:
            ticket_id = validate_sha256_digest(item)
        except ProtocolValueError, TypeError, ValueError:
            continue
        if ticket_id not in identities:
            identities.append(ticket_id)
    return tuple(identities)


def _capture_handoff_retirement_pending_from_json(raw: object) -> dict[str, str]:
    """Decode bounded ticket-to-task bindings awaiting retirement confirmation."""

    if not isinstance(raw, Mapping):
        return {}
    pending: dict[str, str] = {}
    entries = cast(Mapping[object, object], raw)
    for raw_ticket_id, raw_task_id in sorted(
        entries.items(), key=lambda item: str(item[0]).encode()
    ):
        if len(pending) >= _MAX_CAPTURE_TICKET_RESERVATIONS:
            break
        if type(raw_ticket_id) is not str or type(raw_task_id) is not str:
            continue
        try:
            ticket_id = validate_sha256_digest(raw_ticket_id)
        except ProtocolValueError, TypeError, ValueError:
            continue
        if ticket_id != raw_ticket_id or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(raw_task_id) is None:
            continue
        pending[ticket_id] = raw_task_id
    return pending


def _capture_handoff_retirements_from_json(raw: object) -> tuple[JsonObject, ...]:
    """Decode the bounded retirement account; malformed entries are dropped."""

    if not isinstance(raw, (list, tuple)):
        return ()
    entries: list[JsonObject] = []
    for item in cast(Sequence[object], raw)[-_MAX_CAPTURE_HANDOFF_RETIREMENTS:]:
        if not isinstance(item, Mapping):
            continue
        entry = cast(Mapping[str, JsonValue], item)
        if _capture_handoff_retirement_valid(entry):
            entries.append(JsonObject(dict(entry)))
    return tuple(entries)


def _timestamp_age_ms(now: Timestamp, earlier: Timestamp | None) -> int:
    if earlier is None or earlier >= now:
        return 0
    delta = now.as_datetime() - earlier.as_datetime()
    return max(0, delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000)


def _load_frontier_motion_notices(raw: object) -> dict[str, FrontierMotionNotice]:
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, FrontierMotionNotice] = {}
    for key, value in cast(Mapping[str, JsonValue], raw).items():
        if type(key) is not str or not isinstance(value, Mapping):
            continue
        notice = cast(Mapping[str, JsonValue], value)
        try:
            result[key] = FrontierMotionNotice(
                cast(int, notice.get("from_sequence")),
                cast(int, notice.get("to_sequence")),
                cast(str, notice.get("head_digest")),
                cast(int, notice.get("observation_record_count")),
                cast(str, notice.get("task_id")),
                cast(int, notice.get("recency_ordinal", 0)),
            )
        except ProtocolValueError, TypeError, ValueError:
            continue
    return result


def _load_frontier_motion_delivered(raw: object) -> dict[str, _FrontierMotionDelivered]:
    if not isinstance(raw, Mapping):
        return {}
    result: dict[str, _FrontierMotionDelivered] = {}
    for key, value in cast(Mapping[str, JsonValue], raw).items():
        if type(key) is not str or not isinstance(value, Mapping):
            continue
        entry = cast(Mapping[str, JsonValue], value)
        try:
            # Marks written before head/recency identity existed are ignored.
            # They cannot distinguish a replay from a same-task rewind, so the
            # only honest upgrade behavior is to fail open to a duplicate.
            result[key] = _FrontierMotionDelivered(
                cast(str, entry.get("task_id")),
                cast(int, entry.get("to_sequence")),
                cast(str, entry.get("head_digest")),
                cast(int, entry.get("recency_ordinal")),
            )
        except ProtocolValueError, TypeError, ValueError:
            continue
    return result


def _renumber_frontier_motion_recency(state: _WorkspaceState) -> None:
    """Compact the bounded LRU clock before its canonical integer can overflow."""

    notices = state.frontier_motion_notices or {}
    delivered = state.frontier_motion_delivered or {}
    ordered = sorted(
        (
            *((notice.recency_ordinal, 0, session) for session, notice in notices.items()),
            *((mark.recency_ordinal, 1, session) for session, mark in delivered.items()),
        ),
        key=lambda item: (item[0], item[1], item[2].encode()),
    )
    for ordinal, (_prior, kind, session) in enumerate(ordered, 1):
        if kind == 0:
            notices[session] = dataclasses.replace(notices[session], recency_ordinal=ordinal)
        else:
            delivered[session] = dataclasses.replace(delivered[session], recency_ordinal=ordinal)
    state.frontier_motion_recency = len(ordered)


def _next_frontier_motion_recency(state: _WorkspaceState) -> int:
    if state.frontier_motion_recency >= _MAX_SAFE_INTEGER:
        _renumber_frontier_motion_recency(state)
    state.frontier_motion_recency += 1
    return state.frontier_motion_recency


def _touch_frontier_motion_notice(
    state: _WorkspaceState,
    session_id: str,
    notice: FrontierMotionNotice,
) -> None:
    assert state.frontier_motion_notices is not None
    state.frontier_motion_notices[session_id] = dataclasses.replace(
        notice,
        recency_ordinal=_next_frontier_motion_recency(state),
    )


def _touch_frontier_motion_delivered(
    state: _WorkspaceState,
    session_id: str,
    *,
    task_id: str,
    to_sequence: int,
    head_digest: str,
) -> _FrontierMotionDelivered:
    assert state.frontier_motion_delivered is not None
    mark = _FrontierMotionDelivered(
        task_id,
        to_sequence,
        head_digest,
        _next_frontier_motion_recency(state),
    )
    state.frontier_motion_delivered[session_id] = mark
    return mark


def _frontier_lineage_rewound(
    *,
    current_sequence: int,
    current_head_digest: str,
    recorded_sequence: int,
    recorded_head_digest: str,
) -> bool:
    """Return whether the actual routed head proves a stored frontier is gone."""

    return current_sequence < recorded_sequence or (
        current_sequence == recorded_sequence and current_head_digest != recorded_head_digest
    )


def _advice_delivery_scope_key(
    *,
    yoetz_session_id: str | None,
    session_commitment: str | None,
) -> str | None:
    """Prefer the mapped Yoetz session; otherwise the current Codex session."""

    if type(yoetz_session_id) is str:
        return yoetz_session_id
    if type(session_commitment) is str:
        return session_commitment
    return None


def _task_scoped_delivery_snapshot(
    state: _WorkspaceState,
    *,
    yoetz_session_id: str | None,
    session_commitment: str | None,
) -> AdviceSnapshot | None:
    """Task-scoped snapshot for hook delivery: never the workspace fallback.

    A mapped Yoetz session snapshot is authority when present. Otherwise the
    current Codex session's retained envelopes are rebuilt in memory so a
    same-session failed command stays deliverable before ``start`` returns.
    """

    if type(yoetz_session_id) is str and state.session_advice is not None:
        mapped = state.session_advice.get(yoetz_session_id)
        if mapped is not None:
            return mapped
    if type(session_commitment) is not str or not session_commitment:
        return None
    envelopes = tuple(
        envelope
        for envelope in (state.envelopes or ())
        if envelope.session_commitment == session_commitment
    )
    if not envelopes:
        return None
    from yoetz.application.observation_advice import (
        ObservationAdviceBuildInput,
        build_observation_advice_snapshot,
    )

    return build_observation_advice_snapshot(
        ObservationAdviceBuildInput(
            envelopes=envelopes,
            lifecycle=ObservationLifecycle.ACTIVE,
            gaps=(),
            has_real_observation=True,
        )
    )


def _copy_state(state: _WorkspaceState) -> _WorkspaceState:
    """Independent copy of one workspace state for the parse cache.

    Containers are copied; contained values (envelopes, rows, cursors,
    snapshots, timestamps) are frozen dataclasses or immutable builtins, so a
    shallow container copy fully isolates callers from the cached instance.
    """

    return dataclasses.replace(
        state,
        session_workspaces=dict(state.session_workspaces or {}),
        cursors=dict(state.cursors or {}),
        dedup=set(state.dedup or ()),
        dedup_order=list(state.dedup_order or ()),
        dedup_lanes=dict(state.dedup_lanes or {}),
        envelopes=list(state.envelopes or ()),
        envelopes_truncated=state.envelopes_truncated,
        gaps=dict(state.gaps or {}),
        session_gaps={session: set(gaps) for session, gaps in (state.session_gaps or {}).items()},
        unsupported_events=set(state.unsupported_events or ()),
        session_advice=dict(state.session_advice or {}),
        session_advice_suppression=dict(state.session_advice_suppression or {}),
        frontier_motion_notices=dict(state.frontier_motion_notices or {}),
        frontier_motion_delivered=dict(state.frontier_motion_delivered or {}),
        open_pre=dict(state.open_pre or {}),
        unpaired_scopes=set(state.unpaired_scopes or ()),
        unpaired_notices=dict(state.unpaired_notices or {}),
        codex_tool_hooks=dict(state.codex_tool_hooks or {}),
        code_mode_cells=dict(state.code_mode_cells or {}),
        codex_tool_hook_clock=state.codex_tool_hook_clock,
        pending_rollout_items=dict(state.pending_rollout_items or {}),
        evicted_open_calls=dict(state.evicted_open_calls or {}),
        pairing_state_unknown=state.pairing_state_unknown,
        stream_cursors=dict(state.stream_cursors or {}),
        stream_partials=dict(state.stream_partials or {}),
        stream_call_tools={
            session: dict(tools) for session, tools in (state.stream_call_tools or {}).items()
        },
        stream_call_tool_generations=dict(state.stream_call_tool_generations or {}),
        stream_source_identities=dict(state.stream_source_identities or {}),
        stream_profiles=dict(state.stream_profiles or {}),
        stream_partial_dropped_sessions=set(state.stream_partial_dropped_sessions or ()),
        hook_sequences=dict(state.hook_sequences or {}),
        hook_sequence_clock=state.hook_sequence_clock,
        pending_outbox=list(state.pending_outbox or ()),
        quarantine=list(state.quarantine or ()),
        codex_session_bindings=dict(state.codex_session_bindings or {}),
        storage_corrupt_sessions=set(state.storage_corrupt_sessions or ()),
        ended_sessions=set(state.ended_sessions or ()),
        session_generations=dict(state.session_generations or {}),
        ended_session_generations=dict(state.ended_session_generations or {}),
        pending_lifecycles=list(state.pending_lifecycles or ()),
        pending_consent_revocation=state.pending_consent_revocation,
        pending_consent_projects=(
            None if state.pending_consent_projects is None else dict(state.pending_consent_projects)
        ),
        content_capture_epoch=state.content_capture_epoch,
        selection_settings=state.selection_settings,
        read_protections=list(state.read_protections or ()),
        capture_backlogs=dict(state.capture_backlogs or {}),
        capture_reservations=dict(state.capture_reservations or {}),
        capture_backlog_scope_unknown=state.capture_backlog_scope_unknown,
        capture_reservation_bootstrap=state.capture_reservation_bootstrap,
        capture_handoff_retirement_ids=state.capture_handoff_retirement_ids,
        capture_handoff_retirement_pending=(
            None
            if state.capture_handoff_retirement_pending is None
            else dict(state.capture_handoff_retirement_pending)
        ),
        pressure_snapshots=dict(state.pressure_snapshots or {}),
    )


def _restore_state(target: _WorkspaceState, source: _WorkspaceState) -> None:
    """Restore a state object from a previously captured independent copy.

    ``_save`` performs bounded retention before it writes the replacement file.
    If the protected durable rows still cannot fit, that retention work is
    rejected along with the write. Restoring the caller's mutable state keeps
    a failed save from leaking its speculative cache/history pruning into a
    surrounding batch or a later retry.
    """

    for field in dataclasses.fields(_WorkspaceState):
        setattr(target, field.name, getattr(source, field.name))


class _ObservationBatch(contextlib.AbstractContextManager[None]):
    """One local transaction, including a savepoint for nested callers.

    A class context manager preserves typed immutable protocol exceptions;
    generator context managers try to assign their traceback on propagation.
    """

    def __init__(self, store: LocalObservationStore, workspace: str, phase: str) -> None:
        self.store = store
        self.workspace = workspace
        self.phase = phase
        self.state: _WorkspaceState | None = None
        self.before: _WorkspaceState | None = None
        self.nested = False
        self.was_dirty = False

    def __enter__(self) -> None:
        lock = self.store._lock  # pyright: ignore[reportPrivateUsage]
        # Parse the committed document and encode its members before queueing
        # for the cross-process flock (in-process arrival order is kept). When
        # no other process commits meanwhile, the transaction starts from this
        # parse and the flock covers only mutation and the save (#689).
        lock.enter(
            self.phase,
            prepare=functools.partial(self.store._prewarm, self.workspace),  # pyright: ignore[reportPrivateUsage]
        )
        try:
            self.nested = self.workspace in self.store._batch  # pyright: ignore[reportPrivateUsage]
            self.was_dirty = self.workspace in self.store._batch_dirty  # pyright: ignore[reportPrivateUsage]
            self.state = self.store._load(self.workspace)  # pyright: ignore[reportPrivateUsage]
            self.before = _copy_state(self.state)
            if not self.nested:
                self.store._batch[self.workspace] = self.state  # pyright: ignore[reportPrivateUsage]
        except BaseException:
            self.store._lock.__exit__(None, None, None)  # pyright: ignore[reportPrivateUsage]
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        assert self.state is not None and self.before is not None
        try:
            if exc_type is not None:
                _restore_state(self.state, self.before)
                if not self.was_dirty:
                    self.store._batch_dirty.discard(self.workspace)  # pyright: ignore[reportPrivateUsage]
            if not self.nested:
                self.store._batch.pop(self.workspace, None)  # pyright: ignore[reportPrivateUsage]
                dirty = self.workspace in self.store._batch_dirty  # pyright: ignore[reportPrivateUsage]
                self.store._batch_dirty.discard(self.workspace)  # pyright: ignore[reportPrivateUsage]
                if exc_type is None and dirty:
                    try:
                        self.store._save(self.workspace, self.state)  # pyright: ignore[reportPrivateUsage]
                    except BaseException:
                        _restore_state(self.state, self.before)
                        raise
        finally:
            self.store._lock.__exit__(exc_type, exc, traceback)  # pyright: ignore[reportPrivateUsage]


def _new_content_capture_epoch() -> str:
    """Create an unguessable persisted epoch for one consent authority."""

    return "sha256:" + hashlib.sha256(os.urandom(_KEY_BYTES)).hexdigest()


def _ensure_content_capture_epoch(state: _WorkspaceState) -> str:
    """Return the state nonce, upgrading a pre-epoch state to a fresh one."""

    epoch = state.content_capture_epoch
    if type(epoch) is str:
        try:
            return validate_sha256_digest(epoch)
        except ProtocolValueError, TypeError, ValueError:
            pass
    epoch = _new_content_capture_epoch()
    state.content_capture_epoch = epoch
    return epoch


def _rotate_content_capture_epoch(state: _WorkspaceState) -> str:
    """Advance the local content fence after a real authority transition."""

    epoch = _new_content_capture_epoch()
    state.content_capture_epoch = epoch
    return epoch


def _consent_generation(
    consent: LocalObservationConsent,
    *,
    content_capture_epoch: str,
    runtime_gate_generation: str,
) -> str:
    """Derive a fence token from the durable consent and runtime epochs."""

    return canonical_digest(
        JsonObject(
            {
                "content_capture_epoch": content_capture_epoch,
                "granted_at": consent.granted_at.wire,
                "paused": consent.paused,
                "profiles": list(consent.content_capture_profiles),
                "revoked_at": None if consent.revoked_at is None else consent.revoked_at.wire,
                "runtime_gate_generation": runtime_gate_generation,
                "workspace_commitment": consent.workspace_commitment,
            }
        )
    )


def _stream_profile_id_valid(profile_id: object) -> bool:
    """Accept ``None`` or one bounded ASCII profile-id token such as ``codex-rollout-jsonl/x/v1``."""

    if profile_id is None:
        return True
    return (
        type(profile_id) is str
        and 0 < len(profile_id) <= 128
        and profile_id.isascii()
        and profile_id[0].isalnum()
        and all(char.isalnum() or char in "._+/-" for char in profile_id)
    )


def _content_capture_profiles_from_json(row: Mapping[str, JsonValue]) -> tuple[str, ...]:
    """Load the bounded plural consent arm, tolerating an early singular draft."""

    raw = row.get("content_capture_profiles")
    if raw is None:
        legacy = row.get("content_capture_profile")
        raw = () if legacy is None else (legacy,)
    if not isinstance(raw, (tuple, list)):
        return ()
    profiles: list[str] = []
    for value in cast(tuple[JsonValue, ...] | list[JsonValue], raw):
        if type(value) is str and is_content_capture_profile(value):
            profiles.append(value)
    return tuple(sorted(set(profiles), key=str.encode))[:2]


# Enough for the largest selected queue plus the retained envelope and
# quarantine caches of one workspace; a larger working set only loses reuse.
_CODEC_MEMO_ENTRIES: Final = 12_288


class _EnvelopeCodec:
    """Process-local, bounded, exact memo of envelope JSON conversions (#689).

    Every hook pass and service write re-encoded, and after any other writer's
    commit re-parsed, the whole workspace document while holding the shared
    store lock, although only a row or two changed. The envelopes, outbox rows
    and quarantine entries that dominate that document are immutable, so:

    - encoding caches one :class:`CanonicalFragment` per object identity (the
      memo holds the object, so its identity cannot be reused while cached),
      and splicing it yields exactly the bytes inline encoding would;
    - decoding caches the envelope built from one persisted JSON object, keyed
      by that object's key-sorted C-encoded text, which is equal exactly for
      equal JSON values; ``observation_envelope_from_json`` is a pure function
      of that value, so a hit returns the same validated envelope.

    A process that already read the committed document therefore holds the
    lock only for what changed, not for the size of the whole state.
    """

    def __init__(self, capacity: int) -> None:
        self._capacity = capacity
        self._guard = threading.Lock()
        # Decoded envelope and the container depth of the JSON it came from.
        self._decoded: OrderedDict[str, tuple[ObservationEnvelope, int]] = OrderedDict()
        self._encoded: OrderedDict[int, tuple[object, CanonicalFragment]] = OrderedDict()
        self._dedup: OrderedDict[tuple[str, int], tuple[ObservationEnvelope, str]] = OrderedDict()
        # Pressure facts per envelope identity: (envelope, byte length, protected).
        self._facts: dict[int, tuple[ObservationEnvelope, int, bool]] = {}

    @staticmethod
    def decode_key(raw: object) -> str | None:
        """Return the key-sorted C encoding of a parsed JSON object, equal for equal values."""

        if type(raw) is not dict:
            return None
        try:
            return json.dumps(raw, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        except TypeError, ValueError:
            return None

    def validated_levels(self, key: str) -> int | None:
        """Return the container depth of an envelope JSON this process already validated.

        Entries exist only for JSON that passed the full canonical profile, both in the
        document walk and in ``JsonObject`` construction, so an equal value needs no walk.
        """

        with self._guard:
            cached = self._decoded.get(key)
        return None if cached is None else cached[1]

    def decode(self, raw: Mapping[str, JsonValue], key: str | None = None) -> ObservationEnvelope:
        if key is None:
            key = self.decode_key(raw)
        if key is None:
            return observation_envelope_from_json(JsonObject(raw))
        with self._guard:
            cached = self._decoded.get(key)
            if cached is not None:
                self._decoded.move_to_end(key)
                return cached[0]
        envelope = observation_envelope_from_json(JsonObject(raw))
        levels = container_levels(raw)
        with self._guard:
            self._decoded[key] = (envelope, levels)
            while len(self._decoded) > self._capacity:
                self._decoded.popitem(last=False)
        return envelope

    def fragment(self, item: object, build: Callable[[], JsonValue]) -> CanonicalFragment:
        key = id(item)
        with self._guard:
            cached = self._encoded.get(key)
            if cached is not None and cached[0] is item:
                self._encoded.move_to_end(key)
                return cached[1]
        fragment = canonical_fragment(build())
        with self._guard:
            self._encoded[key] = (item, fragment)
            while len(self._encoded) > self._capacity:
                self._encoded.popitem(last=False)
        return fragment

    def pressure_facts(self, envelope: ObservationEnvelope) -> tuple[int, bool]:
        """Return an envelope's persisted byte length and protection in one lookup.

        Pressure sampling walks every retained row on each hook admission; one
        unlocked identity lookup per row keeps that walk cheap at a backlog of
        thousands (#887). Entries hold the envelope, so an identity cannot be
        reused while cached; a racing fill computes the same pure value.
        """

        cached = self._facts.get(id(envelope))
        if cached is not None and cached[0] is envelope:
            return cached[1], cached[2]
        size = _envelope_fragment(envelope).byte_length
        protected = _outbox_row_is_protected(envelope)
        with self._guard:
            if len(self._facts) >= self._capacity:
                self._facts.clear()
            self._facts[id(envelope)] = (envelope, size, protected)
        return size, protected

    def dedup_key(self, workspace: str, envelope: ObservationEnvelope) -> str:
        key = (workspace, id(envelope))
        with self._guard:
            cached = self._dedup.get(key)
            if cached is not None and cached[0] is envelope:
                self._dedup.move_to_end(key)
                return cached[1]
        digest = canonical_digest(
            JsonObject(
                {
                    "workspace_commitment": workspace,
                    "session_commitment": envelope.session_commitment,
                    "source": envelope.source.value,
                    "source_identity": envelope.source_identity,
                    "event_kind": envelope.event_kind,
                    "cursor": observation_cursor_to_json(envelope.cursor),
                }
            )
        )
        with self._guard:
            self._dedup[key] = (envelope, digest)
            while len(self._dedup) > self._capacity:
                self._dedup.popitem(last=False)
        return digest


_CODEC: Final = _EnvelopeCodec(_CODEC_MEMO_ENTRIES)


def _validate_state_document(parsed: object) -> dict[int, str]:
    """Apply the canonical profile to a lexically strict state document (#689).

    Equivalent to validating the whole document at once, member by member at the same depths,
    except that an envelope JSON value this process already validated (an equal value, with its
    recorded depth still inside the nesting bound) is not walked again. A re-read after another
    writer's commit therefore validates only what changed. Returns each envelope object's decode
    key by identity, so decoding does not encode it a second time.
    """

    keys: dict[int, str] = {}
    if type(parsed) is not dict:
        ensure_canonical_value(cast(ParsedJsonValue, parsed))
        return keys

    def envelope(item: ParsedJsonValue, depth: int) -> None:
        key = _CODEC.decode_key(item)
        if key is not None:
            keys[id(item)] = key
            levels = _CODEC.validated_levels(key)
            if levels is not None and depth + levels < MAX_JSON_DEPTH:
                return
        ensure_canonical_value(item, depth=depth)

    document = cast(dict[str, ParsedJsonValue], parsed)
    for name, value in document.items():
        ensure_canonical_value(name, depth=1)
        if name == "envelopes" and type(value) is list:
            for item in cast(list[ParsedJsonValue], value):
                envelope(item, 2)
        elif name in {"pending_outbox", "quarantine"} and type(value) is list:
            for item in cast(list[ParsedJsonValue], value):
                if type(item) is not dict:
                    ensure_canonical_value(item, depth=2)
                    continue
                for field, member in cast(dict[str, ParsedJsonValue], item).items():
                    ensure_canonical_value(field, depth=3)
                    if field == "envelope":
                        envelope(member, 3)
                    else:
                        ensure_canonical_value(member, depth=3)
        else:
            ensure_canonical_value(value, depth=1)
    return keys


def _envelope_fragment(envelope: ObservationEnvelope) -> CanonicalFragment:
    return _CODEC.fragment(envelope, functools.partial(observation_envelope_to_json, envelope))


def _envelope_bytes(envelope: ObservationEnvelope) -> int:
    """Return the canonical byte length of one envelope's persisted JSON."""

    return _envelope_fragment(envelope).byte_length


@functools.lru_cache(maxsize=1024)
def _delivery_unit_overhead(codex_session_id: str) -> int:
    """Return the canonical bytes of one delivery unit other than its envelope.

    The canonical object is ``{"codex_session_id":<id>,"envelope":<fragment>}``
    (members sort in that order) and a fragment splices verbatim, so the unit
    length is this wrapper's length with an empty ``{}`` envelope, minus those
    two bytes, plus the fragment's own length.
    """

    return (
        len(
            canonical_encode(
                cast(JsonValue, {"codex_session_id": codex_session_id, "envelope": {}})
            )
        )
        - 2
    )


def _delivery_unit_bytes(codex_session_id: str, envelope: ObservationEnvelope) -> int:
    """Return the canonical byte length of one ``{codex_session_id, envelope}`` unit.

    Pressure sampling sizes every pending row on each hook admission, so this
    must not re-encode the unit: at a retained backlog of thousands of rows a
    per-row encode dominated hook wall time (#887). The memoized envelope
    fragment plus a per-session-id wrapper overhead gives the identical length.
    """

    return _delivery_unit_overhead(codex_session_id) + _envelope_fragment(envelope).byte_length


def _outbox_row_fragment(row: ObservationOutboxRow) -> CanonicalFragment:
    return _CODEC.fragment(row, functools.partial(_outbox_row_to_spliced_json, row))


def _outbox_row_bytes(row: ObservationOutboxRow) -> int:
    return _outbox_row_fragment(row).byte_length


def _quarantine_entry_fragment(
    entry: tuple[str, ObservationEnvelope, str, Timestamp],
) -> CanonicalFragment:
    return _CODEC.fragment(
        entry,
        lambda: cast(
            JsonValue,
            {
                "codex_session_id": entry[0],
                "envelope": _envelope_fragment(entry[1]),
                "reason": entry[2],
                "quarantined_at": entry[3].wire,
            },
        ),
    )


def _dedup_key(workspace: str, envelope: ObservationEnvelope) -> str:
    return _CODEC.dedup_key(workspace, envelope)


def _prime_codec(state: _WorkspaceState) -> None:
    """Fill the codec memo for one committed state's immutable members.

    ``state`` is a cached committed parse that nobody mutates, so reading its
    lists here needs no lock.
    """

    for envelope in state.envelopes or ():
        _envelope_fragment(envelope)
    for row in state.pending_outbox or ():
        _outbox_row_fragment(row)
    for entry in state.quarantine or ():
        _quarantine_entry_fragment(entry)
    for item in state.admission_buffer.inputs:
        _envelope_fragment(item.envelope)


def _outbox_row_to_spliced_json(row: ObservationOutboxRow) -> JsonValue:
    """Return :func:`_outbox_row_to_json`'s value with the envelope as a cached fragment."""

    return cast(
        JsonValue,
        {
            "codex_session_id": row.codex_session_id,
            "envelope": _envelope_fragment(row.envelope),
            "attempts": row.attempts,
            "last_reason": row.last_reason,
            "last_attempt_at": (None if row.last_attempt_at is None else row.last_attempt_at.wire),
            "consecutive_reason_attempts": row.consecutive_reason_attempts,
        },
    )


def _outbox_row_to_json(row: ObservationOutboxRow) -> JsonObject:  # pyright: ignore[reportUnusedFunction]
    """Return one pending row exactly as the workspace state persists it.

    The inline reference for :func:`_outbox_row_to_spliced_json`, which the
    store now encodes; tests pin the two to identical bytes (#689).
    """

    return JsonObject(
        {
            "codex_session_id": row.codex_session_id,
            "envelope": observation_envelope_to_json(row.envelope),
            "attempts": row.attempts,
            "last_reason": row.last_reason,
            "last_attempt_at": (None if row.last_attempt_at is None else row.last_attempt_at.wire),
            "consecutive_reason_attempts": row.consecutive_reason_attempts,
        }
    )


def _outbox_row_is_protected(envelope: ObservationEnvelope) -> bool:
    """Return whether a retained row is outside optional-read admission.

    Routine summaries and clean detailed routine reads are disposable
    selection output.  Every other envelope remains protected, including
    unknown, failed, pre-event, and content-bearing rows.  The local store
    derives this from its service-owned structural shape; a host label cannot
    downgrade a row's protection.
    """

    if envelope.event_kind == "RoutineReadSummary":
        return False
    return not (
        envelope.structural_payload.get("action") == "routine_read_detailed"
        and not envelope.gap_codes
        and not envelope.content_object_refs
    )


_OPTIONAL_ROUTINE_SELECTION_GAPS: Final = frozenset(
    {"content_unselected", "observation_input_loss"}
)


def _optional_routine_selection_envelope(envelope: ObservationEnvelope) -> bool:
    """Recognize an input whose exact selected account is durable elsewhere.

    The diagnostic envelope cache is secondary to the admission buffer and
    outbox.  Only service-marked routine reads with no captured content (and
    the two bounded selection coverage gaps) may be reclaimed.  A plain read
    without an authenticated selection route remains in the cache because it
    may still be the only durable diagnostic record for the host event.
    """

    if envelope.content_object_refs or any(
        gap not in _OPTIONAL_ROUTINE_SELECTION_GAPS for gap in envelope.gap_codes
    ):
        return False
    action = envelope.structural_payload.get("action")
    if action == "routine_read_detailed":
        return True
    if action != "routine_read":
        return False
    try:
        return observation_selection_route(envelope.structural_payload) is not None
    except ProtocolValueError, TypeError, ValueError:
        return False


def _read_protection_envelope_is_read(envelope: ObservationEnvelope) -> bool:
    """Recognize only service-owned read structure at the local-store boundary."""

    if type(envelope) is not ObservationEnvelope:
        return False
    tool_name = envelope.structural_payload.get("tool_name")
    if type(tool_name) is not str:
        return False
    lowered = tool_name.casefold()
    if lowered in ROUTINE_READ_TOOLS:
        return True
    # Shell command text is intentionally absent from structural envelopes.
    # The adapter's typed classifier emits this marker only for its closed
    # shell read grammar; an arbitrary host action or reference is ignored.
    return lowered in SHELL_TOOLS and envelope.structural_payload.get("action") in {
        "routine_read",
        "routine_read_detailed",
    }


class LocalObservationStore:
    """Durable ObservationPort-shaped local store for consent and structural envelopes."""

    def __init__(
        self,
        *,
        _state: Path | None = None,
        _monotonic: Callable[[], float] | None = None,
        _wall: Callable[[], float] | None = None,
    ) -> None:
        self._root = observation_dir(_state=_state)
        self._state_root = self._root.parent
        # Monotonic milliseconds accumulated per store sub-stage since
        # construction. Hooks fold these into their pass-timing rows so the
        # formerly opaque 'store' stage is attributable (#290), and so time
        # spent queueing for the store lock is reported as queueing rather
        # than as unexplained wall time (#310).
        self.stage_timings_ms: dict[str, float] = {
            "hydrate": 0.0,
            "encode": 0.0,
            "lock_wait": 0.0,
            "lock_hold": 0.0,
            "write": 0.0,
        }
        self._lock = _InterprocessStoreLock(
            self._root / ".store.lock", waits_ms=self.stage_timings_ms
        )
        self._monotonic = _monotonic
        self._wall = _wall
        # Parse cache keyed by workspace commitment, validated by the state
        # file's (inode, size, mtime_ns, ctime_ns). Hooks are one-shot
        # processes that call many store methods against the same file;
        # re-reading and re-parsing a ~400KB state on every method call
        # dominated hook wall time (#209). _atomic_write replaces the inode,
        # so a stat match means the cached parse is byte-current even across
        # processes. Bounded so the long-lived daemon, which iterates every
        # workspace on its sweep loop, never accretes one parsed object graph
        # per workspace it has ever seen.
        self._state_cache: dict[str, tuple[tuple[int, int, int, int], _WorkspaceState]] = {}
        # Committed reads run without the store lock (#689), so the service's
        # worker threads may consult and refresh the parse cache concurrently.
        # The guard covers only dictionary access; cached states are never
        # mutated in place, and every reader receives its own copy.
        self._cache_guard = threading.Lock()
        self._key_material_cache: bytes | None = None
        # Open write batches keyed by workspace commitment. Inside a batch
        # `_load` hands back the held mutable state and `_save` only marks it
        # dirty, so one hook pass serializes and fsyncs once instead of the
        # 10-18 times measured on a lived-in store (#242).
        self._batch: dict[str, _WorkspaceState] = {}
        self._batch_dirty: set[str] = set()
        # Production READY composition enables this gate before exposing the
        # coordinator.  Reference stores and hook-only readers leave it off;
        # they do not own the workspace-global capture admission lane.
        self._capture_reservation_bootstrap_required = False

    def _now_mono(self) -> float:
        import time

        return time.monotonic() if self._monotonic is None else self._monotonic()

    def _wall_now(self) -> float:
        import time

        return time.time() if self._wall is None else self._wall()

    def _wall_timestamp(self) -> Timestamp:
        current = datetime.fromtimestamp(self._wall_now(), UTC)
        stamp = current.replace(microsecond=(current.microsecond // 1000) * 1000)
        return timestamp_from_datetime(stamp)

    def _boot_epoch(self) -> float:
        """Approximate wall time at monotonic zero: stable within a boot session.

        A reboot resets the monotonic clock, so this shifts by the previous
        uptime and cleanly distinguishes samples from an earlier boot.
        """

        return self._wall_now() - self._now_mono()

    def _epoch_matches(self, epoch: float | None) -> bool:
        return epoch is not None and abs(self._boot_epoch() - epoch) <= _EPOCH_TOLERANCE_SECONDS

    def key_material(self) -> bytes:
        path = self._root / "key-material.bin"
        # The key is created once by an atomic replace and never rewritten, so
        # an existing complete file is authoritative without the store lock.
        # Every hook resolves its workspace commitment through this read;
        # queueing it behind a contended batch turned a lock timeout into a
        # dropped event misreported as an unconsented workspace (#689).
        existing = _read_bytes(path, maximum=_KEY_BYTES)
        if existing is not None and len(existing) == _KEY_BYTES:
            return existing
        with self._lock:
            existing = _read_bytes(path, maximum=_KEY_BYTES)
            if existing is not None and len(existing) == _KEY_BYTES:
                return existing
            material = os.urandom(_KEY_BYTES)
            _atomic_write(path, material)
            return material

    def _cached_key_material(self) -> bytes:
        # The key file is created once and never rewritten, so a per-instance
        # memo is safe; the uncached read costs a file open per call, which
        # multiplies badly inside per-entry loops (quarantine eviction).
        if self._key_material_cache is None:
            self._key_material_cache = self.key_material()
        return self._key_material_cache

    def set_runtime_enabled(self, enabled: bool) -> None:
        """Publish the service-loaded observation gate for config-free hook reads.

        The marker is synchronized when a fresh READY composition is built.  A
        missing marker preserves the typed configuration default (enabled);
        malformed or unsafe markers fail closed in :meth:`runtime_enabled`.

        The runtime gate carries the nonce that participates in every content
        fence.  Repeating the same value is a no-op so READY repair and restart
        retries do not invalidate an unchanged in-flight review; an actual
        transition gets a new nonce atomically with the enabled bit.
        """

        if type(enabled) is not bool:
            raise TypeError("observation_runtime_gate_invalid")
        with self._lock:
            gate_path = self._root / _RUNTIME_GATE_NAME
            marker_present = gate_path.exists() and not gate_path.is_symlink()
            try:
                current, _generation = self._runtime_gate_facts()
            except PublicOperationError:
                # Preserve the existing repair behavior for a malformed
                # marker: the authorized service setter may replace it with a
                # fresh, valid gate and a fresh fence nonce.
                current = None
            if marker_present and current is enabled:
                return
            payload = (
                canonical_encode(
                    JsonObject(
                        {
                            "enabled": enabled,
                            "generation": _new_content_capture_epoch(),
                            "schema": _RUNTIME_GATE_SCHEMA,
                        }
                    )
                )
                + b"\n"
            )
            _atomic_write(gate_path, payload)

    def set_capture_reservation_bootstrap_required(self, required: bool = True) -> None:
        """Require a persisted complete route inventory before central admission.

        The flag is process-local because READY composition is the authority
        that owns the coordinator.  Every new service generation sets it
        before accepting capture work, so a missing or stale persisted proof
        fails closed after restart and upgrade while read-only hook stores keep
        their legacy behavior.
        """

        if type(required) is not bool:
            raise TypeError("capture_bootstrap_requirement_invalid")
        self._capture_reservation_bootstrap_required = required

    def _runtime_gate_facts(self) -> tuple[bool, str]:
        """Read the enabled bit and fence nonce from one marker descriptor.

        Deliberately lock-free: the marker is a tiny owner-only file that
        :meth:`set_runtime_enabled` only ever replaces atomically, and every
        hook event begins with this read. Serializing it on the interprocess
        store lock converted ordinary batch contention into gate failures
        that discarded events (#273). Reading through one descriptor keeps
        the safety checks and the payload bound to a single inode instead.
        """

        path = self._root / _RUNTIME_GATE_NAME
        flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NONBLOCK", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            return True, _LEGACY_RUNTIME_GATE_GENERATION
        except OSError as exc:
            message = (
                "Observation runtime gate is unsafe."
                if exc.errno == errno.ELOOP
                else "Observation runtime gate is unavailable."
            )
            raise _error(PublicErrorCode.STORAGE_UNSAFE, message, retryable=False) from exc
        try:
            facts = os.fstat(descriptor)
            if (
                not stat.S_ISREG(facts.st_mode)
                or facts.st_uid != os.geteuid()
                or facts.st_mode & 0o077
                or facts.st_size <= 0
                or facts.st_size > _MAX_RUNTIME_GATE_BYTES
            ):
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "Observation runtime gate is unsafe.",
                    retryable=False,
                )
            chunks: list[bytes] = []
            remaining = _MAX_RUNTIME_GATE_BYTES + 1
            while remaining > 0 and (chunk := os.read(descriptor, remaining)):
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_RUNTIME_GATE_BYTES:
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "Observation runtime gate is unsafe.",
                    retryable=False,
                )
        except OSError as exc:
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation runtime gate is invalid.",
                retryable=False,
            ) from exc
        finally:
            os.close(descriptor)
        try:
            parsed = strict_json_parse(raw)
        except ProtocolValueError as exc:
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation runtime gate is invalid.",
                retryable=False,
            ) from exc
        if (
            not isinstance(parsed, Mapping)
            or set(parsed)
            not in (
                {"schema", "enabled"},
                {"schema", "enabled", "generation"},
            )
            or parsed.get("schema") != _RUNTIME_GATE_SCHEMA
            or type(parsed.get("enabled")) is not bool
        ):
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation runtime gate is invalid.",
                retryable=False,
            )
        raw_generation = parsed.get("generation")
        if raw_generation is None:
            generation = _LEGACY_RUNTIME_GATE_GENERATION
        elif type(raw_generation) is str:
            try:
                generation = validate_sha256_digest(raw_generation)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise _error(
                    PublicErrorCode.STORAGE_UNSAFE,
                    "Observation runtime gate is invalid.",
                    retryable=False,
                ) from exc
        else:
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation runtime gate is invalid.",
                retryable=False,
            )
        return cast(bool, parsed["enabled"]), generation

    def runtime_enabled(self) -> bool:
        """Return the current service-synchronized capture gate, failing closed."""

        return self._runtime_gate_facts()[0]

    def runtime_gate_generation(self) -> str:
        """Return the persisted runtime nonce without taking the store lock."""

        return self._runtime_gate_facts()[1]

    def workspace_commitment(self, path: str) -> str:
        return workspace_commitment_from_path(self._cached_key_material(), path)

    def session_commitment(self, codex_session_id: str) -> str:
        return session_commitment_from_codex_id(self._cached_key_material(), codex_session_id)

    @_read_mostly
    def pending_consent_revocation(
        self, workspace_commitment: str
    ) -> tuple[str, tuple[tuple[str, int], ...] | None] | None:
        """Return the durable source-consent fence awaiting project invalidation."""

        with self._reading():
            state = self._load(workspace_commitment)
            token = state.pending_consent_revocation
            if token is None:
                return None
            if state.pending_consent_projects is None:
                return token, None
            return token, tuple(
                sorted(state.pending_consent_projects.items(), key=lambda item: item[0].encode())
            )

    def record_consent_revocation_plan(
        self,
        workspace_commitment: str,
        token: str,
        project_generations: Mapping[str, int],
    ) -> None:
        """Durably bind a revoke token to the project generations it must fence."""

        validate_sha256_digest(token)
        normalized: dict[str, int] = {}
        if len(project_generations) > _MAX_PENDING_CONSENT_PROJECTS:
            raise ProtocolValueError("invalid_event_value_type")
        for project_id, generation in project_generations.items():
            validate_id(IdKind.PROJECT, project_id)
            if type(generation) is not int or isinstance(generation, bool) or generation < 1:
                raise ProtocolValueError("invalid_event_value_type")
            normalized[project_id] = generation
        with self._lock:
            state = self._load(workspace_commitment)
            if state.pending_consent_revocation != token:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Observation consent revocation is no longer current.",
                    retryable=False,
                )
            if (
                state.pending_consent_projects is not None
                and state.pending_consent_projects != normalized
            ):
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Observation consent revocation plan changed.",
                    retryable=False,
                )
            state.pending_consent_projects = normalized
            self._save(workspace_commitment, state)

    def mark_consent_revocation_fenced(self, workspace_commitment: str, token: str) -> None:
        """Clear a completed project-generation fence, idempotently."""

        validate_sha256_digest(token)
        with self._lock:
            state = self._load(workspace_commitment)
            if state.pending_consent_revocation != token:
                return
            state.pending_consent_revocation = None
            state.pending_consent_projects = None
            self._save(workspace_commitment, state)

    def _session_workspace_owners_unlocked(self, session_commitment: str) -> frozenset[str]:
        """Return every local workspace that records one session commitment."""

        owners: set[str] = set()
        for workspace, state in self._iter_workspaces():
            assert state.session_workspaces is not None
            bound_workspace = state.session_workspaces.get(session_commitment)
            if bound_workspace is not None:
                owners.add(workspace)
                if type(bound_workspace) is str and bound_workspace:
                    owners.add(bound_workspace)
            assert state.codex_session_bindings is not None
            if session_commitment in state.codex_session_bindings.values():
                owners.add(workspace)
            # Generation tombstones are ownership evidence even when the raw host binding was
            # pruned; otherwise late replay could rebind the same session to another workspace.
            if session_commitment in (state.session_generations or {}):
                owners.add(workspace)
            if session_commitment in (state.ended_session_generations or {}):
                owners.add(workspace)
        return frozenset(owners)

    def grant_consent(
        self,
        workspace_commitment: str,
        granted_at: Timestamp | None = None,
        *,
        content_capture_profiles: tuple[str, ...] | None = None,
    ) -> LocalConsentGrant:
        """Record structural observation consent without disturbing live content arms.

        A grant over a live (unrevoked) consent continues it: the original
        ``granted_at`` is kept, and so are the already-approved native content
        profiles unless ``content_capture_profiles`` names an explicit
        replacement set.  An already-effective grant therefore leaves the
        consent unchanged and never advances the content fence, so connecting
        a second host or repeating setup cannot silently drop or re-fence
        another host's arm (issue #835).  A grant over a paused consent resumes it exactly as
        ``resume`` does.

        With no prior consent, or after revocation, the grant starts fresh at
        ``granted_at`` (default now) with no content arm unless one is named.
        Revocation already cleared the arms; a later grant never infers them
        back.
        """

        if content_capture_profiles is not None:
            if type(content_capture_profiles) is not tuple:
                raise ProtocolValueError("invalid_event_value_type")
            for profile in content_capture_profiles:
                validate_content_capture_profile(profile)
        with self._lock:
            state = self._load(workspace_commitment)
            if state.pending_consent_revocation is not None:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Observation consent revocation is still being fenced.",
                    retryable=True,
                )
            prior = state.consent
            live = prior if prior is not None and prior.revoked_at is None else None
            if live is not None:
                stamp = live.granted_at
                profiles = (
                    live.content_capture_profiles
                    if content_capture_profiles is None
                    else content_capture_profiles
                )
            else:
                stamp = granted_at if granted_at is not None else _now()
                profiles = () if content_capture_profiles is None else content_capture_profiles
            next_consent = LocalObservationConsent(
                workspace_commitment=workspace_commitment,
                granted_at=stamp,
                revoked_at=None,
                paused=False,
                content_capture_profiles=profiles,
            )
            if live is None:
                transition = LocalConsentTransition.GRANTED
            elif live == next_consent:
                transition = LocalConsentTransition.UNCHANGED
            elif live.paused:
                transition = LocalConsentTransition.RESUMED
            else:
                transition = LocalConsentTransition.UPDATED
            if prior != next_consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            # Still a mutation-driven save: bounded housekeeping (such as aged quarantine
            # pruning) runs as it always did, while the consent and its fence stay put.
            self._save(workspace_commitment, state)
            return LocalConsentGrant(transition, next_consent)

    def enable_content_capture(self, workspace_commitment: str, profile: str) -> None:
        """Explicitly enable one versioned native-host content profile.

        This is a second consent arm.  A historical structural grant remains
        contentless until this operation is performed, and a revoked grant can
        never be re-enabled without a fresh structural grant.
        """

        validate_content_capture_profile(profile)
        with self._lock:
            state = self._load(workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            if consent.revoked_at is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is revoked.",
                    retryable=False,
                )
            profiles = tuple(
                sorted(
                    {*consent.content_capture_profiles, profile},
                    key=str.encode,
                )
            )
            next_consent = dataclasses.replace(
                consent,
                content_capture_profiles=profiles,
            )
            if next_consent != consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            self._save(workspace_commitment, state)

    def disable_content_capture(
        self, workspace_commitment: str, profile: str | None = None
    ) -> None:
        """Disable one native-host content arm, or all arms when omitted."""

        if profile is not None:
            validate_content_capture_profile(profile)

        with self._lock:
            state = self._load(workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            profiles = (
                ()
                if profile is None
                else tuple(item for item in consent.content_capture_profiles if item != profile)
            )
            next_consent = dataclasses.replace(
                consent,
                content_capture_profiles=profiles,
            )
            if next_consent != consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            self._save(workspace_commitment, state)

    @_read_mostly
    def content_capture_profiles(self, workspace_commitment: str) -> tuple[str, ...]:
        """Return the persisted content arms, including while observation is paused."""

        with self._reading():
            consent = self._load(workspace_commitment).consent
            return () if consent is None else consent.content_capture_profiles

    @_read_mostly
    def content_capture_authority(
        self, workspace_commitment: str
    ) -> LocalContentCaptureAuthority | None:
        """Read the authoritative local content fence under the store lock."""

        with self._reading():
            state = self._load(workspace_commitment)
            prior_epoch = state.content_capture_epoch
            content_capture_epoch = _ensure_content_capture_epoch(state)
            if content_capture_epoch != prior_epoch:
                self._save(workspace_commitment, state)
            consent = state.consent
            if consent is None:
                return None
            runtime_enabled, runtime_generation = self._runtime_gate_facts()
            return LocalContentCaptureAuthority(
                workspace_commitment=workspace_commitment,
                generation=_consent_generation(
                    consent,
                    content_capture_epoch=content_capture_epoch,
                    runtime_gate_generation=runtime_generation,
                ),
                active=consent.active,
                revoked=consent.revoked_at is not None,
                runtime_enabled=runtime_enabled,
                profiles=consent.content_capture_profiles,
            )

    @_read_mostly
    def content_capture_authority_is_current(
        self,
        workspace_commitment: str,
        generation: str,
        profiles: tuple[str, ...],
    ) -> bool:
        """Atomically test a previously read content fence against current consent."""

        if (
            type(generation) is not str
            or not generation.startswith("sha256:")
            or type(profiles) is not tuple
        ):
            return False
        try:
            validate_sha256_digest(generation)
        except ProtocolValueError, TypeError, ValueError:
            return False
        with self._reading():
            state = self._load(workspace_commitment)
            prior_epoch = state.content_capture_epoch
            content_capture_epoch = _ensure_content_capture_epoch(state)
            if content_capture_epoch != prior_epoch:
                self._save(workspace_commitment, state)
            consent = state.consent
            runtime_enabled, runtime_generation = self._runtime_gate_facts()
            return (
                consent is not None
                and consent.active
                and runtime_enabled
                and _consent_generation(
                    consent,
                    content_capture_epoch=content_capture_epoch,
                    runtime_gate_generation=runtime_generation,
                )
                == generation
                and consent.content_capture_profiles == profiles
            )

    @_read_mostly
    def selection_settings_for(
        self,
        workspace_commitment: str,
        *,
        now: Timestamp | None = None,
    ) -> ObservationSelectionSettings:
        """Return owner-selected settings after atomically expiring stale entries.

        Settings are kept in the same owner-private workspace file as consent
        and the bounded outbox.  Expiry is an exclusive wall-clock boundary;
        a read that observes it removes the entry under the existing store
        lock, so a concurrent hook cannot continue using an expired override.
        """

        with self._reading():
            state = self._load(workspace_commitment)
            current = state.selection_settings or ObservationSelectionSettings()
            stamp = now if now is not None else self._wall_timestamp()
            active = self._prune_selection_settings(current, stamp)
            if active != current:
                state.selection_settings = active
                self._save(workspace_commitment, state)
            return active

    def set_workspace_selection(
        self,
        workspace_commitment: str,
        selection: ObservationSelection,
        *,
        expires_at: Timestamp | None = None,
        set_at: Timestamp | None = None,
    ) -> ObservationSelectionSetting:
        """Persist the owner-selected default for this workspace.

        This changes future structural admission only.  It neither grants
        observation consent nor changes native content or privacy authority.
        """

        setting = self._selection_setting(selection, expires_at=expires_at, set_at=set_at)
        with self._lock:
            state = self._load(workspace_commitment)
            settings = self._prune_selection_settings(
                state.selection_settings or ObservationSelectionSettings(),
                setting.set_at,
            )
            next_settings = settings.with_workspace(setting)
            if next_settings != settings:
                state.selection_settings = next_settings
                self._save(workspace_commitment, state)
            return setting

    def set_session_selection(
        self,
        workspace_commitment: str,
        session_commitment: str,
        selection: ObservationSelection,
        *,
        expires_at: Timestamp | None = None,
        set_at: Timestamp | None = None,
    ) -> ObservationSelectionSetting:
        """Persist a temporary owner-selected override for one session."""

        setting = self._selection_setting(selection, expires_at=expires_at, set_at=set_at)
        with self._lock:
            state = self._load(workspace_commitment)
            settings = self._prune_selection_settings(
                state.selection_settings or ObservationSelectionSettings(),
                setting.set_at,
            )
            next_settings = settings.with_session(session_commitment, setting)
            if next_settings != settings:
                state.selection_settings = next_settings
                self._save(workspace_commitment, state)
            return setting

    def clear_workspace_selection(
        self,
        workspace_commitment: str,
        *,
        now: Timestamp | None = None,
    ) -> ObservationSelectionSettings:
        """Remove the persisted workspace default and fall back to configuration."""

        with self._lock:
            state = self._load(workspace_commitment)
            settings = self._prune_selection_settings(
                state.selection_settings or ObservationSelectionSettings(),
                now if now is not None else self._wall_timestamp(),
            )
            next_settings = settings.with_workspace(None)
            if next_settings != settings:
                state.selection_settings = next_settings
                self._save(workspace_commitment, state)
            return next_settings

    def clear_session_selection(
        self,
        workspace_commitment: str,
        session_commitment: str,
        *,
        now: Timestamp | None = None,
    ) -> ObservationSelectionSettings:
        """Revoke one session override without changing workspace defaults."""

        with self._lock:
            state = self._load(workspace_commitment)
            settings = self._prune_selection_settings(
                state.selection_settings or ObservationSelectionSettings(),
                now if now is not None else self._wall_timestamp(),
            )
            next_settings = settings.without_session(session_commitment)
            if next_settings != settings:
                state.selection_settings = next_settings
                self._save(workspace_commitment, state)
            return next_settings

    @staticmethod
    def _read_protection_auth_generation(
        workspace_commitment: str, state: _WorkspaceState
    ) -> str | None:
        """Return the opaque consent fence used by explicit read scopes.

        ``content_capture_epoch`` is only a nonce here. Including it prevents
        a pause/resume or revoke/grant ABA from reactivating an old scope;
        checking content authority remains a separate caller responsibility.
        """

        consent = state.consent
        if consent is None:
            return None
        epoch = _ensure_content_capture_epoch(state)
        return canonical_digest(
            JsonObject(
                {
                    "kind": "observation-read-protection-auth/v1",
                    "workspace_commitment": workspace_commitment,
                    "consent_granted_at": consent.granted_at.wire,
                    "consent_revoked_at": (
                        None if consent.revoked_at is None else consent.revoked_at.wire
                    ),
                    "consent_paused": consent.paused,
                    "consent_epoch": epoch,
                }
            )
        )

    @staticmethod
    def _read_protection_generation(state: _WorkspaceState, session_commitment: str) -> int:
        assert state.session_generations is not None
        generation = state.session_generations.get(session_commitment, 0)
        return generation if generation >= 1 else 1

    def _prune_read_protections(
        self,
        state: _WorkspaceState,
        *,
        workspace_commitment: str,
        now: Timestamp,
        auth_generation: str | None = None,
    ) -> bool:
        """Drop expired or generation-fenced scopes before they can match."""

        assert state.read_protections is not None
        if auth_generation is None:
            auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
        kept: list[ReadProtection] = []
        changed = False
        for protection in state.read_protections:
            current_generation = self._read_protection_generation(
                state, protection.session_commitment
            )
            if (
                protection.expires_at <= now
                or protection.auth_generation != auth_generation
                or protection.session_generation != current_generation
            ):
                changed = True
                continue
            kept.append(protection)
        if changed:
            state.read_protections[:] = kept
        return changed

    def _read_protection_candidates(
        self,
        state: _WorkspaceState,
        *,
        workspace_commitment: str,
        session_commitment: str,
        envelope: ObservationEnvelope,
        now: Timestamp,
        attempt_id: str | None = None,
    ) -> tuple[str | None, list[tuple[int, ReadProtection]]]:
        """Return current matching scopes and their opaque auth fence."""

        if (
            type(envelope) is not ObservationEnvelope
            or envelope.session_commitment != session_commitment
            or not _read_protection_envelope_is_read(envelope)
        ):
            return None, []
        consent = state.consent
        if consent is None or not consent.active:
            return None, []
        auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
        if auth_generation is None:
            return None, []
        current_generation = self._read_protection_generation(state, session_commitment)
        if (
            session_commitment in (state.ended_sessions or set())
            or envelope.cursor.source_generation != current_generation
        ):
            return auth_generation, []
        matches = [
            (index, protection)
            for index, protection in enumerate(state.read_protections or ())
            if (
                protection.session_commitment == session_commitment
                and protection.auth_generation == auth_generation
                and protection.session_generation == current_generation
                and protection.expires_at > now
                and (
                    protection.remaining > 0
                    or (
                        attempt_id is not None
                        and (protection.reserved(attempt_id) or protection.consumed(attempt_id))
                    )
                )
            )
        ]
        if attempt_id is not None:
            matches.sort(
                key=lambda item: (
                    0 if item[1].reserved(attempt_id) or item[1].consumed(attempt_id) else 1
                )
            )
        return auth_generation, matches

    def protect_next_reads(
        self,
        workspace_commitment: str,
        session_commitment: str,
        reference: str,
        *,
        count: int = 1,
        expires_at: Timestamp | None = None,
    ) -> JsonObject:
        """Protect a bounded number of future reads for one current session.

        This operation only raises retention protection. It cannot create
        consent, enable content capture, or authorize privacy/provider egress.
        The reference is syntax-checked so a later claim may be created after
        this request; no projection lookup is performed.
        """

        try:
            workspace_commitment = validate_commitment(workspace_commitment)
            session_commitment = validate_commitment(session_commitment)
            reference = validate_read_protection_reference(reference)
        except ProtocolValueError, TypeError, ValueError:
            raise
        if (
            type(count) is not int
            or isinstance(count, bool)
            or not 1 <= count <= MAX_READ_PROTECTION_COUNT
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if expires_at is not None and type(expires_at) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")

        with self._lock:
            state = self._load(workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            if consent.workspace_commitment != workspace_commitment:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation workspace is invalid.",
                    retryable=False,
                )
            if not consent.active:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is inactive.",
                    retryable=False,
                )
            assert state.session_workspaces is not None
            bound_workspace = state.session_workspaces.get(session_commitment)
            if bound_workspace is not None and bound_workspace != workspace_commitment:
                raise _error(
                    PublicErrorCode.SESSION_CONFLICT,
                    "Observation session is already bound.",
                    retryable=False,
                )
            now = self._wall_timestamp()
            maximum_expiry = timestamp_from_datetime(
                now.as_datetime() + timedelta(seconds=DEFAULT_READ_PROTECTION_TTL_SECONDS)
            )
            effective_expiry = maximum_expiry if expires_at is None else expires_at
            if effective_expiry <= now or effective_expiry > maximum_expiry:
                raise ProtocolValueError("invalid_timestamp")
            auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
            if auth_generation is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            self._prune_read_protections(
                state,
                workspace_commitment=workspace_commitment,
                now=now,
                auth_generation=auth_generation,
            )
            assert state.read_protections is not None
            current_generation = self._read_protection_generation(state, session_commitment)
            same_scope = next(
                (
                    index
                    for index, protection in enumerate(state.read_protections)
                    if (
                        protection.reference == reference
                        and protection.session_commitment == session_commitment
                        and protection.auth_generation == auth_generation
                        and protection.session_generation == current_generation
                    )
                ),
                None,
            )
            outstanding = sum(
                protection.remaining + len(protection.reserved_attempt_ids)
                for protection in state.read_protections
            )
            existing_remaining = (
                0 if same_scope is None else state.read_protections[same_scope].remaining
            )
            if outstanding + count > MAX_READ_PROTECTION_COUNT:
                raise ProtocolValueError("invalid_event_value_type")
            if same_scope is not None:
                prior = state.read_protections[same_scope]
                state.read_protections[same_scope] = ReadProtection(
                    reference=prior.reference,
                    session_commitment=prior.session_commitment,
                    auth_generation=prior.auth_generation,
                    session_generation=prior.session_generation,
                    remaining=existing_remaining + count,
                    expires_at=max(prior.expires_at, effective_expiry),
                    reserved_attempt_ids=prior.reserved_attempt_ids,
                    consumed_attempt_ids=prior.consumed_attempt_ids,
                )
            else:
                if len(state.read_protections) >= MAX_READ_PROTECTIONS:
                    raise ProtocolValueError("invalid_event_value_type")
                state.read_protections.append(
                    ReadProtection(
                        reference=reference,
                        session_commitment=session_commitment,
                        auth_generation=auth_generation,
                        session_generation=current_generation,
                        remaining=count,
                        expires_at=effective_expiry,
                    )
                )
            self._save(workspace_commitment, state)
            remaining = (
                state.read_protections[same_scope].remaining if same_scope is not None else count
            )
            return JsonObject(
                {
                    "workspace_commitment": workspace_commitment,
                    "session_commitment": session_commitment,
                    "reference": reference,
                    "count": count,
                    "remaining": remaining,
                    "expires_at": effective_expiry.wire,
                    "session_generation": current_generation,
                    "protected": True,
                    "content_authority_changed": False,
                    "privacy_authority_changed": False,
                }
            )

    @_read_mostly
    def read_is_protected(
        self,
        workspace_commitment: str,
        session_commitment: str,
        envelope: ObservationEnvelope,
    ) -> bool:
        """Return whether one read envelope has an active explicit scope."""

        if type(envelope) is not ObservationEnvelope or envelope.event_kind not in {
            "PreToolUse",
            "preToolUse",
            "PostToolUse",
            "postToolUse",
            "PostToolUseFailure",
            "postToolUseFailure",
        }:
            return False
        try:
            validate_commitment(workspace_commitment)
            validate_commitment(session_commitment)
            attempt_id = read_protection_attempt_identity(envelope)
        except ProtocolValueError, TypeError, ValueError:
            return False
        with self._reading():
            state = self._load(workspace_commitment)
            now = self._wall_timestamp()
            prior_epoch = state.content_capture_epoch
            auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
            changed = self._prune_read_protections(
                state,
                workspace_commitment=workspace_commitment,
                now=now,
                auth_generation=auth_generation,
            )
            if state.content_capture_epoch != prior_epoch:
                changed = True
            _auth, matches = self._read_protection_candidates(
                state,
                workspace_commitment=workspace_commitment,
                session_commitment=session_commitment,
                envelope=envelope,
                now=now,
                attempt_id=attempt_id,
            )
            if not matches:
                if changed:
                    self._save(workspace_commitment, state)
                return False
            # A pre-event (and a post-only profile's post event) reserves an
            # exact native identity. This makes an out-of-order post unable
            # to consume another call's remaining slot.
            index, protection = matches[0]
            if protection.reserved(attempt_id) or protection.consumed(attempt_id):
                if changed:
                    self._save(workspace_commitment, state)
                return True
            if protection.remaining <= 0:
                if changed:
                    self._save(workspace_commitment, state)
                return False
            assert state.read_protections is not None
            state.read_protections[index] = protection.reserve(attempt_id)
            self._save(workspace_commitment, state)
            return True

    @_read_mostly
    def read_protection_reference(
        self,
        workspace_commitment: str,
        session_commitment: str,
        envelope: ObservationEnvelope,
    ) -> str | None:
        """Return the service-stored reference for one active protected read."""

        if type(envelope) is not ObservationEnvelope or envelope.event_kind not in {
            "PreToolUse",
            "preToolUse",
            "PostToolUse",
            "postToolUse",
            "PostToolUseFailure",
            "postToolUseFailure",
        }:
            return None
        try:
            validate_commitment(workspace_commitment)
            validate_commitment(session_commitment)
            attempt_id = read_protection_attempt_identity(envelope)
        except ProtocolValueError, TypeError, ValueError:
            return None
        with self._reading():
            state = self._load(workspace_commitment)
            now = self._wall_timestamp()
            prior_epoch = state.content_capture_epoch
            auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
            changed = self._prune_read_protections(
                state,
                workspace_commitment=workspace_commitment,
                now=now,
                auth_generation=auth_generation,
            )
            if state.content_capture_epoch != prior_epoch:
                changed = True
            if changed:
                self._save(workspace_commitment, state)
            _auth, matches = self._read_protection_candidates(
                state,
                workspace_commitment=workspace_commitment,
                session_commitment=session_commitment,
                envelope=envelope,
                now=now,
                attempt_id=attempt_id,
            )
            return None if not matches else matches[0][1].reference

    def consume_read_protection(
        self,
        workspace_commitment: str,
        session_commitment: str,
        envelope: ObservationEnvelope,
    ) -> bool:
        """Account one logical post exactly once; pre-events never consume."""

        if type(envelope) is not ObservationEnvelope or envelope.event_kind not in {
            "PostToolUse",
            "postToolUse",
            "PostToolUseFailure",
            "postToolUseFailure",
        }:
            return False
        try:
            validate_commitment(workspace_commitment)
            validate_commitment(session_commitment)
            attempt_id = read_protection_attempt_identity(envelope)
        except ProtocolValueError, TypeError, ValueError:
            return False
        with self._lock:
            state = self._load(workspace_commitment)
            now = self._wall_timestamp()
            prior_epoch = state.content_capture_epoch
            auth_generation = self._read_protection_auth_generation(workspace_commitment, state)
            changed = self._prune_read_protections(
                state,
                workspace_commitment=workspace_commitment,
                now=now,
                auth_generation=auth_generation,
            )
            if state.content_capture_epoch != prior_epoch:
                changed = True
            _auth, matches = self._read_protection_candidates(
                state,
                workspace_commitment=workspace_commitment,
                session_commitment=session_commitment,
                envelope=envelope,
                now=now,
                attempt_id=attempt_id,
            )
            # An exact retry of a previously consumed post is a no-op. Check
            # exhausted rows too, since their identity remains until expiry.
            if auth_generation is not None:
                current_generation = self._read_protection_generation(state, session_commitment)
                for protection in state.read_protections or ():
                    if (
                        protection.session_commitment == session_commitment
                        and protection.auth_generation == auth_generation
                        and protection.session_generation == current_generation
                        and protection.consumed(attempt_id)
                    ):
                        if changed:
                            self._save(workspace_commitment, state)
                        return False
            if not matches:
                if changed:
                    self._save(workspace_commitment, state)
                return False
            index, protection = matches[0]
            assert state.read_protections is not None
            state.read_protections[index] = protection.consume(attempt_id)
            self._save(workspace_commitment, state)
            return True

    def session_selection_setting(
        self,
        workspace_commitment: str,
        session_commitment: str,
        *,
        now: Timestamp | None = None,
    ) -> ObservationSelectionSetting | None:
        """Return one active temporary override, expiring it when necessary."""

        return self.selection_settings_for(workspace_commitment, now=now).session(
            session_commitment
        )

    def resolve_selection(
        self,
        workspace_commitment: str,
        *,
        session_commitment: str | None = None,
        configured: ObservationSelection | None = None,
        now: Timestamp | None = None,
    ) -> ObservationSelectionResolution:
        """Resolve active session > workspace > configured > Focused/512.

        The returned value is a pure selection projection.  It contains no
        content authority and does not inspect or change privacy policy.
        ``selection_settings_for`` performs any required expiry cleanup under
        the owner-private store lock before this resolution.
        """

        settings = self.selection_settings_for(workspace_commitment, now=now)
        return resolve_observation_selection(
            settings,
            session_commitment=session_commitment,
            configured=DEFAULT_OBSERVATION_SELECTION if configured is None else configured,
            now=now,
        )

    def _selection_setting(
        self,
        selection: ObservationSelection,
        *,
        expires_at: Timestamp | None,
        set_at: Timestamp | None,
    ) -> ObservationSelectionSetting:
        if type(selection) is not ObservationSelection:
            raise ProtocolValueError("invalid_event_value_type")
        stamp = set_at if set_at is not None else self._wall_timestamp()
        try:
            setting = ObservationSelectionSetting(selection, stamp, expires_at)
        except ProtocolValueError, TypeError, ValueError:
            raise
        if setting.expired(stamp):
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation selection expiry must be in the future.",
                retryable=False,
            )
        return setting

    @staticmethod
    def _prune_selection_settings(
        settings: ObservationSelectionSettings,
        now: Timestamp,
    ) -> ObservationSelectionSettings:
        if type(settings) is not ObservationSelectionSettings or type(now) is not Timestamp:
            raise ProtocolValueError("invalid_event_value_type")
        workspace = settings.workspace
        if workspace is not None and workspace.expired(now):
            workspace = None
        sessions = tuple(
            (key, setting) for key, setting in settings.sessions if not setting.expired(now)
        )
        if workspace == settings.workspace and sessions == settings.sessions:
            return settings
        return ObservationSelectionSettings(workspace=workspace, sessions=sessions)

    def _bind_session_state(
        self, workspace_commitment: str, state: _WorkspaceState, session_commitment: str
    ) -> None:
        """Bind one commitment in an already-held workspace state."""

        if state.consent is None:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation consent is missing.",
                retryable=False,
            )
        owners = self._session_workspace_owners_unlocked(session_commitment)
        if owners - {workspace_commitment}:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation session is already bound.",
                retryable=False,
            )
        assert state.session_workspaces is not None
        existing = state.session_workspaces.get(session_commitment)
        if existing is not None and existing != workspace_commitment:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation session is already bound.",
                retryable=False,
            )
        state.session_workspaces[session_commitment] = workspace_commitment

    def bind_session(self, workspace_commitment: str, session_commitment: str) -> None:
        with self._lock:
            state = self._load(workspace_commitment)
            self._bind_session_state(workspace_commitment, state, session_commitment)
            self._save(workspace_commitment, state)

    def begin_session_generation(self, workspace_commitment: str, session_commitment: str) -> int:
        """Advance the durable generation and clear only the prior stopped fence."""

        with self._lock:
            state = self._load(workspace_commitment)
            generation = self._begin_session_generation_state(state, session_commitment)
            self._prune_open_pre(state, self._wall_timestamp())
            self._save(workspace_commitment, state)
            return generation

    @staticmethod
    def _begin_session_generation_state(state: _WorkspaceState, session_commitment: str) -> int:
        """Advance one generation in an already-held workspace state."""

        assert state.session_generations is not None
        assert state.ended_session_generations is not None
        assert state.ended_sessions is not None
        generation = state.session_generations.get(session_commitment, 0) + 1
        state.session_generations[session_commitment] = generation
        state.ended_session_generations.pop(session_commitment, None)
        state.ended_sessions.discard(session_commitment)
        if state.pressure_snapshots is not None:
            state.pressure_snapshots.pop(session_commitment, None)
        if state.read_protections is not None:
            state.read_protections[:] = [
                protection
                for protection in state.read_protections
                if protection.session_commitment != session_commitment
            ]
        assert state.stream_partial_dropped_sessions is not None
        state.stream_partial_dropped_sessions.discard(session_commitment)
        state.stream_partial_dropped_sessions.discard(_LEGACY_STREAM_PARTIAL_DROPPED_SESSION)
        if not state.stream_partial_dropped_sessions:
            LocalObservationStore._resolve_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
        return generation

    @_read_mostly
    def current_session_generation(self, workspace_commitment: str, session_commitment: str) -> int:
        with self._reading():
            state = self._load(workspace_commitment)
            assert state.session_generations is not None
            return state.session_generations.get(session_commitment, 1)

    @_read_mostly
    def persisted_session_generation(
        self, workspace_commitment: str, session_commitment: str
    ) -> int:
        """Return the stored counter, preserving zero for legacy state.

        ``current_session_generation`` is the public event-stamping view and
        therefore presents a pre-counter binding as generation one. Lifecycle
        reconciliation needs the persisted counter itself so a deferred first
        start can materialize generation one exactly once instead of advancing
        a legacy ended binding to generation two.
        """

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.session_generations is not None
            return state.session_generations.get(session_commitment, 0)

    def note_session_end(
        self,
        workspace_commitment: str,
        session_commitment: str,
        *,
        generation: int | None = None,
    ) -> None:
        """Persist that a bound Codex session ended.

        When every bound session for a workspace has ended (or consent stops),
        the lifecycle reports STOPPED rather than lingering as DEGRADED.
        """

        with self._lock:
            state = self._load(workspace_commitment)
            if self._note_session_end_state(
                state, workspace_commitment, session_commitment, generation
            ):
                self._prune_open_pre(state, self._wall_timestamp())
                self._save(workspace_commitment, state)

    @staticmethod
    def _note_session_end_state(
        state: _WorkspaceState,
        workspace_commitment: str,
        session_commitment: str,
        generation: int | None,
    ) -> bool:
        """Apply one generation-fenced end to an already-held workspace state."""

        assert state.ended_sessions is not None
        assert state.session_generations is not None
        assert state.ended_session_generations is not None
        assert state.session_workspaces is not None
        current = state.session_generations.get(session_commitment, 1)
        observed = current if generation is None else generation
        if observed != current:
            return False
        # Retain the binding so "all bound sessions ended" is computable.
        state.session_workspaces.setdefault(session_commitment, workspace_commitment)
        state.ended_sessions.add(session_commitment)
        state.ended_session_generations[session_commitment] = observed
        if state.pressure_snapshots is not None:
            state.pressure_snapshots.pop(session_commitment, None)
        if state.read_protections is not None:
            state.read_protections[:] = [
                protection
                for protection in state.read_protections
                if protection.session_commitment != session_commitment
            ]
        settings = state.selection_settings or ObservationSelectionSettings()
        cleared_settings = settings.without_session(session_commitment)
        if cleared_settings != settings:
            # Session overrides are temporary by default.  Ending a session is
            # the durable reverse path; a workspace default remains intact.
            state.selection_settings = cleared_settings
        assert state.stream_partial_dropped_sessions is not None
        state.stream_partial_dropped_sessions.discard(session_commitment)
        if not state.stream_partial_dropped_sessions:
            LocalObservationStore._resolve_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
        return True

    def bind_codex_session(self, workspace_commitment: str, codex_session_id: str) -> str:
        """Bind a Codex session id to a consented workspace; return session commitment."""

        session = self.session_commitment(codex_session_id)
        with self._lock:
            state = self._load(workspace_commitment)
            assert state.codex_session_bindings is not None
            prior = _copy_state(state)
            if (
                codex_session_id not in state.codex_session_bindings
                and len(state.codex_session_bindings) >= _MAX_CODEX_SESSION_BINDINGS
            ):
                # Only the durable lifecycle/retention authority may make
                # room. It removes ended, fully drained lanes and leaves all
                # active or still-recoverable bindings untouched.
                self._prune_codex_session_bindings_state(state, set(state.codex_session_bindings))
                if len(state.codex_session_bindings) >= _MAX_CODEX_SESSION_BINDINGS:
                    _restore_state(state, prior)
                    raise _error(
                        PublicErrorCode.LIMIT_EXCEEDED,
                        "Observation session binding capacity is exhausted; end and drain a prior session before retrying.",
                        retryable=True,
                    )
            try:
                self._bind_session_state(workspace_commitment, state, session)
            except BaseException:
                _restore_state(state, prior)
                raise
            state.codex_session_bindings[codex_session_id] = session
            self._save(workspace_commitment, state)
        return session

    def reconcile_outbox_session_lifecycle(
        self,
        workspace_commitment: str,
        row: ObservationOutboxRow,
        *,
        session_lock_owned: bool = False,
    ) -> bool:
        """Converge raw session membership before one outbox row is delivered.

        A hook can capture an envelope while the workspace reservation is held by
        recovery. The row is the durable handoff containing both the raw host
        session id and its target workspace. A later hook drain or READY sweep
        binds that id under the same workspace-then-session locks before sending
        the row. Contended locks and foreign ownership return ``False`` so the
        caller leaves the row untouched for a later pass.
        """

        if type(row) is not ObservationOutboxRow:
            return False
        pending = self.list_pending_session_lifecycles(workspace_commitment, row.codex_session_id)
        if not pending and row.codex_session_id in self.codex_sessions_for_workspace(
            workspace_commitment
        ):
            # The normal mapped-session path already serialized its lifecycle
            # mutation before enqueueing. Avoid taking a second pair of locks
            # for every ordinary delivery row.
            return True
        if not self.reconcile_pending_session_lifecycles(
            workspace_commitment,
            row.codex_session_id,
            session_lock_owned=session_lock_owned,
        ):
            return False
        if self.list_pending_session_lifecycles(workspace_commitment, row.codex_session_id):
            # A foreign owner or stale target remains unresolved. Do not route
            # the row before its explicit lifecycle intent converges.
            return False
        from yoetz.adapters.integrations.codex_lifecycle import (
            acquire_session_lock,
            acquire_workspace_recovery_lock,
        )

        try:
            with acquire_workspace_recovery_lock(
                workspace_commitment, _state=self._state_root
            ) as workspace_owned:
                if not workspace_owned:
                    return False
                session_lock = (
                    contextlib.nullcontext(True)
                    if session_lock_owned
                    else acquire_session_lock(row.codex_session_id, _state=self._state_root)
                )
                with session_lock as session_owned:
                    if not session_owned:
                        return False
                    session_commitment = self.session_commitment(row.codex_session_id)
                    known = row.codex_session_id in self.codex_sessions_for_workspace(
                        workspace_commitment
                    )
                    if not known:
                        self.bind_codex_session(workspace_commitment, row.codex_session_id)
                    current_generation = self.current_session_generation(
                        workspace_commitment, session_commitment
                    )
                    event_kind = row.envelope.event_kind
                    source_generation = row.envelope.cursor.source_generation
                    if event_kind == "SessionEnd" and (current_generation == source_generation):
                        self.note_session_end(
                            workspace_commitment,
                            session_commitment,
                            generation=source_generation,
                        )
                    elif event_kind == "SessionStart":
                        # A historical outbox Start does not prove that its
                        # lifecycle was deferred. Only explicit pending
                        # intents may advance a generation.
                        return True
                    return True
        except Exception:
            return False

    @_read_mostly
    def codex_session_ended(self, workspace_commitment: str, codex_session_id: str) -> bool:
        """Whether the bound Codex session is marked ended for its current generation.

        Drain routing consults this for ``mapping_missing`` rejections: pending outbox rows
        of a session that ended while unmapped can never deliver -- no future ``start`` will
        map an ended session -- so they get a terminal state instead of retrying forever and
        holding outbox capacity (#275). A restarted session clears the mark via
        ``begin_session_generation``.
        """

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.codex_session_bindings is not None
            assert state.ended_sessions is not None
            session = state.codex_session_bindings.get(codex_session_id)
            return session is not None and session in state.ended_sessions

    def quarantine_ended_unmapped_session(
        self,
        workspace: str,
        codex_session_id: str,
        reason: str,
    ) -> int:
        """Quarantine an ended unmapped lane only when no attach owns its lifecycle lock.

        A concurrent turn-boundary attach must win over terminalization: it may have
        received mapping_missing before persisting the mapping. Acquiring the same
        lifecycle lock closes that race; a contended lock leaves every row pending for
        the next pass, while an uncontended ended session is terminal (#275).
        """

        if not self.codex_session_ended(workspace, codex_session_id):
            return 0
        from yoetz.adapters.integrations.codex_lifecycle import acquire_session_lock

        with acquire_session_lock(codex_session_id, _state=self._state_root) as owned:
            if not owned or not self.codex_session_ended(workspace, codex_session_id):
                return 0
            return self.quarantine_outbox_session(workspace, codex_session_id, reason)

    @_read_mostly
    def find_workspace_for_codex_session(self, codex_session_id: str) -> str | None:
        with self._reading():
            owners = self._session_workspace_owners_unlocked(
                self.session_commitment(codex_session_id)
            )
            if len(owners) == 1:
                workspace = next(iter(owners))
                consent = self._load(workspace).consent
                if consent is not None and consent.active:
                    return workspace
                return None
            if owners:
                # Never select the first filesystem entry when one raw session has multiple
                # durable owners.
                return None
            # Single active consent may auto-bind later at ingest.
            active = [
                workspace
                for workspace, state in self._iter_workspaces()
                if state.consent is not None and state.consent.active
            ]
            if len(active) == 1:
                return active[0]
            return None

    @_read_mostly
    def codex_sessions_for_workspace(self, workspace_commitment: str) -> tuple[str, ...]:
        """Return the bounded structural session IDs already bound to one workspace."""

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.codex_session_bindings is not None
            return tuple(sorted(state.codex_session_bindings, key=str.encode))

    @_read_mostly
    def codex_session_workspace_owners(self, codex_session_id: str) -> frozenset[str]:
        """Return every local workspace that records one host session or derived child lane."""

        with self._reading():
            return self._session_workspace_owners_unlocked(
                self.session_commitment(codex_session_id)
            )

    @_read_mostly
    def unambiguous_codex_sessions_for_workspace(
        self, workspace_commitment: str
    ) -> tuple[str, ...]:
        """Return host session IDs recorded in this workspace and no other local workspace."""

        with self._reading():
            target = self._load(workspace_commitment)
            assert target.codex_session_bindings is not None
            return tuple(
                sorted(
                    (
                        session_id
                        for session_id, session in target.codex_session_bindings.items()
                        if self._session_workspace_owners_unlocked(session)
                        == frozenset((workspace_commitment,))
                    ),
                    key=str.encode,
                )
            )

    @_read_mostly
    def codex_session_lifecycles_for_workspace(
        self, workspace_commitment: str
    ) -> tuple[tuple[str, bool], ...]:
        """Return every bound host session id with its ended flag from one state read.

        The SessionStart recovery scan needs the ended flag of every binding in the
        workspace. Asking ``codex_session_ended`` per binding copies the whole state once
        per call outside a batch, so the scan cost grew with the binding count (#549).
        """

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.codex_session_bindings is not None
            assert state.ended_sessions is not None
            bindings = state.codex_session_bindings
            ended = state.ended_sessions
            return tuple(
                (session_id, bindings[session_id] in ended)
                for session_id in sorted(bindings, key=str.encode)
            )

    def _prune_codex_session_bindings_state(
        self,
        state: _WorkspaceState,
        requested: set[str],
    ) -> tuple[str, ...]:
        """Prune only bindings proven terminal by durable lifecycle state."""

        assert state.codex_session_bindings is not None
        assert state.ended_sessions is not None
        assert state.pending_outbox is not None
        assert state.quarantine is not None
        assert state.storage_corrupt_sessions is not None
        assert state.pending_lifecycles is not None
        bindings = state.codex_session_bindings
        busy = {row.codex_session_id for row in state.pending_outbox}
        busy.update(entry[0] for entry in state.quarantine)
        busy.update(state.storage_corrupt_sessions)
        busy.update(intent.codex_session_id for intent in state.pending_lifecycles)
        removed: list[str] = []
        for session_id in sorted(requested & bindings.keys(), key=str.encode):
            if bindings[session_id] not in state.ended_sessions or session_id in busy:
                continue
            session_commitment = bindings[session_id]
            del bindings[session_id]
            # One-shot frontier notices are keyed by host session id and are
            # only ever dropped through the binding's ended flag.
            if state.frontier_motion_notices:
                state.frontier_motion_notices.pop(session_id, None)
            if state.frontier_motion_delivered:
                state.frontier_motion_delivered.pop(session_id, None)
            # The workspace route has no work left to resolve once the raw binding is
            # removed. Keep the ended generation and replay state, but drop the live route
            # membership so stopped state and future ownership checks remain accurate.
            if not any(bound == session_commitment for bound in bindings.values()):
                assert state.session_workspaces is not None
                state.session_workspaces.pop(session_commitment, None)
                if state.stream_partial_dropped_sessions is not None:
                    state.stream_partial_dropped_sessions.discard(session_commitment)
                    if not state.stream_partial_dropped_sessions:
                        self._resolve_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            removed.append(session_id)
        return tuple(removed)

    def prune_codex_session_bindings(
        self, workspace_commitment: str, codex_session_ids: Iterable[str]
    ) -> tuple[str, ...]:
        """Drop requested bindings whose sessions are ended and fully drained (#549).

        Rule: a binding is removed only when its session is marked ended for its current
        generation, no pending outbox row and no quarantine row still names the session,
        and the session is not held as storage-corrupt. Anything else is kept whatever
        the caller asked for. The ended-unmapped quarantine path resolves a host session
        id through this map to decide that its rows are terminal, and the corruption
        repair path clears a session through it, so a binding with undrained work must
        outlive that work. A pruned session that resumes re-binds on its next hook event;
        its generation counter is keyed by commitment and retained, so the resumed
        generation continues rather than restarting. Returns the ids removed, sorted.
        """

        requested = {
            session_id for session_id in codex_session_ids if type(session_id) is str and session_id
        }
        if not requested:
            return ()
        with self._lock:
            state = self._load(workspace_commitment)
            removed = self._prune_codex_session_bindings_state(state, requested)
            if removed:
                self._save(workspace_commitment, state)
            return removed

    @_read_mostly
    def consent_for(self, workspace_commitment: str) -> LocalObservationConsent | None:
        with self._reading():
            return self._load(workspace_commitment).consent

    @_read_mostly
    def list_consented_workspaces(self) -> tuple[str, ...]:
        with self._reading():
            result = [
                workspace
                for workspace, state in self._iter_workspaces()
                if state.consent is not None
            ]
            return tuple(sorted(result, key=str.encode))

    def _prune_open_pre(self, state: _WorkspaceState, now: Timestamp) -> bool:
        """Bound missing-post bookkeeping across restarts and session fences.

        Expiry records one aggregate incomplete-pairing gap before removing
        the identity.  It never fabricates a post/failure event, and it keeps
        newer session generations independent from an older stale pre.
        """

        assert state.open_pre is not None
        if not state.open_pre:
            return False
        ended = state.ended_sessions or set()
        ended_generations = state.ended_session_generations or {}
        generations = state.session_generations or {}
        stale_keys: list[str] = []
        for key, entry in state.open_pre.items():
            stale = entry.deadline is None or entry.deadline <= now
            if entry.session_commitment is not None:
                ended_generation = ended_generations.get(entry.session_commitment)
                stale = stale or (
                    entry.session_commitment in ended
                    and (ended_generation is None or entry.source_generation == ended_generation)
                )
                current_generation = generations.get(entry.session_commitment)
                stale = stale or (
                    current_generation is not None
                    and entry.source_generation is not None
                    and entry.source_generation < current_generation
                )
            if stale:
                stale_keys.append(key)
        if not stale_keys:
            return False
        for key in stale_keys:
            del state.open_pre[key]
        self._note_gap_state(state, _PENDING_ATTEMPT_EXPIRED_GAP)
        return True

    def note_open_pre(
        self,
        workspace: str,
        correlation_id: str,
        event_kind: str,
        *,
        source: ObservationSource | None = None,
        session_commitment: str | None = None,
        source_generation: int | None = None,
        receipt_time: Timestamp | None = None,
    ) -> bool:
        """Record an open Pre event awaiting its Post.

        New hook callers provide the complete source/session/generation scope.
        The unscoped form remains readable for pre-#607 local state and tests,
        but it is never used by the shared ingress.
        """

        with self._lock:
            state = self._load(workspace)
            assert state.open_pre is not None
            now = self._wall_timestamp()
            self._prune_open_pre(state, now)
            key = (
                _pairing_key(
                    source=source,
                    session_commitment=session_commitment,
                    source_generation=source_generation,
                    correlation_id=correlation_id,
                )
                if source is not None
                and session_commitment is not None
                and source_generation is not None
                else correlation_id
            )
            if key not in state.open_pre and len(state.open_pre) >= _MAX_OPEN_PRE:
                # A pending pre is an accepted pairing identity.  Keep every
                # existing identity when this bounded map is full; callers
                # that have the envelope can attach the typed gap so the new
                # attempt remains visible without stealing an older pair.
                self._note_gap_state(state, _PENDING_ATTEMPT_LIMIT_GAP)
                self._save(workspace, state)
                return False
            if key in state.open_pre:
                # A host retry must not extend the original pending deadline.
                self._save(workspace, state)
                return True
            stamp = now if receipt_time is None else receipt_time
            state.open_pre[key] = _OpenPre(
                event_kind=event_kind.split(_OPEN_PRE_SEPARATOR, 1)[0],
                source=(
                    source
                    if source is not None
                    and session_commitment is not None
                    and source_generation is not None
                    else None
                ),
                session_commitment=(
                    session_commitment
                    if source is not None
                    and session_commitment is not None
                    and source_generation is not None
                    else None
                ),
                source_generation=(
                    source_generation
                    if source is not None
                    and session_commitment is not None
                    and source_generation is not None
                    else None
                ),
                correlation_id=correlation_id,
                receipt_time=stamp,
                deadline=_open_pre_deadline(stamp),
            )
            self._save(workspace, state)
            return True

    def consume_open_pre(
        self,
        workspace: str,
        correlation_id: str,
        *,
        source: ObservationSource | None = None,
        session_commitment: str | None = None,
        source_generation: int | None = None,
    ) -> str | None:
        with self._lock:
            state = self._load(workspace)
            assert state.open_pre is not None
            changed = self._prune_open_pre(state, self._wall_timestamp())
            key = (
                _pairing_key(
                    source=source,
                    session_commitment=session_commitment,
                    source_generation=source_generation,
                    correlation_id=correlation_id,
                )
                if source is not None
                and session_commitment is not None
                and source_generation is not None
                else correlation_id
            )
            entry = state.open_pre.pop(key, None)
            if entry is None:
                if changed:
                    self._save(workspace, state)
                return None
            self._save(workspace, state)
            return entry.event_kind

    @_read_mostly
    def has_open_pre(
        self,
        workspace: str,
        correlation_id: str,
        *,
        source: ObservationSource | None = None,
        session_commitment: str | None = None,
        source_generation: int | None = None,
    ) -> bool:
        with self._reading():
            state = self._load(workspace)
            assert state.open_pre is not None
            changed = self._prune_open_pre(state, self._wall_timestamp())
            key = (
                _pairing_key(
                    source=source,
                    session_commitment=session_commitment,
                    source_generation=source_generation,
                    correlation_id=correlation_id,
                )
                if source is not None
                and session_commitment is not None
                and source_generation is not None
                else correlation_id
            )
            result = key in state.open_pre
            if changed:
                self._save(workspace, state)
            return result

    def note_unpaired_event(
        self,
        workspace: str,
        *,
        source: ObservationSource,
        session_commitment: str,
        source_generation: int,
        source_identity: str,
    ) -> None:
        """Retain one accepted paired-profile orphan without broad resolution.

        The aggregate ``unpaired_event`` gap is intentionally append-only for
        true paired-profile orphans.  A later pair in another lane may prove
        only that lane's pairing and cannot erase this condition.
        """

        with self._lock:
            state = self._load(workspace)
            assert state.unpaired_scopes is not None
            self._note_unpaired_notice(
                state,
                source=source,
                session_commitment=session_commitment,
                source_generation=source_generation,
            )
            scope = _orphan_scope_key(
                source=source,
                session_commitment=session_commitment,
                source_generation=source_generation,
                source_identity=source_identity,
            )
            if scope not in state.unpaired_scopes:
                if len(state.unpaired_scopes) >= _MAX_UNPAIRED_SCOPES:
                    # The aggregate gap remains active even when the bounded
                    # detail set is full; never drop evidence by resolving it.
                    self._note_gap_state(state, ObservationGapCode.UNPAIRED_EVENT.value)
                    self._save(workspace, state)
                    return
                state.unpaired_scopes.add(scope)
            self._note_gap_state(state, ObservationGapCode.UNPAIRED_EVENT.value)
            self._save(workspace, state)

    @staticmethod
    def _note_unpaired_notice(
        state: _WorkspaceState,
        *,
        source: ObservationSource,
        session_commitment: str,
        source_generation: int,
    ) -> None:
        """Queue one informational notice the first time an orphan scope appears (#917).

        Repeated orphans in a known scope add nothing. When the bounded map is
        full, the oldest delivered notice is forgotten to make room; only when
        every retained notice is still undelivered is no notice queued, and the
        aggregate gap is still disclosed.
        """

        notices = state.unpaired_notices
        assert notices is not None
        lane = _unpaired_notice_lane(
            source=source,
            session_commitment=session_commitment,
            source_generation=source_generation,
        )
        if lane in notices:
            return
        if len(notices) >= _MAX_UNPAIRED_SCOPES:
            delivered = [notice for notice in notices.values() if notice.delivered]
            if not delivered:
                return
            del notices[min(delivered, key=lambda notice: (notice.ordinal, notice.lane)).lane]
        ordinal = min(_MAX_SAFE_INTEGER, max((n.ordinal for n in notices.values()), default=0) + 1)
        notices[lane] = UnpairedScopeNotice(
            lane, source.value, session_commitment, source_generation, ordinal=ordinal
        )

    @_read_mostly
    def peek_unpaired_notice(
        self, workspace: str, session_commitment: str
    ) -> UnpairedScopeNotice | None:
        """Return the oldest undelivered orphan-scope notice for one host session."""

        with self._reading():
            state = self._load(workspace)
            pending = [
                notice
                for notice in (state.unpaired_notices or {}).values()
                if notice.session_commitment == session_commitment and not notice.delivered
            ]
            return min(pending, key=lambda notice: (notice.ordinal, notice.lane), default=None)

    def commit_unpaired_notice_delivery(self, workspace: str, lane: str) -> None:
        """Mark one notice delivered after its bytes reached the host.

        A delivered notice is not repeated while the bounded map retains it.
        """

        with self._lock:
            state = self._load(workspace)
            notices = state.unpaired_notices or {}
            current = notices.get(lane)
            if current is None or current.delivered:
                return
            notices[lane] = dataclasses.replace(current, delivered=True)
            state.unpaired_notices = notices
            self._save(workspace, state)

    def set_advice_snapshot(self, workspace: str, snapshot: AdviceSnapshot | None) -> None:
        with self._lock:
            state = self._load(workspace)
            state.advice_snapshot = snapshot
            state.advice_frontier = None if snapshot is None else snapshot.freshness_frontier
            self._save(workspace, state)

    def set_session_advice_snapshot(
        self,
        workspace: str,
        *,
        yoetz_session_id: str,
        snapshot: AdviceSnapshot | None,
    ) -> None:
        with self._lock:
            state = self._load(workspace)
            if state.session_advice is None:
                state.session_advice = {}
            if snapshot is None:
                state.session_advice.pop(yoetz_session_id, None)
            else:
                state.session_advice[yoetz_session_id] = snapshot
            self._save(workspace, state)

    @_read_mostly
    def peek_advice_for_delivery(
        self,
        workspace: str,
        *,
        yoetz_session_id: str | None = None,
        allow_standing: bool = True,
        session_commitment: str | None = None,
    ) -> AdviceDelivery | None:
        """Select advice to deliver once per *condition* identity. Never mutates state.

        Pure read by construction: the caller records the delivery with
        ``commit_advice_delivery`` only after the text has actually reached the
        agent. Persisting the identity here would mean a hook killed between
        the save and the stdout write suppresses that advice permanently, which
        is strictly worse than the storm this cadence exists to stop.

        Task-scoped conditions never fall back to the workspace-wide snapshot
        (#249). A mapped Yoetz session uses its own snapshot when present;
        otherwise selection is rebuilt from the current Codex session's
        retained envelopes. The workspace snapshot may contribute only
        deliberately standing machine conditions.

        ``allow_standing=False`` withholds standing machine conditions
        (STANDING_MACHINE_ACTIONS) and falls through to the highest-ranked
        actionable item, so those conditions reach the agent only on the
        session-boundary events that opt in (#241).
        """

        from yoetz.application.observation_advice import (
            advice_delivery_identity,
            hook_advice_context,
            select_advice_item,
            select_standing_item,
        )

        with self._reading():
            state = self._load(workspace)
            snapshot = _task_scoped_delivery_snapshot(
                state,
                yoetz_session_id=yoetz_session_id,
                session_commitment=session_commitment,
            )
            item = None
            if snapshot is not None:
                if not snapshot.ranked_finding_ids:
                    snapshot = None
                else:
                    item = select_advice_item(snapshot, allow_standing=allow_standing)
                    if item is None and snapshot.ranked_items:
                        # Every ranked item on the task-scoped snapshot was
                        # cadence-gated on this event class.
                        snapshot = None
            if snapshot is None and allow_standing and state.advice_snapshot is not None:
                standing = select_standing_item(state.advice_snapshot)
                if standing is not None:
                    snapshot = state.advice_snapshot
                    item = standing
            if snapshot is None:
                return None
            identity = advice_delivery_identity(snapshot, item=item)
            scope = _advice_delivery_scope_key(
                yoetz_session_id=yoetz_session_id,
                session_commitment=session_commitment,
            )
            if type(scope) is str:
                delivered = (state.session_advice_suppression or {}).get(scope)
            else:
                delivered = state.last_advice_suppression
            if delivered == identity:
                return None
            return AdviceDelivery(
                snapshot=snapshot,
                item=item,
                delivery_identity=identity,
                text=hook_advice_context(snapshot, item=item),
            )

    def commit_advice_delivery(
        self,
        workspace: str,
        delivery_identity: str,
        *,
        yoetz_session_id: str | None = None,
        session_commitment: str | None = None,
    ) -> None:
        """Record advice as delivered — call only after the text reached the agent.

        ``last_advice_suppression`` / ``session_advice_suppression`` hold
        ``deliver-`` tokens, not the snapshot's ``suppress-`` identity. Both
        persist as unvalidated ``str | None``, so a pre-upgrade file simply
        never matches and the first hook after upgrade delivers once — no
        migration, and downgrade is symmetric. They stay single values, never a
        set: A→B→A must redeliver A.

        Mapped deliveries key suppression by Yoetz session; unmapped hook
        deliveries key it by Codex session commitment so one task cannot
        silence another (#249). Callers that pass neither still use the
        workspace-wide slot.

        A crash between the emission and this call costs at most one
        redelivery; the reverse order would cost the advice entirely.
        """

        if type(delivery_identity) is not str or not delivery_identity:
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            scope = _advice_delivery_scope_key(
                yoetz_session_id=yoetz_session_id,
                session_commitment=session_commitment,
            )
            if type(scope) is str:
                if state.session_advice_suppression is None:
                    state.session_advice_suppression = {}
                if state.session_advice_suppression.get(scope) == delivery_identity:
                    return
                state.session_advice_suppression[scope] = delivery_identity
            else:
                if state.last_advice_suppression == delivery_identity:
                    return
                state.last_advice_suppression = delivery_identity
            self._save(workspace, state)

    def note_frontier_motion(
        self,
        workspace: str,
        codex_session_id: str,
        *,
        from_sequence: int,
        to_sequence: int,
        head_digest: str,
        observation_record_count: int,
        task_id: str,
        lineage_frontier: Frontier | None = None,
    ) -> None:
        """Merge contiguous undelivered appends against the actual routed lineage."""

        candidate = FrontierMotionNotice(
            from_sequence,
            to_sequence,
            head_digest,
            observation_record_count,
            task_id,
        )
        if lineage_frontier is None:
            # Compatibility for direct local-store callers. The application
            # coordinator always supplies the actual routed head so a replayed
            # operation result cannot masquerade as the current lineage.
            lineage_frontier = Frontier(candidate.to_sequence, candidate.head_digest)
        if (
            type(lineage_frontier) is not Frontier
            or lineage_frontier.sequence < candidate.to_sequence
        ):
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.frontier_motion_notices is not None
            assert state.frontier_motion_delivered is not None
            notices = state.frontier_motion_notices
            delivered = state.frontier_motion_delivered
            mutated = False
            # The delivered mark is scoped to one task and one observed ledger
            # lineage. The actual current routed frontier distinguishes a
            # historical completed-operation replay (current head still at or
            # beyond the mark) from a same-task restore whose head fell behind
            # or diverged at the marked sequence.
            delivered_entry = delivered.get(codex_session_id)
            if delivered_entry is not None and delivered_entry.task_id != task_id:
                del delivered[codex_session_id]
                delivered_entry = None
                mutated = True
            elif delivered_entry is not None and _frontier_lineage_rewound(
                current_sequence=lineage_frontier.sequence,
                current_head_digest=lineage_frontier.head_digest,
                recorded_sequence=delivered_entry.to_sequence,
                recorded_head_digest=delivered_entry.head_digest,
            ):
                del delivered[codex_session_id]
                delivered_entry = None
                mutated = True
            elif delivered_entry is not None:
                delivered_entry = _touch_frontier_motion_delivered(
                    state,
                    codex_session_id,
                    task_id=delivered_entry.task_id,
                    to_sequence=delivered_entry.to_sequence,
                    head_digest=delivered_entry.head_digest,
                )
                mutated = True
            delivered_to = delivered_entry.to_sequence if delivered_entry is not None else 0
            prior = notices.get(codex_session_id)
            if prior is not None and prior.task_id != task_id:
                del notices[codex_session_id]
                prior = None
                mutated = True
            elif prior is not None and _frontier_lineage_rewound(
                current_sequence=lineage_frontier.sequence,
                current_head_digest=lineage_frontier.head_digest,
                recorded_sequence=prior.to_sequence,
                recorded_head_digest=prior.head_digest,
            ):
                del notices[codex_session_id]
                prior = None
                mutated = True
            if prior is not None and prior.to_sequence <= delivered_to:
                del notices[codex_session_id]
                prior = None
                mutated = True
            if candidate.to_sequence <= delivered_to:
                if mutated:
                    self._save(workspace, state)
                return
            if prior is not None and prior.to_sequence == candidate.from_sequence:
                candidate = FrontierMotionNotice(
                    prior.from_sequence,
                    candidate.to_sequence,
                    candidate.head_digest,
                    prior.observation_record_count + candidate.observation_record_count,
                    candidate.task_id,
                )
            elif prior is not None and candidate.to_sequence <= prior.to_sequence:
                if mutated:
                    self._save(workspace, state)
                return
            clamped = _clamp_frontier_motion_notice(candidate, delivered_to)
            if clamped is None:
                notices.pop(codex_session_id, None)
                self._save(workspace, state)
                return
            _touch_frontier_motion_notice(state, codex_session_id, clamped)
            self._save(workspace, state)

    @_read_mostly
    def peek_frontier_motion(
        self, workspace: str, codex_session_id: str
    ) -> FrontierMotionNotice | None:
        with self._reading():
            state = self._load(workspace)
            return (state.frontier_motion_notices or {}).get(codex_session_id)

    def commit_frontier_motion_delivery(
        self,
        workspace: str,
        codex_session_id: str,
        delivery_identity: str,
        *,
        emitted_to_sequence: int | None = None,
        emitted_task_id: str | None = None,
        emitted_head_digest: str | None = None,
    ) -> None:
        """Advance the delivered mark for the notice bytes that reached the hook consumer.

        Identity match removes that exact notice. A merge that races peek and commit
        changes identity; the peeked emitted frontier still advances high-water and
        clamps any same-task remainder so the emitted range is not re-announced.
        A queued same-task notice below the emitted frontier proves the observed
        lineage rewound after the peek: the emitted mark is not reinstalled and the
        rewind notice stays queued so the new lineage's prefix is still announced.
        """

        with self._lock:
            state = self._load(workspace)
            notices = state.frontier_motion_notices or {}
            current = notices.get(codex_session_id)
            if current is None or current.delivery_identity != delivery_identity:
                if (
                    type(emitted_to_sequence) is not int
                    or type(emitted_task_id) is not str
                    or not emitted_task_id
                    or not 0 < emitted_to_sequence <= _MAX_SAFE_INTEGER
                    or type(emitted_head_digest) is not str
                ):
                    return
                try:
                    validate_sha256_digest(emitted_head_digest)
                except ProtocolValueError:
                    return
                if (
                    current is not None
                    and current.task_id == emitted_task_id
                    and _frontier_lineage_rewound(
                        current_sequence=current.to_sequence,
                        current_head_digest=current.head_digest,
                        recorded_sequence=emitted_to_sequence,
                        recorded_head_digest=emitted_head_digest,
                    )
                ):
                    # A same-task rewind was queued between peek and commit.
                    # Writing the emitted mark would clamp the rewind notice out
                    # of existence and silently drop the new lineage's prefix.
                    return
                assert state.frontier_motion_delivered is not None
                delivered = state.frontier_motion_delivered
                previous = delivered.pop(codex_session_id, None)
                if (
                    previous is not None
                    and previous.task_id == emitted_task_id
                    and previous.to_sequence > emitted_to_sequence
                ):
                    delivered_to = previous.to_sequence
                    delivered_head_digest = previous.head_digest
                else:
                    delivered_to = emitted_to_sequence
                    delivered_head_digest = emitted_head_digest
                _touch_frontier_motion_delivered(
                    state,
                    codex_session_id,
                    task_id=emitted_task_id,
                    to_sequence=delivered_to,
                    head_digest=delivered_head_digest,
                )
                if current is not None and current.task_id == emitted_task_id:
                    clamped = _clamp_frontier_motion_notice(current, delivered_to)
                    if clamped is None:
                        notices.pop(codex_session_id, None)
                    else:
                        _touch_frontier_motion_notice(state, codex_session_id, clamped)
                self._save(workspace, state)
                return
            del notices[codex_session_id]
            assert state.frontier_motion_delivered is not None
            delivered = state.frontier_motion_delivered
            previous = delivered.pop(codex_session_id, None)
            if (
                previous is not None
                and previous.task_id == current.task_id
                and previous.to_sequence > current.to_sequence
            ):
                delivered_to = previous.to_sequence
                delivered_head_digest = previous.head_digest
            else:
                delivered_to = current.to_sequence
                delivered_head_digest = current.head_digest
            _touch_frontier_motion_delivered(
                state,
                codex_session_id,
                task_id=current.task_id,
                to_sequence=delivered_to,
                head_digest=delivered_head_digest,
            )
            self._save(workspace, state)

    @_read_mostly
    def advice_snapshot_for(self, workspace: str) -> AdviceSnapshot | None:
        """Non-consuming read of the current advice snapshot for status views."""

        with self._reading():
            return self._load(workspace).advice_snapshot

    @_read_mostly
    def list_envelopes(self, workspace: str) -> tuple[ObservationEnvelope, ...]:
        with self._reading():
            state = self._load(workspace)
            assert state.envelopes is not None
            return tuple(state.envelopes)

    def refresh_advice(
        self,
        workspace: str,
        *,
        composition: object | None = None,
        check_facts: object = (),
        inspect_fact: object | None = None,
        plan_path_digests: object = (),
        semantic_addon: object | None = None,
    ) -> AdviceSnapshot | None:
        """Recompute local (and optional AI-powered) advice from retained envelopes."""

        from yoetz.application.observation_advice import (
            ObservationAdviceBuildInput,
            ObservationAdviceSemanticAddon,
            build_observation_advice_snapshot,
        )
        from yoetz.kernel.policies.observation_advice import (
            ObservationCheckFact,
            ObservationCompositionFact,
            ObservationInspectFact,
        )

        with self._lock:
            state = self._load(workspace)
            assert state.envelopes is not None
            assert state.gaps is not None
            assert state.cursors is not None
            status = self._status_unlocked(workspace)
            typed_checks: tuple[ObservationCheckFact, ...] = ()
            if type(check_facts) is tuple:
                typed_checks = tuple(
                    item
                    for item in cast(tuple[object, ...], check_facts)
                    if type(item) is ObservationCheckFact
                )
            typed_inspect = inspect_fact if type(inspect_fact) is ObservationInspectFact else None
            typed_composition = (
                composition if type(composition) is ObservationCompositionFact else None
            )
            typed_plans: tuple[str, ...] = ()
            if type(plan_path_digests) is tuple:
                typed_plans = tuple(
                    item
                    for item in cast(tuple[object, ...], plan_path_digests)
                    if type(item) is str
                )
            typed_semantic = (
                semantic_addon if type(semantic_addon) is ObservationAdviceSemanticAddon else None
            )
            snapshot = build_observation_advice_snapshot(
                ObservationAdviceBuildInput(
                    envelopes=tuple(state.envelopes),
                    lifecycle=status.lifecycle,
                    gaps=status.gaps,
                    check_facts=typed_checks,
                    inspect_fact=typed_inspect,
                    composition=typed_composition,
                    plan_path_digests=typed_plans,
                    prior_snapshot=state.advice_snapshot,
                    semantic_addon=typed_semantic,
                    # Selected routine diagnostics may have been reclaimed
                    # after their exact account became durable in the
                    # admission buffer/outbox. A cursor still proves that a
                    # source contributed an accepted observation, even when
                    # no secondary envelope cache remains for it.
                    has_real_observation=bool(state.envelopes) or bool(state.cursors),
                )
            )
            if snapshot is not state.advice_snapshot:
                # build_observation_advice_snapshot returns the prior object
                # unchanged when nothing moved; rewriting it cost ~91 ms of
                # encode plus an fsync on every suppressed hook (#242). The
                # pruning `_save` drives still runs: a hook flushes its batch
                # exactly once regardless of this branch.
                state.advice_snapshot = snapshot
                state.advice_frontier = None if snapshot is None else snapshot.freshness_frontier
                self._save(workspace, state)
            return snapshot

    @_read_mostly
    def get_stream_cursor(
        self, workspace: str, session_commitment: str
    ) -> ObservationCursor | None:
        with self._reading():
            state = self._load(workspace)
            assert state.stream_cursors is not None
            return state.stream_cursors.get(session_commitment)

    def set_stream_cursor(
        self, workspace: str, session_commitment: str, cursor: ObservationCursor
    ) -> None:
        with self._lock:
            state = self._load(workspace)
            assert state.stream_cursors is not None
            state.stream_cursors[session_commitment] = cursor
            self._save(workspace, state)

    @_read_mostly
    def stream_call_tools_for_session(
        self,
        workspace: str,
        session_commitment: str,
        *,
        source_generation: int,
    ) -> dict[str, str]:
        with self._reading():
            state = self._load(workspace)
            assert state.stream_call_tools is not None
            assert state.stream_call_tool_generations is not None
            if state.stream_call_tool_generations.get(session_commitment) != source_generation:
                return {}
            return dict(state.stream_call_tools.get(session_commitment, {}))

    def replace_stream_call_tools(
        self,
        workspace: str,
        session_commitment: str,
        *,
        source_generation: int,
        call_tools: Mapping[str, str],
    ) -> None:
        if type(source_generation) is not int or source_generation < 1:
            raise ProtocolValueError("invalid_event_value_type")
        clean: dict[str, str] = {}
        for call_id, tool_name in call_tools.items():
            if (
                type(call_id) is not str
                or type(tool_name) is not str
                or not call_id
                or not tool_name
                or len(call_id) > 128
                or len(tool_name) > 128
            ):
                raise ProtocolValueError("invalid_event_value_type")
            if len(clean) >= _MAX_STREAM_CALL_TOOLS:
                break
            clean[call_id] = tool_name
        with self._lock:
            state = self._load(workspace)
            assert state.stream_call_tools is not None
            assert state.stream_call_tool_generations is not None
            state.stream_call_tools.pop(session_commitment, None)
            state.stream_call_tool_generations.pop(session_commitment, None)
            retained = sum(len(tools) for tools in state.stream_call_tools.values())
            while retained + len(clean) > _MAX_STREAM_CALL_TOOLS and state.stream_call_tools:
                oldest_session = next(iter(state.stream_call_tools))
                oldest_tools = state.stream_call_tools[oldest_session]
                oldest_tools.pop(next(iter(oldest_tools)))
                retained -= 1
                if not oldest_tools:
                    del state.stream_call_tools[oldest_session]
                    state.stream_call_tool_generations.pop(oldest_session, None)
            if clean:
                state.stream_call_tools[session_commitment] = clean
                state.stream_call_tool_generations[session_commitment] = source_generation
            self._save(workspace, state)

    @_read_mostly
    def stream_source_identity_for_session(
        self, workspace: str, session_commitment: str
    ) -> str | None:
        with self._reading():
            state = self._load(workspace)
            assert state.stream_source_identities is not None
            return state.stream_source_identities.get(session_commitment)

    def set_stream_source_identity(
        self,
        workspace: str,
        session_commitment: str,
        source_identity: str | None,
    ) -> None:
        if source_identity is not None and (
            type(source_identity) is not str
            or not source_identity.startswith("hmac-sha256:")
            or len(source_identity) != 76
        ):
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.stream_source_identities is not None
            if source_identity is None:
                state.stream_source_identities.pop(session_commitment, None)
            else:
                state.stream_source_identities[session_commitment] = source_identity
            self._save(workspace, state)

    @_read_mostly
    def stream_profile_for_session(self, workspace: str, session_commitment: str) -> str | None:
        """Return the exact rollout profile id the session's current generation admitted."""

        with self._reading():
            state = self._load(workspace)
            assert state.stream_profiles is not None
            return state.stream_profiles.get(session_commitment)

    def set_stream_profile(
        self,
        workspace: str,
        session_commitment: str,
        profile_id: str | None,
    ) -> None:
        if not _stream_profile_id_valid(profile_id):
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.stream_profiles is not None
            if profile_id is None:
                state.stream_profiles.pop(session_commitment, None)
            else:
                state.stream_profiles[session_commitment] = profile_id
            self._save(workspace, state)

    def set_stream_reconcile_state(
        self,
        workspace: str,
        session_commitment: str,
        *,
        cursor: ObservationCursor,
        partial: bytes,
        call_tools: Mapping[str, str],
        source_identity: str | None,
        profile_id: str | None = None,
    ) -> None:
        """Atomically persist one replay-safe session-stream progress frontier."""

        if type(cursor) is not ObservationCursor or type(partial) is not bytes:
            raise ProtocolValueError("invalid_event_value_type")
        if source_identity is not None and (
            type(source_identity) is not str
            or not source_identity.startswith("hmac-sha256:")
            or len(source_identity) != 76
            or any(char not in "0123456789abcdef" for char in source_identity[12:])
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if not _stream_profile_id_valid(profile_id):
            raise ProtocolValueError("invalid_event_value_type")
        clean: dict[str, str] = {}
        for call_id, tool_name in call_tools.items():
            if (
                type(call_id) is not str
                or type(tool_name) is not str
                or not call_id
                or not tool_name
                or len(call_id) > 128
                or len(tool_name) > 128
            ):
                raise ProtocolValueError("invalid_event_value_type")
            if len(clean) >= _MAX_STREAM_CALL_TOOLS:
                break
            clean[call_id] = tool_name
        with self._lock:
            state = self._load(workspace)
            assert state.stream_cursors is not None
            assert state.stream_partials is not None
            assert state.stream_partial_dropped_sessions is not None
            assert state.stream_call_tools is not None
            assert state.stream_call_tool_generations is not None
            assert state.stream_source_identities is not None
            assert state.stream_profiles is not None
            state.stream_cursors[session_commitment] = cursor
            if len(partial) > _MAX_STREAM_PARTIAL_BYTES:
                state.stream_partials.pop(session_commitment, None)
                state.stream_partial_dropped_sessions.add(session_commitment)
                self._note_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            elif partial:
                state.stream_partials[session_commitment] = partial
                state.stream_partial_dropped_sessions.discard(session_commitment)
            else:
                state.stream_partials.pop(session_commitment, None)
                state.stream_partial_dropped_sessions.discard(session_commitment)
            if not state.stream_partial_dropped_sessions:
                self._resolve_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            state.stream_call_tools.pop(session_commitment, None)
            state.stream_call_tool_generations.pop(session_commitment, None)
            retained = sum(len(tools) for tools in state.stream_call_tools.values())
            while retained + len(clean) > _MAX_STREAM_CALL_TOOLS and state.stream_call_tools:
                oldest_session = next(iter(state.stream_call_tools))
                oldest_tools = state.stream_call_tools[oldest_session]
                oldest_tools.pop(next(iter(oldest_tools)))
                retained -= 1
                if not oldest_tools:
                    del state.stream_call_tools[oldest_session]
                    state.stream_call_tool_generations.pop(oldest_session, None)
            if clean:
                state.stream_call_tools[session_commitment] = clean
                state.stream_call_tool_generations[session_commitment] = cursor.source_generation
            if source_identity is None:
                state.stream_source_identities.pop(session_commitment, None)
            else:
                state.stream_source_identities[session_commitment] = source_identity
            if profile_id is None:
                state.stream_profiles.pop(session_commitment, None)
            else:
                state.stream_profiles[session_commitment] = profile_id
            self._save(workspace, state)

    @_read_mostly
    def get_stream_partial(self, workspace: str, session_commitment: str) -> bytes:
        with self._reading():
            state = self._load(workspace)
            assert state.stream_partials is not None
            return state.stream_partials.get(session_commitment, b"")

    def set_stream_partial(self, workspace: str, session_commitment: str, partial: bytes) -> None:
        if type(partial) is not bytes:
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.stream_partials is not None
            assert state.stream_partial_dropped_sessions is not None
            if len(partial) > _MAX_STREAM_PARTIAL_BYTES:
                # An oversized tail drops with an explicit gap instead of
                # pinning megabytes of read-cache in the state file: the
                # reader rereads it from the committed cursor on the next
                # reconcile (#289). Raising here instead stalled the stream
                # forever while retaining the partial that caused the stall.
                state.stream_partials.pop(session_commitment, None)
                state.stream_partial_dropped_sessions.add(session_commitment)
                self._note_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            elif partial:
                state.stream_partials[session_commitment] = partial
                state.stream_partial_dropped_sessions.discard(session_commitment)
            else:
                state.stream_partials.pop(session_commitment, None)
                state.stream_partial_dropped_sessions.discard(session_commitment)
            if not state.stream_partial_dropped_sessions:
                self._resolve_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            self._save(workspace, state)

    def note_stream_reconcile(self, workspace: str, *, mono: float | None = None) -> None:
        import time

        with self._lock:
            state = self._load(workspace)
            current = time.monotonic() if mono is None else mono
            state.last_stream_reconcile_mono_ms = int(current * 1000)
            state.monotonic_epoch = self._boot_epoch()
            self._save(workspace, state)

    @staticmethod
    def _note_codex_tool_hook(state: _WorkspaceState, session_commitment: str) -> None:
        """Count one Codex ``PreToolUse``/``PostToolUse`` hook for a host session (#917).

        Lifecycle hooks do not count: they are registered even when no tool hook
        fires. Each entry also stamps the store's tool-hook clock, which is what
        decides a code-mode cell. The bounded map forgets the least recently
        active session, never the new one; a forgotten session relearns a fresh
        stamp from its next tool hook, so an open cell still sees that hook.
        """

        assert state.codex_tool_hooks is not None
        state.codex_tool_hook_clock = min(_MAX_SAFE_INTEGER, state.codex_tool_hook_clock + 1)
        current = state.codex_tool_hooks.pop(session_commitment, _ToolHookSession(0, 0))
        state.codex_tool_hooks[session_commitment] = dataclasses.replace(
            current,
            count=min(_MAX_SAFE_INTEGER, current.count + 1),
            touched=state.codex_tool_hook_clock,
        )
        while len(state.codex_tool_hooks) > _MAX_CODEX_TOOL_HOOK_ENTRIES:
            oldest = min(state.codex_tool_hooks.items(), key=lambda item: item[1].touched)[0]
            del state.codex_tool_hooks[oldest]

    @_read_mostly
    def codex_tool_hook_count(self, workspace: str, session_commitment: str) -> int:
        """How many Codex tool hooks this store has admitted for one host session."""

        with self._reading():
            state = self._load(workspace)
            entry = (state.codex_tool_hooks or {}).get(session_commitment)
            return 0 if entry is None else entry.count

    @_read_mostly
    def code_mode_pass_snapshot(self, workspace: str, session_commitment: str) -> int:
        """Return the session's latest tool-hook stamp, read before a stream pass reads (#917)."""

        with self._reading():
            state = self._load(workspace)
            entry = (state.codex_tool_hooks or {}).get(session_commitment)
            return 0 if entry is None else entry.touched

    def settle_code_mode_pass(self, workspace: str, session_commitment: str, snapshot: int) -> None:
        """Record that a stream pass started at ``snapshot`` read the rollout completely.

        Every tool hook up to ``snapshot`` fired before that pass read, so a
        code-mode cell whose output the pass did not see was still running when
        those hooks fired. A pass that stopped early must not call this.
        """

        with self._lock:
            state = self._load(workspace)
            hooks = state.codex_tool_hooks
            entry = None if hooks is None else hooks.get(session_commitment)
            if hooks is None or entry is None:
                return
            settled = min(snapshot, entry.touched)
            if settled <= entry.settled:
                return
            hooks[session_commitment] = dataclasses.replace(entry, settled=settled)
            self._save(workspace, state)

    def begin_code_mode_cell(self, workspace: str, session_commitment: str, call_id: str) -> bool:
        """Note that the stream read a code-mode ``exec`` cell's call; return whether to hold it.

        The call is always held (kept local): whether the cell's nested calls
        are hook-recorded is only known once its output is read, and an early
        answer from the session's past would be irreversible. The read position
        is durable and replayed unchanged (#917).
        """

        with self._lock:
            state = self._load(workspace)
            assert state.code_mode_cells is not None
            key = _code_mode_cell_key(session_commitment, call_id)
            if key in state.code_mode_cells:
                return True
            self._remember_code_mode_cell(
                state, key, _CodeModeCell(state.codex_tool_hook_clock, None, 0)
            )
            self._save(workspace, state)
            return True

    def finish_code_mode_cell(self, workspace: str, session_commitment: str, call_id: str) -> bool:
        """Return whether a code-mode cell's output stays local (#917).

        It stays local only when a Codex tool hook of this session was ingested
        after the stream read the cell's call and has since been settled by a
        complete stream pass that did not see the output: that hook fired while
        the cell ran, so the nested hook rows are the cell's record. Otherwise
        the output is delivered and records the cell; a hook that may belong to
        a later cell never removes this cell's record. An output whose call was
        never noted is delivered.
        """

        with self._lock:
            state = self._load(workspace)
            assert state.code_mode_cells is not None
            key = _code_mode_cell_key(session_commitment, call_id)
            current = state.code_mode_cells.get(key)
            if current is None:
                return False
            if current.output_local is not None:
                return current.output_local
            entry = (state.codex_tool_hooks or {}).get(session_commitment)
            local = entry is not None and entry.settled > current.hook_clock_at_start
            self._remember_code_mode_cell(
                state, key, dataclasses.replace(current, output_local=local)
            )
            self._save(workspace, state)
            return local

    def note_pending_rollout_item(
        self,
        workspace: str,
        session_commitment: str,
        codex_session_id: str,
        envelope: ObservationEnvelope,
    ) -> None:
        """Remember a rollout tool item read before any hook post it pairs with (#910).

        The item stays in the local store only until a later hook post of the same
        session, or the turn's end, decides it: the stream reconciler then delivers
        it once when it is the only carrier of a call's outcome, or settles it as a
        copy. Past a hard bound the oldest item is dropped and ``unpaired_event``
        recorded for its session; the reconciler's soft bound normally delivers it
        first.
        """

        if (
            not _pending_rollout_item_token(session_commitment)
            or not _pending_rollout_item_token(codex_session_id)
            or type(envelope) is not ObservationEnvelope
            or envelope.session_commitment != session_commitment
            or not _pending_rollout_item_token(envelope.source_identity)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.pending_rollout_items is not None
            identity = envelope.source_identity
            state.codex_tool_hook_clock = min(_MAX_SAFE_INTEGER, state.codex_tool_hook_clock + 1)
            state.pending_rollout_items.pop(identity, None)
            state.pending_rollout_items[identity] = PendingRolloutItem(
                session_commitment,
                codex_session_id,
                envelope,
                state.codex_tool_hook_clock,
                0,
                self._pending_rollout_activity(state, session_commitment),
            )
            while len(state.pending_rollout_items) > _MAX_PENDING_ROLLOUT_ITEMS_HARD:
                oldest = min(state.pending_rollout_items.values(), key=lambda item: item.touched)
                del state.pending_rollout_items[oldest.source_identity]
                self._note_gap_state(state, ObservationGapCode.UNPAIRED_EVENT.value)
                self._note_session_gap_state(
                    state, oldest.session_commitment, ObservationGapCode.UNPAIRED_EVENT.value
                )
            self._save(workspace, state)

    @_read_mostly
    def pending_rollout_items(
        self, workspace: str, session_commitment: str | None = None
    ) -> tuple[PendingRolloutItem, ...]:
        """Undecided rollout tool items, oldest first; one session's, or all when ``None``."""

        with self._reading():
            state = self._load(workspace)
            return tuple(
                item
                for item in sorted(
                    (state.pending_rollout_items or {}).values(), key=lambda item: item.touched
                )
                if session_commitment is None or item.session_commitment == session_commitment
            )

    @staticmethod
    def _note_evicted_tool_call(state: _WorkspaceState, evicted: ObservationEnvelope) -> None:
        """Keep the open state of a Codex tool call whose hook row leaves the ring (#910).

        An evicted ``PreToolUse`` leaves its call open for the rollout pairing replay, so a
        parallel same-command run is not taken for finished; an evicted ``PostToolUse`` closes
        it, since every later row the replay still holds follows that post.
        """

        if evicted.source is not ObservationSource.CODEX_HOOK:
            return
        assert state.evicted_open_calls is not None
        call_id = evicted.structural_payload.get("tool_call_id")
        if not _pending_rollout_item_token(call_id):
            return
        key = _evicted_open_call_key(evicted.session_commitment, cast(str, call_id))
        if evicted.event_kind == "PostToolUse":
            state.evicted_open_calls.pop(key, None)
            return
        commitment = evicted.structural_payload.get("command_commitment")
        if evicted.event_kind != "PreToolUse" or not _pending_rollout_item_token(commitment):
            return
        state.codex_tool_hook_clock = min(_MAX_SAFE_INTEGER, state.codex_tool_hook_clock + 1)
        state.evicted_open_calls[key] = (
            evicted.session_commitment,
            cast(str, commitment),
            cast(str, call_id),
            state.codex_tool_hook_clock,
        )
        while len(state.evicted_open_calls) > _MAX_CODEX_TOOL_HOOK_ENTRIES:
            oldest = min(state.evicted_open_calls.items(), key=lambda item: item[1][3])[0]
            del state.evicted_open_calls[oldest]

    @staticmethod
    def _forget_evicted_open_calls(state: _WorkspaceState, session_commitment: str) -> None:
        assert state.evicted_open_calls is not None
        for key, entry in tuple(state.evicted_open_calls.items()):
            if entry[0] == session_commitment:
                del state.evicted_open_calls[key]

    @_read_mostly
    def evicted_open_calls(
        self, workspace: str, session_commitment: str
    ) -> tuple[tuple[str, str], ...]:
        """``(command commitment, call id)`` of one session's calls open past the ring."""

        with self._reading():
            state = self._load(workspace)
            return tuple(
                (commitment, call_id)
                for session, commitment, call_id, _touched in sorted(
                    (state.evicted_open_calls or {}).values(), key=lambda item: item[3]
                )
                if session == session_commitment
            )

    @staticmethod
    def _pending_rollout_activity(state: _WorkspaceState, session_commitment: str) -> str:
        """A mark that changes whenever the session stores a new tool hook or stream row."""

        entry = (state.codex_tool_hooks or {}).get(session_commitment)
        hooks = 0 if entry is None else entry.count
        cursor = (state.stream_cursors or {}).get(session_commitment)
        stream = (
            "-"
            if cursor is None
            else f"{cursor.source_generation}.{cursor.byte_position}.{cursor.event_position}"
        )
        return f"{hooks}:{stream}"

    def age_pending_rollout_items(self, workspace: str) -> tuple[PendingRolloutItem, ...]:
        """Count one workspace reconcile against every undecided rollout item (#910).

        An item whose session stored a new tool hook or stream row since the last
        count starts again from zero; otherwise its idle count grows by one. Returns
        the updated items, oldest first, so the reconciler can bound a session that
        stopped (a crash, or a call that never finishes).
        """

        with self._lock:
            state = self._load(workspace)
            assert state.pending_rollout_items is not None
            if not state.pending_rollout_items:
                return ()
            for identity, item in tuple(state.pending_rollout_items.items()):
                activity = self._pending_rollout_activity(state, item.session_commitment)
                state.pending_rollout_items[identity] = dataclasses.replace(
                    item,
                    activity=activity,
                    idle_reconciles=(
                        0
                        if activity != item.activity
                        else min(_MAX_SAFE_INTEGER, item.idle_reconciles + 1)
                    ),
                )
            self._save(workspace, state)
            return tuple(
                sorted(state.pending_rollout_items.values(), key=lambda item: item.touched)
            )

    def settle_pending_rollout_item(
        self, workspace: str, session_commitment: str, source_identity: str
    ) -> None:
        """Forget one decided rollout tool item; an unknown identity is a no-op."""

        with self._lock:
            state = self._load(workspace)
            assert state.pending_rollout_items is not None
            current = state.pending_rollout_items.get(source_identity)
            if current is None or current.session_commitment != session_commitment:
                return
            del state.pending_rollout_items[source_identity]
            self._save(workspace, state)

    @staticmethod
    def _remember_code_mode_cell(state: _WorkspaceState, key: str, cell: _CodeModeCell) -> None:
        assert state.code_mode_cells is not None
        state.codex_tool_hook_clock = min(_MAX_SAFE_INTEGER, state.codex_tool_hook_clock + 1)
        state.code_mode_cells.pop(key, None)
        state.code_mode_cells[key] = dataclasses.replace(cell, touched=state.codex_tool_hook_clock)
        while len(state.code_mode_cells) > _MAX_CODEX_TOOL_HOOK_ENTRIES:
            oldest = min(state.code_mode_cells.items(), key=lambda item: item[1].touched)[0]
            del state.code_mode_cells[oldest]

    @_read_mostly
    def last_stream_reconcile_mono(self, workspace: str) -> float | None:
        with self._reading():
            value = self._load(workspace).last_stream_reconcile_mono_ms
            return None if value is None else value / 1000.0

    def allocate_hook_ordinal(self, workspace: str, session_commitment: str) -> int:
        """Allocate a durable per-session hook sequence when the host supplies no ordinal."""

        with self._lock:
            state = self._load(workspace)
            assert state.hook_sequences is not None
            hook_sequences = state.hook_sequences
            previous = hook_sequences.get(session_commitment, 0)
            state.hook_sequence_clock = max(
                state.hook_sequence_clock,
                previous,
                max(hook_sequences.values(), default=0),
            )
            next_value = min(_MAX_SAFE_INTEGER, state.hook_sequence_clock + 1)
            state.hook_sequence_clock = next_value
            # Re-touch the session so eviction follows recency while the workspace clock keeps
            # ordinals monotonic after a session is evicted and later returns.
            hook_sequences.pop(session_commitment, None)
            hook_sequences[session_commitment] = next_value
            if len(hook_sequences) > _MAX_HOOK_SEQUENCES:
                active = set(state.session_workspaces or ()) - set(state.ended_sessions or ())
                active.update(
                    session
                    for session in (state.codex_session_bindings or {}).values()
                    if session not in (state.ended_sessions or set())
                )
                candidates = [
                    session
                    for session in hook_sequences
                    if session != session_commitment and session not in active
                ]
                if not candidates:
                    candidates = [
                        session for session in hook_sequences if session != session_commitment
                    ]
                if candidates:
                    oldest = min(
                        candidates,
                        key=lambda session: (hook_sequences[session], session.encode()),
                    )
                    del hook_sequences[oldest]
            self._save(workspace, state)
            return next_value

    def _outbox_limits(
        self,
        state: _WorkspaceState,
        session_commitment: str,
    ) -> tuple[int, int]:
        """Return aggregate and selected-session row limits for one enqueue.

        The aggregate workspace queue follows the highest active owner
        selection so one explicitly larger lane can use its selected capacity.
        Admission for the current lane still follows its own resolved setting;
        a sibling's larger selection must not silently widen this session.
        """

        settings = state.selection_settings or ObservationSelectionSettings()
        now = self._wall_timestamp()
        aggregate_limit = self._aggregate_outbox_limit(state, now=now)
        resolved = resolve_observation_selection(
            settings,
            session_commitment=session_commitment,
            configured=DEFAULT_OBSERVATION_SELECTION,
            now=now,
        )
        return aggregate_limit, resolved.selection.queue_count

    def _aggregate_outbox_limit(
        self,
        state: _WorkspaceState,
        *,
        now: Timestamp | None = None,
    ) -> int:
        """Return the largest active workspace queue capacity."""

        settings = state.selection_settings or ObservationSelectionSettings()
        stamp = self._wall_timestamp() if now is None else now
        capacity = settings.aggregate_capacity(now=stamp)
        return (
            _MAX_OUTBOX
            if capacity.profile is CapacityProfile.STANDARD
            else BudgetLimits.for_capacity(capacity).queue_count
        )

    def _state_byte_limit(
        self,
        workspace_commitment: str,
        state: _WorkspaceState,
        *,
        required: int | None = None,
    ) -> int:
        """Return the active state bound while preserving prior larger occupancy.

        A capacity override may be lowered while rows accepted under a larger
        profile are still pending.  The existing file size is the durable
        occupancy ceiling for that drain, capped by the largest supported
        profile.  Small standard-profile files continue to honor the historic
        ``_MAX_STATE_BYTES`` test/deployment seam, so a temporary pressure cap
        can still exercise the standard retention ladder.

        ``required`` is the size of the state a caller is about to write.  When
        it does not fit and the accepted queue is over its selected target, the
        bound becomes :meth:`_over_target_state_limit`, so a refused event or a
        lifecycle transition is still recorded (#843).  The cheaper bound is
        returned whenever the write already fits.
        """

        settings = state.selection_settings or ObservationSelectionSettings()
        now = self._wall_timestamp()
        capacity = settings.aggregate_capacity(now=now)
        selected = (
            _MAX_STATE_BYTES
            if capacity.profile is CapacityProfile.STANDARD
            else BudgetLimits.for_capacity(capacity).state_bytes
        )
        limit = selected
        path = self._workspace_path(workspace_commitment)
        current_size = 0
        key = self._stat_key(path)
        if key is not None:
            current_size = key[1]
        if current_size > _DEFAULT_STATE_BYTES and current_size > selected:
            limit = current_size
        if required is not None and required > limit:
            limit = max(
                limit,
                self._over_target_state_limit(state, capacity, selected, now=now),
            )
        return min(_MAX_EXPANDED_STATE_BYTES, max(1, limit))

    def _over_target_state_limit(
        self,
        state: _WorkspaceState,
        capacity: ObservationCapacity,
        selected_state_bytes: int,
        *,
        now: Timestamp,
    ) -> int:
        """Return the finite bound for accepted rows above a lowered selection.

        Accepted rows are never deleted to fit a lower selection, and admission
        stops new rows while they exceed it.  The bound is the selected state
        budget, plus the persisted bytes of accepted rows beyond the selected
        queue budget, plus a fixed accounting reserve.  Loss accounting and
        lifecycle writes cannot raise it: it moves only with the accepted rows
        and shrinks as they drain.  Outside an over-target transition it is 0,
        so an ordinary full queue keeps its standard retention ladder.
        """

        rows = tuple(state.pending_outbox or ())
        buffered = tuple(state.admission_buffer.inputs)
        if not rows and not buffered:
            return 0
        queue_budget = BudgetLimits.for_capacity(capacity).queue_bytes
        # Measure in admission units first; only a queue that admission would
        # already refuse is over target.
        if len(rows) + len(buffered) <= self._aggregate_outbox_limit(state, now=now):
            admitted_bytes = sum(
                _delivery_unit_bytes(row.codex_session_id, row.envelope) for row in rows
            ) + sum(_envelope_bytes(item.envelope) for item in buffered)
            if admitted_bytes <= queue_budget:
                return 0
        persisted_bytes = sum(_outbox_row_bytes(row) for row in rows)
        if buffered:
            persisted_bytes += len(
                canonical_encode(admission_buffer_to_json(state.admission_buffer))
            )
        return (
            selected_state_bytes
            + max(0, persisted_bytes - queue_budget)
            + _OVER_TARGET_ACCOUNTING_RESERVE_BYTES
        )

    def _admission_allowed(
        self,
        workspace: str,
        state: _WorkspaceState,
        envelope: ObservationEnvelope,
        candidate_queue_bytes: int,
        candidate_session_bytes: int,
        *,
        accepted_transfer: bool = False,
    ) -> bool:
        """Check count, bytes, reserves, and per-session admission."""

        return (
            self._admission_refusal(
                workspace,
                state,
                envelope,
                candidate_queue_bytes,
                candidate_session_bytes,
                accepted_transfer=accepted_transfer,
            )
            is None
        )

    def _admission_refusal(
        self,
        workspace: str,
        state: _WorkspaceState,
        envelope: ObservationEnvelope,
        candidate_queue_bytes: int,
        candidate_session_bytes: int,
        *,
        accepted_transfer: bool = False,
    ) -> AdmissionLossCause | None:
        """Return the first refusing admission dimension, or None when admitted.

        ``accepted_transfer`` is used only while flushing a previously
        accepted admission-buffer input.  Such a transfer may be over a newly
        lowered target, but it still stays below the largest finite profile
        and the local state-byte bound.  New host input always follows the
        current selection and cannot use this escape hatch.
        """

        now = self._wall_timestamp()
        settings = state.selection_settings or ObservationSelectionSettings()
        aggregate_capacity = settings.aggregate_capacity(now=now)
        limits = BudgetLimits.for_capacity(
            ObservationCapacity(LARGEST_SUPPORTED_QUEUE_COUNT)
            if accepted_transfer
            else aggregate_capacity
        )
        aggregate_limit = (
            limits.queue_count
            if accepted_transfer
            else self._aggregate_outbox_limit(state, now=now)
        )
        resolved = resolve_observation_selection(
            settings,
            session_commitment=envelope.session_commitment,
            configured=DEFAULT_OBSERVATION_SELECTION,
            now=now,
        )
        session_limit = resolved.selection.queue_count
        session_limits = BudgetLimits.for_capacity(resolved.selection.capacity)
        usage = self._selection_pressure_usage(
            workspace,
            state,
            envelope.session_commitment,
            limits,
            now,
            # State bytes have their own selected/current occupancy check
            # below. Avoid a second whole-state encode in this hot path.
            state_bytes=0,
        )
        projected_count = usage.queue_count + 1
        projected_bytes = usage.queue_bytes + candidate_queue_bytes
        protected = _outbox_row_is_protected(envelope)
        if projected_count > aggregate_limit:
            return AdmissionLossCause.QUEUE_COUNT
        if projected_bytes > limits.queue_bytes:
            return AdmissionLossCause.QUEUE_BYTES
        if not accepted_transfer:
            if usage.session_queue_count + 1 > session_limit:
                return AdmissionLossCause.SESSION_QUEUE_COUNT
            if usage.session_queue_bytes + candidate_session_bytes > session_limits.queue_bytes:
                return AdmissionLossCause.SESSION_QUEUE_BYTES
            if not protected:
                count_remaining = max(0, limits.protected_count - usage.protected_count)
                bytes_remaining = max(0, limits.protected_bytes - usage.protected_bytes)
                if projected_count > aggregate_limit - count_remaining:
                    return AdmissionLossCause.PROTECTED_RESERVE
                if projected_bytes > limits.queue_bytes - bytes_remaining:
                    return AdmissionLossCause.PROTECTED_RESERVE
                if usage.session_queue_count + 1 > limits.session_fair_share:
                    return AdmissionLossCause.SESSION_FAIR_SHARE
                if (
                    usage.session_queue_bytes + candidate_session_bytes
                    > limits.session_fair_share_bytes
                ):
                    return AdmissionLossCause.SESSION_FAIR_SHARE
        return None

    def _outbox_admission_allowed(
        self,
        workspace: str,
        state: _WorkspaceState,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        *,
        accepted_transfer: bool = False,
    ) -> bool:
        """Check one pending outbox row against the active budget."""

        return (
            self._outbox_admission_refusal(
                workspace,
                state,
                codex_session_id,
                envelope,
                accepted_transfer=accepted_transfer,
            )
            is None
        )

    def _outbox_admission_refusal(
        self,
        workspace: str,
        state: _WorkspaceState,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        *,
        accepted_transfer: bool = False,
    ) -> AdmissionLossCause | None:
        return self._admission_refusal(
            workspace,
            state,
            envelope,
            _delivery_unit_bytes(codex_session_id, envelope),
            _envelope_bytes(envelope),
            accepted_transfer=accepted_transfer,
        )

    def _buffer_admission_refusal(
        self,
        workspace: str,
        state: _WorkspaceState,
        envelope: ObservationEnvelope,
    ) -> AdmissionLossCause | None:
        """Check one newly buffered input before it becomes durable state."""

        envelope_bytes = _envelope_bytes(envelope)
        return self._admission_refusal(
            workspace,
            state,
            envelope,
            envelope_bytes,
            envelope_bytes,
        )

    def enqueue_outbox(
        self,
        workspace: str,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        *,
        accepted_transfer: bool = False,
    ) -> str | None:
        """Queue a structural envelope for service drain. Returns overflow gap or None."""

        with self._lock:
            state = self._load(workspace)
            original_state = state
            assert state.pending_outbox is not None
            assert state.gaps is not None
            reclaimed = False
            # Dedup identical source identities already pending for this session.
            for row in state.pending_outbox:
                if (
                    row.codex_session_id == codex_session_id
                    and row.envelope.source_identity == envelope.source_identity
                    and row.envelope.event_kind == envelope.event_kind
                    and row.envelope.cursor.source_generation == envelope.cursor.source_generation
                    and row.envelope.cursor.event_position == envelope.cursor.event_position
                ):
                    return None
            if len(state.pending_outbox) >= self._aggregate_outbox_limit(state):
                # Preserve strict FIFO for an existing lane. A new lane may
                # reclaim one disposable sibling row, but only after the
                # complete candidate (including quarantine detail) passes the
                # same admission and state-byte checks as a normal enqueue.
                # The speculative state keeps a rejected host event from
                # mutating an already accepted queue.
                candidate = self._fair_new_lane_outbox_candidate(
                    workspace,
                    state,
                    codex_session_id,
                    envelope,
                    accepted_transfer=accepted_transfer,
                )
                if candidate is None:
                    self._note_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
                    self._note_session_gap_state(
                        state,
                        envelope.session_commitment,
                        ObservationGapCode.OUTBOX_OVERFLOW.value,
                    )
                    self._save(workspace, state)
                    return ObservationGapCode.OUTBOX_OVERFLOW.value
                state = candidate
                reclaimed = True
            elif not self._outbox_admission_allowed(
                workspace,
                state,
                codex_session_id,
                envelope,
                accepted_transfer=accepted_transfer,
            ):
                self._note_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
                self._save(workspace, state)
                return ObservationGapCode.OUTBOX_OVERFLOW.value
            assert state.pending_outbox is not None
            if not reclaimed:
                state.pending_outbox.append(
                    ObservationOutboxRow(codex_session_id=codex_session_id, envelope=envelope)
                )
                # Resolve before projecting so the size-checked bytes are exactly
                # the bytes _save would otherwise re-encode: one encode, not three.
                self._resolve_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
            projected = self._encode_state(workspace, state)
            if len(projected) > self._state_byte_limit(workspace, state, required=len(projected)):
                if reclaimed:
                    # The speculative candidate failed the final bound. Keep
                    # the accepted queue and quarantine exactly as they were.
                    state = original_state
                elif (
                    state.pending_outbox
                    and state.pending_outbox[-1].codex_session_id == codex_session_id
                    and state.pending_outbox[-1].envelope.source_identity
                    == envelope.source_identity
                ):
                    state.pending_outbox.pop()
                self._note_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
                self._save(workspace, state)
                return ObservationGapCode.OUTBOX_OVERFLOW.value
            self._save(workspace, state, projected=projected)
            return None

    def list_pending_outbox(
        self, workspace: str, *, codex_session_id: str | None = None
    ) -> tuple[tuple[str, ObservationEnvelope], ...]:
        """Return the legacy two-field view used by existing hook/setup callers."""

        rows = self.list_pending_outbox_rows(workspace, codex_session_id=codex_session_id)
        return tuple((row.codex_session_id, row.envelope) for row in rows)

    @_read_mostly
    def selection_epoch(self, workspace: str) -> int:
        with self._reading():
            return self._load(workspace).selection_epoch

    def record_admission_loss(
        self,
        workspace: str,
        envelope: ObservationEnvelope,
        *,
        cause: AdmissionLossCause = AdmissionLossCause.UNKNOWN,
    ) -> bool:
        """Record a non-replayable rejection and aggregate its notice cadence.

        Exact endpoints and a rolling commitment survive recovery. A bounded
        range is explicitly not an exhaustive identity list; when 64 distinct
        lanes are already represented, only the aggregate commitment grows.
        The return value requests one notice, then at most one per minute of
        continuing loss. It makes no claim that the host displayed a notice.

        ``cause`` is the closed admission dimension that refused the input.
        It and the lost input's pairing commitments are kept in a separate
        per-lane detail so the wire-shaped range stays unchanged.
        """

        with self._lock:
            state = self._load(workspace)
            route = self._selection_loss_route(envelope)
            lane = canonical_digest(
                JsonObject(
                    {
                        "source": envelope.source.value,
                        "session": envelope.session_commitment,
                        "generation": envelope.cursor.source_generation,
                        "route": route,
                    }
                )
            )
            entries = list(state.selection_loss_ranges)
            index = next((i for i, entry in enumerate(entries) if entry.get("lane") == lane), None)
            previous = None if index is None else entries[index]
            # An exact native retry is not a newly lost input.
            if previous is not None and previous.get("last_identity") == envelope.source_identity:
                return False
            state.selection_rejected_count = min(
                _MAX_SAFE_INTEGER, state.selection_rejected_count + 1
            )
            state.selection_loss_commitment = canonical_digest(
                JsonObject(
                    {
                        "previous": state.selection_loss_commitment,
                        "lane": lane,
                        "identity": envelope.source_identity,
                        "cursor": observation_cursor_to_json(envelope.cursor),
                    }
                )
            )
            entry = JsonObject(
                {
                    "lane": lane,
                    "source": envelope.source.value,
                    "session": envelope.session_commitment,
                    "source_generation": envelope.cursor.source_generation,
                    "route": route,
                    "first_identity": envelope.source_identity
                    if previous is None
                    else previous["first_identity"],
                    "last_identity": envelope.source_identity,
                    "first_position": envelope.cursor.event_position
                    if previous is None
                    else previous["first_position"],
                    "last_position": envelope.cursor.event_position,
                    "count": 1
                    if previous is None
                    else min(_MAX_SAFE_INTEGER, cast(int, previous["count"]) + 1),
                    "identity_extent": "bounded_range",
                }
            )
            stored = True
            if index is not None:
                entries[index] = entry
            elif len(entries) < 64:
                entries.append(entry)
            else:
                stored = False
            state.selection_loss_ranges = tuple(entries)
            if stored:
                self._record_loss_detail(state, entry, envelope, cause)
            now_ms = int(self._wall_now() * 1000)
            previous_notice = state.selection_last_loss_notice_ms
            notice = (
                previous_notice is None
                or now_ms < previous_notice
                or now_ms - previous_notice >= 60_000
            )
            if notice:
                state.selection_last_loss_notice_ms = now_ms
                state.selection_loss_notice_pending = True
            self._note_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
            self._save(workspace, state)
            return notice

    @staticmethod
    def _selection_loss_route(envelope: ObservationEnvelope) -> JsonObject:
        structural = envelope.structural_payload
        return JsonObject(
            {
                key: structural.get(key)
                for key in (
                    "selection_task_id",
                    "selection_session_id",
                    "selection_writer_id",
                    "selection_authority_generation",
                )
            }
        )

    @_read_mostly
    def selection_history_gaps(
        self, workspace: str, envelope: ObservationEnvelope
    ) -> tuple[str, ...]:
        """Carry known routed loss into later evidence without retargeting history.

        Unrouted or evicted range detail remains visible in workspace status;
        it cannot be attributed to a later task merely because the host reused
        a session. A recovered queue never clears an exact matching history.
        """

        route = self._selection_loss_route(envelope)
        if any(value is None for value in route.values()):
            return ()
        with self._reading():
            state = self._load(workspace)
            details = _loss_details_by_lane(state)
            related: frozenset[str] | None = None
            for entry in state.selection_loss_ranges:
                if not (
                    entry.get("source") == envelope.source.value
                    and entry.get("session") == envelope.session_commitment
                    and entry.get("source_generation") == envelope.cursor.source_generation
                    and entry.get("route") == route
                ):
                    continue
                detail = details.get(cast(str, entry.get("lane")))
                pairings = _bounded_loss_pairings(entry, detail)
                if pairings is None:
                    # Legacy or overflowed lane: which later inputs the loss
                    # affected is unknown, so keep route-wide inheritance.
                    return (ObservationGapCode.OBSERVATION_INPUT_LOSS.value,)
                if related is None:
                    related = _loss_related_pairing_keys(envelope)
                if related & pairings:
                    return (ObservationGapCode.OBSERVATION_INPUT_LOSS.value,)
            return ()

    @staticmethod
    def _record_loss_detail(
        state: _WorkspaceState,
        entry: JsonObject,
        envelope: ObservationEnvelope,
        cause: AdmissionLossCause,
    ) -> None:
        """Update one lane's cause tally and bounded pairing commitments.

        Only closed cause codes and pairing digests are stored; never a host
        call id, path, command, or content.  The detail ``count`` must equal the
        range count to be trusted, so a range advanced by an older writer that
        dropped this detail falls back to route-wide inheritance.
        """

        lane = cast(str, entry["lane"])
        details = _loss_details_by_lane(state)
        previous = details.get(lane)
        count = cast(int, entry["count"])
        if previous is None and count != 1:
            # The lane existed before this detail did: its earlier losses have
            # no recorded pairing, so the lane stays route-wide.
            scope = "route"
            pairings: list[str] = []
            causes: dict[str, int] = {AdmissionLossCause.UNKNOWN.value: count - 1}
        elif previous is None:
            scope = "paired_inputs"
            pairings = []
            causes = {}
        else:
            scope = cast(str, previous["scope"])
            pairings = list(cast(tuple[str, ...], previous["pairings"]))
            causes = dict(cast(Mapping[str, int], previous["causes"]))
            if cast(int, previous["count"]) + 1 != count:
                scope = "route"
        causes[cause.value] = min(_MAX_SAFE_INTEGER, causes.get(cause.value, 0) + 1)
        own_keys = _loss_own_pairing_keys(envelope) or _loss_related_pairing_keys(envelope)
        if scope == "paired_inputs" and not own_keys:
            # A lost input that names no host call (a prompt, a session or subagent lifecycle
            # event) cannot be bounded to a pairing: every later input of the lane may depend
            # on it, so the lane stays route-wide (review of #998).
            scope = "route"
        if scope == "paired_inputs":
            for key in sorted(own_keys, key=str.encode):
                if key in pairings:
                    continue
                if len(pairings) >= _MAX_LOSS_PAIRINGS:
                    scope = "route"
                    break
                pairings.append(key)
        if scope == "route":
            pairings = []
        details[lane] = JsonObject(
            {
                "lane": lane,
                "count": count,
                "cause": cause.value,
                "causes": JsonObject(dict(sorted(causes.items()))),
                "scope": scope,
                "pairings": tuple(pairings),
            }
        )
        live = {item.get("lane") for item in state.selection_loss_ranges}
        state.selection_loss_details = tuple(
            details[key] for key in sorted(details, key=str.encode) if key in live
        )

    @_read_mostly
    def selection_loss_causes(self, workspace: str) -> tuple[JsonObject, ...]:
        """Return each retained loss lane's closed refusal causes, content-free."""

        with self._reading():
            state = self._load(workspace)
            details = _loss_details_by_lane(state)
            result: list[JsonObject] = []
            for entry in state.selection_loss_ranges:
                lane = entry.get("lane")
                if type(lane) is not str:
                    continue
                detail = details.get(lane)
                if detail is None or detail.get("count") != entry.get("count"):
                    result.append(
                        JsonObject(
                            {
                                "lane": lane,
                                "cause": AdmissionLossCause.UNKNOWN.value,
                                "inherit_scope": "route",
                            }
                        )
                    )
                    continue
                result.append(
                    JsonObject(
                        {
                            "lane": lane,
                            "cause": detail["cause"],
                            "causes": detail["causes"],
                            "inherit_scope": detail["scope"],
                        }
                    )
                )
            return tuple(result)

    @_read_mostly
    def admission_loss_cause(
        self, workspace: str, envelope: ObservationEnvelope
    ) -> AdmissionLossCause | None:
        """Return the recorded cause when ``envelope`` is its lane's latest loss."""

        with self._reading():
            state = self._load(workspace)
            details = _loss_details_by_lane(state)
            for entry in state.selection_loss_ranges:
                if entry.get("last_identity") != envelope.source_identity:
                    continue
                if entry.get("source") != envelope.source.value:
                    continue
                if entry.get("session") != envelope.session_commitment:
                    continue
                detail = details.get(cast(str, entry.get("lane")))
                if detail is None or detail.get("count") != entry.get("count"):
                    return AdmissionLossCause.UNKNOWN
                return AdmissionLossCause(cast(str, detail["cause"]))
            return None

    @_read_mostly
    def pending_selection_losses(self, workspace: str) -> tuple[JsonObject, ...]:
        """Return bounded, exactly routed historical losses awaiting durable reporting.

        Unrouted and overflow-only history stays local: a later task binding
        cannot establish which task owned an input that was already lost.
        Reporting one permanent gap per lane does not clear or reset its count.
        """

        with self._reading():
            return self._pending_selection_losses(self._load(workspace))

    @staticmethod
    def _pending_selection_losses(state: _WorkspaceState) -> tuple[JsonObject, ...]:
        result: list[JsonObject] = []
        details = _loss_details_by_lane(state)
        for item in state.selection_loss_ranges:
            try:
                loss = ObservationSelectionLoss.from_local_range_for_recovery(item)
            except ProtocolValueError, TypeError, ValueError:
                continue
            if (
                item.get("lane") in state.selection_reported_loss_lanes
                or loss.lane in state.selection_reported_loss_lanes
            ):
                continue
            # The closed refusal causes travel with the report so the durable lane marker
            # discloses them (tb4n1 B3, #998); a lane without valid detail reports `unknown`.
            detail = details.get(cast(str, item.get("lane")))
            causes: tuple[str, ...] = (
                tuple(sorted(cast(Mapping[str, int], detail["causes"])))
                if detail is not None and detail.get("count") == item.get("count")
                else (AdmissionLossCause.UNKNOWN.value,)
            )
            result.append(JsonObject({**item, "loss_causes": causes}))
        return tuple(result)

    def acknowledge_selection_loss(self, workspace: str, lane: str) -> None:
        """Acknowledge only after task history and ledger append have committed."""

        with self._lock:
            state = self._load(workspace)
            if lane in state.selection_reported_loss_lanes:
                return
            matched = False
            for item in state.selection_loss_ranges:
                if item.get("lane") == lane:
                    matched = True
                    break
                try:
                    normalized = ObservationSelectionLoss.from_local_range_for_recovery(item)
                except ProtocolValueError, TypeError, ValueError:
                    continue
                if normalized.lane == lane:
                    matched = True
                    break
            if not matched:
                return
            active_lanes: set[str] = set()
            for item in state.selection_loss_ranges:
                raw_lane = item.get("lane")
                if type(raw_lane) is str:
                    active_lanes.add(raw_lane)
            for item in state.selection_loss_ranges:
                try:
                    active_lanes.add(
                        ObservationSelectionLoss.from_local_range_for_recovery(item).lane
                    )
                except ProtocolValueError, TypeError, ValueError:
                    continue
            state.selection_reported_loss_lanes = tuple(
                sorted(
                    {*state.selection_reported_loss_lanes, lane} & active_lanes,
                    key=str.encode,
                )
            )
            self._save(workspace, state)

    @_read_mostly
    def selection_loss_workspaces(self, task_id: str | None = None) -> tuple[str, ...]:
        """Discover durable maintenance demand without requiring a host event.

        A task check supplies its authenticated task id so unrelated workspace
        lanes are excluded from the returned maintenance work after the bounded
        durable workspace discovery.
        """

        with self._reading():
            workspaces: list[str] = []
            for workspace, state in self._iter_workspaces():
                pending = self._pending_selection_losses(state)
                if task_id is None:
                    if pending:
                        workspaces.append(workspace)
                    continue
                for item in pending:
                    route = observation_selection_route(item.get("route"))
                    if route is not None and route[0] == task_id:
                        workspaces.append(workspace)
                        break
            return tuple(workspaces)

    def consume_admission_loss_notice(self, workspace: str) -> bool:
        with self._lock:
            state = self._load(workspace)
            if not state.selection_loss_notice_pending:
                return False
            state.selection_loss_notice_pending = False
            self._save(workspace, state)
            return True

    @_read_mostly
    def prepare_selected_admission(
        self,
        workspace: str,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        *,
        fence: str,
        focused: bool,
        routine_candidate: bool,
        proven_routine_success: bool,
        summary_builder: SummaryBuilder,
    ) -> AdmissionPlan:
        """Prepare admission from a held state; this operation writes nothing."""

        with self._reading():
            state = self._load(workspace)
            return plan_admission(
                state.admission_buffer,
                envelope,
                host_session=codex_session_id,
                fence=fence,
                focused=focused,
                routine_candidate=routine_candidate,
                proven_routine_success=proven_routine_success,
                now_ms=int(self._wall_now() * 1000),
                summary_builder=summary_builder,
            )

    @staticmethod
    def _buffer_input_key(item: object) -> tuple[object, ...]:
        """Return the stable identity of one already accepted buffer input."""

        envelope = getattr(item, "envelope", None)
        cursor = getattr(envelope, "cursor", None)
        return (
            getattr(item, "host_session", None),
            getattr(item, "fence", None),
            getattr(envelope, "session_commitment", None),
            getattr(getattr(envelope, "source", None), "value", None),
            getattr(envelope, "source_identity", None),
            getattr(cursor, "source_generation", None),
            getattr(cursor, "byte_position", None),
            getattr(cursor, "event_position", None),
        )

    @staticmethod
    def _pending_row_matches(
        row: ObservationOutboxRow,
        codex_session_id: str,
        envelope: ObservationEnvelope,
    ) -> bool:
        """Match the idempotency identity used by :meth:`enqueue_outbox`."""

        return (
            row.codex_session_id == codex_session_id
            and row.envelope.source_identity == envelope.source_identity
            and row.envelope.event_kind == envelope.event_kind
            and row.envelope.cursor.source_generation == envelope.cursor.source_generation
            and row.envelope.cursor.event_position == envelope.cursor.event_position
        )

    def _delivery_is_accepted_transfer(
        self,
        envelope: ObservationEnvelope,
        previous_buffer: AdmissionBuffer,
        incoming: ObservationEnvelope | None,
    ) -> bool:
        """Recognize a delivery made solely from prior accepted buffer input.

        A summary containing the current incoming envelope is a new admission,
        even when it also represents older buffered inputs.  This prevents a
        fresh host event from borrowing the over-target drain allowance.
        """

        if incoming is not None and (
            envelope.source is incoming.source
            and envelope.source_identity == incoming.source_identity
            and envelope.cursor.source_generation == incoming.cursor.source_generation
            and envelope.cursor.event_position == incoming.cursor.event_position
        ):
            return False
        prior_ids = {item.envelope.source_identity for item in previous_buffer.inputs}
        if not prior_ids:
            return False
        if envelope.event_kind == "RoutineReadSummary":
            members = envelope.structural_payload.get("members")
            if not isinstance(members, tuple) or not members:
                return False
            return all(
                isinstance(member, Mapping)
                and type(member.get("source_identity")) is str
                and member.get("source_identity") in prior_ids
                for member in members
            )
        return envelope.source_identity in prior_ids

    def _selected_admission_plan_refusal(
        self,
        workspace: str,
        state: _WorkspaceState,
        plan: AdmissionPlan,
        incoming: ObservationEnvelope | None,
    ) -> AdmissionLossCause | None:
        """Preflight a buffer transition without mutating the held state.

        The candidate starts with the old accepted inputs, removes inputs that
        the plan is about to deliver, and then admits only genuinely new buffer
        entries and deliveries.  This catches a full queue even when a plan has
        no delivery yet, while allowing accepted buffered inputs to drain after
        a selection is lowered.  Returns the refusing dimension, or None.
        """

        if incoming is not None:
            now = self._wall_timestamp()
            settings = state.selection_settings or ObservationSelectionSettings()
            limits = BudgetLimits.for_capacity(settings.aggregate_capacity(now=now))
            resolved = resolve_observation_selection(
                settings, session_commitment=incoming.session_commitment, now=now
            )
            usage = self._selection_pressure_usage(
                workspace,
                state,
                incoming.session_commitment,
                limits,
                now,
                # Exact aggregate projected bytes are checked below. This
                # gate concerns new native input; raw outbox writes also
                # carry already-accepted replay work.
                state_bytes=0,
            )
            evaluation = evaluate_pressure(
                usage, ObservationMode.from_value(resolved.selection.detail.value), limits=limits
            )
            if not evaluation.admission_allowed:
                return self._pressure_refusal_cause(state, evaluation)

        candidate = _copy_state(state)
        previous_buffer = candidate.admission_buffer
        target_keys = {self._buffer_input_key(item) for item in plan.buffer.inputs}
        retained = tuple(
            item for item in previous_buffer.inputs if self._buffer_input_key(item) in target_keys
        )
        candidate.admission_buffer = AdmissionBuffer(retained)
        retained_indexes = {
            self._buffer_input_key(item): index for index, item in enumerate(retained)
        }
        current_inputs = list(retained)
        for item in plan.buffer.inputs:
            key = self._buffer_input_key(item)
            prior_index = retained_indexes.get(key)
            if prior_index is not None:
                current_inputs[prior_index] = item
                continue
            refusal = self._buffer_admission_refusal(workspace, candidate, item.envelope)
            if refusal is not None:
                return refusal
            current_inputs.append(item)
            candidate.admission_buffer = AdmissionBuffer(tuple(current_inputs))
        candidate.admission_buffer = AdmissionBuffer(tuple(plan.buffer.inputs))
        for codex_session_id, envelope in plan.deliveries:
            if candidate.pending_outbox is None:
                return AdmissionLossCause.STATE_BYTES
            if any(
                self._pending_row_matches(row, codex_session_id, envelope)
                for row in candidate.pending_outbox
            ):
                continue
            transfer = self._delivery_is_accepted_transfer(
                envelope,
                previous_buffer,
                incoming,
            )
            refusal = self._outbox_admission_refusal(
                workspace,
                candidate,
                codex_session_id,
                envelope,
                accepted_transfer=transfer,
            )
            if refusal is not None:
                return refusal
            candidate.pending_outbox.append(
                ObservationOutboxRow(codex_session_id=codex_session_id, envelope=envelope)
            )
        encoded_size = len(self._encode_state(workspace, candidate))
        if encoded_size > self._state_byte_limit(workspace, candidate, required=encoded_size):
            return AdmissionLossCause.STATE_BYTES
        return None

    def _pressure_refusal_cause(
        self, state: _WorkspaceState, evaluation: PressureEvaluation
    ) -> AdmissionLossCause:
        """Name the hard pressure dimension that refused one native input."""

        if evaluation.dimension is PressureDimension.CAPTURE_BACKLOG:
            if self._capture_pressure_scope_unknown(state):
                return AdmissionLossCause.CAPTURE_SCOPE_UNKNOWN
            return AdmissionLossCause.PRESSURE_CAPTURE_BACKLOG
        if evaluation.dimension is PressureDimension.BYTES:
            return AdmissionLossCause.PRESSURE_BYTES
        return AdmissionLossCause.PRESSURE_COUNT

    def commit_selected_admission(
        self,
        workspace: str,
        plan: AdmissionPlan,
        *,
        incoming: ObservationEnvelope | None = None,
        newly_observed: bool = False,
        replayable: bool = False,
    ) -> bool:
        """Commit a buffer/cursor account and its deliveries in one local batch.

        Failure restores every old buffered input and outbox row. Replayable
        callers keep their source cursor at the previous accounted position.
        Non-replayable rejection is recorded separately from intentional summary.
        """

        with self.batched(workspace):
            state = self._load(workspace)
            assert state.pending_outbox is not None
            refusal = self._selected_admission_plan_refusal(
                workspace,
                state,
                plan,
                incoming,
            )
            if refusal is not None:
                if incoming is not None and not replayable and newly_observed:
                    self.record_admission_loss(workspace, incoming, cause=refusal)
                self._note_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
                self._save(workspace, state)
                return False
            state.admission_buffer = plan.buffer
            for session, envelope in plan.deliveries:
                # The complete candidate was already checked under this same
                # lock. Re-entering enqueue_outbox encoded the full state once
                # per delivery, even though no admission input could change.
                if not any(
                    self._pending_row_matches(row, session, envelope)
                    for row in state.pending_outbox
                ):
                    state.pending_outbox.append(ObservationOutboxRow(session, envelope))
            self._resolve_gap_state(state, _LOCAL_OUTBOX_OVERFLOW_GAP)
            if newly_observed:
                state.selection_admitted_count = min(
                    _MAX_SAFE_INTEGER, state.selection_admitted_count + 1
                )
            state.selection_summarized_input_count = min(
                _MAX_SAFE_INTEGER,
                state.selection_summarized_input_count
                + sum(
                    self._represented_input_count(envelope)
                    for _, envelope in plan.deliveries
                    if envelope.event_kind == "RoutineReadSummary"
                ),
            )
            state.selection_summarized_count = min(
                _MAX_SAFE_INTEGER,
                state.selection_summarized_count
                + sum(
                    envelope.event_kind == "RoutineReadSummary" for _, envelope in plan.deliveries
                ),
            )
            self._note_summary_refusals(state, plan.refusals)
            self._reclaim_optional_selection_cache(state, plan)
            self._save(workspace, state)
            return True

    def _note_summary_refusals(
        self, state: _WorkspaceState, refusals: tuple[SummaryRefusal, ...]
    ) -> None:
        """Record one bounded account per refused lane, deduplicated by member.

        The refused lane is drained by the same plan, so a repeated refusal can
        only come from a genuinely new member. That is what makes this an
        at-most-once record rather than the per-sweep exception origin line the
        daemon used to repeat every minute (issue #753).
        """

        if not refusals:
            return
        entries = list(state.selection_summary_refusals)
        known = {
            (
                entry.get("source"),
                entry.get("session"),
                entry.get("source_generation"),
                entry.get("source_identity"),
            )
            for entry in entries
        }
        observed_at = self._wall_timestamp()
        recorded = False
        for refusal in refusals:
            self._note_gap_state(state, ROUTINE_SUMMARY_INVALID_GAP)
            self._note_session_gap_state(
                state, refusal.session_commitment, ROUTINE_SUMMARY_INVALID_GAP
            )
            identity = (
                refusal.source,
                refusal.session_commitment,
                refusal.source_generation,
                refusal.source_identity,
            )
            if identity in known:
                continue
            known.add(identity)
            recorded = True
            if len(entries) >= _MAX_SUMMARY_REFUSALS:
                entries.pop(0)
            entries.append(
                JsonObject(
                    {
                        "source": refusal.source,
                        "session": refusal.session_commitment,
                        "source_generation": refusal.source_generation,
                        "source_identity": refusal.source_identity,
                        "byte_position": refusal.byte_position,
                        "event_position": refusal.event_position,
                        "last_event_position": refusal.last_event_position,
                        "input_count": refusal.input_count,
                        "reason": refusal.reason,
                        "observed_at": observed_at.wire,
                        "disposition": "admitted_individually",
                    }
                )
            )
        state.selection_summary_refusals = tuple(entries)
        if recorded:
            state.selection_summary_refusal_notice_pending = True

    @_read_mostly
    def summary_refusals(self, workspace: str) -> tuple[JsonObject, ...]:
        """Return the bounded account of every refused routine-read summary.

        This is deliberately separate from ``selection_accounting``: that
        projection's shape is frozen by the local control-result schema, while
        this is a local-only cause record read by ``observe status`` and by the
        owner's diagnostics.
        """

        with self._reading():
            return self._load(workspace).selection_summary_refusals

    def consume_summary_refusal_notice(self, workspace: str) -> bool:
        """Report a new refused summary once so one hook can name the cause."""

        with self._lock:
            state = self._load(workspace)
            if not state.selection_summary_refusal_notice_pending:
                return False
            state.selection_summary_refusal_notice_pending = False
            self._save(workspace, state)
            return True

    def flush_selected_admission(
        self,
        workspace: str,
        *,
        summary_builder: SummaryBuilder,
        force: bool = False,
        host_session: str | None = None,
        material_boundary: bool = False,
    ) -> bool:
        with self.batched(workspace):
            state = self._load(workspace)
            plan = flush_admission(
                state.admission_buffer,
                now_ms=int(self._wall_now() * 1000),
                summary_builder=summary_builder,
                force=force,
                host_session=host_session,
            )
            if not plan.deliveries:
                if material_boundary:
                    state.selection_epoch = min(_MAX_SAFE_INTEGER, state.selection_epoch + 1)
                    self._save(workspace, state)
                return True
            accepted = self.commit_selected_admission(workspace, plan)
            if accepted and material_boundary:
                state.selection_epoch = min(_MAX_SAFE_INTEGER, state.selection_epoch + 1)
                self._save(workspace, state)
            return accepted

    @_read_mostly
    def selection_accounting(self, workspace: str) -> JsonObject:
        """Read bounded retention accounting without changing pressure or state."""

        with self._reading():
            state = self._load(workspace)
            return JsonObject(
                {
                    "observed_count": state.selection_observed_count,
                    "accounting_scope": "locally_ingested_since_selection_upgrade",
                    "admitted_input_count": state.selection_admitted_count,
                    "delivered_input_count": state.selection_delivered_count,
                    "summarized_input_count": state.selection_summarized_input_count,
                    "intentionally_omitted_input_count": state.selection_omitted_count,
                    "check_selection": "reported_by_each_check",
                    "summary_record_count": state.selection_summarized_count,
                    "buffered_input_count": len(state.admission_buffer.inputs),
                    "pending_attempt_count": state.admission_buffer.pending_attempt_count,
                    "buffered_successful_call_count": state.admission_buffer.summarized_call_count,
                    "unrecoverable_input_count": state.selection_rejected_count,
                    "loss_identity_commitment": state.selection_loss_commitment,
                    "loss_ranges": state.selection_loss_ranges,
                    "loss_identity_list_complete": False,
                    "selection_epoch": state.selection_epoch,
                }
            )

    @staticmethod
    def _represented_input_count(envelope: ObservationEnvelope) -> int:
        count = envelope.structural_payload.get("input_count")
        if envelope.event_kind == "RoutineReadSummary" and type(count) is int and 1 <= count <= 32:
            return count
        return 1

    @staticmethod
    def _optional_selection_account_identities(
        envelope: ObservationEnvelope,
    ) -> set[tuple[str, str, str]]:
        """Return source identities represented by an optional durable account."""

        if envelope.event_kind == "RoutineReadSummary":
            members = envelope.structural_payload.get("members")
            if not isinstance(members, tuple):
                return set()
            return {
                (envelope.source.value, envelope.session_commitment, source_identity)
                for member in members
                if isinstance(member, Mapping)
                and type(source_identity := member.get("source_identity")) is str
            }
        if not _optional_routine_selection_envelope(envelope):
            return set()
        return {(envelope.source.value, envelope.session_commitment, envelope.source_identity)}

    def _reclaim_optional_selection_cache(
        self,
        state: _WorkspaceState,
        plan: AdmissionPlan,
    ) -> None:
        """Drop diagnostic duplicates once a selected account is durable.

        The source cursor and dedup set remain the authoritative ingest record.
        Selected inputs are accounted by the immutable admission buffer or an
        outbox summary/individual row, so keeping the full raw envelope as a
        second copy only inflates every subsequent state serialization.  The
        exact source identity stays available through that durable account;
        protected, failed, and unselected envelopes remain in the diagnostic
        cache.
        """

        assert state.envelopes is not None
        assert state.pending_outbox is not None
        assert state.quarantine is not None
        identities: set[tuple[str, str, str]] = set()
        for item in state.admission_buffer.inputs:
            identities.update(self._optional_selection_account_identities(item.envelope))
        for _, envelope in plan.deliveries:
            identities.update(self._optional_selection_account_identities(envelope))
        for row in state.pending_outbox:
            identities.update(self._optional_selection_account_identities(row.envelope))
        for _, envelope, _, _ in state.quarantine:
            identities.update(self._optional_selection_account_identities(envelope))
        if not identities:
            return
        state.envelopes[:] = [
            envelope
            for envelope in state.envelopes
            if (
                envelope.source.value,
                envelope.session_commitment,
                envelope.source_identity,
            )
            not in identities
        ]

    def note_selection_omission(self, workspace: str) -> None:
        """Count an accepted redundant self-observation after its exact dedup gate."""

        with self._lock:
            state = self._load(workspace)
            state.selection_omitted_count = min(
                _MAX_SAFE_INTEGER, state.selection_omitted_count + 1
            )
            self._save(workspace, state)

    @staticmethod
    def _merge_capture_backlog_snapshot(
        snapshot: _CaptureBacklogSnapshot,
        reservations: tuple[_CaptureReservation, ...],
    ) -> _CaptureBacklogSnapshot:
        """Add only reservations absent from a task's complete inventory.

        A legacy aggregate can predate central reservation identities. Treat
        every reservation as new when no identities were recorded; a complete
        bootstrap supplies the identities and avoids charging an already
        counted ticket twice. Reservation bytes remain an upper bound for
        identities that are present in both views.
        """

        accounted = set(snapshot.accounted_ticket_ids)
        accounted_reservations = tuple(item for item in reservations if item.ticket_id in accounted)
        extra_reservations = tuple(item for item in reservations if item.ticket_id not in accounted)
        oldest_candidates = [
            item
            for item in (
                snapshot.oldest_receipt_time,
                *(reservation.reserved_at for reservation in reservations),
            )
            if item is not None
        ]
        return dataclasses.replace(
            snapshot,
            count=max(snapshot.count, len(accounted_reservations)) + len(extra_reservations),
            # Capture backlog bytes are an aggregate and ticket identities do
            # not bind each reservation to its retained manifests. Charge all
            # reservation upper bounds additively, even for an identity the
            # inventory listed, so a legacy ticket can never hide a retry
            # growth or another ticket's bytes.
            byte_count=snapshot.byte_count + sum(item.byte_count for item in reservations),
            oldest_receipt_time=(min(oldest_candidates) if oldest_candidates else None),
        )

    @classmethod
    def _capture_backlog_usage(
        cls,
        state: _WorkspaceState,
    ) -> tuple[int, int, Timestamp | None, bool]:
        """Combine task snapshots with central reservations without double charging a route."""

        snapshots = state.capture_backlogs or {}
        reservations = state.capture_reservations or {}
        reservations_by_task: dict[str, list[_CaptureReservation]] = {}
        for reservation in reservations.values():
            reservations_by_task.setdefault(reservation.task_id, []).append(reservation)

        count = 0
        byte_count = 0
        oldest_candidates: list[Timestamp] = []
        for route_id, snapshot in snapshots.items():
            merged = cls._merge_capture_backlog_snapshot(
                snapshot, tuple(reservations_by_task.get(route_id, ()))
            )
            count += merged.count
            byte_count += merged.byte_count
            if merged.oldest_receipt_time is not None:
                oldest_candidates.append(merged.oldest_receipt_time)

        for task_id, task_reservations in reservations_by_task.items():
            if task_id in snapshots:
                continue
            count += len(task_reservations)
            byte_count += sum(item.byte_count for item in task_reservations)
            oldest_candidates.extend(item.reserved_at for item in task_reservations)

        return (
            count,
            byte_count,
            min(oldest_candidates) if oldest_candidates else None,
            state.capture_backlog_scope_unknown
            or any(item.needs_reconcile for item in reservations.values()),
        )

    def reserve_capture_ticket(
        self,
        workspace: str,
        ticket_id: str,
        task_id: str,
        byte_count: int,
    ) -> None:
        """Atomically reserve one ticket and its bounded content bytes workspace-wide.

        ``byte_count`` is an upper bound computed before encrypted object
        staging. Repeating the same ticket identity is idempotent and may only
        increase its reservation, so a changed retry cannot release capacity
        that an earlier attempt already consumed.
        """

        try:
            workspace = validate_commitment(workspace)
            ticket_id = validate_sha256_digest(ticket_id)
        except ProtocolValueError, TypeError, ValueError:
            raise ProtocolValueError("invalid_event_value_type")
        if (
            type(task_id) is not str
            or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None
            or type(byte_count) is not int
            or isinstance(byte_count, bool)
            or not 0 <= byte_count <= _MAX_CAPTURE_CONTENT_BYTES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        key = _capture_reservation_key(ticket_id, task_id)
        with self._lock:
            state = self._load(workspace)
            assert state.capture_reservations is not None
            existing = state.capture_reservations.get(key)
            if self._capture_reservation_bootstrap_required and (
                state.capture_reservation_bootstrap is None or state.capture_backlog_scope_unknown
            ):
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation capture budget scope is unknown.",
                    retryable=False,
                )
            if existing is not None:
                if existing.ticket_id != ticket_id or existing.task_id != task_id:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Observation capture reservation conflicts.",
                        retryable=False,
                    )
                if byte_count <= existing.byte_count:
                    return
                if state.capture_backlog_scope_unknown or existing.needs_reconcile:
                    raise _error(
                        PublicErrorCode.LIMIT_EXCEEDED,
                        "Observation capture budget scope is unknown.",
                        retryable=False,
                    )
                candidate = dataclasses.replace(existing, byte_count=byte_count)
            else:
                if state.capture_backlog_scope_unknown:
                    raise _error(
                        PublicErrorCode.LIMIT_EXCEEDED,
                        "Observation capture budget scope is unknown.",
                        retryable=False,
                    )
                if len(state.capture_reservations) >= _MAX_CAPTURE_TICKET_RESERVATIONS:
                    raise _error(
                        PublicErrorCode.LIMIT_EXCEEDED,
                        "Observation capture handoff capacity is exhausted.",
                        retryable=False,
                    )
                candidate = _CaptureReservation(
                    ticket_id=ticket_id,
                    task_id=task_id,
                    byte_count=byte_count,
                    reserved_at=self._wall_timestamp(),
                    needs_reconcile=True,
                )
            _current_count, _current_bytes, _oldest, unknown = self._capture_backlog_usage(state)
            if unknown and existing is None:
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation capture budget scope is unknown.",
                    retryable=False,
                )
            # Evaluate the complete proposed reservation map. Adding a delta
            # to the current aggregate would double-charge a stale task
            # snapshot that already contains this ticket's retained bytes.
            proposed_reservations = dict(state.capture_reservations)
            proposed_reservations[key] = candidate
            proposed_state = dataclasses.replace(state, capture_reservations=proposed_reservations)
            proposed_count, proposed_bytes, _oldest, _unknown = self._capture_backlog_usage(
                proposed_state
            )
            if (
                proposed_count > _MAX_CAPTURE_TICKET_RESERVATIONS
                or proposed_bytes > _MAX_CAPTURE_CONTENT_BYTES
            ):
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation captured-content byte budget is exhausted.",
                    retryable=False,
                )
            state.capture_reservations[key] = candidate
            self._save(workspace, state)

    def confirm_capture_ticket_reservation(
        self, workspace: str, ticket_id: str, task_id: str
    ) -> None:
        """Mark a reservation durable after its staging ticket transaction commits."""

        workspace = validate_commitment(workspace)
        ticket_id = validate_sha256_digest(ticket_id)
        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        key = _capture_reservation_key(ticket_id, task_id)
        with self._lock:
            state = self._load(workspace)
            assert state.capture_reservations is not None
            existing = state.capture_reservations.get(key)
            if existing is None:
                return
            if existing.ticket_id != ticket_id or existing.task_id != task_id:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation capture reservation conflicts.",
                    retryable=False,
                )
            if existing.needs_reconcile:
                state.capture_reservations[key] = dataclasses.replace(
                    existing, needs_reconcile=False
                )
                self._save(workspace, state)

    def release_capture_ticket_reservation(
        self, workspace: str, ticket_id: str, task_id: str
    ) -> None:
        """Release one reservation only after durable ticket retirement."""

        workspace = validate_commitment(workspace)
        ticket_id = validate_sha256_digest(ticket_id)
        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        key = _capture_reservation_key(ticket_id, task_id)
        with self._lock:
            state = self._load(workspace)
            assert state.capture_reservations is not None
            existing = state.capture_reservations.get(key)
            if existing is None:
                return
            if existing.ticket_id != ticket_id or existing.task_id != task_id:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation capture reservation conflicts.",
                    retryable=False,
                )
            del state.capture_reservations[key]
            self._save(workspace, state)

    def reconcile_capture_ticket_reservations(
        self, workspace: str, task_id: str, active_ticket_ids: tuple[str, ...]
    ) -> None:
        """Reconcile a task's reservations against its durable active tickets.

        A reservation that outlived a committed deletion is released. A
        durable active ticket without a reservation latches unknown scope so a
        later capture cannot assume the central counter is complete.
        """

        workspace = validate_commitment(workspace)
        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        if type(active_ticket_ids) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        active: set[str] = set()
        for ticket_id in active_ticket_ids:
            try:
                normalized = validate_sha256_digest(ticket_id)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise ProtocolValueError("invalid_event_value_type") from exc
            if normalized in active:
                raise ProtocolValueError("duplicate_set_member")
            active.add(normalized)
        with self._lock:
            state = self._load(workspace)
            assert state.capture_reservations is not None
            assert state.capture_backlogs is not None
            changed = False
            known: set[str] = set()
            for key, reservation in tuple(state.capture_reservations.items()):
                if reservation.task_id != task_id:
                    continue
                known.add(reservation.ticket_id)
                if reservation.ticket_id not in active:
                    del state.capture_reservations[key]
                    changed = True
                elif reservation.needs_reconcile:
                    state.capture_reservations[key] = dataclasses.replace(
                        reservation, needs_reconcile=False
                    )
                    changed = True
            snapshot = state.capture_backlogs.get(task_id)
            if snapshot is not None and len(active) <= snapshot.count:
                accounted_ids = tuple(sorted(active, key=str.encode))
                if snapshot.accounted_ticket_ids != accounted_ids:
                    state.capture_backlogs[task_id] = dataclasses.replace(
                        snapshot, accounted_ticket_ids=accounted_ids
                    )
                    changed = True
            elif snapshot is not None or active - known:
                state.capture_backlog_scope_unknown = True
                state.capture_reservation_bootstrap = None
                changed = True
            if changed:
                self._save(workspace, state)

    def mark_capture_backlog_scope_unknown(self, workspace: str) -> None:
        """Latch unknown scope after an inventory read failed or was incomplete."""

        workspace = validate_commitment(workspace)
        with self._lock:
            state = self._load(workspace)
            if (
                not state.capture_backlog_scope_unknown
                or state.capture_reservation_bootstrap is not None
            ):
                state.capture_backlog_scope_unknown = True
                state.capture_reservation_bootstrap = None
                self._save(workspace, state)

    @staticmethod
    def _capture_bootstrap_snapshots(
        backlogs: Mapping[str, ObservationCaptureBacklog],
        observed_at: Timestamp,
        ticket_ids_by_task: Mapping[str, tuple[str, ...]] | None = None,
    ) -> dict[str, _CaptureBacklogSnapshot]:
        if not isinstance(cast(object, backlogs), Mapping) or len(backlogs) > (
            _MAX_CAPTURE_BACKLOG_ROUTES
        ):
            raise ProtocolValueError("invalid_event_value_type")
        accounted: dict[str, tuple[str, ...]] = {}
        if ticket_ids_by_task is not None:
            if (
                not isinstance(cast(object, ticket_ids_by_task), Mapping)
                or len(ticket_ids_by_task) > _MAX_CAPTURE_BACKLOG_ROUTES
            ):
                raise ProtocolValueError("invalid_event_value_type")
            accounted_total = 0
            for task_id, ticket_ids in ticket_ids_by_task.items():
                if (
                    type(task_id) is not str
                    or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None
                    or task_id not in backlogs
                    or type(ticket_ids) is not tuple
                ):
                    raise ProtocolValueError("invalid_event_value_type")
                normalized_ids: list[str] = []
                for ticket_id in ticket_ids:
                    try:
                        normalized = validate_sha256_digest(ticket_id)
                    except (ProtocolValueError, TypeError, ValueError) as exc:
                        raise ProtocolValueError("invalid_event_value_type") from exc
                    if normalized in normalized_ids:
                        raise ProtocolValueError("duplicate_set_member")
                    normalized_ids.append(normalized)
                normalized_ids.sort(key=str.encode)
                accounted_total += len(normalized_ids)
                if accounted_total > _MAX_CAPTURE_TICKET_RESERVATIONS:
                    raise ProtocolValueError("invalid_event_value_type")
                accounted[task_id] = tuple(normalized_ids)
        snapshots: dict[str, _CaptureBacklogSnapshot] = {}
        for task_id, backlog in backlogs.items():
            if (
                type(task_id) is not str
                or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None
                or type(backlog) is not ObservationCaptureBacklog
            ):
                raise ProtocolValueError("invalid_event_value_type")
            if backlog.count > _MAX_SAFE_INTEGER or backlog.byte_count > _MAX_SAFE_INTEGER:
                raise ProtocolValueError("invalid_event_value_type")
            snapshots[task_id] = _CaptureBacklogSnapshot(
                count=backlog.count,
                byte_count=backlog.byte_count,
                oldest_receipt_time=backlog.oldest_receipt_time,
                observed_at=observed_at,
                accounted_ticket_ids=accounted.get(task_id, ()),
            )
        return snapshots

    def bootstrap_capture_reservations(
        self,
        workspace: str,
        backlogs: Mapping[str, ObservationCaptureBacklog],
        *,
        observed_at: Timestamp | None = None,
        complete: bool = True,
        proof_guard: Callable[[], bool] | None = None,
        ticket_ids_by_task: Mapping[str, tuple[str, ...]] | None = None,
    ) -> bool:
        """Account every task in a ready inventory before opening central admission.

        Complete is supplied only by ready after it has read the service
        catalog and every task bundle. A partial or failed read latches unknown
        scope and leaves central admission closed. When the optional ticket
        identities are supplied, reservations are reconciled against that
        complete set; without identities legacy reservations remain additive
        so an aggregate can never hide their bytes or count.
        """

        workspace = validate_commitment(workspace)
        if type(complete) is not bool or (proof_guard is not None and not callable(proof_guard)):
            raise ProtocolValueError("invalid_event_value_type")
        stamp = self._wall_timestamp() if observed_at is None else observed_at
        if type(stamp) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        if not complete:
            self.mark_capture_backlog_scope_unknown(workspace)
            return False
        snapshots = self._capture_bootstrap_snapshots(
            backlogs,
            stamp,
            ticket_ids_by_task,
        )
        proof = _CaptureBootstrap(
            proof=_capture_bootstrap_proof(workspace, snapshots),
            observed_at=stamp,
            route_count=len(snapshots),
        )
        with self._lock:
            state = self._load(workspace)
            # READY can change generation while this worker waits for flock.
            # Revalidate under the store lock before replacing any accounting.
            try:
                current = proof_guard is None or proof_guard() is True
            except Exception:
                current = False
            if not current:
                state.capture_reservation_bootstrap = None
                state.capture_backlog_scope_unknown = True
                self._save(workspace, state)
                return False
            state.capture_backlogs = snapshots
            state.capture_reservation_bootstrap = proof
            state.capture_backlog_scope_unknown = False
            assert state.capture_reservations is not None
            if state.capture_reservations:
                reconciled: dict[str, _CaptureReservation] = {}
                for key, item in state.capture_reservations.items():
                    task_ids = (
                        None if ticket_ids_by_task is None else ticket_ids_by_task.get(item.task_id)
                    )
                    if task_ids is not None and item.ticket_id not in task_ids:
                        # The complete task inventory proves this old
                        # reservation no longer has a durable ticket. It is
                        # safe to release it because the coordinator's
                        # capture lock excludes an in-flight reservation.
                        continue
                    reconciled[key] = dataclasses.replace(
                        item,
                        needs_reconcile=False,
                    )
                state.capture_reservations = reconciled
            self._save(workspace, state)
        return True

    @staticmethod
    def _capture_pressure_scope_unknown(state: _WorkspaceState) -> bool:
        """Whether admission pressure must treat the capture backlog as unknown.

        A reservation is created unconfirmed and confirmed only after its
        staging ticket commits, outside the store lock.  Under a proven
        inventory its reserved byte bound is already charged above, so that
        in-flight window is a known occupancy, not unknown scope.  Treating it
        as unknown drove every native input in the window to a hard refusal
        and a permanent loss (tb4n1 B3).  Reservation and recovery keep their
        stricter view: a new reservation still waits for confirmation and the
        unconfirmed reservation stays recovery demand.
        """

        if state.capture_backlog_scope_unknown:
            return True
        if state.capture_reservation_bootstrap is not None:
            return False
        return any(item.needs_reconcile for item in (state.capture_reservations or {}).values())

    @staticmethod
    def _capture_inventory_recovery_pending(state: _WorkspaceState) -> bool:
        """Use the same unknown dimensions as capture pressure, without summing occupancy."""

        return state.capture_backlog_scope_unknown or any(
            item.needs_reconcile for item in (state.capture_reservations or {}).values()
        )

    @_read_mostly
    def capture_inventory_recovery_needed(self, workspace: str) -> bool:
        """Read durable recovery demand independently of native-input admission."""

        workspace = validate_commitment(workspace)
        with self._reading():
            return self._capture_inventory_recovery_pending(self._load(workspace))

    @staticmethod
    def _capture_handoff_candidates(
        state: _WorkspaceState, now: Timestamp, older_than_ms: int
    ) -> tuple[str, ...]:
        """Task routes whose oldest unfinished handoff is at least ``older_than_ms`` old."""

        oldest_by_task: dict[str, Timestamp] = {}
        for reservation in (state.capture_reservations or {}).values():
            current = oldest_by_task.get(reservation.task_id)
            if current is None or reservation.reserved_at < current:
                oldest_by_task[reservation.task_id] = reservation.reserved_at
        for task_id, snapshot in (state.capture_backlogs or {}).items():
            # A route report without an identity cannot be opened; unknown
            # scope is repaired by inventory recovery instead.
            if task_id == _UNKNOWN_CAPTURE_BACKLOG_ROUTE or snapshot.oldest_receipt_time is None:
                continue
            current = oldest_by_task.get(task_id)
            if current is None or snapshot.oldest_receipt_time < current:
                oldest_by_task[task_id] = snapshot.oldest_receipt_time
        eligible = sorted(
            (
                (stamp, task_id)
                for task_id, stamp in oldest_by_task.items()
                if _timestamp_age_ms(now, stamp) >= older_than_ms
            ),
            key=lambda item: (item[0].wire, item[1].encode()),
        )
        candidates = [task_id for _stamp, task_id in eligible]
        # An account committed before ticket destruction is maintenance demand
        # even when the ticket was legacy and had no central reservation.  Its
        # task route must be revisited after a restart so the durable binding
        # can be confirmed against the authoritative ticket listing.
        pending_tasks = set((state.capture_handoff_retirement_pending or {}).values())
        candidates.extend(sorted(pending_tasks.difference(candidates), key=str.encode))
        return tuple(candidates)

    @_read_mostly
    def capture_handoff_candidates(
        self,
        workspace: str,
        *,
        older_than_ms: int = CAPTURE_HANDOFF_RECONCILE_AGE_MS,
    ) -> tuple[str, ...]:
        """Return task routes with an aged handoff or pending accounting confirmation.

        Central reservations and cached task snapshots both count, so a legacy
        ticket without a reservation is still found. A pending accounting
        binding remains a maintenance candidate until the task's complete
        ticket listing confirms retirement. This read never changes pressure,
        admission, or accounting (#836).
        """

        workspace = validate_commitment(workspace)
        if (
            type(older_than_ms) is not int
            or isinstance(older_than_ms, bool)
            or not 0 <= older_than_ms <= _MAX_SAFE_INTEGER
        ):
            raise ProtocolValueError("invalid_event_value_type")
        now = self._wall_timestamp()
        with self._reading():
            return self._capture_handoff_candidates(self._load(workspace), now, older_than_ms)

    @_read_mostly
    def capture_handoff_structural_state(self, workspace: str) -> CaptureHandoffStructuralState:
        """Name the structural rows that could still consume a native handoff.

        Only an outbox row or a selected-admission input can still be delivered
        to the coordinator. A quarantined row is terminal: its reason is kept
        so a retired handoff can name the transition that stranded it.
        """

        workspace = validate_commitment(workspace)
        with self._reading():
            state = self._load(workspace)
            pending: set[tuple[str, str, str]] = set()
            for row in state.pending_outbox or ():
                pending.add(
                    (
                        row.envelope.source.value,
                        row.envelope.session_commitment,
                        row.envelope.source_identity,
                    )
                )
            for item in state.admission_buffer.inputs:
                pending.add(
                    (
                        item.envelope.source.value,
                        item.envelope.session_commitment,
                        item.envelope.source_identity,
                    )
                )
            quarantined: dict[tuple[str, str, str], str] = {}
            for _session, envelope, reason, _at in state.quarantine or ():
                key = (envelope.source.value, envelope.session_commitment, envelope.source_identity)
                if key not in pending:
                    quarantined[key] = reason
            return CaptureHandoffStructuralState(
                pending=frozenset(pending),
                quarantined=MappingProxyType(quarantined),
            )

    def record_capture_handoff_retirement(
        self,
        workspace: str,
        *,
        ticket_id: str,
        stage: CaptureHandoffRetirementStage,
        reason: CaptureHandoffRetirementReason,
        ticket_state: str,
        source: ObservationSource,
        task_id: str,
        age_ms: int,
        quarantine_reason: str | None = None,
    ) -> None:
        """Account one retired handoff and its honest content gap (#836).

        The staged content of a retired handoff will never be attached to its
        structural observation, so ``content_capture_unavailable`` is recorded.
        The bounded entry names the ticket identity, stage, ticket state, and
        reason; it never carries a source identity, content, path, or exception
        text. Ticket identity makes the accounting commit safe to replay before
        the destructive ticket retirement.
        """

        workspace = validate_commitment(workspace)
        if (
            type(ticket_id) is not str
            or validate_sha256_digest(ticket_id) != ticket_id
            or type(stage) is not CaptureHandoffRetirementStage
            or type(reason) is not CaptureHandoffRetirementReason
            or ticket_state not in {"staging", "pending"}
            or type(source) is not ObservationSource
            or type(task_id) is not str
            or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None
            or type(age_ms) is not int
            or isinstance(age_ms, bool)
            or age_ms < 0
            or (
                quarantine_reason is not None
                and (
                    type(quarantine_reason) is not str
                    or _OUTBOX_REASON_RE.fullmatch(quarantine_reason) is None
                )
            )
        ):
            raise ProtocolValueError("invalid_event_value_type")
        entry = JsonObject(
            {
                "stage": stage.value,
                "reason": reason.value,
                "ticket_id": ticket_id,
                "ticket_state": ticket_state,
                "source": source.value,
                "task_id": task_id,
                "age_ms": min(age_ms, _MAX_SAFE_INTEGER),
                "quarantine_reason": quarantine_reason,
                "retired_at": self._wall_timestamp().wire,
            }
        )
        with self._lock:
            state = self._load(workspace)
            pending = dict(state.capture_handoff_retirement_pending or {})
            prior_task = pending.get(ticket_id)
            if prior_task is not None:
                if prior_task != task_id:
                    raise _error(
                        PublicErrorCode.STORAGE_CORRUPT,
                        "Observation capture retirement conflicts.",
                        retryable=False,
                    )
                return
            if ticket_id in state.capture_handoff_retirement_ids:
                return
            if len(pending) >= _MAX_CAPTURE_TICKET_RESERVATIONS:
                # Do not evict an unconfirmed identity: doing so would let a
                # later replay increment the loss account a second time.
                raise _error(
                    PublicErrorCode.LIMIT_EXCEEDED,
                    "Observation capture retirement confirmation is pending.",
                    retryable=False,
                )
            pending[ticket_id] = task_id
            self._note_gap_state(state, ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            state.capture_handoff_retirements = (
                *state.capture_handoff_retirements,
                entry,
            )[-_MAX_CAPTURE_HANDOFF_RETIREMENTS:]
            state.capture_handoff_retired_count = min(
                _MAX_SAFE_INTEGER, state.capture_handoff_retired_count + 1
            )
            state.capture_handoff_retirement_pending = pending
            retirement_ids: list[str] = []
            for item in (*state.capture_handoff_retirement_ids, *pending, ticket_id):
                if item not in retirement_ids:
                    retirement_ids.append(item)
            # Keep every accounted identity whose retirement confirmation is
            # still pending, then active reservation identities.  The pending
            # map is authoritative for legacy tickets without reservations;
            # the bounded history only needs to preserve confirmed replays.
            reservation_ids = {
                reservation.ticket_id for reservation in (state.capture_reservations or {}).values()
            }
            pinned_ids: list[str] = []
            seen_pinned: set[str] = set()
            for item in retirement_ids:
                if item in pending and item not in seen_pinned:
                    seen_pinned.add(item)
                    pinned_ids.append(item)
            for item in retirement_ids:
                if len(pinned_ids) >= _MAX_CAPTURE_TICKET_RESERVATIONS:
                    break
                if item in reservation_ids and item not in seen_pinned:
                    seen_pinned.add(item)
                    pinned_ids.append(item)
            unpinned_ids = [item for item in retirement_ids if item not in seen_pinned]
            available = max(0, _MAX_CAPTURE_TICKET_RESERVATIONS - len(pinned_ids))
            retained_unpinned = unpinned_ids[-available:] if available else []
            state.capture_handoff_retirement_ids = tuple(pinned_ids + retained_unpinned)
            self._save(workspace, state)

    def confirm_capture_handoff_retirement(
        self, workspace: str, ticket_id: str, task_id: str
    ) -> None:
        """Drop one pending accounting binding after destructive retirement succeeds."""

        workspace = validate_commitment(workspace)
        ticket_id = validate_sha256_digest(ticket_id)
        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            pending = dict(state.capture_handoff_retirement_pending or {})
            prior_task = pending.get(ticket_id)
            if prior_task is None:
                return
            if prior_task != task_id:
                raise _error(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "Observation capture retirement conflicts.",
                    retryable=False,
                )
            del pending[ticket_id]
            state.capture_handoff_retirement_pending = pending or None
            self._save(workspace, state)

    def reconcile_capture_handoff_retirements(
        self, workspace: str, task_id: str, active_ticket_ids: tuple[str, ...]
    ) -> None:
        """Confirm accounted tickets absent from a complete active-ticket listing."""

        workspace = validate_commitment(workspace)
        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        if type(active_ticket_ids) is not tuple:
            raise ProtocolValueError("invalid_event_value_type")
        active: set[str] = set()
        for ticket_id in active_ticket_ids:
            try:
                normalized = validate_sha256_digest(ticket_id)
            except (ProtocolValueError, TypeError, ValueError) as exc:
                raise ProtocolValueError("invalid_event_value_type") from exc
            if normalized in active:
                raise ProtocolValueError("duplicate_set_member")
            active.add(normalized)
        with self._lock:
            state = self._load(workspace)
            pending = dict(state.capture_handoff_retirement_pending or {})
            changed = False
            for ticket_id, owner in tuple(pending.items()):
                if owner == task_id and ticket_id not in active:
                    del pending[ticket_id]
                    changed = True
            if changed:
                state.capture_handoff_retirement_pending = pending or None
                self._save(workspace, state)

    @_read_mostly
    def capture_handoff_retirement_workspaces(self, task_id: str) -> tuple[str, ...]:
        """Find workspaces with accounting still awaiting retirement confirmation."""

        if type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None:
            raise ProtocolValueError("invalid_event_value_type")
        with self._reading():
            return tuple(
                sorted(
                    (
                        workspace
                        for workspace, state in self._iter_workspaces()
                        if task_id in (state.capture_handoff_retirement_pending or {}).values()
                    ),
                    key=str.encode,
                )
            )

    @_read_mostly
    def capture_handoff_retirements(self, workspace: str) -> JsonObject:
        """Return the bounded local-only account of retired native handoffs.

        Like ``summary_refusals`` this is read by ``observe status`` and the
        owner's diagnostics; it is not part of a frozen control-result schema.
        """

        workspace = validate_commitment(workspace)
        with self._reading():
            state = self._load(workspace)
            return JsonObject(
                {
                    "retired_count": state.capture_handoff_retired_count,
                    "recent": state.capture_handoff_retirements,
                }
            )

    @_read_mostly
    def capture_reservation_bootstrap_ready(
        self, workspace: str, task_id: str | None = None
    ) -> bool:
        """Return whether central admission has a complete persisted root proof."""

        workspace = validate_commitment(workspace)
        if task_id is not None and (
            type(task_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(task_id) is None
        ):
            raise ProtocolValueError("invalid_event_value_type")
        with self._reading():
            state = self._load(workspace)
            if state.capture_reservation_bootstrap is None or state.capture_backlog_scope_unknown:
                return False
            if task_id is None:
                return True
            return task_id in (state.capture_backlogs or {})

    def update_capture_backlog(
        self,
        workspace: str,
        count: int,
        byte_count: int,
        oldest_receipt_time: Timestamp | None,
        observed_at: Timestamp,
        *,
        route_id: str | None = None,
    ) -> None:
        """Cache one task's read-only capture backlog after a durable store transaction.

        A route report is deliberately not treated as a workspace-global
        reservation. The bounded map keeps active task reports for pressure
        feedback, while a missing route or a saturated map latches an unknown
        scope so pressure logic cannot infer that unreported work is absent.
        """

        if (
            type(count) is not int
            or isinstance(count, bool)
            or not 0 <= count <= _MAX_SAFE_INTEGER
            or type(byte_count) is not int
            or isinstance(byte_count, bool)
            or not 0 <= byte_count <= _MAX_SAFE_INTEGER
            or type(observed_at) is not Timestamp
            or (oldest_receipt_time is not None and type(oldest_receipt_time) is not Timestamp)
        ):
            raise ProtocolValueError("invalid_event_value_type")
        if route_id is not None and (
            type(route_id) is not str or _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(route_id) is None
        ):
            raise ProtocolValueError("invalid_event_value_type")
        key = _UNKNOWN_CAPTURE_BACKLOG_ROUTE if route_id is None else route_id
        snapshot = _CaptureBacklogSnapshot(
            count=count,
            byte_count=byte_count,
            oldest_receipt_time=oldest_receipt_time,
            observed_at=observed_at,
        )
        with self._lock:
            state = self._load(workspace)
            assert state.capture_backlogs is not None
            if route_id is not None:
                previous = state.capture_backlogs.get(route_id)
                if previous is not None and len(previous.accounted_ticket_ids) <= count:
                    snapshot = dataclasses.replace(
                        snapshot,
                        accounted_ticket_ids=previous.accounted_ticket_ids,
                    )
            if route_id is not None and (
                state.capture_reservation_bootstrap is not None
                and route_id not in state.capture_backlogs
            ):
                # A new route invalidates the old root inventory. The next
                # complete ready enumeration may mint a replacement proof.
                state.capture_reservation_bootstrap = None
                state.capture_backlog_scope_unknown = True
            elif route_id is None:
                # An unscoped report cannot be part of a complete root
                # inventory. Preserve the report for pressure feedback but
                # force a fresh authoritative enumeration before admission.
                state.capture_reservation_bootstrap = None
                state.capture_backlog_scope_unknown = True
            if key not in state.capture_backlogs and len(state.capture_backlogs) >= (
                _MAX_CAPTURE_BACKLOG_ROUTES
            ):
                # Preserve all existing active reports. Losing one silently
                # would make the aggregate appear smaller and could authorize
                # optional detail during pressure.
                state.capture_backlog_scope_unknown = True
                self._save(workspace, state)
                return
            state.capture_backlogs[key] = snapshot
            self._save(workspace, state)

    @_read_mostly
    def capture_backlog(self, workspace: str) -> JsonObject:
        """Return conservative aggregate feedback from known task routes.

        ``partial`` means the returned totals are the sum of known routes and
        are not a complete workspace aggregate. ``unknown`` means at least
        one route is missing or the bounded route cache saturated. The
        snapshot is read-only and contains counts and timestamps only.
        """

        with self._reading():
            state = self._load(workspace)
            snapshots = state.capture_backlogs or {}
            reservations = state.capture_reservations or {}
            reservations_by_task: dict[str, list[_CaptureReservation]] = {}
            for reservation in reservations.values():
                reservations_by_task.setdefault(reservation.task_id, []).append(reservation)
            routes_by_task = dict(snapshots)
            for task_id, task_reservations in reservations_by_task.items():
                snapshot = snapshots.get(task_id)
                if snapshot is None:
                    reserved_oldest = min(item.reserved_at for item in task_reservations)
                    reserved_observed = max(item.reserved_at for item in task_reservations)
                    routes_by_task[task_id] = _CaptureBacklogSnapshot(
                        count=len(task_reservations),
                        byte_count=sum(item.byte_count for item in task_reservations),
                        oldest_receipt_time=reserved_oldest,
                        observed_at=reserved_observed,
                    )
                else:
                    routes_by_task[task_id] = self._merge_capture_backlog_snapshot(
                        snapshot, tuple(task_reservations)
                    )
            count = sum(snapshot.count for snapshot in routes_by_task.values())
            byte_count = sum(snapshot.byte_count for snapshot in routes_by_task.values())
            oldest_candidates = tuple(
                snapshot.oldest_receipt_time
                for snapshot in routes_by_task.values()
                if snapshot.oldest_receipt_time is not None
            )
            oldest = min(oldest_candidates) if oldest_candidates else None
            observed_candidates = tuple(
                snapshot.observed_at for snapshot in routes_by_task.values()
            )
            observed_at = max(observed_candidates) if observed_candidates else None
            reservation_unknown = any(item.needs_reconcile for item in reservations.values())
            routes = JsonObject(
                {
                    key: JsonObject(
                        {
                            "count": snapshot.count,
                            "byte_count": snapshot.byte_count,
                            "oldest_receipt_time": (
                                None
                                if snapshot.oldest_receipt_time is None
                                else snapshot.oldest_receipt_time.wire
                            ),
                            "observed_at": snapshot.observed_at.wire,
                            "reservation_count": len(reservations_by_task.get(key, ())),
                            "reservation_unknown": any(
                                item.needs_reconcile for item in reservations_by_task.get(key, ())
                            ),
                        }
                    )
                    for key, snapshot in sorted(
                        routes_by_task.items(), key=lambda item: item[0].encode()
                    )
                }
            )
            scope_unknown = state.capture_backlog_scope_unknown or reservation_unknown
            return JsonObject(
                {
                    "capture_backlog_scope": (
                        "unknown" if scope_unknown or not routes_by_task else "partial"
                    ),
                    "route_count": len(routes_by_task),
                    "count": count,
                    "byte_count": byte_count,
                    "oldest_receipt_time": None if oldest is None else oldest.wire,
                    "observed_at": None if observed_at is None else observed_at.wire,
                    "reservation_count": len(reservations),
                    "reserved_byte_count": sum(item.byte_count for item in reservations.values()),
                    "reservation_unknown": reservation_unknown,
                    "routes": routes,
                }
            )

    def capture_backlog_status(self, workspace: str) -> JsonObject:
        """Compatibility alias for the read-only local pressure snapshot."""

        return self.capture_backlog(workspace)

    def _selection_pressure_usage(
        self,
        workspace: str,
        state: _WorkspaceState,
        session_commitment: str,
        limits: BudgetLimits,
        now: Timestamp,
        *,
        state_bytes: int | None = None,
    ) -> BudgetUsage:
        """Build one bounded usage sample without changing selection state."""

        rows = tuple(state.pending_outbox or ())
        buffered = tuple(state.admission_buffer.inputs)
        queue_count = len(rows) + len(buffered)
        # One pass with one memoized lookup per row: this runs on every hook
        # admission, and a retained backlog can reach the session fair share
        # (thousands of rows) now that age no longer refuses input (#887).
        facts = _CODEC.pressure_facts
        overhead = _delivery_unit_overhead
        queue_bytes = 0
        protected_count = len(buffered)
        protected_bytes = 0
        session_count = 0
        session_bytes = 0
        # Retries must not make a stalled row look young.  The envelope
        # receipt is the original observation time; ``last_attempt_at`` is
        # only delivery-attempt metadata.
        oldest: Timestamp | None = None
        for row in rows:
            envelope = row.envelope
            size, protected = facts(envelope)
            unit = overhead(row.codex_session_id) + size
            queue_bytes += unit
            if protected:
                protected_count += 1
                protected_bytes += unit
            if envelope.session_commitment == session_commitment:
                session_count += 1
                session_bytes += size
            if oldest is None or envelope.receipt_time < oldest:
                oldest = envelope.receipt_time
        for item in buffered:
            size, _protected = facts(item.envelope)
            queue_bytes += size
            protected_bytes += size
            if item.envelope.session_commitment == session_commitment:
                session_count += 1
                session_bytes += size
        if state_bytes is None:
            state_bytes = len(canonical_encode(self._state_to_json(workspace, state))) + 1
        (
            capture_tickets,
            capture_bytes,
            capture_oldest,
            _capture_scope_unknown,
        ) = self._capture_backlog_usage(state)
        if capture_oldest is not None and (oldest is None or capture_oldest < oldest):
            oldest = capture_oldest
        if self._capture_pressure_scope_unknown(state):
            # Missing capture routes are an unknown backlog, never a clean
            # zero.  Drive the capture dimension to its hard ceiling.
            capture_tickets = limits.capture_tickets
            capture_bytes = limits.capture_bytes
        pending_keys = set(state.open_pre or ())
        for item in buffered:
            if item.kind != "pending":
                continue
            correlation = _envelope_pairing_correlation(item.envelope, "paired")
            if correlation is not None:
                pending_keys.add(
                    _pairing_key(
                        source=item.envelope.source,
                        session_commitment=item.envelope.session_commitment,
                        source_generation=item.envelope.cursor.source_generation,
                        correlation_id=correlation,
                    )
                )
            else:
                pending_keys.add(
                    "pending:"
                    + item.envelope.source.value
                    + ":"
                    + item.envelope.session_commitment
                    + ":"
                    + item.envelope.source_identity
                )
        return BudgetUsage(
            queue_count=queue_count,
            queue_bytes=queue_bytes,
            state_bytes=state_bytes,
            oldest_pending_age_ms=_timestamp_age_ms(now, oldest),
            pending_attempts=len(pending_keys),
            capture_tickets=capture_tickets,
            capture_bytes=capture_bytes,
            protected_count=protected_count,
            protected_bytes=protected_bytes,
            session_queue_count=session_count,
            session_queue_bytes=session_bytes,
        )

    def update_selection_pressure(
        self,
        workspace: str,
        session_commitment: str,
    ) -> PressureEvaluation:
        """Advance one session's pressure snapshot from live adapter usage.

        This is a writer-side operation used by hooks and the sweeper.  Reads
        use :meth:`selection_runtime_status` and never start the recovery
        dwell or persist a notice.
        """

        if type(session_commitment) is not str:
            raise ProtocolValueError("invalid_commitment")
        with self._lock:
            state = self._load(workspace)
            now = self._wall_timestamp()
            self._prune_open_pre(state, now)
            settings = state.selection_settings or ObservationSelectionSettings()
            resolved = resolve_observation_selection(
                settings,
                session_commitment=session_commitment,
                now=now,
            )
            limits = BudgetLimits.for_capacity(settings.aggregate_capacity(now=now))
            mode = ObservationMode.from_value(resolved.selection.detail.value)
            usage = self._selection_pressure_usage(
                workspace,
                state,
                session_commitment,
                limits,
                now,
            )
            previous = None
            if self._epoch_matches(state.monotonic_epoch):
                previous = (state.pressure_snapshots or {}).get(session_commitment)
            evaluation = evaluate_pressure(
                usage,
                mode,
                previous,
                max(0, int(self._now_mono() * 1000)),
                limits=limits,
            )
            snapshots = state.pressure_snapshots
            if snapshots is None:
                snapshots = {}
                state.pressure_snapshots = snapshots
            if session_commitment in (state.ended_sessions or ()):
                snapshots.pop(session_commitment, None)
            else:
                snapshots[session_commitment] = evaluation.snapshot
            if len(snapshots) > _MAX_HOOK_SEQUENCES:
                candidates = sorted(
                    (key for key in snapshots if key != session_commitment),
                    key=lambda key: (snapshots[key].since_ms, key.encode()),
                )
                if candidates:
                    del snapshots[candidates[0]]
            state.monotonic_epoch = self._boot_epoch()
            if previous != evaluation.snapshot or not self._epoch_matches(state.monotonic_epoch):
                self._save(workspace, state)
            return evaluation

    @_read_mostly
    def selection_runtime_status(
        self,
        workspace: str,
        session_commitment: str | None = None,
    ) -> JsonObject:
        """Return selected/effective pressure state without starting recovery.

        A workspace read is an aggregate projection.  It evaluates every
        still-active session lane and carries forward the worst pressure state
        so one high child cannot be hidden by a healthy workspace/default
        selection.  The pure evaluation is deliberately not persisted; only
        the hook/sweeper writer advances hysteresis snapshots.
        """

        with self._reading():
            state = self._load(workspace)
            now = self._wall_timestamp()
            settings = state.selection_settings or ObservationSelectionSettings()
            resolved = resolve_observation_selection(
                settings,
                session_commitment=session_commitment,
                now=now,
            )
            aggregate = settings.aggregate_capacity(now=now)
            limits = BudgetLimits.for_capacity(aggregate)
            path = self._workspace_path(workspace)
            stat_key = self._stat_key(path)
            usage = self._selection_pressure_usage(
                workspace,
                state,
                session_commitment or "",
                limits,
                now,
                state_bytes=0 if stat_key is None else stat_key[1],
            )
            monotonic_ms = max(0, int(self._now_mono() * 1000))
            snapshots = state.pressure_snapshots or {}

            def evaluate_lane(lane: str | None) -> PressureEvaluation:
                lane_resolution = resolve_observation_selection(
                    settings,
                    session_commitment=lane,
                    now=now,
                )
                lane_usage = (
                    usage
                    if lane == session_commitment
                    else self._selection_pressure_usage(
                        workspace,
                        state,
                        "" if lane is None else lane,
                        limits,
                        now,
                        state_bytes=0 if stat_key is None else stat_key[1],
                    )
                )
                previous = snapshots.get(lane) if lane is not None else None
                if not self._epoch_matches(state.monotonic_epoch) or lane in (
                    state.ended_sessions or ()
                ):
                    previous = None
                return evaluate_pressure(
                    lane_usage,
                    ObservationMode.from_value(lane_resolution.selection.detail.value),
                    previous,
                    monotonic_ms,
                    limits=limits,
                )

            lane_evaluations: list[tuple[str | None, PressureEvaluation]] = []
            if session_commitment is not None:
                lane_evaluations.append((session_commitment, evaluate_lane(session_commitment)))
            else:
                # A snapshot is valid for this workspace only while its lane is
                # still active.  Session overrides also count as active owner
                # lanes before a host binding has been materialized; ended
                # lanes never keep workspace pressure elevated.
                ended = state.ended_sessions or set()
                active_lanes = {
                    key
                    for key, setting in settings.sessions
                    if not setting.expired(now) and key not in ended
                }
                active_lanes.update(
                    key
                    for key, bound_workspace in (state.session_workspaces or {}).items()
                    if bound_workspace == workspace and key not in ended
                )
                active_lanes.update(
                    key for key in (state.codex_session_bindings or {}).values() if key not in ended
                )
                # Always evaluate the workspace lane so a workspace selection
                # remains visible when no child session is currently active.
                lane_evaluations.append((None, evaluate_lane(None)))
                for lane in sorted(active_lanes, key=str.encode):
                    lane_evaluations.append((lane, evaluate_lane(lane)))

            lane, evaluation = max(
                lane_evaluations,
                key=lambda item: (
                    item[1].state.rank,
                    item[1].utilization_bps,
                    b"" if item[0] is None else item[0].encode(),
                ),
            )
            del lane
            pressure_state = evaluation.state
            selected_mode = ObservationMode.from_value(resolved.selection.detail.value)
            if session_commitment is None:
                # Workspace status is a worst-lane projection.  A workspace
                # Detailed setting is never reported as effective Detailed
                # while an active sibling lane is pressure-downgraded.
                effective_mode = min(
                    (item[1].effective_mode for item in lane_evaluations),
                    key=lambda mode: 0 if mode is ObservationMode.FOCUSED else 1,
                )
            else:
                effective_mode = evaluation.effective_mode
            capture = self.capture_backlog(workspace)
            selected_capacity = resolved.selection.capacity
            effective_budget = JsonObject(
                {
                    "schema": EFFECTIVE_BUDGET_SCHEMA,
                    "budget_policy_version": BUDGET_POLICY_VERSION,
                    "validation_status": BUDGET_VALIDATION_STATUS,
                    "scope": "workspace" if session_commitment is None else "session",
                    "selected_queue_count": selected_capacity.queue_count,
                    "selected_capacity_label": selected_capacity.label,
                    "effective_queue_count": aggregate.queue_count,
                    "effective_capacity_label": aggregate.label,
                    # The shared queue follows the largest active selection
                    # in the workspace, which may be a sibling's.
                    "effective_reason": (
                        "selected" if aggregate == selected_capacity else "workspace_aggregate"
                    ),
                    "limits": {
                        "queue_count": limits.queue_count,
                        "queue_bytes": limits.queue_bytes,
                        "state_bytes": limits.state_bytes,
                        "pending_attempts": limits.pending_attempts,
                        "capture_tickets": limits.capture_tickets,
                        "capture_bytes": limits.capture_bytes,
                        "protected_count": limits.protected_count,
                        "protected_bytes": limits.protected_bytes,
                        "session_fair_share": limits.session_fair_share,
                        "session_fair_share_bytes": limits.session_fair_share_bytes,
                        "max_pending_age_ms": limits.max_pending_age_ms,
                        "state_document_ceiling_bytes": STATE_DOCUMENT_CEILING_BYTES,
                    },
                    "limiting_dimension": evaluation.dimension.value,
                    "utilization_bps": evaluation.utilization_bps,
                    "no_cap": no_cap_support(),
                }
            )
            return JsonObject(
                {
                    "policy_version": BUDGET_POLICY_VERSION,
                    "validation_status": BUDGET_VALIDATION_STATUS,
                    "selected_mode": selected_mode.value,
                    "effective_mode": effective_mode.value,
                    "selected_capacity": selected_capacity.queue_count,
                    "effective_capacity": aggregate.queue_count,
                    "selected_capacity_label": selected_capacity.label,
                    "effective_capacity_label": aggregate.label,
                    "effective_budget": effective_budget,
                    "selection_origin": resolved.origin,
                    "selection_expires_at": (
                        None if resolved.expires_at is None else resolved.expires_at.wire
                    ),
                    "pressure_state": pressure_state.value,
                    "pressure_transition_identity": evaluation.transition_identity,
                    "content_allowed": all(item[1].content_allowed for item in lane_evaluations),
                    "admission_allowed": all(
                        item[1].admission_allowed for item in lane_evaluations
                    ),
                    "queue_count": usage.queue_count,
                    "queue_bytes": usage.queue_bytes,
                    "state_bytes": usage.state_bytes,
                    "oldest_pending_age_ms": usage.oldest_pending_age_ms,
                    "pending_attempts": usage.pending_attempts,
                    "pending_lifecycle_count": len(state.pending_lifecycles or ()),
                    "capture_backlog": capture,
                    "protected_count_reserve": limits.protected_count,
                    "protected_bytes_reserve": limits.protected_bytes,
                    "session_fair_share": limits.session_fair_share,
                    "session_fair_share_bytes": limits.session_fair_share_bytes,
                    "accounting": self.selection_accounting(workspace),
                    "session_commitment": session_commitment,
                }
            )

    def maintain_selected_admission(self, workspace: str, *, force: bool = False) -> None:
        """Flush due accounts and advance pressure recovery from background drain."""

        from yoetz.adapters.integrations.observation_admission import build_routine_read_summary

        with self.batched(workspace):
            self.flush_selected_admission(
                workspace,
                summary_builder=build_routine_read_summary,
                force=force,
            )
            state = self._load(workspace)
            sessions = set((state.codex_session_bindings or {}).values())
            sessions.update(state.pressure_snapshots or ())
            sessions.update(
                item.envelope.session_commitment for item in state.admission_buffer.inputs
            )
            sessions.difference_update(state.ended_sessions or ())
            for session in sorted(sessions)[:_MAX_HOOK_SEQUENCES]:
                self.update_selection_pressure(workspace, session)

    def promote_buffered_observation(self, workspace: str, source_identity: str) -> JsonObject:
        """Promote retained structural call identities before summary admission.

        Optional historical content was never retained by this buffer. A
        successful promotion therefore preserves native identity and time,
        while explicitly reporting that bytes must be reacquired if needed.
        """

        from yoetz.adapters.integrations.observation_admission import build_routine_read_summary

        if type(source_identity) is not str or not 1 <= len(source_identity) <= 128:
            raise ProtocolValueError("invalid_event_value_type")
        with self.batched(workspace):
            state = self._load(workspace)
            if state.consent is None or not state.consent.active:
                return JsonObject({"outcome": "unavailable", "reason": "consent_inactive"})
            target = next(
                (
                    item
                    for item in state.admission_buffer.inputs
                    if item.envelope.source_identity == source_identity
                ),
                None,
            )
            if target is None:
                return JsonObject(
                    {
                        "outcome": "unavailable",
                        "reason": "promotion_window_closed",
                        "content_availability": "not_retained",
                        "next_action": "reacquire_current_state_evidence",
                    }
                )
            if target.kind == "pending":
                return JsonObject({"outcome": "pending", "reason": "tool_outcome_not_observed"})
            call_id = target.envelope.structural_payload.get("tool_call_id") or (
                target.envelope.structural_payload.get("correlation_id")
            )
            lane = tuple(item for item in state.admission_buffer.inputs if item.lane == target.lane)
            remaining = tuple(
                item for item in state.admission_buffer.inputs if item.lane != target.lane
            )
            deliveries: list[tuple[str, ObservationEnvelope]] = []
            successes: list[ObservationEnvelope] = []
            promoted_ids: list[str] = []
            for item in lane:
                item_call = item.envelope.structural_payload.get("tool_call_id") or (
                    item.envelope.structural_payload.get("correlation_id")
                )
                promote = item is target or (call_id is not None and item_call == call_id)
                if promote or item.kind == "pending":
                    if successes:
                        deliveries.append(
                            (
                                item.host_session,
                                build_routine_read_summary(tuple(successes), item.fence),
                            )
                        )
                        successes.clear()
                    envelope = item.envelope
                    if promote:
                        promoted_ids.append(envelope.source_identity)
                        envelope = dataclasses.replace(
                            envelope,
                            structural_payload=JsonObject(
                                {**envelope.structural_payload, "action": "evidence_linked_read"}
                            ),
                            gap_codes=tuple(
                                sorted({*envelope.gap_codes, "routine_read_detail_omitted"})
                            ),
                        )
                    deliveries.append((item.host_session, envelope))
                else:
                    successes.append(item.envelope)
            if successes:
                deliveries.append(
                    (
                        target.host_session,
                        build_routine_read_summary(tuple(successes), target.fence),
                    )
                )
            admitted = self.commit_selected_admission(
                workspace,
                AdmissionPlan(AdmissionBuffer(remaining), tuple(deliveries), False),
            )
            return JsonObject(
                {
                    "outcome": "queued_individual" if admitted else "pending",
                    "reason": "structural_promotion" if admitted else "admission_backpressure",
                    "source_identities": tuple(promoted_ids),
                    "original_receipt_time": target.envelope.receipt_time.wire,
                    "original_cursor": observation_cursor_to_json(target.envelope.cursor),
                    "content_availability": "not_retained",
                    "next_action": "reacquire_content_if_required",
                }
            )

    @_read_mostly
    def list_pending_outbox_rows(
        self, workspace: str, *, codex_session_id: str | None = None
    ) -> tuple[ObservationOutboxRow, ...]:
        """Return immutable pending rows including bounded delivery-attempt metadata."""

        with self._reading():
            state = self._load(workspace)
            assert state.pending_outbox is not None
            if codex_session_id is None:
                return tuple(state.pending_outbox)
            return tuple(
                row for row in state.pending_outbox if row.codex_session_id == codex_session_id
            )

    @_read_mostly
    def has_unattempted_outbox_rows(self) -> bool:
        """Report whether any workspace holds an outbox row no drain has attempted yet.

        The idle service sweeper polls this read-only probe so a row a hook deferred without
        contacting the service is swept promptly instead of an idle interval later (#887).
        Rows that already failed an attempt are excluded: they keep the ordinary retry cadence.
        """

        with self._reading():
            for _workspace, state in self._iter_workspaces():
                if any(row.attempts == 0 for row in state.pending_outbox or ()):
                    return True
            return False

    @_read_mostly
    def buffered_admission_host_sessions(self, workspace: str) -> tuple[str, ...]:
        """Return the host sessions with inputs still held in the admission buffer (#1012)."""

        with self._reading():
            state = self._load(workspace)
            return tuple(
                sorted(
                    {item.host_session for item in state.admission_buffer.inputs}, key=str.encode
                )
            )

    def pending_workspaces(self) -> tuple[str, ...]:
        """Return opaque commitments with delivery, lifecycle, or capture recovery work."""

        now = self._wall_timestamp()
        with self._reading():
            pending: list[str] = []
            for workspace, state in self._iter_workspaces():
                assert state.pending_outbox is not None
                assert state.pending_lifecycles is not None
                pressure_active = any(
                    snapshot.state is not PressureState.HEALTHY
                    for session, snapshot in (state.pressure_snapshots or {}).items()
                    if session not in (state.ended_sessions or ())
                )
                if (
                    state.pending_outbox
                    or state.pending_lifecycles
                    or state.admission_buffer.inputs
                    or pressure_active
                    or self._capture_inventory_recovery_pending(state)
                    or self._pending_selection_losses(state)
                    or state.capture_handoff_retirement_pending
                    # An aged native handoff is maintenance demand even with an
                    # empty outbox: its structural row may be gone (#836).
                    or self._capture_handoff_candidates(
                        state, now, CAPTURE_HANDOFF_RECONCILE_AGE_MS
                    )
                ):
                    pending.append(workspace)
            return tuple(sorted(pending, key=str.encode))

    @_read_mostly
    def list_pending_session_lifecycles(
        self, workspace_commitment: str, codex_session_id: str | None = None
    ) -> tuple[PendingSessionLifecycle, ...]:
        """Return immutable deferred lifecycle intents in capture order."""

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.pending_lifecycles is not None
            if codex_session_id is None:
                return tuple(state.pending_lifecycles)
            return tuple(
                intent
                for intent in state.pending_lifecycles
                if intent.codex_session_id == codex_session_id
            )

    @_read_mostly
    def lifecycle_reconciliation_snapshot(
        self, workspace_commitment: str
    ) -> tuple[frozenset[str], frozenset[str]]:
        """Return bound and deferred raw session ids from one state read."""

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.codex_session_bindings is not None
            assert state.pending_lifecycles is not None
            return (
                frozenset(state.codex_session_bindings),
                frozenset(intent.codex_session_id for intent in state.pending_lifecycles),
            )

    @_read_mostly
    def effective_session_generation(
        self,
        workspace_commitment: str,
        codex_session_id: str,
        session_commitment: str,
    ) -> int:
        """Return the generation future envelopes must use while intents are queued."""

        with self._reading():
            state = self._load(workspace_commitment)
            assert state.session_generations is not None
            generation = state.session_generations.get(session_commitment, 0) or 1
            assert state.pending_lifecycles is not None
            for intent in state.pending_lifecycles:
                if (
                    intent.codex_session_id != codex_session_id
                    or intent.session_commitment != session_commitment
                ):
                    continue
                if intent.event_kind == "SessionStart":
                    generation = intent.target_generation
                elif intent.target_generation == generation:
                    # A queued end makes the next start a new generation.  The
                    # current generation remains the one stamped on events
                    # captured before that start is observed.
                    continue
            return generation

    def record_pending_session_lifecycle(
        self,
        workspace_commitment: str,
        codex_session_id: str,
        session_commitment: str,
        event_kind: str,
        target_generation: int,
        *,
        clear_mapping: bool = False,
    ) -> bool:
        """Persist one lifecycle intent when a nonblocking membership lock is busy.

        The intent and the envelope that caused it are committed by the same
        workspace batch in the hook. Consecutive duplicate intents collapse;
        distinct start/end transitions retain their order up to a bounded
        per-workspace queue.
        """

        intent = PendingSessionLifecycle(
            codex_session_id=codex_session_id,
            session_commitment=session_commitment,
            event_kind=event_kind,
            target_generation=target_generation,
            clear_mapping=clear_mapping,
        )
        with self._lock:
            state = self._load(workspace_commitment)
            assert state.pending_lifecycles is not None
            for prior in reversed(state.pending_lifecycles):
                if prior.codex_session_id != codex_session_id:
                    continue
                if (
                    prior.event_kind == intent.event_kind
                    and prior.target_generation == intent.target_generation
                    and prior.clear_mapping == intent.clear_mapping
                    and prior.session_commitment == intent.session_commitment
                ):
                    return True
                break
            if len(state.pending_lifecycles) >= _MAX_PENDING_LIFECYCLES:
                return False
            state.pending_lifecycles.append(intent)
            self._save(workspace_commitment, state)
            return True

    def _pending_session_workspace_owners(self, codex_session_id: str) -> frozenset[str]:
        """Return every raw binding owner while the store lock is held."""

        owners: set[str] = set()
        for workspace, state in self._iter_workspaces():
            assert state.codex_session_bindings is not None
            if codex_session_id in state.codex_session_bindings:
                owners.add(workspace)
        with contextlib.suppress(ProtocolValueError, TypeError, ValueError):
            owners.update(
                self._session_workspace_owners_unlocked(self.session_commitment(codex_session_id))
            )
        return frozenset(owners)

    def _reconcile_pending_session_lifecycle_lanes(
        self,
        workspace_commitment: str,
        session_ids: tuple[str, ...],
        *,
        session_lock_owned: bool,
        owned_session_id: str | None,
    ) -> bool:
        """Reconcile each pending raw-session lane independently.

        The workspace reservation protects shared state, while each session lock fences only that
        session's lifecycle. One contended sibling therefore remains durable without preventing
        an unrelated session from converging in the same pass.
        """

        from yoetz.adapters.integrations.codex_lifecycle import (
            acquire_session_lock,
            acquire_workspace_recovery_lock,
            clear_mapping,
        )

        with acquire_workspace_recovery_lock(
            workspace_commitment, _state=self._state_root
        ) as workspace_owned:
            if not workspace_owned:
                return False
            acquired_any = False
            for session_id in session_ids:
                session_lock = (
                    contextlib.nullcontext(True)
                    if session_lock_owned and session_id == owned_session_id
                    else acquire_session_lock(session_id, _state=self._state_root)
                )
                with session_lock as session_owned:
                    if not session_owned:
                        continue
                    acquired_any = True
                    with self.batched(workspace_commitment):
                        state = self._load(workspace_commitment)
                        assert state.pending_lifecycles is not None
                        current = list(state.pending_lifecycles)
                        remaining: list[PendingSessionLifecycle] = []
                        changed = False
                        blocked = False
                        for intent in current:
                            if intent.codex_session_id != session_id:
                                remaining.append(intent)
                                continue
                            # Preserve FIFO for one raw session. If an older intent is still
                            # fenced, a later transition cannot be applied independently of it.
                            if blocked:
                                remaining.append(intent)
                                continue
                            owners = self._pending_session_workspace_owners(session_id)
                            if owners - {workspace_commitment}:
                                remaining.append(intent)
                                blocked = True
                                continue
                            if state.consent is None or not state.consent.active:
                                remaining.append(intent)
                                blocked = True
                                continue
                            assert state.codex_session_bindings is not None
                            assert state.session_workspaces is not None
                            assert state.session_generations is not None
                            assert state.ended_sessions is not None
                            session = self.session_commitment(intent.codex_session_id)
                            if session != intent.session_commitment:
                                remaining.append(intent)
                                blocked = True
                                continue
                            if intent.codex_session_id not in state.codex_session_bindings:
                                removed = self._prune_codex_session_bindings_state(
                                    state, set(state.codex_session_bindings)
                                )
                                if removed:
                                    changed = True
                                if len(state.codex_session_bindings) >= _MAX_CODEX_SESSION_BINDINGS:
                                    # Keep the accepted lifecycle intent durable
                                    # until a terminal lane can be pruned. Never
                                    # silently discard an active child binding.
                                    remaining.append(intent)
                                    blocked = True
                                    continue
                                state.session_workspaces.setdefault(session, workspace_commitment)
                                state.codex_session_bindings[intent.codex_session_id] = session
                                changed = True
                            stored_generation = state.session_generations.get(session, 0)
                            generation = (
                                stored_generation
                                if stored_generation > 0 or intent.event_kind == "SessionStart"
                                else 1
                            )
                            ended = session in state.ended_sessions
                            if intent.event_kind == "SessionStart":
                                if generation > intent.target_generation:
                                    changed = True
                                    continue
                                if intent.clear_mapping:
                                    clear_mapping(intent.codex_session_id, _state=self._state_root)
                                if generation == intent.target_generation and not ended:
                                    pass
                                elif generation + 1 == intent.target_generation and (
                                    ended or intent.clear_mapping
                                ):
                                    self._begin_session_generation_state(state, session)
                                    changed = True
                                elif generation == 0 and intent.target_generation == 1:
                                    self._begin_session_generation_state(state, session)
                                    changed = True
                                elif generation > intent.target_generation:
                                    changed = True
                                else:
                                    remaining.append(intent)
                                    blocked = True
                                    continue
                            elif generation == intent.target_generation:
                                if not ended:
                                    self._note_session_end_state(
                                        state,
                                        workspace_commitment,
                                        session,
                                        intent.target_generation,
                                    )
                                    changed = True
                            elif generation < intent.target_generation:
                                remaining.append(intent)
                                blocked = True
                                continue
                            else:
                                changed = True
                        if remaining != current:
                            state.pending_lifecycles[:] = remaining
                            changed = True
                        if changed:
                            self._prune_open_pre(state, self._wall_timestamp())
                            self._save(workspace_commitment, state)
            return acquired_any

    def reconcile_pending_session_lifecycles(
        self,
        workspace_commitment: str,
        codex_session_id: str | None = None,
        *,
        session_lock_owned: bool = False,
    ) -> bool:
        """Apply queued lifecycle operations under the shared workspace reservation.

        ``False`` means a reservation or session lock was busy and the intents
        remain durable.  A successful pass removes only operations that were
        applied or proven already applied at their frozen target generation.
        """

        pending = self.list_pending_session_lifecycles(workspace_commitment, codex_session_id)
        if not pending:
            return True
        session_ids = tuple(sorted({intent.codex_session_id for intent in pending}, key=str.encode))
        return self._reconcile_pending_session_lifecycle_lanes(
            workspace_commitment,
            session_ids,
            session_lock_owned=session_lock_owned,
            owned_session_id=codex_session_id,
        )

    def bump_outbox_row_attempt(
        self,
        workspace: str,
        expected: ObservationOutboxRow,
        *,
        reason: str | None,
        attempted_at: Timestamp | None = None,
    ) -> ObservationOutboxRow | None:
        """Persist one exact delivery attempt and return its new durable value."""

        if reason is not None and (
            type(reason) is not str or _OUTBOX_REASON_RE.fullmatch(reason) is None
        ):
            raise ProtocolValueError("invalid_event_value_type")
        stamp = self._wall_timestamp() if attempted_at is None else attempted_at
        if type(stamp) is not Timestamp:
            raise ProtocolValueError("invalid_timestamp")
        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            for index, row in enumerate(state.pending_outbox):
                if row.row_identity == expected.row_identity and row.attempts == expected.attempts:
                    updated = ObservationOutboxRow(
                        codex_session_id=row.codex_session_id,
                        envelope=row.envelope,
                        attempts=min(row.attempts + 1, _MAX_SAFE_INTEGER),
                        last_reason=reason,
                        last_attempt_at=stamp,
                        consecutive_reason_attempts=(
                            min(row.consecutive_reason_attempts + 1, _MAX_SAFE_INTEGER)
                            if reason is not None and reason == row.last_reason
                            else (1 if reason is not None else 0)
                        ),
                    )
                    state.pending_outbox[index] = updated
                    self._save(workspace, state)
                    return updated
            return None

    @_read_mostly
    def pending_outbox_count(self, workspace: str) -> int:
        with self._reading():
            state = self._load(workspace)
            assert state.pending_outbox is not None
            return len(state.pending_outbox)

    @_read_mostly
    def last_successful_drain_mono(self, workspace: str) -> float | None:
        """Return the current-boot monotonic drain sample, if one is comparable."""

        with self._reading():
            state = self._load(workspace)
            if not self._epoch_matches(state.monotonic_epoch):
                return None
            value = state.last_successful_drain_mono_ms
            return None if value is None else value / 1000.0

    def note_outbox_session_reason(self, workspace: str, codex_session_id: str, reason: str) -> int:
        """Stamp a shared last_reason on every un-reasoned pending row of one session.

        Used when a drain pass retires a session after one probe (its rows all
        fail identically): the probed row carries the reason from its real
        attempt, and this stamps the skipped siblings in a single save so
        ``observe status`` reports the true shared cause instead of
        ``not_attempted``. Attempt counts are untouched — no attempt was made.
        """

        if _OUTBOX_REASON_RE.fullmatch(reason) is None:
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            stamped = 0
            for index, row in enumerate(state.pending_outbox):
                if row.codex_session_id == codex_session_id and row.last_reason is None:
                    state.pending_outbox[index] = dataclasses.replace(row, last_reason=reason)
                    stamped += 1
            if stamped:
                self._save(workspace, state)
            return stamped

    @contextlib.contextmanager
    def drain_lease(self, workspace: str) -> Generator[bool]:
        """Nonblocking per-workspace drain mutex; yields whether it was acquired.

        Codex runs async hooks concurrently (up to 8), and every hook drains
        the same workspace outbox. Without a lease each concurrent hook
        re-ingests the identical backlog — 8x daemon load for zero additional
        delivery. Losing the lease is not a failure: another live hook process
        is already draining.
        """

        digest = workspace.removeprefix("hmac-sha256:")
        if len(digest) != 64:
            raise ProtocolValueError("invalid_commitment")
        path = self._root / f".drain-{digest}.lock"
        if fcntl is None:  # pragma: no cover - POSIX-only host
            yield True
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
            try:
                yield True
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    @contextlib.contextmanager
    def advice_delivery_lease(self, workspace: str) -> Generator[bool]:
        """Nonblocking advice-delivery mutex independent of workspace state.

        The lease serializes selection, stdout emission, and the subsequent
        delivery commit across concurrent hook processes.  It deliberately
        uses a separate lock file: a blocked host stdout pipe may delay another
        advice delivery, but must never block observation ingest or outbox work
        that needs the workspace-state lock.
        """

        digest = workspace.removeprefix("hmac-sha256:")
        if len(digest) != 64:
            raise ProtocolValueError("invalid_commitment")
        path = self._root / f".advice-delivery-{digest}.lock"
        if fcntl is None:  # pragma: no cover - POSIX-only host
            yield True
            return
        flags = os.O_RDWR | os.O_CREAT | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags, 0o600)
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                yield False
                return
            try:
                yield True
            finally:
                with contextlib.suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)

    def acknowledge_outbox(
        self, workspace: str, codex_session_id: str, source_identity: str
    ) -> bool:
        """Remove one outbox entry after the task-bundle transaction has committed."""

        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            for index, row in enumerate(state.pending_outbox):
                if (
                    row.codex_session_id == codex_session_id
                    and row.envelope.source_identity == source_identity
                ):
                    del state.pending_outbox[index]
                    state.selection_delivered_count = min(
                        _MAX_SAFE_INTEGER,
                        state.selection_delivered_count
                        + self._represented_input_count(row.envelope),
                    )
                    self._resolve_delivered(state)
                    state.last_successful_drain_mono_ms = int(self._now_mono() * 1000)
                    state.monotonic_epoch = self._boot_epoch()
                    self._save(workspace, state)
                    return True
            return False

    def acknowledge_outbox_row(self, workspace: str, expected: ObservationOutboxRow) -> bool:
        """Acknowledge only an exact attempted row, never a same-source successor."""

        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            for index, row in enumerate(state.pending_outbox):
                if row.row_identity == expected.row_identity and row.attempts == expected.attempts:
                    del state.pending_outbox[index]
                    state.selection_delivered_count = min(
                        _MAX_SAFE_INTEGER,
                        state.selection_delivered_count
                        + self._represented_input_count(row.envelope),
                    )
                    self._resolve_delivered(state)
                    state.last_successful_drain_mono_ms = int(self._now_mono() * 1000)
                    state.monotonic_epoch = self._boot_epoch()
                    self._save(workspace, state)
                    return True
            return False

    def _quarantine_row_state(
        self,
        state: _WorkspaceState,
        row: ObservationOutboxRow,
        reason: str,
        *,
        quarantined_at: Timestamp | None = None,
    ) -> bool:
        """Move one row into bounded quarantine while a state lock is held."""

        assert state.quarantine is not None
        already = any(
            entry[0] == row.codex_session_id
            and entry[1].source_identity == row.envelope.source_identity
            and observation_envelope_to_json(entry[1]) == observation_envelope_to_json(row.envelope)
            for entry in state.quarantine
        )
        if already:
            return False
        state.quarantine.append(
            (
                row.codex_session_id,
                row.envelope,
                reason,
                self._wall_timestamp() if quarantined_at is None else quarantined_at,
            )
        )
        while len(state.quarantine) > _MAX_QUARANTINE:
            evicted = state.quarantine.pop(0)
            self._record_quarantine_eviction(state, evicted[0], evicted[1], evicted[2])
        return True

    def quarantine_outbox(
        self, workspace: str, codex_session_id: str, source_identity: str, reason: str
    ) -> bool:
        """Move a permanently-rejected outbox entry into a bounded, visible quarantine.

        Quarantined entries are never treated as committed: they leave the pending
        drain queue but are retained and surface as an ``outbox_quarantined``
        coverage gap in status until an operator reclaims them or the count,
        byte-budget, or clock-fenced age bound folds them into the aggregate
        eviction evidence — never a silent drop.
        """

        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            assert state.quarantine is not None
            assert state.gaps is not None
            moved: ObservationEnvelope | None = None
            for index, row in enumerate(state.pending_outbox):
                if (
                    row.codex_session_id == codex_session_id
                    and row.envelope.source_identity == source_identity
                ):
                    moved = row.envelope
                    del state.pending_outbox[index]
                    break
            if moved is None:
                return False
            self._quarantine_row_state(
                state,
                ObservationOutboxRow(codex_session_id=codex_session_id, envelope=moved),
                reason,
            )
            if reason in _OBSERVATION_GAP_CODES:
                self._note_gap_state(state, reason)
            self._note_gap_state(state, ObservationGapCode.OUTBOX_QUARANTINED.value)
            self._save(workspace, state)
            return True

    def quarantine_outbox_row(
        self, workspace: str, expected: ObservationOutboxRow, reason: str
    ) -> bool:
        """Quarantine only the exact attempted row selected by a drain actor."""

        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            assert state.quarantine is not None
            assert state.gaps is not None
            moved: ObservationEnvelope | None = None
            for index, row in enumerate(state.pending_outbox):
                if row.row_identity == expected.row_identity and row.attempts == expected.attempts:
                    moved = row.envelope
                    del state.pending_outbox[index]
                    break
            if moved is None:
                return False
            self._quarantine_row_state(
                state,
                ObservationOutboxRow(codex_session_id=expected.codex_session_id, envelope=moved),
                reason,
            )
            if reason in _OBSERVATION_GAP_CODES:
                self._note_gap_state(state, reason)
            self._note_gap_state(state, ObservationGapCode.OUTBOX_QUARANTINED.value)
            self._save(workspace, state)
            return True

    def quarantine_outbox_session(self, workspace: str, codex_session_id: str, reason: str) -> int:
        """Atomically quarantine every pending row for one terminally failed session."""

        if type(codex_session_id) is not str or not codex_session_id:
            raise ProtocolValueError("invalid_event_value_type")
        if type(reason) is not str or _OUTBOX_REASON_RE.fullmatch(reason) is None:
            raise ProtocolValueError("invalid_event_value_type")
        with self._lock:
            state = self._load(workspace)
            assert state.pending_outbox is not None
            assert state.quarantine is not None
            assert state.gaps is not None
            assert state.storage_corrupt_sessions is not None
            pending: list[ObservationOutboxRow] = []
            moved: list[ObservationOutboxRow] = []
            for row in state.pending_outbox:
                (moved if row.codex_session_id == codex_session_id else pending).append(row)
            if not moved:
                return 0
            state.pending_outbox[:] = pending
            stamp = self._wall_timestamp()
            for row in moved:
                self._quarantine_row_state(state, row, reason, quarantined_at=stamp)
            if reason in _OBSERVATION_GAP_CODES:
                self._note_gap_state(state, reason)
            if reason == ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value:
                state.storage_corrupt_sessions.add(codex_session_id)
            self._note_gap_state(state, ObservationGapCode.OUTBOX_QUARANTINED.value)
            self._save(workspace, state)
            return len(moved)

    @_read_mostly
    def quarantined_count(self, workspace: str) -> int:
        with self._reading():
            state = self._load(workspace)
            assert state.quarantine is not None
            return len(state.quarantine)

    @_read_mostly
    def quarantine_facts(self, workspace: str) -> tuple[int, int, int]:
        """Return (quarantine depth, involuntary evictions, operator reclaims).

        The two loss counters are deliberately separate: an eviction is yoetz
        destroying detail on its own (byte cap or age bound), a reclaim is the
        operator deliberately dropping it. Folding them together would let a
        voluntary cleanup read as data loss, or vice versa.
        """

        with self._reading():
            state = self._load(workspace)
            assert state.quarantine is not None
            return (
                len(state.quarantine),
                state.quarantine_evicted_count,
                state.quarantine_reclaimed_count,
            )

    def reclaim_quarantine(self, workspace: str) -> int:
        """Operator-initiated drop of all quarantined observation detail.

        Reclaimed entries extend the same aggregate commitment chain as
        cap/age evictions but are counted separately (operator action, not
        data loss), so a recovered install can shed the per-hook tax without
        the drop becoming silent or reading as destruction.
        Returns how many entries were reclaimed.
        """

        with self._lock:
            state = self._load(workspace)
            assert state.quarantine is not None
            reclaimed = len(state.quarantine)
            if reclaimed == 0:
                return 0
            for entry in state.quarantine:
                self._record_quarantine_eviction(
                    state, entry[0], entry[1], entry[2], reclaimed=True
                )
            state.quarantine.clear()
            self._save(workspace, state)
            return reclaimed

    @_read_mostly
    def list_quarantine(
        self, workspace: str
    ) -> tuple[tuple[str, ObservationEnvelope, str, Timestamp], ...]:
        with self._reading():
            state = self._load(workspace)
            assert state.quarantine is not None
            return tuple(state.quarantine)

    def note_coverage_gap(self, workspace: str, gap_code: str) -> None:
        """Record a safe local coverage gap without retaining payload prose."""

        with self._lock:
            state = self._load(workspace)
            assert state.gaps is not None
            if type(gap_code) is str and gap_code:
                self._note_gap_state(state, gap_code)
            self._save(workspace, state)

    def note_session_coverage_gap(
        self, workspace: str, session_commitment: str, gap_code: str
    ) -> None:
        """Record a safe coverage gap for one session lane."""

        with self._lock:
            state = self._load(workspace)
            if (
                type(gap_code) is str
                and gap_code
                and type(session_commitment) is str
                and session_commitment
            ):
                self._note_session_gap_state(state, session_commitment, gap_code)
            self._save(workspace, state)

    @_read_mostly
    def session_gap_codes(self, workspace: str, session_commitment: str) -> tuple[str, ...]:
        """Return active bounded-loss codes for one session lane."""

        with self._reading():
            state = self._load(workspace)
            assert state.session_gaps is not None
            return tuple(sorted(state.session_gaps.get(session_commitment, ()), key=str.encode))

    def _note_gap_state(self, state: _WorkspaceState, gap_code: str) -> None:
        assert state.gaps is not None
        observed_at = self._wall_timestamp()
        prior = state.gaps.get(gap_code)
        state.gaps[gap_code] = _GapState(
            observed_at if prior is None else prior.first_seen,
            observed_at,
            True,
        )

    @staticmethod
    def _note_session_gap_state(
        state: _WorkspaceState, session_commitment: str, gap_code: str
    ) -> None:
        """Retain an active bounded-loss marker for one observation lane."""

        assert state.session_gaps is not None
        if not session_commitment or not gap_code:
            return
        gaps: set[str] | None = state.session_gaps.get(session_commitment)
        if gaps is None:
            if len(state.session_gaps) >= _MAX_ENVELOPES:
                oldest = min(state.session_gaps, key=str.encode)
                del state.session_gaps[oldest]
            gaps = set()
            state.session_gaps[session_commitment] = gaps
        if gap_code not in gaps and len(gaps) >= _MAX_SESSION_GAP_CODES:
            return
        gaps.add(gap_code)

    @staticmethod
    def _resolve_session_gap_state(
        state: _WorkspaceState, gap_code: str, session_commitment: str | None = None
    ) -> None:
        assert state.session_gaps is not None
        targets = (
            (session_commitment,) if session_commitment is not None else tuple(state.session_gaps)
        )
        for session in targets:
            gaps = state.session_gaps.get(session)
            if gaps is None:
                continue
            gaps.discard(gap_code)
            if not gaps:
                del state.session_gaps[session]

    @staticmethod
    def _ordered_dedup_keys(state: _WorkspaceState) -> list[str]:
        """Return dedup keys in durable insertion order, repairing legacy state."""

        assert state.dedup is not None
        seen: set[str] = set()
        ordered: list[str] = []
        for key in state.dedup_order or ():
            if key in state.dedup and key not in seen:
                ordered.append(key)
                seen.add(key)
        ordered.extend(sorted((state.dedup - seen), key=str.encode))
        return ordered

    def _hydrate_dedup_metadata(self, workspace: str, state: _WorkspaceState) -> None:
        """Backfill lane metadata from retained envelopes when loading old state."""

        assert state.dedup_order is not None
        assert state.dedup_lanes is not None
        assert state.dedup is not None
        state.dedup_order[:] = self._ordered_dedup_keys(state)
        for key in tuple(state.dedup_lanes):
            if key not in state.dedup:
                del state.dedup_lanes[key]
        for envelope in state.envelopes or ():
            key = _dedup_key(workspace, envelope)
            if key in state.dedup and key not in state.dedup_lanes:
                state.dedup_lanes[key] = envelope.session_commitment

    @staticmethod
    def _select_dedup_eviction_key(state: _WorkspaceState) -> str | None:
        """Choose the oldest key from an overrepresented session lane."""

        assert state.dedup_lanes is not None
        ordered = LocalObservationStore._ordered_dedup_keys(state)
        if not ordered:
            return None
        counts: dict[str, int] = {}
        for key in ordered:
            lane = state.dedup_lanes.get(key, f"_unknown:{key}")
            counts[lane] = counts.get(lane, 0) + 1
        for key in ordered:
            lane = state.dedup_lanes.get(key, f"_unknown:{key}")
            if counts[lane] > 1:
                return key
        return ordered[0]

    @staticmethod
    def _fair_envelope_index(envelopes: list[ObservationEnvelope]) -> int | None:
        """Choose the oldest envelope from an overrepresented lane first."""

        if not envelopes:
            return None
        counts: dict[str, int] = {}
        for envelope in envelopes:
            counts[envelope.session_commitment] = counts.get(envelope.session_commitment, 0) + 1
        for index, envelope in enumerate(envelopes):
            if counts[envelope.session_commitment] > 1:
                return index
        return 0

    @staticmethod
    def _fair_outbox_index(rows: list[ObservationOutboxRow]) -> int | None:
        """Choose the oldest row from an overrepresented delivery lane."""

        if not rows:
            return None
        counts: dict[str, int] = {}
        for row in rows:
            counts[row.codex_session_id] = counts.get(row.codex_session_id, 0) + 1
        for index, row in enumerate(rows):
            if counts[row.codex_session_id] > 1:
                return index
        return 0

    @staticmethod
    def _fair_new_lane_outbox_index(
        rows: list[ObservationOutboxRow], incoming_session: str
    ) -> int | None:
        """Choose a disposable eviction candidate for a new lane only."""

        if any(row.codex_session_id == incoming_session for row in rows):
            return None
        counts: dict[str, int] = {}
        for row in rows:
            counts[row.codex_session_id] = counts.get(row.codex_session_id, 0) + 1
        for index, row in enumerate(rows):
            if counts[row.codex_session_id] > 1 and not _outbox_row_is_protected(row.envelope):
                return index
        return None

    def _fair_new_lane_outbox_candidate(
        self,
        workspace: str,
        state: _WorkspaceState,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        *,
        accepted_transfer: bool = False,
    ) -> _WorkspaceState | None:
        """Build and validate a fair queue-reclamation candidate.

        The current queue is immutable until the candidate has passed admission
        and the local state-byte bound.  Only rows classified as disposable by
        ``_outbox_row_is_protected`` are eligible, so a full queue of accepted
        protected work fails closed rather than evicting a record to make room.
        """

        assert state.pending_outbox is not None
        evicted_index = self._fair_new_lane_outbox_index(state.pending_outbox, codex_session_id)
        if evicted_index is None:
            return None
        candidate = _copy_state(state)
        assert candidate.pending_outbox is not None
        evicted_row = candidate.pending_outbox.pop(evicted_index)
        self._quarantine_row_state(
            candidate,
            evicted_row,
            ObservationGapCode.OUTBOX_OVERFLOW.value,
        )
        self._note_gap_state(candidate, _LOCAL_OUTBOX_OVERFLOW_GAP)
        self._note_session_gap_state(
            candidate,
            evicted_row.envelope.session_commitment,
            ObservationGapCode.OUTBOX_OVERFLOW.value,
        )
        if not self._outbox_admission_allowed(
            workspace,
            candidate,
            codex_session_id,
            envelope,
            accepted_transfer=accepted_transfer,
        ):
            return None
        candidate.pending_outbox.append(
            ObservationOutboxRow(codex_session_id=codex_session_id, envelope=envelope)
        )
        projected = self._encode_state(workspace, candidate)
        if len(projected) > self._state_byte_limit(workspace, candidate, required=len(projected)):
            return None
        return candidate

    @classmethod
    def _resolve_delivered(cls, state: _WorkspaceState) -> None:
        """Clear the conditions a completed delivery disproves.

        A row that reached the service and was acknowledged is live evidence that the service was
        reachable, the vault was open, and the outbox is no longer over its bound.
        """

        for code in (
            ObservationGapCode.SERVICE_UNAVAILABLE.value,
            ObservationGapCode.VAULT_LOCKED.value,
            _LOCAL_OUTBOX_OVERFLOW_GAP,
        ):
            cls._resolve_gap_state(state, code)

    @staticmethod
    def _resolve_gap_state(state: _WorkspaceState, gap_code: str) -> None:
        assert state.gaps is not None
        prior = state.gaps.get(gap_code)
        if prior is not None:
            state.gaps[gap_code] = _GapState(prior.first_seen, prior.last_seen, False)

    def trust_policy_digest(self, workspace: str, policy_digest: str) -> None:
        """Persist a tamper-evident local activation cache for one exact digest.

        The task-bundle repository remains the authoritative encrypted trust
        record. This cache contains no argv or content and cannot activate a
        different byte digest.
        """

        import hashlib
        import hmac

        if (
            type(policy_digest) is not str
            or not policy_digest.startswith("sha256:")
            or len(policy_digest) != 71
        ):
            raise ProtocolValueError("invalid_approved_check_policy")
        with self._lock:
            state = self._load(workspace)
            state.trusted_policy_digest = policy_digest
            state.trusted_policy_mac = hmac.new(
                self.key_material(),
                b"yoetz/check-policy-trust/v1\0"
                + workspace.encode("ascii")
                + b"\0"
                + policy_digest.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            self._save(workspace, state)

    @_read_mostly
    def policy_digest_is_trusted(self, workspace: str, policy_digest: str) -> bool:
        import hashlib
        import hmac

        with self._reading():
            state = self._load(workspace)
            expected = hmac.new(
                self.key_material(),
                b"yoetz/check-policy-trust/v1\0"
                + workspace.encode("ascii")
                + b"\0"
                + policy_digest.encode("ascii"),
                hashlib.sha256,
            ).hexdigest()
            return (
                state.trusted_policy_digest == policy_digest
                and state.trusted_policy_mac is not None
                and hmac.compare_digest(state.trusted_policy_mac, expected)
            )

    def revoke_policy_trust(self, workspace: str) -> None:
        with self._lock:
            state = self._load(workspace)
            state.trusted_policy_digest = None
            state.trusted_policy_mac = None
            self._save(workspace, state)

    def ingest(
        self,
        envelope: ObservationEnvelope,
        *,
        workspace_commitment: str | None = None,
    ) -> ObservationIngestResult:
        """Durably ingest one envelope, optionally at an explicit local workspace.

        The explicit workspace is a hook-only fallback for an observation whose
        session membership could not be created because its nonblocking
        lifecycle reservation was busy. It selects the already-consented target
        state without mutating session ownership; ordinary callers continue to
        resolve the workspace from the envelope's bound session commitment.
        """

        if type(envelope) is not ObservationEnvelope:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation envelope is invalid.",
                retryable=False,
            )
        with self._lock:
            if workspace_commitment is None:
                try:
                    workspace = self._workspace_for_envelope(envelope)
                except PublicOperationError:
                    return ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.CONSENT_MISSING.value,
                        None,
                    )
            else:
                try:
                    workspace = validate_commitment(workspace_commitment)
                except ProtocolValueError:
                    return ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.CONSENT_MISSING.value,
                        None,
                    )
                if self._session_workspace_owners_unlocked(envelope.session_commitment) - {
                    workspace
                }:
                    return ObservationIngestResult(
                        ObservationIngestDisposition.REJECTED,
                        ObservationGapCode.CONSENT_MISSING.value,
                        None,
                    )
            state = self._load(workspace)
            consent = state.consent
            if consent is None:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CONSENT_MISSING.value,
                    None,
                )
            if consent.revoked_at is not None:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CONSENT_REVOKED.value,
                    None,
                )
            if consent.paused:
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    "paused",
                    None,
                )
            if workspace_commitment is not None:
                assert state.session_workspaces is not None
                state.session_workspaces.setdefault(envelope.session_commitment, workspace)
            assert state.dedup is not None
            assert state.dedup_order is not None
            assert state.dedup_lanes is not None
            assert state.cursors is not None
            assert state.envelopes is not None
            assert state.gaps is not None
            assert state.unsupported_events is not None
            self._hydrate_dedup_metadata(workspace, state)
            key = _dedup_key(workspace, envelope)
            if key in state.dedup:
                cursor = state.cursors.get(
                    _cursor_key(envelope.source, envelope.session_commitment)
                )
                return ObservationIngestResult(
                    ObservationIngestDisposition.DUPLICATE,
                    "duplicate",
                    cursor,
                )
            cursor_key = _cursor_key(envelope.source, envelope.session_commitment)
            existing = state.cursors.get(cursor_key)
            if existing is not None and envelope.cursor.is_stale_relative_to(existing):
                self._note_gap_state(state, ObservationGapCode.CURSOR_STALE.value)
                self._save(workspace, state)
                return ObservationIngestResult(
                    ObservationIngestDisposition.REJECTED,
                    ObservationGapCode.CURSOR_STALE.value,
                    existing,
                )
            state.dedup.add(key)
            state.dedup_order.append(key)
            state.dedup_lanes[key] = envelope.session_commitment
            state.selection_observed_count = min(
                _MAX_SAFE_INTEGER, state.selection_observed_count + 1
            )
            while len(state.dedup_order) > _MAX_DEDUP:
                evicted_key = self._select_dedup_eviction_key(state)
                if evicted_key is None:
                    break
                state.dedup_order.remove(evicted_key)
                state.dedup.discard(evicted_key)
                evicted_session = state.dedup_lanes.pop(evicted_key, None)
                self._note_gap_state(state, _LOCAL_DEDUP_EVICTED_GAP)
                self._note_gap_state(state, ObservationGapCode.TRUNCATED_PAYLOAD.value)
                if evicted_session is not None:
                    self._note_session_gap_state(state, evicted_session, _LOCAL_DEDUP_EVICTED_GAP)
                    self._note_session_gap_state(
                        state, evicted_session, ObservationGapCode.TRUNCATED_PAYLOAD.value
                    )
            state.cursors[cursor_key] = envelope.cursor
            if envelope.source is ObservationSource.CODEX_HOOK and envelope.event_kind in {
                "PreToolUse",
                "PostToolUse",
            }:
                self._note_codex_tool_hook(state, envelope.session_commitment)
            if envelope.source is ObservationSource.CODEX_HOOK and envelope.event_kind in {
                "Stop",
                "SessionEnd",
            }:
                self._forget_evicted_open_calls(state, envelope.session_commitment)
            state.envelopes.append(envelope)
            if len(state.envelopes) > _MAX_ENVELOPES:
                state.envelopes_truncated = True
                evicted_index = self._fair_envelope_index(state.envelopes)
                if evicted_index is not None:
                    evicted = state.envelopes.pop(evicted_index)
                    self._note_evicted_tool_call(state, evicted)
                    self._note_gap_state(state, _LOCAL_ENVELOPE_RETENTION_GAP)
                    self._note_gap_state(state, ObservationGapCode.TRUNCATED_PAYLOAD.value)
                    self._note_session_gap_state(
                        state,
                        evicted.session_commitment,
                        _LOCAL_ENVELOPE_RETENTION_GAP,
                    )
                    self._note_session_gap_state(
                        state,
                        evicted.session_commitment,
                        ObservationGapCode.TRUNCATED_PAYLOAD.value,
                    )
            state.last_receipt = envelope.receipt_time
            mono_ms = int(self._now_mono() * 1000)
            state.monotonic_epoch = self._boot_epoch()
            if envelope.source in {
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CODEX_HOOK,
                ObservationSource.CURSOR_HOOK,
            }:
                state.last_hook_receipt_mono_ms = mono_ms
            else:
                state.last_stream_reconcile_mono_ms = mono_ms
            # Accepting an envelope is live proof the cursor advanced past whatever was stale.
            # Content capture is only proven by an envelope that actually carried captured
            # content, so it clears on that narrower evidence and not on ingest alone.
            self._resolve_gap_state(state, ObservationGapCode.CURSOR_STALE.value)
            if envelope.content_object_refs:
                self._resolve_gap_state(state, ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            assert state.codex_session_bindings is not None
            assert state.storage_corrupt_sessions is not None
            repaired_sessions = {
                codex_session_id
                for codex_session_id, commitment in state.codex_session_bindings.items()
                if commitment == envelope.session_commitment
            }
            state.storage_corrupt_sessions.difference_update(repaired_sessions)
            if not state.storage_corrupt_sessions:
                self._resolve_gap_state(state, ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)
            if (
                ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
                and not _is_post_only_profile(envelope)
            ):
                # A generic paired ingress row carries no proof that all historical orphan
                # identities remain retained. Keep pairing history unknown until a complete
                # provenance-aware writer can establish otherwise.
                state.pairing_state_unknown = True
            for gap in envelope.gap_codes:
                self._note_gap_state(state, gap)
            if ObservationGapCode.UNSUPPORTED_EVENT.value in envelope.gap_codes:
                state.unsupported_events.add(envelope.event_kind)
            self._save(workspace, state)
            return ObservationIngestResult(
                ObservationIngestDisposition.ACCEPTED,
                None,
                envelope.cursor,
            )

    def ingest_with_pairing(
        self,
        envelope: ObservationEnvelope,
        *,
        workspace_commitment: str,
        pairing_mode: str,
        correlation_id: str | None,
        source: ObservationSource,
        session_commitment: str,
        source_generation: int,
        is_pre_event: bool,
        is_post_event: bool,
    ) -> tuple[ObservationIngestResult, ObservationEnvelope]:
        """Atomically admit one hook envelope and update its pairing state.

        The batch is owned here when a direct caller has not already opened
        one. Hook ingress opens an outer batch so its outbox enqueue remains in
        the same local transaction; nested use keeps that transaction intact.
        """

        if type(envelope) is not ObservationEnvelope:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation envelope is invalid.",
                retryable=False,
            )
        if type(workspace_commitment) is not str:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation workspace is invalid.",
                retryable=False,
            )
        try:
            validate_commitment(workspace_commitment)
        except ProtocolValueError as exc:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation workspace is invalid.",
                retryable=False,
            ) from exc
        expected_mode, expected_kind = _envelope_pairing_contract(envelope)
        expected_correlation = _envelope_pairing_correlation(envelope, expected_kind)
        expected_pre = envelope.event_kind in {
            "PreToolUse",
            "PreCompact",
            "SubagentStart",
            "PermissionRequest",
        }
        expected_post = envelope.event_kind in {
            "PostToolUse",
            "PostCompact",
            "SubagentStop",
        }
        if (
            source is not envelope.source
            or session_commitment != envelope.session_commitment
            or type(source_generation) is not int
            or source_generation != envelope.cursor.source_generation
            or type(is_pre_event) is not bool
            or type(is_post_event) is not bool
            or is_pre_event is not expected_pre
            or is_post_event is not expected_post
            or pairing_mode != expected_mode
            or correlation_id != expected_correlation
        ):
            raise ProtocolValueError("invalid_event_value_type")
        with self.batched(workspace_commitment):
            return self._ingest_with_pairing(
                envelope,
                workspace_commitment=workspace_commitment,
                pairing_mode=expected_mode,
                correlation_id=expected_correlation,
                source=envelope.source,
                session_commitment=envelope.session_commitment,
                source_generation=envelope.cursor.source_generation,
                is_pre_event=expected_pre,
                is_post_event=expected_post,
            )

    def _ingest_with_pairing(
        self,
        envelope: ObservationEnvelope,
        *,
        workspace_commitment: str,
        pairing_mode: str,
        correlation_id: str | None,
        source: ObservationSource,
        session_commitment: str,
        source_generation: int,
        is_pre_event: bool,
        is_post_event: bool,
    ) -> tuple[ObservationIngestResult, ObservationEnvelope]:
        """Admit one hook envelope and update its pairing state atomically.

        Pairing is part of durable admission, rather than a probe performed
        before ``ingest`` and a follow-up mutation afterwards.  The caller
        receives the exact envelope that was admitted, including an orphan
        gap when the post had no matching pre.  This keeps the retained
        envelope, outbox row, and materialized receipt on the same side of a
        concurrent duplicate/reorder race.

        The public wrapper owns the batch for direct callers; this internal
        method runs inside that batch and keeps the lock held through the
        envelope rewrite.
        """

        if type(envelope) is not ObservationEnvelope:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation envelope is invalid.",
                retryable=False,
            )
        if type(workspace_commitment) is not str:
            raise _error(
                PublicErrorCode.INVALID_REQUEST,
                "Observation workspace is invalid.",
                retryable=False,
            )
        paired = pairing_mode == "paired"
        pairing_pre_open = False
        original_envelope = envelope
        with self._lock:
            # Generic host-call pairing covers the tool pre/post protocol only.
            # Child/lifecycle events carry their own lineage identity; a
            # parent tool id on a SubagentStart must not leave a synthetic
            # open-pre entry waiting for SubagentStop (which is not a tool
            # result and cannot consume that entry).
            if (
                paired
                and correlation_id is not None
                and is_pre_event
                and envelope.event_kind == "PreToolUse"
            ):
                # Check the pending-attempt bound before ingesting the new
                # envelope.  ``note_open_pre`` repeats the check after the
                # envelope is durably retained, but the returned envelope
                # needs the typed reason when this new identity cannot be
                # paired without evicting an older one.
                state = self._load(workspace_commitment)
                assert state.open_pre is not None
                pre_key = _pairing_key(
                    source=source,
                    session_commitment=session_commitment,
                    source_generation=source_generation,
                    correlation_id=correlation_id,
                )
                if pre_key not in state.open_pre and len(state.open_pre) >= _MAX_OPEN_PRE:
                    envelope = dataclasses.replace(
                        envelope,
                        gap_codes=tuple(
                            sorted(
                                {
                                    *envelope.gap_codes,
                                    _PENDING_ATTEMPT_LIMIT_GAP,
                                },
                                key=str.encode,
                            )
                        ),
                    )
            if paired and is_post_event and envelope.event_kind == "PostToolUse":
                if correlation_id is None:
                    # A paired carrier that emits a result without a tool-call identity is an
                    # orphan observation. Post-only profiles never enter this branch.
                    envelope = dataclasses.replace(
                        envelope,
                        gap_codes=tuple(
                            sorted(
                                {
                                    *envelope.gap_codes,
                                    ObservationGapCode.UNPAIRED_EVENT.value,
                                },
                                key=str.encode,
                            )
                        ),
                    )
                else:
                    pairing_pre_open = self.has_open_pre(
                        workspace_commitment,
                        correlation_id,
                        source=source,
                        session_commitment=session_commitment,
                        source_generation=source_generation,
                    )
                    if not pairing_pre_open:
                        envelope = dataclasses.replace(
                            envelope,
                            gap_codes=tuple(
                                sorted(
                                    {
                                        *envelope.gap_codes,
                                        ObservationGapCode.UNPAIRED_EVENT.value,
                                    },
                                    key=str.encode,
                                )
                            ),
                        )

            result = self.ingest(envelope, workspace_commitment=workspace_commitment)
            if result.disposition is not ObservationIngestDisposition.ACCEPTED:
                # Pairing is probed before admission so an accepted orphan can
                # retain its diagnostic on the same envelope.  A duplicate
                # must receive the canonical input instead: returning the
                # probe's synthetic gap would make an idempotent replay look
                # like a second retained orphan.
                if result.disposition is ObservationIngestDisposition.DUPLICATE:
                    state = self._load(workspace_commitment)
                    duplicate_key = _dedup_key(workspace_commitment, original_envelope)
                    for retained in reversed(state.envelopes or ()):
                        if _dedup_key(workspace_commitment, retained) == duplicate_key:
                            return result, retained
                return result, original_envelope

            if (
                paired
                and correlation_id is not None
                and is_pre_event
                and envelope.event_kind == "PreToolUse"
            ):
                self.note_open_pre(
                    workspace_commitment,
                    correlation_id,
                    envelope.event_kind,
                    source=source,
                    session_commitment=session_commitment,
                    source_generation=source_generation,
                    receipt_time=envelope.receipt_time,
                )
            elif paired and is_post_event and envelope.event_kind == "PostToolUse":
                if correlation_id is None:
                    self.note_unpaired_event(
                        workspace_commitment,
                        source=source,
                        session_commitment=session_commitment,
                        source_generation=source_generation,
                        source_identity=envelope.source_identity,
                    )
                elif pairing_pre_open:
                    # With the lock held, a true pre cannot disappear between
                    # the probe and consume. Treat an unexpected miss as an
                    # orphan anyway so the durable result stays conservative.
                    consumed = self.consume_open_pre(
                        workspace_commitment,
                        correlation_id,
                        source=source,
                        session_commitment=session_commitment,
                        source_generation=source_generation,
                    )
                    if consumed is None:
                        envelope = dataclasses.replace(
                            envelope,
                            gap_codes=tuple(
                                sorted(
                                    {
                                        *envelope.gap_codes,
                                        ObservationGapCode.UNPAIRED_EVENT.value,
                                    },
                                    key=str.encode,
                                )
                            ),
                        )
                        state = self._load(workspace_commitment)
                        assert state.envelopes is not None
                        for index in range(len(state.envelopes) - 1, -1, -1):
                            retained = state.envelopes[index]
                            if retained.source_identity == envelope.source_identity:
                                state.envelopes[index] = envelope
                                self._save(workspace_commitment, state)
                                break
                        self.note_unpaired_event(
                            workspace_commitment,
                            source=source,
                            session_commitment=session_commitment,
                            source_generation=source_generation,
                            source_identity=envelope.source_identity,
                        )
                else:
                    self.note_unpaired_event(
                        workspace_commitment,
                        source=source,
                        session_commitment=session_commitment,
                        source_generation=source_generation,
                        source_identity=envelope.source_identity,
                    )
            return result, envelope

    @_read_mostly
    def status(self, query: ObservationStatusQuery) -> ObservationStatus:
        with self._reading():
            return self._status_unlocked(query.workspace_commitment)

    def pause(self, command: ObservationControlCommand) -> ObservationStatus:
        with self._lock:
            state = self._load(command.workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            if consent.revoked_at is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is revoked.",
                    retryable=False,
                )
            next_consent = LocalObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=consent.revoked_at,
                paused=True,
                content_capture_profiles=consent.content_capture_profiles,
            )
            if next_consent != consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            self._save(command.workspace_commitment, state)
            return self._status_unlocked(command.workspace_commitment)

    def resume(self, command: ObservationControlCommand) -> ObservationStatus:
        with self._lock:
            state = self._load(command.workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            if consent.revoked_at is not None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is revoked.",
                    retryable=False,
                )
            next_consent = LocalObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=None,
                paused=False,
                content_capture_profiles=consent.content_capture_profiles,
            )
            if next_consent != consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            self._save(command.workspace_commitment, state)
            return self._status_unlocked(command.workspace_commitment)

    def revoke(self, command: ObservationRevokeCommand) -> ObservationStatus:
        with self._lock:
            state = self._load(command.workspace_commitment)
            consent = state.consent
            if consent is None:
                raise _error(
                    PublicErrorCode.INVALID_REQUEST,
                    "Observation consent is missing.",
                    retryable=False,
                )
            revoked_at = consent.revoked_at or (
                state.last_receipt if state.last_receipt is not None else consent.granted_at
            )
            if consent.revoked_at is None:
                state.pending_consent_revocation = canonical_digest(
                    JsonObject(
                        {
                            "workspace_commitment": consent.workspace_commitment,
                            "granted_at": consent.granted_at.wire,
                            "revoked_at": revoked_at.wire,
                        }
                    )
                )
                state.pending_consent_projects = None
            next_consent = LocalObservationConsent(
                workspace_commitment=consent.workspace_commitment,
                granted_at=consent.granted_at,
                revoked_at=revoked_at,
                paused=True,
                content_capture_profiles=(),
            )
            if next_consent != consent:
                _rotate_content_capture_epoch(state)
            state.consent = next_consent
            self._save(command.workspace_commitment, state)
            return self._status_unlocked(command.workspace_commitment)

    def batched(self, workspace_commitment: str) -> _ObservationBatch:
        """Hold one workspace transaction; serialize once on successful exit.

        Durability trade-off: a SIGKILL inside a batch loses that batch's local
        mutations rather than only the tail. That matches the outbox's design —
        an un-acked row is retried, a lost envelope is re-ingested or recovered
        by stream reconcile — but callers MUST close the batch before any
        service RPC so an outbox acknowledgement can never become durable ahead
        of the ingest it acknowledges, and MUST NOT span a network wait: the
        batch holds the interprocess store lock for its whole duration. An
        exception rolls back the current batch, including a nested savepoint,
        so ingest identity cannot commit without its selected admission.
        """
        caller = sys._getframe(1).f_code.co_name  # noqa: SLF001  # pyright: ignore[reportPrivateUsage]
        return _ObservationBatch(self, workspace_commitment, caller)

    def _workspace_path(self, workspace_commitment: str) -> Path:
        digest = workspace_commitment.removeprefix("hmac-sha256:")
        if len(digest) != 64:
            raise ProtocolValueError("invalid_commitment")
        return self._root / "workspaces" / f"{digest}.json"

    def _iter_workspaces(self) -> list[tuple[str, _WorkspaceState]]:
        directory = self._root / "workspaces"
        if not directory.is_dir():
            return []
        result: list[tuple[str, _WorkspaceState]] = []
        for path in directory.glob("*.json"):
            if path.is_symlink() or not path.is_file():
                continue
            digest = path.stem
            workspace = f"hmac-sha256:{digest}"
            result.append((workspace, self._load(workspace)))
        return result

    def _stat_key(self, path: Path) -> tuple[int, int, int, int] | None:
        try:
            if path.is_symlink():
                return None
            facts = path.stat()
        except OSError:
            return None
        return (facts.st_ino, facts.st_size, facts.st_mtime_ns, facts.st_ctime_ns)

    def _cache_state(
        self,
        workspace_commitment: str,
        key: tuple[int, int, int, int],
        state: _WorkspaceState,
    ) -> None:
        entry = (key, _copy_state(state))
        with self._cache_guard:
            self._state_cache.pop(workspace_commitment, None)
            self._state_cache[workspace_commitment] = entry
            while len(self._state_cache) > _MAX_STATE_CACHE_ENTRIES:
                self._state_cache.pop(next(iter(self._state_cache)))

    def _drop_cached_state(self, workspace_commitment: str) -> None:
        with self._cache_guard:
            self._state_cache.pop(workspace_commitment, None)

    def _prewarm(self, workspace_commitment: str) -> None:
        """Parse the committed document into the cache without the store lock.

        A no-op when the cache already matches the file. The parse is only a
        cache fill: the locked transaction still re-validates the file
        identity and re-reads under the lock if a writer committed meanwhile.
        """

        with contextlib.suppress(Exception):
            path = self._workspace_path(workspace_commitment)
            key = self._stat_key(path)
            if key is None:
                return
            with self._cache_guard:
                cached = self._state_cache.get(workspace_commitment)
            if cached is None or cached[0] != key:
                self._load(workspace_commitment)
                with self._cache_guard:
                    cached = self._state_cache.get(workspace_commitment)
            if cached is not None:
                # Encode each immutable member once here, outside the lock, so
                # the transaction's size projections and save only splice.
                _prime_codec(cached[1])

    @contextlib.contextmanager
    def _reading(self) -> Generator[None]:
        """Serve the enclosed reads from committed state unless this thread holds the lock.

        A write inside raises :class:`_LockedWriteRequired`; :func:`_read_mostly`
        methods turn that into one rerun under the store lock.
        """

        if self._lock.held_by_current_thread():
            yield
            return
        depth = _optimistic_read_depth()
        _OPTIMISTIC_READS.depth = depth + 1
        try:
            yield
        finally:
            _OPTIMISTIC_READS.depth = depth

    def _read[ResultT](self, operation: Callable[[], ResultT]) -> ResultT:
        """Run a read-mostly operation against the committed state, lock-free.

        Every workspace document is replaced atomically, so a read outside the
        lock observes exactly one committed version, as a locked read would at
        a slightly different instant. Pure reads therefore never queue behind
        a hook batch or a sweep (#689). If the operation reaches a write (a
        legacy repair on first read, for example) its in-memory copy is
        discarded and it reruns under the store lock. A caller that already
        holds the lock keeps reading its own open transaction.
        """

        if self._lock.held_by_current_thread():
            return operation()
        depth = _optimistic_read_depth()
        _OPTIMISTIC_READS.depth = depth + 1
        try:
            return operation()
        except _LockedWriteRequired:
            pass
        finally:
            _OPTIMISTIC_READS.depth = depth
        with self._lock:
            return operation()

    def _load(self, workspace_commitment: str) -> _WorkspaceState:
        # Only the lock owner may see an open batch: another thread's batch is
        # uncommitted, and a committed read must see the file instead.
        if self._lock.held_by_current_thread():
            held = self._batch.get(workspace_commitment)
            if held is not None:
                return held
        path = self._workspace_path(workspace_commitment)
        before = self._stat_key(path)
        with self._cache_guard:
            cached = self._state_cache.get(workspace_commitment)
        if cached is not None and before is not None and cached[0] == before:
            return _copy_state(cached[1])
        raw = _read_bytes(path, maximum=_MAX_LEGACY_STATE_BYTES)
        if raw is None:
            return _WorkspaceState()
        hydrate_started = self._now_mono()
        try:
            try:
                parsed = strict_json_parse(raw, validate=False)
                envelope_keys = _validate_state_document(parsed)
            except ProtocolValueError:
                return _WorkspaceState()
            if not isinstance(parsed, Mapping):
                return _WorkspaceState()
            state = self._state_from_json(
                cast(Mapping[str, JsonValue], parsed), envelope_keys=envelope_keys
            )
            self._hydrate_dedup_metadata(workspace_commitment, state)
        finally:
            self.stage_timings_ms["hydrate"] += (self._now_mono() - hydrate_started) * 1000
        # Cache only when the file provably did not change while it was read.
        if before is not None and before == self._stat_key(path):
            self._cache_state(workspace_commitment, before, state)
        return state

    def _prune_expired_quarantine(self, state: _WorkspaceState) -> None:
        assert state.quarantine is not None
        if not state.quarantine:
            return
        # Fence the destructive path on a trusted clock, like every other
        # wall-time consumer in this module: after a reboot, snapshot restore,
        # or clock jump the persisted epoch disagrees and pruning is skipped
        # until fresh progress re-establishes it. Age is measured from the
        # store-authored quarantined_at, never the (possibly far older)
        # envelope receipt time.
        if not self._epoch_matches(state.monotonic_epoch):
            return
        horizon = datetime.fromtimestamp(self._wall_now(), UTC) - timedelta(
            days=_MAX_QUARANTINE_AGE_DAYS
        )
        # RFC3339 wire strings at fixed precision order lexicographically, so
        # this hot-path comparison never reparses timestamps.
        horizon_wire = timestamp_from_datetime(
            horizon.replace(microsecond=(horizon.microsecond // 1000) * 1000)
        ).wire
        kept: list[tuple[str, ObservationEnvelope, str, Timestamp]] = []
        for entry in state.quarantine:
            if entry[3].wire < horizon_wire:
                self._record_quarantine_eviction(state, entry[0], entry[1], entry[2])
            else:
                kept.append(entry)
        if len(kept) != len(state.quarantine):
            state.quarantine[:] = kept

    def _prune_frontier_motion_notices(self, state: _WorkspaceState) -> None:
        """Drop ended-session notices and delivered marks; cap both mappings."""

        ended = state.ended_sessions or set()
        bindings = state.codex_session_bindings or {}

        def _session_ended(session_id: str) -> bool:
            commitment = bindings.get(session_id)
            return commitment is not None and commitment in ended

        notices = state.frontier_motion_notices
        if notices:
            for session_id in tuple(notices):
                if _session_ended(session_id):
                    del notices[session_id]
            while len(notices) > _MAX_FRONTIER_MOTION_NOTICES:
                oldest = min(
                    notices,
                    key=lambda session_id: (
                        notices[session_id].recency_ordinal,
                        session_id.encode(),
                    ),
                )
                del notices[oldest]
        delivered = state.frontier_motion_delivered
        if delivered:
            for session_id in tuple(delivered):
                if _session_ended(session_id):
                    del delivered[session_id]
            while len(delivered) > _MAX_FRONTIER_MOTION_NOTICES:
                oldest = min(
                    delivered,
                    key=lambda session_id: (
                        delivered[session_id].recency_ordinal,
                        session_id.encode(),
                    ),
                )
                del delivered[oldest]

    @staticmethod
    def _session_commitment_for_key(key: str) -> str | None:
        """Return a session commitment encoded as a direct or cursor-map key."""

        candidate = key
        if not candidate.startswith("hmac-sha256:"):
            _prefix, separator, suffix = candidate.partition(":")
            if not separator:
                return None
            candidate = suffix
        try:
            return validate_commitment(candidate)
        except ProtocolValueError, TypeError, ValueError:
            return None

    @staticmethod
    def _session_replay_protected(state: _WorkspaceState) -> set[str]:
        """Find sessions whose replay state is still needed by live work."""

        ended = state.ended_sessions or set()
        protected = {
            session for session in (state.session_workspaces or {}) if session not in ended
        }
        protected.update((state.codex_session_bindings or {}).values())
        protected.update(state.storage_corrupt_sessions or ())
        protected.update(row.envelope.session_commitment for row in (state.pending_outbox or ()))
        protected.update(
            envelope.session_commitment
            for _codex_session_id, envelope, _reason, _quarantined_at in (state.quarantine or ())
        )
        protected.update(intent.session_commitment for intent in (state.pending_lifecycles or ()))
        return protected

    @classmethod
    def _trim_session_mapping(
        cls,
        mapping: MutableMapping[str, _SessionMapValue] | None,
        protected: set[str],
    ) -> bool:
        """Trim one session keyed map, preserving keys needed by live work."""

        if mapping is None or len(mapping) <= _MAX_SESSION_REPLAY_KEYS:
            return False
        candidates = sorted(
            (key for key in mapping if cls._session_commitment_for_key(key) not in protected),
            key=str.encode,
        )
        changed = False
        while len(mapping) > _MAX_SESSION_REPLAY_KEYS and candidates:
            mapping.pop(candidates.pop(0), None)
            changed = True
        return changed

    @classmethod
    def _prune_session_replay_maps(cls, state: _WorkspaceState) -> bool:
        """Bound ended-session replay indexes while preserving live lanes."""

        protected = cls._session_replay_protected(state)
        changed = False
        generation_keys = set(state.session_generations or ())
        generation_keys.update(state.ended_session_generations or ())
        generation_keys.update(state.ended_sessions or ())
        tombstone_candidates = sorted(generation_keys - protected, key=str.encode)
        while len(generation_keys) > _MAX_SESSION_REPLAY_KEYS and tombstone_candidates:
            session = tombstone_candidates.pop(0)
            generation_keys.discard(session)
            if state.session_generations is not None:
                changed = state.session_generations.pop(session, None) is not None or changed
            if state.ended_session_generations is not None:
                changed = state.ended_session_generations.pop(session, None) is not None or changed
            if state.ended_sessions is not None and session in state.ended_sessions:
                state.ended_sessions.discard(session)
                changed = True

        direct_maps = (
            cast(MutableMapping[str, object] | None, state.session_workspaces),
            cast(MutableMapping[str, object] | None, state.cursors),
            cast(MutableMapping[str, object] | None, state.stream_cursors),
            cast(MutableMapping[str, object] | None, state.stream_partials),
            cast(MutableMapping[str, object] | None, state.stream_call_tools),
            cast(MutableMapping[str, object] | None, state.stream_call_tool_generations),
            cast(MutableMapping[str, object] | None, state.stream_source_identities),
            cast(MutableMapping[str, object] | None, state.stream_profiles),
            cast(MutableMapping[str, object] | None, state.hook_sequences),
            cast(MutableMapping[str, object] | None, state.session_advice_suppression),
        )
        for mapping in direct_maps:
            changed = cls._trim_session_mapping(mapping, protected) or changed

        if state.stream_partial_dropped_sessions is not None:
            candidates = sorted(
                session
                for session in state.stream_partial_dropped_sessions
                if session not in protected
            )
            while (
                len(state.stream_partial_dropped_sessions) > _MAX_SESSION_REPLAY_KEYS and candidates
            ):
                state.stream_partial_dropped_sessions.discard(candidates.pop(0))
                changed = True

        if state.session_gaps is not None and len(state.session_gaps) > _MAX_SESSION_REPLAY_KEYS:
            candidates = sorted(
                (session for session in state.session_gaps if session not in protected),
                key=str.encode,
            )
            while len(state.session_gaps) > _MAX_SESSION_REPLAY_KEYS and candidates:
                del state.session_gaps[candidates.pop(0)]
                changed = True

        if (
            state.dedup is not None
            and state.dedup_order is not None
            and state.dedup_lanes is not None
        ):
            for key in tuple(state.dedup_lanes):
                if key not in state.dedup:
                    del state.dedup_lanes[key]
                    changed = True
            while len(state.dedup_order) > _MAX_DEDUP:
                key = cls._select_dedup_eviction_key(state)
                if key is None:
                    break
                state.dedup_order.remove(key)
                state.dedup.discard(key)
                state.dedup_lanes.pop(key, None)
                changed = True
        return changed

    def _encode_state(self, workspace_commitment: str, state: _WorkspaceState) -> bytes:
        """Encode one state to its on-disk bytes, attributing the cost (#290)."""

        encode_started = self._now_mono()
        try:
            return canonical_encode(self._state_to_json(workspace_commitment, state)) + b"\n"
        finally:
            self.stage_timings_ms["encode"] += (self._now_mono() - encode_started) * 1000

    def _drop_oversized_stream_partials(self, state: _WorkspaceState) -> bool:
        """Enforce the per-entry partial bound on states persisted before #289."""

        partials = state.stream_partials
        dropped_sessions = state.stream_partial_dropped_sessions
        assert partials is not None
        assert dropped_sessions is not None
        oversized = [
            key for key, value in partials.items() if len(value) > _MAX_STREAM_PARTIAL_BYTES
        ]
        for key in oversized:
            del partials[key]
            dropped_sessions.add(key)
            self._note_gap_state(state, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)
        return bool(oversized)

    def _save(
        self,
        workspace_commitment: str,
        state: _WorkspaceState,
        *,
        projected: bytes | None = None,
    ) -> None:
        """Save one workspace state without leaking failed retention work.

        The bounded retention pass mutates the state before it knows whether
        the protected durable rows can fit. Keep that speculative work out of
        callers, batches, and the parse cache when the write is rejected.
        """

        if _optimistic_read_depth() and not self._lock.held_by_current_thread():
            raise _LockedWriteRequired
        if self._batch.get(workspace_commitment) is state:
            self._batch_dirty.add(workspace_commitment)
            return
        prior = _copy_state(state)
        try:
            self._save_unchecked(workspace_commitment, state, projected=projected)
        except BaseException:
            _restore_state(state, prior)
            raise

    def _save_unchecked(
        self,
        workspace_commitment: str,
        state: _WorkspaceState,
        *,
        projected: bytes | None = None,
    ) -> None:
        """Serialize one workspace state, trimming to the safe local bound.

        ``projected`` reuses bytes a caller already encoded for a size check;
        they are discarded when pruning mutated the state after that encode.
        """

        directory = self._root / "workspaces"
        _ensure_dir(directory)
        path = self._workspace_path(workspace_commitment)
        quarantined_before = len(state.quarantine or ())
        notices_before = len(state.frontier_motion_notices or ())
        delivered_before = len(state.frontier_motion_delivered or ())
        self._prune_expired_quarantine(state)
        self._prune_frontier_motion_notices(state)
        replay_maps_changed = self._prune_session_replay_maps(state)
        partials_dropped = self._drop_oversized_stream_partials(state)
        if (
            projected is not None
            and not replay_maps_changed
            and not partials_dropped
            and len(state.quarantine or ()) == quarantined_before
            and len(state.frontier_motion_notices or ()) == notices_before
            and len(state.frontier_motion_delivered or ()) == delivered_before
        ):
            payload = projected
        else:
            payload = self._encode_state(workspace_commitment, state)
        # Retention and the final check use the bound for this exact write,
        # which includes a finite over-target allowance when accepted rows
        # exceed a lowered selection (#843). Healing an eviction gap still
        # requires headroom under the ordinary bound.
        selected_limit = self._state_byte_limit(workspace_commitment, state)
        state_limit = self._state_byte_limit(workspace_commitment, state, required=len(payload))
        partials = state.stream_partials
        dropped_sessions = state.stream_partial_dropped_sessions
        assert partials is not None
        assert dropped_sessions is not None
        if partials and len(payload) > state_limit:
            # Preserve the existing largest-first read-cache removal order.
            order = sorted(
                partials, key=lambda key: (len(partials[key]), key.encode()), reverse=True
            )

            def drop_partials(candidate: _WorkspaceState, count: int) -> None:
                assert candidate.stream_partials is not None
                assert candidate.stream_partial_dropped_sessions is not None
                for key in order[:count]:
                    del candidate.stream_partials[key]
                    candidate.stream_partial_dropped_sessions.add(key)
                    self._note_gap_state(candidate, _LOCAL_STREAM_PARTIAL_DROPPED_GAP)

            payload = self._trim_retained_prefix(
                workspace_commitment, state, len(order), state_limit, drop_partials
            )
        truncated = False
        assert state.envelopes is not None
        if state.envelopes and len(payload) > state_limit:

            def drop_envelopes(candidate: _WorkspaceState, count: int) -> None:
                assert candidate.envelopes is not None
                for _ in range(min(count, len(candidate.envelopes))):
                    evicted_index = self._fair_envelope_index(candidate.envelopes)
                    if evicted_index is None:
                        break
                    evicted = candidate.envelopes.pop(evicted_index)
                    self._note_evicted_tool_call(candidate, evicted)
                    candidate.envelopes_truncated = True
                    self._note_gap_state(candidate, ObservationGapCode.TRUNCATED_PAYLOAD.value)
                    self._note_session_gap_state(
                        candidate,
                        evicted.session_commitment,
                        ObservationGapCode.TRUNCATED_PAYLOAD.value,
                    )

            payload = self._trim_retained_prefix(
                workspace_commitment, state, len(state.envelopes), state_limit, drop_envelopes
            )
            truncated = True
        assert state.pending_outbox is not None
        assert state.quarantine is not None
        assert state.gaps is not None
        # Pending rows are accepted durable records, never retention candidates.
        if state.quarantine and len(payload) > state_limit:

            def drop_quarantine(candidate: _WorkspaceState, count: int) -> None:
                assert candidate.quarantine is not None
                for session, envelope, reason, _ in candidate.quarantine[:count]:
                    self._record_quarantine_eviction(candidate, session, envelope, reason)
                del candidate.quarantine[:count]

            payload = self._trim_retained_prefix(
                workspace_commitment, state, len(state.quarantine), state_limit, drop_quarantine
            )
        if len(payload) > state_limit:
            raise _error(
                PublicErrorCode.STORAGE_UNSAFE,
                "Observation state exceeds its safe local bound.",
                retryable=False,
            )
        truncation = state.gaps.get(ObservationGapCode.TRUNCATED_PAYLOAD.value)
        if (
            not truncated
            and truncation is not None
            and truncation.active
            and len(payload) + selected_limit // _STATE_HEADROOM_DIVISOR <= selected_limit
        ):
            # Landing with a full headroom margin, having shed nothing, is live
            # proof the store is no longer losing observations to the bound.
            # Landing merely *under* the bound proves nothing — that is the
            # state an eviction itself leaves behind, so clearing there would
            # retire the gap in the same pass that opened it. History stays in
            # gap_history; only the active flag, which reports live
            # degradation, is cleared (#310).
            assert state.session_gaps is not None
            bounded_count_loss = any(
                state.gaps.get(code) is not None and state.gaps[code].active
                for code in (_LOCAL_DEDUP_EVICTED_GAP, _LOCAL_ENVELOPE_RETENTION_GAP)
            ) or any(
                _LOCAL_DEDUP_EVICTED_GAP in gaps or _LOCAL_ENVELOPE_RETENTION_GAP in gaps
                for gaps in state.session_gaps.values()
            )
            # A session-scoped retention gap is independent of a sibling's history. Once the
            # workspace is healthy again, retire only the TRUNCATED marker for lanes that have no
            # remaining local count loss; the lane-specific loss markers stay active while their
            # bounded caches continue to be incomplete.
            for session, gaps in tuple(state.session_gaps.items()):
                if not (_LOCAL_DEDUP_EVICTED_GAP in gaps or _LOCAL_ENVELOPE_RETENTION_GAP in gaps):
                    self._resolve_session_gap_state(
                        state,
                        ObservationGapCode.TRUNCATED_PAYLOAD.value,
                        session,
                    )
            if not bounded_count_loss:
                self._resolve_gap_state(state, ObservationGapCode.TRUNCATED_PAYLOAD.value)
                self._resolve_gap_state(state, _LOCAL_DEDUP_EVICTED_GAP)
                self._resolve_session_gap_state(state, _LOCAL_DEDUP_EVICTED_GAP)
            payload = self._encode_state(workspace_commitment, state)
        write_started = self._now_mono()
        _atomic_write(path, payload)
        self.stage_timings_ms["write"] += (self._now_mono() - write_started) * 1000
        key = self._stat_key(path)
        if key is None:
            self._drop_cached_state(workspace_commitment)
        else:
            self._cache_state(workspace_commitment, key, state)

    def _trim_retained_prefix(
        self,
        workspace: str,
        state: _WorkspaceState,
        count: int,
        limit: int,
        remove: Callable[[_WorkspaceState, int], None],
    ) -> bytes:
        """Choose the smallest fitting retention prefix with logarithmic encodes.

        Probe copies only: loss commitments and pending records in the held
        transaction change once, after selection. If the entire optional class
        cannot fit, remove it before considering the next retention class.
        The final encode remains authoritative and the enclosing save retains
        its STORAGE_UNSAFE rollback if protected state alone cannot fit.
        """

        low, high = 1, count
        while low < high:
            middle = (low + high) // 2
            candidate = _copy_state(state)
            remove(candidate, middle)
            if len(self._encode_state(workspace, candidate)) <= limit:
                high = middle
            else:
                low = middle + 1
        remove(state, low)
        return self._encode_state(workspace, state)

    def _record_quarantine_eviction(
        self,
        state: _WorkspaceState,
        codex_session_id: str,
        envelope: ObservationEnvelope,
        reason: str,
        *,
        reclaimed: bool = False,
    ) -> None:
        assert state.gaps is not None
        material = JsonObject(
            {
                "prior": state.quarantine_evicted_commitment,
                "session_commitment": envelope.session_commitment,
                "source_identity": envelope.source_identity,
                "source_commitment": envelope.cursor.last_source_commitment,
                "reason": reason,
                "reclaimed": reclaimed,
                "codex_session_commitment": session_commitment_from_codex_id(
                    self._cached_key_material(), codex_session_id
                ),
            }
        )
        state.quarantine_evicted_commitment = canonical_digest(material)
        if reclaimed:
            state.quarantine_reclaimed_count += 1
        else:
            state.quarantine_evicted_count += 1
        receipt = envelope.receipt_time
        if state.quarantine_evicted_first is None or receipt < state.quarantine_evicted_first:
            state.quarantine_evicted_first = receipt
        if state.quarantine_evicted_last is None or state.quarantine_evicted_last < receipt:
            state.quarantine_evicted_last = receipt
        self._note_gap_state(state, ObservationGapCode.QUARANTINE_DETAIL_EVICTED.value)
        self._note_session_gap_state(
            state,
            envelope.session_commitment,
            ObservationGapCode.QUARANTINE_DETAIL_EVICTED.value,
        )

    def _workspace_for_envelope(self, envelope: ObservationEnvelope) -> str:
        owners = self._session_workspace_owners_unlocked(envelope.session_commitment)
        if len(owners) == 1:
            return next(iter(owners))
        if owners:
            raise _error(
                PublicErrorCode.SESSION_CONFLICT,
                "Observation session has multiple workspace owners.",
                retryable=False,
            )
        active = [
            workspace
            for workspace, state in self._iter_workspaces()
            if state.consent is not None and state.consent.active
        ]
        if len(active) == 1:
            workspace = active[0]
            state = self._load(workspace)
            assert state.session_workspaces is not None
            state.session_workspaces[envelope.session_commitment] = workspace
            self._save(workspace, state)
            return workspace
        raise _error(
            PublicErrorCode.INVALID_REQUEST,
            "Observation workspace consent is missing.",
            retryable=False,
        )

    def _status_unlocked(self, workspace_commitment: str) -> ObservationStatus:
        from yoetz.application.observation_health import (
            DEFAULT_OBSERVATION_HEALTH_THRESHOLDS,
            ObservationHealthSignals,
            compute_observation_lifecycle,
        )

        state = self._load(workspace_commitment)
        consent = state.consent
        coverage = {
            ObservationSource.CLAUDE_HOOK: False,
            ObservationSource.CODEX_HOOK: False,
            ObservationSource.CODEX_SESSION_STREAM: False,
            ObservationSource.CURSOR_HOOK: False,
        }
        assert state.envelopes is not None
        assert state.cursors is not None
        assert state.gaps is not None
        assert state.unsupported_events is not None
        assert state.pending_outbox is not None
        assert state.session_workspaces is not None
        # The envelope list is a bounded diagnostic cache. Selected routine
        # entries can be reclaimed once their exact source identities are
        # represented by the durable admission buffer/outbox, so source
        # coverage must come from the authoritative cursor account as well.
        for cursor_key in state.cursors:
            raw_source, separator, _ = cursor_key.partition(":")
            if not separator:
                continue
            try:
                source = ObservationSource(raw_source)
            except ProtocolValueError, TypeError, ValueError:
                continue
            coverage[source] = True
        for envelope in state.envelopes:
            coverage[envelope.source] = True
        pending = len(state.pending_outbox)
        last_hook = (
            None
            if state.last_hook_receipt_mono_ms is None
            else state.last_hook_receipt_mono_ms / 1000.0
        )
        last_stream = (
            None
            if state.last_stream_reconcile_mono_ms is None
            else state.last_stream_reconcile_mono_ms / 1000.0
        )
        last_drain = (
            None
            if state.last_successful_drain_mono_ms is None
            else state.last_successful_drain_mono_ms / 1000.0
        )
        # Fence persisted monotonic samples to their boot epoch. After a restart
        # or reboot the monotonic clock is incomparable, so drop the stale
        # samples; lifecycle then reports DEGRADED until fresh qualifying
        # progress arrives in the current epoch instead of trusting bad ages.
        if not self._epoch_matches(state.monotonic_epoch):
            last_hook = None
            last_stream = None
            last_drain = None
        consent_active = consent is not None and consent.revoked_at is None and not consent.paused
        mapping_available = bool(state.session_workspaces) or bool(state.codex_session_bindings)
        pairing_gap_reconciled = self._reconcile_legacy_unpaired_gap(state)
        if pairing_gap_reconciled:
            # Status is the first durable read after an upgrade that can
            # observe this legacy false diagnostic.  Preserve its inactive
            # history while making the current projection honest.
            self._save(workspace_commitment, state)
        current_gaps = self._current_gaps(
            state, workspace_commitment=workspace_commitment, mapping_available=mapping_available
        )
        bound_sessions = set(state.session_workspaces)
        ended_sessions = state.ended_sessions or set()
        # STOPPED once every bound session has ended (consent-stop is handled in
        # compute_observation_lifecycle via consent_active).
        session_ended = bool(bound_sessions) and bound_sessions <= ended_sessions
        signals = ObservationHealthSignals(
            consent_active=consent_active,
            mapping_available=mapping_available,
            source_coverage=coverage,
            pending_outbox_count=pending,
            # Delivery backlog is reported independently as pending_outbox_count.
            # No source-frontier lag estimator is available at this local seam,
            # so never relabel undelivered rows as observed event lag.
            lag_events=0,
            gaps=current_gaps,
            unsupported_events=tuple(sorted(state.unsupported_events, key=str.encode)),
            advice_frontier=state.advice_frontier,
            last_hook_receipt_monotonic=last_hook,
            last_stream_advancement_monotonic=last_stream,
            last_successful_drain_monotonic=last_drain if pending == 0 else last_drain,
            session_ended=session_ended,
        )
        lifecycle = compute_observation_lifecycle(
            signals,
            now_monotonic=self._now_mono(),
            thresholds=DEFAULT_OBSERVATION_HEALTH_THRESHOLDS,
        )
        selection_runtime: ObservationSelectionRuntimeStatus | None = None
        try:
            selection_runtime = observation_selection_runtime_status_from_json(
                self.selection_runtime_status(workspace_commitment)
            )
        except OSError, ProtocolValueError, TypeError, ValueError, RuntimeError:
            # Selection status is an optional extension.  A legacy/corrupt
            # pressure projection must not hide the authoritative lifecycle
            # status or make a read fail open into invented budget facts.
            selection_runtime = None
        return ObservationStatus(
            lifecycle=lifecycle,
            workspace_commitment=workspace_commitment,
            source_coverage=coverage,
            last_observation_receipt_time=state.last_receipt,
            lag_events=0,
            gaps=current_gaps,
            unsupported_events=tuple(sorted(state.unsupported_events, key=str.encode)),
            advice_frontier=state.advice_frontier,
            selection_runtime=selection_runtime,
        )

    @staticmethod
    def _reconcile_legacy_unpaired_gap(state: _WorkspaceState) -> bool:
        """Retire only historical false post-only pairing diagnostics.

        Before issue #607, Claude and Cursor post-only hooks were fed through
        Codex's pre/post pairing path.  Their old envelopes may therefore
        carry ``unpaired_event`` even though no pre-event was part of the
        installed profile.  Resolve that current diagnostic only when every
        retained historical unpaired envelope belongs to an exact reviewed
        post-only profile and no scoped true orphan has been recorded.  The
        gap-history row remains immutable evidence of the old behavior.
        """

        prior = (state.gaps or {}).get(ObservationGapCode.UNPAIRED_EVENT.value)
        if (
            prior is None
            or not prior.active
            or state.unpaired_scopes
            or state.pairing_state_unknown
            or state.envelopes_truncated
        ):
            return False
        candidates = [
            envelope
            for envelope in (state.envelopes or ())
            if ObservationGapCode.UNPAIRED_EVENT.value in envelope.gap_codes
        ]
        if not candidates or not all(_is_post_only_profile(envelope) for envelope in candidates):
            return False
        LocalObservationStore._resolve_gap_state(state, ObservationGapCode.UNPAIRED_EVENT.value)
        return True

    def _current_gaps(
        self,
        state: _WorkspaceState,
        *,
        workspace_commitment: str,
        mapping_available: bool,
    ) -> tuple[str, ...]:
        """Project current observable gaps while retaining full history separately."""

        assert state.gaps is not None
        assert state.pending_outbox is not None
        assert state.quarantine is not None
        # Codes re-derived below from live state. Everything else reports its recorded active
        # flag, which ``_resolve_gap_state`` clears when a condition is observed to have healed.
        # Note that gap sightings are stamped with the local wall clock while ``last_receipt`` is
        # a caller-asserted envelope time, so the two are never compared: resolution is driven by
        # observed signals, never by ordering one clock against the other.
        transient = {
            ObservationGapCode.MAPPING_MISSING.value,
            ObservationGapCode.OUTBOX_OVERFLOW.value,
            ObservationGapCode.OUTBOX_QUARANTINED.value,
            _LOCAL_OUTBOX_OVERFLOW_GAP,
            _LOCAL_STREAM_PARTIAL_DROPPED_GAP,
            _LOCAL_DEDUP_EVICTED_GAP,
            _LOCAL_ENVELOPE_RETENTION_GAP,
        }
        # Current adapter failures come from unresolved pending attempts.
        # Successful replay retires the live cause; gap history and retained
        # quarantine causes remain independently available.
        transient.update(code for code in state.gaps if code.startswith("control_"))
        current = {code for code, seen in state.gaps.items() if seen.active} - transient
        current.update(
            row.last_reason
            for row in state.pending_outbox
            if row.last_reason is not None and row.last_reason.startswith("control_")
        )
        if state.unpaired_scopes:
            # A true paired-profile orphan is session/source/generation scoped
            # detail; it keeps the aggregate gap active until an explicit
            # operator-level repair, regardless of unrelated valid pairs.
            current.add(ObservationGapCode.UNPAIRED_EVENT.value)
        # A dropped stream partial means the source tail is pending a reread:
        # the stream is observably behind its source until reconcile catches
        # up, which is exactly SOURCE_LAG on the wire vocabulary (#289).
        partial_gap = state.gaps.get(_LOCAL_STREAM_PARTIAL_DROPPED_GAP)
        if partial_gap is not None and partial_gap.active:
            current.add(ObservationGapCode.SOURCE_LAG.value)
        if state.quarantine:
            current.add(ObservationGapCode.OUTBOX_QUARANTINED.value)
            assert state.storage_corrupt_sessions is not None
            current.update(
                reason
                for _session_id, _envelope, reason, _quarantined_at in state.quarantine
                if reason in _OBSERVATION_GAP_CODES
                and not (
                    reason == ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value
                    and not state.storage_corrupt_sessions
                )
            )
        overflow_gap = state.gaps.get(_LOCAL_OUTBOX_OVERFLOW_GAP)
        if len(state.pending_outbox) >= self._aggregate_outbox_limit(state) or (
            overflow_gap is not None and overflow_gap.active
        ):
            current.add(ObservationGapCode.OUTBOX_OVERFLOW.value)
        source_overflow = state.gaps.get(ObservationGapCode.OUTBOX_OVERFLOW.value)
        if source_overflow is not None and source_overflow.active:
            current.add(ObservationGapCode.OUTBOX_OVERFLOW.value)
        for row in state.pending_outbox:
            # A row deferred behind an ADR-022 check barrier is designed
            # back-pressure awaiting retry, never a current coverage gap (#351);
            # the row keeps its honest last_reason annotation without it.
            if row.last_reason is not None and row.last_reason != OBSERVATION_BACKPRESSURE_REASON:
                current.add(row.last_reason)
        # A legacy synchronous hook has acknowledged durable append, not
        # service ingest.  Until the READY forwarder consumes that fenced spool
        # file, status must report incomplete coverage rather than pretending
        # the hook reached the normal outbox.
        with contextlib.suppress(Exception):
            from yoetz.adapters.integrations.hook_spool import HookSpool

            if HookSpool(_state=self._state_root).has_pending(workspace_commitment):
                current.add(ObservationGapCode.SOURCE_LAG.value)
        # Live mapping presence outranks both the latched code and any stale row reason: a row
        # rejected for a missing mapping keeps that reason after the mapping is restored, and
        # reporting it again is the exact defect #219 filed.
        if mapping_available:
            current.discard(ObservationGapCode.MAPPING_MISSING.value)
        elif state.gaps.get(ObservationGapCode.MAPPING_MISSING.value) is not None:
            current.add(ObservationGapCode.MAPPING_MISSING.value)
        return tuple(sorted(current, key=str.encode))

    def _state_to_json(self, workspace: str, state: _WorkspaceState) -> dict[str, JsonValue]:
        consent = state.consent
        content_capture_epoch = _ensure_content_capture_epoch(state)
        assert state.session_workspaces is not None
        assert state.cursors is not None
        assert state.dedup is not None
        assert state.dedup_order is not None
        assert state.dedup_lanes is not None
        assert state.envelopes is not None
        assert state.gaps is not None
        assert state.session_gaps is not None
        assert state.unsupported_events is not None
        assert state.open_pre is not None
        assert state.unpaired_scopes is not None
        assert state.stream_cursors is not None
        assert state.stream_call_tools is not None
        assert state.stream_call_tool_generations is not None
        assert state.stream_source_identities is not None
        assert state.codex_session_bindings is not None
        assert state.read_protections is not None
        consent_json: JsonValue = None
        if consent is not None:
            consent_body: dict[str, JsonValue] = {
                "workspace_commitment": consent.workspace_commitment,
                "granted_at": consent.granted_at.wire,
                "revoked_at": None if consent.revoked_at is None else consent.revoked_at.wire,
                "paused": consent.paused,
            }
            if consent.content_capture_profiles:
                consent_body["content_capture_profiles"] = consent.content_capture_profiles
            consent_json = JsonObject(consent_body)
        dedup_order = self._ordered_dedup_keys(state)
        payload: dict[str, JsonValue] = {
            # /15 adds bounded explicit read-protection scopes after /14's
            # owner-selected detail/capacity settings and /13's
            # durable content-consent and runtime-gate fence epochs, /12's
            # explicit native-host content-consent arm, /11's
            # source/session/generation-scoped paired-profile orphan identities,
            # retention provenance, and pairing-history fencing. /10 adds
            # generation-fenced deferred host-session lifecycle intents.
            # /9 generation-fences call-id pairing and stream file identity. /8
            # persisted unfenced call-id to tool-name pairing for rollout outputs.
            # /7 attributes dropped stream-partial gaps per session. /6 adds one-shot
            # task-frontier motion notices. /5 adds terminal
            # corruption-session tracking. /3 added quarantined_at per
            # quarantine entry and the reclaimed counter. Readers tolerate both directions:
            # unknown keys are ignored and missing keys default safely.
            "schema": "yoetz.observation-local/15",
            "admission_buffer": admission_buffer_to_json(state.admission_buffer),
            "selection_epoch": state.selection_epoch,
            "selection_observed_count": state.selection_observed_count,
            "selection_admitted_count": state.selection_admitted_count,
            "selection_delivered_count": state.selection_delivered_count,
            "selection_summarized_input_count": state.selection_summarized_input_count,
            "selection_omitted_count": state.selection_omitted_count,
            "selection_summarized_count": state.selection_summarized_count,
            "selection_rejected_count": state.selection_rejected_count,
            "selection_loss_commitment": state.selection_loss_commitment,
            "selection_loss_ranges": state.selection_loss_ranges,
            "selection_reported_loss_lanes": state.selection_reported_loss_lanes,
            # Optional since /15: older readers ignore it and older writers
            # drop it, which leaves every lane route-wide (tb4n1 B3).
            "selection_loss_details": state.selection_loss_details,
            "selection_last_loss_notice_ms": state.selection_last_loss_notice_ms,
            "selection_loss_notice_pending": state.selection_loss_notice_pending,
            "selection_summary_refusals": state.selection_summary_refusals,
            "selection_summary_refusal_notice_pending": (
                state.selection_summary_refusal_notice_pending
            ),
            "read_protections": tuple(
                read_protection_to_json(item) for item in state.read_protections
            ),
            "pairing_state_unknown": state.pairing_state_unknown,
            "workspace_commitment": workspace,
            "content_capture_epoch": content_capture_epoch,
            "consent": consent_json,
            "session_workspaces": JsonObject(
                {key: value for key, value in sorted(state.session_workspaces.items())}
            ),
            "cursors": JsonObject(
                {
                    key: observation_cursor_to_json(cursor)
                    for key, cursor in sorted(state.cursors.items())
                }
            ),
            "dedup": tuple(dedup_order),
            "ended_sessions": tuple(sorted(state.ended_sessions or set(), key=str.encode)),
            "session_generations": JsonObject(
                {
                    key: value
                    for key, value in sorted(
                        (state.session_generations or {}).items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            ),
            "ended_session_generations": JsonObject(
                {
                    key: value
                    for key, value in sorted(
                        (state.ended_session_generations or {}).items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            ),
            # Immutable members are spliced from cached canonical fragments;
            # the encoded bytes are identical to inline encoding (#689).
            "envelopes": cast(
                JsonValue, tuple(_envelope_fragment(item) for item in state.envelopes)
            ),
            "gaps": tuple(sorted(state.gaps, key=str.encode)),
            "gap_history": JsonObject(
                {
                    code: JsonObject(
                        {
                            "first_seen": seen.first_seen.wire,
                            "last_seen": seen.last_seen.wire,
                            "active": seen.active,
                        }
                    )
                    for code, seen in sorted(state.gaps.items(), key=lambda item: item[0].encode())
                }
            ),
            "unsupported_events": tuple(sorted(state.unsupported_events, key=str.encode)),
            "last_receipt": None if state.last_receipt is None else state.last_receipt.wire,
            "advice_frontier": state.advice_frontier,
            "advice_snapshot": (
                None
                if state.advice_snapshot is None
                else advice_snapshot_to_json(state.advice_snapshot)
            ),
            "last_advice_suppression": state.last_advice_suppression,
            "session_advice": JsonObject(
                {
                    key: advice_snapshot_to_json(snapshot)
                    for key, snapshot in sorted(
                        (state.session_advice or {}).items(), key=lambda item: item[0].encode()
                    )
                }
            ),
            "session_advice_suppression": JsonObject(
                {
                    key: value
                    for key, value in sorted(
                        (state.session_advice_suppression or {}).items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            ),
            "open_pre": JsonObject(
                {key: _open_pre_to_json(value) for key, value in sorted(state.open_pre.items())}
            ),
            "stream_cursors": JsonObject(
                {
                    key: observation_cursor_to_json(cursor)
                    for key, cursor in sorted(state.stream_cursors.items())
                }
            ),
            "stream_partials": JsonObject(
                {
                    key: "b64:" + base64.b64encode(value).decode("ascii")
                    for key, value in sorted(
                        (state.stream_partials or {}).items(), key=lambda item: item[0].encode()
                    )
                }
            ),
            "hook_sequences": JsonObject(
                {
                    key: value
                    for key, value in sorted(
                        (state.hook_sequences or {}).items(), key=lambda item: item[0].encode()
                    )
                }
            ),
            "hook_sequence_clock": state.hook_sequence_clock,
            "last_stream_reconcile_mono_ms": state.last_stream_reconcile_mono_ms,
            "last_hook_receipt_mono_ms": state.last_hook_receipt_mono_ms,
            "last_successful_drain_mono_ms": state.last_successful_drain_mono_ms,
            # Canonical JSON forbids floats; persist the epoch as integer millis.
            "monotonic_epoch_ms": (
                None if state.monotonic_epoch is None else round(state.monotonic_epoch * 1000)
            ),
            "pending_outbox": cast(
                JsonValue,
                tuple(_outbox_row_fragment(row) for row in (state.pending_outbox or ())),
            ),
            "quarantine": cast(
                JsonValue,
                tuple(_quarantine_entry_fragment(entry) for entry in (state.quarantine or ())),
            ),
            "quarantine_evicted_count": state.quarantine_evicted_count,
            "quarantine_reclaimed_count": state.quarantine_reclaimed_count,
            "quarantine_evicted_commitment": state.quarantine_evicted_commitment,
            "quarantine_evicted_first": (
                None
                if state.quarantine_evicted_first is None
                else state.quarantine_evicted_first.wire
            ),
            "quarantine_evicted_last": (
                None
                if state.quarantine_evicted_last is None
                else state.quarantine_evicted_last.wire
            ),
            "trusted_policy_digest": state.trusted_policy_digest,
            "trusted_policy_mac": state.trusted_policy_mac,
            "codex_session_bindings": JsonObject(
                {key: value for key, value in sorted(state.codex_session_bindings.items())}
            ),
        }
        if state.storage_corrupt_sessions:
            payload["storage_corrupt_sessions"] = tuple(
                sorted(state.storage_corrupt_sessions, key=str.encode)
            )
        if state.frontier_motion_notices or state.frontier_motion_delivered:
            payload["frontier_motion_recency"] = state.frontier_motion_recency
        if state.frontier_motion_notices:
            payload["frontier_motion_notices"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "from_sequence": notice.from_sequence,
                            "head_digest": notice.head_digest,
                            "observation_record_count": notice.observation_record_count,
                            "recency_ordinal": notice.recency_ordinal,
                            "task_id": notice.task_id,
                            "to_sequence": notice.to_sequence,
                        }
                    )
                    for key, notice in sorted(
                        state.frontier_motion_notices.items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            )
        if state.frontier_motion_delivered:
            payload["frontier_motion_delivered"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "head_digest": value.head_digest,
                            "recency_ordinal": value.recency_ordinal,
                            "task_id": value.task_id,
                            "to_sequence": value.to_sequence,
                        }
                    )
                    for key, value in sorted(
                        state.frontier_motion_delivered.items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            )
        if state.codex_tool_hooks:
            payload["codex_tool_hooks"] = JsonObject(
                {
                    session: JsonObject(
                        {"count": entry.count, "touched": entry.touched, "settled": entry.settled}
                    )
                    for session, entry in sorted(
                        state.codex_tool_hooks.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.code_mode_cells:
            payload["code_mode_cells"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "hook_clock_at_start": cell.hook_clock_at_start,
                            "output_local": cell.output_local,
                            "touched": cell.touched,
                        }
                    )
                    for key, cell in sorted(
                        state.code_mode_cells.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.codex_tool_hook_clock:
            payload["codex_tool_hook_clock"] = state.codex_tool_hook_clock
        if state.evicted_open_calls:
            payload["evicted_open_calls"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "session": session,
                            "commitment": commitment,
                            "call_id": call_id,
                            "touched": touched,
                        }
                    )
                    for key, (session, commitment, call_id, touched) in sorted(
                        state.evicted_open_calls.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.pending_rollout_items:
            payload["pending_rollout_items"] = JsonObject(
                {
                    identity: JsonObject(
                        {
                            "session": item.session_commitment,
                            "codex_session_id": item.codex_session_id,
                            "envelope": observation_envelope_to_json(item.envelope),
                            "touched": item.touched,
                            "idle_reconciles": item.idle_reconciles,
                            "activity": item.activity,
                        }
                    )
                    for identity, item in sorted(
                        state.pending_rollout_items.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.stream_partial_dropped_sessions:
            payload["stream_partial_dropped_sessions"] = tuple(
                sorted(state.stream_partial_dropped_sessions, key=str.encode)
            )
        if state.stream_call_tools:
            payload["stream_call_tools"] = JsonObject(
                {
                    session: JsonObject(
                        {
                            "source_generation": state.stream_call_tool_generations[session],
                            "tools": JsonObject(
                                {
                                    call_id: tool_name
                                    for call_id, tool_name in sorted(
                                        tools.items(), key=lambda item: item[0].encode()
                                    )
                                }
                            ),
                        }
                    )
                    for session, tools in sorted(
                        state.stream_call_tools.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.stream_source_identities:
            payload["stream_source_identities"] = JsonObject(
                {
                    session: identity
                    for session, identity in sorted(
                        state.stream_source_identities.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.stream_profiles:
            payload["stream_profiles"] = JsonObject(
                {
                    session: profile_id
                    for session, profile_id in sorted(
                        state.stream_profiles.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.envelopes_truncated:
            payload["envelopes_truncated"] = True
        if state.unpaired_scopes:
            payload["unpaired_scopes"] = tuple(sorted(state.unpaired_scopes, key=str.encode))
        if state.unpaired_notices:
            # Optional and tolerated in both directions like every /15 key: an
            # older reader ignores it and would at most announce a scope again.
            payload["unpaired_notices"] = JsonObject(
                {
                    lane: JsonObject(
                        {
                            "source": notice.source,
                            "session_commitment": notice.session_commitment,
                            "source_generation": notice.source_generation,
                            "delivered": notice.delivered,
                            "ordinal": notice.ordinal,
                        }
                    )
                    for lane, notice in sorted(
                        state.unpaired_notices.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.pending_lifecycles:
            payload["pending_lifecycles"] = tuple(
                JsonObject(
                    {
                        "codex_session_id": intent.codex_session_id,
                        "session_commitment": intent.session_commitment,
                        "event_kind": intent.event_kind,
                        "target_generation": intent.target_generation,
                        "clear_mapping": intent.clear_mapping,
                    }
                )
                for intent in state.pending_lifecycles
            )
        if state.pending_consent_revocation is not None:
            payload["pending_consent_revocation"] = state.pending_consent_revocation
            if state.pending_consent_projects is not None:
                payload["pending_consent_projects"] = JsonObject(
                    {
                        key: value
                        for key, value in sorted(
                            state.pending_consent_projects.items(),
                            key=lambda item: item[0].encode(),
                        )
                    }
                )
        if state.dedup_lanes:
            payload["dedup_sessions"] = tuple(state.dedup_lanes.get(key) for key in dedup_order)
        if state.session_gaps:
            payload["session_gaps"] = JsonObject(
                {
                    session: tuple(sorted(gaps, key=str.encode))
                    for session, gaps in sorted(
                        state.session_gaps.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.selection_settings is not None and (
            state.selection_settings.workspace is not None or state.selection_settings.sessions
        ):
            payload["selection_settings"] = observation_selection_settings_to_json(
                state.selection_settings
            )
        if (
            state.capture_backlogs
            or state.capture_backlog_scope_unknown
            or state.capture_reservation_bootstrap is not None
        ):
            payload["capture_backlogs"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "count": snapshot.count,
                            "byte_count": snapshot.byte_count,
                            "oldest_receipt_time": (
                                None
                                if snapshot.oldest_receipt_time is None
                                else snapshot.oldest_receipt_time.wire
                            ),
                            "observed_at": snapshot.observed_at.wire,
                            "accounted_ticket_ids": snapshot.accounted_ticket_ids,
                        }
                    )
                    for key, snapshot in sorted(
                        (state.capture_backlogs or {}).items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            )
            payload["capture_backlog_scope_unknown"] = state.capture_backlog_scope_unknown
            if state.capture_reservation_bootstrap is not None:
                payload["capture_reservation_bootstrap"] = JsonObject(
                    {
                        "proof": state.capture_reservation_bootstrap.proof,
                        "observed_at": state.capture_reservation_bootstrap.observed_at.wire,
                        "route_count": state.capture_reservation_bootstrap.route_count,
                    }
                )
        if state.capture_reservations:
            payload["capture_reservations"] = JsonObject(
                {
                    key: JsonObject(
                        {
                            "ticket_id": reservation.ticket_id,
                            "task_id": reservation.task_id,
                            "byte_count": reservation.byte_count,
                            "reserved_at": reservation.reserved_at.wire,
                            "needs_reconcile": reservation.needs_reconcile,
                        }
                    )
                    for key, reservation in sorted(
                        state.capture_reservations.items(), key=lambda item: item[0].encode()
                    )
                }
            )
        if state.capture_handoff_retirements or state.capture_handoff_retired_count:
            payload["capture_handoff_retirements"] = state.capture_handoff_retirements
            payload["capture_handoff_retired_count"] = state.capture_handoff_retired_count
        if state.capture_handoff_retirement_ids:
            payload["capture_handoff_retirement_ids"] = state.capture_handoff_retirement_ids
        if state.capture_handoff_retirement_pending:
            payload["capture_handoff_retirement_pending"] = JsonObject(
                {
                    ticket_id: task_id
                    for ticket_id, task_id in sorted(
                        state.capture_handoff_retirement_pending.items(),
                        key=lambda item: item[0].encode(),
                    )
                }
            )
        if state.pressure_snapshots:
            payload["pressure_snapshots"] = _pressure_snapshots_to_json(state.pressure_snapshots)
        return payload

    def _state_from_json(
        self,
        raw: Mapping[str, JsonValue],
        *,
        envelope_keys: Mapping[int, str] | None = None,
    ) -> _WorkspaceState:
        keys: Mapping[int, str] = {} if envelope_keys is None else envelope_keys
        consent_raw = raw.get("consent")
        consent: LocalObservationConsent | None = None
        if isinstance(consent_raw, Mapping):
            row = cast(Mapping[str, JsonValue], consent_raw)
            revoked = row.get("revoked_at")
            consent = LocalObservationConsent(
                workspace_commitment=str(row["workspace_commitment"]),
                granted_at=Timestamp(str(row["granted_at"])),
                revoked_at=None if revoked is None else Timestamp(str(revoked)),
                paused=bool(row.get("paused", False)),
                content_capture_profiles=_content_capture_profiles_from_json(row),
            )
        pending_consent_revocation = raw.get("pending_consent_revocation")
        if type(pending_consent_revocation) is not str:
            pending_consent_revocation = None
        else:
            try:
                validate_sha256_digest(pending_consent_revocation)
            except ProtocolValueError, TypeError, ValueError:
                pending_consent_revocation = None
        pending_consent_projects: dict[str, int] | None = None
        raw_pending_projects = raw.get("pending_consent_projects")
        if isinstance(raw_pending_projects, Mapping):
            pending_consent_projects = {}
            for project_id, generation in raw_pending_projects.items():
                if len(pending_consent_projects) >= _MAX_PENDING_CONSENT_PROJECTS:
                    break
                if type(project_id) is not str or type(generation) is not int:
                    continue
                if isinstance(generation, bool) or generation < 1:
                    continue
                try:
                    validate_id(IdKind.PROJECT, project_id)
                except ProtocolValueError, TypeError, ValueError:
                    continue
                pending_consent_projects[project_id] = generation
        if pending_consent_revocation is None:
            pending_consent_projects = None
        session_workspaces = {
            str(key): str(value)
            for key, value in cast(
                Mapping[str, JsonValue], raw.get("session_workspaces") or {}
            ).items()
        }
        cursors = {
            str(key): observation_cursor_from_json(JsonObject(cast(Mapping[str, JsonValue], value)))
            for key, value in cast(Mapping[str, JsonValue], raw.get("cursors") or {}).items()
        }
        dedup_raw = raw.get("dedup") or ()
        dedup_values = (
            cast(tuple[JsonValue, ...] | list[JsonValue], dedup_raw)
            if isinstance(dedup_raw, (tuple, list))
            else ()
        )
        dedup_order: list[str] = []
        for value in dedup_values:
            if type(value) is str and value not in dedup_order:
                dedup_order.append(value)
        dedup_lanes: dict[str, str] = {}
        dedup_sessions_raw = raw.get("dedup_sessions") or ()
        if isinstance(dedup_sessions_raw, (tuple, list)):
            for key, lane in zip(dedup_order, dedup_sessions_raw, strict=False):
                if type(lane) is not str:
                    continue
                try:
                    validate_commitment(lane)
                except ProtocolValueError, TypeError, ValueError:
                    continue
                dedup_lanes[key] = lane
        ended_sessions_raw = raw.get("ended_sessions") or ()
        session_generations = {
            str(key): int(value)
            for key, value in cast(
                Mapping[str, JsonValue], raw.get("session_generations") or {}
            ).items()
            if (
                type(value) is int
                and not isinstance(value, bool)
                and 0 <= value <= _MAX_SAFE_INTEGER
            )
        }
        ended_session_generations = {
            str(key): int(value)
            for key, value in cast(
                Mapping[str, JsonValue], raw.get("ended_session_generations") or {}
            ).items()
            if type(value) is int and not isinstance(value, bool) and value >= 1
        }
        pending_lifecycles: list[PendingSessionLifecycle] = []
        for item in cast(
            tuple[JsonValue, ...] | list[JsonValue], raw.get("pending_lifecycles") or ()
        ):
            if not isinstance(item, Mapping):
                continue
            pending = cast(Mapping[str, JsonValue], item)
            try:
                pending_lifecycles.append(
                    PendingSessionLifecycle(
                        codex_session_id=pending.get("codex_session_id"),  # type: ignore[arg-type]
                        session_commitment=pending.get("session_commitment"),  # type: ignore[arg-type]
                        event_kind=pending.get("event_kind"),  # type: ignore[arg-type]
                        target_generation=pending.get("target_generation"),  # type: ignore[arg-type]
                        clear_mapping=pending.get("clear_mapping", False),  # type: ignore[arg-type]
                    )
                )
            except ProtocolValueError, TypeError, ValueError:
                continue
            if len(pending_lifecycles) >= _MAX_PENDING_LIFECYCLES:
                break
        envelopes_raw = raw.get("envelopes") or ()
        envelopes_truncated = raw.get("envelopes_truncated") is True
        gaps_raw = raw.get("gaps") or ()
        gap_history: dict[str, _GapState] = {}
        session_gaps: dict[str, set[str]] = {}
        raw_session_gaps = raw.get("session_gaps") or {}
        if isinstance(raw_session_gaps, Mapping):
            for session, codes in cast(Mapping[str, JsonValue], raw_session_gaps).items():
                if len(session_gaps) >= _MAX_SESSION_REPLAY_KEYS:
                    break
                if type(session) is not str or not isinstance(codes, (tuple, list)):
                    continue
                try:
                    validate_commitment(session)
                except ProtocolValueError, TypeError, ValueError:
                    continue
                retained_codes = {
                    code
                    for code in cast(tuple[JsonValue, ...] | list[JsonValue], codes)
                    if type(code) is str
                    and (
                        code in _OBSERVATION_GAP_CODES
                        or code
                        in {
                            _LOCAL_DEDUP_EVICTED_GAP,
                            _LOCAL_ENVELOPE_RETENTION_GAP,
                            _LOCAL_OUTBOX_OVERFLOW_GAP,
                            _LOCAL_STREAM_PARTIAL_DROPPED_GAP,
                        }
                    )
                }
                if retained_codes:
                    session_gaps[session] = set(
                        sorted(retained_codes, key=str.encode)[:_MAX_SESSION_GAP_CODES]
                    )
        raw_gap_history = raw.get("gap_history") or {}
        if isinstance(raw_gap_history, Mapping):
            for code, value in cast(Mapping[str, JsonValue], raw_gap_history).items():
                if type(code) is not str or not isinstance(value, Mapping):
                    continue
                seen = cast(Mapping[str, JsonValue], value)
                first_seen = seen.get("first_seen")
                last_seen = seen.get("last_seen")
                if type(first_seen) is not str or type(last_seen) is not str:
                    continue
                try:
                    gap_history[code] = _GapState(
                        Timestamp(first_seen),
                        Timestamp(last_seen),
                        seen.get("active", True) is True,
                    )
                except ProtocolValueError, TypeError, ValueError:
                    continue
        legacy_seen = self._wall_timestamp()
        for code in cast(tuple[str, ...], gaps_raw):
            if type(code) is str and code not in gap_history:
                gap_history[code] = _GapState(legacy_seen, legacy_seen)
        # /10 and earlier did not persist retention provenance. Their
        # truncation gap is the only durable indication that older envelope
        # history may have been evicted, so preserve that uncertainty when
        # deciding whether a historical pairing diagnostic can be retired.
        if not envelopes_truncated and raw.get("schema") not in _RETENTION_PROVENANCE_SCHEMAS:
            envelopes_truncated = ObservationGapCode.TRUNCATED_PAYLOAD.value in gap_history
        unsupported_raw = raw.get("unsupported_events") or ()
        advice_raw = raw.get("advice_snapshot")
        stream_cursors = {
            str(key): observation_cursor_from_json(JsonObject(cast(Mapping[str, JsonValue], value)))
            for key, value in cast(Mapping[str, JsonValue], raw.get("stream_cursors") or {}).items()
        }
        stream_partials: dict[str, bytes] = {}
        for key, value in cast(Mapping[str, JsonValue], raw.get("stream_partials") or {}).items():
            if type(value) is not str or not value.startswith("b64:"):
                continue
            try:
                stream_partials[str(key)] = base64.b64decode(
                    value[4:].encode("ascii"), validate=True
                )
            except ValueError, OSError:
                continue
        stream_call_tools: dict[str, dict[str, str]] = {}
        stream_call_tool_generations: dict[str, int] = {}
        remaining_call_tools = _MAX_STREAM_CALL_TOOLS
        stream_call_tools_raw = raw.get("stream_call_tools")
        if isinstance(stream_call_tools_raw, Mapping):
            for session, values in cast(Mapping[str, JsonValue], stream_call_tools_raw).items():
                if remaining_call_tools == 0:
                    break
                if type(session) is not str or not isinstance(values, Mapping):
                    continue
                values_row = cast(Mapping[str, JsonValue], values)
                generation = values_row.get("source_generation")
                raw_tools = values_row.get("tools")
                if (
                    type(generation) is not int
                    or generation < 1
                    or not isinstance(raw_tools, Mapping)
                ):
                    # /8 entries were not generation-fenced and are discarded.
                    continue
                tools: dict[str, str] = {}
                for call_id, tool_name in cast(Mapping[str, JsonValue], raw_tools).items():
                    if (
                        remaining_call_tools == 0
                        or type(call_id) is not str
                        or type(tool_name) is not str
                        or not call_id
                        or not tool_name
                        or len(call_id) > 128
                        or len(tool_name) > 128
                    ):
                        continue
                    tools[call_id] = tool_name
                    remaining_call_tools -= 1
                if tools:
                    stream_call_tools[session] = tools
                    stream_call_tool_generations[session] = generation
        stream_source_identities = {
            str(session): identity
            for session, identity in cast(
                Mapping[str, JsonValue], raw.get("stream_source_identities") or {}
            ).items()
            if type(session) is str
            and type(identity) is str
            and identity.startswith("hmac-sha256:")
            and len(identity) == 76
        }
        stream_profiles = {
            str(session): profile_id
            for session, profile_id in cast(
                Mapping[str, JsonValue], raw.get("stream_profiles") or {}
            ).items()
            if type(session) is str
            and type(profile_id) is str
            and _stream_profile_id_valid(profile_id)
        }
        dropped_sessions_raw = raw.get("stream_partial_dropped_sessions")
        stream_partial_dropped_sessions: set[str]
        if isinstance(dropped_sessions_raw, (list, tuple)):
            stream_partial_dropped_sessions = {
                value
                for value in cast(tuple[JsonValue, ...] | list[JsonValue], dropped_sessions_raw)
                if type(value) is str and value
            }
        else:
            legacy_gap = gap_history.get(_LOCAL_STREAM_PARTIAL_DROPPED_GAP)
            stream_partial_dropped_sessions = (
                set(stream_cursors) | set(session_workspaces)
                if legacy_gap is not None and legacy_gap.active
                else set[str]()
            )
            if legacy_gap is not None and legacy_gap.active and not stream_partial_dropped_sessions:
                stream_partial_dropped_sessions.add(_LEGACY_STREAM_PARTIAL_DROPPED_SESSION)
        hook_sequences: dict[str, int] = {}
        for key, value in cast(Mapping[str, JsonValue], raw.get("hook_sequences") or {}).items():
            if type(value) is int and not isinstance(value, bool) and value >= 0:
                hook_sequences[str(key)] = value
        raw_hook_sequence_clock = raw.get("hook_sequence_clock", 0)
        hook_sequence_clock = (
            raw_hook_sequence_clock
            if type(raw_hook_sequence_clock) is int
            and not isinstance(raw_hook_sequence_clock, bool)
            and 0 <= raw_hook_sequence_clock <= _MAX_SAFE_INTEGER
            else max(hook_sequences.values(), default=0)
        )
        hook_sequence_clock = max(hook_sequence_clock, max(hook_sequences.values(), default=0))
        reconcile_mono = raw.get("last_stream_reconcile_mono_ms")
        last_reconcile = (
            int(reconcile_mono)
            if type(reconcile_mono) is int
            and not isinstance(reconcile_mono, bool)
            and reconcile_mono >= 0
            else None
        )
        hook_mono_raw = raw.get("last_hook_receipt_mono_ms")
        last_hook_mono = (
            int(hook_mono_raw)
            if type(hook_mono_raw) is int
            and not isinstance(hook_mono_raw, bool)
            and hook_mono_raw >= 0
            else None
        )
        drain_mono_raw = raw.get("last_successful_drain_mono_ms")
        last_drain_mono = (
            int(drain_mono_raw)
            if type(drain_mono_raw) is int
            and not isinstance(drain_mono_raw, bool)
            and drain_mono_raw >= 0
            else None
        )
        epoch_raw = raw.get("monotonic_epoch_ms")
        monotonic_epoch = (
            float(epoch_raw) / 1000.0
            if type(epoch_raw) is int and not isinstance(epoch_raw, bool)
            else None
        )
        bindings = {
            str(key): str(value)
            for key, value in cast(
                Mapping[str, JsonValue], raw.get("codex_session_bindings") or {}
            ).items()
        }
        storage_corrupt_sessions = {
            str(value)
            for value in cast(
                tuple[JsonValue, ...] | list[JsonValue],
                raw.get("storage_corrupt_sessions") or (),
            )
            if type(value) is str and value
        }
        open_pre = _open_pre_map_from_json(
            raw.get("open_pre"),
            legacy_receipt_time=_safe_timestamp(raw.get("last_receipt")),
        )
        unpaired_raw = raw.get("unpaired_scopes")
        unpaired_scopes = (
            {
                value
                for value in cast(tuple[JsonValue, ...] | list[JsonValue], unpaired_raw)
                if type(value) is str and value
            }
            if isinstance(unpaired_raw, (tuple, list))
            else set[str]()
        )
        if len(unpaired_scopes) > _MAX_UNPAIRED_SCOPES:
            unpaired_scopes = set(sorted(unpaired_scopes, key=str.encode)[:_MAX_UNPAIRED_SCOPES])
        raw_pairing_state_unknown = raw.get("pairing_state_unknown")
        legacy_pairing_history_complete = (
            raw.get("schema") == "yoetz.observation-local/11"
            and raw.get("pairing_history_complete") is True
        )
        # A pre-/11 writer can read a /11 file and save it again while dropping
        # the scoped orphan set. Missing or malformed provenance is therefore
        # incomplete history, even when the file claims a provenance-aware
        # schema.
        pairing_state_unknown = not (
            legacy_pairing_history_complete
            or (
                raw.get("schema") in _PAIRING_PROVENANCE_SCHEMAS
                and type(raw_pairing_state_unknown) is bool
                and raw_pairing_state_unknown is False
            )
        )
        last_receipt = raw.get("last_receipt")
        envelopes: list[ObservationEnvelope] = []
        for item in cast(tuple[JsonValue, ...] | list[JsonValue], envelopes_raw):
            if isinstance(item, Mapping):
                envelopes.append(
                    _CODEC.decode(cast(Mapping[str, JsonValue], item), keys.get(id(item)))
                )
            else:
                envelopes.append(observation_envelope_from_json(item))
        if len(envelopes) > _MAX_ENVELOPES:
            # A handoff from an older writer may carry over-limit detail even
            # though it has no explicit truncation marker.  Treat the missing
            # prefix as unknown rather than resolving a gap from the suffix.
            envelopes_truncated = True
        advice_snapshot = None
        if advice_raw is not None:
            if isinstance(advice_raw, Mapping):
                advice_snapshot = advice_snapshot_from_json(
                    JsonObject(cast(Mapping[str, JsonValue], advice_raw))
                )
            else:
                advice_snapshot = advice_snapshot_from_json(advice_raw)
        pending_outbox: list[ObservationOutboxRow] = []
        for item in cast(tuple[JsonValue, ...] | list[JsonValue], raw.get("pending_outbox") or ()):
            if not isinstance(item, Mapping):
                continue
            row = cast(Mapping[str, JsonValue], item)
            session = row.get("codex_session_id")
            envelope_raw = row.get("envelope")
            if type(session) is not str or not isinstance(envelope_raw, Mapping):
                continue
            attempts_raw = row.get("attempts", 0)
            attempts = (
                attempts_raw
                if type(attempts_raw) is int
                and not isinstance(attempts_raw, bool)
                and 0 <= attempts_raw <= _MAX_SAFE_INTEGER
                else 0
            )
            last_reason_raw = row.get("last_reason")
            last_reason = (
                last_reason_raw
                if type(last_reason_raw) is str
                and _OUTBOX_REASON_RE.fullmatch(last_reason_raw) is not None
                else None
            )
            last_attempt_raw = row.get("last_attempt_at")
            try:
                last_attempt_at = (
                    None if last_attempt_raw is None else Timestamp(str(last_attempt_raw))
                )
            except ProtocolValueError, TypeError, ValueError:
                last_attempt_at = None
            consecutive_raw = row.get("consecutive_reason_attempts")
            if (
                type(consecutive_raw) is int
                and not isinstance(consecutive_raw, bool)
                and 0 <= consecutive_raw <= attempts
            ):
                consecutive_reason_attempts = consecutive_raw
            else:
                # A legacy omission or malformed counter cannot prove that all
                # historical attempts used last_reason. Start the reason-local
                # streak at zero; the next attempt persists the bounded counter,
                # so compatibility grants at most one fresh retry budget.
                consecutive_reason_attempts = 0
            try:
                pending_outbox.append(
                    ObservationOutboxRow(
                        codex_session_id=session,
                        envelope=_CODEC.decode(
                            cast(Mapping[str, JsonValue], envelope_raw),
                            keys.get(id(envelope_raw)),
                        ),
                        attempts=attempts,
                        last_reason=last_reason,
                        last_attempt_at=last_attempt_at,
                        consecutive_reason_attempts=consecutive_reason_attempts,
                    )
                )
            except ProtocolValueError, TypeError, ValueError:
                continue
        quarantine: list[tuple[str, ObservationEnvelope, str, Timestamp]] = []
        # Entries written before quarantined_at existed default to load time:
        # their true quarantine age is unknown, so the age bound restarts
        # rather than destroying them retroactively.
        quarantined_at_default = self._wall_timestamp()
        for item in cast(tuple[JsonValue, ...] | list[JsonValue], raw.get("quarantine") or ()):
            if not isinstance(item, Mapping):
                continue
            row = cast(Mapping[str, JsonValue], item)
            session = row.get("codex_session_id")
            envelope_raw = row.get("envelope")
            reason = row.get("reason")
            if (
                type(session) is not str
                or type(reason) is not str
                or not isinstance(envelope_raw, Mapping)
            ):
                continue
            raw_quarantined_at = row.get("quarantined_at")
            try:
                quarantined_at = (
                    Timestamp(raw_quarantined_at)
                    if type(raw_quarantined_at) is str
                    else quarantined_at_default
                )
                quarantine.append(
                    (
                        session,
                        _CODEC.decode(
                            cast(Mapping[str, JsonValue], envelope_raw),
                            keys.get(id(envelope_raw)),
                        ),
                        reason,
                        quarantined_at,
                    )
                )
            except ProtocolValueError, TypeError, ValueError:
                continue
        raw_quarantine_evicted_count = raw.get("quarantine_evicted_count", 0)
        quarantine_evicted_count = (
            raw_quarantine_evicted_count if type(raw_quarantine_evicted_count) is int else 0
        )
        raw_quarantine_reclaimed_count = raw.get("quarantine_reclaimed_count", 0)
        quarantine_reclaimed_count = (
            raw_quarantine_reclaimed_count if type(raw_quarantine_reclaimed_count) is int else 0
        )
        frontier_motion_notices = _load_frontier_motion_notices(raw.get("frontier_motion_notices"))
        frontier_motion_delivered = _load_frontier_motion_delivered(
            raw.get("frontier_motion_delivered")
        )
        raw_frontier_motion_recency = raw.get("frontier_motion_recency", 0)
        frontier_motion_recency = (
            raw_frontier_motion_recency
            if type(raw_frontier_motion_recency) is int
            and 0 <= raw_frontier_motion_recency <= _MAX_SAFE_INTEGER
            else 0
        )
        frontier_motion_recency = max(
            [
                frontier_motion_recency,
                *(notice.recency_ordinal for notice in frontier_motion_notices.values()),
                *(mark.recency_ordinal for mark in frontier_motion_delivered.values()),
            ]
        )
        raw_content_capture_epoch = raw.get("content_capture_epoch")
        content_capture_epoch = None
        if type(raw_content_capture_epoch) is str:
            try:
                content_capture_epoch = validate_sha256_digest(raw_content_capture_epoch)
            except ProtocolValueError, TypeError, ValueError:
                # A malformed or absent epoch is upgraded to a fresh nonce on
                # the next durable save.  It must never make an old fence
                # current by falling back to consent fields alone.
                content_capture_epoch = None
        read_protections: list[ReadProtection] = []
        raw_read_protections = raw.get("read_protections")
        read_protection_total = 0
        if isinstance(raw_read_protections, (tuple, list)):
            for item in cast(tuple[JsonValue, ...] | list[JsonValue], raw_read_protections):
                try:
                    protection = read_protection_from_json(item)
                except ProtocolValueError, TypeError, ValueError:
                    continue
                protection_total = protection.remaining + len(protection.reserved_attempt_ids)
                if protection_total > MAX_READ_PROTECTION_COUNT - read_protection_total:
                    continue
                read_protections.append(protection)
                read_protection_total += protection_total
                if len(read_protections) >= MAX_READ_PROTECTIONS:
                    break
        selection_settings = observation_selection_settings_from_json(raw.get("selection_settings"))
        capture_backlogs: dict[str, _CaptureBacklogSnapshot] = {}
        raw_capture_scope = raw.get("capture_backlog_scope_unknown")
        capture_backlog_scope_unknown = raw_capture_scope is True or (
            raw_capture_scope is not None and type(raw_capture_scope) is not bool
        )
        raw_capture_backlogs = raw.get("capture_backlogs")
        if isinstance(raw_capture_backlogs, Mapping):
            for raw_route_id, raw_snapshot in sorted(
                cast(Mapping[str, JsonValue], raw_capture_backlogs).items(),
                key=lambda item: item[0].encode(),
            ):
                if type(raw_route_id) is not str or (
                    raw_route_id != _UNKNOWN_CAPTURE_BACKLOG_ROUTE
                    and _CAPTURE_BACKLOG_ROUTE_RE.fullmatch(raw_route_id) is None
                ):
                    capture_backlog_scope_unknown = True
                    continue
                if not isinstance(raw_snapshot, Mapping):
                    capture_backlog_scope_unknown = True
                    continue
                snapshot_row = cast(Mapping[str, JsonValue], raw_snapshot)
                raw_count = snapshot_row.get("count")
                raw_byte_count = snapshot_row.get("byte_count")
                raw_oldest = snapshot_row.get("oldest_receipt_time")
                raw_observed = snapshot_row.get("observed_at")
                raw_accounted = snapshot_row.get("accounted_ticket_ids", ())
                if (
                    type(raw_count) is not int
                    or isinstance(raw_count, bool)
                    or not 0 <= raw_count <= _MAX_SAFE_INTEGER
                    or type(raw_byte_count) is not int
                    or isinstance(raw_byte_count, bool)
                    or not 0 <= raw_byte_count <= _MAX_SAFE_INTEGER
                    or (raw_oldest is not None and type(raw_oldest) is not str)
                    or type(raw_observed) is not str
                    or not isinstance(raw_accounted, (tuple, list))
                    or not all(type(ticket_id) is str for ticket_id in raw_accounted)
                ):
                    capture_backlog_scope_unknown = True
                    continue
                try:
                    accounted_ids = tuple(
                        validate_sha256_digest(ticket_id)
                        for ticket_id in cast(tuple[str, ...] | list[str], raw_accounted)
                    )
                    if accounted_ids != tuple(sorted(set(accounted_ids), key=str.encode)):
                        raise ProtocolValueError("invalid_event_value_type")
                    snapshot = _CaptureBacklogSnapshot(
                        count=raw_count,
                        byte_count=raw_byte_count,
                        oldest_receipt_time=(None if raw_oldest is None else Timestamp(raw_oldest)),
                        observed_at=Timestamp(raw_observed),
                        accounted_ticket_ids=accounted_ids,
                    )
                except ProtocolValueError, TypeError, ValueError:
                    capture_backlog_scope_unknown = True
                    continue
                if (
                    raw_route_id not in capture_backlogs
                    and len(capture_backlogs) >= _MAX_CAPTURE_BACKLOG_ROUTES
                ):
                    capture_backlog_scope_unknown = True
                    continue
                capture_backlogs[raw_route_id] = snapshot
        capture_reservations: dict[str, _CaptureReservation] = {}
        raw_capture_reservations = raw.get("capture_reservations")
        if raw_capture_reservations is not None and not isinstance(
            raw_capture_reservations, Mapping
        ):
            capture_backlog_scope_unknown = True
        elif isinstance(raw_capture_reservations, Mapping):
            for raw_key, raw_reservation in sorted(
                cast(Mapping[str, JsonValue], raw_capture_reservations).items(),
                key=lambda item: item[0].encode() if type(item[0]) is str else b"",
            ):
                if type(raw_key) is not str:
                    capture_backlog_scope_unknown = True
                    continue
                try:
                    validate_sha256_digest(raw_key)
                except ProtocolValueError, TypeError, ValueError:
                    capture_backlog_scope_unknown = True
                    continue
                if not isinstance(raw_reservation, Mapping):
                    capture_backlog_scope_unknown = True
                    continue
                reservation_row = cast(Mapping[str, JsonValue], raw_reservation)
                raw_ticket_id = reservation_row.get("ticket_id")
                raw_task_id = reservation_row.get("task_id")
                raw_byte_count = reservation_row.get("byte_count")
                raw_reserved_at = reservation_row.get("reserved_at")
                raw_needs_reconcile = reservation_row.get("needs_reconcile")
                if (
                    type(raw_ticket_id) is not str
                    or type(raw_task_id) is not str
                    or type(raw_byte_count) is not int
                    or isinstance(raw_byte_count, bool)
                    or type(raw_reserved_at) is not str
                    or type(raw_needs_reconcile) is not bool
                ):
                    capture_backlog_scope_unknown = True
                    continue
                try:
                    reservation = _CaptureReservation(
                        ticket_id=raw_ticket_id,
                        task_id=raw_task_id,
                        byte_count=raw_byte_count,
                        reserved_at=Timestamp(raw_reserved_at),
                        needs_reconcile=raw_needs_reconcile,
                    )
                except ProtocolValueError, TypeError, ValueError:
                    capture_backlog_scope_unknown = True
                    continue
                if _capture_reservation_key(reservation.ticket_id, reservation.task_id) != raw_key:
                    capture_backlog_scope_unknown = True
                    continue
                if (
                    raw_key not in capture_reservations
                    and len(capture_reservations) >= _MAX_CAPTURE_TICKET_RESERVATIONS
                ):
                    capture_backlog_scope_unknown = True
                    continue
                capture_reservations[raw_key] = reservation
        capture_reservation_bootstrap: _CaptureBootstrap | None = None
        raw_capture_bootstrap = raw.get("capture_reservation_bootstrap")
        if raw_capture_bootstrap is not None:
            if not isinstance(raw_capture_bootstrap, Mapping):
                capture_backlog_scope_unknown = True
            else:
                bootstrap_row = cast(Mapping[str, JsonValue], raw_capture_bootstrap)
                raw_proof = bootstrap_row.get("proof")
                raw_observed = bootstrap_row.get("observed_at")
                raw_route_count = bootstrap_row.get("route_count")
                if (
                    type(raw_proof) is not str
                    or type(raw_observed) is not str
                    or type(raw_route_count) is not int
                    or isinstance(raw_route_count, bool)
                ):
                    capture_backlog_scope_unknown = True
                else:
                    try:
                        capture_reservation_bootstrap = _CaptureBootstrap(
                            proof=raw_proof,
                            observed_at=Timestamp(raw_observed),
                            route_count=raw_route_count,
                        )
                    except ProtocolValueError, TypeError, ValueError:
                        capture_backlog_scope_unknown = True
        if capture_reservation_bootstrap is not None:
            expected_proof = _capture_bootstrap_proof(
                str(raw.get("workspace_commitment", "")), capture_backlogs
            )
            if (
                expected_proof != capture_reservation_bootstrap.proof
                or capture_reservation_bootstrap.route_count != len(capture_backlogs)
            ):
                capture_reservation_bootstrap = None
                capture_backlog_scope_unknown = True
        pressure_snapshots = _load_pressure_snapshots(raw.get("pressure_snapshots"))
        selection_loss_ranges = tuple(
            JsonObject(cast(Mapping[str, JsonValue], item))
            for item in cast(tuple[JsonValue, ...], raw.get("selection_loss_ranges", ()))[:64]
        )
        selection_loss_lanes = {
            item.get("lane") for item in selection_loss_ranges if type(item.get("lane")) is str
        }
        for item in selection_loss_ranges:
            try:
                selection_loss_lanes.add(
                    ObservationSelectionLoss.from_local_range_for_recovery(item).lane
                )
            except ProtocolValueError, TypeError, ValueError:
                continue
        selection_reported_loss_lanes = tuple(
            sorted(
                {
                    lane
                    for lane in cast(tuple[str, ...], raw.get("selection_reported_loss_lanes", ()))
                    if type(lane) is str and lane in selection_loss_lanes
                },
                key=str.encode,
            )
        )
        state = _WorkspaceState(
            consent=consent,
            admission_buffer=admission_buffer_from_json(raw.get("admission_buffer")),
            selection_epoch=int(cast(int, raw.get("selection_epoch", 0))),
            selection_observed_count=int(cast(int, raw.get("selection_observed_count", 0))),
            selection_admitted_count=int(cast(int, raw.get("selection_admitted_count", 0))),
            selection_delivered_count=int(cast(int, raw.get("selection_delivered_count", 0))),
            selection_summarized_input_count=int(
                cast(int, raw.get("selection_summarized_input_count", 0))
            ),
            selection_omitted_count=int(cast(int, raw.get("selection_omitted_count", 0))),
            selection_summarized_count=int(cast(int, raw.get("selection_summarized_count", 0))),
            selection_rejected_count=int(cast(int, raw.get("selection_rejected_count", 0))),
            selection_loss_commitment=cast(str | None, raw.get("selection_loss_commitment")),
            selection_loss_ranges=selection_loss_ranges,
            selection_reported_loss_lanes=selection_reported_loss_lanes,
            selection_loss_details=_loss_details_from_json(
                raw.get("selection_loss_details"),
                {
                    cast(str, item.get("lane"))
                    for item in selection_loss_ranges
                    if type(item.get("lane")) is str
                },
            ),
            selection_last_loss_notice_ms=cast(
                int | None, raw.get("selection_last_loss_notice_ms")
            ),
            selection_loss_notice_pending=raw.get("selection_loss_notice_pending") is True,
            selection_summary_refusals=tuple(
                JsonObject(cast(Mapping[str, JsonValue], item))
                for item in cast(tuple[JsonValue, ...], raw.get("selection_summary_refusals", ()))[
                    :_MAX_SUMMARY_REFUSALS
                ]
            ),
            selection_summary_refusal_notice_pending=(
                raw.get("selection_summary_refusal_notice_pending") is True
            ),
            capture_handoff_retirements=_capture_handoff_retirements_from_json(
                raw.get("capture_handoff_retirements")
            ),
            capture_handoff_retired_count=_bounded_count(raw.get("capture_handoff_retired_count")),
            capture_handoff_retirement_ids=_capture_handoff_retirement_ids_from_json(
                raw.get("capture_handoff_retirement_ids")
            ),
            capture_handoff_retirement_pending=_capture_handoff_retirement_pending_from_json(
                raw.get("capture_handoff_retirement_pending")
            ),
            session_workspaces=session_workspaces,
            cursors=cursors,
            dedup=set(dedup_order),
            dedup_order=dedup_order,
            dedup_lanes=dedup_lanes,
            ended_sessions=set(cast(tuple[str, ...], ended_sessions_raw)),
            session_generations=session_generations,
            ended_session_generations=ended_session_generations,
            pending_lifecycles=pending_lifecycles,
            pending_consent_revocation=pending_consent_revocation,
            pending_consent_projects=pending_consent_projects,
            content_capture_epoch=content_capture_epoch,
            selection_settings=selection_settings,
            read_protections=read_protections,
            pressure_snapshots=pressure_snapshots,
            envelopes=envelopes,
            envelopes_truncated=envelopes_truncated,
            session_gaps=session_gaps,
            gaps=gap_history,
            unsupported_events=set(cast(tuple[str, ...], unsupported_raw)),
            last_receipt=None if last_receipt is None else Timestamp(str(last_receipt)),
            advice_frontier=cast(str | None, raw.get("advice_frontier")),
            advice_snapshot=advice_snapshot,
            last_advice_suppression=cast(str | None, raw.get("last_advice_suppression")),
            session_advice=_load_session_advice(raw.get("session_advice")),
            session_advice_suppression={
                key: value
                for key, value in cast(
                    Mapping[str, JsonValue], raw.get("session_advice_suppression") or {}
                ).items()
                if type(key) is str and type(value) is str
            },
            frontier_motion_notices=frontier_motion_notices,
            frontier_motion_delivered=frontier_motion_delivered,
            frontier_motion_recency=frontier_motion_recency,
            open_pre=open_pre,
            unpaired_scopes=unpaired_scopes,
            unpaired_notices=_unpaired_notices_from_json(raw.get("unpaired_notices")),
            codex_tool_hooks=_codex_tool_hooks_from_json(raw.get("codex_tool_hooks")),
            code_mode_cells=_code_mode_cells_from_json(raw.get("code_mode_cells")),
            codex_tool_hook_clock=_bounded_counter(raw.get("codex_tool_hook_clock")),
            pending_rollout_items=_pending_rollout_items_from_json(
                raw.get("pending_rollout_items")
            ),
            evicted_open_calls=_evicted_open_calls_from_json(raw.get("evicted_open_calls")),
            pairing_state_unknown=pairing_state_unknown,
            stream_cursors=stream_cursors,
            stream_partials=stream_partials,
            stream_call_tools=stream_call_tools,
            stream_call_tool_generations=stream_call_tool_generations,
            stream_source_identities=stream_source_identities,
            stream_profiles=stream_profiles,
            stream_partial_dropped_sessions=stream_partial_dropped_sessions,
            hook_sequences=hook_sequences,
            hook_sequence_clock=hook_sequence_clock,
            last_stream_reconcile_mono_ms=last_reconcile,
            last_hook_receipt_mono_ms=last_hook_mono,
            last_successful_drain_mono_ms=last_drain_mono,
            monotonic_epoch=monotonic_epoch,
            pending_outbox=pending_outbox,
            quarantine=quarantine,
            quarantine_evicted_count=quarantine_evicted_count,
            quarantine_reclaimed_count=quarantine_reclaimed_count,
            quarantine_evicted_commitment=cast(
                str | None, raw.get("quarantine_evicted_commitment")
            ),
            quarantine_evicted_first=(
                None
                if raw.get("quarantine_evicted_first") is None
                else Timestamp(str(raw.get("quarantine_evicted_first")))
            ),
            quarantine_evicted_last=(
                None
                if raw.get("quarantine_evicted_last") is None
                else Timestamp(str(raw.get("quarantine_evicted_last")))
            ),
            trusted_policy_digest=cast(str | None, raw.get("trusted_policy_digest")),
            trusted_policy_mac=cast(str | None, raw.get("trusted_policy_mac")),
            codex_session_bindings=bindings,
            storage_corrupt_sessions=storage_corrupt_sessions,
            capture_backlogs=capture_backlogs,
            capture_reservations=capture_reservations,
            capture_backlog_scope_unknown=capture_backlog_scope_unknown,
            capture_reservation_bootstrap=capture_reservation_bootstrap,
        )
        if any(notice.recency_ordinal == 0 for notice in frontier_motion_notices.values()) or any(
            mark.recency_ordinal == 0 for mark in frontier_motion_delivered.values()
        ):
            # Notices persisted before the LRU clock existed load with ordinal
            # 0. Fold them into the clock once so they hold a real position
            # instead of tying at zero until the next touch.
            _renumber_frontier_motion_recency(state)
        return state


def workspace_commitment_for_path(path: str, *, _state: Path | None = None) -> str:
    return LocalObservationStore(_state=_state).workspace_commitment(path)


def session_commitment_from_codex_id(key_material: bytes, codex_session_id: str) -> str:
    """Return a path-free session commitment for a Codex session token."""

    import hashlib
    import hmac

    if type(key_material) is not bytes or not 16 <= len(key_material) <= 64:
        raise ProtocolValueError("invalid_commitment")
    if type(codex_session_id) is not str or not codex_session_id or "\x00" in codex_session_id:
        raise ProtocolValueError("invalid_event_value_type")
    digest = hmac.new(
        key_material,
        _SESSION_DOMAIN + codex_session_id.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return f"hmac-sha256:{digest}"
