"""Unified Codex hook observation ingress (structural envelopes only)."""

from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import time
from collections.abc import Awaitable, Callable, Generator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, BinaryIO, Final, Literal, NoReturn, Protocol, cast

from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    acquire_session_lock,
    acquire_workspace_recovery_lock,
    apply_pending_mapping,
    is_scoped_child_session_id,
    load_mapping,
    mapping_from_start_ids,
    mapping_path,
    queue_mapping_clear,
    queue_mapping_store,
    scoped_child_session_id,
    store_mapping,
    validate_codex_session_id,
)
from finishup.adapters.integrations.finishup_call_rejections import (
    claim_served_finishup_read,
    rejected_call_commitment,
)
from finishup.adapters.integrations.hook_spool import HookSpool
from finishup.adapters.integrations.observation_admission import build_routine_read_summary
from finishup.adapters.integrations.observation_local import (
    FINISHUP_OWNED_TOOL_NAMES,
    HOOK_MAPPING_VERSION,
    AdviceDelivery,
    LocalObservationConsent,
    LocalObservationStore,
    ObservationOutboxRow,
    ObservationStoreLockEvent,
    ObservationStoreLockTimeout,
    observation_dir,
    observation_store_lock_deadline,
    observation_store_lock_scope,
    self_observation_deliverable,
)
from finishup.adapters.integrations.observation_task_pending import task_pending_outbox_count
from finishup.adapters.workspace_binding import (
    canonical_workspace_locator,
    resolve_workspace_locator,
)
from finishup.adapters.workspace_fingerprint import WorkspaceEffectReading
from finishup.cli import hook_io
from finishup.cli.closure_gate import (
    ACCEPTANCE_RECHECK_ITEM,
    BLOCKER_RECHECK_ITEM,
    MAX_GATE_BLOCKS_PER_TURN,
    ClosureGate,
    closure_gate_already_delivered,
    closure_gate_reasked_blockers,
    closure_gate_turn_blocks,
    read_closure_gate,
    record_closure_gate_delivered,
    reset_closure_gate_turn,
    set_standing_advice_withheld,
    standing_advice_withheld,
)
from finishup.cli.hook_diagnostics import (
    observe_exception_reason,
    record_hook_diagnostic,
    record_hook_timing,
    record_store_lock_event,
)
from finishup.cli.hook_io import (
    MAX_HOOK_SKIM_BYTES,
    MAX_HOOK_STDIN_BYTES,
    OBSERVED_IMAGES_KEY,
    CursorOversizedPayloadError,
    OversizedHookPayloadError,
    read_cursor_hook_ingress,
    read_hook_ingress,
    read_hook_payload,
    strip_hook_media,
)
from finishup.cli.hook_io import (
    claude_context_output as _claude_context_output,
)
from finishup.cli.hook_io import (
    context_output as _context_output,
)
from finishup.cli.hook_io import (
    cursor_context_output as _cursor_context_output,
)
from finishup.cli.hook_io import (
    stderr_line as _stderr_line,
)
from finishup.cli.hook_timing import HookPassTiming, record_hook_pass_timing
from finishup.cli.runtime_facts import SHELL_APPLY_PATCH as _SHELL_APPLY_PATCH
from finishup.cli.runtime_facts import finishup_owned_roots, runtime_structural_facts
from finishup.cli.runtime_facts import shell_heredocs as _shell_heredocs
from finishup.cli.workspace_effect_hook import (
    fingerprinted_tool,
    host_call_complete,
    owned_relative_paths,
    workspace_fingerprint_pass,
)
from finishup.domain.advice_actions import STANDING_MACHINE_ACTIONS as _STANDING_MACHINE_ACTIONS
from finishup.domain.command_segments import (
    COMMAND_COMPOSITIONS,
    MAX_COMMAND_COMMITMENTS,
    command_segment_commitments,
)
from finishup.domain.compaction_recap import RECAP_CONTEXT_LIMIT, RecapFacts
from finishup.domain.finishup_tools import (
    FINISHUP_SCOPED_TOOL_PREFIXES,
    FINISHUP_TOOL_SERVER_NAMES,
)
from finishup.domain.observation import (
    OBSERVATION_CONTENT_CAPTURE_PENDING_REASON,
    ObservationContentChunk,
    ObservationContentKind,
    ObservationCursor,
    ObservationEnvelope,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationSource,
    hook_source_commitment,
    normalize_observed_command,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
    observed_command_commitment,
    validate_observed_images,
)
from finishup.domain.observation_budget import (
    AdmissionLossCause,
    ModeLimits,
    ObservationMode,
    mode_limits,
)
from finishup.domain.observation_profiles import (
    CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION,
    CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID,
    CURSOR_ORDINARY_HOOK_MAPPING_VERSION,
    CURSOR_ORDINARY_OBSERVATION_PROFILE_ID,
    content_capture_profile_matches_source,
)
from finishup.domain.observation_selection import (
    SHELL_TOOLS as _SHELL_TOOLS,
)
from finishup.domain.observation_selection import (
    ObservationClassification,
    RunnerClass,
    classify_observation,
    command_runner_class,
    compound_verification_gap_required,
    is_edit_tool_name,
    is_routine_read_candidate,
    without_routine_read,
)
from finishup.domain.shell_writes import codex_intercepts_shell_apply_patch
from finishup.domain.values import (
    JsonObject,
    Timestamp,
    timestamp_from_datetime,
)
from finishup.domain.values import (
    JsonValue as DomainJsonValue,
)
from finishup.domain.workspace_effect import WORKSPACE_EFFECT_KEY, WORKSPACE_UNCHANGED
from finishup.ports.integrations import (
    FINISHUP_SUPPORT_TOOL_NAMES,
    FINISHUP_WORKFLOW_TOOL_NAMES,
    observation_pairing_contract,
)
from finishup.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode
from finishup.protocol.ids import IdKind, is_valid_id
from finishup.protocol.recovery import READ_ONLY_CHECK_MODES

if TYPE_CHECKING:
    from finishup.adapters.integrations.codex_session_stream import CodexSessionStreamLocator
    from finishup.cli import hooks as hooks_cli
    from finishup.ports.control import ControlClientKind, WorkspaceLocator

__all__ = [
    "ADVICE_SAFE_EVENTS",
    "STANDING_ADVICE_CADENCE_EVENTS",
    "SUPPORTED_HOOK_EVENTS",
    "handle_claude_observe",
    "handle_codex_observe",
    "handle_cursor_observe",
    "handle_observe",
    "handle_spool",
    "map_hook_payload_to_envelope",
    "note_payload_too_large",
]

SUPPORTED_HOOK_EVENTS: Final = frozenset(
    {
        "SessionStart",
        "SessionEnd",
        "Stop",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "PermissionRequest",
        "PermissionDecision",
        "PreCompact",
        "PostCompact",
        "SubagentStart",
        "SubagentStop",
    }
)
# Events that have a Codex-valid model-visible output contract. SessionEnd is
# excluded: the host discards its stdout, so a peek/commit there would consume
# advice the agent never sees (#222). Stop stays listed because its handler is
# synchronous and carries the closure gate, but ordinary advice is never
# delivered at Stop (#985): see `delivery_eligible` in `handle_observe`.
ADVICE_SAFE_EVENTS: Final = frozenset({"PostToolUse", "SessionStart", "Stop"})
# Standing machine conditions (connect_provider and kin) reach the agent at
# SessionStart. Ordinary PostToolUse is deliberately excluded: it is the
# per-tool-call channel that produced 29 byte-identical injections in one
# session (#241). Stop no longer delivers advice (#985); instead, a Stop that
# finds standing advice pending marks it, and only the first PostToolUse after
# that Stop may carry it, which keeps the old once-per-turn bound. SessionEnd
# is teardown-only and cannot continue the agent.
STANDING_ADVICE_CADENCE_EVENTS: Final = frozenset({"SessionStart"})
_MAX_ADVICE_CONTEXT: Final = 1_200
_MAX_CONTENT_CHUNK: Final = 256 * 1024
# Ingest rejections that are recoverable: keep the outbox entry pending for a
# later drain. Anything else is permanently invalid and gets quarantined so it
# is never silently dropped as if committed.
# The drain budget is spent on service delivery only: its clock starts after the
# service connection is open (the connect has its own preflight bound below), so
# loading local state and a cold handshake no longer consume it. tb4n1 measured
# `drain_budget_exhausted` on 94% of hooks when the connect shared this clock. The owner kept
# the 0.2 s budget after tb4n5 and renamed that diagnostic `drain_pass_delivered_nothing`: it
# counts hook passes that delivered no row within the budget (the rows stay queued for the next
# pass or the sweeper), not lateness. Lateness is the outbox delivery lag in `observe status`.
_HOOK_DRAIN_BUDGET_SECONDS: Final = 0.20
_HOOK_DRAIN_ROW_LIMIT: Final = 8
# Stop is the turn boundary the closure gate decides at. The Stop pass drains the
# outbox toward the current frontier with a larger bounded slice, so the gate reads
# observed facts instead of "still draining". The slice is clamped so the gate's own
# status read keeps its reserve inside the host's ten-second Stop window.
_STOP_DRAIN_BUDGET_SECONDS: Final = 2.5
_STOP_DRAIN_ROW_LIMIT: Final = 64
_STOP_CLOSURE_GATE_RESERVE_SECONDS: Final = 5.0
# Headroom between the Stop drain's deadline and the gate's reserve check, for the local commit
# and store-lock wait that can follow the last ingest.
_STOP_DRAIN_DEADLINE_MARGIN_SECONDS: Final = 0.75
# While another owner holds the drain lease, the Stop pass waits for that owner's progress, but
# gives up once the workspace outbox has not moved at all for this long.
_STOP_DRAIN_STALL_SECONDS: Final = 0.75
# Every host renders a ten-second Stop window; the pass's observability budget is that window
# less a small allowance for interpreter start and the output write.
_STOP_PASS_BUDGET_SECONDS: Final = 9.5
# Native Claude/Cursor ordinary-profile content is transient by design: it cannot
# be copied to the structural outbox. Give every ordinary-profile pass a bounded
# chance to drain its structural RPC, and give content-bearing passes enough time
# to deliver the current event after its same-session prefix; bulk work remains
# the service sweeper's responsibility.
_NATIVE_CONTENT_DRAIN_BUDGET_SECONDS: Final = 1.0
_NATIVE_CONTENT_ROW_LIMIT: Final = 16
# Codex hard-clamps SessionEnd hooks to 3 seconds. Teardown records its local
# lifecycle/outbox intent and defers service delivery to the next hook or
# sweeper, so a cold service preflight cannot consume that host window.
_SESSION_END_DRAIN_BUDGET_SECONDS: Final = 0.15
# A run of consecutive service_unavailable rejections means the service is
# struggling now; yield the pass and let a later hook retry rather than
# spending the rest of the budget collecting identical failures.
_DRAIN_MAX_CONSECUTIVE_UNAVAILABLE: Final = 3
# Cold-connect preflight. A hook is always a fresh process, so this budget
# must clear a *cold* handshake, not a warm one: post-#210 a cold connect
# measures tens of milliseconds (it was ~1.0s when the handshake built the
# 69-schema catalog), and 1.0s leaves margin for daemon contention without
# letting a dead daemon consume the whole drain budget.
_HOOK_CONNECT_PREFLIGHT_SECONDS: Final = 1.0
# SessionStart is the primary auto-attach point, but the daemon often spawns on
# demand and may miss a session's opening moments; without a later re-attempt an
# unmapped session stayed unmapped for its whole life and its outbox retried as
# mapping_missing forever (#275). Low-frequency, once-per-turn events only --
# never the PreToolUse/PostToolUse storm. SessionEnd is teardown-only and has a
# three-second host clamp, so it records the lifecycle intent and defers pending
# rows but never spends the extra attach retry budget.
_AUTO_ATTACH_RETRY_EVENTS: Final = frozenset({"UserPromptSubmit", "Stop"})
_AUTO_ATTACH_RETRY_BUDGET_SECONDS: Final = 1.0
# The retry event has a one-second outer hook allowance. Leave room for its start RPC after the
# on-demand connector has spawned or found a service; SessionStart keeps the larger cold-start arm.
_AUTO_ATTACH_RETRY_SERVICE_START_BUDGET_SECONDS: Final = 0.4
_AUTO_ATTACH_START_DEADLINE_MS: Final = 5_000
_HOOK_SERVICE_START_BUDGET_SECONDS: Final = 1.0
# End-to-end observability contract for one hook pass, process start included.
# Never an abort point: the drain and preflight budgets own enforcement.
# Derived from the enforced budgets nested inside one pass plus an allowance
# for the local stages (import, store, advice), so the parts can never again
# drift past the whole and turn hook_budget_exceeded into noise (#288). The
# allowance covers the measured local cost on a full 1 MiB store with margin.
_HOOK_LOCAL_STAGE_ALLOWANCE_SECONDS: Final = 1.0
_HOOK_TOTAL_BUDGET_SECONDS: Final = (
    _HOOK_CONNECT_PREFLIGHT_SECONDS
    + _HOOK_SERVICE_START_BUDGET_SECONDS
    + _HOOK_DRAIN_BUDGET_SECONDS
    + _HOOK_LOCAL_STAGE_ALLOWANCE_SECONDS
)
# Every observation-store lock wait in one hook pass ends by this long after
# entry, chosen from the host window the pass runs in (the rendered hook
# timeouts): 5 s for Claude Code and Cursor tool events, 10 s for their
# SessionStart/Stop and for every Codex observe hook, 3 s for SessionEnd on
# all three. A pass can therefore no longer queue a fresh two seconds per
# acquisition past its host deadline; the complete invocation, not each call,
# is bounded, and the remainder is kept for the output write and interpreter
# start. Individual acquisitions keep their own two-second cap (#689).
_HOOK_STORE_LOCK_BUDGET_BY_WINDOW: Final = {3: 2.0, 5: 3.5, 10: 7.0}
# The post-compaction recap's extra obligations reads may run only in the first four seconds of a
# SessionStart pass (a 10 s host window), so they add nothing to the worst case that exists when the
# status read itself is slow and the drain and the output write keep their room.
_RECAP_READ_WINDOW_SECONDS: Final = 4.0


def _hook_host_window_seconds(source: ObservationSource, event: str | None) -> int:
    """Return the rendered host timeout for one observe pass (#689)."""

    if event == "SessionEnd":
        return 3
    if source is ObservationSource.CODEX_HOOK or event in {"SessionStart", "Stop"}:
        return 10
    return 5


# A pre-call fingerprint must be stored this long before the host's hook timeout: past it the
# host may run the call while the snapshot is still being taken (PR #1080).
_FINGERPRINT_HOST_MARGIN_SECONDS: Final = 1.0
_FINGERPRINT_DIAGNOSED: Final = frozenset(
    {
        "too_large",
        "timeout",
        "unreadable",
        "root_unusable",
        "store_unusable",
        "process_table_unreadable",
    }
)
_TIMING_REPORT_EVENTS: Final = frozenset({"SessionStart", "Stop", "SessionEnd"})
# The stages that partition one pass end to end, in order. Advice refresh is
# deliberately outside the local capture batch, so it is accounted for as its
# own stage rather than being hidden in the store duration.
_PASS_PARTITION_STAGES: Final = ("import", "resolve", "store", "advice", "drain", "deliver")
_ROUTINE_READ_TOOLS: Final = frozenset(
    {
        "glob",
        "grep",
        "list_files",
        "read",
        "read_file",
        "search",
        "view_file",
    }
)
_READ_ONLY_COMMANDS: Final = frozenset({"head", "ls", "pwd", "rg", "tail", "wc"})
_SESSION_START_SOURCES: Final = frozenset({"startup", "resume", "clear", "compact", "fork"})
_STRUCTURAL_ALLOW: Final = frozenset(
    {
        "tool_name",
        "runner_class",
        "exit_status",
        "correlation_id",
        "result_status",
        "permission_decision",
        "subagent_id",
        "duration_ms",
        "success",
        "denied",
        "hook_name",
        "tool_call_id",
        "parent_tool_call_id",
        "permission_kind",
        "decision_reason_code",
        "event_ordinal",
        "attempt",
        "claim_kind",
        "action",
        "changed_paths_digest",
        "mapping_hint",
        "capability_profile_id",
        "codex_version",
        "cursor_version",
        "model_id",
        "model_effort",
        "pairing_mode",
        "correlation_kind",
        "generation_id",
    }
)
_TOKEN_CHARS: Final = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._:/+-"
)
_MAX_TOKEN_CHARS: Final = 128
_CURSOR_SESSION_PREFIX: Final = "cursor:"
_CURSOR_ALIAS_FILE: Final = "cursor-session-aliases.json"
_CURSOR_ALIAS_LOCK: Final = "cursor-session-aliases.lock"
_MAX_CURSOR_ALIASES: Final = 64
_CURSOR_NON_EDIT_ACTIONS: Final = frozenset(
    {"cursor_tool_denied", "cursor_tool_failure", "routine_read"}
)
_CURSOR_UNTESTED_PROFILE_ID: Final = "untested"
_CURSOR_VERSION_TO_PROFILE: Final = {
    "3.17.8": "cursor-ide-3.17.8",
}


type AsyncRunner = Callable[[Callable[[], Awaitable[object]]], object]
type ServiceConnector = hooks_cli.ServiceConnector


def __getattr__(name: str) -> object:
    """Resolve the service-client seam on demand.

    ``connect_service`` stays a patchable module attribute (tests bind it to a
    forbidden connector) without ``finishup.service.client`` — and through it
    ``protocol.schemas``/jsonschema — being imported by hooks that never open a
    connection (#242).
    """

    if name == "connect_service":
        from finishup.service.client import connect_service

        return connect_service
    raise AttributeError(name)


def _connect_service() -> object:
    """Return the connector, honoring a module-attribute override."""

    override = globals().get("connect_service")
    if override is not None:
        return override
    from finishup.service.client import connect_service

    return connect_service


async def _connect_attachment_service(
    kind: ControlClientKind,
    *,
    workspace_locator: WorkspaceLocator | None = None,
    timeout_seconds: float | None = None,
) -> object:
    """Prime only the selected service, within the synchronous hook budget.

    Ordinary drains remain connect-only. The fixed launcher inherits instance pinning;
    this path never supersedes a holder or conveys vault/disclosure authority.
    """

    from finishup.service.client import connect_service, connect_service_on_demand

    override = globals().get("connect_service")
    if override is not None and override is not connect_service:
        return await cast(Callable[..., Awaitable[object]], override)(
            kind, workspace_locator=workspace_locator
        )
    return await connect_service_on_demand(
        kind,
        workspace_locator=workspace_locator,
        timeout_seconds=(
            _HOOK_SERVICE_START_BUDGET_SECONDS if timeout_seconds is None else timeout_seconds
        ),
        supersede_incompatible=False,
    )


class _HookDrainClient(Protocol):
    async def observation_ingest(
        self, body: DomainJsonValue, *, deadline_ms: int | None = None
    ) -> DomainJsonValue: ...

    async def close(self) -> None: ...


type HookDrainConnector = Callable[[ControlClientKind], Awaitable[_HookDrainClient]]


class _StartClient(Protocol):
    async def start(self, request: object, *, deadline_ms: int | None = None) -> object: ...

    async def close(self) -> None: ...


type HookStartConnector = Callable[[ControlClientKind], Awaitable[_StartClient]]


@dataclass(frozen=True, slots=True)
class AutoAttachOutcome:
    """Result of one consented auto-attach attempt.

    Exactly one of the two fields is set: a start-derived mapping, or the closed
    hook-diagnostic reason explaining why no mapping resulted (#459). A None
    mapping without a reason is not a legal outcome.
    """

    mapping: LifecycleMapping | None
    reason: str | None
    recovered: bool = False
    candidate_count: int | None = None

    def __post_init__(self) -> None:
        if (self.mapping is None) == (self.reason is None):
            raise ValueError("auto_attach_outcome_invalid")
        if self.candidate_count is not None and (
            self.reason != "auto_attach_binding_ambiguous"
            or type(self.candidate_count) is not int
            or not 2 <= self.candidate_count <= 1_000_000
        ):
            raise ValueError("auto_attach_outcome_invalid")


# Service-side `start` refusals, classified over the exhaustive public error
# table into the closed hook-diagnostic vocabulary. Retry-later classes share
# `service_unavailable` because the turn-boundary retry (#275) covers them; the
# rest name a cause that a retry will not clear.
_AUTO_ATTACH_ERROR_REASONS: Final[Mapping[PublicErrorCode, str]] = MappingProxyType(
    {
        PublicErrorCode.INVALID_REQUEST: "auto_attach_refused",
        PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: "auto_attach_refused",
        PublicErrorCode.SESSION_NOT_FOUND: "auto_attach_refused",
        PublicErrorCode.EVENT_INVALID: "auto_attach_refused",
        PublicErrorCode.LIMIT_EXCEEDED: "auto_attach_refused",
        PublicErrorCode.PROVIDER_REFUSED: "auto_attach_refused",
        PublicErrorCode.SEMANTIC_RESULT_INVALID: "auto_attach_refused",
        PublicErrorCode.SESSION_CONFLICT: "auto_attach_conflict",
        PublicErrorCode.IDEMPOTENCY_CONFLICT: "auto_attach_conflict",
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT: "auto_attach_conflict",
        PublicErrorCode.OPERATION_PENDING: "service_unavailable",
        PublicErrorCode.FRONTIER_CONFLICT: "service_unavailable",
        PublicErrorCode.BUNDLE_BUSY: "service_unavailable",
        PublicErrorCode.MIGRATION_REQUIRED: "service_unavailable",
        PublicErrorCode.SERVICE_UNAVAILABLE: "service_unavailable",
        PublicErrorCode.PROVIDER_UNAVAILABLE: "service_unavailable",
        PublicErrorCode.PROVIDER_TIMEOUT: "service_unavailable",
        PublicErrorCode.CANCELLED: "service_unavailable",
        PublicErrorCode.INTERNAL_ERROR: "service_unavailable",
        PublicErrorCode.STORAGE_UNSAFE: "storage_unsafe",
        PublicErrorCode.STORAGE_CORRUPT: "storage_corrupt",
        PublicErrorCode.VAULT_LOCKED: "vault_locked",
        PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: "privacy_authority_required",
    }
)
if set(_AUTO_ATTACH_ERROR_REASONS) != set(PublicErrorCode):
    raise RuntimeError("auto_attach_error_reasons_not_exhaustive")

# Transport-level failures over the closed ControlError reason set; reasons
# absent here (a future addition) fall back to `service_unavailable`.
_AUTO_ATTACH_CONTROL_REASONS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "service_incompatible": "service_incompatible",
        "protocol_mismatch": "service_incompatible",
        "vault_locked": "vault_locked",
        "request_timeout": "timeout",
        "privacy_projection_blocked": "privacy_authority_required",
    }
)


def _attachment_recovery_context(reason: str) -> str:
    """Render only trusted classifications, never host/error payload text."""

    if reason == "service_incompatible":
        return (
            "FinishUP attachment pending: service_incompatible. The selected service has an "
            "incompatible holder; the hook did not replace it. Call start and follow its exact "
            "service recovery continuation. "
        )
    if reason == "service_handshake_failed":
        return (
            "FinishUP attachment pending: service_handshake_failed. The running local service "
            "closed the connection while setting it up; the hook did not replace it. Call start "
            "and follow its typed result, which names the cause or the diagnostics to read. "
        )
    # A timed-out attachment may have sent start under the hook's own request identity, which
    # the agent never sees, so no timeout replay token applies: the agent's own start is the
    # recovery (issue #739).
    if reason in {"service_unavailable", "timeout"}:
        return (
            "FinishUP attachment pending: service_unavailable. The bounded service connection "
            "did not complete. Call start before material work to finish service startup and "
            "attachment; later turn hooks also retry within their budget. "
        )
    if reason == "auto_attach_conflict":
        return (
            "FinishUP attachment refused: auto_attach_conflict. The service answered but task "
            "admission conflicted. Use a held session selector or follow start's explicit "
            "admission continuation; restarting the service does not select a task. "
        )
    # The local diagnostic retains the exact closed reason. The model-facing fallback stays
    # reason-neutral because storage, consent, and authoring failures are not mapping failures.
    return (
        "FinishUP attachment incomplete: no mapping was produced. Follow the typed start result. "
    )


def _now() -> Timestamp:
    current = datetime.now(UTC)
    stamp = current.replace(microsecond=(current.microsecond // 1000) * 1000)
    return timestamp_from_datetime(stamp)


def _token_or_none(value: object) -> str | None:
    if type(value) is not str or not value or len(value) > _MAX_TOKEN_CHARS:
        return None
    if any(ch not in _TOKEN_CHARS for ch in value):
        return None
    if value[0] in "._:/+-":
        return None
    return value


def _payload_text(payload: Mapping[str, JsonValue], name: str) -> str | None:
    """A free-text host field read transiently (never stored): the string, or ``None``."""

    value = payload.get(name)
    return value if type(value) is str and value else None


def _consistent_alias_token(
    payload: Mapping[str, JsonValue], names: tuple[str, ...]
) -> tuple[str | None, bool]:
    """Normalize one host alias family without choosing through a conflict.

    Native child hooks have used several spellings for the same identity.  A
    malformed or contradictory spelling is deliberately treated as absent so
    the downstream host-lineage normalizer can report an attribution gap;
    selecting the first alias would let one source hide another.
    """

    values: list[str] = []
    supplied = False
    nested = payload.get("tool_input")
    nested_payload = nested if isinstance(nested, Mapping) else None
    for aliases in (payload, nested_payload):
        if aliases is None:
            continue
        for name in names:
            if name not in aliases:
                continue
            supplied = True
            raw = aliases.get(name)
            if raw is None:
                continue
            token = _token_or_none(raw)
            if token is None:
                return None, False
            values.append(token)
    if any(value != values[0] for value in values[1:]):
        return None, False
    return (values[0] if values else None), supplied


def _int_or_none(value: object) -> int | None:
    if type(value) is bool or type(value) is not int:
        return None
    if not 0 <= value <= 9_007_199_254_740_991:
        return None
    return value


def _bool_or_none(value: object) -> bool | None:
    return value if type(value) is bool else None


def _cursor_alias_paths(_state: Path | None) -> tuple[Path, Path]:
    from finishup.config.paths import state_dir

    root = state_dir() if _state is None else _state
    directory = root / "observation"
    return directory / _CURSOR_ALIAS_FILE, directory / _CURSOR_ALIAS_LOCK


def _load_cursor_aliases(path: Path) -> dict[str, str]:
    import json

    try:
        if path.is_symlink() or path.stat().st_size > 65_536:
            return {}
        loaded = json.loads(path.read_bytes())
    except OSError, ValueError:
        return {}
    if not isinstance(loaded, dict):
        return {}
    aliases: dict[str, str] = {}
    for key, value in cast(dict[object, object], loaded).items():
        conversation = _token_or_none(key)
        session = _token_or_none(value)
        if conversation is not None and session is not None:
            aliases[conversation] = session
    return aliases


def _aliased_cursor_session(conversation: str, *, _state: Path | None) -> str | None:
    """Return the session identifier a sessionStart validated for this conversation."""

    path, _lock = _cursor_alias_paths(_state)
    return _load_cursor_aliases(path).get(conversation)


def _bind_cursor_session_alias(conversation: str, session: str, *, _state: Path | None) -> None:
    """Durably bind one Cursor conversation to one validated session identifier.

    Both identifiers come from the same host payload, so the pair itself is the
    validation. The bounded local map lets later events that carry only the
    conversation identifier keep resolving to the same FinishUP session instead of
    splitting one host conversation across identities (#417).
    """

    import json

    from finishup.config.paths import PathSafetyError, ensure_owner_only_dir

    try:
        import fcntl
    except ImportError:  # pragma: no cover - supported hook hosts are POSIX
        fcntl = None  # type: ignore[assignment]

    path, lock_path = _cursor_alias_paths(_state)
    try:
        ensure_owner_only_dir(path.parent)
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        lock_descriptor = os.open(lock_path, flags, 0o600)
        try:
            os.fchmod(lock_descriptor, 0o600)
            if fcntl is not None:
                fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
            aliases = _load_cursor_aliases(path)
            aliases.pop(conversation, None)
            aliases[conversation] = session
            while len(aliases) > _MAX_CURSOR_ALIASES:
                aliases.pop(next(iter(aliases)))
            encoded = json.dumps(aliases, separators=(",", ":"), sort_keys=True).encode("utf-8")
            temporary = path.with_name(path.name + ".tmp")
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_CLOEXEC", 0),
                0o600,
            )
            try:
                os.fchmod(descriptor, 0o600)
                os.write(descriptor, encoded)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary, path)
        finally:
            os.close(lock_descriptor)
    except OSError, PathSafetyError, ValueError:
        return


def _cursor_capability_profile_id(cursor_version: object) -> str | None:
    """Map an exact Cursor version to its reviewed profile.

    Hook payloads may report a version from any Cursor surface. Only the IDE
    profile owns the reviewed native hook set; the recognized CLI profile has
    no hook cell and therefore remains ``untested`` at hook ingress. An omitted
    version returns ``None`` so the closed pairing contract can apply the
    installed legacy carrier fallback; a supplied but unknown version remains
    explicitly untested and uses the conservative paired contract. Importing
    the adapter here would pull in the full plugin/rendering stack, so keep the
    fail-closed table local and never infer support for a neighboring surface
    or version.
    """

    version = _token_or_none(cursor_version)
    if version is None:
        return None
    return _CURSOR_VERSION_TO_PROFILE.get(version, _CURSOR_UNTESTED_PROFILE_ID)


def _cursor_nested_edit_path(payload: Mapping[str, JsonValue]) -> str | None:
    """Return one bounded edit path from a Cursor tool input, or nothing.

    The string is used only to derive a path commitment. It is not stored.
    A value over the workspace-locator bound is omitted rather than clipped.
    """

    nested = payload.get("tool_input")
    if not isinstance(nested, Mapping):
        return None
    for key in ("path", "file_path", "target_file", "filePath"):
        value = nested.get(key)
        if type(value) is not str or not value:
            continue
        if len(value.encode("utf-8")) > 8_192 or "\n" in value or "\r" in value:
            return None
        return value
    return None


def _resolve_cursor_workspace(
    payload: Mapping[str, JsonValue], explicit_workspace: str | None
) -> str | None:
    """Resolve a Cursor workspace without retaining the host's root list.

    ``workspace_binding`` owns the validation and source precedence.  This
    wrapper returns one resolved path and no payload data.
    """

    resolved = resolve_workspace_locator(
        explicit=explicit_workspace,
        payload=payload,
        env=os.environ,
    )
    # The sibling resolver already performs bounded lexical normalization and
    # rejects symlinked components.  Do not resolve the returned path again:
    # that would re-open the exact symlink race this boundary closes.
    return resolved if type(resolved) is str and resolved else None


def _routine_read_action(payload: Mapping[str, JsonValue]) -> bool:
    """Return the adapter-owned routine candidate bit.

    Classification rules live in the domain module so every host adapter uses
    the same closed read set and shell safety checks.  Outcome facts are
    intentionally ignored here: a failed read is still a read-shaped attempt
    and must remain protected by the full classifier.
    """

    return is_routine_read_candidate(payload)


_COMMAND_ARGUMENT_KEYS: Final = ("cmd", "command", "argv")
_COMMAND_COMMITMENT_RE: Final = re.compile(r"^hmac-sha256:[0-9a-f]{64}$", re.ASCII)


def _is_command_tool(tool_name: object) -> bool:
    """A host shell/exec tool whose ``tool_input`` names a command, never an edit tool."""

    token = _token_or_none(tool_name)
    if token is None or is_edit_tool_name(token):
        return False
    lowered = token.casefold()
    return lowered in _SHELL_TOOLS or any(hint in lowered for hint in ("shell", "exec", "terminal"))


def command_commitment_for_payload(
    payload: Mapping[str, JsonValue], key_material: bytes
) -> str | None:
    """Commit to a host command argument inside the hook process, then drop the text (#909).

    Reads ``tool_input.cmd``, ``tool_input.command`` or ``tool_input.argv`` for a shell/exec
    tool, applies the shared light normalization, and returns the installation-keyed
    ``hmac-sha256:`` commitment. The command text is never returned, stored, or logged here; a
    payload without a usable command argument yields ``None``.
    """

    commitment = command_identity_fields_for_payload(payload, key_material).get(
        "command_commitment"
    )
    return commitment if type(commitment) is str else None


def command_identity_fields_for_payload(
    payload: Mapping[str, JsonValue], key_material: bytes
) -> dict[str, JsonValue]:
    """The keyed command identity structural fields for one host command argument.

    ``command_commitment`` commits to the whole normalized command; a compound, wrapped,
    prefixed or redirected command also yields ``command_segment_commitments`` (sorted keyed
    commitments to the simple commands it runs) and ``command_composition`` (#977), which match a
    planned verification to one part of a composed run. Only keyed values leave this function.
    """

    if not _is_command_tool(payload.get("tool_name")):
        return {}
    tool_input = payload.get("tool_input")
    if not isinstance(tool_input, Mapping):
        return {}
    nested = cast(Mapping[str, JsonValue], tool_input)
    for key in _COMMAND_ARGUMENT_KEYS:
        value = nested.get(key)
        if value is None:
            continue
        normalized = normalize_observed_command(value)
        if normalized is None:
            return {}
        fields: dict[str, JsonValue] = {
            "command_commitment": observed_command_commitment(key_material, normalized)
        }
        segments = command_segment_commitments(key_material, normalized)
        if segments is not None:
            fields["command_segment_commitments"] = list(segments[0])
            fields["command_composition"] = segments[1]
        return fields
    return {}


def _supplied_segment_fields(payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Re-validate segment fields a host normalizer or the spool already computed (#977)."""

    segments = payload.get("command_segment_commitments")
    composition = payload.get("command_composition")
    if not isinstance(segments, list | tuple) or composition not in COMMAND_COMPOSITIONS:
        return {}
    items = list(cast(list[JsonValue], segments))
    if (
        not 1 <= len(items) <= MAX_COMMAND_COMMITMENTS
        or any(
            type(item) is not str or not _COMMAND_COMMITMENT_RE.fullmatch(item) for item in items
        )
        or items != sorted(set(cast(list[str], items)))
    ):
        return {}
    return {"command_segment_commitments": items, "command_composition": composition}


def _attach_command_commitment(
    structural: dict[str, JsonValue],
    payload: Mapping[str, JsonValue],
    *,
    _state: Path | None,
) -> None:
    """Add the keyed command identity to a host-normalized structural row (Claude, Cursor).

    Those normalizers forward only their structural dict to the common path, so the raw
    ``tool_input`` never leaves this process. Failing to read the installation key only omits the
    identity: the failure remains live until an exact covering rerun or explicit acknowledgement.
    """

    if not _is_command_tool(payload.get("tool_name")):
        return
    try:
        fields = command_identity_fields_for_payload(
            payload, LocalObservationStore(_state=_state).key_material()
        )
    except Exception:
        return
    structural.update(fields)


def _extract_structural(
    payload: Mapping[str, JsonValue],
    event_name: str,
    *,
    classification: ObservationClassification | None = None,
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    host_outcome: _NativeOutcomeFacts | None = None,
) -> JsonObject:
    """Extract bounded structural fields and apply the typed selection result.

    A Codex ``PostToolUse`` carries its outcome nested in ``tool_response``; ``host_outcome`` is
    that closed reading when the caller already made it (``handle_observe`` does, so selection
    and the envelope share one decision), and it is read here otherwise.
    """

    codex_post = source is ObservationSource.CODEX_HOOK and event_name == "PostToolUse"
    if codex_post and host_outcome is None:
        host_outcome = _codex_post_tool_outcome(payload)
    fields: dict[str, JsonValue] = {"hook_name": event_name}
    tool_name = _token_or_none(payload.get("tool_name"))
    if tool_name is not None:
        fields["tool_name"] = tool_name
    # A host normalizer (Claude Code, Cursor) or the legacy spool already committed to the command
    # in the hook process; only the keyed value crosses this boundary, never command text.
    supplied_commitment = payload.get("command_commitment")
    if type(supplied_commitment) is str and _COMMAND_COMMITMENT_RE.fullmatch(supplied_commitment):
        fields["command_commitment"] = supplied_commitment
        fields.update(_supplied_segment_fields(payload))
    for key in (
        "correlation_id",
        "parent_tool_call_id",
        "permission_decision",
        "permission_kind",
        "decision_reason_code",
        "result_status",
        "claim_kind",
        "action",
        "changed_paths_digest",
        "mapping_hint",
        "capability_profile_id",
        "codex_version",
        "cursor_version",
        "model_id",
        "model_effort",
        "pairing_mode",
        "correlation_kind",
        "generation_id",
    ):
        token = _token_or_none(payload.get(key))
        if key == "action" and token is not None and token.casefold() == "routine_read":
            # ``routine_read`` is a service-owned marker.  A host or nested
            # tool payload cannot inject it into an envelope.
            continue
        if token is not None and key in _STRUCTURAL_ALLOW:
            fields[key] = token
    # Host child hooks use ``subagent_id`` (Codex), ``agent_id`` (Claude), or
    # ``agent_thread_id`` (some stream records).  Keep one canonical structural
    # key and fail closed when a payload supplies contradictory aliases.
    subagent_id, subagent_supplied = _consistent_alias_token(
        payload, ("subagent_id", "agent_id", "agent_thread_id")
    )
    if subagent_supplied and subagent_id is not None:
        fields["subagent_id"] = subagent_id
    # Codex names the host tool-call id ``tool_use_id``. Normalize it to the
    # canonical structural key here, with the host spelling taking precedence
    # over legacy aliases exactly as it does in the pairing path. The wire
    # schema enumerates structural fields, so the identity must land under
    # ``tool_call_id`` or it is discarded at the boundary (#274).
    if event_name in {"SubagentStart", "SubagentStop"}:
        # For child events these are parent-call aliases.  Use the canonical
        # parent key so hook and stream ingress share the same registry alias;
        # an invalid/conflicting family remains absent and is handled as a gap.
        parent_tool_aliases_present = any(
            name in payload for name in ("parent_tool_call_id", "tool_call_id", "tool_use_id")
        )
        parent_tool_call_id, _parent_tool_aliases_valid = _consistent_alias_token(
            payload, ("parent_tool_call_id", "tool_call_id", "tool_use_id")
        )
        if parent_tool_aliases_present and parent_tool_call_id is not None:
            fields["parent_tool_call_id"] = parent_tool_call_id
            fields.pop("tool_call_id", None)
        elif parent_tool_aliases_present:
            # The initial allowlist pass may have copied a valid-looking
            # ``parent_tool_call_id`` before the complete alias family was
            # checked.  Remove it on an invalid/conflicting family.
            fields.pop("parent_tool_call_id", None)
            fields.pop("tool_call_id", None)
            fields.pop("subagent_id", None)
    else:
        tool_call_id = _token_or_none(payload.get("tool_use_id")) or _token_or_none(
            payload.get("tool_call_id")
        )
        if tool_call_id is not None:
            fields["tool_call_id"] = tool_call_id
    # Nested tool_input / tool_response never contribute prose — only structural scalars.
    tool_input = payload.get("tool_input")
    if isinstance(tool_input, Mapping):
        nested = cast(Mapping[str, JsonValue], tool_input)
        for key in ("tool_name", "permission_kind", "claim_kind", "action", "mapping_hint"):
            token = _token_or_none(nested.get(key))
            if key == "action" and token is not None and token.casefold() == "routine_read":
                continue
            if token is not None and key not in fields:
                fields[key] = token
        digest = _token_or_none(nested.get("changed_paths_digest"))
        if digest is not None and "changed_paths_digest" not in fields:
            fields["changed_paths_digest"] = digest
    if event_name == "PostToolUse":
        from finishup.cli.hooks import cooperative_start_identity

        child_start = cooperative_start_identity(payload)
        fields.update(child_start)
        if child_start:
            # Attach-call aliases must agree with each other, but the parent spawn call is
            # a different identity. An invalid supplied family cannot weaken to child-only.
            for names in (("tool_use_id", "tool_call_id"), ("parent_tool_call_id",)):
                call_id, _valid = _consistent_alias_token(payload, names)
                values = [
                    source[name]
                    for source in (payload, tool_input)
                    if isinstance(source, Mapping)
                    for name in names
                    if name in source
                ]
                if values and (
                    call_id is None or any(_token_or_none(value) is None for value in values)
                ):
                    fields.pop("subagent_id", None)
    if classification is None and codex_post and host_outcome is not None:
        # Selection must see the same outcome the envelope records, or a failed read could be
        # summarized as a proven success and refused later by the summary builder (#753).
        classification_payload = dict(payload)
        _merge_outcome_facts(classification_payload, host_outcome)
        classification = classify_observation(classification_payload, event_name)
    selected = classification or classify_observation(payload, event_name)
    if selected.routine_candidate and (
        event_name in {"PreToolUse", "preToolUse"} or selected.proven_routine_success
    ):
        # The marker is emitted only from the typed classifier.  It is never
        # copied from host ``action`` or ``tool_input.action`` text.
        fields["action"] = "routine_read"
    for key in ("exit_status", "duration_ms", "event_ordinal", "attempt"):
        number = _int_or_none(payload.get(key))
        if number is not None:
            fields[key] = number
    for key in ("success", "denied"):
        flag = _bool_or_none(payload.get(key))
        if flag is not None:
            fields[key] = flag
    if codex_post and host_outcome is not None:
        # Codex 0.157.x states every tool outcome inside ``tool_response`` only: a nested
        # ``exit_code``, an ``Exit code: N`` or ``Process exited with code N`` header, or MCP's
        # ``isError``. Keep the closed facts so a shell, exec or patch result is not an
        # outcome-less call (#883, #910); the result text itself is never copied here.
        _merge_outcome_facts(fields, host_outcome)
    # Classification can prove success from nested host result aliases (for example
    # tool_response.exit_code). Preserve that bounded fact beside the routine marker:
    # summary construction revalidates the persisted envelope after process restart.
    if selected.proven_routine_success:
        fields["success"] = True
    runner = command_runner_class(payload)
    if runner is not None and tool_name is not None:
        fields["runner_class"] = runner
    # Permission outcome aliases commonly seen in host payloads.
    decision = _token_or_none(payload.get("decision"))
    if decision is not None and "permission_decision" not in fields:
        fields["permission_decision"] = decision
    if event_name == "PostToolUse" and OBSERVED_IMAGES_KEY in payload:
        # Digest-only image facts the hook ingress computed before it dropped the bytes (P3-2,
        # issue #1013). The ingress readers discard any host value under this reserved key, so
        # only facts this process derived reach here; a malformed set is dropped, never repaired.
        with contextlib.suppress(ProtocolValueError):
            fields["observed_images"] = list(
                validate_observed_images(payload.get(OBSERVED_IMAGES_KEY))
            )
    return JsonObject(fields)


def _pairing_contract(
    payload: Mapping[str, JsonValue], source: ObservationSource | None = None
) -> tuple[str, str]:
    """Resolve pairing from the closed host/profile contract.

    The marker is an observation of the selected profile, not an authority that
    raw hook input can rewrite.  In particular, Codex remains paired even if a
    caller supplies a forged ``post_only`` marker.  A future paired Claude or
    Cursor profile must be registered in the exact profile table.
    """

    if source is not None:
        harness = (
            "claude"
            if source is ObservationSource.CLAUDE_HOOK
            else "cursor"
            if source is ObservationSource.CURSOR_HOOK
            else "codex"
        )
        profile_id = payload.get("capability_profile_id")
        return observation_pairing_contract(
            harness, profile_id if isinstance(profile_id, str) else None
        )
    return "paired", "tool_call_id"


def _pairing_correlation(payload: Mapping[str, JsonValue], correlation_kind: str) -> str | None:
    """Return a real tool identity, never a host generation identity."""

    if correlation_kind == "none":
        return None
    direct = _token_or_none(payload.get("tool_use_id")) or _token_or_none(
        payload.get("tool_call_id")
    )
    if direct is not None:
        return direct
    if correlation_kind == "generation_id":
        return None
    return _token_or_none(payload.get("correlation_id")) or _token_or_none(
        payload.get("parent_tool_call_id")
    )


def _source_identity(
    event_name: str,
    payload: Mapping[str, JsonValue],
    structural: JsonObject,
    *,
    event_ordinal: int,
) -> str:
    host_ids: dict[str, JsonValue] = {"event_ordinal": event_ordinal}
    for key in (
        "tool_use_id",
        "tool_call_id",
        "correlation_id",
        "event_id",
        "id",
        "parent_tool_call_id",
        "subagent_id",
        "turn_id",
        # Frozen legacy identifier (ADR-048): the spool replay key, also in pre-upgrade spools.
        "_yoetz_spool_id",
    ):
        token = _token_or_none(payload.get(key))
        if token is not None:
            host_ids[key] = token
    material = JsonObject(
        {
            "event_kind": event_name,
            "host_ids": JsonObject(host_ids),
            "session_id": _token_or_none(payload.get("session_id")) or "unknown",
            "structural": structural,
        }
    )
    digest = canonical_digest(material).removeprefix("sha256:")
    return f"hook:{digest[:48]}"


def _is_pre_event(event_name: str) -> bool:
    return event_name in {"PreToolUse", "PreCompact", "SubagentStart", "PermissionRequest"}


def _is_post_event(event_name: str) -> bool:
    return event_name in {"PostToolUse", "PostCompact", "SubagentStop"}


@dataclass(frozen=True, slots=True)
class _ObservationLane:
    """The host lane and the effective service lane for one hook event."""

    host_session_id: str
    effective_session_id: str
    is_child: bool = False
    attribution_gap: bool = False


def _narrow_tool_result(payload: Mapping[str, JsonValue]) -> Mapping[str, JsonValue] | None:
    """Parse only a scoped FinishUP result for child-route reconciliation."""

    tool_name = _token_or_none(payload.get("tool_name"))
    if tool_name not in FINISHUP_OWNED_TOOL_NAMES:
        return None
    from finishup.cli.hooks import _extract_start_result  # pyright: ignore[reportPrivateUsage]

    return _extract_start_result(payload.get("tool_response"))


def _validated_result_task_id(result: Mapping[str, JsonValue] | None) -> str | None:
    """Return a service result task id only when the narrow result shape validates it."""

    if result is None:
        return None
    task_id = result.get("task_id")
    return task_id if type(task_id) is str and is_valid_id(IdKind.TASK, task_id) else None


def _result_task_id_is_malformed(result: Mapping[str, JsonValue] | None) -> bool:
    """Return whether a narrow result supplied a task field that failed validation."""

    return result is not None and "task_id" in result and _validated_result_task_id(result) is None


def _nested_service_session_fact(
    payload: Mapping[str, JsonValue],
) -> tuple[str | None, bool, bool]:
    """Read a nested FinishUP request session without confusing it with the host session."""

    nested = payload.get("tool_input")
    if not isinstance(nested, Mapping) or "session_id" not in nested:
        return None, False, True
    raw = nested.get("session_id")
    if raw is None:
        return None, True, True
    if type(raw) is not str or not is_valid_id(IdKind.SESSION, raw):
        return None, True, False
    return raw, True, True


def _task_lane_for_result(
    payload: Mapping[str, JsonValue],
    *,
    host_session_id: str,
    harness_id: Literal["claude", "codex", "cursor"],
    _state: Path | None,
) -> _ObservationLane | None:
    """Resolve a child lane from a service-authored result, if one is already bound."""

    result = _narrow_tool_result(payload)
    if result is None:
        return None
    if _result_task_id_is_malformed(result):
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    task_id = _validated_result_task_id(result)
    if task_id is None:
        return None
    nested_session_id, nested_session_supplied, nested_session_valid = _nested_service_session_fact(
        payload
    )
    if nested_session_supplied and not nested_session_valid:
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    parent_task_id = result.get("parent_task_id")
    if parent_task_id is not None and (
        type(parent_task_id) is not str or not is_valid_id(IdKind.TASK, parent_task_id)
    ):
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    parent_mapping = load_mapping(host_session_id, _state=_state)
    if parent_mapping is not None and task_id == parent_mapping.yoetz_task_id:
        if nested_session_id is not None and nested_session_id != parent_mapping.yoetz_session_id:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        return _ObservationLane(host_session_id, host_session_id)
    if (
        result.get("outcome") == "delegated"
        and parent_mapping is not None
        and type(parent_task_id) is str
        and parent_task_id == parent_mapping.yoetz_task_id
    ):
        # A delegation result reserves a child but is still authored by the current owner.
        if nested_session_id is not None and nested_session_id != parent_mapping.yoetz_session_id:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        return _ObservationLane(host_session_id, host_session_id)
    try:
        task_lane = scoped_child_session_id(
            host_session_id,
            host=harness_id,
            identity=task_id,
            identity_kind="task",
        )
    except ProtocolValueError, TypeError, ValueError:
        return None
    child_mapping = load_mapping(task_lane, _state=_state)
    if child_mapping is not None and child_mapping.yoetz_task_id == task_id:
        if nested_session_id is not None and nested_session_id != child_mapping.yoetz_session_id:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        return _ObservationLane(host_session_id, task_lane, is_child=True)
    # An explicit lineage result with no matching task lane is known child work, but it cannot be
    # safely leased to the parent. Keep the structural event on the host lane and let the caller
    # record a mapping gap without sending it to the parent's service route.
    if parent_mapping is not None and task_id != parent_mapping.yoetz_task_id:
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    if type(parent_task_id) is str and task_id != parent_task_id:
        # The result explicitly names a parent lineage even when the raw host
        # mapping is still queued or has been removed. It cannot be leased to
        # the raw session without a validated child alias.
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    if parent_mapping is None:
        # A valid service result without any held parent route is still foreign
        # to this host lane. Keep it out of a future parent auto-attach path.
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    return None


def _child_lane_rollout(
    payload: Mapping[str, JsonValue],
    *,
    lane: _ObservationLane,
    locator: CodexSessionStreamLocator,
    hook_provided_path: str | None,
) -> Path | None:
    """Return the delegated child's own rollout for one validated host-identity child lane.

    Only a lane derived from this callback's host session and its host child identity may read a
    child rollout, and only when that rollout's v2 header names the same child thread and this
    session as its spawner (#841). Task-derived and explicit lanes carry no host child thread, so
    they never select a file. The returned path is local-only.
    """

    from finishup.cli.hooks import (
        _child_identity_from_payload,  # pyright: ignore[reportPrivateUsage]
    )

    child_id, _supplied, valid = _child_identity_from_payload(payload)
    if not valid or child_id is None:
        return None
    try:
        expected_lane = scoped_child_session_id(
            lane.host_session_id,
            host="codex",
            identity=child_id,
            identity_kind="host",
        )
    except ProtocolValueError, TypeError, ValueError:
        return None
    if expected_lane != lane.effective_session_id:
        return None
    path, result = locator.resolve_child_rollout(hook_provided_path, child_thread_id=child_id)
    header = result.header
    if path is None or header is None or lane.host_session_id not in header.spawning_sessions:
        return None
    return path


def _pairing_harness(source: ObservationSource) -> Literal["claude", "codex", "cursor"]:
    if source is ObservationSource.CLAUDE_HOOK:
        return "claude"
    if source is ObservationSource.CURSOR_HOOK:
        return "cursor"
    return "codex"


def _resolve_observation_lane(
    payload: Mapping[str, JsonValue],
    *,
    event_name: str,
    source: ObservationSource,
    _state: Path | None,
    explicit_session_id: str | None = None,
    explicit_attribution_gap: bool = False,
) -> _ObservationLane:
    """Select a validated child lane while preserving ordinary parent callbacks."""

    try:
        host_session_id = validate_codex_session_id(payload.get("session_id"))
    except ProtocolValueError:
        # The caller performs the public invalid-session diagnostic. This fallback only keeps
        # this helper total for tests and degraded ingress.
        return _ObservationLane("invalid-session", "invalid-session")

    # A derived child lane is an internal namespace.  It must never be accepted
    # as a new parent host session when its mapping has been removed or its
    # service result names a different task.  The normal parent session is
    # handled below, where optional host aliases remain ordinary unless they
    # establish a validated child route.
    reserved_mapping = None
    if is_scoped_child_session_id(host_session_id):
        reserved_mapping = load_mapping(host_session_id, _state=_state)
        if reserved_mapping is None:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        if event_name in {"SubagentStart", "SubagentStop"}:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        nested_session_id, nested_session_supplied, nested_session_valid = (
            _nested_service_session_fact(payload)
        )
        if nested_session_supplied and not nested_session_valid:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        if nested_session_id is not None and nested_session_id != reserved_mapping.yoetz_session_id:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        reserved_result = _narrow_tool_result(payload)
        if _result_task_id_is_malformed(reserved_result):
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        result_task_id = _validated_result_task_id(reserved_result)
        if result_task_id is not None and result_task_id != reserved_mapping.yoetz_task_id:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
        return _ObservationLane(host_session_id, host_session_id, is_child=True)
    if event_name in {"SubagentStart", "SubagentStop"}:
        # Native lifecycle hooks describe the parent lineage commitment. They never lease the
        # child work lane, even when a child identity is present on the event.
        return _ObservationLane(host_session_id, host_session_id)

    harness_id = _pairing_harness(source)
    if explicit_session_id is not None:
        try:
            candidate = validate_codex_session_id(explicit_session_id)
        except ProtocolValueError:
            candidate = host_session_id
        if candidate != host_session_id and load_mapping(candidate, _state=_state) is not None:
            return _ObservationLane(
                host_session_id,
                candidate,
                is_child=True,
                attribution_gap=explicit_attribution_gap,
            )
        if explicit_attribution_gap:
            return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)

    from finishup.cli.hooks import (
        _child_identity_from_payload,  # pyright: ignore[reportPrivateUsage]
    )

    child_id, aliases_supplied, aliases_valid = _child_identity_from_payload(payload)
    result = _narrow_tool_result(payload)
    nested_session_id, nested_session_supplied, nested_session_valid = _nested_service_session_fact(
        payload
    )
    if nested_session_supplied and not nested_session_valid:
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    if _result_task_id_is_malformed(result):
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    result_task_id = _validated_result_task_id(result)
    if aliases_supplied and not aliases_valid:
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    if child_id is not None:
        try:
            child_lane = scoped_child_session_id(
                host_session_id,
                host=harness_id,
                identity=child_id,
                identity_kind="host",
            )
        except ProtocolValueError, TypeError, ValueError:
            child_lane = None
        if child_lane is not None:
            child_mapping = load_mapping(child_lane, _state=_state)
            if child_mapping is not None:
                if (result_task_id is None or result_task_id == child_mapping.yoetz_task_id) and (
                    nested_session_id is None or nested_session_id == child_mapping.yoetz_session_id
                ):
                    return _ObservationLane(host_session_id, child_lane, is_child=True)
                # A stale host alias must not win over a service result naming
                # another child.  A separately validated task alias may still
                # route that result; otherwise keep it as an explicit gap.
                result_lane = _task_lane_for_result(
                    payload,
                    host_session_id=host_session_id,
                    harness_id=harness_id,
                    _state=_state,
                )
                if result_lane is not None and result_lane.is_child:
                    return result_lane
                return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)

        # A valid host child id without a matching lane is known child-shaped
        # input.  It cannot safely inherit the parent route.  A narrow service
        # result can rescue it only through an already-owned task lane.
        result_lane = _task_lane_for_result(
            payload,
            host_session_id=host_session_id,
            harness_id=harness_id,
            _state=_state,
        )
        if result_lane is not None and result_lane.is_child:
            return result_lane
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)

    result_lane = _task_lane_for_result(
        payload,
        host_session_id=host_session_id,
        harness_id=harness_id,
        _state=_state,
    )
    if result_lane is not None:
        return result_lane

    parent_mapping = load_mapping(host_session_id, _state=_state)
    if nested_session_id is not None and (
        parent_mapping is None or nested_session_id != parent_mapping.yoetz_session_id
    ):
        # A nested FinishUP request names a service session different from the
        # held parent binding. Without a validated child lane this is foreign
        # work and cannot inherit the parent's route.
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)

    # With no child alias and no service-authored child result, retain the ordinary
    # parent route. A present-but-null alias is treated as absent; malformed or
    # contradictory aliases returned early above as an explicit gap.
    if explicit_attribution_gap:
        return _ObservationLane(host_session_id, host_session_id, attribution_gap=True)
    del aliases_supplied
    return _ObservationLane(host_session_id, host_session_id)


def _event_ordinal_from_payload(payload: Mapping[str, JsonValue]) -> int | None:
    raw = payload.get("event_ordinal")
    if type(raw) is int and not isinstance(raw, bool) and raw >= 1:
        return raw
    return None


def map_hook_payload_to_envelope(
    event_name: str,
    payload: Mapping[str, JsonValue],
    *,
    session_commitment: str,
    event_ordinal: int,
    key_material: bytes,
    source_generation: int = 1,
    gap_codes: tuple[str, ...] = (),
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    classification: ObservationClassification | None = None,
    host_outcome: _NativeOutcomeFacts | None = None,
    workspace_reading: WorkspaceEffectReading | None = None,
) -> ObservationEnvelope:
    """Map a bounded hook payload to a structural ObservationEnvelope.

    ``workspace_reading`` is this live pass's before/after workspace fact (PR #1080); it is added
    after extraction, so a host payload can never supply ``workspace_effect`` itself.
    """

    if event_name not in SUPPORTED_HOOK_EVENTS:
        structural = JsonObject({"hook_name": "unsupported"})
        gaps = tuple(
            sorted({*gap_codes, ObservationGapCode.UNSUPPORTED_EVENT.value}, key=str.encode)
        )
        identity = _source_identity(event_name, payload, structural, event_ordinal=event_ordinal)
        return ObservationEnvelope(
            session_commitment=session_commitment,
            event_kind=_token_or_none(event_name) or "unsupported_event",
            source_identity=identity,
            source=source,
            cursor=ObservationCursor(
                source_generation=source_generation,
                byte_position=0,
                event_position=event_ordinal,
                last_source_commitment=f"hmac-sha256:{'0' * 64}",
                mapping_version=HOOK_MAPPING_VERSION,
            ),
            receipt_time=_now(),
            structural_payload=structural,
            content_object_refs=(),
            gap_codes=gaps,
        )
    structural = _extract_structural(
        payload,
        event_name,
        classification=classification,
        source=source,
        host_outcome=host_outcome,
    )
    gaps = set(gap_codes)
    if event_name in {
        "PostToolUse",
        "postToolUse",
        "PostToolUseFailure",
        "postToolUseFailure",
    } and (compound_verification_gap_required(payload)):
        # Preserve the host's outer exit fact. The bounded gap records that a masking-capable
        # shell composition does not expose every nested command outcome (#968).
        gaps.add(ObservationGapCode.COMPOUND_OUTCOME_UNAVAILABLE.value)
    if "event_ordinal" not in structural:
        structural = JsonObject({**structural, "event_ordinal": event_ordinal})
    command_fields = command_identity_fields_for_payload(payload, key_material)
    if command_fields:
        structural = JsonObject({**structural, **command_fields})
    identity = _source_identity(event_name, payload, structural, event_ordinal=event_ordinal)
    commitment = hook_source_commitment(key_material, identity)
    if workspace_reading is not None:
        # The closed before/after fact, after identity: it never changes the call's source.
        structural = JsonObject({**structural, WORKSPACE_EFFECT_KEY: workspace_reading.effect})
    return ObservationEnvelope(
        session_commitment=session_commitment,
        event_kind=event_name,
        source_identity=identity,
        source=source,
        cursor=ObservationCursor(
            source_generation=source_generation,
            byte_position=0,
            event_position=event_ordinal,
            last_source_commitment=commitment,
            mapping_version=HOOK_MAPPING_VERSION,
        ),
        receipt_time=_now(),
        structural_payload=structural,
        content_object_refs=(),
        gap_codes=tuple(sorted(gaps, key=str.encode)),
    )


# Native edit tools whose arguments are reviewable code content (#883). Names are the exact
# spellings each host reports on its generic tool hooks: Codex 0.157.x ``apply_patch`` (also on
# code-mode nested calls); Claude Code ``Write``/``Edit``/``MultiEdit``/``NotebookEdit``; Cursor
# ``Write`` (its documented file-edit tool name) plus the agent tool aliases it has reported.
_PATCH_TOOL_NAMES: Final = frozenset({"apply_patch", "ApplyPatch", "functions.apply_patch"})
_EDIT_TOOL_NAMES: Final = frozenset(
    {
        "Write",
        "Edit",
        "MultiEdit",
        "NotebookEdit",
        "StrReplace",
        "str_replace",
        "search_replace",
        "edit_file",
        "write_file",
        "create_file",
    }
)
_EDIT_PATH_KEYS: Final = ("file_path", "path", "target_file", "filePath", "notebook_path")
_EDIT_TEXT_KEYS: Final = frozenset(
    {
        "content",
        "contents",
        "code_edit",
        "old_string",
        "new_string",
        "old_str",
        "new_str",
        "new_source",
        "cell_id",
        "cell_type",
        "edit_mode",
    }
)
_EDIT_BODY_KEYS: Final = frozenset(
    {"content", "contents", "code_edit", "new_string", "new_str", "new_source", "edits"}
)
_EDIT_ITEM_KEYS: Final = frozenset({"old_string", "new_string", "old_str", "new_str"})
_OUTSIDE_WORKSPACE_PATH: Final = "<outside-workspace>"
_WINDOWS_DRIVE_PATH: Final = re.compile(r"^([A-Za-z]):/(.*)$", re.DOTALL)
_WINDOWS_DRIVE_RELATIVE: Final = re.compile(r"^[A-Za-z]:")
_WSL_MOUNT_PATH: Final = re.compile(r"^/mnt/([A-Za-z])(/.*)?$", re.DOTALL)
_PATCH_PATH_HEADER: Final = re.compile(
    r"^(\*\*\* (?:Add|Update|Delete) File: |\*\*\* Move to: )(.*?)(\r?)$"
)
_UNIFIED_FILE_HEADER: Final = re.compile(r"^(--- |\+\+\+ )(.*?)(\t[^\r\n]*)?(\r?)$")
_GIT_DIFF_HEADER: Final = re.compile(r"^diff --git (\S+) (\S+)(\r?)$")
_PATCH_RESULT_LINE: Final = re.compile(r"^([AMDR] )(.+?)(\r?)$")
_CODEX_EXIT_CODE: Final = re.compile(r"\AExit code: (-?[0-9]{1,4})(?![0-9])")


def _absolute_path_key(value: str) -> tuple[str, bool] | None:
    """Return one comparable absolute-path key, or ``None`` for a relative path.

    POSIX/macOS paths stay case-sensitive. Windows drive paths (``C:\\x``/``C:/x``) are keyed
    in their WSL 2 ``/mnt/c/x`` spelling so that a Windows-side and a WSL-side locator for the
    same file compare equal; drive, WSL-mount and UNC keys compare case-insensitively.
    """

    text = value.replace("\\", "/")
    drive = _WINDOWS_DRIVE_PATH.match(text)
    if drive is not None:
        return f"/mnt/{drive.group(1).lower()}/{drive.group(2)}", True
    if text.startswith("//"):
        return "//" + "/".join(part for part in text[2:].split("/") if part), True
    mount = _WSL_MOUNT_PATH.match(text)
    if mount is not None:
        return f"/mnt/{mount.group(1).lower()}{mount.group(2) or ''}", True
    if text.startswith(("/", "~")) or _WINDOWS_DRIVE_RELATIVE.match(text):
        return text, False
    return None


def workspace_relative_edit_path(value: str, workspace_locator: str | None) -> str | None:
    """Return a workspace-relative POSIX path for review content, or ``None``.

    Absolute locators never enter captured content (ADR-006): a path inside the workspace is
    relativized, and a path outside it, a home-relative or drive-relative path, or any path
    with a ``..`` segment returns ``None`` so the caller can drop or mask it. The rule is
    lexical and identical on macOS, Linux and Windows through WSL 2; it never touches the
    filesystem.
    """

    if type(value) is not str or not value or "\n" in value or "\x00" in value:
        return None
    key = _absolute_path_key(value)
    if key is None:
        relative = value.replace("\\", "/")
    else:
        if workspace_locator is None:
            return None
        path_key, path_folds = key
        if path_key.startswith("~") or _WINDOWS_DRIVE_RELATIVE.match(path_key):
            return None
        root = _absolute_path_key(workspace_locator)
        if root is None:
            return None
        root_key, root_folds = root
        root_key = root_key.rstrip("/")
        folds = path_folds or root_folds
        compare_path = path_key.casefold() if folds else path_key
        compare_root = root_key.casefold() if folds else root_key
        if not root_key or not compare_path.startswith(compare_root + "/"):
            return None
        relative = path_key[len(root_key) + 1 :]
    parts = [part for part in relative.split("/") if part not in {"", "."}]
    if not parts or ".." in parts:
        return None
    return "/".join(parts)


def _sanitize_patch_paths(text: str, workspace_locator: str | None) -> str:
    """Relativize file locators in patch headers; mask any locator outside the workspace."""

    def rewrite(token: str) -> str:
        if token == "/dev/null":
            return token
        if token.startswith(("a/", "b/")) and _absolute_path_key(token) is None:
            relative = workspace_relative_edit_path(token[2:], workspace_locator)
            return token[:2] + relative if relative is not None else _OUTSIDE_WORKSPACE_PATH
        relative = workspace_relative_edit_path(token, workspace_locator)
        return relative if relative is not None else _OUTSIDE_WORKSPACE_PATH

    lines = text.split("\n")
    for index, line in enumerate(lines):
        header = _PATCH_PATH_HEADER.match(line)
        if header is not None:
            lines[index] = header.group(1) + rewrite(header.group(2)) + header.group(3)
            continue
        git = _GIT_DIFF_HEADER.match(line)
        if git is not None:
            lines[index] = (
                f"diff --git {rewrite(git.group(1))} {rewrite(git.group(2))}{git.group(3)}"
            )
            continue
        unified = _UNIFIED_FILE_HEADER.match(line)
        if unified is None:
            continue
        # ``--- x`` is a file header only when paired with ``+++ y``; otherwise it is a removed
        # hunk line whose code content must stay byte-exact.
        paired = (
            index + 1 < len(lines) and lines[index + 1].startswith("+++ ")
            if unified.group(1) == "--- "
            else index > 0 and lines[index - 1].startswith("--- ")
        )
        if paired:
            lines[index] = unified.group(1) + rewrite(unified.group(2)) + (unified.group(4) or "")
    return "\n".join(lines)


def _sanitize_patch_result(text: str, workspace_locator: str | None) -> str:
    """Relativize the ``A/M/D path`` lines of an apply_patch result summary."""

    lines = text.split("\n")
    for index, line in enumerate(lines):
        match = _PATCH_RESULT_LINE.match(line)
        if match is None or _absolute_path_key(match.group(2)) is None:
            continue
        relative = workspace_relative_edit_path(match.group(2), workspace_locator)
        lines[index] = (
            match.group(1)
            + (relative if relative is not None else _OUTSIDE_WORKSPACE_PATH)
            + match.group(3)
        )
    return "\n".join(lines)


def _edit_outcome(payload: Mapping[str, JsonValue], source: ObservationSource) -> str:
    """Return ``applied``, ``failed`` or ``unknown`` for one post-tool native edit."""

    hook_event = payload.get("hook_event_name")
    if hook_event in {"PostToolUseFailure", "postToolUseFailure"}:
        return "failed"
    if hook_event == "afterFileEdit":
        return "applied"  # Cursor emits it only after the agent's edit was written.
    response = payload.get("tool_response")
    if response is None:
        response = payload.get("tool_output")
    if type(response) is str:
        exit_code = _CODEX_EXIT_CODE.match(response)
        if exit_code is not None:
            return "applied" if exit_code.group(1) == "0" else "failed"
        if "Success. Updated the following files" in response:
            return "applied"
        if "verification failed" in response or "Failed to apply" in response:
            return "failed"
    facts = _native_outcome_facts(payload)
    if facts.denied or facts.success is False:
        return "failed"
    if facts.success is True:
        return "applied"
    if source in {ObservationSource.CLAUDE_HOOK, ObservationSource.CURSOR_HOOK} and hook_event in {
        "PostToolUse",
        "postToolUse",
    }:
        # Claude Code and Cursor report a failed tool call on their separate failure event, so
        # their ordinary post-tool event is the host's own success signal for the edit.
        return "applied"
    return "unknown"


def _native_edit_content(
    tool: str | None,
    payload: Mapping[str, JsonValue],
    *,
    workspace_locator: str | None,
    outcome: str,
) -> tuple[ObservationContentKind, str, JsonValue] | None:
    """Select one native edit as review content with workspace-relative locators only."""

    arguments = payload.get("tool_input")
    if tool in _PATCH_TOOL_NAMES:
        patch: JsonValue | None = arguments
        if isinstance(arguments, Mapping):
            # Codex 0.157.x sends ``{"command": <patch>}`` on Pre and Post; older and
            # freeform carriers used ``patch``/``input``.
            patch = next(
                (
                    arguments[key]
                    for key in ("command", "patch", "input")
                    if type(arguments.get(key)) is str and arguments[key]
                ),
                None,
            )
        if type(patch) is not str or not patch:
            return None
        return (
            ObservationContentKind.WORKSPACE_DIFF,
            "patch",
            # Frozen legacy identifier (ADR-048): the captured-content header the semantic case
            # parses back from stored objects.
            f"# yoetz edit outcome: {outcome}\n" + _sanitize_patch_paths(patch, workspace_locator),
        )
    if isinstance(arguments, Mapping) and tool in _EDIT_TOOL_NAMES:
        source: Mapping[str, JsonValue] = arguments
    elif (
        arguments is None
        and type(payload.get("file_path")) is str
        and type(payload.get("edits")) is list
    ):
        # Cursor ``afterFileEdit``: ``{"file_path": <absolute>, "edits": [{old_string,
        # new_string}]}`` at the top level.
        source = payload
    else:
        return None
    # Preserve only the host's public edit fields; never serialize unknown nested prompt,
    # reasoning or credential fields just because they share an input object.
    selected: dict[str, JsonValue] = {
        key: value for key, value in source.items() if key in _EDIT_TEXT_KEYS and type(value) is str
    }
    for key in _EDIT_PATH_KEYS:
        value = source.get(key)
        if type(value) is str and value:
            relative = workspace_relative_edit_path(value, workspace_locator)
            selected["path"] = relative if relative is not None else _OUTSIDE_WORKSPACE_PATH
            break
    edits = source.get("edits")
    if type(edits) is list:
        selected["edits"] = [
            {
                key: value
                for key, value in item.items()
                if key in _EDIT_ITEM_KEYS and type(value) is str
            }
            for item in edits
            if isinstance(item, Mapping)
        ]
    response = payload.get("tool_response")
    if isinstance(response, Mapping) and type(response.get("structuredPatch")) is list:
        # Claude Code's post-edit result carries line-numbered hunks with context; keep them and
        # never its ``originalFile`` copy or absolute ``filePath``.
        selected["structured_patch"] = response["structuredPatch"]
    if not any(key in selected for key in _EDIT_BODY_KEYS):
        return None
    selected["edit_outcome"] = outcome
    return ObservationContentKind.CHANGED_FILE, "changed-file", cast(JsonValue, selected)


_SHELL_TOOL_NAMES: Final = frozenset({"Bash", "Shell", "shell", "exec_command", "local_shell"})
_SHELL_GIT_APPLY: Final = re.compile(
    r"(?:^|[\s;&|(])git\s+apply(?:\s+-{1,2}[A-Za-z0-9=-]+)*\s*-?\s*$"
)
_SHELL_WRITER: Final = re.compile(r"(?:^|[\s;&|(])(cat|tee)(?:\s+-a)?\b")
_SHELL_REDIRECT: Final = re.compile(r">>?\s*(['\"]?)([^\s'\";&|<>]+)\1")
_SHELL_TEE_TARGET: Final = re.compile(
    r"(?:^|[\s;&|(])tee(?:\s+-a)?\s+(['\"]?)([^\s'\";&|<>-][^\s'\";&|<>]*)\1"
)


def _intercepted_shell_apply_patch(
    event_name: str, payload: Mapping[str, JsonValue], source: ObservationSource
) -> bool:
    """A Codex shell ``apply_patch <<EOF`` pre-event: the only hook Codex fires for it (#1041).

    Codex intercepts the shell call and applies the patch itself, so no post-tool event follows;
    the pending attempt is pre-only and the session stream's ``FileChange`` item closes it. Codex
    intercepts only a script that is that one statement: a patch followed by a test runs in the
    shell and fires its post-tool event, so its attempt is an ordinary one (n7 RC2).
    """

    if event_name != "PreToolUse" or source is not ObservationSource.CODEX_HOOK:
        return False
    if _token_or_none(payload.get("tool_name")) not in _SHELL_TOOL_NAMES:
        return False
    arguments = payload.get("tool_input")
    command = arguments.get("command") if isinstance(arguments, Mapping) else None
    return type(command) is str and codex_intercepts_shell_apply_patch(command)


def _cursor_served_finishup_read(
    event_name: str, payload: Mapping[str, JsonValue], state_root: Path | None
) -> bool:
    """Whether a Cursor ``MCP:<tool>`` post-event is provably FinishUP's own served read.

    Cursor's ordinary ``postToolUse`` names no MCP server, so ``MCP:status`` may be another
    server's tool whose result is real evidence. FinishUP's bridge records a commitment to each read
    it served successfully (tool, FinishUP session and writer, ``request_id``) before returning it;
    only a post-event whose own ``tool_input`` claims one, once and within its expiry, is treated
    as FinishUP's. Anything else, including every pre-event and any replay, stays ordinary evidence.
    """

    if event_name != "PostToolUse":
        return False
    tool = payload.get("tool_name")
    if type(tool) is not str or not tool.startswith("MCP:"):
        return False
    return claim_served_finishup_read(tool, payload.get("tool_input"), state_root=state_root)


def _proven_finishup_structural(
    structural: Mapping[str, DomainJsonValue], *, proven: bool
) -> Mapping[str, DomainJsonValue]:
    """The structural view the delivery policy reads; a proven FinishUP read gets its scoped name."""

    tool = structural.get("tool_name")
    if not proven or type(tool) is not str or not tool.startswith("MCP:"):
        return structural
    return {**structural, "tool_name": f"finishup:{tool[len('MCP:') :]}"}


def _finishup_request_commitment(event_name: str, payload: Mapping[str, JsonValue]) -> str | None:
    """The commitment to one FinishUP call on its pre-event (tb4n5, #1041).

    It covers the tool, the request's FinishUP ``session_id``/``writer_id`` and its ``request_id``,
    read from the host's own ``tool_input`` (an id-less ``publish_work``, whose id the bridge mints
    after this event, commits to its canonical body instead, #1084). FinishUP's MCP server records
    the same commitment when it answers the call with an error, which a host sends no post for;
    the pending attempt then closes as rejected by FinishUP instead of expiring. Only the
    commitment is kept: never an identifier or any other argument. Every host adapter computes it
    from the payload the host sent, before normalization drops ``tool_input`` (Claude Code and
    Cursor pass it in).
    """

    if event_name not in {"PreToolUse", "preToolUse"}:
        return None
    arguments = payload.get("tool_input")
    if not isinstance(arguments, Mapping):
        return None
    return rejected_call_commitment(payload.get("tool_name"), arguments)


def _shell_edit_contents(
    command: str,
    *,
    cwd: str | None,
    workspace_locator: str | None,
    event_name: str,
    source: ObservationSource,
    outcome: str,
) -> list[tuple[ObservationContentKind, str, JsonValue]]:
    """Recognize shell-mediated edits whose new bytes are visible in the command itself.

    Covered: ``apply_patch <<EOF`` (Codex intercepts it as a sole statement, so only its
    pre-tool event exists; with anything around it, it runs in the shell and is read from the
    post-tool event), ``git apply <<EOF`` and whole-file writes through ``cat > path <<EOF`` or
    ``tee path <<EOF``. A write outside the workspace (for example a ``/tmp`` scratch file) is
    not code under review and is skipped. Edits made by scripts (``sed -i``, ``python``,
    ``git apply file.patch``) carry no reviewable bytes in the command and stay uncaptured.
    """

    patches: list[str] = []
    writes: list[JsonValue] = []
    intercepted = source is ObservationSource.CODEX_HOOK and codex_intercepts_shell_apply_patch(
        command
    )
    for prefix, suffix, body in _shell_heredocs(command):
        if _SHELL_APPLY_PATCH.search(prefix) and intercepted:
            # Codex intercepts a sole shell apply_patch and emits no post-tool event for it.
            if event_name == "PreToolUse":
                patches.append(body)
            continue
        if event_name != "PostToolUse":
            continue
        if _SHELL_APPLY_PATCH.search(prefix) or _SHELL_GIT_APPLY.search(prefix):
            patches.append(body)
            continue
        if _SHELL_WRITER.search(prefix) is None:
            continue
        target = _SHELL_REDIRECT.search(f"{prefix} {suffix}") or _SHELL_TEE_TARGET.search(prefix)
        if target is None:
            continue
        path = target.group(2)
        if _absolute_path_key(path) is None and cwd is not None and _absolute_path_key(cwd):
            path = cwd.rstrip("/\\") + "/" + path
        relative = workspace_relative_edit_path(path, workspace_locator)
        if relative is None:
            continue
        writes.append({"path": relative, "content": body})
    selected: list[tuple[ObservationContentKind, str, JsonValue]] = []
    if patches:
        selected.append(
            (
                ObservationContentKind.WORKSPACE_DIFF,
                "patch",
                # Frozen legacy identifier (ADR-048): captured-content headers the semantic case
                # parses back from stored objects.
                f"# yoetz edit outcome: {outcome}\n# yoetz edit source: shell\n"
                + "".join(_sanitize_patch_paths(patch, workspace_locator) for patch in patches),
            )
        )
    if writes:
        selected.append(
            (
                ObservationContentKind.CHANGED_FILE,
                "changed-file",
                {"edit_outcome": outcome, "edit_source": "shell", "writes": writes},
            )
        )
    return selected


# Every host spelling of every FinishUP MCP tool, support tools included. The workflow-only
# ``FINISHUP_OWNED_TOOL_NAMES`` keeps governing self-observation delivery; this wider set decides
# only that a tool's own content is never captured and that its oversized hook body is complete
# as a structural row. The spellings are read off the workflow set so they cannot drift.
_FINISHUP_TOOL_SPELLINGS: Final = frozenset(
    name[: -len("start")] for name in FINISHUP_OWNED_TOOL_NAMES if name.endswith("start")
)
_FINISHUP_MCP_OWNED_TOOL_NAMES: Final = FINISHUP_OWNED_TOOL_NAMES | frozenset(
    f"{prefix}{name}" for prefix in _FINISHUP_TOOL_SPELLINGS for name in FINISHUP_SUPPORT_TOOL_NAMES
)


def finishup_mcp_tool(tool_name: object) -> bool:
    """Whether a host tool name is one of FinishUP's own MCP tools, in any host spelling.

    Codex code mode calls a nested MCP tool by the same ``mcp__finishup__<tool>`` name, so the
    nested call's own hook is covered by the same spellings.
    """

    return type(tool_name) is str and tool_name in _FINISHUP_MCP_OWNED_TOOL_NAMES


def _oversized_ingress_gap(
    payload: Mapping[str, JsonValue],
    *,
    source: ObservationSource,
    event: str,
    _state: Path | None,
) -> str | None:
    """Name what an oversized hook body that kept only its identity view lost.

    A FinishUP-owned tool lost nothing: its content is never captured, and its outcome and ids are
    in the identity view. Every other oversized body keeps its structural row, pairs with its
    pre-event, and records ``payload_content_omitted`` plus the per-host diagnostic instead of
    vanishing (tb4n1 B5, issue #667).
    """

    if event in {"PreToolUse", "PostToolUse"} and finishup_mcp_tool(payload.get("tool_name")):
        return None
    prefix = (
        "claude"
        if source is ObservationSource.CLAUDE_HOOK
        else "cursor"
        if source is ObservationSource.CURSOR_HOOK
        else "codex"
    )
    degraded = "hook_cursor_observe_degraded" if prefix == "cursor" else "hook_observe_degraded"
    with contextlib.suppress(BaseException):
        _stderr_line(
            f"{degraded}: payload_content_omitted; "
            "structural identity retained; native content omitted; see observe status"
        )
    with contextlib.suppress(BaseException):
        record_hook_diagnostic(f"{prefix}_payload_content_omitted", event, _state=_state)
    return ObservationGapCode.PAYLOAD_CONTENT_OMITTED.value


def _visible_content_chunks(
    event_name: str,
    payload: Mapping[str, JsonValue],
    *,
    envelope: ObservationEnvelope,
    workspace_locator: str | None,
    optional_limits: ModeLimits | None = None,
) -> tuple[tuple[ObservationContentChunk, ...], bool]:
    """Extract only explicitly visible task content and redact secrets before transport.

    Only high-confidence secret shapes are redacted here; heuristic-only matches stay in the
    encrypted local store and are redacted at egress (issue #982). A chunk is marked
    ``redacted`` only when its bytes were actually changed.

    Returns ``(chunks, truncated)``. Caps set ``truncated`` so callers attach
    ``truncated_payload`` without inventing success.
    """

    from finishup.observability.privacy import redact_high_confidence_content

    selected: list[tuple[ObservationContentKind, str, bytes]] = []
    if event_name in {"PreToolUse", "PostToolUse"} and finishup_mcp_tool(payload.get("tool_name")):
        # FinishUP's own tool arguments and results are already durable in the
        # ledger the call wrote to or read from. Capturing them back as tool
        # input/output evidence re-encrypted every ``status`` projection the
        # agent read and was the heaviest part of the self-observation loop
        # (#564). Nothing is omitted that the service does not hold. The
        # read-only ``closure_prepare`` support tool is a projection of that
        # same ledger and the largest reply FinishUP serves (tb4n1 B5).
        return (), False
    if event_name == "PostToolUse":
        # Image, audio, and video bytes are not reviewable text. A view of a
        # screenshot is kept as its structure and text; the base64 is replaced
        # by a fixed placeholder instead of filling the content budget and
        # marking the event truncated (tb4n1 B5).
        payload, _media_omitted = strip_hook_media(payload)

    def add(kind: ObservationContentKind, label: str, value: JsonValue) -> None:
        if type(value) is str and value:
            selected.append((kind, label, value.encode("utf-8")))
        elif isinstance(value, Mapping) or type(value) in {tuple, list}:
            try:
                selected.append((kind, label, canonical_encode(value)))
            except ProtocolValueError, TypeError, ValueError:
                return

    # Native edit arguments are visible task content (#883). They are captured once, from the
    # post-tool event: a pre-tool edit is only a proposal and would duplicate the post-tool copy.
    # The capture names the host-reported outcome, so a failed or unconfirmed edit is never
    # presented as applied code, and it carries workspace-relative locators only (ADR-006).
    tool = (
        _token_or_none(payload.get("tool_name"))
        if event_name in {"PreToolUse", "PostToolUse"}
        else None
    )
    native_edit_tool = tool in _PATCH_TOOL_NAMES or tool in _EDIT_TOOL_NAMES
    edit_content = False
    edit_outcome = "unknown"
    if event_name == "PostToolUse":
        edit_outcome = _edit_outcome(payload, envelope.source)
        edit = _native_edit_content(
            tool,
            payload,
            workspace_locator=workspace_locator,
            outcome=edit_outcome,
        )
        if edit is not None:
            add(*edit)
            edit_content = True
    if event_name in {"PreToolUse", "PostToolUse"} and tool in _SHELL_TOOL_NAMES:
        arguments = payload.get("tool_input")
        command = arguments.get("command") if isinstance(arguments, Mapping) else None
        if type(command) is str and "<<" in command:
            cwd = payload.get("cwd")
            for shell_edit in _shell_edit_contents(
                command,
                cwd=cwd if type(cwd) is str else None,
                workspace_locator=workspace_locator,
                event_name=event_name,
                source=envelope.source,
                outcome=(
                    _edit_outcome(payload, envelope.source)
                    if event_name == "PostToolUse"
                    else "unknown"
                ),
            ):
                # Additive: the shell call's own output remains ordinary tool output.
                add(*shell_edit)

    if event_name == "UserPromptSubmit":
        add(
            ObservationContentKind.VISIBLE_USER_MESSAGE,
            "user",
            payload.get("prompt") or payload.get("message"),
        )
    elif event_name in {"Stop", "AgentMessage"}:
        add(
            ObservationContentKind.VISIBLE_ASSISTANT_MESSAGE,
            "assistant",
            payload.get("message") or payload.get("output") or payload.get("content"),
        )
    elif event_name in {"SubagentStart", "SubagentStop"}:
        add(
            ObservationContentKind.VISIBLE_SUBAGENT_MESSAGE,
            "subagent",
            payload.get("message") or payload.get("output") or payload.get("content"),
        )
    elif event_name == "PreToolUse":
        # Generic Codex input bytes have no capture consumer and are excluded from
        # AI-powered selection. Keep the structural envelope/correlation, but
        # avoid encrypting a second copy of command arguments. Ordinary native
        # profiles retain their explicitly selected capture contract.
        # Native edit input is captured from its post-tool event instead (see above).
        if not native_edit_tool and envelope.source is not ObservationSource.CODEX_HOOK:
            add(ObservationContentKind.TOOL_INPUT, "tool-input", payload.get("tool_input"))
    elif event_name == "PostToolUse":
        tool_result = (
            payload.get("tool_response")
            or payload.get("tool_output")
            or payload.get("output")
            or payload.get("result")
            or payload.get("result_json")
        )
        if not native_edit_tool and not edit_content:
            add(ObservationContentKind.TOOL_OUTPUT, "tool-output", tool_result)
        elif (
            edit_outcome != "applied"
            and type(tool_result) is str
            and not tool_result.lstrip().startswith(("{", "["))
        ):
            # A successful edit's result only repeats the outcome already named on the edit.
            # A failed or unconfirmed edit keeps its plain-text result (Codex: exit code and
            # error) with locators relativized. Structured edit results carry absolute paths
            # and whole original files; their hunks are already kept above.
            add(
                ObservationContentKind.TOOL_OUTPUT,
                "tool-output",
                _sanitize_patch_result(tool_result, workspace_locator),
            )
    elif event_name not in SUPPORTED_HOOK_EVENTS:
        # Unknown host events are retained only when the host marks their
        # payload visible. Hidden/system/developer/reasoning fields are never read.
        if payload.get("visibility") in {"user", "assistant", "tool", "task"}:
            add(
                ObservationContentKind.UNSUPPORTED_VISIBLE_PAYLOAD,
                "unsupported",
                payload.get("visible_content") or payload.get("message"),
            )

    # Authenticated post-tool command context stays local, never a provider excerpt.
    if (
        event_name == "PostToolUse"
        and _is_command_tool(payload.get("tool_name"))
        and command_runner_class(payload) in {"test", "build", "lint", "typecheck"}
    ):
        add(ObservationContentKind.TOOL_INPUT, "tool-input", payload.get("tool_input"))

    for key, kind, label in (
        ("diff", ObservationContentKind.WORKSPACE_DIFF, "diff"),
        ("patch", ObservationContentKind.WORKSPACE_DIFF, "patch"),
        ("file_content", ObservationContentKind.CHANGED_FILE, "changed-file"),
    ):
        value = payload.get(key)
        if kind is ObservationContentKind.WORKSPACE_DIFF and type(value) is str:
            value = _sanitize_patch_paths(value, workspace_locator)
        add(kind, label, value)
    if event_name == "SessionStart" and workspace_locator is not None:
        add(ObservationContentKind.WORKSPACE_LOCATOR, "workspace", workspace_locator)

    chunks: list[ObservationContentChunk] = []
    remaining = 680_000 if optional_limits is None else optional_limits.max_optional_bytes
    truncated = False
    for selected_index, (kind, label, raw) in enumerate(selected):
        # Capture keeps heuristic-only matches; egress redacts them (issue #982).
        redacted, detected = redact_high_confidence_content(raw)
        if not redacted:
            continue
        part_limit = remaining
        if optional_limits is not None:
            if kind is ObservationContentKind.TOOL_INPUT or (
                edit_content
                and kind
                in {ObservationContentKind.WORKSPACE_DIFF, ObservationContentKind.CHANGED_FILE}
            ):
                part_limit = min(part_limit, optional_limits.max_input_bytes)
            elif kind is ObservationContentKind.TOOL_OUTPUT:
                part_limit = min(part_limit, optional_limits.max_output_bytes)
        if len(redacted) > part_limit:
            truncated = True
        redacted = redacted[:part_limit]
        if not redacted:
            truncated = True
            break
        full_parts = [
            redacted[offset : offset + _MAX_CONTENT_CHUNK]
            for offset in range(0, len(redacted), _MAX_CONTENT_CHUNK)
        ]
        if len(full_parts) > 16:
            truncated = True
        parts = full_parts[:16]
        hit_chunk_cap = False
        for index, part in enumerate(parts):
            chunks.append(
                ObservationContentChunk(
                    content_kind=kind,
                    correlation_identity=f"{envelope.source_identity}:{label}",
                    source_commitment=envelope.cursor.last_source_commitment,
                    media_type="text/plain",
                    part_index=index,
                    part_count=len(parts),
                    content=part,
                    redacted=detected,
                )
            )
            if len(chunks) >= 16:
                hit_chunk_cap = True
                if index + 1 < len(parts):
                    truncated = True
                break
        remaining -= len(redacted)
        if hit_chunk_cap:
            if selected_index + 1 < len(selected):
                truncated = True
            break
    return tuple(chunks), truncated


def _elapsed_ms(started: float, finished: float) -> int:
    return max(0, int((finished - started) * 1000))


def _hook_total_budget_seconds(event: str, *, native_content: bool = False) -> float:
    """Return the end-to-end budget for one pass of *event*.

    Events that may legitimately retry auto-attach (and SessionStart, the
    primary attach point) carry that enforced budget on top of the base sum;
    the high-frequency PreToolUse/PostToolUse storm and teardown SessionEnd
    keep the tighter contract (#288, #616).
    """

    total = _HOOK_TOTAL_BUDGET_SECONDS
    if event == "Stop":
        # The Stop pass drains toward the current frontier and then reads status for the
        # closure gate, both inside the host's ten-second Stop window (#994).
        return _STOP_PASS_BUDGET_SECONDS
    if native_content:
        total += _NATIVE_CONTENT_DRAIN_BUDGET_SECONDS - _HOOK_DRAIN_BUDGET_SECONDS
    if event == "SessionStart" or event in _AUTO_ATTACH_RETRY_EVENTS:
        total += _AUTO_ATTACH_RETRY_BUDGET_SECONDS
    return total


def _record_pass_timing(
    event: str,
    *,
    entry_started: float,
    stages: Mapping[str, int],
    monotonic: Callable[[], float],
    _state: Path | None,
    native_content: bool = False,
) -> None:
    """Record the end-to-end hook budget.

    Observability only: exceeding the budget never aborts a pass, because that
    would drop ingest. The drain and preflight budgets stay the enforcement
    points. Rows are emitted only over budget or at a session boundary, so the
    64 KiB diagnostics window keeps its failure-reason history.
    """

    with contextlib.suppress(BaseException):
        total_ms = _elapsed_ms(entry_started, monotonic())
        over = total_ms > int(
            _hook_total_budget_seconds(event, native_content=native_content) * 1000
        )
        if not over and event not in _TIMING_REPORT_EVENTS:
            return
        if over:
            record_hook_diagnostic("hook_budget_exceeded", event, _state=_state)
        # What the partition does not cover is reported as its own term rather
        # than left for a reader to derive by knowing which stages nest. A row
        # whose stages sum to half its total said nothing about the other half
        # (#310/#311); now it names it.
        attributed = sum(stages.get(name, 0) for name in _PASS_PARTITION_STAGES)
        record_hook_timing(
            event,
            ms=total_ms,
            stages={
                **stages,
                "total": total_ms,
                "unattributed": max(0, total_ms - attributed),
            },
            _state=_state,
        )


def _finish_hook_pass(
    timing: HookPassTiming,
    *,
    monotonic: Callable[[], float],
    _state: Path | None,
    ms: int | None = None,
) -> None:
    """Fold one host hook pass into its bounded timing aggregate (#915).

    Every pass counts, in budget or not, and none adds a row to the failure-reason file, so the
    typical cost is measurable without evicting failure history. ``ms`` lets a caller that also
    judges the pass against a cap use the very same measurement. Never raises.
    """

    with contextlib.suppress(BaseException):
        record_hook_pass_timing(
            timing.host,
            timing.event,
            timing.path,
            timing.outcome,
            ms=_elapsed_ms(timing.started, monotonic()) if ms is None else ms,
            _state=_state,
        )


def _cached_recommendation_context(*, _state: Path | None) -> str:
    from finishup.application.recommendations import cached_pending_recommendations

    pending = cached_pending_recommendations(root=_state, limit=1)
    if not pending:
        return ""
    item = pending[0]
    suffix = f" --release-version {item.release_version}" if item.release_version else ""
    text = (
        f"FinishUP recommends: {item.title}. {item.summary} Explain this to the user and ask "
        f"for approval; if approved run 'finishup recommend accept {item.id}{suffix}', "
        f"otherwise 'finishup recommend decline {item.id}{suffix}'."
    )
    if item.kind == "package_update":
        # The agent is the messenger (ADR-021): tell the user now, offer to do the mechanical
        # upgrade steps, and make the restart that activates the new version explicit (#819).
        text += (
            " Tell the user now. If they approve, offer a subagent that follows "
            "'finishup upgrade' and reports each step. Existing sessions keep their version; "
            "start a fresh session afterwards. Fully restart the host only if activation requires it."
        )
    return text[:_MAX_ADVICE_CONTEXT]


async def _try_service_ingest(
    client: _HookDrainClient,
    codex_session_id: str,
    envelope: ObservationEnvelope,
    *,
    content_chunks: tuple[ObservationContentChunk, ...] = (),
    content_capture_profile: str | None = None,
    capture_only: bool = False,
    deadline_ms: int,
) -> ObservationIngestResult:
    """Attempt one typed ingest through an already-open preflight client."""

    from finishup.application.observation_drain import (
        ObservationControlFailure,
        observation_control_failure,
    )
    from finishup.ports.control import ControlError

    stage = "request_encode"
    try:
        body = observation_ingest_request_to_json(
            ObservationIngestRequest(
                codex_session_id=codex_session_id,
                envelope=envelope,
                content_chunks=content_chunks,
                content_capture_profile=content_capture_profile,
                capture_only=capture_only,
            )
        )
        stage = "control"
        raw = await client.observation_ingest(body, deadline_ms=deadline_ms)
        stage = "response_decode"
        try:
            return observation_ingest_result_from_json(raw)
        except ProtocolValueError, TypeError, ValueError:
            return ObservationControlFailure(
                ObservationIngestDisposition.REJECTED,
                "control_frame_invalid",
                None,
                "frame_invalid",
                False,
                None,
                "response_decode",
            )
    except ControlError as error:
        return observation_control_failure(error)
    except ProtocolValueError, TypeError, ValueError:
        reason = "invalid_request" if stage == "request_encode" else "frame_invalid"
        return ObservationControlFailure(
            ObservationIngestDisposition.REJECTED,
            "control_" + reason,
            None,
            reason,
            False,
            None,
            stage,
        )
    except Exception:
        return ObservationIngestResult(
            ObservationIngestDisposition.REJECTED,
            ObservationGapCode.SERVICE_UNAVAILABLE.value,
            None,
        )


async def _drain_outbox(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    codex_session_id: str,
    content_by_source_identity: Mapping[str, tuple[ObservationContentChunk, ...]] | None = None,
    content_capture_profile: str | None = None,
    connect: HookDrainConnector | None = None,
    event_name: str = "drain",
    _state: Path | None = None,
    budget_seconds: float = _HOOK_DRAIN_BUDGET_SECONDS,
    priority_source_identity: str | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    session_lock_owned: bool = False,
    drain_lease_owned: bool = False,
    row_limit: int = _HOOK_DRAIN_ROW_LIMIT,
    deadline: float | None = None,
) -> bool:
    """Drain the workspace outbox under a nonblocking per-workspace lease.

    Returns whether this pass held the lease (and so attempted delivery itself).

    Codex runs async hooks concurrently; without the lease every concurrent
    hook re-ingests the identical backlog for zero extra delivery. Losing the
    lease means another live owner — a concurrent hook or the service sweeper —
    is already draining. That is the intended coordination, not a failure, so
    nothing is recorded (#351): one failure-shaped row per contending hook was
    exactly the diagnostic noise that buried genuine preflight/service faults.
    A crashed holder cannot wedge the lease; flock releases with its process.
    """

    if drain_lease_owned:
        await _drain_outbox_leased(
            store,
            workspace_commitment=workspace_commitment,
            codex_session_id=codex_session_id,
            content_by_source_identity=content_by_source_identity,
            content_capture_profile=content_capture_profile,
            connect=connect,
            event_name=event_name,
            _state=_state,
            budget_seconds=budget_seconds,
            priority_source_identity=priority_source_identity,
            monotonic=monotonic,
            session_lock_owned=session_lock_owned,
            row_limit=row_limit,
            deadline=deadline,
        )
        return True

    with store.drain_lease(workspace_commitment) as owned:
        if not owned:
            if content_by_source_identity:
                # Native content chunks are intentionally absent from the
                # durable outbox, so the concurrent owner cannot replay this
                # hook's bytes. Stage them into the service's encrypted capture
                # handoff anyway: capture_only never advances the cursor or the
                # ledger, so it needs no drain lease, and the owner (or the
                # sweeper) that later delivers the structural row consumes the
                # durable ticket. Only bytes that could not be staged are
                # reported as a content gap.
                await _stage_content_without_lease(
                    store,
                    workspace_commitment=workspace_commitment,
                    content_by_source_identity=content_by_source_identity,
                    content_capture_profile=content_capture_profile,
                    connect=connect,
                    event_name=event_name,
                    _state=_state,
                    budget_seconds=budget_seconds,
                    monotonic=monotonic,
                    deadline=deadline,
                )
            return False
        await _drain_outbox_leased(
            store,
            workspace_commitment=workspace_commitment,
            codex_session_id=codex_session_id,
            content_by_source_identity=content_by_source_identity,
            content_capture_profile=content_capture_profile,
            connect=connect,
            event_name=event_name,
            _state=_state,
            budget_seconds=budget_seconds,
            priority_source_identity=priority_source_identity,
            monotonic=monotonic,
            session_lock_owned=session_lock_owned,
            row_limit=row_limit,
            deadline=deadline,
        )
        return True


def _drain_connect_timeout(deadline: float | None, monotonic: Callable[[], float]) -> float:
    """The connect preflight bound, clamped to an absolute pass deadline when one is set."""

    timeout = _HOOK_CONNECT_PREFLIGHT_SECONDS
    if deadline is not None:
        timeout = min(timeout, deadline - monotonic())
    return timeout


async def _stage_native_content(
    client: _HookDrainClient,
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    all_pending: Sequence[ObservationOutboxRow],
    content_by_source_identity: Mapping[str, tuple[ObservationContentChunk, ...]],
    content_capture_profile: str | None,
    remaining: Callable[[], float],
    _state: Path | None,
) -> set[str] | None:
    """Stage transient native content into the service's durable encrypted handoff.

    Returns the source identities whose bytes are now durable (the service answered the
    distinct capture-pending reason only after the encrypted manifests and the retry ticket
    committed), or ``None`` when a control failure ended staging; the caller then closes the
    connection and stops. ``capture_only`` never advances the ingest cursor or the ledger.
    """

    import asyncio

    from finishup.application.observation_drain import ObservationControlFailure

    staged_content_sources: set[str] = set()
    for source_identity, chunks in content_by_source_identity.items():
        if not chunks:
            continue
        source_row = next(
            (row for row in all_pending if row.envelope.source_identity == source_identity),
            None,
        )
        if source_row is None:
            continue
        source = source_row.envelope.source
        codex_profileless = (
            source is ObservationSource.CODEX_HOOK and content_capture_profile is None
        )
        profiled_native = (
            source
            in {
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            and content_capture_profile is not None
            and content_capture_profile_matches_source(source.value, content_capture_profile)
        )
        if not codex_profileless and not profiled_native:
            continue
        left = remaining()
        if left <= 0:
            break
        try:
            staged = await asyncio.wait_for(
                _try_service_ingest(
                    client,
                    source_row.codex_session_id,
                    source_row.envelope,
                    content_chunks=chunks,
                    content_capture_profile=content_capture_profile,
                    capture_only=True,
                    deadline_ms=max(1, int(left * 1_000)),
                ),
                timeout=left,
            )
        except TimeoutError:
            break
        if isinstance(staged, ObservationControlFailure):
            from finishup.cli.hook_diagnostics import record_drain_failure

            if not record_drain_failure(staged, source_row.envelope, "retry", _state=_state):
                store.note_coverage_gap(workspace_commitment, "drain_diagnostic_unavailable")
            store.note_coverage_gap(
                workspace_commitment, ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value
            )
            return None
        if staged.reason == OBSERVATION_CONTENT_CAPTURE_PENDING_REASON:
            staged_content_sources.add(source_identity)
    return staged_content_sources


async def _stage_content_without_lease(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    content_by_source_identity: Mapping[str, tuple[ObservationContentChunk, ...]],
    content_capture_profile: str | None,
    connect: HookDrainConnector | None,
    event_name: str,
    _state: Path | None,
    budget_seconds: float,
    monotonic: Callable[[], float],
    deadline: float | None = None,
) -> None:
    """Make this hook's transient content durable while another owner drains (B4, tb4n1).

    Never raises. Every source whose bytes were not staged keeps the explicit
    ``content_capture_unavailable`` gap, exactly as before this path existed.
    """

    import asyncio

    from finishup.ports.control import ControlClientKind

    staged: set[str] = set()
    client: _HookDrainClient | None = None
    # The stage that raised names the closed reason (tb4n2 N-3b): the local outbox read keeps
    # `drain_preflight_failed`, the connect is `drain_connect_timeout` / `drain_connect_failed`
    # and the content handoff is `native_content_stage_failed`.
    failure_reason = "drain_preflight_failed"
    try:
        all_pending = store.list_pending_outbox_rows(workspace_commitment)
        if all_pending:
            connector = cast(HookDrainConnector, _connect_service()) if connect is None else connect
            timeout = _drain_connect_timeout(deadline, monotonic)
            if timeout > 0:
                failure_reason = "drain_connect_failed"
                try:
                    client = await asyncio.wait_for(
                        connector(ControlClientKind.CLI), timeout=timeout
                    )
                except TimeoutError:
                    failure_reason = "drain_connect_timeout"
                    raise
                failure_reason = "native_content_stage_failed"
                started = monotonic()
                budget = budget_seconds
                if deadline is not None:
                    budget = min(budget, deadline - started)
                result = await _stage_native_content(
                    client,
                    store,
                    workspace_commitment=workspace_commitment,
                    all_pending=all_pending,
                    content_by_source_identity=content_by_source_identity,
                    content_capture_profile=content_capture_profile,
                    remaining=lambda: budget - (monotonic() - started),
                    _state=_state,
                )
                staged = set() if result is None else result
    except Exception:
        record_hook_diagnostic(failure_reason, event_name, _state=_state)
    finally:
        if any(source not in staged for source in content_by_source_identity):
            with contextlib.suppress(Exception):
                store.note_coverage_gap(
                    workspace_commitment,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()


async def _drain_outbox_leased(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    codex_session_id: str,
    content_by_source_identity: Mapping[str, tuple[ObservationContentChunk, ...]] | None = None,
    content_capture_profile: str | None = None,
    connect: HookDrainConnector | None = None,
    event_name: str = "drain",
    _state: Path | None = None,
    budget_seconds: float = _HOOK_DRAIN_BUDGET_SECONDS,
    priority_source_identity: str | None = None,
    monotonic: Callable[[], float] = time.monotonic,
    session_lock_owned: bool = False,
    row_limit: int = _HOOK_DRAIN_ROW_LIMIT,
    deadline: float | None = None,
) -> None:
    """Drain all mapped-session work fairly; ack only after service commit.

    The current session receives the first slot for low-latency hook feedback,
    then sessions are interleaved round-robin. A busy current session therefore
    cannot indefinitely filter or starve recovered work from another mapped
    session in the same workspace.
    """

    import asyncio

    from finishup.application.observation_drain import (
        EXPECTED_OBSERVATION_BACKPRESSURE_REASONS,
        WORKSPACE_GLOBAL_OBSERVATION_STOP_REASONS,
        ObservationControlFailure,
        ObservationDrainAction,
        route_observation_ingest,
    )
    from finishup.ports.control import ControlClientKind

    all_pending = store.list_pending_outbox_rows(workspace_commitment)
    if not all_pending:
        if content_by_source_identity:
            store.note_coverage_gap(
                workspace_commitment,
                ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
            )
        return

    connector = cast(HookDrainConnector, _connect_service()) if connect is None else connect
    client: _HookDrainClient
    # The connect has its own preflight bound; the delivery budget starts only once the
    # connection is open (tb4n1 B4). An absolute pass deadline (the Stop pass keeps the
    # closure gate's reserve) clamps both.
    preflight_remaining = _drain_connect_timeout(deadline, monotonic)
    if preflight_remaining <= 0:
        record_hook_diagnostic("drain_pass_delivered_nothing", event_name, _state=_state)
        if content_by_source_identity:
            store.note_coverage_gap(
                workspace_commitment,
                ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
            )
        return
    try:
        client = await asyncio.wait_for(
            connector(ControlClientKind.CLI),
            timeout=preflight_remaining,
        )
    except Exception as failure:
        # A connect that ran out of its preflight bound is told apart from one the service
        # refused or that failed outright (tb4n2 N-3b).
        record_hook_diagnostic(
            "drain_connect_timeout"
            if isinstance(failure, TimeoutError)
            else "drain_connect_failed",
            event_name,
            _state=_state,
        )
        if content_by_source_identity:
            store.note_coverage_gap(
                workspace_commitment,
                ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
            )
        return
    # The delivery clock starts here, after the connection opened: content staging, the
    # lifecycle reconciliation, service calls and the local commit after each returned
    # decision share it. Loading the local snapshot and the cold handshake do not.
    started = monotonic()
    if deadline is not None:
        budget_seconds = min(budget_seconds, max(0.0, deadline - started))

    # Stage native content through the already-open service connection before
    # choosing a bounded FIFO prefix. The service returns the distinct pending
    # reason only after encrypted manifests and the retry ticket are durable;
    # capture_only never advances the cursor or ledger.
    staged_content_sources: set[str] = set()
    if content_by_source_identity:
        try:
            staged_result = await _stage_native_content(
                client,
                store,
                workspace_commitment=workspace_commitment,
                all_pending=all_pending,
                content_by_source_identity=content_by_source_identity,
                content_capture_profile=content_capture_profile,
                remaining=lambda: budget_seconds - (monotonic() - started),
                _state=_state,
            )
        except Exception:
            # The rows stay pending for the next owner; only this pass's transient content is
            # lost, and it keeps the explicit gap (tb4n2 N-3b).
            record_hook_diagnostic("native_content_stage_failed", event_name, _state=_state)
            with contextlib.suppress(Exception):
                store.note_coverage_gap(
                    workspace_commitment,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            staged_result = None
        if staged_result is None:
            with contextlib.suppress(Exception):
                await client.close()
            return
        staged_content_sources = staged_result

    grouped: dict[str, list[ObservationOutboxRow]] = {}
    for row in all_pending:
        grouped.setdefault(row.codex_session_id, []).append(row)
    session_order = sorted(grouped, key=str.encode)
    if codex_session_id in grouped:
        session_order.remove(codex_session_id)
        session_order.insert(0, codex_session_id)
    pending: list[ObservationOutboxRow] = []
    pending_limit = row_limit
    if priority_source_identity is not None:
        # Native content is not replayable, so make the current content row's
        # same-session prefix the first bounded work package. The prefix keeps
        # cursor order intact; it never jumps over an older row to deliver
        # plaintext out of order. A large or permanently blocked backlog is
        # still reported as a content gap rather than extending the hook
        # without bound.
        priority_row = next(
            (
                row
                for row in all_pending
                if row.envelope.source_identity == priority_source_identity
            ),
            None,
        )
        if priority_row is not None:
            priority_queue = grouped.get(priority_row.codex_session_id, [])
            priority_index = next(
                (
                    index
                    for index, row in enumerate(priority_queue)
                    if row.envelope.source_identity == priority_source_identity
                ),
                None,
            )
            if priority_index is not None:
                pending_limit = max(row_limit, _NATIVE_CONTENT_ROW_LIMIT)
                prefix_count = min(priority_index + 1, pending_limit)
                pending.extend(priority_queue[:prefix_count])
                remaining_priority = priority_queue[prefix_count:]
                if remaining_priority:
                    grouped[priority_row.codex_session_id] = remaining_priority
                else:
                    grouped.pop(priority_row.codex_session_id, None)
                if priority_row.codex_session_id in session_order:
                    session_order.remove(priority_row.codex_session_id)
                if remaining_priority:
                    session_order.insert(0, priority_row.codex_session_id)
    while grouped and len(pending) < pending_limit:
        for session_id in tuple(session_order):
            queue = grouped.get(session_id)
            if not queue:
                grouped.pop(session_id, None)
                continue
            pending.append(queue.pop(0))
            if not queue:
                grouped.pop(session_id, None)
            if len(pending) >= pending_limit:
                break
    # Retryable rejections split three ways by scope (the reason vocabulary is
    # RETRYABLE_OBSERVATION_REJECTIONS in application/observation_drain.py):
    # - mapping_missing is session-scoped and cannot heal mid-pass, so one
    #   rejection retires the rest of that session for this pass;
    # - vault_locked / observation_disabled / paused are workspace-global and
    #   cannot heal mid-pass, so they end the pass;
    # - service_unavailable is the catch-all for row-scoped and transient
    #   failures (bundle contention, one malformed envelope, a dropped reply).
    #   It must not poison other *sessions*, but it still retires its own
    #   session for the pass: the failed row stays pending at the head of its
    #   lane, and delivering a later row of the same session would advance the
    #   ingest cursor past it and destroy it as terminal cursor_stale (#272).
    #   A run of them across sessions means the service is genuinely
    #   struggling, so the pass yields after a few.
    # Re-attempting every row of a permanently-undeliverable backlog burned
    # the whole drain budget per hook forever — the recurrence tax of #211.
    skipped_sessions: set[str] = set()
    delivered_content: set[str] = set()
    bound_sessions, pending_lifecycle_sessions = store.lifecycle_reconciliation_snapshot(
        workspace_commitment
    )
    consecutive_unavailable = 0
    # The hook owns a bounded slice; the service sweeper owns bulk delivery.
    # Hitting the slice after moving backlog or durably staging native content
    # is a capacity yield, not a failed drain. Staging leaves the structural
    # row pending, but it is useful progress: its transient bytes survived.
    # Budget expiry records a diagnostic only when no progress occurred (#351).
    progressed = len(staged_content_sources)
    try:
        for row in pending:
            if row.codex_session_id in skipped_sessions:
                continue
            # A previous hook may have captured this row while its workspace
            # membership reservation was busy. Converge the raw session route
            # before any service delivery; contention leaves the row untouched.
            if (
                row.codex_session_id not in bound_sessions
                or row.codex_session_id in pending_lifecycle_sessions
            ) and not store.reconcile_outbox_session_lifecycle(
                workspace_commitment,
                row,
                session_lock_owned=session_lock_owned and row.codex_session_id == codex_session_id,
            ):
                skipped_sessions.add(row.codex_session_id)
                continue
            remaining = budget_seconds - (monotonic() - started)
            if remaining <= 0:
                if progressed == 0:
                    record_hook_diagnostic(
                        "drain_pass_delivered_nothing", event_name, _state=_state
                    )
                break
            chunks = (
                ()
                if content_by_source_identity is None
                or row.envelope.source_identity in staged_content_sources
                else content_by_source_identity.get(row.envelope.source_identity, ())
            )
            # A drain delivers every mapped lane in the shared workspace. The
            # hook's content profile names only its own host's rows: sending it
            # with a Codex or other-host row made the service refuse that row as
            # content_capture_profile_mismatch, a terminal quarantine that also
            # stranded the row's durable capture handoff (#836). The service
            # resolves a foreign row's profile from its own ticket.
            row_profile = (
                content_capture_profile
                if content_capture_profile is not None
                and content_capture_profile_matches_source(
                    row.envelope.source.value, content_capture_profile
                )
                else None
            )
            try:
                result = await asyncio.wait_for(
                    _try_service_ingest(
                        client,
                        row.codex_session_id,
                        row.envelope,
                        content_chunks=chunks,
                        content_capture_profile=row_profile,
                        deadline_ms=max(1, int(remaining * 1_000)),
                    ),
                    timeout=remaining,
                )
            except TimeoutError:
                if chunks:
                    store.note_coverage_gap(
                        workspace_commitment,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    )
                if progressed == 0:
                    record_hook_diagnostic(
                        "drain_pass_delivered_nothing", event_name, _state=_state
                    )
                break
            decision = route_observation_ingest(result, row=row)
            # One batch per row, opened only after this row's RPC returned and
            # closed before the next one: the acknowledgement is never durable
            # ahead of the ingest it acknowledges, and the store lock never
            # spans a network wait (#242).
            expected_backpressure = decision.reason in EXPECTED_OBSERVATION_BACKPRESSURE_REASONS
            with store.batched(workspace_commitment):
                attempted = store.bump_outbox_row_attempt(
                    workspace_commitment, row, reason=decision.reason
                )
                if attempted is not None:
                    if decision.reason is not None and not expected_backpressure:
                        store.note_coverage_gap(workspace_commitment, decision.reason)
                    if chunks and decision.action is not ObservationDrainAction.ACKNOWLEDGE:
                        store.note_coverage_gap(
                            workspace_commitment,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        )
                    if decision.action is ObservationDrainAction.QUARANTINE:
                        store.quarantine_outbox_row(
                            workspace_commitment,
                            attempted,
                            decision.reason or ObservationGapCode.SERVICE_UNAVAILABLE.value,
                        )
                        progressed += 1
                    elif decision.action is ObservationDrainAction.ACKNOWLEDGE:
                        store.acknowledge_outbox_row(workspace_commitment, attempted)
                        if chunks:
                            delivered_content.add(row.envelope.source_identity)
                        progressed += 1
            if attempted is None:
                if chunks:
                    store.note_coverage_gap(
                        workspace_commitment,
                        ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                    )
                continue
            if decision.reason is not None and not expected_backpressure:
                record_hook_diagnostic(decision.reason, event_name, _state=_state)
            if decision.reason is not None and not expected_backpressure:
                from finishup.cli.hook_diagnostics import record_drain_failure

                if not record_drain_failure(
                    result, row.envelope, decision.action.value, _state=_state
                ):
                    store.note_coverage_gap(workspace_commitment, "drain_diagnostic_unavailable")
            if isinstance(result, ObservationControlFailure):
                break
            if decision.action is ObservationDrainAction.RETRY:
                if decision.reason in WORKSPACE_GLOBAL_OBSERVATION_STOP_REASONS:
                    break
                # The lane's head row stays pending; skipping to a later row of
                # the same session would deliver it out of order (#272), so the
                # session retires for the pass whatever the retryable reason.
                skipped_sessions.add(row.codex_session_id)
                if decision.reason == ObservationGapCode.MAPPING_MISSING.value:
                    # The session ended while unmapped: nothing will ever map it, so
                    # its rows would otherwise retry forever. Terminalization takes
                    # the lifecycle lock so a concurrent attach that is still
                    # persisting its mapping wins this race (#275, #283 review).
                    moved = 0
                    with contextlib.suppress(Exception):
                        moved = store.quarantine_ended_unmapped_session(
                            workspace_commitment,
                            row.codex_session_id,
                            decision.reason,
                        )
                    if moved:
                        consecutive_unavailable = 0
                        continue
                if decision.reason is not None:
                    # Stamp the retired siblings with the shared cause so
                    # `observe status` never reports them as not_attempted.
                    with contextlib.suppress(Exception):
                        store.note_outbox_session_reason(
                            workspace_commitment,
                            row.codex_session_id,
                            decision.reason,
                        )
                if decision.reason == ObservationGapCode.SERVICE_UNAVAILABLE.value:
                    consecutive_unavailable += 1
                    if consecutive_unavailable >= _DRAIN_MAX_CONSECUTIVE_UNAVAILABLE:
                        break
                else:
                    consecutive_unavailable = 0
                continue
            consecutive_unavailable = 0
    finally:
        if content_by_source_identity:
            for source_identity in content_by_source_identity:
                if source_identity in staged_content_sources:
                    continue
                if source_identity not in delivered_content:
                    with contextlib.suppress(Exception):
                        store.note_coverage_gap(
                            workspace_commitment,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        )
        with contextlib.suppress(Exception):
            await client.close()


async def _try_auto_start(
    codex_session_id: str,
    *,
    _state: Path | None,
    harness_id: Literal["claude", "codex", "cursor"] = "codex",
    workspace_locator: str | None,
    recovery_mapping: LifecycleMapping | None = None,
    connect: HookStartConnector | None = None,
    _session_lock_owned: bool = False,
    _recovery_session_lock_owned: bool = False,
    service_start_timeout_seconds: float | None = None,
) -> AutoAttachOutcome:
    """Service `start` for consented SessionStart auto-attach, or a typed reason.

    The request carries the paired identity the start contract requires:
    ``workspace_ref`` is the canonical workspace locator the hook already bound
    consent to (the working-tree identity), and ``external_ref`` is the
    host-session identity. The service persists only HMAC commitments of both;
    nothing here writes the raw locator. Without a locator there is no legal
    request, so the attempt stops before any service call (#459).

    Honesty: when this succeeds the mapping is start-derived. When it fails, callers keep an
    observation session binding only — later MCP/CLI ``start`` can merge.
    """

    if workspace_locator is None:
        return AutoAttachOutcome(None, "auto_attach_workspace_unbound")

    from pydantic import ValidationError

    from finishup import __version__
    from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
    from finishup.protocol.ids import IdKind, new_id
    from finishup.protocol.models import OperationFailureModel, StartRequest

    external_ref = f"{harness_id}-session:{codex_session_id.removeprefix(f'{harness_id}:')}"
    request_base = {
        "protocol_version": "0.1",
        "schema_version": "1.0.0",
        "actor": {
            # Frozen legacy identifier (ADR-048): a recorded actor id, kept for retry identity.
            "actor_id": f"yoetz:{harness_id}-observe",
            "actor_type": "harness",
        },
        "client": {
            # Frozen legacy identifier (ADR-048): the client kind wire enum value.
            "kind": "yoetz_cli",
            "version": __version__,
            "integration": "local_cli",
        },
        "task_title": f"{harness_id.title()} observation auto-attach",
        "requested_view": "compact",
    }
    try:
        request_body = {
            **request_base,
            "request_id": new_id(IdKind.REQUEST),
            "mode": "create_or_attach" if recovery_mapping is None else "attach",
            "external_ref": external_ref,
            "workspace_ref": workspace_locator,
        }
        if recovery_mapping is not None:
            request_body["session_id"] = recovery_mapping.yoetz_session_id
        request = StartRequest.model_validate(request_body)
    except ValidationError, ValueError, TypeError:
        # An authoring defect in this function, never a runtime condition: it
        # must be visible, not collapsed into an absent mapping.
        return AutoAttachOutcome(None, "auto_attach_request_invalid")

    client: _StartClient | None = None
    attempt_started = time.monotonic()
    recovered_task_id = None if recovery_mapping is None else recovery_mapping.yoetz_task_id

    def _remaining_deadline_ms() -> int:
        elapsed_ms = int((time.monotonic() - attempt_started) * 1_000)
        remaining = _AUTO_ATTACH_START_DEADLINE_MS - elapsed_ms
        if remaining <= 0:
            raise TimeoutError
        return remaining

    try:
        if connect is None:
            connector = cast(Callable[..., Awaitable[_StartClient]], _connect_attachment_service)
            client = await connector(
                ControlClientKind.CLI,
                workspace_locator=WorkspaceLocator(workspace_locator),
                timeout_seconds=service_start_timeout_seconds,
            )
        else:
            client = await connect(ControlClientKind.CLI)
        result = await client.start(request, deadline_ms=_remaining_deadline_ms())
        # A validated local predecessor selects recovery before admission. An
        # ordinary create attempt would now succeed and strand predecessor work.
    except ControlError as error:
        from finishup.service.client import handshake_failure

        if handshake_failure(error) is not None:
            # A running service of this installation closed the hello (#1040 follow-up): not a
            # service that still has to start, and not another installation to replace.
            return AutoAttachOutcome(None, "service_handshake_failed")
        return AutoAttachOutcome(
            None, _AUTO_ATTACH_CONTROL_REASONS.get(error.reason, "service_unavailable")
        )
    except TimeoutError:
        return AutoAttachOutcome(None, "timeout")
    except Exception:
        return AutoAttachOutcome(None, "service_unavailable")
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()

    branch = getattr(result, "root", result)
    if isinstance(branch, OperationFailureModel):
        return AutoAttachOutcome(
            None, _AUTO_ATTACH_ERROR_REASONS.get(branch.error.code, "auto_attach_refused")
        )
    if getattr(branch, "ok", None) is not True:
        return AutoAttachOutcome(None, "auto_attach_result_invalid")
    task_id = getattr(branch, "task_id", None)
    session_id = getattr(branch, "session_id", None)
    writer_id = getattr(branch, "writer_id", None)
    if type(task_id) is not str or type(session_id) is not str or type(writer_id) is not str:
        return AutoAttachOutcome(None, "auto_attach_result_invalid")
    if recovered_task_id is not None and task_id != recovered_task_id:
        return AutoAttachOutcome(None, "auto_attach_result_invalid")
    frontier = getattr(branch, "frontier", None)
    last_frontier = None
    if frontier is not None:
        sequence = getattr(frontier, "sequence", None)
        digest = getattr(frontier, "head_digest", None)
        if type(sequence) is str and type(digest) is str:
            from finishup.adapters.integrations.codex_lifecycle import encode_frontier_token

            try:
                last_frontier = encode_frontier_token(sequence=sequence, head_digest=digest)
            except Exception:
                return AutoAttachOutcome(None, "auto_attach_result_invalid")
    try:
        mapping = mapping_from_start_ids(
            codex_session_id=codex_session_id,
            yoetz_task_id=task_id,
            yoetz_session_id=session_id,
            yoetz_writer_id=writer_id,
            last_frontier=last_frontier,
        )
    except Exception:
        return AutoAttachOutcome(None, "auto_attach_result_invalid")
    try:
        if not _queue_and_reconcile_mapping(
            mapping,
            _state=_state,
            _session_lock_owned=_session_lock_owned,
        ):
            return AutoAttachOutcome(None, "auto_attach_recovery_busy")
    except Exception:
        return AutoAttachOutcome(None, "auto_attach_mapping_write_failed")
    if (
        recovered_task_id is not None
        and recovery_mapping is not None
        and recovery_mapping.codex_session_id != mapping.codex_session_id
    ):
        predecessor_mapping = mapping_from_start_ids(
            codex_session_id=recovery_mapping.codex_session_id,
            yoetz_task_id=mapping.yoetz_task_id,
            yoetz_session_id=mapping.yoetz_session_id,
            yoetz_writer_id=mapping.yoetz_writer_id,
            last_frontier=recovery_mapping.last_frontier,
        )
        try:
            if not _queue_and_reconcile_mapping(
                predecessor_mapping,
                _state=_state,
                _session_lock_owned=_recovery_session_lock_owned,
            ):
                return AutoAttachOutcome(None, "auto_attach_recovery_busy")
        except Exception:
            return AutoAttachOutcome(None, "auto_attach_mapping_write_failed")
    return AutoAttachOutcome(mapping, None, recovered=recovered_task_id is not None)


def _host_session_matches(
    session_id: str, harness_id: Literal["claude", "codex", "cursor"]
) -> bool:
    """True when the stored host session id belongs to this hook family."""

    if harness_id == "claude":
        return session_id.startswith(_CLAUDE_SESSION_PREFIX)
    if harness_id == "cursor":
        return session_id.startswith(_CURSOR_SESSION_PREFIX)
    return not session_id.startswith((_CLAUDE_SESSION_PREFIX, _CURSOR_SESSION_PREFIX))


# Ended host-session bindings retained per workspace beyond the ones a recovery
# attach consumed. Consumed bindings are pruned at consumption; this cap bounds
# the never-consumed remainder (sessions that never mapped, sibling tasks in one
# workspace) so neither the SessionStart scan nor the state file grows with the
# workspace's whole history (#549). Ranked by mapping recency so the selectors
# recovery would pick survive; ended sessions without a mapping go first.
_MAX_ENDED_SESSION_BINDINGS: Final = 32


def _queue_and_reconcile_mapping(
    mapping: LifecycleMapping,
    *,
    _state: Path | None,
    _session_lock_owned: bool = False,
) -> bool:
    """Queue one lifecycle write, replay the lane, and verify its exact route.

    A producer that loses the session lock may still leave a durable pending
    operation. The owner therefore queues its result before replaying residual
    work, then re-reads both the materialized mapping and the pending fence.
    A concurrent newer producer makes this operation ineligible to report as
    the active route; the next hook owns that newer operation.
    """

    lifecycle_lock = (
        contextlib.nullcontext(True)
        if _session_lock_owned
        else acquire_session_lock(mapping.codex_session_id, _state=_state)
    )
    with lifecycle_lock as owned:
        queue_mapping_store(mapping, _state=_state)
        if not owned:
            return False
        from finishup.cli.hooks import recover_pending_start_mapping

        if recover_pending_start_mapping(
            mapping.codex_session_id,
            _state=_state,
            _session_lock_owned=True,
        ).pending:
            return False
        pending = mapping_path(mapping.codex_session_id, _state=_state).with_name(
            f".{mapping.codex_session_id}.pending.json"
        )
        applying = pending.with_name(pending.name + ".applying")
        return load_mapping(mapping.codex_session_id, _state=_state) == mapping and not (
            pending.exists() or pending.is_symlink() or applying.exists() or applying.is_symlink()
        )


@dataclass(frozen=True, slots=True)
class _RecoveryCandidate:
    """One eligible predecessor mapping plus the recency used to select it."""

    mapping: LifecycleMapping
    modified_ns: int


@dataclass(frozen=True, slots=True)
class _RecoveryScan:
    """One pass's ended-session recovery scan, computed once and revalidated (#549)."""

    # The selected predecessor mapping, or None when recovery is not admissible.
    mapping: LifecycleMapping | None
    # (host session id, ended) for every binding in the workspace at scan time.
    lifecycles: tuple[tuple[str, bool], ...]
    # Every ended same-host session considered by the scan, including one without
    # a mapping yet.  Holding these session locks keeps a mapping from appearing
    # or changing while the recovery request is in flight.
    eligible_session_ids: tuple[str, ...] = ()
    # Valid, unambiguous mappings among ``eligible_session_ids``.  Recency is
    # part of the snapshot because a same-byte rewrite can change the selector.
    candidates: tuple[_RecoveryCandidate, ...] = ()


def _load_recovery_candidate(session_id: str, *, _state: Path | None) -> _RecoveryCandidate | None:
    """Read one valid mapping and the file recency used for recovery ranking."""

    mapping = load_mapping(session_id, _state=_state)
    if mapping is None:
        return None
    try:
        path = mapping_path(session_id, _state=_state)
        if path.is_symlink():
            return None
        return _RecoveryCandidate(mapping, path.stat().st_mtime_ns)
    except OSError, ProtocolValueError:
        return None


def _latest_mapping(
    candidates: tuple[_RecoveryCandidate, ...],
) -> LifecycleMapping | None:
    """Rank already-loaded mappings by the file recency captured in one pass."""

    latest: tuple[int, bytes, LifecycleMapping] | None = None
    for candidate in candidates:
        ranked = (
            candidate.modified_ns,
            candidate.mapping.codex_session_id.encode(),
            candidate.mapping,
        )
        if latest is None or ranked[:2] > latest[:2]:
            latest = ranked
    return None if latest is None else latest[2]


def _scan_ended_workspace_recovery(
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    *,
    harness_id: Literal["claude", "codex", "cursor"],
    _state: Path | None,
    lifecycles: tuple[tuple[str, bool], ...] | None = None,
) -> _RecoveryScan:
    """Select the latest same-host predecessor when every other bound session has ended.

    One state read yields every binding's ended flag, so the live-session early
    return costs no per-binding store call; the cross-workspace ambiguity probe
    and the mapping reads run only once some ended same-host candidate exists,
    and each candidate's mapping file is read once per pass (#549).
    """

    if lifecycles is None:
        lifecycles = store.codex_session_lifecycles_for_workspace(workspace_commitment)
    # Scoped child lanes have no native SessionEnd in the shared-session host contract. They
    # must not keep the parent workspace ineligible for recovery or be selected as a parent
    # predecessor. Their own mapping remains available for direct child callbacks.
    lifecycles = tuple(
        (session_id, ended)
        for session_id, ended in lifecycles
        if not is_scoped_child_session_id(session_id)
    )
    if any(session_id != codex_session_id and not ended for session_id, ended in lifecycles):
        return _RecoveryScan(None, lifecycles)
    eligible = tuple(
        session_id
        for session_id, is_ended in lifecycles
        if session_id != codex_session_id
        and is_ended
        and _host_session_matches(session_id, harness_id)
    )
    if not eligible:
        return _RecoveryScan(None, lifecycles)
    unambiguous = frozenset(store.unambiguous_codex_sessions_for_workspace(workspace_commitment))
    candidates = tuple(
        candidate
        for session_id in eligible
        if session_id in unambiguous
        and (candidate := _load_recovery_candidate(session_id, _state=_state)) is not None
    )
    if len({candidate.mapping.yoetz_task_id for candidate in candidates}) != 1:
        return _RecoveryScan(None, lifecycles, eligible, candidates)
    return _RecoveryScan(_latest_mapping(candidates), lifecycles, eligible, candidates)


@contextlib.contextmanager
def _acquire_recovery_session_locks(
    session_ids: tuple[str, ...],
    *,
    held_codex_session_id: str,
    _state: Path | None,
) -> Generator[bool]:
    """Hold every scanned predecessor lock through validation and attach.

    Session locks are nonblocking by contract.  If another host event owns one
    of the candidate locks, recovery yields ``False`` and the caller reports
    recovery busy without making a service request. Acquiring in sorted order avoids a lock
    hierarchy cycle between concurrent recovery attempts.
    """

    with contextlib.ExitStack() as stack:
        for session_id in sorted(set(session_ids), key=str.encode):
            if session_id == held_codex_session_id:
                continue
            if not stack.enter_context(acquire_session_lock(session_id, _state=_state)):
                yield False
                return
        yield True


@contextlib.contextmanager
def _acquire_observe_membership_lock(
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    *,
    _state: Path | None,
    force: bool = False,
    session_lock_owned: bool = False,
) -> Generator[bool]:
    """Reserve a workspace before creating a new host-session membership.

    Existing membership is idempotent and need not contend with recovery except
    for a forced SessionStart. A new membership takes the workspace reservation
    first, then its session lock, matching recovery's lock order. Both locks are
    nonblocking so a busy hook can still retain an explicitly targeted
    observation envelope. ``session_lock_owned`` is used only by the clear-route
    caller, which already owns the session lock but must still reserve the
    workspace before changing membership state.
    """

    existing = codex_session_id in store.codex_sessions_for_workspace(workspace_commitment)
    if not force and existing:
        yield True
        return
    with acquire_workspace_recovery_lock(workspace_commitment, _state=_state) as workspace_owned:
        if not workspace_owned:
            yield False
            return
        if session_lock_owned:
            # The clear-route caller already owns the session lock. It still
            # needs the workspace reservation so recovery cannot race the
            # generation/membership mutation.
            yield True
            return
        with acquire_session_lock(codex_session_id, _state=_state) as session_owned:
            yield session_owned


def _recovery_scan_still_valid(
    store: LocalObservationStore,
    workspace_commitment: str,
    scan: _RecoveryScan,
    *,
    _state: Path | None,
) -> bool:
    """Re-check all scan inputs while every eligible predecessor is locked (#605).

    The caller holds the selected predecessor and every other eligible session
    lock through this check and the recovery RPC.  Re-reading the complete
    bounded candidate set catches cross-workspace ownership changes, newly
    materialized mappings, changed task identities, and recency changes that
    could otherwise leave a stale non-selected candidate outside validation.
    """

    if scan.mapping is None:
        return False
    current_lifecycles = tuple(
        (session_id, ended)
        for session_id, ended in store.codex_session_lifecycles_for_workspace(workspace_commitment)
        if not is_scoped_child_session_id(session_id)
    )
    if current_lifecycles != scan.lifecycles:
        return False
    unambiguous = frozenset(store.unambiguous_codex_sessions_for_workspace(workspace_commitment))
    current = tuple(
        candidate
        for session_id in scan.eligible_session_ids
        if session_id in unambiguous
        and (candidate := _load_recovery_candidate(session_id, _state=_state)) is not None
    )
    if current != scan.candidates:
        return False
    return _latest_mapping(current) == scan.mapping


def _prune_surplus_ended_session_bindings(
    store: LocalObservationStore,
    workspace_commitment: str,
    lifecycles: tuple[tuple[str, bool], ...],
    codex_session_id: str,
    *,
    _state: Path | None,
) -> tuple[str, ...]:
    """Keep the newest ended bindings up to the cap; ask the store to prune the rest.

    Only the surplus is ranked, and ranking is one ``stat`` per ended binding:
    sessions with no mapping file first (they cannot serve recovery), then by
    mapping modification time, oldest first. The store enforces the
    ended-and-drained rule, so a surplus binding with pending or quarantined rows
    survives and is offered again on a later pass (#549).
    """

    ended = [
        session_id
        for session_id, is_ended in lifecycles
        if is_ended and session_id != codex_session_id
    ]
    surplus = len(ended) - _MAX_ENDED_SESSION_BINDINGS
    if surplus <= 0:
        return ()

    def _rank(session_id: str) -> tuple[int, int, bytes]:
        try:
            path = mapping_path(session_id, _state=_state)
            if path.is_symlink():
                return (0, 0, session_id.encode())
            return (1, path.stat().st_mtime_ns, session_id.encode())
        except OSError, ProtocolValueError:
            return (0, 0, session_id.encode())

    ended.sort(key=_rank)
    return store.prune_codex_session_bindings(workspace_commitment, ended[:surplus])


def _rewrite_one_ended_predecessor_mapping(
    store: LocalObservationStore,
    workspace_commitment: str,
    session_id: str,
    successor: LifecycleMapping,
    *,
    _state: Path | None,
    _session_lock_owned: bool = False,
) -> bool:
    """Rewrite one ended predecessor if it still maps the recovered task.

    Returns True when the predecessor now carries the successor route, whether it
    was rewritten here or was already aligned: those are the bindings the
    recovery consumed (#549).
    """

    if not store.codex_session_ended(workspace_commitment, session_id):
        return False
    predecessor = load_mapping(session_id, _state=_state)
    if predecessor is None or predecessor.yoetz_task_id != successor.yoetz_task_id:
        return False
    if (
        predecessor.yoetz_session_id == successor.yoetz_session_id
        and predecessor.yoetz_writer_id == successor.yoetz_writer_id
    ):
        return True
    rewritten = mapping_from_start_ids(
        codex_session_id=predecessor.codex_session_id,
        yoetz_task_id=successor.yoetz_task_id,
        yoetz_session_id=successor.yoetz_session_id,
        yoetz_writer_id=successor.yoetz_writer_id,
        last_frontier=predecessor.last_frontier,
    )
    try:
        return _queue_and_reconcile_mapping(
            rewritten,
            _state=_state,
            _session_lock_owned=_session_lock_owned,
        )
    except Exception:
        return False


def _rewrite_ended_predecessor_mappings(
    store: LocalObservationStore,
    workspace_commitment: str,
    successor: LifecycleMapping,
    *,
    harness_id: Literal["claude", "codex", "cursor"],
    _state: Path | None,
    held_codex_session_id: str | None = None,
    held_codex_session_ids: frozenset[str] = frozenset(),
    authorized_codex_session_ids: frozenset[str] | None = None,
    lifecycles: tuple[tuple[str, bool], ...] | None = None,
) -> tuple[str, ...]:
    """Point ended same-host mappings at the rotated successor route (#577).

    Returns the predecessors that now carry the successor route. ``lifecycles``
    is the pass's scan snapshot when the caller has one; the ended flag is still
    re-read under each predecessor's lock before its mapping is touched. When
    the caller supplies ``authorized_codex_session_ids``, only that scan-proven
    unambiguous set can be rewritten. Direct callers compute the same set here.
    """

    if lifecycles is None:
        lifecycles = store.codex_session_lifecycles_for_workspace(workspace_commitment)
    # A supplied set is a scan snapshot protected by the workspace reservation
    # in the production recovery path. Direct callers have no such reservation,
    # so they recheck each candidate while holding its per-session lock below.
    authorized = authorized_codex_session_ids
    held = set(held_codex_session_ids)
    if held_codex_session_id is not None:
        held.add(held_codex_session_id)
    consumed: list[str] = []
    for session_id, ended in lifecycles:
        if session_id == successor.codex_session_id or not ended:
            continue
        if not _host_session_matches(session_id, harness_id):
            continue
        if authorized is not None and session_id not in authorized:
            continue
        try:
            if session_id in held:
                if authorized is None and session_id not in frozenset(
                    store.unambiguous_codex_sessions_for_workspace(workspace_commitment)
                ):
                    continue
                aligned = _rewrite_one_ended_predecessor_mapping(
                    store,
                    workspace_commitment,
                    session_id,
                    successor,
                    _state=_state,
                    _session_lock_owned=True,
                )
            else:
                with acquire_session_lock(session_id, _state=_state) as owned:
                    if not owned:
                        continue
                    if authorized is None and session_id not in frozenset(
                        store.unambiguous_codex_sessions_for_workspace(workspace_commitment)
                    ):
                        continue
                    aligned = _rewrite_one_ended_predecessor_mapping(
                        store,
                        workspace_commitment,
                        session_id,
                        successor,
                        _state=_state,
                        _session_lock_owned=True,
                    )
        except Exception:
            continue
        if aligned:
            consumed.append(session_id)
    return tuple(consumed)


async def _try_workspace_auto_start(
    codex_session_id: str,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    workspace_locator: str | None,
    harness_id: Literal["claude", "codex", "cursor"],
    _state: Path | None,
    connect: HookStartConnector | None,
    prune_surplus: bool = False,
    _session_lock_owned: bool = False,
    service_start_timeout_seconds: float | None = None,
) -> AutoAttachOutcome:
    """Auto-start, holding every eligible predecessor stable through recovery.

    The recovery scan runs once per call; the bounded re-check under the selected
    and eligible-predecessor locks compares the complete candidate snapshot before
    the RPC, so the retry events' one-second budget wraps a bounded amount of
    synchronous local work (#549/#605). ``prune_surplus`` is the SessionStart
    pass's retention step; retry events skip it.
    """

    with acquire_workspace_recovery_lock(workspace_commitment, _state=_state) as recovery_owned:
        if not recovery_owned:
            # Membership and recovery share this reservation. A contended
            # SessionStart must wait for the owner; issuing an ordinary start
            # here would attach a second task during recovery.
            return AutoAttachOutcome(None, "auto_attach_recovery_busy")
        lifecycles = store.codex_session_lifecycles_for_workspace(workspace_commitment)
        if prune_surplus:
            pruned: tuple[str, ...] = ()
            with contextlib.suppress(Exception):
                pruned = _prune_surplus_ended_session_bindings(
                    store, workspace_commitment, lifecycles, codex_session_id, _state=_state
                )
            if pruned:
                lifecycles = tuple(entry for entry in lifecycles if entry[0] not in pruned)
        scan = _scan_ended_workspace_recovery(
            store,
            workspace_commitment,
            codex_session_id,
            harness_id=harness_id,
            _state=_state,
            lifecycles=lifecycles,
        )
        recovery = scan.mapping
        candidate_count = len({candidate.mapping.yoetz_task_id for candidate in scan.candidates})
        if candidate_count > 1:
            # Several independently bound predecessors are ambiguous. New
            # admission cannot turn that ambiguity into authority to resume.
            return AutoAttachOutcome(
                None, "auto_attach_binding_ambiguous", candidate_count=candidate_count
            )
        if recovery is None:
            # Release the workspace reservation before the ordinary RPC.
            # A return expression containing ``await`` would evaluate while
            # this context is still held.
            pass
        else:
            # Recovery locks the selected predecessor first for compatibility
            # with its existing lifecycle fence, then takes every other
            # candidate in stable order.
            with acquire_session_lock(
                recovery.codex_session_id, _state=_state
            ) as predecessor_owned:
                if predecessor_owned:
                    with _acquire_recovery_session_locks(
                        scan.eligible_session_ids,
                        held_codex_session_id=recovery.codex_session_id,
                        _state=_state,
                    ) as candidates_owned:
                        if candidates_owned and _recovery_scan_still_valid(
                            store, workspace_commitment, scan, _state=_state
                        ):
                            if service_start_timeout_seconds is None:
                                outcome = await _try_auto_start(
                                    codex_session_id,
                                    _state=_state,
                                    harness_id=harness_id,
                                    workspace_locator=workspace_locator,
                                    recovery_mapping=recovery,
                                    connect=connect,
                                    _session_lock_owned=_session_lock_owned,
                                    _recovery_session_lock_owned=True,
                                )
                            else:
                                outcome = await _try_auto_start(
                                    codex_session_id,
                                    _state=_state,
                                    harness_id=harness_id,
                                    workspace_locator=workspace_locator,
                                    recovery_mapping=recovery,
                                    connect=connect,
                                    _session_lock_owned=_session_lock_owned,
                                    _recovery_session_lock_owned=True,
                                    service_start_timeout_seconds=service_start_timeout_seconds,
                                )
                            if outcome.mapping is not None and outcome.recovered:
                                with contextlib.suppress(Exception):
                                    consumed = _rewrite_ended_predecessor_mappings(
                                        store,
                                        workspace_commitment,
                                        outcome.mapping,
                                        harness_id=harness_id,
                                        _state=_state,
                                        held_codex_session_ids=frozenset(scan.eligible_session_ids),
                                        authorized_codex_session_ids=frozenset(
                                            candidate.mapping.codex_session_id
                                            for candidate in scan.candidates
                                        ),
                                        lifecycles=scan.lifecycles,
                                    )
                                    # Recovery consumed these predecessors: the live successor
                                    # binding now carries their task, and their mapping files stay
                                    # in the lifecycle store to route any rows still pending. The
                                    # store keeps every binding whose rows are not yet drained.
                                    store.prune_codex_session_bindings(
                                        workspace_commitment, consumed
                                    )
                            return outcome

            # The recorded predecessor existed but could not be held stable.
            # Retrying admission as new work here would strand that task.
            return AutoAttachOutcome(None, "auto_attach_recovery_busy")

    # No persisted recovery capability exists: admit independently as new work.
    if service_start_timeout_seconds is None:
        return await _try_auto_start(
            codex_session_id,
            _state=_state,
            harness_id=harness_id,
            workspace_locator=workspace_locator,
            connect=connect,
            _session_lock_owned=_session_lock_owned,
        )
    return await _try_auto_start(
        codex_session_id,
        _state=_state,
        harness_id=harness_id,
        workspace_locator=workspace_locator,
        connect=connect,
        _session_lock_owned=_session_lock_owned,
        service_start_timeout_seconds=service_start_timeout_seconds,
    )


def _record_auto_attach(
    outcome: AutoAttachOutcome,
    event_name: str,
    *,
    _state: Path | None,
) -> LifecycleMapping | None:
    """Surface a failed auto-attach as a payload-free diagnostic; return the mapping."""

    if outcome.mapping is not None:
        return outcome.mapping
    reason = outcome.reason if outcome.reason is not None else "service_unavailable"
    count_suffix = (
        "" if outcome.candidate_count is None else f"; candidates: {outcome.candidate_count}"
    )
    _stderr_line(f"hook_auto_attach_failed: {reason}{count_suffix}")
    with contextlib.suppress(Exception):
        if outcome.candidate_count is None:
            record_hook_diagnostic(reason, event_name, _state=_state)
        else:
            record_hook_diagnostic(
                reason, event_name, candidate_count=outcome.candidate_count, _state=_state
            )
    return None


def _note_dropped_event_gap(
    store: LocalObservationStore,
    payload: Mapping[str, JsonValue],
    workspace: str | None,
) -> None:
    """Record a coverage gap for an event dropped before the local pass ran.

    Mirrors the binding order of the main pass: the explicit workspace
    argument first, then the Codex-session→workspace map. A silently missing
    event is the one outcome this subsystem must not produce, so any drop
    must be visible to ``observe status`` and coverage wording.
    """

    commitment: str | None = None
    if workspace is not None:
        try:
            locator = canonical_workspace_locator(workspace)
            if locator is None:
                raise ValueError("workspace_locator_invalid")
            candidate = store.workspace_commitment(locator)
            consent = store.consent_for(candidate)
            if consent is not None and consent.active:
                commitment = candidate
        except Exception:
            commitment = None
    if commitment is None:
        codex_session_id = validate_codex_session_id(payload.get("session_id"))
        commitment = store.find_workspace_for_codex_session(codex_session_id)
    if commitment is None:
        return
    consent = store.consent_for(commitment)
    if consent is None or not consent.active:
        return
    store.note_coverage_gap(commitment, ObservationGapCode.OBSERVATION_STORAGE_CORRUPT.value)


_PAYLOAD_TOO_LARGE_REASONS: Final[Mapping[ObservationSource, str]] = MappingProxyType(
    {
        ObservationSource.CLAUDE_HOOK: "claude_payload_too_large",
        ObservationSource.CODEX_HOOK: "codex_payload_too_large",
        ObservationSource.CURSOR_HOOK: "cursor_payload_too_large",
    }
)


def _note_payload_too_large_gap(
    *,
    source: ObservationSource,
    workspace: str | None,
    _state: Path | None,
) -> None:
    """Bind the oversize loss to a consented workspace without reading the body.

    The command-line locator is the only binding available: the session id,
    tool name, and changed paths all live inside the bytes this pass refused to
    parse. Cursor resolves its locator through the host resolver with an empty
    payload, which keeps ``CURSOR_PROJECT_DIR`` and the explicit argument in
    their usual precedence while forwarding no host field at all.
    """

    locator = (
        resolve_workspace_locator(explicit=workspace, payload={}, env=os.environ)
        if source is ObservationSource.CURSOR_HOOK
        else (None if workspace is None else canonical_workspace_locator(workspace))
    )
    if type(locator) is not str or not locator:
        return
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(locator)
    consent = store.consent_for(commitment)
    if consent is None or not consent.active:
        return
    store.note_coverage_gap(commitment, ObservationGapCode.PAYLOAD_TOO_LARGE.value)


def note_payload_too_large(
    event: str,
    *,
    source: ObservationSource,
    workspace: str | None,
    _state: Path | None = None,
) -> None:
    """Name one oversized hook event that produced no structural row.

    Usually the body was never parsed, so the only identity this pass can
    honestly claim is the host that ran it, the hook name that host named on
    its own command line, and the bound itself. Even the true size is unknown
    by construction: the ingress reads at most skim-cap-plus-one bytes and
    stops. A body inside the skim cap normally keeps a structural row (tb4n1
    B5); one that fails the skim's safety checks, or (Cursor) keeps no row
    (invalid, no session, or no resolvable workspace), lands here too.
    Nothing is inferred from unread bytes, and no structural row is minted.

    Two records, because there are two audiences. The bounded owner-only
    diagnostic tells an operator which host lost which event; the workspace
    coverage gap makes the same loss reach ``observe status``. It does not yet
    reach task receipts, which read only the ledger; there the dropped edit has
    no evidence at all, so it can never read as captured work (issue #667).
    """

    # Every host reaches this past the shared trusted cap: over the skim cap,
    # a complete oversized body that failed the skim's safety checks, or (Cursor)
    # a skimmed body that kept no row. Both bounds are named; the true size is
    # unknown by construction (tb4n1 B5).
    bounds = (
        f"host event over the {MAX_HOOK_STDIN_BYTES}-byte hook ingress cap and not "
        f"recoverable within the {MAX_HOOK_SKIM_BYTES}-byte skim"
    )
    detail = (
        f"hook_cursor_observe_degraded: payload_too_large; {bounds}"
        if source is ObservationSource.CURSOR_HOOK
        else f"hook_observe_degraded: payload_too_large; {bounds}"
    )
    with contextlib.suppress(BaseException):
        _stderr_line(f"{detail}; not observed; see observe status")
    with contextlib.suppress(BaseException):
        record_hook_diagnostic(
            _PAYLOAD_TOO_LARGE_REASONS.get(source, "codex_payload_too_large"),
            event,
            _state=_state,
        )
    with contextlib.suppress(BaseException):
        _note_payload_too_large_gap(source=source, workspace=workspace, _state=_state)


def _consent_binding_diagnostic(consent: LocalObservationConsent | None) -> str:
    """Name why a resolved workspace admits no ingest: paused, or no active consent.

    Revocation wins over the retained pause flag, matching the `observe status`
    consent label: a revoked grant is unconsented, not paused.
    """

    if consent is not None and consent.revoked_at is None and consent.paused:
        return "paused"
    return "workspace_unconsented"


def _session_start_source(payload: Mapping[str, JsonValue]) -> str | None:
    """Resolve the closed SessionStart lifecycle source from a host envelope.

    Codex carries ``source`` directly. Claude and Cursor wrappers encode the
    same closed value in their already-admitted structural action so the
    observation wire schema does not gain a free-form source field.
    """

    source = payload.get("source")
    if type(source) is str and source in _SESSION_START_SOURCES:
        return source
    action = payload.get("action")
    if type(action) is str:
        if action == "claude_session_clear" or action == "cursor_session_clear":
            return "clear"
        if action == "claude_session_compact" or action == "cursor_session_compact":
            return "compact"
    return None


def _report_session_end_unrecorded(event: str, *, _state: Path | None) -> None:
    """Name a teardown whose local session end did not persist (#843)."""

    _stderr_line(
        "hook_observe_degraded: session_end_unrecorded; session end not recorded; see observe status"
    )
    record_hook_diagnostic("session_end_unrecorded", event, _state=_state)


def _task_pending_outbox_count(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    codex_session_id: str,
    yoetz_session_id: str,
    _state: Path | None,
) -> int:
    """Count local outbox rows still pending that can still change this task's observed facts.

    A row counts when it belongs to this host session or to another host session mapped to
    the same FinishUP session (a delegated child lane). Rows of other tasks sharing the workspace,
    and rows of unmapped sessions (which cannot reach any task ledger until mapped), do not
    hold this task's Stop decision. The shared helper also backs the service's optional
    pre-check wait (``check`` with ``await_observations``, issue #1012).
    """

    return task_pending_outbox_count(
        store,
        workspace_commitment=workspace_commitment,
        yoetz_session_id=yoetz_session_id,
        codex_session_id=codex_session_id,
        _state=_state,
    )


async def _finish_stop_drain(
    store: LocalObservationStore,
    *,
    workspace_commitment: str,
    codex_session_id: str,
    yoetz_session_id: str,
    connect: HookDrainConnector | None,
    _state: Path | None,
    deadline: float,
    monotonic: Callable[[], float],
    session_lock_owned: bool,
) -> int:
    """Drain this task's rows to the current frontier inside the Stop window (tb4n1 B4/C6).

    Returns the task's rows still pending. Bounded by ``deadline``, which keeps the closure
    gate's status-read reserve. While another owner (a concurrent hook or the service
    sweeper) holds the drain lease, the pass waits for that owner's progress instead of
    giving up; when this pass held the lease and delivered nothing, the remaining rows are
    blocked on a retryable service condition and are left to the sweeper.
    """

    import asyncio

    from finishup.adapters.integrations.observation_task_pending import task_pending_outbox_rows

    def _snapshot() -> tuple[int, frozenset[tuple[str, int]]]:
        """This task's pending count, and a fingerprint of the whole outbox's movement."""

        task_left = len(
            task_pending_outbox_rows(
                store,
                workspace_commitment=workspace_commitment,
                yoetz_session_id=yoetz_session_id,
                codex_session_id=codex_session_id,
                _state=_state,
            )
        )
        moving = frozenset(
            (row.row_identity, row.attempts)
            for row in store.list_pending_outbox_rows(workspace_commitment)
        )
        return task_left, moving

    left, outbox = _snapshot()
    last_progress = monotonic()
    while left:
        now = monotonic()
        if now >= deadline or now - last_progress >= _STOP_DRAIN_STALL_SECONDS:
            break
        owned = await _drain_outbox(
            store,
            workspace_commitment=workspace_commitment,
            codex_session_id=codex_session_id,
            connect=connect,
            event_name="Stop",
            _state=_state,
            budget_seconds=min(_STOP_DRAIN_BUDGET_SECONDS, deadline - now),
            monotonic=monotonic,
            session_lock_owned=session_lock_owned,
            row_limit=_STOP_DRAIN_ROW_LIMIT,
            deadline=deadline,
        )
        after, after_outbox = _snapshot()
        # A pass that held the lease itself and delivered none of this task's rows is a blocked
        # backlog (a retryable refusal), left to the sweeper. Behind another owner, any outbox
        # movement is progress: it may deliver other tasks' rows, or retry, before reaching ours.
        if owned and after >= left:
            left = after
            break
        moved = owned or after_outbox != outbox
        if moved:
            last_progress = monotonic()
        left, outbox = after, after_outbox
        if left and not owned:
            await asyncio.sleep(max(0.0, min(0.05, deadline - monotonic())))
    return left


def _decide_closure_gate(
    mapping: LifecycleMapping,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    codex_session_id: str,
    workspace_locator: str | None,
    payload: Mapping[str, JsonValue],
    connect: ServiceConnector | None,
    run: AsyncRunner,
    harness_id: str,
    remaining_seconds: float,
    _state: Path | None,
    active_stop: bool = False,
    final_message: str | None = None,
) -> ClosureGate | None:
    """Decide the Stop-time closure gate for one mapped session (#977). Never raises.

    ``final_message`` is the agent's last message when the host's Stop payload carries one
    (Codex and Claude Code ``last_assistant_message``; Cursor's ``stop`` has none). It only
    decides which resolved obligations the acceptance re-read names (#1050) and never leaves
    this process: it is not stored, sent or recorded in a diagnostic.

    Reads the service's compact status for the mapped session; the gate fires at most once per
    session and ledger frontier. Every outcome lands in the bounded hook diagnostics so an
    operator (or a benchmark export of ``finishup observe status``) can see what the gate decided.
    On an ``active_stop`` (the host already continued this turn) only a re-check key not yet
    asked (blocker, acknowledgement, acceptance re-read) or a withdrawn deliverable not yet
    voiced may continue the agent, within the per-turn cap; the caller records the outcome
    (#985, tb4n3 RC-8).
    """

    reason = "closure_gate_unavailable"
    gate: ClosureGate | None = None
    try:
        if active_stop and (
            closure_gate_turn_blocks(mapping.yoetz_session_id, _state=_state)
            >= MAX_GATE_BLOCKS_PER_TURN
        ):
            return None
        if remaining_seconds < _STOP_CLOSURE_GATE_RESERVE_SECONDS:
            reason = "closure_gate_budget_exhausted"
            return None
        from finishup.cli.hooks import bound_connector, resolve_session_workspace

        locator = (
            workspace_locator
            if workspace_locator is not None
            else resolve_session_workspace(None, payload).locator
        )
        connector = (
            connect
            if connect is not None
            else bound_connector(
                cast(Callable[..., Awaitable[object]], _connect_service()), locator
            )
        )
        # Observed-run facts are used only when this task's hook rows have all reached the
        # service: the Stop pass drained toward the current frontier just before this read.
        # Rows of other tasks in the same workspace no longer suppress the facts (tb4n1 C6).
        try:
            pending = (
                _task_pending_outbox_count(
                    store,
                    workspace_commitment=workspace_commitment,
                    codex_session_id=codex_session_id,
                    yoetz_session_id=mapping.yoetz_session_id,
                    _state=_state,
                )
                > 0
            )
        except Exception:
            pending = True
        # Blockers this session was already re-asked about are honoured without asking again.
        reasked = closure_gate_reasked_blockers(mapping.yoetz_session_id, _state=_state)
        # A recorded code-mode ``exec`` cell is the capability signal (#1079). No cell, a store
        # that cannot answer, or any error is the neutral close instruction. The host brand is not.
        code_mode = False
        try:
            commitment = store.session_commitment(codex_session_id)
            probe = getattr(store, "session_observed_code_mode", None)
            if callable(probe):
                code_mode = probe(workspace_commitment, commitment) is True
        except Exception:
            code_mode = False

        async def _read() -> ClosureGate | None:
            return await read_closure_gate(
                session_id=mapping.yoetz_session_id,
                writer_id=mapping.yoetz_writer_id,
                connect=cast(Callable[..., Awaitable[object]], connector),
                # Frozen legacy identifier (ADR-048): a recorded actor id, kept for retry identity.
                actor_id=f"yoetz:{harness_id}-hooks",
                observation_pending=pending,
                reasked_blockers=reasked,
                active_stop=active_stop,
                final_message=final_message,
                host=harness_id,
                code_mode=code_mode,
                on_acceptance_covered=lambda: record_hook_diagnostic(
                    "closure_gate_acceptance_covered", "Stop", _state=_state
                ),
            )

        decided = cast(ClosureGate | None, run(_read))
        if decided is None:
            reason = "closure_gate_not_required"
            return None
        if not active_stop and closure_gate_already_delivered(
            mapping.yoetz_session_id, decided.identity, _state=_state
        ):
            reason = "closure_gate_repeat_suppressed"
            return None
        if active_stop and not record_closure_gate_delivered(
            mapping.yoetz_session_id,
            decided.identity,
            blocker_keys=decided.blocker_keys,
            active_stop=True,
            _state=_state,
        ):
            # Nothing else bounds an active Stop: without durable once-per-key and per-turn
            # memory the re-check is not emitted, so the agent may stop (fail open). Recording
            # before the write can only under-ask, never loop.
            return None
        gate = decided
        reason = ""
        return gate
    except Exception:
        return None
    finally:
        # An active Stop that emits nothing is recorded once by the caller as the normal end of a
        # continued turn (``closure_gate_turn_end_after_continue``).
        if reason and not active_stop:
            with contextlib.suppress(Exception):
                record_hook_diagnostic(reason, "Stop", _state=_state)


def _standing_advice_carry(
    store: LocalObservationStore,
    *,
    event: str,
    native_host: bool,
    stop_note: bool,
    delivery_eligible: bool,
    workspace_commitment: str,
    yoetz_session_id: str | None,
    session_commitment: str,
    _state: Path | None,
) -> bool:
    """Bridge standing advice a Stop withheld to the next PostToolUse (#985). Never raises.

    At a Codex or Claude Code Stop that finds standing advice pending, mark the session; the
    first later advice-eligible PostToolUse may then carry standing advice (returns True). The
    caller clears the mark once that advice is delivered or nothing is pending. Cursor never
    delivered advice at stop, so its cadence is unchanged.
    """

    if not native_host:
        return False
    try:
        if event == "Stop" and stop_note:
            pending = store.peek_advice_for_delivery(
                workspace_commitment,
                yoetz_session_id=yoetz_session_id,
                allow_standing=True,
                session_commitment=session_commitment,
            )
            if pending is not None:
                set_standing_advice_withheld(session_commitment, True, _state=_state)
            return False
        if event == "PostToolUse" and delivery_eligible:
            return standing_advice_withheld(session_commitment, _state=_state)
    except Exception:
        return False
    return False


def _record_closure_gate_emitted(
    yoetz_session_id: str,
    closure_gate: ClosureGate,
    event: str,
    *,
    active_stop: bool,
    _state: Path | None,
) -> None:
    """Record the diagnostics and memory of a closure gate the host received. Never raises."""

    with contextlib.suppress(BaseException):
        # An active-Stop re-check was remembered before it was written.
        if not active_stop and not record_closure_gate_delivered(
            yoetz_session_id,
            closure_gate.identity,
            blocker_keys=closure_gate.blocker_keys,
            _state=_state,
        ):
            # Visible, never fatal: the host loop guard still bounds a repeat.
            record_hook_diagnostic("closure_gate_memory_unwritten", event, _state=_state)
        record_hook_diagnostic("closure_gate_continued", event, _state=_state)
        if BLOCKER_RECHECK_ITEM in closure_gate.items:
            record_hook_diagnostic("closure_gate_blocker_rechecked", event, _state=_state)
        if ACCEPTANCE_RECHECK_ITEM in closure_gate.items:
            record_hook_diagnostic("closure_gate_acceptance_rechecked", event, _state=_state)
        if active_stop:
            record_hook_diagnostic("closure_gate_active_stop_rechecked", event, _state=_state)


def _session_start_context(
    additional: str,
    payload: Mapping[str, JsonValue],
    *,
    include_admission_notice: bool,
    harness_id: str,
    workspace_locator: str | None,
    connect: ServiceConnector | None,
    resolve_runner: Callable[[], AsyncRunner],
    deadline: float,
    skip_service: bool,
    monotonic: Callable[[], float],
    _state: Path | None,
) -> str:
    """Append the cached release recommendation and the admission notice at SessionStart.

    Existing task/receipt advice keeps its place first on this shared context channel; the
    recommendation follows it only when both fit the bound (#819).
    """

    with contextlib.suppress(Exception):
        recommendation = _cached_recommendation_context(_state=_state)
        if recommendation and not additional:
            additional = recommendation
        elif recommendation and len(additional) + 1 + len(recommendation) <= _MAX_ADVICE_CONTEXT:
            additional = f"{additional} {recommendation}"
    if include_admission_notice and _session_start_source(payload) != "clear":
        from finishup.cli.host_hold_advisory import PrivacyConnector
        from finishup.cli.host_startup_advisory import append_admission_notice

        additional = append_admission_notice(
            additional,
            harness_id,
            workspace_locator,
            connect=None if connect is None else cast(PrivacyConnector, connect),
            run_async=resolve_runner(),
            deadline=deadline,
            max_chars=_MAX_ADVICE_CONTEXT,
            skip_service=skip_service,
            monotonic=monotonic,
        )
    return additional


def _commit_emitted_advice(
    store: LocalObservationStore,
    workspace_commitment: str,
    pending_delivery: AdviceDelivery,
    *,
    yoetz_session_id: str | None,
    session_commitment: str,
    event: str,
    standing_carry: bool,
    _state: Path | None,
) -> None:
    """Commit advice the host received. Nothing here may raise past the emission."""

    with contextlib.suppress(BaseException):
        store.commit_advice_delivery(
            workspace_commitment,
            pending_delivery.delivery_identity,
            yoetz_session_id=yoetz_session_id,
            session_commitment=session_commitment,
        )
        if event == "SessionStart":
            set_standing_advice_withheld(session_commitment, False, _state=_state)
        elif (
            standing_carry
            and pending_delivery.item is not None
            and pending_delivery.item.recommended_next_action in _STANDING_MACHINE_ACTIONS
        ):
            # Clear the carry only when the standing advice itself went out: when ordinary
            # advice outranked it on this PostToolUse, the next one carries it (a single-turn
            # Codex exec has no later SessionStart).
            set_standing_advice_withheld(session_commitment, False, _state=_state)


def _retry_auto_attach(
    codex_session_id: str,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    harness_id: Literal["claude", "codex", "cursor"],
    workspace_locator: str | None,
    connect: ServiceConnector | None,
    resolve_runner: Callable[[], AsyncRunner],
    event: str,
    session_lock_owned: bool,
    _state: Path | None,
) -> LifecycleMapping | None:
    """Re-attempt auto-attach for a session that started while the service was unreachable.

    One missed SessionStart no longer costs the session's whole record (#275). Bounded; the
    caller runs it before the drain so a fresh mapping delivers this session's backlog in the
    same pass.
    """

    mapping: LifecycleMapping | None = None
    retry_session_lock = (
        contextlib.nullcontext(True)
        if session_lock_owned
        else acquire_session_lock(codex_session_id, _state=_state)
    )
    with retry_session_lock as owned:
        if owned:
            mapping = load_mapping(codex_session_id, _state=_state)
            if mapping is None:

                async def _attach_retry() -> AutoAttachOutcome:
                    import asyncio

                    attach = _try_workspace_auto_start(
                        codex_session_id,
                        store=store,
                        workspace_commitment=workspace_commitment,
                        _state=_state,
                        harness_id=harness_id,
                        workspace_locator=workspace_locator,
                        connect=cast(HookStartConnector | None, connect),
                        _session_lock_owned=True,
                        service_start_timeout_seconds=(
                            _AUTO_ATTACH_RETRY_SERVICE_START_BUDGET_SECONDS
                        ),
                    )
                    return await asyncio.wait_for(
                        attach,
                        timeout=_AUTO_ATTACH_RETRY_BUDGET_SECONDS,
                    )

                try:
                    outcome = cast(AutoAttachOutcome, resolve_runner()(_attach_retry))
                except TimeoutError:
                    outcome = AutoAttachOutcome(None, "timeout")
                except Exception:
                    outcome = AutoAttachOutcome(None, "service_unavailable")
                mapping = _record_auto_attach(outcome, event, _state=_state)
                if mapping is None:
                    # The retry marker names the path; the typed reason above names the cause.
                    record_hook_diagnostic("auto_attach_retry_failed", event, _state=_state)
    return mapping


@dataclass(frozen=True, slots=True)
class _SessionStartAttach:
    """What the SessionStart attach/status step leaves for the rest of the pass."""

    mapping: LifecycleMapping | None
    pending_mapping_deferred: bool
    additional: str
    attach_advisory_only: bool
    # The bounded post-compaction recap (ADR-044), kept apart from ``additional`` so the
    # admission notice and release recommendation are composed against their own bound first.
    recap: str = ""


def _session_start_attach(
    codex_session_id: str,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    workspace_locator: str | None,
    harness_id: Literal["claude", "codex", "cursor"],
    payload: Mapping[str, JsonValue],
    connect: ServiceConnector | None,
    resolve_runner: Callable[[], AsyncRunner],
    event: str,
    mapping: LifecycleMapping | None,
    pending_mapping_deferred: bool,
    skip_service: bool,
    skip_advice_loop: bool,
    session_lock_owned: bool,
    _state: Path | None,
    recap: bool = False,
    recap_time_left: Callable[[], float] | None = None,
) -> _SessionStartAttach:
    """Recover, auto-attach or status-read a non-clear SessionStart's mapping.

    Under the session lifecycle lock: recover a pending start, auto-attach an unmapped
    session, or read a mapped session's status, and compose the startup context.
    """

    # SessionStart-only status/attach helpers: they drag protocol.models
    # and service.client, which no other event needs (#242).
    from finishup.cli.hooks import (
        _LOCKED_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _PRIVACY_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _RETRY_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _STARTUP_RECOVERY_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _STORAGE_CORRUPT_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _STORAGE_UNSAFE_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _UNAVAILABLE_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _WORKSPACE_MISMATCH_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        _WORKSPACE_UNBOUND_CONTEXT,  # pyright: ignore[reportPrivateUsage]
        SessionWorkspace,
        StatusOutcome,
        _active_context,  # pyright: ignore[reportPrivateUsage]
        _read_status,  # pyright: ignore[reportPrivateUsage]
        _stale_mapping_context,  # pyright: ignore[reportPrivateUsage]
        bound_connector,
        resolve_session_workspace,
    )

    additional = ""
    recap_text = ""
    attach_reason: str | None = None
    attach_advisory_only = False
    session_lifecycle_lock = (
        contextlib.nullcontext(True)
        if session_lock_owned
        else acquire_session_lock(codex_session_id, _state=_state)
    )
    with session_lifecycle_lock as owned:
        if owned:
            from finishup.cli.hooks import recover_pending_start_mapping

            pending_mapping_deferred = (
                pending_mapping_deferred
                or recover_pending_start_mapping(
                    codex_session_id,
                    _state=_state,
                    _session_lock_owned=True,
                ).pending
            )
            mapping = load_mapping(codex_session_id, _state=_state)
            if not pending_mapping_deferred and mapping is None and not skip_advice_loop:
                if not skip_service:

                    async def _attach() -> AutoAttachOutcome:
                        return await _try_workspace_auto_start(
                            codex_session_id,
                            store=store,
                            workspace_commitment=workspace_commitment,
                            _state=_state,
                            harness_id=harness_id,
                            workspace_locator=workspace_locator,
                            connect=cast(HookStartConnector | None, connect),
                            prune_surplus=True,
                            _session_lock_owned=True,
                        )

                    attach_outcome = cast(AutoAttachOutcome, resolve_runner()(_attach))
                    attach_reason = attach_outcome.reason
                    mapping = _record_auto_attach(
                        attach_outcome,
                        event,
                        _state=_state,
                    )
                if mapping is None:
                    # Static advisory for the unattached binding: it needs no
                    # service, so local-only mode still emits it (issue #280).
                    additional = (
                        "FinishUP observation is consented for this workspace; "
                        "no ledger task is mapped yet (observation-derived binding "
                        "only). After guidance reads, tool/schema discovery, and "
                        "necessary bootstrap clarification, call start to attach a task "
                        "before substantive material work. " + _STARTUP_RECOVERY_CONTEXT
                    )
                    if attach_reason is not None:
                        additional = _attachment_recovery_context(attach_reason) + additional
                    attach_advisory_only = True
                else:
                    additional = _active_context(mapping, mapping.last_frontier)
            elif mapping is not None and not skip_service and not pending_mapping_deferred:
                active_mapping = mapping
                # The consented locator when this hook named one. The legacy
                # bound-session lane recovers a commitment by session id and
                # leaves the locator unset, which probed the daemon bare and
                # was refused as `repository_identity_required` (issue #659);
                # derive the probe's locator from the host payload's cwd or the
                # hook cwd instead. The daemon still fences it against the
                # mapped task's route, so a wrong guess is a typed mismatch,
                # never access to another repository.
                selection = (
                    SessionWorkspace(workspace_locator, "explicit")
                    if workspace_locator is not None
                    else resolve_session_workspace(None, payload)
                )
                status_locator = selection.locator

                async def _status() -> StatusOutcome:
                    # The read carries the consented locator exactly as the
                    # auto-attach `start` does, so the daemon's repository
                    # fence admits a live mapping (issue #578). The
                    # module-level connector override stays honoured.
                    connector = (
                        connect
                        if connect is not None
                        else bound_connector(
                            cast(Callable[..., Awaitable[object]], _connect_service()),
                            status_locator,
                        )
                    )
                    return await _read_status(
                        active_mapping,
                        connect=connector,
                        # Frozen legacy identifier (ADR-048): a recorded actor id.
                        actor_id=f"yoetz:{harness_id}-hooks",
                        recap=recap,
                        recap_time_left=recap_time_left,
                    )

                # The rows pending when the facts are read are the ones those facts cannot
                # include, even if the sweeper acknowledges them before the output (ADR-044).
                pending_before = (
                    _pending_work_rows(store, workspace_commitment, codex_session_id)
                    if recap
                    else None
                )
                outcome = cast(StatusOutcome, resolve_runner()(_status))
                kind, updated = outcome.kind, outcome.mapping
                if kind == "active" and updated is not None:
                    store_mapping(updated, _state=_state)
                    mapping = updated
                    additional = _active_context(updated, updated.last_frontier)
                    if outcome.recap is not None:
                        recap_text = _compaction_recap_text(outcome.recap, pending_before)
                elif kind == "stale":
                    # The service answered: only the stored mapping is stale
                    # (re-started elsewhere). Repair flows through the agent's
                    # own start via handle_post_tool_use; meanwhile the static
                    # advisory must not starve pending advice (issue #308).
                    additional = _stale_mapping_context(mapping, outcome.replacement)
                    attach_advisory_only = True
                    with contextlib.suppress(Exception):
                        record_hook_diagnostic("mapping_stale", event, _state=_state)
                elif kind in {"workspace_unbound", "workspace_mismatch"}:
                    # The daemon refused to bind the read to a repository. The
                    # mapping is live and kept; this is never `mapping_stale`
                    # and never a re-attach instruction (issue #578).
                    additional = (
                        _WORKSPACE_UNBOUND_CONTEXT
                        if kind == "workspace_unbound"
                        else _WORKSPACE_MISMATCH_CONTEXT
                    )
                    attach_advisory_only = True
                    with contextlib.suppress(Exception):
                        record_hook_diagnostic(f"status_{kind}", event, _state=_state)
                        record_hook_diagnostic(selection.diagnostic_reason, event, _state=_state)
                elif kind == "locked":
                    additional = _LOCKED_CONTEXT
                elif kind == "retry":
                    additional = _RETRY_CONTEXT
                elif kind == "privacy":
                    additional = _PRIVACY_CONTEXT
                elif kind in {"storage_unsafe", "storage_corrupt"}:
                    # Opposite retry advice, so never the shared
                    # "unavailable" text (#338); the same token
                    # lands in hook diagnostics for `observe status`.
                    additional = (
                        _STORAGE_UNSAFE_CONTEXT
                        if kind == "storage_unsafe"
                        else _STORAGE_CORRUPT_CONTEXT
                    )
                    with contextlib.suppress(Exception):
                        record_hook_diagnostic(kind, event, _state=_state)
                else:
                    additional = _UNAVAILABLE_CONTEXT
    return _SessionStartAttach(
        mapping=mapping,
        pending_mapping_deferred=pending_mapping_deferred,
        additional=additional,
        attach_advisory_only=attach_advisory_only,
        recap=recap_text,
    )


def _pending_work_rows(
    store: LocalObservationStore, workspace_commitment: str, codex_session_id: str
) -> int | None:
    """This session's undelivered local rows that would add ledger work, or ``None``."""

    try:
        from finishup.cli.compaction_recap import pending_work_rows

        return pending_work_rows(store, workspace_commitment, codex_session_id)
    except Exception:
        return None


def _compaction_recap_text(facts: RecapFacts, pending_rows: int | None) -> str:
    """Render the post-compaction recap (ADR-044); an unrenderable recap is no recap."""

    try:
        from finishup.cli.compaction_recap import compact_recap_text

        return compact_recap_text(facts, pending_rows=pending_rows)
    except Exception:
        return ""


def _workspace_fingerprint_hook_pass(
    resolved_event: str,
    payload: Mapping[str, JsonValue],
    *,
    source: ObservationSource,
    host_session_id: str,
    live_locator: str | None,
    explicit: tuple[str | None, str | None],
    workspace_commitment: str,
    store: LocalObservationStore,
    stages: dict[str, int],
    monotonic: Callable[[], float],
    entry_started: float,
    content_payload: Mapping[str, JsonValue] | None,
    _state: Path | None,
) -> WorkspaceEffectReading | None:
    """This live hook pass's half of the before/after workspace fingerprint (PR #1080).

    ``PreToolUse`` stores the snapshot and returns ``None``; ``PostToolUse`` returns the reading
    its envelope carries. Only a fingerprinted tool in a live pass with an explicit locator takes
    part; an unavailable comparison leaves a ``workspace_fingerprint_<reason>`` diagnostic.
    """

    tool = payload.get("tool_name")
    workspace, replayed_commitment = explicit
    if (
        resolved_event not in {"PreToolUse", "PostToolUse"}
        or live_locator is None
        or workspace is None
        or replayed_commitment is not None
        or not fingerprinted_tool(tool, finishup_owned=finishup_mcp_tool(tool))
    ):
        return None
    started = monotonic()
    reading: WorkspaceEffectReading | None = None
    with contextlib.suppress(Exception):
        _pairing_mode, correlation_kind = _pairing_contract(payload, source)
        call = _pairing_correlation(payload, correlation_kind=correlation_kind)
        outcome_facts = dict(payload)
        # Claude Code and Cursor pass a structural payload; their tool input (the command text
        # a background launch is read from) travels beside it in the content payload.
        if "tool_input" not in outcome_facts and content_payload is not None:
            tool_input = content_payload.get("tool_input")
            if tool_input is not None:
                outcome_facts["tool_input"] = tool_input
        if source is ObservationSource.CODEX_HOOK and resolved_event == "PostToolUse":
            _merge_outcome_facts(outcome_facts, _codex_post_tool_outcome(payload))
        reading = workspace_fingerprint_pass(
            resolved_event,
            call_identity=None
            if call is None
            else f"{source.value}\x00{host_session_id}\x00{call}",
            workspace_locator=live_locator,
            workspace_commitment=workspace_commitment,
            key_material=store.key_material(),
            observation_root=observation_dir(_state=_state),
            complete=host_call_complete(cast(Mapping[str, DomainJsonValue], outcome_facts)),
            # FinishUP's own state (this pass's, too) changes on every hook pass.
            excluded=owned_relative_paths(
                live_locator,
                (*finishup_owned_roots(), *(() if _state is None else (str(_state),))),
            ),
            # A pre-call snapshot must finish while the host is still waiting for this pass.
            host_deadline=time.monotonic()
            + (
                entry_started
                + _hook_host_window_seconds(source, resolved_event)
                - _FINGERPRINT_HOST_MARGIN_SECONDS
                - monotonic()
            ),
        )
    if resolved_event == "PostToolUse" and reading is None:
        reading = WorkspaceEffectReading("unavailable", "store_unusable")
    if reading is not None and reading.fresh and reading.reason in _FINGERPRINT_DIAGNOSED:
        # A degraded comparison is named once in ``observe status``. A call without a pre-call
        # snapshot or still running is an ordinary per-call fact the result already carries,
        # so it never evicts real failures from the bounded diagnostic window.
        with contextlib.suppress(Exception):
            record_hook_diagnostic(
                f"workspace_fingerprint_{reading.reason}", resolved_event, _state=_state
            )
    stages["fingerprint"] = _elapsed_ms(started, monotonic())
    # The pre-call half only stores its snapshot; nothing crosses the envelope.
    return None if resolved_event == "PreToolUse" else reading


def _classify_after_fingerprint(
    payload: Mapping[str, JsonValue], event: str, reading: WorkspaceEffectReading | None
) -> ObservationClassification:
    """Classify one observation; a read-shaped shell call joins a routine-read summary only when
    its fingerprint saw the workspace unchanged, otherwise it is recorded on its own with its
    fact (PR #1080)."""

    classification = classify_observation(payload, event)
    if reading is None or reading.effect == WORKSPACE_UNCHANGED:
        return classification
    return without_routine_read(classification)


def handle_observe(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    _entry_monotonic: float | None = None,
    _monotonic: Callable[[], float] = time.monotonic,
    _workspace_commitment: str | None = None,
    source: ObservationSource = ObservationSource.CODEX_HOOK,
    _output_event_name: str | None = None,
    _session_lock_owned: bool = False,
    _routing_session_id: str | None = None,
    _child_attribution_gap: bool = False,
    _content_capture_profile: str | None = None,
    _content_payload: Mapping[str, JsonValue] | None = None,
    _ingress_gap: str | None = None,
    _include_admission_notice: bool = True,
    _include_recap: bool = True,
    _pass_timing: HookPassTiming | None = None,
    _derived_runner_class: RunnerClass | None = None,
    _stop_final_message: str | None = None,
    _request_commitment: str | None = None,
    _proven_finishup_read: bool = False,
) -> int:
    """Bounded observation ingress for Codex lifecycle hooks. Always exits 0.

    ``skip_service`` keeps the hook fully local: capture, binding, and outbox
    enqueue still run, but no service connection is ever opened (auto-attach,
    mapped-session status, and outbox drains are all skipped). Advisory output
    that needs no service still runs — an unattached SessionStart binding emits
    the static "call start to attach a task" context either way (issue #280).

    ``_entry_monotonic`` is the console shim's pre-import sample; without it the
    recorded import stage reads zero rather than guessing.

    ``_pass_timing`` is the host entry's timing sample (#915). This pass only reports how far it
    got; the entry that owns the sample records it, so nested callers and the service's spool
    replay never count as a host hook pass.
    """

    entry_started = _monotonic() if _entry_monotonic is None else _entry_monotonic
    stages: dict[str, int] = {}

    # Native content is carried only in this process. Reserve the workspace
    # drain before entering the local store batch so a background sweeper cannot
    # consume the newly enqueued structural row while the foreground hook is
    # still preparing its transient chunks. The lease is deliberately entered
    # manually: the batch and the later service pass live in separate scopes,
    # while the outer finally must still release it on every early return or
    # cancellation.
    native_drain_lease: contextlib.AbstractContextManager[bool] | None = None
    native_drain_lease_entered = False
    native_drain_lease_owned = False

    def _release_native_drain_lease() -> None:
        nonlocal native_drain_lease, native_drain_lease_entered, native_drain_lease_owned
        if not native_drain_lease_entered or native_drain_lease is None:
            return
        lease = native_drain_lease
        native_drain_lease = None
        native_drain_lease_entered = False
        native_drain_lease_owned = False
        with contextlib.suppress(BaseException):
            lease.__exit__(None, None, None)

    # True from a SessionEnd's local end until its capture batch commits. The
    # end is saved with that batch, so a failed batch loses it (#843).
    session_end_uncommitted = False
    # True once the capture batch commits; a later lock timeout then only cost
    # follow-up work, never the input itself.
    capture_committed = False
    lock_context = contextlib.ExitStack()
    try:
        # Attribute this pass's store-lock events to a hook and record them in
        # hook diagnostics, then bound every lock wait in the pass by one
        # deadline measured from process entry (#689).
        lock_event_name = event_name or "observe"

        def _record_lock_event(lock_event: ObservationStoreLockEvent) -> None:
            record_store_lock_event(lock_event_name, lock_event, _state=_state)

        lock_budget = _HOOK_STORE_LOCK_BUDGET_BY_WINDOW[
            _hook_host_window_seconds(source, event_name)
        ]
        lock_context.enter_context(
            observation_store_lock_scope(role="hook", reporter=_record_lock_event)
        )
        lock_context.enter_context(
            observation_store_lock_deadline(
                time.monotonic() + max(0.0, lock_budget - (_monotonic() - entry_started))
            )
        )
        if source is ObservationSource.CODEX_HOOK:
            # Cold imports are pure preparation. Importing this runtime inside
            # the ingress batch serialized every new Codex process behind it.
            from importlib import import_module

            import_module("finishup.adapters.integrations.codex_session_stream")

        store = LocalObservationStore(_state=_state)
        resolve_started = _monotonic()
        stages["import"] = _elapsed_ms(entry_started, resolve_started)
        raw_stdout_json = hook_io.stdout_json

        def _resolve_runner() -> AsyncRunner:
            """Resolve the async runner only on a branch that opens a connection."""

            if run_async is not None:
                return run_async
            import anyio

            return cast(AsyncRunner, anyio.run)

        def _stdout_json(value: JsonValue, stream: BinaryIO | None = None) -> bool:
            """Emit one JSON object; report whether the bytes actually left."""

            emitted = raw_stdout_json(value, stream)
            if not emitted:
                with contextlib.suppress(BaseException):
                    record_hook_diagnostic(
                        "stdout_write_failed", event_name or "unknown_event", _state=_state
                    )
            if stream is None and sys.stdout is sys.__stdout__:
                with contextlib.suppress(BaseException):
                    sys.stdout.flush()
                    sys.stdout.close()
            return emitted

        # Assigned only by the Stop-time closure gate below (#977); every earlier render sees None.
        closure_gate: ClosureGate | None = None

        def _render_context(
            additional_context: str, *, limit: int | None = None
        ) -> dict[str, JsonValue]:
            """Render advice in the receiving host's own stdout contract.

            Cursor keeps its raw event name; Claude Code gets its documented
            non-error Stop feedback instead of Codex's `decision: block`. ``limit`` is the larger
            character bound only the post-compaction recap is designed against (ADR-044).
            """

            if source is ObservationSource.CURSOR_HOOK:
                raw_cursor_event = _output_event_name
                if raw_cursor_event is None:
                    return {}
                if closure_gate is not None and raw_cursor_event == "stop":
                    # The closure gate is the one Stop text Cursor may auto-submit (#977).
                    return _cursor_context_output(
                        raw_cursor_event, additional_context, allow_stop_followup=True
                    )
                if limit is not None:
                    return _cursor_context_output(raw_cursor_event, additional_context, limit=limit)
                return _cursor_context_output(raw_cursor_event, additional_context)
            if source is ObservationSource.CLAUDE_HOOK:
                # Claude requires hookSpecificOutput.hookEventName to name the
                # event that actually fired. PostToolUseFailure is normalized to
                # PostToolUse for FinishUP's internal observation/advice cadence, so
                # render with the preserved host event instead (#435).
                if limit is not None:
                    return _claude_context_output(
                        _output_event_name or resolved_event, additional_context, limit=limit
                    )
                return _claude_context_output(
                    _output_event_name or resolved_event, additional_context
                )
            if limit is not None:
                return _context_output(resolved_event, additional_context, limit=limit)
            return _context_output(resolved_event, additional_context)

        content_omitted = False
        try:
            if source is ObservationSource.CODEX_HOOK:
                # Codex is the one host whose raw body reaches this reader; the
                # Claude Code and Cursor adapters skim their own raw body and
                # hand this pass an already-reduced structural object.
                payload, content_omitted = read_hook_ingress(stdin_bytes)
            else:
                payload = read_hook_payload(stdin_bytes)
        except OversizedHookPayloadError:
            # A complete body inside the skim cap that failed its safety
            # checks yields nothing to keep; it is the same size loss.
            note_payload_too_large(
                event_name or "observe", source=source, workspace=workspace, _state=_state
            )
            _stdout_json({}, stdout)
            return 0
        except ProtocolValueError as exc:
            if exc.reason_code != "payload_too_large":
                raise
            # An oversized host body is a coverage loss for exactly this event,
            # not an unexplained hook fault. Letting it fall through to the
            # outer handler recorded the bare `observe` reason, which named
            # neither the cause nor the affected event (issue #667).
            note_payload_too_large(
                event_name or "observe", source=source, workspace=workspace, _state=_state
            )
            _stdout_json({}, stdout)
            return 0
        if content_omitted:
            # Above the trusted cap the event keeps its structural row (and so
            # its pairing) instead of being lost; only its content is gone
            # (tb4n1 B5). The gap also keeps content capture off for this row.
            oversized_event = (
                event_name or _token_or_none(payload.get("hook_event_name")) or "observe"
            )
            _ingress_gap = _oversized_ingress_gap(
                payload, source=source, event=oversized_event, _state=_state
            )
        harness_id: Literal["claude", "codex", "cursor"] = (
            "claude"
            if source is ObservationSource.CLAUDE_HOOK
            else "cursor"
            if source is ObservationSource.CURSOR_HOOK
            else "codex"
        )
        raw_event = event_name or payload.get("hook_event_name")
        if type(raw_event) is not str or not raw_event:
            _stdout_json({}, stdout)
            return 0
        resolved_event = raw_event
        if source is ObservationSource.CODEX_HOOK:
            # A v2 delegated child's callbacks carry the root session; its own transcript is
            # the host fact that names the child (#841). Resolve it before any lane decision.
            from finishup.cli.hooks import with_transcript_child_identity

            identity_conflict: str | None = None
            with contextlib.suppress(Exception):
                payload, identity_conflict = with_transcript_child_identity(
                    payload, event_name=resolved_event
                )
            if identity_conflict is not None:
                with contextlib.suppress(Exception):
                    record_hook_diagnostic(identity_conflict, resolved_event, _state=_state)
        mapping_lifecycle_deferred = False
        # ``clear`` is a host lifecycle command, not an observation consent
        # decision. Apply or queue its mapping operation before the runtime
        # gate and workspace consent checks so a busy/disabled hook cannot
        # leave the integration route stale.
        if resolved_event == "SessionStart" and _session_start_source(payload) == "clear":
            try:
                clear_session_id = validate_codex_session_id(payload.get("session_id"))
                clear_lock = (
                    contextlib.nullcontext(True)
                    if _session_lock_owned
                    else acquire_session_lock(clear_session_id, _state=_state)
                )
                with clear_lock as clear_owned:
                    if clear_owned:
                        # Make this clear the durable latest intent before
                        # replaying any interrupted predecessor. A concurrent
                        # loser may have queued an older store while this lock
                        # owner was recovering; the queue write coalesces it.
                        queue_mapping_clear(clear_session_id, _state=_state)
                        from finishup.cli.hooks import recover_pending_start_mapping

                        recovery = recover_pending_start_mapping(
                            clear_session_id,
                            _state=_state,
                            _session_lock_owned=True,
                        )
                        if recovery.pending:
                            mapping_lifecycle_deferred = True
                    else:
                        queue_mapping_clear(clear_session_id, _state=_state)
                        mapping_lifecycle_deferred = True
            except Exception:
                mapping_lifecycle_deferred = True
                pass
        capture_authority_known = True
        try:
            capture_enabled = store.runtime_enabled()
        except TimeoutError:
            # Retain structural activity on contention, but unknown runtime
            # authority must never permit extracting or forwarding plaintext.
            capture_authority_known = False
            _stderr_line("hook_observe_degraded: runtime_gate_contended")
            record_hook_diagnostic("runtime_gate_contended", resolved_event, _state=_state)
            capture_enabled = True
        except Exception:
            _stderr_line("hook_observe_degraded: runtime_gate_unsafe")
            record_hook_diagnostic("runtime_gate_unsafe", resolved_event, _state=_state)
            with contextlib.suppress(Exception):
                _note_dropped_event_gap(store, payload, workspace)
            _stdout_json({}, stdout)
            return 0
        if not capture_enabled:
            # The READY generation synchronized an explicit disabled config.
            # Stop before session binding, ordinals, capture, or outbox enqueue.
            if resolved_event == "SessionStart":
                additional = ""
                with contextlib.suppress(Exception):
                    additional = _cached_recommendation_context(_state=_state)
                _stdout_json(_render_context(additional) if additional else {}, stdout)
            else:
                _stdout_json({}, stdout)
            return 0
        session_raw = payload.get("session_id")
        try:
            codex_session_id = validate_codex_session_id(session_raw)
        except ProtocolValueError:
            _stderr_line("hook_observe_degraded: invalid_session")
            record_hook_diagnostic("invalid_session", resolved_event, _state=_state)
            _stdout_json({}, stdout)
            return 0
        host_session_id = codex_session_id
        lane = _resolve_observation_lane(
            payload,
            event_name=resolved_event,
            source=source,
            _state=_state,
            explicit_session_id=_routing_session_id,
            explicit_attribution_gap=_child_attribution_gap,
        )
        codex_session_id = lane.effective_session_id
        child_attribution_gap = lane.attribution_gap

        workspace_commitment: str | None = None
        workspace_locator: str | None = None
        # Why a pass that ingests nothing ingested nothing. Every host ingress
        # shares this branch, so the reason is host-agnostic (#420/#435): an
        # explicit locator that cannot be canonicalized (`--workspace ""` from
        # an unset CLAUDE_PROJECT_DIR, a missing or symlinked path), a canonical
        # locator without consent, or a deliberately paused one. Without a
        # payload-free row here, `observe status` cannot tell a hook that fired
        # and was dropped from one that never fired.
        binding_diagnostic: str | None = None
        if _workspace_commitment is not None:
            workspace_commitment = _workspace_commitment
        elif workspace is not None:
            try:
                # Cursor already passed through the bounded host resolver. All
                # other hook sources use the same explicit-path canonicalizer
                # as consent/control so a Git subdirectory cannot acquire a
                # second commitment identity.
                workspace_locator = (
                    workspace
                    if source is ObservationSource.CURSOR_HOOK
                    else canonical_workspace_locator(workspace)
                )
            except Exception:
                workspace_locator = None
            if workspace_locator is None:
                binding_diagnostic = "workspace_unresolvable"
            else:
                try:
                    workspace_commitment = store.workspace_commitment(workspace_locator)
                except ObservationStoreLockTimeout:
                    # Contention while creating the key is not a missing consent.
                    raise
                except Exception:
                    workspace_commitment = None
                    workspace_locator = None
        if workspace_commitment is None and workspace is None:
            # A hook without an explicit locator may retain the legacy bound-session/single-active
            # lane. An explicit locator that failed canonical consent never falls back to a
            # different commitment, including a legacy exact-subdirectory grant.
            workspace_commitment = store.find_workspace_for_codex_session(host_session_id)
            workspace_locator = None
        consent = None if workspace_commitment is None else store.consent_for(workspace_commitment)
        if consent is None or not consent.active:
            # Consent missing/paused/revoked: no ingest, no spool; still exit 0,
            # but leave the typed, payload-free trace.
            if binding_diagnostic is None:
                binding_diagnostic = _consent_binding_diagnostic(consent)
            with contextlib.suppress(Exception):
                record_hook_diagnostic(binding_diagnostic, resolved_event, _state=_state)
            # Update advice consumes only the precomputed cache, independently of observation
            # consent. Never ingest or spool this event on the no-consent path.
            additional = ""
            if resolved_event == "SessionStart" and (
                source is not ObservationSource.CURSOR_HOOK or _output_event_name == "sessionStart"
            ):
                with contextlib.suppress(Exception):
                    additional = _cached_recommendation_context(_state=_state)
            _stdout_json(_render_context(additional) if additional else {}, stdout)
            return 0

        assert workspace_commitment is not None
        # A SessionEnd must either mark the bound session ended or leave a
        # durable deferred intent. Keep this set until the capture batch
        # commits so failures before either lifecycle path are named too.
        if resolved_event == "SessionEnd":
            session_end_uncommitted = True
        # PR #1080: a before/after workspace fingerprint decides whether a call changed the
        # workspace; the command's text never does. It runs here, before the store lock, and
        # only in a live host pass with an explicit locator (replays carry no locator).
        workspace_reading = _workspace_fingerprint_hook_pass(
            resolved_event,
            payload,
            source=source,
            host_session_id=host_session_id,
            live_locator=workspace_locator,
            explicit=(workspace, _workspace_commitment),
            workspace_commitment=workspace_commitment,
            store=store,
            stages=stages,
            monotonic=_monotonic,
            entry_started=entry_started,
            content_payload=_content_payload,
            _state=_state,
        )
        native_content_reservation = (
            not skip_service
            and capture_authority_known
            and (
                (source is ObservationSource.CODEX_HOOK and _content_capture_profile is None)
                or (
                    source
                    in {
                        ObservationSource.CLAUDE_HOOK,
                        ObservationSource.CURSOR_HOOK,
                    }
                    and _content_capture_profile is not None
                    and content_capture_profile_matches_source(
                        source.value, _content_capture_profile
                    )
                    and _content_capture_profile in consent.content_capture_profiles
                )
            )
        )
        if native_content_reservation:
            try:
                candidate_lease = store.drain_lease(workspace_commitment)
                candidate_owned = candidate_lease.__enter__()
            except Exception:
                # The reservation is an optimization for transient content;
                # if its lock file cannot be opened, retain the structural
                # event and let the normal drain path report any content gap.
                native_drain_lease = None
                native_drain_lease_entered = False
                native_drain_lease_owned = False
            else:
                native_drain_lease = candidate_lease
                native_drain_lease_entered = True
                native_drain_lease_owned = candidate_owned
        store_started = _monotonic()
        # Payload parse, runtime gate, workspace resolution and the consent
        # probe ran between 'import' and here, unwindowed. Three of those calls
        # take the store lock, so a contended pass spent real time in a region
        # no stage could name (#310/#311).
        stages["resolve"] = _elapsed_ms(resolve_started, store_started)
        # One flush for the whole local pass. The batch is closed before any
        # service RPC so an outbox acknowledgement can never become durable
        # ahead of the ingest it acknowledges, and it never spans a network
        # wait: it holds the interprocess store lock for its duration.
        #
        # Session membership creation shares the lifecycle lock with recovery.
        # An already-known binding is idempotent and may continue while another
        # pass owns that session's lock; if a new binding loses the nonblocking
        # lock, keep the event as an observation envelope and defer membership
        # creation rather than silently dropping a non-SessionStart hook.
        known_session_binding = codex_session_id in store.codex_sessions_for_workspace(
            workspace_commitment
        )
        binding_lock = _acquire_observe_membership_lock(
            store,
            workspace_commitment,
            codex_session_id,
            _state=_state,
            force=resolved_event in {"SessionStart", "SessionEnd"},
            session_lock_owned=_session_lock_owned,
        )
        with contextlib.ExitStack() as local_pass:
            deferred_lifecycle_recorded = True
            binding_owned = local_pass.enter_context(binding_lock)
            local_pass.enter_context(store.batched(workspace_commitment))
            if binding_owned:
                session_commitment = store.bind_codex_session(
                    workspace_commitment, codex_session_id
                )
            else:
                # Another handler is changing membership.  Use the stable
                # session commitment for local capture and let a later hook
                # bind it once the lifecycle lock is available.
                session_commitment = store.session_commitment(codex_session_id)
            if resolved_event == "SessionStart" and binding_owned:
                # A recovery attach holds the predecessor's lifecycle lock.
                # Gate generation restart on that same lock so a resumed
                # predecessor cannot clear its ended marker between
                # selection and attach.
                source_generation = store.begin_session_generation(
                    workspace_commitment, session_commitment
                )
            else:
                source_generation = store.effective_session_generation(
                    workspace_commitment, codex_session_id, session_commitment
                )
                lifecycle_start_applied = False
                if resolved_event in {"SessionStart", "SessionEnd"} and not binding_owned:
                    pending = store.list_pending_session_lifecycles(
                        workspace_commitment, codex_session_id
                    )
                    latest = pending[-1] if pending else None
                    clear_requested = _session_start_source(payload) == "clear"
                    if resolved_event == "SessionStart":
                        target_generation = source_generation
                        if latest is not None and latest.event_kind == "SessionEnd":
                            target_generation += 1
                        elif (
                            latest is not None
                            and latest.event_kind == "SessionStart"
                            and latest.clear_mapping == clear_requested
                        ):
                            target_generation = latest.target_generation
                        elif clear_requested and known_session_binding:
                            target_generation += 1
                        elif known_session_binding and store.codex_session_ended(
                            workspace_commitment, codex_session_id
                        ):
                            # The public generation accessor presents legacy
                            # pre-counter state as generation one. A deferred
                            # first resume must use the persisted zero so its
                            # eventual begin transition creates generation one
                            # rather than manufacturing generation two.
                            persisted_generation = store.persisted_session_generation(
                                workspace_commitment, session_commitment
                            )
                            target_generation = (
                                persisted_generation + 1 if persisted_generation > 0 else 1
                            )

                        if not lifecycle_start_applied:
                            source_generation = target_generation
                            deferred_lifecycle_recorded = store.record_pending_session_lifecycle(
                                workspace_commitment,
                                codex_session_id,
                                session_commitment,
                                "SessionStart",
                                target_generation,
                                clear_mapping=clear_requested,
                            )
                    else:
                        deferred_end_already_present = any(
                            intent.event_kind == "SessionEnd"
                            and intent.session_commitment == session_commitment
                            and intent.target_generation == source_generation
                            for intent in pending
                        )
                        deferred_lifecycle_recorded = store.record_pending_session_lifecycle(
                            workspace_commitment,
                            codex_session_id,
                            session_commitment,
                            "SessionEnd",
                            source_generation,
                        )
                        if not deferred_lifecycle_recorded:
                            # No retry carrier was accepted (the bounded
                            # pending-lifecycle queue is full). The hook can
                            # still retain its structural event, but the
                            # lifecycle end itself is not durable.
                            session_end_uncommitted = False
                            _report_session_end_unrecorded(resolved_event, _state=_state)
                        elif deferred_end_already_present:
                            # The exact retry intent was already durable before
                            # this pass; a later failure cannot lose it.
                            session_end_uncommitted = False
            gap_codes: list[str] = []
            if _ingress_gap is not None:
                gap_codes.append(_ingress_gap)
            if not deferred_lifecycle_recorded:
                gap_codes.append(ObservationGapCode.OUTBOX_OVERFLOW.value)
                store.note_session_coverage_gap(
                    workspace_commitment,
                    session_commitment,
                    ObservationGapCode.OUTBOX_OVERFLOW.value,
                )

            if child_attribution_gap:
                # The host supplied child lineage, but no validated child lane was available.
                # Retain the structural fact on the parent commitment while fencing it away from
                # the parent's service route, advice, and frontier delivery.
                gap_codes.append(ObservationGapCode.MAPPING_MISSING.value)
                store.note_session_coverage_gap(
                    workspace_commitment,
                    session_commitment,
                    ObservationGapCode.MAPPING_MISSING.value,
                )

            # Pairing is selected by the host/profile contract.  Post-only
            # profiles never consult the pre-event map; a generation id is a
            # conversation/turn identity and is never accepted as a tool id.
            pairing_mode, correlation_kind = _pairing_contract(payload, source)
            correlation = _pairing_correlation(
                payload,
                correlation_kind=correlation_kind,
            )

            if resolved_event not in SUPPORTED_HOOK_EVENTS:
                gap_codes.append(ObservationGapCode.UNSUPPORTED_EVENT.value)

            tool_name = _token_or_none(payload.get("tool_name"))
            # Every host spelling of a FinishUP-owned call must suppress the shared
            # advice loop.  The older Codex-only set missed Claude's plugin
            # scope and Cursor's server-qualified names, so those hosts could
            # receive frontier advice from the hook observing the same call.
            # This affects only advice delivery; explicit self-call failures
            # still follow ``self_observation_deliverable`` and remain queued.
            # A successful/unknown FinishUP call already has authoritative service-side evidence,
            # so its own hook must not lease the shared advice channel. An explicit failure is
            # new host evidence, however, and remains eligible to receive pending guidance. The
            # all-owned-tool guard previously suppressed that failure path as well.
            host_outcome = _native_outcome_facts(
                payload,
                force_failure=resolved_event == "PostToolUseFailure",
            )
            skip_advice_loop = (
                tool_name is not None
                and tool_name in FINISHUP_OWNED_TOOL_NAMES
                and host_outcome.success is not False
            )

            supplied_ordinal = _event_ordinal_from_payload(payload)
            event_ordinal = (
                supplied_ordinal
                if supplied_ordinal is not None
                else store.allocate_hook_ordinal(workspace_commitment, session_commitment)
            )

            classification_payload = dict(payload if _content_payload is None else _content_payload)
            # Native adapters have already extracted outcome facts from their
            # exact host contract. Keep those facts beside the original tool
            # input for conservative classification, without persisting prose.
            for outcome_key in ("success", "denied", "exit_status", "result_status"):
                if outcome_key in payload:
                    classification_payload[outcome_key] = payload[outcome_key]
            # Codex nests its outcome in ``tool_response``. Read it once, here, so selection and
            # the persisted envelope share one closed decision (#910).
            codex_outcome = (
                _codex_post_tool_outcome(payload)
                if source is ObservationSource.CODEX_HOOK and resolved_event == "PostToolUse"
                else None
            )
            if codex_outcome is not None:
                _merge_outcome_facts(classification_payload, codex_outcome)
            classification = _classify_after_fingerprint(
                classification_payload, resolved_event, workspace_reading
            )
            pressure = store.update_selection_pressure(workspace_commitment, session_commitment)
            selected_focused = pressure.effective_mode is ObservationMode.FOCUSED
            if pressure.transition is not None and pressure.transition.notice in {
                "downgrade",
                "recovery",
            }:
                _stderr_line(
                    "finishup_observation_detail: "
                    f"selected={pressure.selected_mode.value} effective={pressure.effective_mode.value} "
                    f"transition={pressure.transition.notice} pressure={pressure.dimension.value}"
                )
            # A protected event is a conservative workspace subject-state
            # boundary. Flush earlier accounts before its individual identity.
            material_boundary = not classification.routine_candidate
            try:
                flush_ok = store.flush_selected_admission(
                    workspace_commitment,
                    summary_builder=build_routine_read_summary,
                    # Stop is a turn boundary: flush buffered routine accounts so the
                    # Stop drain and the closure gate see this turn whole (tb4n1 B4/C6).
                    force=material_boundary
                    or resolved_event in {"SessionStart", "SessionEnd", "Stop"},
                    material_boundary=material_boundary,
                )
            except ProtocolValueError:
                # A refused routine-read summary now drains its own lane, so
                # this is a residual structural defect in the buffered account.
                # It must degrade this one hook with a bounded reason, never
                # reach the outer handler as the opaque `observe` token that
                # made a permanently wedged flush unreadable (issue #753).
                flush_ok = False
                _stderr_line(
                    "hook_observe_degraded: admission_flush_invalid; observation durability unknown"
                )
                record_hook_diagnostic("admission_flush_invalid", resolved_event, _state=_state)
            envelope = map_hook_payload_to_envelope(
                resolved_event,
                payload,
                session_commitment=session_commitment,
                event_ordinal=event_ordinal,
                key_material=store.key_material(),
                source_generation=source_generation,
                gap_codes=tuple(sorted(set(gap_codes), key=str.encode)),
                source=source,
                classification=classification,
                host_outcome=codex_outcome,
                workspace_reading=workspace_reading,
            )
            if _derived_runner_class is not None:
                envelope = replace(
                    envelope,
                    structural_payload=JsonObject(
                        {**envelope.structural_payload, "runner_class": _derived_runner_class}
                    ),
                )
            if resolved_event in {"PreToolUse", "PostToolUse"}:
                # Closed runtime facts (#977): install target, write scope, effective user.
                # Read from the host's own tool input in this process; only tokens persist.
                with contextlib.suppress(Exception):
                    tool_token = envelope.structural_payload.get("tool_name")
                    runtime_facts = runtime_structural_facts(
                        _content_payload if _content_payload is not None else payload,
                        tool_name=tool_token if type(tool_token) is str else None,
                        workspace_locator=workspace_locator,
                        inside=lambda value: (
                            workspace_relative_edit_path(value, workspace_locator) is not None
                        ),
                    )
                    if runtime_facts:
                        envelope = replace(
                            envelope,
                            structural_payload=JsonObject(
                                {**envelope.structural_payload, **runtime_facts}
                            ),
                        )
            if not selected_focused and envelope.structural_payload.get("action") == "routine_read":
                envelope = replace(
                    envelope,
                    structural_payload=JsonObject(
                        {**envelope.structural_payload, "action": "routine_read_detailed"}
                    ),
                )
            read_protected = classification.routine_candidate and store.read_is_protected(
                workspace_commitment, session_commitment, envelope
            )
            if read_protected:
                reference = store.read_protection_reference(
                    workspace_commitment, session_commitment, envelope
                )
                protected_fields: dict[str, DomainJsonValue] = {
                    **envelope.structural_payload,
                    "action": "evidence_linked_read",
                }
                if reference is not None:
                    protected_fields["protection_reference"] = reference
                envelope = replace(envelope, structural_payload=JsonObject(protected_fields))
            route = load_mapping(codex_session_id, _state=_state)
            authority = store.content_capture_authority(workspace_commitment)
            selection_fence = ""
            if route is not None and authority is not None and authority.active:
                envelope = replace(
                    envelope,
                    structural_payload=JsonObject(
                        {
                            **envelope.structural_payload,
                            "selection_task_id": route.yoetz_task_id,
                            "selection_session_id": route.yoetz_session_id,
                            "selection_writer_id": route.yoetz_writer_id,
                            "selection_authority_generation": authority.generation,
                        }
                    ),
                )
                selection_fence = canonical_digest(
                    JsonObject(
                        {
                            "task": route.yoetz_task_id,
                            "session": route.yoetz_session_id,
                            "writer": route.yoetz_writer_id,
                            "host_session": session_commitment,
                            "source": source.value,
                            "generation": source_generation,
                            "authority": authority.generation,
                            "epoch": store.selection_epoch(workspace_commitment),
                            "delegate": envelope.structural_payload.get("subagent_id"),
                            "parent_call": envelope.structural_payload.get("parent_tool_call_id"),
                            "classification": classification.version,
                            "mode": pressure.effective_mode.value,
                        }
                    )
                )
            gap_codes.extend(store.selection_history_gaps(workspace_commitment, envelope))
            # Claude/Cursor native content requires the explicit profile emitted
            # by the rendered artifact and its matching consent arm. Codex hook
            # content is the profileless arm of the structural observation grant;
            # Codex session-stream content keeps its historical behavior.
            native_content_source = source in {
                ObservationSource.CLAUDE_HOOK,
                ObservationSource.CODEX_HOOK,
                ObservationSource.CURSOR_HOOK,
            }
            content_authorized = capture_authority_known and not native_content_source
            if native_content_source:
                if source is ObservationSource.CODEX_HOOK:
                    content_authorized = (
                        capture_authority_known and _content_capture_profile is None
                    )
                else:
                    content_authorized = (
                        capture_authority_known
                        and _content_capture_profile is not None
                        and content_capture_profile_matches_source(
                            source.value, _content_capture_profile
                        )
                        and _content_capture_profile in consent.content_capture_profiles
                    )
                if capture_authority_known and not content_authorized:
                    gap_codes.append(ObservationGapCode.CONTENT_UNSELECTED.value)
            # An oversized Cursor skim already omitted native content. Do not
            # re-read the identity view as a capture source (issue #667).
            if _ingress_gap is not None:
                content_authorized = False
            if not capture_authority_known:
                gap_codes.append(ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value)
            if tuple(sorted(set(gap_codes), key=str.encode)) != envelope.gap_codes:
                envelope = replace(
                    envelope,
                    gap_codes=tuple(sorted(set(gap_codes), key=str.encode)),
                )
            # Pair first, before extracting optional bytes. An orphan, failure
            # or unknown outcome must remain individually observable.
            local_result, envelope = store.ingest_with_pairing(
                envelope,
                workspace_commitment=workspace_commitment,
                pairing_mode=pairing_mode,
                correlation_id=correlation,
                source=source,
                session_commitment=session_commitment,
                source_generation=source_generation,
                is_pre_event=_is_pre_event(resolved_event),
                is_post_event=_is_post_event(resolved_event),
                pre_only=_intercepted_shell_apply_patch(resolved_event, payload, source),
                # Claude Code and Cursor normalize ``tool_input`` away before this ingress, so
                # their adapters commit to the call first and pass only the commitment (tb4n5).
                request_commitment=(
                    _request_commitment
                    if _request_commitment is not None
                    else _finishup_request_commitment(resolved_event, payload)
                ),
            )
            optional_routine = (
                not read_protected
                and classification.routine_candidate
                and (resolved_event == "PreToolUse" or classification.proven_routine_success)
            )
            summary_eligible = (
                selected_focused
                and bool(selection_fence)
                and optional_routine
                and all(
                    gap in {"content_unselected", "observation_input_loss"}
                    for gap in envelope.gap_codes
                )
                and flush_ok
            )
            omit_optional_content = optional_routine and (
                summary_eligible or not pressure.content_allowed
            )
            if omit_optional_content and not summary_eligible:
                envelope = replace(
                    envelope,
                    gap_codes=tuple(
                        sorted({*envelope.gap_codes, "optional_observation_detail_omitted"})
                    ),
                )
            if not content_authorized or omit_optional_content or not flush_ok:
                content_chunks, content_truncated = (), False
            else:
                content_chunks, content_truncated = _visible_content_chunks(
                    resolved_event,
                    payload if _content_payload is None else _content_payload,
                    envelope=envelope,
                    workspace_locator=workspace_locator,
                    optional_limits=(
                        mode_limits(pressure.effective_mode) if optional_routine else None
                    ),
                )
            if content_truncated:
                envelope = replace(
                    envelope,
                    gap_codes=tuple(
                        sorted(
                            {*envelope.gap_codes, ObservationGapCode.TRUNCATED_PAYLOAD.value},
                            key=str.encode,
                        )
                    ),
                )
            content_map = {envelope.source_identity: content_chunks} if content_chunks else None
            service_content_profile = _content_capture_profile if content_authorized else None
            native_content_priority = (
                next(iter(content_map))
                if content_map
                and source
                in {
                    ObservationSource.CLAUDE_HOOK,
                    ObservationSource.CODEX_HOOK,
                    ObservationSource.CURSOR_HOOK,
                }
                else None
            )
            # A contentless ordinary-native row has no transient bytes that need a foreground
            # service handoff. Keep its local envelope/outbox intent and let a later hook or the
            # sweeper deliver it; opening a fresh service connection here would add latency to
            # self-observation and structural-only host events. Content-bearing native rows still
            # use the longer foreground window and priority path.
            native_profile_drain = native_content_source and (
                (
                    source is ObservationSource.CODEX_HOOK
                    and _content_capture_profile is None
                    and content_map is not None
                )
                or (
                    source is not ObservationSource.CODEX_HOOK
                    and _content_capture_profile is not None
                    and content_capture_profile_matches_source(
                        source.value, _content_capture_profile
                    )
                )
            )
            # Stop is never deferred: the closure gate decides there and must read the
            # task's observed facts after this pass delivers them (tb4n1 B4/C6).
            defer_contentless_native_drain = (
                native_profile_drain
                and content_map is None
                and resolved_event not in {"SessionStart", "Stop"}
            )
            native_content_drain_budget = (
                _NATIVE_CONTENT_DRAIN_BUDGET_SECONDS
                if native_profile_drain
                else _HOOK_DRAIN_BUDGET_SECONDS
            )

            if content_chunks and local_result.disposition.value != "accepted":
                # The plaintext chunks have no durable retry carrier. A local
                # cursor/consent rejection therefore needs the same explicit
                # omission signal as a service delivery failure.
                store.note_coverage_gap(
                    workspace_commitment,
                    ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                )
            # A FinishUP-owned tool call is delivered only when it carries evidence
            # the service does not already hold from serving it (#564); the
            # envelope itself is always retained locally above.
            if (
                not child_attribution_gap
                and local_result.disposition.value == "accepted"
                and self_observation_deliverable(
                    resolved_event,
                    _proven_finishup_structural(
                        envelope.structural_payload, proven=_proven_finishup_read
                    ),
                )
            ):
                plan = store.prepare_selected_admission(
                    workspace_commitment,
                    codex_session_id,
                    envelope,
                    fence=selection_fence,
                    focused=summary_eligible,
                    routine_candidate=classification.routine_candidate,
                    proven_routine_success=classification.proven_routine_success,
                    summary_builder=build_routine_read_summary,
                )
                admitted = flush_ok and store.commit_selected_admission(
                    workspace_commitment,
                    plan,
                    incoming=envelope,
                    newly_observed=True,
                )
                if not admitted:
                    if not flush_ok:
                        store.record_admission_loss(
                            workspace_commitment,
                            envelope,
                            cause=AdmissionLossCause.FLUSH_FAILED,
                        )
                    if content_chunks:
                        store.note_coverage_gap(
                            workspace_commitment,
                            ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
                        )
                    if store.consume_admission_loss_notice(workspace_commitment):
                        # The closed refusal dimension, never input content
                        # (tb4n1 B3): `unknown` only if no range was recorded.
                        loss_cause = (
                            store.admission_loss_cause(workspace_commitment, envelope)
                            or AdmissionLossCause.UNKNOWN
                        )
                        _stderr_line(
                            "hook_observe_degraded: outbox_overflow; loss accounted; "
                            f"see observe status; cause={loss_cause.value}"
                        )
                        record_hook_diagnostic("outbox_overflow", resolved_event, _state=_state)
                        record_hook_diagnostic(
                            "admission_loss_" + loss_cause.value,
                            resolved_event,
                            _state=_state,
                        )
                elif read_protected and _is_post_event(resolved_event):
                    store.consume_read_protection(
                        workspace_commitment, session_commitment, envelope
                    )
            elif local_result.disposition.value == "accepted":
                store.note_selection_omission(workspace_commitment)
            if (
                local_result.disposition.value == "accepted"
                and store.consume_summary_refusal_notice(workspace_commitment)
            ):
                # The inputs were admitted individually; only the bounded
                # summary account for that lane was lost.
                _stderr_line(
                    "hook_observe_degraded: routine_summary_invalid; "
                    "reads admitted individually; see observe status"
                )
                record_hook_diagnostic("routine_summary_invalid", resolved_event, _state=_state)

            # Persist session end so lifecycle can report STOPPED once every bound
            # session has ended.
            if resolved_event == "SessionEnd" and binding_owned:
                try:
                    store.note_session_end(
                        workspace_commitment,
                        session_commitment,
                        generation=source_generation,
                    )
                    session_end_uncommitted = True
                except Exception:
                    # Teardown stays fail-open, but an end that did not persist
                    # leaves the session and any temporary override active. Name
                    # it instead of letting the lifecycle write vanish (#843).
                    session_end_uncommitted = False
                    _report_session_end_unrecorded(resolved_event, _state=_state)

            # Cursor transcripts are outside its structural observation contract.
            # Only the Codex hook source may reconcile the secondary JSONL stream.
            # A validated child lane reconciles that child's own rollout (#841); every other
            # Codex lane keeps the host-session stream.
            if source is ObservationSource.CODEX_HOOK:
                with contextlib.suppress(Exception):
                    from finishup.adapters.integrations.codex_session_stream import (
                        CodexSessionStreamLocator,
                        reconcile_session_stream,
                        reconcile_session_stream_path,
                        resolve_codex_home,
                        should_trigger_stream_reconcile,
                    )

                    hook_path = payload.get("session_file") or payload.get("transcript_path")
                    hook_path_token = hook_path if type(hook_path) is str else None
                    session_source = payload.get("source")
                    if should_trigger_stream_reconcile(
                        resolved_event,
                        last_reconcile_mono=store.last_stream_reconcile_mono(workspace_commitment),
                        session_source=session_source if type(session_source) is str else None,
                    ):
                        locator = CodexSessionStreamLocator(resolve_codex_home())
                        if not lane.is_child:
                            reconcile_session_stream(
                                store,
                                workspace_commitment=workspace_commitment,
                                session_commitment=session_commitment,
                                codex_session_id=codex_session_id,
                                locator=locator,
                                hook_provided_path=hook_path_token,
                            )
                        else:
                            child_rollout = _child_lane_rollout(
                                payload,
                                lane=lane,
                                locator=locator,
                                hook_provided_path=hook_path_token,
                            )
                            if child_rollout is not None:
                                reconcile_session_stream_path(
                                    store,
                                    workspace_commitment=workspace_commitment,
                                    session_commitment=session_commitment,
                                    codex_session_id=codex_session_id,
                                    path=child_rollout,
                                )
        session_end_uncommitted = False
        capture_committed = True
        if _pass_timing is not None:
            _pass_timing.outcome = "ingested"

        stages["store"] = _elapsed_ms(store_started, _monotonic())

        if (
            resolved_event in {"PreToolUse", "PostToolUse", "PermissionRequest"}
            and not content_map
            and _monotonic() - entry_started >= _HOOK_LOCAL_STAGE_ALLOWANCE_SECONDS
        ):
            # Ingress is already durable. Yield expensive follow-up work to
            # the service/next hook when contention spent the local allowance.
            # Never defer transient native content through this structural lane.
            record_hook_diagnostic("hook_followup_deferred", resolved_event, _state=_state)
            if _pass_timing is not None:
                _pass_timing.outcome = "followup_deferred"
            _stdout_json({}, stdout)
            for name, spent in store.stage_timings_ms.items():
                stages[f"store_{name}"] = max(0, int(spent))
            _record_pass_timing(
                resolved_event,
                entry_started=entry_started,
                stages=stages,
                monotonic=_monotonic,
                _state=_state,
            )
            return 0

        # Refresh local advice only after the capture batch has
        # closed.  The refresh can build and persist a comparatively large
        # snapshot; keeping it outside the batch means a host cancellation
        # cannot roll back the already-durable envelope, pairing, mapping, or
        # outbox intent (#616).  Advice selection and its delivery lease remain
        # below the service drain and stdout write, preserving commit-after-
        # output semantics.
        advice_started = _monotonic()
        # Teardown cannot deliver advice to a closing host. Its structural end
        # intent is already durable and the service refreshes advice when it
        # drains that intent, so avoid cold advice construction inside the
        # host's hard three-second SessionEnd window.
        # PreToolUse adds an attempted action, not an outcome. Reuse the
        # snapshot at its real frontier; post-result and lifecycle hooks plus
        # service ingest own material advice refresh.
        if resolved_event not in {"SessionEnd", "PreToolUse"}:
            with contextlib.suppress(Exception):
                store.refresh_advice(workspace_commitment)
        stages["advice"] = _elapsed_ms(advice_started, _monotonic())

        # SessionStart: auto-start/attach first, persist mapping, then drain outbox.
        # Every branch below that opens a service connection is gated on
        # skip_service so local-only callers (e.g. the setup readiness probe)
        # never create or attach real ledger tasks.
        additional = ""
        attach_advisory_only = False
        pending_mapping_deferred = mapping_lifecycle_deferred
        mapping: LifecycleMapping | None = load_mapping(codex_session_id, _state=_state)
        if resolved_event != "SessionStart" or _session_start_source(payload) != "clear":
            # A cancelled or lock-contended SessionStart can leave a validated
            # start result in the durable pending file.  Recover that exact
            # session before a later hook drains its outbox; otherwise the
            # service sees a transient mapping_missing and the lane is
            # needlessly retired for this pass.
            from finishup.cli.hooks import recover_pending_start_mapping

            with contextlib.suppress(Exception):
                pending_mapping_deferred = (
                    pending_mapping_deferred
                    or recover_pending_start_mapping(
                        codex_session_id,
                        _state=_state,
                        _session_lock_owned=_session_lock_owned,
                    ).pending
                )
            mapping = load_mapping(codex_session_id, _state=_state)
        drain_started = _monotonic()
        # The Stop pass may spend more of its host window on delivery, up to the point that
        # still leaves the closure gate its status-read reserve.
        stop_drain_deadline: float | None = (
            entry_started
            + _hook_host_window_seconds(source, "Stop")
            - _STOP_CLOSURE_GATE_RESERVE_SECONDS
            - _STOP_DRAIN_DEADLINE_MARGIN_SECONDS
            if resolved_event == "Stop"
            else None
        )
        session_recap = ""
        if resolved_event == "SessionStart":
            session_source_value = _session_start_source(payload)
            if session_source_value != "clear":
                attach = _session_start_attach(
                    codex_session_id,
                    store=store,
                    workspace_commitment=workspace_commitment,
                    workspace_locator=workspace_locator,
                    harness_id=harness_id,
                    payload=payload,
                    connect=connect,
                    resolve_runner=_resolve_runner,
                    event=resolved_event,
                    mapping=mapping,
                    pending_mapping_deferred=pending_mapping_deferred,
                    skip_service=skip_service,
                    skip_advice_loop=skip_advice_loop,
                    session_lock_owned=_session_lock_owned,
                    _state=_state,
                    # Codex runs its re-ground hook and this pass concurrently on a compact
                    # start; whichever holds the session lifecycle lock reads status and carries
                    # the active context, so it must carry the recap too (the other emits at
                    # most the admission notice). Claude Code and Cursor have this pass only.
                    recap=session_source_value == "compact" and _include_recap,
                    recap_time_left=lambda: (
                        entry_started + _RECAP_READ_WINDOW_SECONDS - _monotonic()
                    ),
                )
                mapping = attach.mapping
                pending_mapping_deferred = attach.pending_mapping_deferred
                additional = attach.additional
                attach_advisory_only = attach.attach_advisory_only
                session_recap = attach.recap
            elif (
                source is ObservationSource.CURSOR_HOOK
                and mapping is None
                and _token_or_none(payload.get("tool_name")) is None
                and not pending_mapping_deferred
            ):
                # Cursor consumes the static startup guidance on its native ``sessionStart``
                # channel even when the host marks the lifecycle as a clear. The clear fence
                # remains local-only; this branch never opens a service connection or drains a
                # mapping.
                from finishup.cli.hooks import (
                    _STARTUP_RECOVERY_CONTEXT as startup_recovery_context,  # pyright: ignore[reportPrivateUsage]
                )

                additional = (
                    "FinishUP observation is consented for this workspace; "
                    "no ledger task is mapped yet (observation-derived binding "
                    "only). After guidance reads, tool/schema discovery, and "
                    "necessary bootstrap clarification, call start to attach a task "
                    "before substantive material work. " + startup_recovery_context
                )
                attach_advisory_only = True
            if (
                not child_attribution_gap
                and not skip_service
                and not pending_mapping_deferred
                and session_source_value != "clear"
            ):

                async def _drain() -> None:
                    await _drain_outbox(
                        store,
                        workspace_commitment=workspace_commitment,
                        codex_session_id=codex_session_id,
                        content_by_source_identity=content_map,
                        content_capture_profile=service_content_profile,
                        connect=cast(HookDrainConnector | None, connect),
                        event_name=resolved_event,
                        _state=_state,
                        budget_seconds=native_content_drain_budget,
                        priority_source_identity=native_content_priority,
                        monotonic=_monotonic,
                        session_lock_owned=_session_lock_owned,
                        drain_lease_owned=native_drain_lease_owned,
                    )

                with contextlib.suppress(Exception):
                    _resolve_runner()(_drain)
            # A clear SessionStart has no service drain; the regular SessionStart
            # path released its reservation immediately after the drain above.
            _release_native_drain_lease()

        # Issue #537: no applied-vs-serving drift probe runs on this path. A hook process
        # has no serving route of its own, so the only comparison available here is a
        # `codex mcp get` subprocess plus the PATH version probes needed to find the
        # binary — routinely a large fraction of `_HOOK_TOTAL_BUDGET_SECONDS` and bounded
        # only by the adapter's own 10s command timeout, which is the #209-#213 hook
        # latency loop again. The MCP bridge starts for the same Codex session, knows its
        # serving route from its own argv, and emits `registration_drift` for free.

        if (
            not skip_service
            and not skip_advice_loop
            and mapping is None
            and not pending_mapping_deferred
            and resolved_event in _AUTO_ATTACH_RETRY_EVENTS
        ):
            # Re-attempt auto-attach for a session that started while the service was
            # unreachable, so one missed SessionStart no longer costs the session's whole
            # record (#275). Bounded, and placed before the drain below so a fresh mapping
            # delivers this session's backlog in the same pass.
            mapping = _retry_auto_attach(
                codex_session_id,
                store=store,
                workspace_commitment=workspace_commitment,
                harness_id=harness_id,
                workspace_locator=workspace_locator,
                connect=connect,
                resolve_runner=_resolve_runner,
                event=resolved_event,
                session_lock_owned=_session_lock_owned,
                _state=_state,
            )

        # A pending lifecycle operation is a local fence, not a service
        # mapping_missing result. Leave the captured rows pending until the
        # next hook can acquire this exact session lock.
        if (
            not child_attribution_gap
            and not skip_service
            and resolved_event != "SessionStart"
            and not pending_mapping_deferred
            and resolved_event not in {"SessionStart", "SessionEnd"}
            and not defer_contentless_native_drain
        ):
            # Every later mapped hook drains the complete session outbox, so the
            # current envelope plus any stream-recovered or previously-pending
            # entries all reconcile. Retryable rejections stay pending and
            # permanently-invalid ones are quarantined (never dropped) by the
            # shared drain routing. Unmapped events remain pending until mapped.
            async def _drain_all() -> None:
                await _drain_outbox(
                    store,
                    workspace_commitment=workspace_commitment,
                    codex_session_id=codex_session_id,
                    content_by_source_identity=content_map,
                    content_capture_profile=service_content_profile,
                    connect=cast(HookDrainConnector | None, connect),
                    event_name=resolved_event,
                    _state=_state,
                    budget_seconds=(
                        _SESSION_END_DRAIN_BUDGET_SECONDS
                        if resolved_event == "SessionEnd"
                        else _STOP_DRAIN_BUDGET_SECONDS
                        if resolved_event == "Stop"
                        else native_content_drain_budget
                    ),
                    priority_source_identity=native_content_priority,
                    monotonic=_monotonic,
                    session_lock_owned=_session_lock_owned,
                    drain_lease_owned=native_drain_lease_owned,
                    row_limit=(
                        _STOP_DRAIN_ROW_LIMIT if resolved_event == "Stop" else _HOOK_DRAIN_ROW_LIMIT
                    ),
                    deadline=stop_drain_deadline,
                )

            with contextlib.suppress(Exception):
                _resolve_runner()(_drain_all)
            _release_native_drain_lease()
            if resolved_event == "Stop" and stop_drain_deadline is not None and mapping is not None:
                # Finish the drain at Stop: the closure gate below then decides on observed
                # facts. The outcome is a bounded diagnostic either way (tb4n1 B4/C6).
                stop_mapping = mapping

                async def _finish() -> int:
                    assert stop_drain_deadline is not None
                    return await _finish_stop_drain(
                        store,
                        workspace_commitment=workspace_commitment,
                        codex_session_id=codex_session_id,
                        yoetz_session_id=stop_mapping.yoetz_session_id,
                        connect=cast(HookDrainConnector | None, connect),
                        _state=_state,
                        deadline=stop_drain_deadline,
                        monotonic=_monotonic,
                        session_lock_owned=_session_lock_owned,
                    )

                stop_left = 1
                with contextlib.suppress(Exception):
                    stop_left = cast(int, _resolve_runner()(_finish))
                record_hook_diagnostic(
                    "stop_drain_complete" if stop_left == 0 else "stop_drain_incomplete",
                    resolved_event,
                    _state=_state,
                )

        if content_chunks and skip_service:
            # Content is intentionally ephemeral. Without a ready mapped
            # service there is no encrypted destination, so retain only the
            # structural envelope plus an explicit omission gap.
            store.note_coverage_gap(
                workspace_commitment,
                ObservationGapCode.CONTENT_CAPTURE_UNAVAILABLE.value,
            )

        deliver_started = _monotonic()
        stages["drain"] = _elapsed_ms(drain_started, deliver_started)

        # Advice selection and commit are serialized with the stdout write by a
        # dedicated delivery lease. The lease is independent of workspace state:
        # a blocked host pipe delays advice, never observation ingest or outbox work.
        # Commit remains after emit, so a failed write never suppresses a later delivery.
        pending_delivery: AdviceDelivery | None = None
        delivery_session_id: str | None = None
        # stop_hook_active says a prior Stop already continued this turn. Ordinary items and
        # advice never continue it again; only a re-check readiness announced since the last
        # gate (a blocker, an acknowledgement, the acceptance re-read) or a withdrawn deliverable
        # not yet voiced is asked once, within the per-turn cap (#985, tb4n3 RC-8), and anything
        # else records the normal end of a continued turn.
        stop_already_active = payload.get("stop_hook_active") is True
        if resolved_event == "Stop" and not stop_already_active and mapping is not None:
            # A Stop the host did not continue starts a new turn for the gate's per-turn cap,
            # whether or not the gate is evaluated below (#985). Never raises.
            reset_closure_gate_turn(mapping.yoetz_session_id, _state=_state)
        if (
            resolved_event == "Stop"
            and not child_attribution_gap
            and not skip_service
            and not pending_mapping_deferred
            and mapping is not None
        ):
            closure_gate = _decide_closure_gate(
                mapping,
                store=store,
                workspace_commitment=workspace_commitment,
                codex_session_id=codex_session_id,
                workspace_locator=workspace_locator,
                payload=payload,
                connect=connect,
                run=_resolve_runner(),
                harness_id=harness_id,
                remaining_seconds=(
                    _hook_host_window_seconds(source, resolved_event)
                    - (_monotonic() - entry_started)
                ),
                _state=_state,
                active_stop=stop_already_active,
                # #1050: Codex hands this reader its raw Stop body; Claude Code's adapter passes
                # the message beside its structural envelope; Cursor's stop carries none.
                final_message=(
                    _payload_text(payload, "last_assistant_message")
                    if source is ObservationSource.CODEX_HOOK
                    else _stop_final_message
                ),
            )
            if closure_gate is not None:
                # The gate is the whole Stop message: it names what remains, and ordinary
                # advice waits for a later event rather than diluting it.
                additional = closure_gate.text
        if (
            resolved_event == "Stop"
            and stop_already_active
            and mapping is not None
            and closure_gate is None
        ):
            # An already-continued Stop that emits nothing is the normal end of a continued turn
            # (#985); it guards no loop, so the diagnostic says what happened (tb4n3 RC-8).
            with contextlib.suppress(Exception):
                record_hook_diagnostic(
                    "closure_gate_turn_end_after_continue", resolved_event, _state=_state
                )
        # Task/receipt context always wins this shared channel outright, with one exception:
        # the static attach advisory carries no advice of its own, so pending advice joins it
        # (the delivery text is appended below) instead of being silently starved at the very
        # SessionStart that bootstraps an unmapped session (issues #241, #280).
        delivery_eligible = (
            not child_attribution_gap
            and closure_gate is None
            and (not additional or attach_advisory_only)
            and resolved_event in ADVICE_SAFE_EVENTS
            # Ordinary advice never rides a Stop (#985): on every host the Stop channel continues
            # the agent (Codex `decision: block`, Claude Stop feedback, Cursor follow-up), so it
            # would spend the turn's continuation the closure gate needs. It stays pending for
            # the next PostToolUse or SessionStart.
            and resolved_event != "Stop"
            and not skip_advice_loop
            and not stop_already_active
            and (
                source is not ObservationSource.CURSOR_HOOK
                or _output_event_name == "sessionStart"
                or (
                    _output_event_name == "postToolUse"
                    and payload.get("capability_profile_id")
                    == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
                )
            )
        )
        # Codex and Claude Code: standing advice a Stop withheld rides the first later
        # PostToolUse instead of waiting for the next SessionStart (#985). Cursor never
        # delivered advice at stop, so its cadence is unchanged.
        standing_carry = _standing_advice_carry(
            store,
            event=resolved_event,
            native_host=source is not ObservationSource.CURSOR_HOOK,
            stop_note=(not child_attribution_gap and closure_gate is None and not skip_advice_loop),
            delivery_eligible=delivery_eligible,
            workspace_commitment=workspace_commitment,
            yoetz_session_id=None if mapping is None else mapping.yoetz_session_id,
            session_commitment=session_commitment,
            _state=_state,
        )
        delivery_gate = (
            store.advice_delivery_lease(workspace_commitment)
            if delivery_eligible
            else contextlib.nullcontext(False)
        )
        with delivery_gate as delivery_acquired:
            if delivery_eligible and delivery_acquired:
                delivery_session_id = None if mapping is None else mapping.yoetz_session_id
                # No frontier-motion notice rides this channel (#915). Every recorded
                # notice describes observation-authored motion, which leaves a held
                # cooperative frontier admissible (ADR-022), so it carried nothing to act
                # on and asked for `status` between routine tool calls. Motion by any
                # other writer still reaches the agent as `frontier_conflict` on its next
                # state-sensitive operation.
                delivery = store.peek_advice_for_delivery(
                    workspace_commitment,
                    yoetz_session_id=delivery_session_id,
                    allow_standing=(
                        resolved_event in STANDING_ADVICE_CADENCE_EVENTS or standing_carry
                    ),
                    session_commitment=session_commitment,
                )
                if delivery is None and standing_carry:
                    set_standing_advice_withheld(session_commitment, False, _state=_state)
                if delivery is not None:
                    additional = " ".join(part for part in (additional, delivery.text) if part)[
                        :_MAX_ADVICE_CONTEXT
                    ]
                    pending_delivery = delivery
            # Release recommendations are read from one bounded local cache only.
            # Existing task/receipt advice keeps its place first on this shared context
            # channel; the recommendation follows it only when both fit the bound, so an
            # update notice is no longer starved by every session that has task context (#819).
            if (
                resolved_event == "SessionStart"
                and not skip_advice_loop
                and (
                    source is not ObservationSource.CURSOR_HOOK
                    or _output_event_name == "sessionStart"
                )
            ):
                additional = _session_start_context(
                    additional,
                    payload,
                    include_admission_notice=(
                        _include_admission_notice
                        and not pending_mapping_deferred
                        and not mapping_lifecycle_deferred
                    ),
                    harness_id=harness_id,
                    workspace_locator=workspace_locator,
                    connect=connect,
                    resolve_runner=_resolve_runner,
                    deadline=entry_started + _HOOK_TOTAL_BUDGET_SECONDS - 0.1,
                    skip_service=skip_service,
                    monotonic=_monotonic,
                    _state=_state,
                )

            context_limit: int | None = None
            if session_recap and resolved_event == "SessionStart":
                additional = f"{additional}\n{session_recap}".strip()
                context_limit = RECAP_CONTEXT_LIMIT
            rendered_output = _render_context(additional, limit=context_limit) if additional else {}
            host_consumable = bool(rendered_output)
            if additional:
                emitted = _stdout_json(rendered_output, stdout)
            else:
                emitted = _stdout_json({}, stdout)
            if emitted and host_consumable and closure_gate is not None and mapping is not None:
                _record_closure_gate_emitted(
                    mapping.yoetz_session_id,
                    closure_gate,
                    resolved_event,
                    active_stop=stop_already_active,
                    _state=_state,
                )
            if emitted and host_consumable and pending_delivery is not None:
                # Strictly after the write: delivered-but-unrecorded costs one
                # redelivery, recorded-but-undelivered would cost the advice.
                _commit_emitted_advice(
                    store,
                    workspace_commitment,
                    pending_delivery,
                    yoetz_session_id=delivery_session_id,
                    session_commitment=session_commitment,
                    event=resolved_event,
                    standing_carry=standing_carry,
                    _state=_state,
                )
        # Advice selection, the lease, the stdout write itself and the delivery
        # commits sit past the 'drain' window; a blocked host pipe or a
        # contended commit was previously invisible (#310/#311).
        stages["deliver"] = _elapsed_ms(deliver_started, _monotonic())
        # Attribute the whole pass's store work (#290), folded in last because
        # the store keeps saving after the 'store' stage window closes: the
        # drain saves once per delivered row and advice commits its own. A
        # snapshot taken at that window would have hidden exactly the rows the
        # 1300ms drains were made of. These are store-wide accumulations, not a
        # partition of 'store' — store_hydrate also covers the consent probe
        # that runs before the window opens.
        with contextlib.suppress(BaseException):
            for name, spent in store.stage_timings_ms.items():
                stages[f"store_{name}"] = max(0, int(spent))
        _record_pass_timing(
            resolved_event,
            entry_started=entry_started,
            stages=stages,
            monotonic=_monotonic,
            _state=_state,
            native_content=(
                native_profile_drain and content_map is not None and resolved_event != "SessionEnd"
            ),
        )
        return 0
    except BaseException as failure:
        if _pass_timing is not None:
            _pass_timing.outcome = "failed"
        if isinstance(failure, ObservationStoreLockTimeout):
            # The store stayed contended past this pass's lock budget. The
            # lock reporter already recorded a `store_lock_timeout` row with
            # the holder's role and phase, so no second reason is added (#689).
            with contextlib.suppress(BaseException):
                _stderr_line(
                    "hook_observe_degraded: store_lock_timeout; "
                    + (
                        "observation input retained; follow-up skipped"
                        if capture_committed
                        else "observation input not retained; see observe status"
                    )
                )
        else:
            with contextlib.suppress(BaseException):
                _stderr_line("hook_observe_degraded: observe; observation durability unknown")
            with contextlib.suppress(BaseException):
                record_hook_diagnostic(
                    observe_exception_reason(failure), event_name or "observe", _state=_state
                )
        if session_end_uncommitted:
            with contextlib.suppress(BaseException):
                _report_session_end_unrecorded("SessionEnd", _state=_state)
        emitted = False
        with contextlib.suppress(BaseException):
            emitted = hook_io.stdout_json({}, stdout)
        if not emitted:
            with contextlib.suppress(BaseException):
                record_hook_diagnostic(
                    "stdout_write_failed", event_name or "observe", _state=_state
                )
        return 0
    finally:
        _release_native_drain_lease()
        with contextlib.suppress(BaseException):
            lock_context.close()


def handle_codex_observe(
    *,
    event_name: str,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    _entry_monotonic: float | None = None,
    _monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Run ``finishup hooks observe`` as one timed Codex host hook pass (#915)."""

    timing = HookPassTiming(
        "codex",
        event_name,
        "observe",
        _monotonic() if _entry_monotonic is None else _entry_monotonic,
    )
    try:
        return handle_observe(
            event_name=event_name,
            stdin_bytes=stdin_bytes,
            stdout=stdout,
            workspace=workspace,
            _state=_state,
            connect=connect,
            run_async=run_async,
            skip_service=skip_service,
            _entry_monotonic=_entry_monotonic,
            _pass_timing=timing,
        )
    except BaseException:
        timing.outcome = "failed"
        raise
    finally:
        _finish_hook_pass(timing, monotonic=_monotonic, _state=_state)


_CLAUDE_SESSION_PREFIX: Final = "claude:"
# Derived from the same exact tool-name set as the rendered hook matcher, so
# the renderer and this sanitizer allowlist cannot drift apart. The plugin scope
# is the current one or the legacy one a 0.1-0.2.5 plugin still installs (ADR-048).
_CLAUDE_PLUGIN_TOOL_PREFIXES: Final = tuple(
    f"mcp__plugin_{server}_{server}__" for server in FINISHUP_TOOL_SERVER_NAMES
)
_CLAUDE_SCOPED_TOOL_RE: Final = re.compile(
    "^(?:"
    + "|".join(re.escape(prefix) for prefix in _CLAUDE_PLUGIN_TOOL_PREFIXES)
    + ")(?:"
    + "|".join(FINISHUP_WORKFLOW_TOOL_NAMES)
    + ")$",
    re.ASCII,
)
_CLAUDE_PLUGIN_START_TOOL_NAMES: Final = frozenset(
    f"{prefix}start" for prefix in _CLAUDE_PLUGIN_TOOL_PREFIXES
)
_CLAUDE_UNTESTED_PROFILE_ID: Final = "untested"
_CLAUDE_VERSION_TO_PROFILE: Final = {
    "2.1.241": "claude-code-cli-local-project-2.1.241",
}


def _claude_capability_profile_id(claude_version: object) -> str | None:
    """Map an exact evidenced Claude version to its reviewed profile.

    The hook payload is the only version evidence this ingress has. A payload
    that names no version uses the omitted-profile compatibility path. A
    neighboring version whose native contract was never proven stays
    explicitly untested and uses the conservative paired contract; the
    fail-closed table never infers a range.
    """

    token = _token_or_none(claude_version)
    if token is None:
        return None
    return _CLAUDE_VERSION_TO_PROFILE.get(token, _CLAUDE_UNTESTED_PROFILE_ID)


# ``check`` under either server scope, current or legacy (ADR-048).
_CLAUDE_CHECK_TOOL_NAMES: Final = frozenset(
    f"{prefix}check" for prefix in FINISHUP_SCOPED_TOOL_PREFIXES
)

_NATIVE_OUTCOME_JSON_BYTES: Final = 65_536
_NATIVE_SUCCESS_STATUSES: Final = frozenset(
    {"complete", "completed", "ok", "passed", "success", "succeeded"}
)
_CLAUDE_TOOL_RESPONSE_FACT_KEYS: Final = frozenset(
    {
        # Claude's built-in Bash result and documented MCP result boundary.
        "interrupted",
        "is_interrupted",
        "is_interrupt",
        "isInterrupted",
        "cancelled",
        "canceled",
        "is_cancelled",
        "isCanceled",
        "is_error",
        "isError",
        "success",
        "exit_code",
        "exitCode",
        "exit_status",
        "exitStatus",
    }
)
_MCP_RESULT_FACT_KEYS: Final = frozenset({"is_error", "isError"})
_NATIVE_FAILURE_STATUS_MAP: Final = MappingProxyType(
    {
        "aborted": "aborted",
        "canceled": "cancelled",
        "cancelled": "cancelled",
        "denied": "denied",
        "error": "error",
        "errored": "error",
        "failed": "failure",
        "failure": "failure",
        "interrupted": "interrupted",
        "nonzero": "nonzero_exit",
        "nonzero_exit": "nonzero_exit",
        "permission_denied": "denied",
        "timed_out": "timeout",
        "timeout": "timeout",
    }
)


@dataclass(frozen=True, slots=True)
class _NativeOutcomeFacts:
    """Closed outcome facts extracted from a native host result.

    Host result objects are untrusted and may contain arbitrary prose.  This
    value retains only booleans, a bounded process exit code, and a closed
    result token.  ``success=None`` deliberately means that the host did not
    provide enough outcome evidence to call the operation successful.
    """

    success: bool | None
    denied: bool
    exit_status: int | None
    result_status: str | None


def _bounded_outcome_mapping(value: object) -> Mapping[str, JsonValue] | None:
    """Return one bounded host result object, parsing JSON strings transiently."""

    if isinstance(value, Mapping):
        return cast(Mapping[str, JsonValue], value)
    if type(value) is not str or not value:
        return None
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if len(encoded) > _NATIVE_OUTCOME_JSON_BYTES:
        return None
    try:
        parsed = strict_json_parse(encoded)
    except ProtocolValueError, TypeError, ValueError:
        return None
    return cast(Mapping[str, JsonValue], parsed) if isinstance(parsed, Mapping) else None


def _native_outcome_mappings(
    payload: Mapping[str, JsonValue],
    *,
    claude_tool_response_boundary: bool = False,
    claude_mcp_tool_response_boundary: bool = False,
    cursor_mcp_result_boundary: bool = False,
) -> tuple[Mapping[str, JsonValue], ...]:
    """Collect bounded host-result mappings without descending into domain output."""

    mappings: list[Mapping[str, JsonValue]] = [payload]
    for key in ("tool_response", "tool_output", "result", "result_json"):
        mapping = _bounded_outcome_mapping(payload.get(key))
        if mapping is None:
            continue
        if (
            claude_tool_response_boundary
            and key == "tool_response"
            or cursor_mcp_result_boundary
            and key in {"tool_output", "result_json"}
        ):
            # Claude and Cursor pass MCP structured content and arbitrary tool output through
            # their result carriers. Only the protocol-level ``isError`` bit is a host fact for
            # MCP; fields such as ``success``, ``exitCode``, ``outcome``, or ``status`` belong
            # to the tool's domain and must not turn a successful delivery into a host failure.
            fact_keys = (
                _MCP_RESULT_FACT_KEYS
                if claude_mcp_tool_response_boundary or cursor_mcp_result_boundary
                else _CLAUDE_TOOL_RESPONSE_FACT_KEYS
            )
            mappings.append({field: mapping[field] for field in fact_keys if field in mapping})
            continue
        mappings.append(mapping)
        for nested_key in ("structuredContent", "structured_content", "data", "result"):
            nested = _bounded_outcome_mapping(mapping.get(nested_key))
            if nested is not None:
                mappings.append(nested)
    return tuple(mappings)


def _native_outcome_facts(
    payload: Mapping[str, JsonValue],
    *,
    force_failure: bool = False,
    force_denied: bool = False,
    require_process_exit: bool = False,
    host_event_success: bool = False,
    background_launch: bool = False,
    claude_tool_response_boundary: bool = False,
    claude_mcp_tool_response_boundary: bool = False,
    cursor_mcp_result_boundary: bool = False,
    mappings: tuple[Mapping[str, JsonValue], ...] | None = None,
) -> _NativeOutcomeFacts:
    """Extract closed native outcome facts without retaining host prose.

    Command-like tools require an explicit process exit when
    ``require_process_exit`` is true, unless the selected host contract says
    that the event itself is an authoritative tool-level success signal. The
    latter still never manufactures an exit status. A background launch is
    only a partial result until the host supplies completion evidence.

    ``mappings`` replaces the generic carrier walk with fact mappings a host
    boundary has already selected (the Codex result reader below), so every
    host shares one reduction and one failure-wins order.
    """

    success_true = False
    success_false = False
    denied = force_denied
    interrupted = False
    error = False
    error_false = False
    unknown = False
    partial = False
    valid_exits: list[int] = []
    invalid_exit = False
    failure_status: str | None = "failure" if force_failure else None
    success_status = False

    selected_mappings = (
        mappings
        if mappings is not None
        else _native_outcome_mappings(
            payload,
            claude_tool_response_boundary=claude_tool_response_boundary,
            claude_mcp_tool_response_boundary=claude_mcp_tool_response_boundary,
            cursor_mcp_result_boundary=cursor_mcp_result_boundary,
        )
    )
    for mapping in selected_mappings:
        for key in ("denied", "is_denied", "permission_denied"):
            value = mapping.get(key)
            if type(value) is bool and value:
                denied = True
        for key in (
            "interrupted",
            "is_interrupted",
            "is_interrupt",
            "isInterrupted",
            "cancelled",
            "canceled",
            "is_cancelled",
            "isCanceled",
        ):
            value = mapping.get(key)
            if type(value) is bool and value:
                interrupted = True
        for key in ("is_error", "isError", "failed"):
            value = mapping.get(key)
            if type(value) is bool and value:
                error = True
            elif key in {"is_error", "isError"} and type(value) is bool:
                error_false = True
        for key in ("success", "ok"):
            value = mapping.get(key)
            if type(value) is bool:
                success_true = success_true or value
                success_false = success_false or not value
        for key in ("exit_code", "exitCode", "exit_status", "exitStatus"):
            if key not in mapping:
                continue
            value = mapping.get(key)
            if type(value) is int and not isinstance(value, bool) and -1 <= value <= 255:
                valid_exits.append(value)
            else:
                invalid_exit = True
        for key in ("result_status", "status", "outcome", "failure_type"):
            if key not in mapping:
                continue
            value = mapping.get(key)
            if type(value) is not str:
                if value is not None:
                    unknown = True
                continue
            lowered = value.lower()
            if lowered in _NATIVE_FAILURE_STATUS_MAP:
                failure_status = _NATIVE_FAILURE_STATUS_MAP[lowered]
                if failure_status == "denied":
                    denied = True
            elif lowered in _NATIVE_SUCCESS_STATUSES:
                success_status = True
            elif lowered in {"partial", "partially_completed"}:
                partial = True
            else:
                # Keep an explicit unknown marker useful for materialization,
                # while never copying an arbitrary host token or prose.
                unknown = True
        if "error" in mapping:
            value = mapping.get("error")
            if value not in (None, False, ""):
                error = True

    if denied:
        failure_status = "denied"
    elif interrupted:
        failure_status = "interrupted"
    elif error:
        failure_status = "error"
    elif valid_exits and any(value != 0 for value in valid_exits):
        failure_status = "nonzero_exit"

    if failure_status is not None:
        return _NativeOutcomeFacts(
            False,
            denied,
            next((value for value in valid_exits if value != 0), None),
            failure_status,
        )
    if success_false:
        return _NativeOutcomeFacts(
            False,
            denied,
            valid_exits[0] if valid_exits else None,
            "failure",
        )
    if partial:
        return _NativeOutcomeFacts(
            None,
            denied,
            valid_exits[0] if valid_exits else None,
            "partial",
        )
    if invalid_exit:
        return _NativeOutcomeFacts(None, denied, None, "unknown")
    if valid_exits:
        return _NativeOutcomeFacts(
            all(value == 0 for value in valid_exits),
            denied,
            valid_exits[0],
            "success" if all(value == 0 for value in valid_exits) else "nonzero_exit",
        )
    if unknown:
        return _NativeOutcomeFacts(None, denied, None, "unknown")
    if background_launch:
        return _NativeOutcomeFacts(None, denied, None, "partial")
    if host_event_success:
        # Claude's PostToolUse event is the host's closed success fact. Keep
        # exit_status absent: an event-level success proves the tool call, not
        # an invented process-exit integer.
        return _NativeOutcomeFacts(True, denied, None, "success")
    if require_process_exit:
        return _NativeOutcomeFacts(None, denied, None, "unknown")
    if success_true or success_status or error_false:
        return _NativeOutcomeFacts(True, denied, None, "success")
    return _NativeOutcomeFacts(None, denied, None, None)


# Codex 0.157.x states a tool call's outcome only inside ``tool_response`` (#910). The closed
# shapes read here come from recorded Codex 0.157.1 rollouts (fixture
# ``observations/codex-post-tool-outcomes-0.157.1.case.json``): a nested ``tools.exec_command``
# result object ``{chunk_id, wall_time_seconds, exit_code, original_token_count, output}``, as an
# object or as JSON text; the freeform function-output header ``Exit code: N`` (``apply_patch`` and
# the classic shell); and the unified-exec header ``Process exited with code N``.
_CODEX_TOP_LEVEL_FACT_KEYS: Final = ("exit_status", "success", "denied")
# Codex's own shell tools, compared case-insensitively. The shared selection set also names
# ``exec`` and ``command``; a code-mode ``exec`` cell's result is model-authored JSON, so it is
# never read as a process exit here.
_CODEX_SHELL_OUTCOME_TOOLS: Final = frozenset({"bash", "shell", "exec_command", "local_shell"})
_CODEX_EXIT_FACT_KEYS: Final = ("exit_code", "exitCode", "exit_status", "exitStatus")
_CODEX_EXEC_RESULT_MARKERS: Final = frozenset(
    {"chunk_id", "wall_time_seconds", "original_token_count"}
)
_CODEX_HEADER_EXIT: Final = re.compile(r"(?:Exit code: |Process exited with code )(-?[0-9]{1,4})")
_CODEX_HEADER_FIELD: Final = re.compile(
    r"Chunk ID: [A-Za-z0-9._-]{1,64}"
    r"|Wall time: [0-9]{1,12}(?:\.[0-9]{1,12})? seconds"
    r"|Original token count: [0-9]{1,12}"
    r"|Total output lines: [0-9]{1,12}"
    r"|Process running with session ID [0-9]{1,20}"
)
_CODEX_HEADER_MAX_LINES: Final = 12


def _unique_json_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate_object_key")
    return result


def _drop_json_float(_literal: str) -> None:
    """Drop a vendor fraction; the canonical value model has no float."""

    return None


def _reject_json_constant(_literal: str) -> NoReturn:
    raise ValueError("nonfinite_number")


def _codex_result_object(
    value: object, *, require_exec_marker: bool
) -> Mapping[str, JsonValue] | None:
    """Return one Codex tool-result object, parsing JSON text transiently.

    Codex serializes a nested ``exec_command`` result as JSON text whose ``wall_time_seconds`` is
    fractional; that vendor float is dropped here and nothing parsed leaves this call. JSON text
    counts as the host's result only when it carries one of Codex's own exec-result keys and a
    string ``output``, so a command whose output happens to be a JSON document naming
    ``exit_code`` is never mistaken for the host's outcome. A result sent as a JSON *object* with a
    float field never reaches this reader: the strict hook stdin parser refuses the whole event as
    ``float_forbidden`` (a pre-existing boundary; the recorded 0.157.1 shapes carry text).
    """

    if isinstance(value, Mapping):
        return cast(Mapping[str, JsonValue], value)
    if type(value) is not str or len(value) > MAX_HOOK_STDIN_BYTES:
        return None
    if not value.lstrip().startswith("{"):
        return None
    try:
        parsed: object = json.loads(
            value,
            object_pairs_hook=_unique_json_pairs,
            parse_float=_drop_json_float,
            parse_constant=_reject_json_constant,
        )
    except ValueError, RecursionError:
        return None
    if not isinstance(parsed, dict):
        return None
    result = cast(dict[str, JsonValue], parsed)
    if require_exec_marker and (
        _CODEX_EXEC_RESULT_MARKERS.isdisjoint(result) or type(result.get("output")) is not str
    ):
        return None
    return result


def _codex_header_exit_codes(text: str) -> tuple[int, ...]:
    """Read exit codes from a Codex function-output header, never from the output itself.

    The header is a closed grammar that ends at the ``Output:`` line. An unrecognized line, or a
    text with no terminator, is not Codex's header and yields no fact rather than a guess.
    ``Process running with session ID N`` is a process that has not exited: it states no exit.
    """

    codes: list[int] = []
    for raw_line in text.split("\n", _CODEX_HEADER_MAX_LINES)[:_CODEX_HEADER_MAX_LINES]:
        line = raw_line.removesuffix("\r")
        if line == "Output:":
            return tuple(codes)
        exit_match = _CODEX_HEADER_EXIT.fullmatch(line)
        if exit_match is not None:
            codes.append(int(exit_match.group(1)))
        elif _CODEX_HEADER_FIELD.fullmatch(line) is None:
            return ()
    return ()


def _codex_post_tool_outcome(payload: Mapping[str, JsonValue]) -> _NativeOutcomeFacts:
    """Return the closed outcome Codex states for one ``PostToolUse`` (#910).

    Codex sends no top-level outcome: a command's exit status is nested in ``tool_response``.
    Only each tool family's closed facts are read: process exit codes for shell and patch tools,
    and the protocol-level ``isError`` bit for MCP tools, whose result body is tool-domain data.
    Output text is never searched for words such as ``FAILED`` and no fact means unknown; the
    shared reducer resolves conflicting facts failure-first. Top-level ``exit_status``,
    ``success`` and ``denied`` stay honored for a caller that already normalized its payload.
    """

    facts: list[Mapping[str, JsonValue]] = []
    top_level = {key: payload[key] for key in _CODEX_TOP_LEVEL_FACT_KEYS if key in payload}
    if top_level:
        facts.append(top_level)
    tool = _token_or_none(payload.get("tool_name"))
    response = payload.get("tool_response")
    if tool is not None and response is not None:
        if tool.lower().startswith("mcp__"):
            result = _codex_result_object(response, require_exec_marker=False)
            if result is not None:
                facts.append({key: result[key] for key in _MCP_RESULT_FACT_KEYS if key in result})
        elif tool.lower() in _CODEX_SHELL_OUTCOME_TOOLS or tool in _PATCH_TOOL_NAMES:
            result = _codex_result_object(response, require_exec_marker=type(response) is str)
            if result is not None:
                # ``exit_code: null`` is a process that has not exited yet: no fact. A true error
                # bit beside an exit still wins, but a false one never stands in for an exit.
                facts.append(
                    {
                        key: result[key]
                        for key in _CODEX_EXIT_FACT_KEYS
                        if result.get(key) is not None
                    }
                )
                facts.append(
                    {key: True for key in _MCP_RESULT_FACT_KEYS if result.get(key) is True}
                )
            elif type(response) is str:
                codes = _codex_header_exit_codes(response)
                if not codes and tool in _PATCH_TOOL_NAMES:
                    # A bare ``Exit code: N`` prefix keeps the apply_patch contract of #883.
                    legacy = _CODEX_EXIT_CODE.match(response)
                    codes = (int(legacy.group(1)),) if legacy is not None else ()
                facts.extend({"exit_code": code} for code in codes)
    return _native_outcome_facts(payload, mappings=tuple(facts))


def _merge_outcome_facts(fields: dict[str, JsonValue], facts: _NativeOutcomeFacts) -> None:
    """Write one host's closed outcome facts as structural fields, failure first.

    ``fields`` is the structural copy of the payload, so a top-level fact it already carries was
    part of ``facts`` too; only a stated exit, success, denial or closed status is written. A
    result status the host already named is replaced only by a failure.
    """

    fields.pop("exit_status", None)
    if facts.exit_status is not None:
        fields["exit_status"] = facts.exit_status
    if facts.success is not None:
        fields["success"] = facts.success
    else:
        fields.pop("success", None)
    if facts.denied:
        fields["denied"] = True
    if facts.result_status is not None and facts.result_status != "unknown":
        if facts.success is False or "result_status" not in fields:
            fields["result_status"] = facts.result_status


def _record_claude_permission_denied(
    payload: Mapping[str, JsonValue],
    *,
    _state: Path | None,
    workspace: str | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
) -> dict[str, JsonValue]:
    """Record that a host reviewer held a scoped AI-powered ``check`` and advise on it.

    ``source`` is Claude Code's closed origin token (``auto_mode`` | ``permission_rule`` |
    ``hook``). An absent source is attributed to auto mode, the only reviewer that produces a
    ``classifier_denied`` / ``no_verdict`` reason (issue #467). Any other tool name is ignored:
    the rendered matcher is scoped to ``check`` and this ingress must not widen it.

    The returned object is the hook's stdout (issue #857): FinishUP's first-hand grant and
    admission facts, read inside the hook deadline, decide whether the advisory confirms the
    owner's standing authorization and offers the session's one ``retry``, or tells the agent to
    stop and ask. It is advice plus the host's own documented retry flag, never an allow
    decision, and it echoes nothing from the host payload.
    """

    if payload.get("tool_name") not in _CLAUDE_CHECK_TOOL_NAMES:
        return {}
    source = payload.get("source")
    held_by_rule = source in ("permission_rule", "hook")
    record_hook_diagnostic(
        "host_permission_rule_denied" if held_by_rule else "host_auto_review_denied",
        "PermissionDenied",
        _state=_state,
    )
    tool_input = payload.get("tool_input")
    mode = tool_input.get("mode") if isinstance(tool_input, Mapping) else None
    if mode == "deterministic_only" or (type(mode) is str and mode in READ_ONLY_CHECK_MODES):
        # This call asks for no external review (a local-only check, or an inspection, #1048);
        # a semantic grant says nothing about why the host held it. Leave the ordinary host
        # approval path intact.
        return {}
    from finishup.cli.hooks import resolve_session_workspace
    from finishup.cli.host_hold_advisory import (
        PrivacyConnector,
        RetryOfferOutcome,
        classifier_verdict_present,
        compose_host_hold_advisory,
        note_retry_offer,
        read_host_hold_facts,
    )

    locator = resolve_session_workspace(workspace, payload).locator
    facts = read_host_hold_facts(
        locator,
        connect=None if connect is None else cast(PrivacyConnector, connect),
        run_async=run_async if run_async is not None else _default_runner(),
        skip_service=skip_service,
    )
    session = _token_or_none(payload.get("session_id"))
    retry_offer: RetryOfferOutcome = "unrecorded"
    if facts.grant_confirmed and classifier_verdict_present(source, payload.get("reason")):
        # The ledger is consulted only when a retry could actually be emitted, so a session
        # whose first hold was unconfirmed or rule-held keeps its one retry for later.
        retry_offer = "unrecorded" if session is None else note_retry_offer(session, _state=_state)
    advisory = compose_host_hold_advisory(
        facts,
        source=source,
        reason=payload.get("reason"),
        retry_offer=retry_offer,
    )
    with contextlib.suppress(Exception):
        record_hook_diagnostic(advisory.diagnostic, "PermissionDenied", _state=_state)
    return hook_io.claude_permission_denied_output(
        advisory.explanation,
        retry=advisory.retry,
    )


def _default_runner() -> AsyncRunner:
    import anyio

    return cast(AsyncRunner, anyio.run)


def _native_profile_path(observation_profile: str | None, ordinary_profile_id: str) -> str:
    """Name the rendered observation profile a Claude Code or Cursor hook ran under (#915)."""

    if observation_profile is None:
        return "structural"
    return "ordinary" if observation_profile == ordinary_profile_id else "invalid_profile"


def handle_claude_observe(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    observation_profile: str | None = None,
    _entry_monotonic: float | None = None,
    _monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Run one Claude Code hook as one timed host hook pass (#915)."""

    timing = HookPassTiming(
        "claude",
        event_name or "unknown_event",
        _native_profile_path(observation_profile, CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID),
        _monotonic() if _entry_monotonic is None else _entry_monotonic,
    )
    try:
        return _handle_claude_observe(
            event_name=event_name,
            stdin_bytes=stdin_bytes,
            stdout=stdout,
            workspace=workspace,
            _state=_state,
            connect=connect,
            run_async=run_async,
            skip_service=skip_service,
            observation_profile=observation_profile,
            _entry_monotonic=_entry_monotonic,
            _pass_timing=timing,
        )
    except BaseException:
        timing.outcome = "failed"
        raise
    finally:
        _finish_hook_pass(timing, monotonic=_monotonic, _state=_state)


def _handle_claude_observe(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    observation_profile: str | None = None,
    _entry_monotonic: float | None = None,
    _pass_timing: HookPassTiming | None = None,
) -> int:
    """Normalize one Claude hook into bounded FinishUP observation.

    The host payload can contain transcript/cwd paths, prompts, assistant text,
    complete tool inputs/responses, and raw errors.  Structural profiles retain
    only the historical scoped FinishUP events.  The explicit ordinary profile
    admits generic tool pre/post/failure events; content remains separately
    gated by the matching user consent arm.
    """

    event_map = {
        "PostToolUse": "PostToolUse",
        "PostToolUseFailure": "PostToolUse",
        "SessionEnd": "SessionEnd",
        "SessionStart": "SessionStart",
        "Stop": "Stop",
        "SubagentStart": "SubagentStart",
        "SubagentStop": "SubagentStop",
    }
    ordinary_profile = observation_profile == CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
    if observation_profile is not None and not ordinary_profile:
        with contextlib.suppress(Exception):
            record_hook_diagnostic(
                "observation_profile_invalid", event_name or "unknown_event", _state=_state
            )
        with contextlib.suppress(BaseException):
            hook_io.stdout_json({}, stdout)
        return 0
    if ordinary_profile:
        # Generic tool hooks are authoritative.  Specialized filesystem and
        # batch events stay out of this subscription until a common dedup
        # contract proves that they add distinct work.
        event_map.update(
            {
                "PermissionDenied": "PermissionDecision",
                "PermissionRequest": "PermissionRequest",
                "PreToolUse": "PreToolUse",
                "PostToolUse": "PostToolUse",
                "PostToolUseFailure": "PostToolUse",
                # StopFailure is a per-turn API failure, not a lifecycle end.
                # Keep the observation visible without fencing the session.
                "StopFailure": "Stop",
            }
        )
    start_actions = {
        "startup": "claude_session_startup",
        "resume": "claude_session_resume",
        "clear": "claude_session_clear",
        "compact": "claude_session_compact",
        "fork": "claude_session_fork",
    }
    try:
        content_omitted = False
        try:
            payload, content_omitted = read_hook_ingress(stdin_bytes)
        except (OversizedHookPayloadError, ProtocolValueError) as exc:
            if exc.reason_code != "payload_too_large" and not isinstance(
                exc, OversizedHookPayloadError
            ):
                raise
            # This host ingress swallowed every refusal into a bare `{}` with no
            # record at all, so an oversized Claude Code event left no trace of
            # the work it dropped (issue #667).
            note_payload_too_large(
                event_map.get(event_name or "", "unknown_event"),
                source=ObservationSource.CLAUDE_HOOK,
                workspace=workspace,
                _state=_state,
            )
            hook_io.stdout_json({}, stdout)
            return 0
        raw_event = event_name or payload.get("hook_event_name")
        denied_output: dict[str, JsonValue] | None = None
        if raw_event == "PermissionDenied" and (
            not ordinary_profile or payload.get("tool_name") in _CLAUDE_CHECK_TOOL_NAMES
        ):
            # Not an observation of work: the host refused the call before FinishUP saw it. Retain
            # only a closed reason token; tool input, reason prose, cwd, and ids are discarded.
            # The stdout object is the bounded hold advisory (issue #857), or `{}` for any other
            # tool. Nothing here may raise past the write: a second object would corrupt stdout.
            output: dict[str, JsonValue] = {}
            try:
                output = _record_claude_permission_denied(
                    payload,
                    _state=_state,
                    workspace=workspace,
                    connect=connect,
                    run_async=run_async,
                    skip_service=skip_service,
                )
            except Exception:
                output = {}
            if not ordinary_profile:
                hook_io.stdout_json(output, stdout)
                return 0
            denied_output = output
        if type(raw_event) is not str or raw_event not in event_map:
            hook_io.stdout_json({}, stdout)
            return 0
        session = _token_or_none(payload.get("session_id"))
        if session is None or len(session) > _MAX_TOKEN_CHARS - len(_CLAUDE_SESSION_PREFIX):
            hook_io.stdout_json({}, stdout)
            return 0
        capability_profile_id = (
            CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID
            if ordinary_profile
            else _claude_capability_profile_id(payload.get("claude_code_version"))
        )
        pairing_mode, correlation_kind = observation_pairing_contract(
            "claude", capability_profile_id
        )
        structural: dict[str, JsonValue] = {
            "action": "claude_lifecycle",
            "pairing_mode": pairing_mode,
            "correlation_kind": correlation_kind,
            "hook_event_name": event_map[raw_event],
            "session_id": f"{_CLAUDE_SESSION_PREFIX}{session}",
        }
        if capability_profile_id is not None:
            structural["capability_profile_id"] = capability_profile_id
        if ordinary_profile:
            # Keep the materialization cursor vocabulary stable while recording
            # the exact host mapping used by this opt-in profile separately.
            structural["mapping_hint"] = CLAUDE_CODE_ORDINARY_HOOK_MAPPING_VERSION
        routing_session_id: str | None = None
        child_attribution_gap = False
        if raw_event == "Stop" and payload.get("stop_hook_active") is True:
            structural["stop_hook_active"] = True
        if raw_event == "SessionStart":
            source = payload.get("source")
            if type(source) is str and source in start_actions:
                structural["action"] = start_actions[source]
            else:
                structural["action"] = "claude_session"
        if raw_event in {"SubagentStart", "SubagentStop"}:
            # Claude's native child hooks provide the child identity and
            # transcript metadata, but no parent tool-call identifier. Keep
            # the child-only signal usable for later parent-scoped binding;
            # conflicting aliases stay absent and become an attribution gap.
            structural["action"] = "claude_subagent"
            subagent_id, _subagent_aliases_supplied = _consistent_alias_token(
                payload, ("subagent_id", "agent_id", "agent_thread_id")
            )
            if subagent_id is not None:
                structural["subagent_id"] = subagent_id
            parent_tool_call_id, _parent_aliases_supplied = _consistent_alias_token(
                payload, ("parent_tool_call_id", "tool_call_id", "tool_use_id")
            )
            if parent_tool_call_id is not None:
                structural["parent_tool_call_id"] = parent_tool_call_id
        if ordinary_profile and raw_event == "PermissionRequest":
            # Claude's documented PermissionRequest payload has no tool_use_id.
            # Retain the event and any bounded tool name without manufacturing
            # a call identity or pairing operation. The closed permission
            # classification describes the host event and mints no work row.
            tool_token = _token_or_none(payload.get("tool_name"))
            if tool_token is not None:
                structural["tool_name"] = tool_token
            structural["action"] = "claude_permission_request"
            structural["permission_decision"] = "requested"
        if ordinary_profile and raw_event == "PreToolUse":
            tool_token = _token_or_none(payload.get("tool_name"))
            correlation = _token_or_none(payload.get("tool_use_id")) or _token_or_none(
                payload.get("tool_call_id")
            )
            if tool_token is None or correlation is None:
                with contextlib.suppress(Exception):
                    record_hook_diagnostic(
                        "claude_tool_identity_missing", event_map[raw_event], _state=_state
                    )
                hook_io.stdout_json({}, stdout)
                return 0
            structural["tool_name"] = tool_token
            structural["tool_use_id"] = correlation
            structural["action"] = "claude_tool_pending"
            if _routine_read_action(payload):
                structural["action"] = "routine_read"
        if ordinary_profile and raw_event == "PermissionDenied":
            tool_token = _token_or_none(payload.get("tool_name"))
            correlation = _token_or_none(payload.get("tool_use_id")) or _token_or_none(
                payload.get("tool_call_id")
            )
            if tool_token is None or correlation is None:
                with contextlib.suppress(Exception):
                    record_hook_diagnostic(
                        "claude_tool_identity_missing", event_map[raw_event], _state=_state
                    )
                hook_io.stdout_json({}, stdout)
                return 0
            structural.update(
                {
                    "action": "claude_permission_denied",
                    "denied": True,
                    "permission_decision": "denied",
                    "tool_name": tool_token,
                    "tool_use_id": correlation,
                }
            )
        if ordinary_profile and raw_event == "StopFailure":
            structural["action"] = "claude_api_failure"
            outcome = _native_outcome_facts(
                payload,
                force_failure=True,
            )
            structural["result_status"] = outcome.result_status or "error"
        if raw_event in {"PostToolUse", "PostToolUseFailure"} or (
            raw_event == "PermissionDenied" and not ordinary_profile
        ):
            tool_name = payload.get("tool_name")
            if not ordinary_profile and (
                type(tool_name) is not str or _CLAUDE_SCOPED_TOOL_RE.fullmatch(tool_name) is None
            ):
                hook_io.stdout_json({}, stdout)
                return 0
            tool_token = _token_or_none(tool_name)
            if tool_token is None:
                hook_io.stdout_json({}, stdout)
                return 0
            if ordinary_profile:
                tool_input = payload.get("tool_input")
                background_launch = (
                    isinstance(tool_input, Mapping)
                    and type(tool_input.get("run_in_background")) is bool
                    and tool_input.get("run_in_background") is True
                )
                outcome = _native_outcome_facts(
                    payload,
                    force_failure=raw_event == "PostToolUseFailure",
                    require_process_exit=(tool_token.lower() in _SHELL_TOOLS),
                    host_event_success=raw_event == "PostToolUse",
                    background_launch=background_launch,
                    claude_tool_response_boundary=True,
                    claude_mcp_tool_response_boundary=tool_token.lower().startswith("mcp__"),
                )
                structural["action"] = (
                    "claude_tool_success"
                    if outcome.success is True
                    else "claude_tool_failure"
                    if outcome.success is False
                    else "claude_tool_outcome_unknown"
                )
                if outcome.success is not None:
                    structural["success"] = outcome.success
                if outcome.denied:
                    structural["denied"] = True
                if outcome.exit_status is not None:
                    structural["exit_status"] = outcome.exit_status
                if outcome.result_status is not None:
                    structural["result_status"] = outcome.result_status
                if (
                    _routine_read_action(payload)
                    and outcome.success is not False
                    and not outcome.denied
                ):
                    structural["action"] = "routine_read"
            else:
                structural["action"] = (
                    "claude_mcp_success" if raw_event == "PostToolUse" else "claude_mcp_failure"
                )
                structural["success"] = raw_event == "PostToolUse"
            structural["tool_name"] = tool_token
            correlation = _token_or_none(payload.get("tool_use_id")) or _token_or_none(
                payload.get("tool_call_id")
            )
            if correlation is not None:
                structural["tool_use_id"] = correlation
            # Keep a validated child identity when Claude supplies one on a tool callback. The
            # identity is structural only; route selection still requires a child mapping that a
            # successful service start established. A parent callback carrying an optional
            # agent_id therefore remains on the parent lane.
            callback_subagent_id, _callback_aliases_supplied = _consistent_alias_token(
                payload, ("subagent_id", "agent_id", "agent_thread_id")
            )
            if callback_subagent_id is not None:
                structural["subagent_id"] = callback_subagent_id
            if not ordinary_profile:
                result_status = _token_or_none(
                    payload.get("result_status") or payload.get("failure_type")
                )
                if result_status is not None:
                    structural["result_status"] = result_status
                duration = _int_or_none(payload.get("duration_ms"))
                if duration is not None:
                    structural["duration_ms"] = duration
            if raw_event == "PostToolUse" and tool_token in _CLAUDE_PLUGIN_START_TOOL_NAMES:
                # Claude's observation envelope stays structural-only, but the
                # successful start result is the sole authority that can bind
                # this host session to the cooperative FinishUP task. Inspect the
                # raw response transiently and persist only validated ids.
                from finishup.cli.hooks import (
                    bind_start_mapping_outcome,
                    record_start_bind_diagnostic,
                )

                # A scoped successful start that binds nothing is recorded as a
                # typed, payload-free diagnostic instead of failing silently
                # (issue #581): `observe status` can then say why observation
                # kept routing to the previous task.
                with contextlib.suppress(Exception):
                    binding_payload: dict[str, JsonValue] = {
                        "session_id": f"{_CLAUDE_SESSION_PREFIX}{session}",
                        "tool_name": tool_token,
                        "tool_response": payload.get("tool_response"),
                    }
                    for alias in ("subagent_id", "agent_id", "agent_thread_id"):
                        value = payload.get(alias)
                        if alias in payload:
                            binding_payload[alias] = value
                    tool_input = payload.get("tool_input")
                    if isinstance(tool_input, Mapping):
                        nested_aliases: dict[str, JsonValue] = {}
                        for alias in ("subagent_id", "agent_id", "agent_thread_id"):
                            if alias in tool_input:
                                nested_aliases[alias] = cast(JsonValue, tool_input.get(alias))
                        if nested_aliases:
                            # Preserve the direct and nested namespaces independently.  A
                            # contradictory pair must be rejected by the binder before it can
                            # publish an alias; flattening nested values into the direct field
                            # made ``agent_id=A`` plus ``tool_input.agent_id=B`` look consistent.
                            binding_payload["tool_input"] = cast(JsonValue, nested_aliases)
                    record_start_bind_diagnostic(
                        bind_start_mapping_outcome(
                            binding_payload,
                            _state=_state,
                            host="claude",
                        ),
                        "PostToolUse",
                        _state=_state,
                    )

            routing_payload = dict(payload)
            routing_payload["session_id"] = f"{_CLAUDE_SESSION_PREFIX}{session}"
            resolved_lane = _resolve_observation_lane(
                cast(Mapping[str, JsonValue], routing_payload),
                event_name="PostToolUse",
                source=ObservationSource.CLAUDE_HOOK,
                _state=_state,
            )
            if resolved_lane.is_child:
                routing_session_id = resolved_lane.effective_session_id
            elif resolved_lane.attribution_gap:
                child_attribution_gap = True
            elif any(
                key in payload
                for key in ("agent_transcript_path", "agent_type", "subagent_id", "agent_id")
            ):
                # Claude's child callback can omit every child identity and result body. Preserve
                # the parent mapping but fence this observation from parent delivery; a later
                # validated child result can drain it through the child alias. The same fence
                # applies to a successful callback carrying child-only transcript metadata: a
                # success bit does not authorize parent attribution.
                child_attribution_gap = True
        if event_map[raw_event] == "PostToolUse" and OBSERVED_IMAGES_KEY in payload:
            # Digest-only image facts the ingress reader computed (P3-2, issue #1013).
            structural[OBSERVED_IMAGES_KEY] = payload[OBSERVED_IMAGES_KEY]
        if ordinary_profile and raw_event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}:
            _attach_command_commitment(structural, payload, _state=_state)
        derived_runner_class = (
            command_runner_class(payload)
            if ordinary_profile and raw_event in {"PreToolUse", "PostToolUse", "PostToolUseFailure"}
            else None
        )
        claude_ingress_gap = (
            _oversized_ingress_gap(
                payload,
                source=ObservationSource.CLAUDE_HOOK,
                event=event_map[raw_event],
                _state=_state,
            )
            if content_omitted
            else None
        )
        result = handle_observe(
            event_name=event_map[raw_event],
            stdin_bytes=canonical_encode(structural),
            stdout=io.BytesIO() if denied_output is not None else stdout,
            workspace=workspace,
            _state=_state,
            connect=connect,
            run_async=run_async,
            skip_service=skip_service,
            _entry_monotonic=_entry_monotonic,
            source=ObservationSource.CLAUDE_HOOK,
            _output_event_name=raw_event,
            _routing_session_id=routing_session_id,
            _child_attribution_gap=child_attribution_gap,
            _content_capture_profile=(
                CLAUDE_CODE_ORDINARY_OBSERVATION_PROFILE_ID if ordinary_profile else None
            ),
            _content_payload=payload if ordinary_profile and not content_omitted else None,
            _derived_runner_class=derived_runner_class,
            _ingress_gap=claude_ingress_gap,
            _pass_timing=_pass_timing,
            # #1050: Claude Code's Stop payload names the final message; it decides only which
            # acceptance re-reads the gate asks and never enters the structural envelope.
            _stop_final_message=(
                _payload_text(payload, "last_assistant_message") if raw_event == "Stop" else None
            ),
            # The structural envelope drops ``tool_input``; commit to a FinishUP call here so a
            # pending attempt FinishUP rejected can still close as rejected (tb4n5).
            _request_commitment=_finishup_request_commitment(event_map[raw_event], payload),
        )
        if denied_output is not None:
            hook_io.stdout_json(denied_output, stdout)
        return result
    except BaseException:
        if _pass_timing is not None:
            _pass_timing.outcome = "failed"
        with contextlib.suppress(BaseException):
            hook_io.stdout_json({}, stdout)
        return 0


# Each scoped Cursor spelling of ``start`` and the server key Cursor names beside it, under the
# current and the legacy server name (ADR-048). A spelling only pairs with its own server key.
_CURSOR_START_TOOL_SERVERS: Final = {
    spelling: server_key
    for server in FINISHUP_TOOL_SERVER_NAMES
    for spelling, server_key in (
        (f"mcp__{server}__start", server),
        (f"mcp__plugin_{server}_{server}__start", f"plugin-{server}-{server}"),
        (f"{server}:start", server),
        (f"plugin-{server}-{server}:start", f"plugin-{server}-{server}"),
    )
}
_CURSOR_SERVER_KEYS: Final = frozenset(_CURSOR_START_TOOL_SERVERS.values())


def _bind_cursor_start(
    payload: Mapping[str, JsonValue],
    *,
    raw_event: str,
    session: str,
    _state: Path | None,
) -> None:
    """Bind an owned start transiently; generic ``MCP:start`` has no owner.

    Cursor 3.20.0 supplies the server key only on afterMCPExecution. Its
    ordinary postToolUse spelling cannot distinguish two servers' start tools.
    Older scoped spellings remain admissible, but conflicting owner fields do
    not. The shared binder still owns strict result IDs and lifecycle locking.
    """

    # A previous owned start may have raced lifecycle recovery. Retry its
    # structural sidecar before any later event observes the old/no mapping;
    # Cursor does not run Codex's handle_session_start pending-write drain.
    with contextlib.suppress(Exception):
        with acquire_session_lock(f"{_CURSOR_SESSION_PREFIX}{session}", _state=_state) as owned:
            if owned:
                apply_pending_mapping(f"{_CURSOR_SESSION_PREFIX}{session}", _state=_state)
    if raw_event not in {"afterMCPExecution", "postToolUse"}:
        return
    tool_name = payload.get("tool_name")
    if type(tool_name) is not str:
        return
    server = payload.get("mcp_server_name")
    expected_server = _CURSOR_START_TOOL_SERVERS.get(tool_name)
    if expected_server is not None:
        if "mcp_server_name" in payload and server != expected_server:
            return
    elif not (
        raw_event == "afterMCPExecution"
        and tool_name == "start"
        and type(server) is str
        and server in _CURSOR_SERVER_KEYS
    ):
        return
    # A post-hook can carry a transport failure even with success-shaped data.
    # Never allow that data to replace a valid mapping.
    if _native_outcome_facts(payload).success is False:
        return
    response = payload.get("result_json" if raw_event == "afterMCPExecution" else "tool_output")
    # Cursor serializes the whole MCP CallToolResult. Decode that outer object
    # before the shared binder unwraps structuredContent or one JSON text block.
    parsed = _bounded_outcome_mapping(response)
    from finishup.cli.hooks import bind_start_mapping_outcome, record_start_bind_diagnostic

    with contextlib.suppress(Exception):
        record_start_bind_diagnostic(
            bind_start_mapping_outcome(
                {
                    "session_id": f"{_CURSOR_SESSION_PREFIX}{session}",
                    "tool_name": "mcp__finishup__start",
                    "tool_response": cast(JsonValue, parsed) if parsed is not None else response,
                },
                _state=_state,
                host="cursor",
            ),
            "PostToolUse",
            _state=_state,
        )


def handle_cursor_observe(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    observation_profile: str | None = None,
    _entry_monotonic: float | None = None,
    _monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Keep passive Cursor observation valid at its pre-tool permission boundary.

    The whole invocation, including the neutral pre-tool permission write, is one timed host hook
    pass (#915).
    """
    import io

    timing = HookPassTiming(
        "cursor",
        event_name or "unknown_event",
        _native_profile_path(observation_profile, CURSOR_ORDINARY_OBSERVATION_PROFILE_ID),
        _monotonic() if _entry_monotonic is None else _entry_monotonic,
    )
    raw_event = event_name
    if event_name is None:
        # Read the same bound the ingress reader applies, so an oversized body
        # reaches it whole and can still keep its identity view (#667).
        stdin_bytes = (
            sys.stdin.buffer.read(MAX_HOOK_SKIM_BYTES + 1) if stdin_bytes is None else stdin_bytes
        )
        with contextlib.suppress(Exception):
            candidate = read_cursor_hook_ingress(stdin_bytes)[0].get("hook_event_name")
            raw_event = candidate if isinstance(candidate, str) else None
        timing.event = raw_event or "unknown_event"
    pre_tool = raw_event == "preToolUse"
    # PreToolUse has no advice delivery: buffer the internal observer's empty
    # output and emit one valid neutral permission response on every path.
    completed = False
    try:
        result = _handle_cursor_observe(
            event_name=event_name,
            stdin_bytes=stdin_bytes,
            stdout=io.BytesIO() if pre_tool else stdout,
            workspace=workspace,
            _state=_state,
            connect=connect,
            run_async=run_async,
            skip_service=skip_service,
            observation_profile=observation_profile,
            _entry_monotonic=_entry_monotonic,
            _pass_timing=timing,
        )
        completed = True
        return result
    except BaseException:
        timing.outcome = "failed"
        raise
    finally:
        try:
            if pre_tool and completed:
                hook_io.stdout_json(_cursor_context_output("preToolUse", ""), stdout)
        finally:
            _finish_hook_pass(timing, monotonic=_monotonic, _state=_state)


def _handle_cursor_observe(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    skip_service: bool = False,
    observation_profile: str | None = None,
    _entry_monotonic: float | None = None,
    _pass_timing: HookPassTiming | None = None,
) -> int:
    """Normalize one Cursor hook into bounded FinishUP observation.

    Cursor supplies prompts, transcript paths, file paths/edits, MCP inputs/results,
    response text, email, and other user-controlled content in the same envelope.
    Structural profiles copy none of those values. The explicit ordinary profile
    admits Cursor's generic tool lifecycle and keeps content behind its separate
    consent arm.
    """

    event_map = {
        "afterFileEdit": "PostToolUse",
        "afterMCPExecution": "PostToolUse",
        "sessionEnd": "SessionEnd",
        "sessionStart": "SessionStart",
        "stop": "Stop",
    }
    ordinary_profile = observation_profile == CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
    if observation_profile is not None and not ordinary_profile:
        with contextlib.suppress(Exception):
            record_hook_diagnostic(
                "observation_profile_invalid", event_name or "unknown_event", _state=_state
            )
        with contextlib.suppress(BaseException):
            hook_io.stdout_json({}, stdout)
        return 0
    if ordinary_profile:
        # Generic tool events own observation. afterMCPExecution is binding-only:
        # it alone supplies the owner of the ordinary ``MCP:start`` tool name.
        event_map.pop("afterFileEdit")
        event_map.update(
            {
                "preToolUse": "PreToolUse",
                "postToolUse": "PostToolUse",
                "postToolUseFailure": "PostToolUse",
            }
        )
    try:
        content_omitted = False
        try:
            payload, content_omitted = read_cursor_hook_ingress(stdin_bytes)
        except CursorOversizedPayloadError as exc:
            # The complete body fit the skim cap and failed a safety check.
            # It must not become a structural row. Name the vendor-shape
            # refusal and the size loss separately (issue #667).
            if exc.reason_code != "payload_too_large":
                with contextlib.suppress(BaseException):
                    record_hook_diagnostic(
                        "cursor_payload_invalid",
                        event_map.get(event_name or "", "unknown_event"),
                        _state=_state,
                    )
                with contextlib.suppress(BaseException):
                    _stderr_line("hook_cursor_observe_degraded: invalid_payload")
            note_payload_too_large(
                event_map.get(event_name or "", "unknown_event"),
                source=ObservationSource.CURSOR_HOOK,
                workspace=workspace,
                _state=_state,
            )
            with contextlib.suppress(BaseException):
                hook_io.stdout_json({}, stdout)
            return 0
        except ProtocolValueError as exc:
            # Cursor emits vendor-shaped decimal durations. Keep malformed host
            # ingress fail-open, but make the dropped event visible through the
            # bounded owner-only diagnostic stream. A body over the skim cap is
            # refused here, before any parse, as payload_too_large (issue #667).
            if exc.reason_code == "payload_too_large":
                note_payload_too_large(
                    event_map.get(event_name or "", "unknown_event"),
                    source=ObservationSource.CURSOR_HOOK,
                    workspace=workspace,
                    _state=_state,
                )
                with contextlib.suppress(BaseException):
                    hook_io.stdout_json({}, stdout)
                return 0
            with contextlib.suppress(BaseException):
                record_hook_diagnostic(
                    "cursor_payload_invalid",
                    event_map.get(event_name or "", "unknown_event"),
                    _state=_state,
                )
            with contextlib.suppress(BaseException):
                _stderr_line("hook_cursor_observe_degraded: invalid_payload")
            with contextlib.suppress(BaseException):
                hook_io.stdout_json({}, stdout)
            return 0

        def finish_without_row() -> int:
            if content_omitted:
                note_payload_too_large(
                    event_map.get(event_name or "", "unknown_event"),
                    source=ObservationSource.CURSOR_HOOK,
                    workspace=workspace,
                    _state=_state,
                )
            return 0 if hook_io.stdout_json({}, stdout) else 0

        raw_event = event_name or payload.get("hook_event_name")
        if type(raw_event) is not str or raw_event not in event_map:
            return finish_without_row()
        session_token = _token_or_none(payload.get("session_id"))
        conversation_token = _token_or_none(payload.get("conversation_id"))
        # One host conversation must stay one FinishUP session (#417). sessionStart
        # validates the pair and persists the alias; later events that carry
        # only the conversation identifier resolve through it, and an event
        # whose pair contradicts the validated alias is an ambiguous transition
        # that is rejected rather than silently splitting the session.
        if session_token is not None and conversation_token is not None:
            aliased = _aliased_cursor_session(conversation_token, _state=_state)
            if raw_event == "sessionStart" or aliased is None:
                if conversation_token != session_token:
                    _bind_cursor_session_alias(conversation_token, session_token, _state=_state)
            elif aliased != session_token:
                with contextlib.suppress(Exception):
                    record_hook_diagnostic(
                        "cursor_session_ambiguous", event_map[raw_event], _state=_state
                    )
                return finish_without_row()
            session = session_token
        elif session_token is None and conversation_token is not None:
            session = (
                _aliased_cursor_session(conversation_token, _state=_state) or conversation_token
            )
        else:
            session = session_token
        if session is None or len(session) > _MAX_TOKEN_CHARS - len(_CURSOR_SESSION_PREFIX):
            return finish_without_row()
        resolved_workspace = _resolve_cursor_workspace(payload, workspace)
        if resolved_workspace is None:
            # No structural envelope is created until the workspace locator
            # is resolved.  In particular, Cursor's workspace_roots list is
            # never forwarded to the observation path or persisted.
            with contextlib.suppress(Exception):
                record_hook_diagnostic(
                    "workspace_unresolvable", event_map[raw_event], _state=_state
                )
            return finish_without_row()
        _bind_cursor_start(payload, raw_event=raw_event, session=session, _state=_state)
        if ordinary_profile and raw_event == "afterMCPExecution":
            # No duplicate structural row, content capture, or advice delivery.
            # This skip is deliberate at every size: the paired postToolUse
            # owns the call, so an oversized body here is not a coverage loss.
            return 0 if hook_io.stdout_json({}, stdout) else 0
        cursor_version = _token_or_none(payload.get("cursor_version"))
        capability_profile_id = (
            CURSOR_ORDINARY_OBSERVATION_PROFILE_ID
            if ordinary_profile
            else _cursor_capability_profile_id(cursor_version)
        )
        pairing_mode, correlation_kind = observation_pairing_contract(
            "cursor", capability_profile_id
        )
        structural: dict[str, JsonValue] = {
            "action": (
                "cursor_file_edit"
                if raw_event == "afterFileEdit"
                else "cursor_mcp"
                if raw_event == "afterMCPExecution"
                else "cursor_lifecycle"
            ),
            "pairing_mode": pairing_mode,
            "correlation_kind": correlation_kind,
            "hook_event_name": event_map[raw_event],
            "session_id": f"{_CURSOR_SESSION_PREFIX}{session}",
        }
        if capability_profile_id is not None:
            structural["capability_profile_id"] = capability_profile_id
        if ordinary_profile:
            structural["mapping_hint"] = CURSOR_ORDINARY_HOOK_MAPPING_VERSION
        loop_count = payload.get("loop_count")
        if raw_event == "stop" and type(loop_count) is int and loop_count > 0:
            # Cursor's own loop guard: this stop follows an earlier follow-up message. It maps to
            # stop_hook_active, so the closure gate treats it as an active Stop: only a new
            # blocker key is re-asked, within the per-turn cap of 2, well under Cursor's own
            # default loop_limit of 5 (#977, #985).
            structural["stop_hook_active"] = True
        identity_fields = (
            (
                ("cursor_version", "cursor_version"),
                ("tool_use_id", "tool_call_id"),
                ("tool_name", "tool_name"),
            )
            if ordinary_profile
            else (
                ("cursor_version", "cursor_version"),
                ("generation_id", "correlation_id"),
                ("tool_name", "tool_name"),
            )
        )
        for source_key, target_key in identity_fields:
            value = _token_or_none(payload.get(source_key))
            if value is not None:
                structural[target_key] = value
        tool_call_id = _token_or_none(payload.get("tool_call_id")) or _token_or_none(
            payload.get("tool_use_id")
        )
        if tool_call_id is not None:
            structural["tool_call_id"] = tool_call_id
        # Cursor's lifecycle payloads use ``model_id`` while execution and file
        # edit payloads use ``model``. Prefer the canonical lifecycle spelling
        # when both are present (they can intentionally differ: e.g. a provider
        # alias in ``model`` and the selected model in ``model_id``).
        model_id = _token_or_none(payload.get("model_id")) or _token_or_none(payload.get("model"))
        if model_id is not None:
            structural["model_id"] = model_id
        if raw_event == "sessionStart":
            source = payload.get("source")
            if type(source) is str and source in _SESSION_START_SOURCES:
                # Preserve the closed lifecycle meaning in the existing
                # structural action. Arbitrary host text remains omitted.
                structural["action"] = f"cursor_session_{source}"
        duration = _int_or_none(payload.get("duration"))
        if duration is not None:
            structural["duration_ms"] = duration
        if ordinary_profile and raw_event in {"postToolUse", "postToolUseFailure"}:
            cursor_tool_name = (_token_or_none(payload.get("tool_name")) or "").lower()
            outcome = _native_outcome_facts(
                payload,
                force_failure=raw_event == "postToolUseFailure",
                require_process_exit=(cursor_tool_name in _SHELL_TOOLS),
                cursor_mcp_result_boundary=cursor_tool_name.startswith(("mcp:", "mcp__")),
            )
            structural["action"] = (
                "cursor_tool_denied"
                if outcome.denied
                else "cursor_tool_success"
                if outcome.success is True
                else "cursor_tool_failure"
                if outcome.success is False
                else "cursor_tool_outcome_unknown"
            )
            if outcome.success is not None:
                structural["success"] = outcome.success
            if outcome.denied:
                structural["denied"] = True
            if outcome.exit_status is not None:
                structural["exit_status"] = outcome.exit_status
            if outcome.result_status is not None:
                structural["result_status"] = outcome.result_status
            if (
                _routine_read_action(payload)
                and outcome.success is not False
                and not outcome.denied
            ):
                structural["action"] = "routine_read"
        elif ordinary_profile and raw_event == "preToolUse":
            structural["action"] = "cursor_tool_pending"
        if event_map[raw_event] == "PostToolUse" and OBSERVED_IMAGES_KEY in payload:
            # Digest-only image facts the ingress reader computed (P3-2, issue #1013).
            structural[OBSERVED_IMAGES_KEY] = payload[OBSERVED_IMAGES_KEY]
        if ordinary_profile and raw_event in {"preToolUse", "postToolUse", "postToolUseFailure"}:
            _attach_command_commitment(structural, payload, _state=_state)
        path_value = payload.get("file_path") if raw_event == "afterFileEdit" else None
        if (
            content_omitted
            and not (type(path_value) is str and path_value)
            and raw_event == "postToolUse"
            and structural.get("action") not in _CURSOR_NON_EDIT_ACTIONS
            and is_edit_tool_name(payload.get("tool_name"))
        ):
            # Only a completed edit tool commits its path. A read, a pending
            # call, or a failed or denied edit changed nothing on disk.
            path_value = _cursor_nested_edit_path(payload)
        if (
            type(path_value) is str
            and path_value
            and (raw_event == "afterFileEdit" or content_omitted)
        ):
            store = LocalObservationStore(_state=_state)
            structural["changed_paths_digest"] = hook_source_commitment(
                store.key_material(), f"cursor-path:{path_value}"
            )
            if raw_event == "afterFileEdit":
                structural.setdefault("tool_name", "cursor_file_edit")
        parameters = payload.get("model_params")
        if type(parameters) is list:
            for item in parameters:
                if isinstance(item, Mapping) and item.get("id") == "effort":
                    effort = _token_or_none(item.get("value"))
                    if effort is not None:
                        structural["model_effort"] = effort
                    break
        # A FinishUP-owned tool in a scoped spelling lost nothing; Cursor's generic
        # ``MCP:<tool>`` spelling names no owner, so it keeps the gap (tb4n1 B5).
        cursor_ingress_gap = (
            _oversized_ingress_gap(
                payload,
                source=ObservationSource.CURSOR_HOOK,
                event=event_map[raw_event],
                _state=_state,
            )
            if content_omitted
            else None
        )
        derived_runner_class = (
            command_runner_class(payload)
            if ordinary_profile and raw_event in {"preToolUse", "postToolUse", "postToolUseFailure"}
            else None
        )
        return handle_observe(
            event_name=event_map[raw_event],
            stdin_bytes=canonical_encode(structural),
            stdout=stdout,
            workspace=resolved_workspace,
            _state=_state,
            connect=connect,
            run_async=run_async,
            skip_service=skip_service,
            _entry_monotonic=_entry_monotonic,
            source=ObservationSource.CURSOR_HOOK,
            _output_event_name=raw_event,
            _content_capture_profile=(
                CURSOR_ORDINARY_OBSERVATION_PROFILE_ID if ordinary_profile else None
            ),
            _content_payload=None if content_omitted or not ordinary_profile else payload,
            _derived_runner_class=derived_runner_class,
            _ingress_gap=cursor_ingress_gap,
            _pass_timing=_pass_timing,
            # The structural envelope drops ``tool_input``; commit to a FinishUP call here so a
            # pending attempt FinishUP rejected can still close as rejected (tb4n5).
            _request_commitment=_finishup_request_commitment(event_map[raw_event], payload),
            # Cursor's ordinary ``MCP:<tool>`` names no server: only the bridge's own record of
            # serving this exact read proves it was FinishUP's (tb4 n5 round 2).
            _proven_finishup_read=_cursor_served_finishup_read(
                event_map[raw_event], payload, _state
            ),
        )
    except BaseException:
        if _pass_timing is not None:
            _pass_timing.outcome = "failed"
        with contextlib.suppress(BaseException):
            hook_io.stdout_json({}, stdout)
        return 0


def handle_spool(
    *,
    event_name: str | None,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
    _entry_monotonic: float | None = None,
    _monotonic: Callable[[], float] = time.monotonic,
) -> int:
    """Append one legacy synchronous ingress record and return immediately.

    No service preflight, local-state hydration, outbox drain, advice refresh,
    or observation-store write occurs on this host-critical path.

    Every pass feeds the bounded timing aggregate (#915); only a hard-cap breach
    also leaves a timing row, so a busy legacy host no longer evicts the
    failure-reason history one row per tool call.
    """

    started = _monotonic() if _entry_monotonic is None else _entry_monotonic
    event = event_name or "observe"
    timing = HookPassTiming("codex", event, "sync_fallback_spool", started)
    try:
        raw = (
            stdin_bytes
            if stdin_bytes is not None
            else sys.stdin.buffer.read(MAX_HOOK_SKIM_BYTES + 1)
        )
        try:
            # The spool keeps only structural fields, so an oversized body's
            # identity view loses nothing it would have kept (tb4n1 B5).
            payload, _content_omitted = read_hook_ingress(raw)
        except (OversizedHookPayloadError, ProtocolValueError) as exc:
            if isinstance(exc, ProtocolValueError) and exc.reason_code != "payload_too_large":
                raise
            note_payload_too_large(
                event, source=ObservationSource.CODEX_HOOK, workspace=workspace, _state=_state
            )
            timing.outcome = "failed"
            return 0
        if workspace is not None and event_name in {
            "PreToolUse",
            "PermissionRequest",
            "PostToolUse",
        }:
            workspace_locator = canonical_workspace_locator(workspace)
            if workspace_locator is None:
                raise ValueError("workspace_locator_invalid")
            from finishup.cli.hooks import with_transcript_child_identity

            # Name a v2 delegated child while this hook still runs in the host's own
            # environment; the service replays the spool later with its own Codex home (#841).
            enriched, identity_conflict = with_transcript_child_identity(
                payload, event_name=event_name
            )
            if identity_conflict is not None:
                record_hook_diagnostic(identity_conflict, event_name, _state=_state)
            spool_payload = dict(enriched)
            # Keep the safe classification, never the host command/input prose.
            if _routine_read_action(payload):
                spool_payload["action"] = "routine_read"
            # The spool keeps no tool input, so commit to the command now (#909).
            _attach_command_commitment(spool_payload, payload, _state=_state)
            HookSpool(_state=_state).append(
                workspace=workspace_locator,
                event_name=event_name,
                payload=spool_payload,
            )
            timing.outcome = "ingested"
    except Exception as failure:
        timing.outcome = "failed"
        record_hook_diagnostic(observe_exception_reason(failure), event, _state=_state)
    finally:
        with contextlib.suppress(Exception):
            hook_io.stdout_json({}, stdout)
        # One measurement, taken after the host's stdout write (the point the
        # host waits for), feeds the breach reason, its row and the aggregate,
        # so they can never disagree about a pass. The p95 target is read from
        # the aggregate over every pass; one leg is a hard breach only after
        # the 500ms ceiling, and only a breach keeps its own row.
        total = _elapsed_ms(started, _monotonic())
        if total > 500:
            record_hook_diagnostic("hook_slo_breached", event, _state=_state)
            record_hook_timing(
                event,
                ms=total,
                stages={"total": total},
                path="sync_fallback_spool",
                _state=_state,
            )
        _finish_hook_pass(timing, monotonic=_monotonic, _state=_state, ms=total)
    return 0
