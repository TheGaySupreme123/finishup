"""Codex lifecycle hook command handlers for the FinishUP CLI."""

from __future__ import annotations

import contextlib
import sys
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from types import MappingProxyType
from typing import BinaryIO, Final, Literal, Protocol, cast

from finishup import __version__
from finishup.adapters.integrations.codex_lifecycle import (
    LifecycleMapping,
    acquire_session_lock,
    apply_pending_mapping,
    encode_frontier_token,
    is_scoped_child_session_id,
    load_mapping,
    mapping_from_start_ids,
    mapping_path,
    queue_mapping_store,
    scoped_child_session_id,
    store_mapping,
    validate_codex_session_id,
)
from finishup.adapters.workspace_binding import canonical_workspace_locator
from finishup.cli.hook_io import (
    MAX_HOOK_STDIN_BYTES,
    read_hook_payload,
)
from finishup.cli.hook_io import (
    context_output as _context_output,
)
from finishup.cli.hook_io import (
    stderr_line as _stderr_line,
)
from finishup.cli.hook_io import (
    stdout_json as _stdout_json,
)
from finishup.cli.render import render_hook_recovery_suffix
from finishup.domain.compaction_recap import RECAP_CONTEXT_LIMIT, RecapFacts
from finishup.domain.finishup_tools import FINISHUP_SCOPED_TOOL_PREFIXES
from finishup.ports.control import ControlClientKind, ControlError, WorkspaceLocator
from finishup.protocol.canonical import JsonValue, strict_json_parse
from finishup.protocol.errors import ProtocolValueError, PublicErrorCode
from finishup.protocol.ids import IdKind, is_valid_id, new_id
from finishup.protocol.models import OperationFailureModel, StatusRequest
from finishup.service.client import connect_service

__all__ = [
    "INACTIVE_CONTEXT",
    "TRANSCRIPT_CHILD_IDENTITY_CONFLICT",
    "FINISHUP_START_TOOL_NAMES",
    "StaleReplacement",
    "StatusOutcome",
    "bind_start_mapping_from_hook",
    "bind_start_mapping_outcome",
    "bound_connector",
    "handle_observe",
    "handle_post_tool_use",
    "handle_session_start",
    "handle_user_prompt_submit",
    "intake_cue_text",
    "read_hook_payload",
    "recover_pending_start_mapping",
    "with_transcript_child_identity",
]


class _StatusClient(Protocol):
    async def status(self, request: StatusRequest, *, deadline_ms: int | None = None) -> object: ...

    async def close(self) -> None: ...


type ServiceConnector = Callable[[ControlClientKind], Awaitable[_StatusClient]]
type AsyncRunner = Callable[[Callable[[], Awaitable[object]]], object]
type StartBindOutcome = Literal[
    "bound",
    "skipped",
    "start_bind_unparsed",
    "start_bind_invalid_ids",
    "start_bind_child_lane_unbound",
    "start_bind_deferred",
    "start_bind_write_failed",
]
type HookHost = Literal["claude", "codex", "cursor"]


@dataclass(frozen=True, slots=True)
class StaleReplacement:
    """The current binding the daemon disclosed for a retired session (`session_superseded`)."""

    task_id: str
    session_id: str
    writer_id: str


@dataclass(frozen=True, slots=True)
class StatusOutcome:
    """One hook status read: a closed kind, the refreshed mapping, and any typed replacement.

    ``kind`` is one of active|stale|workspace_unbound|workspace_mismatch|locked|retry|privacy|
    storage_unsafe|storage_corrupt|unavailable. ``mapping`` is set only for ``active``;
    ``replacement`` only for a ``stale`` answer that carried the superseding ids.
    """

    kind: str
    mapping: LifecycleMapping | None = None
    replacement: StaleReplacement | None = None
    # Set only for an ``active`` read made for a post-compaction start (ADR-044): the facts the
    # same status result carried, plus the declared deliverables when the second read answered.
    recap: RecapFacts | None = None


@dataclass(frozen=True, slots=True)
class PendingMappingRecovery:
    """Result of one bounded replay pass for a session's pending mappings."""

    applied: bool
    pending: bool


@dataclass(frozen=True, slots=True)
class _PendingMappingSnapshot:
    """Validated pending operations for one lane before a producer replays them."""

    present: bool
    operation: tuple[str, LifecycleMapping | None] | None
    # Both marker files can coexist after a crash: ``applying`` is older and
    # ``pending`` is newer.  A different task in the newer marker is an alias
    # reuse conflict and must be refused before either operation is replayed.
    conflicting: bool = False


_STATUS_DEADLINE_MS: Final = 5_000
_INTAKE_CUE_BYTES: Final = 512
_MAX_PENDING_MAPPING_REPLAYS: Final = 8

# ``start`` as a Codex or Claude Code hook names it, under the current and the legacy server
# name a 0.1-0.2.5 registration still carries (ADR-048).
FINISHUP_START_TOOL_NAMES: Final = frozenset(
    {"start", *(f"{prefix}start" for prefix in FINISHUP_SCOPED_TOOL_PREFIXES)}
)
_STARTUP_RECOVERY_CONTEXT: Final = (
    "If start fails, follow exact continuations and same-request recovery first, including a "
    "named one-time repair. If startup remains blocked without an applicable recovery path, "
    "ask the user for intro and guidance; do not invent a workflow or continue without a ledger "
    "task outside the documented optional-service fallback."
)
INACTIVE_CONTEXT: Final = (
    "No FinishUP task is mapped to this session; call start before substantive material work. "
    "Guidance reads, tool/schema discovery, and necessary bootstrap clarification come first. "
    + _STARTUP_RECOVERY_CONTEXT
)
_UNAVAILABLE_CONTEXT: Final = (
    "FinishUP service is unavailable for this mapped session; no live receipt can be promised."
)
_LOCKED_CONTEXT: Final = (
    "FinishUP vault is locked for this mapped session; no live receipt can be promised."
    + render_hook_recovery_suffix("vault_locked")
)


def _stale_mapping_context(
    mapping: LifecycleMapping, replacement: StaleReplacement | None = None
) -> str:
    if replacement is None:
        return (
            "FinishUP task mapping for this session is stale: the task was re-started under new "
            "session and writer ids. The service itself is healthy. Call start with mode=attach "
            f"and session_id {mapping.finishup_session_id} (task {mapping.finishup_task_id}) to "
            "continue the same task. Do not open a new task with a different external_ref."
        )
    # The daemon named the superseding binding (`session_superseded`, #578): an agent that
    # already holds those ids continues with them; one that does not re-binds by the retired
    # session selector. Either way the same task continues and no sibling is created.
    return (
        "FinishUP task mapping for this session is stale: the task was re-started under new "
        "session and writer ids. The service itself is healthy. The current binding for task "
        f"{replacement.task_id} is session_id {replacement.session_id} and writer_id "
        f"{replacement.writer_id}; if you hold those ids, continue with them. Otherwise call "
        f"start with mode=attach and session_id {mapping.finishup_session_id} to continue the same "
        "task. Do not open a new task with a different external_ref."
    )


# A resume/compact status read refused by the daemon's repository fence (#578). Both are
# answered by a healthy service about a live mapping, so neither advisory may steer the agent
# into a re-attach that would rotate the session and strand pending observation rows.
_WORKSPACE_UNBOUND_CONTEXT: Final = (
    "FinishUP could not verify the repository of this mapped session because the hook connected "
    "without a project workspace (status_workspace_unbound). The mapping is not stale and the "
    "service is healthy; do not re-attach. Call status from the project directory before "
    "further material work."
)
_WORKSPACE_MISMATCH_CONTEXT: Final = (
    "FinishUP refused the status read for this mapped session because the hook's workspace "
    "resolves to a different repository than the mapped task (status_workspace_mismatch). The "
    "mapping is not stale and the service is healthy; do not re-attach. Call status from the "
    "task's own repository before further material work."
)


_RETRY_CONTEXT: Final = (
    "FinishUP is busy and could not read status on this attempt; the service is reachable. "
    "Call status before promising a receipt."
)
_PRIVACY_CONTEXT: Final = (
    "FinishUP cannot read this mapped session until repository privacy authority is "
    "granted; run 'finishup --privacy'. No live receipt can be promised until then."
)
# The two storage outcomes carry opposite retry advice, so folding both into
# "unavailable" left an agent unable to tell a fault it may retry from data it
# must not keep writing to (#338). Both stay bounded and payload-free.
_STORAGE_UNSAFE_CONTEXT: Final = (
    "FinishUP storage faulted while reading this mapped session (storage_unsafe): the "
    "service is reachable and the stored data is not known to be damaged. Retry status "
    "once before promising a receipt; if it repeats, report it to the operator."
)
_STORAGE_CORRUPT_CONTEXT: Final = (
    "FinishUP stored data for this mapped session is invalid (storage_corrupt). Do not "
    "retry and do not promise a receipt; stop material work on this task and escalate "
    "to the operator, who can inspect it with 'finishup status'."
)

# Hook-side classification of every public error a status read can surface. The
# daemon answering with SESSION_* means the stored mapping no longer names a live
# route/writer — the service is healthy, so reporting it "unavailable" was false
# and absorbing (issue #308). "retry" codes are transient reads that can succeed
# on the next attempt; only genuinely degraded states remain "unavailable".
# The two storage codes keep their own classes because they prescribe opposite
# next steps (#338): "storage_unsafe" is a fault that may be retried,
# "storage_corrupt" is invalid data that must not be.
# `SESSION_CONFLICT` is refined by its closed reason before this table applies (#578): the
# repository fence's `repository_identity_required` / `repository_identity_mismatch` name a
# probe the daemon could not bind to a repository, not a replaced session, and classify as
# `workspace_unbound` / `workspace_mismatch` below. A conflict without such a reason (writer
# route replaced) and `SESSION_NOT_FOUND` (`session_superseded` or absent) remain `stale`.
_STATUS_ERROR_CLASSES: Final[Mapping[PublicErrorCode, str]] = MappingProxyType(
    {
        PublicErrorCode.SESSION_NOT_FOUND: "stale",
        PublicErrorCode.SESSION_CONFLICT: "stale",
        PublicErrorCode.VAULT_LOCKED: "locked",
        PublicErrorCode.OPERATION_PENDING: "retry",
        PublicErrorCode.BUNDLE_BUSY: "retry",
        PublicErrorCode.FRONTIER_CONFLICT: "retry",
        PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED: "privacy",
        PublicErrorCode.INVALID_REQUEST: "unavailable",
        PublicErrorCode.PROTOCOL_VERSION_UNSUPPORTED: "unavailable",
        PublicErrorCode.IDEMPOTENCY_CONFLICT: "unavailable",
        PublicErrorCode.REQUEST_IDENTITY_CONFLICT: "unavailable",
        PublicErrorCode.EVENT_INVALID: "unavailable",
        PublicErrorCode.LIMIT_EXCEEDED: "unavailable",
        PublicErrorCode.STORAGE_UNSAFE: "storage_unsafe",
        PublicErrorCode.STORAGE_CORRUPT: "storage_corrupt",
        PublicErrorCode.MIGRATION_REQUIRED: "unavailable",
        PublicErrorCode.SERVICE_UNAVAILABLE: "unavailable",
        PublicErrorCode.PROVIDER_UNAVAILABLE: "unavailable",
        PublicErrorCode.PROVIDER_REFUSED: "unavailable",
        PublicErrorCode.PROVIDER_TIMEOUT: "unavailable",
        PublicErrorCode.SEMANTIC_RESULT_INVALID: "unavailable",
        PublicErrorCode.CANCELLED: "unavailable",
        PublicErrorCode.INTERNAL_ERROR: "unavailable",
    }
)
if set(_STATUS_ERROR_CLASSES) != set(PublicErrorCode):
    raise RuntimeError("status_error_classes_not_exhaustive")

_FENCE_REASON_CLASSES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "repository_identity_required": "workspace_unbound",
        "repository_identity_mismatch": "workspace_mismatch",
    }
)


def _failure_reason_and_details(
    failure: OperationFailureModel,
) -> tuple[str | None, Mapping[str, object] | None]:
    details = getattr(failure.error, "safe_details", None)
    if not isinstance(details, Mapping):
        return None, None
    typed = cast(Mapping[str, object], details)
    reason = typed.get("reason_code")
    return (reason if type(reason) is str else None), typed


def _replacement_from_details(details: Mapping[str, object]) -> StaleReplacement | None:
    task_id = details.get("task_id")
    session_id = details.get("session_id")
    writer_id = details.get("writer_id")
    if type(task_id) is not str or type(session_id) is not str or type(writer_id) is not str:
        return None
    if not (
        is_valid_id(IdKind.TASK, task_id)
        and is_valid_id(IdKind.SESSION, session_id)
        and is_valid_id(IdKind.WRITER, writer_id)
    ):
        return None
    return StaleReplacement(task_id=task_id, session_id=session_id, writer_id=writer_id)


def _classify_status_failure(failure: OperationFailureModel) -> StatusOutcome:
    """Map one public status failure to its hook class, refining by closed reason code."""

    kind = _STATUS_ERROR_CLASSES.get(failure.error.code, "unavailable")
    reason, details = _failure_reason_and_details(failure)
    if (
        failure.error.code is PublicErrorCode.SESSION_CONFLICT
        and reason is not None
        and reason in _FENCE_REASON_CLASSES
    ):
        return StatusOutcome(_FENCE_REASON_CLASSES[reason])
    if (
        failure.error.code is PublicErrorCode.SESSION_NOT_FOUND
        and reason == "session_superseded"
        and details is not None
    ):
        return StatusOutcome("stale", replacement=_replacement_from_details(details))
    return StatusOutcome(kind)


# Transport-level failures, classified over the closed ControlError reason set.
# Reasons absent here (a future addition) fall back to "unavailable".
_CONTROL_ERROR_CLASSES: Final[Mapping[str, str]] = MappingProxyType(
    {
        # Coordination command refusals are bounded, non-retryable input or authority
        # conditions.  A hook status read cannot repair them, so keep them in the
        # unavailable bucket rather than pretending a retry will change the command.
        "coordination_invalid": "unavailable",
        "project_not_found": "unavailable",
        "project_dissolved": "unavailable",
        "implicit_project_requires_opt_out": "unavailable",
        "general_project_membership_conflict": "unavailable",
        "project_member_not_found": "unavailable",
        "selector_conflict": "unavailable",
        "coordination_consent_required": "unavailable",
        "coordination_source_policy_denied": "unavailable",
        "coordination_grant_required": "unavailable",
        "coordination_generation_revoked": "unavailable",
        "coordination_generation_mismatch": "unavailable",
        "cross_repository_lineage_requires_grant": "unavailable",
        "project_member_already_unbound": "unavailable",
        "vault_locked": "locked",
        "request_timeout": "retry",
        "service_draining": "retry",
        "service_generation_changed": "retry",
        "read_projection_failed": "retry",
        "response_projection_failed": "retry",
        "privacy_projection_unavailable": "retry",
        "privacy_projection_blocked": "privacy",
        "privacy_audit_unreadable": "unavailable",
        "service_unavailable": "unavailable",
        "service_incompatible": "unavailable",
        "peer_untrusted": "unavailable",
        "endpoint_unsafe": "unavailable",
        "protocol_mismatch": "unavailable",
        "frame_invalid": "unavailable",
        "frame_too_large": "unavailable",
        "invalid_request": "unavailable",
        "request_cancelled": "unavailable",
        "method_forbidden": "unavailable",
        "internal_error": "unavailable",
    }
)


def intake_cue_text(*, resource_root: Path | None = None) -> str:
    """Return the first-512-byte intake cue from packaged agent instructions."""

    if resource_root is not None:
        data = (resource_root / "guidance" / "agent-instructions.md").read_bytes()
    else:
        node = resources.files("finishup.resources")
        for part in ("guidance", "agent-instructions.md"):
            node = node.joinpath(part)
        data = node.read_bytes()
    cue = data[:_INTAKE_CUE_BYTES].decode("utf-8", errors="strict")
    # Prefer a clean paragraph boundary inside the first 512 UTF-8 bytes.
    cut = cue.rfind("\n\n")
    if cut > 64:
        cue = cue[:cut].rstrip()
    return cue.strip()


def handle_user_prompt_submit(
    *,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    resource_root: Path | None = None,
    _state: Path | None = None,
    workspace: str | None = None,
) -> int:
    """Inject the materiality/activation cue; route structural facts through observe."""

    try:
        raw = (
            stdin_bytes
            if stdin_bytes is not None
            else sys.stdin.buffer.read(MAX_HOOK_STDIN_BYTES + 1)
        )
        _ = read_hook_payload(raw)
        cue = intake_cue_text(resource_root=resource_root)
        # Compatibility: keep trigger cue, then best-effort structural observe.
        from finishup.cli.observe_hooks import handle_observe

        observe_out = __import__("io").BytesIO()
        handle_observe(
            event_name="UserPromptSubmit",
            stdin_bytes=raw,
            stdout=observe_out,
            workspace=workspace,
            _state=_state,
            skip_service=False,
        )
        _stdout_json(_context_output("UserPromptSubmit", cue), stdout)
        return 0
    except Exception as exc:
        _note_oversize_hook_ingress(exc, "UserPromptSubmit", workspace=workspace, _state=_state)
        _stderr_line("hook_degraded: user-prompt-submit")
        try:
            cue = intake_cue_text(resource_root=resource_root)
            _stdout_json(_context_output("UserPromptSubmit", cue), stdout)
        except Exception:
            _stdout_json(_context_output("UserPromptSubmit", INACTIVE_CONTEXT), stdout)
        return 0


def _note_oversize_hook_ingress(
    exc: BaseException,
    event: str,
    *,
    workspace: str | None,
    _state: Path | None,
) -> None:
    """Route a Codex hook body refused for size into observation accounting.

    These entry points parse the host body themselves before handing the same
    bytes to the observation ingress, so an oversized event never reaches
    ``handle_observe`` and their degraded branch could only say that the hook
    had failed — not that an event's worth of work went unobserved (#667).
    """

    if not isinstance(exc, ProtocolValueError) or exc.reason_code != "payload_too_large":
        return
    with contextlib.suppress(Exception):
        from finishup.cli.observe_hooks import note_payload_too_large
        from finishup.domain.observation import ObservationSource

        note_payload_too_large(
            event,
            source=ObservationSource.CODEX_HOOK,
            workspace=workspace,
            _state=_state,
        )


def _as_mapping(value: object) -> Mapping[str, JsonValue] | None:
    if isinstance(value, Mapping):
        return cast(Mapping[str, JsonValue], value)
    return None


def _parse_bounded_result_text(text: object) -> Mapping[str, JsonValue] | None:
    """Parse one bounded strict-JSON object; unwrap a serialized structured result."""

    if type(text) is not str:
        return None
    encoded = text.encode("utf-8")
    if not encoded or len(encoded) > MAX_HOOK_STDIN_BYTES:
        return None
    try:
        candidate = _as_mapping(strict_json_parse(encoded))
    except Exception:
        return None
    if candidate is None:
        return None
    structured = candidate.get("structuredContent")
    if structured is None:
        structured = candidate.get("structured_content")
    if structured is not None:
        return _as_mapping(structured)
    return candidate


def _extract_start_result(tool_response: object) -> Mapping[str, JsonValue] | None:
    """Return the parsed start result object in any admitted host shape, else ``None``.

    Three shapes are admitted, each bounded and inspected transiently:

    1. an object carrying ``structuredContent`` (Codex), or a bare result object;
    2. a single-text-block content list whose text is the strict-JSON result;
    3. a bare JSON string of the structured result — the shape Claude Code 2.1.251 passes as
       ``tool_response`` for MCP tools (captured live 2026-09-04, issue #581); the earlier
       binder rejected it, so a successful scoped ``start`` never re-bound the session.

    Whether the result is a success is the caller's decision, so a refused ``start`` can be
    told apart from an unadmitted shape.
    """

    mapping = _as_mapping(tool_response)
    if mapping is not None:
        structured = mapping.get("structuredContent")
        if structured is None:
            structured = mapping.get("structured_content")
        if structured is not None:
            return _as_mapping(structured)
        if "content" not in mapping:
            return mapping
        content = mapping.get("content")
    elif type(tool_response) is str:
        return _parse_bounded_result_text(tool_response)
    else:
        content = tool_response

    if type(content) is not list:
        return None
    content_blocks = cast(list[object], content)
    if len(content_blocks) != 1:
        return None
    block = _as_mapping(content_blocks[0])
    if block is None or block.get("type") != "text":
        return None
    return _parse_bounded_result_text(block.get("text"))


def _frontier_from_start(result: Mapping[str, JsonValue]) -> str | None:
    frontier = result.get("frontier")
    frontier_map = _as_mapping(frontier)
    if frontier_map is None:
        return None
    sequence = frontier_map.get("sequence")
    digest = frontier_map.get("head_digest")
    if type(sequence) is not str or type(digest) is not str:
        return None
    try:
        return encode_frontier_token(sequence=sequence, head_digest=digest)
    except ProtocolValueError:
        return None


def _child_identity_from_payload(
    payload: Mapping[str, JsonValue],
) -> tuple[str | None, bool, bool]:
    """Return one consistent native child identity without choosing through a conflict.

    The host adapters have emitted three spellings for this identity.  A present ``null`` is
    treated as an absent value, while a malformed value or contradictory non-null aliases is
    invalid.  Callers may still use a service returned child task as a separate bounded route;
    this helper only reports the host-supplied identity fact.
    """

    values: list[str] = []
    supplied = False
    nested = payload.get("tool_input")
    nested_payload: Mapping[str, JsonValue] = (
        cast(Mapping[str, JsonValue], nested) if isinstance(nested, Mapping) else {}
    )
    for name in ("subagent_id", "agent_id", "agent_thread_id"):
        for aliases in (payload, nested_payload):
            if name not in aliases:
                continue
            supplied = True
            value = aliases.get(name)
            if value is None:
                continue
            try:
                token = validate_codex_session_id(value)
            except ProtocolValueError:
                return None, supplied, False
            values.append(token)
    if any(value != values[0] for value in values[1:]):
        return None, supplied, False
    return (values[0] if values else None), supplied, True


# Callback families that describe work performed by the thread that invoked the hook. Session and
# lineage lifecycle events stay host-session signals and are never re-attributed from a transcript.
_TRANSCRIPT_CHILD_IDENTITY_EVENTS: Final = frozenset(
    {
        "PreToolUse",
        "PostToolUse",
        "PermissionRequest",
        "UserPromptSubmit",
        "Stop",
        "PreCompact",
        "PostCompact",
    }
)
# The empty string is never a valid host token, so every child-identity reader treats it as a
# supplied but malformed alias. That turns a contradicted callback into an explicit attribution
# gap without letting it inherit the host session's route.
_CONTRADICTED_CHILD_IDENTITY: Final = ""
TRANSCRIPT_CHILD_IDENTITY_CONFLICT: Final = "child_transcript_identity_conflict"


def with_transcript_child_identity(
    payload: Mapping[str, JsonValue],
    *,
    event_name: str,
    codex_home: Path | None = None,
) -> tuple[Mapping[str, JsonValue], str | None]:
    """Name the delegated child a Codex callback came from when only its transcript says so.

    Codex multi-agent v2 gives every thread of one delegation tree the root ``session_id``, so a
    delegated child's own tool and turn callbacks arrive under the parent's session. Before #841
    such a callback without a host child alias was indistinguishable from the parent's own work:
    the child's attach could not publish its child lane (``start_bind_child_lane_unbound``), its
    command and file evidence and advice landed on the parent lane, and the provisional host
    annotation was never bound. The callback's own ``transcript_path`` (or ``session_file``) is
    the host's record of the thread that raised it. When that file is not the session's own
    rollout and its v2 header names a delegated child spawned by this session, the header's child
    thread is the callback's host child identity, exactly as a native ``agent_id`` would be.

    The payload is returned unchanged when the transcript is the session's own, absent, unsafe,
    or not a delegated-child rollout, so nothing is inferred from an unprovable file. A transcript
    that proves the callback came from a delegated child but cannot name it for this session, or
    that contradicts a host-supplied child alias, marks the child identity malformed: the
    callback becomes an explicit attribution gap and the second member reports
    ``child_transcript_identity_conflict``. Only bounded thread tokens are read; the path is
    never persisted, and no task, route, or annotation is selected here.
    """

    if event_name not in _TRANSCRIPT_CHILD_IDENTITY_EVENTS:
        return payload, None
    try:
        host_session_id = validate_codex_session_id(payload.get("session_id"))
    except ProtocolValueError:
        return payload, None
    raw_path = payload.get("session_file") or payload.get("transcript_path")
    if type(raw_path) is not str or not raw_path or "\0" in raw_path:
        return payload, None
    from finishup.adapters.integrations.codex_session_stream import (
        CodexSessionStreamLocator,
        resolve_codex_home,
    )

    # A ``session_id_rollout_id`` filename also matches a parent session whose id prefixes a
    # child id containing ``_``. Let the bounded header reader distinguish those cases.
    _path, result = CodexSessionStreamLocator(resolve_codex_home(codex_home)).resolve_child_rollout(
        raw_path
    )
    if result.status in {"not_child", "unreadable"}:
        return payload, None
    host_identity, identity_supplied, identity_valid = _child_identity_from_payload(payload)
    if identity_supplied and not identity_valid:
        # Already an explicit gap; a transcript cannot repair a contradictory host alias.
        return payload, None
    header = result.header
    derived = (
        header.child_thread_id
        if header is not None and host_session_id in header.spawning_sessions
        else None
    )
    enriched = dict(payload)
    if derived is None or (host_identity is not None and host_identity != derived):
        enriched["subagent_id"] = _CONTRADICTED_CHILD_IDENTITY
        return enriched, TRANSCRIPT_CHILD_IDENTITY_CONFLICT
    if host_identity == derived:
        return payload, None
    enriched["subagent_id"] = derived
    return enriched, None


def _mapping_for_lane(
    lane_id: str,
    *,
    task_id: str,
    session_id: str,
    writer_id: str,
    last_frontier: str | None,
) -> LifecycleMapping:
    return mapping_from_start_ids(
        codex_session_id=lane_id,
        finishup_task_id=task_id,
        finishup_session_id=session_id,
        finishup_writer_id=writer_id,
        last_frontier=last_frontier,
    )


def _pending_mapping_snapshot(
    codex_session_id: str, *, _state: Path | None
) -> _PendingMappingSnapshot:
    """Inspect a queued lane operation without applying it.

    Child start binding may publish more than one derived lane.  Applying a queued
    operation while preflighting the first lane can make a later ownership conflict
    observable as a partial child bind.  Read the adapter's validated pending record
    first; the caller already holds the lane lock and decides whether replay is safe
    only after every target has passed its ownership check.
    """

    try:
        mapping = mapping_path(codex_session_id, _state=_state)
        pending = mapping.parent / f".{codex_session_id}.pending.json"
        applying = pending.with_name(pending.name + ".applying")
        from finishup.adapters.integrations.codex_lifecycle import (
            _load_pending_mapping_operation,  # pyright: ignore[reportPrivateUsage]
        )

        candidates = tuple(
            candidate
            for candidate in (applying, pending)
            if candidate.exists() or candidate.is_symlink()
        )
        if not candidates:
            return _PendingMappingSnapshot(False, None)
        operations = tuple(
            _load_pending_mapping_operation(
                codex_session_id,
                _state=_state,
                claimed_path=candidate,
            )
            for candidate in candidates
        )
        # ``.applying`` is the older claimed operation and is the one the adapter
        # will replay first when both files are present.  An unreadable marker is
        # intentionally not interpreted as ownership; the caller defers it.
        primary = operations[0]
        if len(operations) == 1:
            return _PendingMappingSnapshot(True, primary)
        if primary is None or operations[1] is None:
            return _PendingMappingSnapshot(True, None)
        first_kind, first_mapping = primary
        second_kind, second_mapping = operations[1]
        conflicting = False
        if first_kind != second_kind:
            # A clear followed by a store can be a valid FIFO sequence, but a
            # producer cannot safely decide which intent it is observing here;
            # defer it and let the normal recovery owner drain the queue.
            return _PendingMappingSnapshot(True, None)
        elif first_kind == "store" and second_kind == "store":
            if first_mapping is None or second_mapping is None:
                return _PendingMappingSnapshot(True, None)
            conflicting = first_mapping.finishup_task_id != second_mapping.finishup_task_id
        return _PendingMappingSnapshot(True, primary, conflicting=conflicting)
    except Exception:
        # An unreadable marker is still a pending lifecycle fact.  Fail closed so
        # the caller does not replace a lane whose ownership it could not inspect.
        return _PendingMappingSnapshot(True, None)


def _persist_start_mappings(
    mappings: tuple[LifecycleMapping, ...], *, _state: Path | None
) -> StartBindOutcome:
    """Persist lane mappings after an all-lane ownership preflight."""

    unique: dict[str, LifecycleMapping] = {}
    for mapping in mappings:
        prior = unique.get(mapping.codex_session_id)
        if prior is not None and prior != mapping:
            return "start_bind_child_lane_unbound"
        unique[mapping.codex_session_id] = mapping
    ordered = tuple(sorted(unique.values(), key=lambda candidate: candidate.codex_session_id))
    if not ordered:
        return "start_bind_child_lane_unbound"
    try:
        with contextlib.ExitStack() as locks:
            owned: list[bool] = []
            for mapping in ordered:
                owned.append(
                    locks.enter_context(
                        acquire_session_lock(mapping.codex_session_id, _state=_state)
                    )
                )
            if not all(owned):
                # Every current child bind is one derived host lane.  Queueing that
                # one lane preserves a retry intent when its lifecycle lock is held
                # by another hook.  Multi-lane callers still defer as a unit because
                # the pending-file protocol has no cross-file transaction marker.
                if len(ordered) == 1:
                    candidate = ordered[0]
                    if is_scoped_child_session_id(candidate.codex_session_id):
                        # We cannot take the lock to make a race-free ownership
                        # decision, but we can reject an already visible conflicting
                        # owner.  The replay primitive repeats this fence while the
                        # eventual owner holds the lock.
                        current_path = mapping_path(candidate.codex_session_id, _state=_state)
                        current = load_mapping(candidate.codex_session_id, _state=_state)
                        if (current_path.exists() or current_path.is_symlink()) and (
                            current is None
                        ):
                            return "start_bind_deferred"
                        snapshot = _pending_mapping_snapshot(
                            candidate.codex_session_id, _state=_state
                        )
                        if snapshot.conflicting:
                            return "start_bind_child_lane_unbound"
                        if snapshot.present:
                            if snapshot.operation is None:
                                return "start_bind_deferred"
                            operation, queued = snapshot.operation
                            if operation != "store" or queued is None:
                                return "start_bind_deferred"
                            if queued.finishup_task_id != candidate.finishup_task_id:
                                return "start_bind_child_lane_unbound"
                        if (
                            current is not None
                            and current.finishup_task_id != candidate.finishup_task_id
                        ):
                            return "start_bind_child_lane_unbound"
                    queue_mapping_store(candidate, _state=_state)
                return "start_bind_deferred"

            pending_states: list[_PendingMappingSnapshot] = []
            existing: list[LifecycleMapping | None] = []
            for mapping in ordered:
                pending_states.append(
                    _pending_mapping_snapshot(mapping.codex_session_id, _state=_state)
                )
                existing.append(load_mapping(mapping.codex_session_id, _state=_state))
            # A queued operation is part of the ownership state even when its mapping
            # file has not been applied yet.  Inspect every target before replaying or
            # queueing any operation; otherwise a stale host alias can cause its task
            # alias to become a partial, routable bind.
            for mapping, snapshot, prior in zip(ordered, pending_states, existing, strict=True):
                if snapshot.present:
                    if snapshot.conflicting:
                        if is_scoped_child_session_id(mapping.codex_session_id):
                            return "start_bind_child_lane_unbound"
                        return "start_bind_deferred"
                    if snapshot.operation is None:
                        return "start_bind_deferred"
                    operation, queued = snapshot.operation
                    if operation != "store" or queued is None:
                        return "start_bind_deferred"
                    if is_scoped_child_session_id(mapping.codex_session_id) and (
                        queued.finishup_task_id != mapping.finishup_task_id
                    ):
                        return "start_bind_child_lane_unbound"
                if not is_scoped_child_session_id(mapping.codex_session_id):
                    continue
                if prior is not None and prior.finishup_task_id != mapping.finishup_task_id:
                    return "start_bind_child_lane_unbound"

            # Replay only after the complete ownership preflight.  Re-read the files
            # after replay because a queued mapping may be the first materialized
            # owner of a child alias.
            for mapping, snapshot in zip(ordered, pending_states, strict=True):
                if not snapshot.present:
                    continue
                if recover_pending_start_mapping(
                    mapping.codex_session_id,
                    _state=_state,
                    _session_lock_owned=True,
                ).pending:
                    return "start_bind_deferred"
            for mapping in ordered:
                if not is_scoped_child_session_id(mapping.codex_session_id):
                    continue
                prior = load_mapping(mapping.codex_session_id, _state=_state)
                if prior is not None and prior.finishup_task_id != mapping.finishup_task_id:
                    return "start_bind_child_lane_unbound"

            for mapping in ordered:
                # Queue the owner result before replaying the lane. If another producer queued
                # while this call was classifying, this durable write coalesces that intent.
                queue_mapping_store(mapping, _state=_state)
            for mapping in ordered:
                recovery = recover_pending_start_mapping(
                    mapping.codex_session_id,
                    _state=_state,
                    _session_lock_owned=True,
                )
                if recovery.pending:
                    return "start_bind_deferred"
    except Exception:
        return "start_bind_write_failed"
    return "bound"


def _mapping_state_before_start(
    codex_session_id: str, *, _state: Path | None
) -> tuple[LifecycleMapping | None, bool]:
    """Read a host lane after reconciling its pending start operation when possible."""

    try:
        with acquire_session_lock(codex_session_id, _state=_state) as owned:
            if owned:
                recover_pending_start_mapping(
                    codex_session_id,
                    _state=_state,
                    _session_lock_owned=True,
                )
            mapping = load_mapping(codex_session_id, _state=_state)
            path = mapping_path(codex_session_id, _state=_state)
            pending = path.parent / f".{codex_session_id}.pending.json"
            applying = pending.with_name(pending.name + ".applying")
            return mapping, (not owned) or any(
                item.exists() or item.is_symlink() for item in (pending, applying)
            )
    except Exception:
        # An unreadable lock or pending marker cannot establish that the raw
        # lane is free. Treat it as pending so a child result never replaces a
        # parent mapping on an uncertain read.
        return load_mapping(codex_session_id, _state=_state), True


def cooperative_start_identity(payload: Mapping[str, JsonValue]) -> dict[str, JsonValue]:
    """Extract only service-returned child lineage facts from an owned start callback.

    These are correlation candidates, never routing authority. The observation service must
    compare them with its already admitted child route and persisted parent relationship.
    """

    if payload.get("tool_name") not in FINISHUP_START_TOOL_NAMES:
        return {}
    result = _extract_start_result(payload.get("tool_response"))
    if result is None or result.get("ok") is not True or result.get("outcome") == "delegated":
        return {}
    fields: dict[str, JsonValue] = {}
    for name, kind in (
        ("task_id", IdKind.TASK),
        ("session_id", IdKind.SESSION),
        ("writer_id", IdKind.WRITER),
        ("parent_task_id", IdKind.TASK),
    ):
        value = result.get(name)
        if type(value) is not str or not is_valid_id(kind, value):
            return {}
        target = "lineage_parent_task_id" if name == "parent_task_id" else "lineage_child_" + name
        fields[target] = value
    if fields["lineage_child_task_id"] == fields["lineage_parent_task_id"]:
        return {}
    return fields


def bind_start_mapping_outcome(
    payload: Mapping[str, JsonValue],
    *,
    _state: Path | None = None,
    host: HookHost = "codex",
) -> StartBindOutcome:
    """Persist a validated mapping from one exact successful start hook result.

    The host response is inspected transiently. Only task/session/writer ids and
    the optional frontier token enter lifecycle storage. ``skipped`` means there
    was nothing to bind (not a start tool, or a start the service refused); the
    ``start_bind_*`` outcomes are closed hook-diagnostic reasons for a scoped
    successful start that produced no mapping (issue #581).
    """

    tool_name = payload.get("tool_name")
    if type(tool_name) is not str or tool_name not in FINISHUP_START_TOOL_NAMES:
        return "skipped"
    if host not in {"claude", "codex", "cursor"}:
        return "start_bind_invalid_ids"
    try:
        codex_session_id = validate_codex_session_id(payload.get("session_id"))
    except ProtocolValueError:
        return "start_bind_invalid_ids"
    result = _extract_start_result(payload.get("tool_response"))
    if result is None:
        return "start_bind_unparsed"
    if result.get("ok") is False:
        return "skipped"
    if result.get("ok") is not True:
        return "start_bind_unparsed"
    outcome = result.get("outcome")
    if outcome is not None and type(outcome) is not str:
        return "start_bind_invalid_ids"
    task_id = result.get("task_id")
    # A delegated start returns the newly reserved child task while its session and writer
    # remain the parent's until the child consumes the attach handle.  Mapping that response as
    # ``(child_task_id, parent_session_id, parent_writer_id)`` strands the parent's observation
    # lane at the next hook.  The service-returned parent_task_id is the explicit ownership fact;
    # use it for this host-session mapping and leave child attachment to its own start result.
    delegated = outcome == "delegated"
    parent_task_id = result.get("parent_task_id")
    if parent_task_id is not None and (
        type(parent_task_id) is not str or not is_valid_id(IdKind.TASK, parent_task_id)
    ):
        return "start_bind_invalid_ids"
    if delegated:
        delegated_parent_task_id = result.get("parent_task_id")
        if type(delegated_parent_task_id) is not str:
            return "start_bind_invalid_ids"
        task_id = delegated_parent_task_id
    session_id = result.get("session_id")
    writer_id = result.get("writer_id")
    if type(task_id) is not str or type(session_id) is not str or type(writer_id) is not str:
        return "start_bind_invalid_ids"
    try:
        result_mapping = _mapping_for_lane(
            codex_session_id,
            task_id=task_id,
            session_id=session_id,
            writer_id=writer_id,
            last_frontier=_frontier_from_start(result),
        )
    except ProtocolValueError, TypeError, ValueError:
        return "start_bind_invalid_ids"
    existing, parent_pending = _mapping_state_before_start(codex_session_id, _state=_state)
    child_identity, identity_supplied, identity_valid = _child_identity_from_payload(payload)
    child_lineage = parent_task_id is not None and not delegated
    targets: list[LifecycleMapping] = []

    if delegated:
        # Delegation reserves a child but keeps the returned session/writer on the owner that
        # requested the reservation.  A shared host session therefore remains on its current
        # mapping.  A nested child delegate can select its already validated child lane by the
        # host identity; an ambiguous identity must never consume the parent's mapping.
        assert parent_task_id is not None
        if type(result.get("task_id")) is not str or not is_valid_id(
            IdKind.TASK, result.get("task_id")
        ):
            return "start_bind_invalid_ids"
        if parent_pending:
            return "start_bind_deferred"
        if identity_supplied and not identity_valid:
            return "start_bind_child_lane_unbound"
        if existing is None or existing.finishup_task_id == parent_task_id:
            targets.append(
                _mapping_for_lane(
                    codex_session_id,
                    task_id=parent_task_id,
                    session_id=session_id,
                    writer_id=writer_id,
                    last_frontier=result_mapping.last_frontier,
                )
            )
        elif identity_valid and child_identity is not None:
            try:
                child_lane = scoped_child_session_id(
                    codex_session_id,
                    host=host,
                    identity=child_identity,
                    identity_kind="host",
                )
                targets.append(
                    _mapping_for_lane(
                        child_lane,
                        task_id=parent_task_id,
                        session_id=session_id,
                        writer_id=writer_id,
                        last_frontier=result_mapping.last_frontier,
                    )
                )
            except ProtocolValueError, TypeError, ValueError:
                return "start_bind_child_lane_unbound"
        else:
            return "start_bind_child_lane_unbound"
    elif child_lineage:
        # An attached/replayed/created child result carries its parent task explicitly.  If the
        # raw host session is already mapped to that parent, it is a shared parent lane and must
        # remain untouched.  A separate host session is safe to bind directly, retaining the
        # old one-session hook contract.  A shared session with no host child identity remains an
        # explicit attribution gap; a task-derived fallback would be a second untrusted alias.
        assert parent_task_id is not None
        if type(task_id) is not str or not is_valid_id(IdKind.TASK, task_id):
            return "start_bind_invalid_ids"
        if task_id == parent_task_id:
            return "start_bind_invalid_ids"
        if identity_supplied and not identity_valid:
            return "start_bind_child_lane_unbound"
        if existing is None and not parent_pending:
            targets.append(result_mapping)
        elif existing is not None and existing.finishup_task_id == task_id:
            targets.append(result_mapping)
        elif identity_valid and child_identity is not None:
            try:
                child_lane = scoped_child_session_id(
                    codex_session_id,
                    host=host,
                    identity=child_identity,
                    identity_kind="host",
                )
                targets.append(
                    _mapping_for_lane(
                        child_lane,
                        task_id=task_id,
                        session_id=session_id,
                        writer_id=writer_id,
                        last_frontier=result_mapping.last_frontier,
                    )
                )
            except ProtocolValueError, TypeError, ValueError:
                return "start_bind_child_lane_unbound"
        else:
            return "start_bind_child_lane_unbound"

        # A missing host child identity remains an attribution gap.  Publishing a
        # task-derived fallback lane would be a second, untrusted alias for the
        # same child and would require an atomic multi-file transaction; the
        # service-authored task id remains available to the caller's explicit
        # cooperative route instead.
    else:
        # Root/ordinary starts keep the established raw host-session mapping.  A
        # valid child identity plus a different task on an already mapped parent
        # session is the one ambiguous native shape that must not overwrite the
        # parent.  If that identity has no established host lane, leave the
        # callback unbound; an ordinary parent sibling start remains allowed when
        # the host supplies no child identity (the normal parent shape).
        if (
            (existing is not None or parent_pending)
            and (existing is None or existing.finishup_task_id != task_id)
            and identity_valid
            and child_identity is not None
        ):
            try:
                child_lane = scoped_child_session_id(
                    codex_session_id,
                    host=host,
                    identity=child_identity,
                    identity_kind="host",
                )
            except ProtocolValueError, TypeError, ValueError:
                return "start_bind_child_lane_unbound"
            prior_child = load_mapping(child_lane, _state=_state)
            if prior_child is not None and prior_child.finishup_task_id != task_id:
                return "start_bind_child_lane_unbound"
            targets.append(
                _mapping_for_lane(
                    child_lane,
                    task_id=task_id,
                    session_id=session_id,
                    writer_id=writer_id,
                    last_frontier=result_mapping.last_frontier,
                )
            )
        elif identity_supplied and not identity_valid:
            return "start_bind_child_lane_unbound"
        else:
            targets.append(result_mapping)

    if not targets:
        return "start_bind_child_lane_unbound"
    return _persist_start_mappings(tuple(targets), _state=_state)


def bind_start_mapping_from_hook(
    payload: Mapping[str, JsonValue],
    *,
    _state: Path | None = None,
    host: HookHost = "codex",
) -> bool:
    """Compatibility wrapper: ``True`` only when a mapping was persisted."""

    return bind_start_mapping_outcome(payload, _state=_state, host=host) == "bound"


def recover_pending_start_mapping(
    codex_session_id: str,
    *,
    _state: Path | None = None,
    _session_lock_owned: bool = False,
) -> PendingMappingRecovery:
    """Replay durable start mappings when the session lock is available.

    A cancelled or contended ``SessionStart`` may leave a validated mapping in
    the lifecycle pending file after the hook that produced it has exited.  A
    later hook may retry this exact session, but it must use the same lifecycle
    lock and FIFO ``.applying`` protocol as the start path.  Contention,
    malformed state, or an interrupted apply are all a no-op; the next hook
    can retry without inventing a mapping or changing another session lane.
    The bounded pass drains residual queued operations in FIFO order. ``pending``
    remains true when an operation could not be applied, so
    callers can defer mapping-sensitive delivery for this pass.
    """

    try:
        mapping = mapping_path(codex_session_id, _state=_state)
        pending = mapping.parent / f".{codex_session_id}.pending.json"
        applying = pending.with_name(pending.name + ".applying")
        paths = (pending, applying)
        if not any(path.exists() or path.is_symlink() for path in paths):
            return PendingMappingRecovery(applied=False, pending=False)
        lifecycle_lock = (
            contextlib.nullcontext(True)
            if _session_lock_owned
            else acquire_session_lock(codex_session_id, _state=_state)
        )
        with lifecycle_lock as owned:
            if not owned:
                return PendingMappingRecovery(applied=False, pending=True)
            applied = False
            for _ in range(_MAX_PENDING_MAPPING_REPLAYS):
                if not apply_pending_mapping(codex_session_id, _state=_state):
                    break
                applied = True
        still_pending = any(path.exists() or path.is_symlink() for path in paths)
        return PendingMappingRecovery(applied=applied, pending=still_pending)
    except Exception:
        return PendingMappingRecovery(applied=False, pending=True)


def record_start_bind_diagnostic(
    outcome: StartBindOutcome, event_name: str, *, _state: Path | None
) -> None:
    """Record a failed scoped start bind as a payload-free hook diagnostic."""

    if outcome in {"bound", "skipped"}:
        return
    from finishup.cli.hook_diagnostics import record_hook_diagnostic

    _stderr_line(f"hook_start_bind_failed: {outcome}")
    with contextlib.suppress(Exception):
        record_hook_diagnostic(outcome, event_name, _state=_state)


def handle_post_tool_use(
    *,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    _state: Path | None = None,
    workspace: str | None = None,
) -> int:
    """Correlate a successful FinishUP start MCP tool call; route structural observe."""

    try:
        raw = (
            stdin_bytes
            if stdin_bytes is not None
            else sys.stdin.buffer.read(MAX_HOOK_STDIN_BYTES + 1)
        )
        payload, _identity_conflict = with_transcript_child_identity(
            read_hook_payload(raw), event_name="PostToolUse"
        )
        record_start_bind_diagnostic(
            bind_start_mapping_outcome(payload, _state=_state), "PostToolUse", _state=_state
        )
        from finishup.cli.observe_hooks import handle_observe

        return handle_observe(
            event_name="PostToolUse",
            stdin_bytes=raw,
            stdout=stdout,
            workspace=workspace,
            _state=_state,
        )
    except Exception as exc:
        _note_oversize_hook_ingress(exc, "PostToolUse", workspace=workspace, _state=_state)
        _stderr_line("hook_degraded: post-tool-use")
        _stdout_json({}, stdout)
        return 0


def _active_context(mapping: LifecycleMapping, frontier: str | None) -> str:
    """Name the mapped task with a selector the guidance recognises (issue #580).

    A bare ``task_id`` is not an attach or status selector, and the hook's own
    ``workspace_ref``/``external_ref`` pair is never what an agent would guess, so
    the context carries the mapping snapshot and the attach selector. New
    sessions attach before status; compaction keeps the held cooperative route.
    """

    token = frontier if frontier is not None else mapping.last_frontier
    frontier_text = token if token is not None else "unknown"
    return (
        f"FinishUP task {mapping.finishup_task_id} is mapped to this session at frontier "
        f"{frontier_text} as session_id {mapping.finishup_session_id} and writer_id "
        f"{mapping.finishup_writer_id}. For a new host session, after guidance reads and tool/schema "
        "discovery, call start with mode=attach and "
        f"session_id {mapping.finishup_session_id} before substantive material work. "
        "Then read status with the returned session/writer ids; for compaction in an "
        "already-started host session, use your held current ids. After resume or compaction, "
        "read status once; keep the returned obligations and findings, then do the work; do not "
        "reread status between ordinary steps. Do not call start with "
        "mode=create_or_attach and a new workspace_ref/external_ref pair, which creates a "
        "sibling task. " + _STARTUP_RECOVERY_CONTEXT
    )


def _local_pending_rows(codex_session_id: str, *, _state: Path | None) -> int | None:
    """This session's undelivered local rows that would add ledger work, or ``None``.

    Sampled before the status read: the rows pending when the facts were read are the ones those
    facts cannot include, even if the delegated observe pass drains them before the output.
    """

    try:
        from finishup.adapters.integrations.observation_local import LocalObservationStore
        from finishup.cli.compaction_recap import pending_work_rows

        store = LocalObservationStore(_state=_state)
        return pending_work_rows(
            store, store.find_workspace_for_codex_session(codex_session_id), codex_session_id
        )
    except Exception:
        return None


def _with_compaction_recap(
    context: str, facts: RecapFacts, *, pending_rows: int | None
) -> tuple[str, int | None]:
    """Append the bounded recap to a compaction start's context; never raises (ADR-044).

    Returns the context and the larger character bound it was designed against, or the
    unchanged context and ``None`` (the default bound) when the recap could not be composed.
    """

    try:
        from finishup.cli.compaction_recap import compact_recap_text

        recap = compact_recap_text(facts, pending_rows=pending_rows)
        return f"{context}\n{recap}".strip(), RECAP_CONTEXT_LIMIT
    except Exception:
        return context, None


def _status_request(
    mapping: LifecycleMapping,
    *,
    # Frozen legacy identifier (ADR-048): a recorded actor id; renaming it would mix ids in one
    # ledger and turn a retry across the upgrade into an idempotency conflict.
    actor_id: str = "yoetz:codex-hooks",
    view: str = "compact",
    limit: str = "1",
    cursor: str | None = None,
) -> StatusRequest:
    return StatusRequest.model_validate(
        {
            "protocol_version": "0.1",
            "schema_version": "1.0.0",
            "request_id": new_id(IdKind.REQUEST),
            "actor": {
                "actor_id": actor_id,
                "actor_type": "harness",
            },
            "client": {
                # Frozen legacy identifier (ADR-048): the client kind wire enum value.
                "kind": "yoetz_cli",
                "version": __version__,
                "integration": "local_cli",
            },
            "session_id": mapping.finishup_session_id,
            "writer_id": mapping.finishup_writer_id,
            "view": view,
            "limit": limit,
            "at_frontier": None,
            "cursor": cursor,
        }
    )


def bound_connector(
    real: Callable[..., Awaitable[object]], workspace_locator: str | None
) -> ServiceConnector:
    """Bind the real service connector to the hook's consented workspace locator.

    The daemon fences every task workflow, status included, to the repository
    the control handshake named. A hook status read sent without a locator was
    refused as `SESSION_CONFLICT` for a perfectly live mapping and then reported
    as `mapping_stale` (issue #578), so every hook status read now carries the
    same locator `start` does. An unrepresentable locator is sent as none; the
    daemon then answers with its typed reason instead of the hook guessing.
    """

    locator: WorkspaceLocator | None
    try:
        locator = None if workspace_locator is None else WorkspaceLocator(workspace_locator)
    except ValueError:
        locator = None

    async def connect(kind: ControlClientKind) -> _StatusClient:
        return cast(_StatusClient, await real(kind, workspace_locator=locator))

    return connect


type LocatorSource = Literal["explicit", "host_payload", "cwd", "absent", "unresolvable"]

# Closed diagnostic tokens naming where a mapped-session status probe got its repository
# locator (issue #659). Recorded only beside a fence refusal so the retained diagnostic window
# is not spent on every healthy SessionStart; never a path, never a host payload.
_LOCATOR_SOURCE_REASONS: Final[Mapping[LocatorSource, str]] = MappingProxyType(
    {
        "explicit": "locator_source_explicit",
        "host_payload": "locator_source_host_payload",
        "cwd": "locator_source_cwd",
        "absent": "locator_absent",
        "unresolvable": "locator_unresolvable",
    }
)


@dataclass(frozen=True, slots=True)
class SessionWorkspace:
    """One bounded locator selection for a mapped-session status probe."""

    locator: str | None
    source: LocatorSource

    @property
    def diagnostic_reason(self) -> str:
        return _LOCATOR_SOURCE_REASONS[self.source]


def _canonical_or_none(candidate: str) -> str | None:
    try:
        return canonical_workspace_locator(candidate)
    except Exception:
        return None


def host_payload_cwd(payload: Mapping[str, JsonValue] | None) -> str | None:
    """The host's own session working directory from the hook payload, if it names one."""

    if payload is None:
        return None
    value = payload.get("cwd")
    return value if type(value) is str and value else None


def resolve_session_workspace(
    workspace: str | None,
    payload: Mapping[str, JsonValue] | None = None,
) -> SessionWorkspace:
    """Select the repository locator a mapped-session status probe carries (issue #659).

    Order: an explicit project path from the rendered command (anything but the bare ``.``),
    then the host payload's session ``cwd``, then the hook's own working directory. The bare
    ``.`` is the hook cwd, not host evidence, so a host-supplied cwd outranks it: Codex and
    Cursor hook working directories are not stable across surfaces, and a hook launched outside
    the project must still bind the project the host named. An explicit project path that fails
    canonicalization is terminal — it never falls through to a different repository — and a
    fully absent context stays absent rather than inheriting a broader fallback. Only the closed
    source token is ever recorded; the path never is.
    """

    if workspace is not None and workspace not in {"", "."}:
        locator = _canonical_or_none(workspace)
        return SessionWorkspace(locator, "explicit" if locator is not None else "unresolvable")
    cwd = host_payload_cwd(payload)
    if cwd is not None:
        locator = _canonical_or_none(cwd)
        if locator is not None:
            return SessionWorkspace(locator, "host_payload")
    if workspace is None and cwd is None:
        # No rendered locator and no host cwd: the hook's own cwd is the ordinary
        # repository-bound CLI default, exactly as before this resolver existed.
        locator = _canonical_or_none(".")
        return SessionWorkspace(locator, "cwd" if locator is not None else "absent")
    locator = _canonical_or_none(".")
    if locator is not None:
        return SessionWorkspace(locator, "cwd")
    return SessionWorkspace(None, "unresolvable")


def session_workspace_locator(workspace: str | None) -> str | None:
    """Canonical locator for a hook that names its workspace, else the hook's own cwd."""

    return resolve_session_workspace(workspace).locator


_RECAP_OBLIGATIONS_DEADLINE_MS: Final = 1_500
# The recap's reads must end within the first four seconds of the hook, so they add nothing to the
# worst case that already exists when the compact read itself is slow (the recap is then skipped)
# and the delegated observe pass follows under the 15 s host timeout.
_RECAP_WINDOW_SECONDS: Final = 4.0
# Below this many milliseconds the hook skips the obligations read (deliverables are then named
# unavailable) rather than risk the host window.
_RECAP_OBLIGATIONS_MIN_MS: Final = 250
_RECAP_OBLIGATIONS_LIMIT: Final = "100"
# Pages of the obligations view the recap will read (300 obligations); beyond that it says the
# view has more pages than were read.
_RECAP_OBLIGATIONS_PAGES: Final = 3


async def _read_recap_facts(
    client: _StatusClient,
    compact_branch: object,
    mapping: LifecycleMapping,
    *,
    actor_id: str,
    time_left: Callable[[], float] | None = None,
) -> RecapFacts | None:
    """Build the post-compaction recap facts from the compact result already in hand.

    Up to three bounded ``obligations`` pages name the declared deliverables of the current plan;
    if they fail, are slow, or the hook has no time left (``time_left`` reports the seconds the
    host window still allows), the recap says they are unavailable or that pages remain unread.
    Nothing here may raise into the hook.
    """

    from finishup.cli.compaction_recap import recap_facts_from_status, recap_with_deliverables

    try:
        facts = recap_facts_from_status(
            compact_branch,
            task_id=mapping.finishup_task_id,
            session_id=mapping.finishup_session_id,
            writer_id=mapping.finishup_writer_id,
        )
        if facts is None:
            return None
        pages: list[object] = []
        cursor: str | None = None
        more_pages = False
        for _page in range(_RECAP_OBLIGATIONS_PAGES):
            budget_ms = _RECAP_OBLIGATIONS_DEADLINE_MS
            if time_left is not None:
                budget_ms = min(budget_ms, int(time_left() * 1_000))
            if budget_ms < _RECAP_OBLIGATIONS_MIN_MS:
                # No room in the host window: whatever was read stands, the rest is unread.
                more_pages = bool(pages) and cursor is not None
                break
            try:
                result = await client.status(
                    _status_request(
                        mapping,
                        actor_id=actor_id,
                        view="obligations",
                        limit=_RECAP_OBLIGATIONS_LIMIT,
                        cursor=cursor,
                    ),
                    deadline_ms=budget_ms,
                )
                branch = getattr(result, "root", result)
                if isinstance(branch, OperationFailureModel):
                    break
            except Exception:
                break
            pages.append(branch)
            cursor = getattr(getattr(branch, "page", None), "next_cursor", None)
            if type(cursor) is not str:
                cursor = None
                more_pages = False
                break
            more_pages = True
        return recap_with_deliverables(facts, pages, more_pages=more_pages)
    except Exception:
        return None


async def _read_status(
    mapping: LifecycleMapping,
    *,
    connect: ServiceConnector | None = None,
    # Frozen legacy identifier (ADR-048): a recorded actor id; renaming it would mix ids in one
    # ledger and turn a retry across the upgrade into an idempotency conflict.
    actor_id: str = "yoetz:codex-hooks",
    workspace_locator: str | None = None,
    recap: bool = False,
    recap_time_left: Callable[[], float] | None = None,
) -> StatusOutcome:
    """Read the mapped session's status through a repository-bound connection.

    Without an explicit ``connect`` the real connector is bound to
    ``workspace_locator`` so the daemon's repository fence can admit the read.
    """

    client: _StatusClient | None = None
    try:
        connector = (
            bound_connector(connect_service, workspace_locator) if connect is None else connect
        )
        connected = await connector(ControlClientKind.CLI)
        client = connected
        result = await connected.status(
            _status_request(mapping, actor_id=actor_id), deadline_ms=_STATUS_DEADLINE_MS
        )
        branch = getattr(result, "root", result)
        if isinstance(branch, OperationFailureModel):
            return _classify_status_failure(branch)
        head = getattr(branch, "head_frontier", None)
        task_id = getattr(branch, "task_id", None)
        session_id = getattr(branch, "session_id", None)
        writer_id = getattr(branch, "writer_id", None)
        if head is None or type(task_id) is not str or type(session_id) is not str:
            return StatusOutcome("unavailable")
        if type(writer_id) is not str:
            return StatusOutcome("unavailable")
        sequence = getattr(head, "sequence", None)
        digest = getattr(head, "head_digest", None)
        if type(sequence) is not str or type(digest) is not str:
            return StatusOutcome("unavailable")
        frontier = encode_frontier_token(sequence=sequence, head_digest=digest)
        updated = LifecycleMapping(
            mapping_version=mapping.mapping_version,
            codex_session_id=mapping.codex_session_id,
            finishup_task_id=task_id,
            finishup_session_id=session_id,
            finishup_writer_id=writer_id,
            last_frontier=frontier,
        )
        facts = (
            await _read_recap_facts(
                connected,
                branch,
                updated,
                actor_id=actor_id,
                time_left=recap_time_left,
            )
            if recap
            else None
        )
        return StatusOutcome("active", mapping=updated, recap=facts)
    except ControlError as error:
        return StatusOutcome(_CONTROL_ERROR_CLASSES.get(error.reason, "unavailable"))
    except Exception:
        return StatusOutcome("unavailable")
    finally:
        if client is not None:
            try:
                await client.close()
            except Exception:
                pass


# Issue #537: the SessionStart hook deliberately runs no applied-vs-serving drift probe.
# A hook process has no serving route of its own, so the only comparison available here is a
# `codex mcp get` subprocess (plus PATH version probes to find the binary), which costs a
# large fraction of the 2.2s end-to-end hook budget in `observe_hooks` and reintroduces the
# #209-#213 hook-latency loop. The MCP bridge (`finishup mcp serve`) starts for the same Codex
# session, knows its own serving route from its argv, and emits the `registration_drift`
# diagnostic for free; that is the single emitter. See docs/runbooks/codex-integration.md.


def handle_session_start(
    *,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    _state: Path | None = None,
    connect: ServiceConnector | None = None,
    run_async: AsyncRunner | None = None,
    workspace: str | None = None,
) -> int:
    """Re-ground after resume/compact; also route structural observe when consented."""

    import anyio

    entered = time.monotonic()
    runner: AsyncRunner = cast(AsyncRunner, anyio.run if run_async is None else run_async)
    try:
        raw = (
            stdin_bytes
            if stdin_bytes is not None
            else sys.stdin.buffer.read(MAX_HOOK_STDIN_BYTES + 1)
        )
        payload = read_hook_payload(raw)
        source = payload.get("source")
        session_raw = payload.get("session_id")
        try:
            codex_session_id = validate_codex_session_id(session_raw)
        except ProtocolValueError:
            if source == "startup":
                from finishup.cli.observe_hooks import handle_observe

                return handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=raw,
                    stdout=stdout,
                    workspace=workspace,
                    _state=_state,
                    connect=connect,
                    run_async=run_async,
                )
            _stdout_json(_context_output("SessionStart", INACTIVE_CONTEXT), stdout)
            return 0
        if source == "startup":
            with acquire_session_lock(codex_session_id, _state=_state) as owned:
                if owned:
                    recover_pending_start_mapping(
                        codex_session_id,
                        _state=_state,
                        _session_lock_owned=True,
                    )
            from finishup.cli.observe_hooks import handle_observe

            return handle_observe(
                event_name="SessionStart",
                stdin_bytes=raw,
                stdout=stdout,
                workspace=workspace,
                _state=_state,
                connect=connect,
                run_async=run_async,
            )
        if source == "clear":
            # The shared observation path owns the durable clear. Keeping one
            # owner avoids queueing/replaying the same logical clear twice and
            # lets it coalesce a concurrent pending producer deterministically.
            from finishup.cli.observe_hooks import handle_observe

            return handle_observe(
                event_name="SessionStart",
                stdin_bytes=raw,
                stdout=stdout,
                workspace=workspace,
                _state=_state,
                connect=connect,
                run_async=run_async,
            )
        if source not in {"resume", "compact"}:
            from finishup.cli.observe_hooks import handle_observe

            return handle_observe(
                event_name="SessionStart",
                stdin_bytes=raw,
                stdout=stdout,
                workspace=workspace,
                _state=_state,
                connect=connect,
                run_async=run_async,
            )
        with acquire_session_lock(codex_session_id, _state=_state) as owned:
            if not owned:
                # Another concurrent handler is already re-grounding this
                # session. Keep the hook evidence through the shared ingress;
                # it will contend for membership without claiming this lock.
                from finishup.cli.observe_hooks import handle_observe

                return handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=raw,
                    stdout=stdout,
                    workspace=workspace,
                    _state=_state,
                    connect=connect,
                    run_async=run_async,
                )
            recovery = recover_pending_start_mapping(
                codex_session_id,
                _state=_state,
                _session_lock_owned=True,
            )
            if recovery.pending:
                from finishup.cli.observe_hooks import handle_observe

                observe_out = __import__("io").BytesIO()
                handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=raw,
                    stdout=observe_out,
                    workspace=workspace,
                    _state=_state,
                    connect=connect,
                    run_async=run_async,
                    _session_lock_owned=True,
                )
                observed = observe_out.getvalue()
                if observed and observed not in {b"{}\n", b"{}\r\n"}:
                    if stdout is not None:
                        stdout.write(observed)
                        stdout.flush()
                    else:
                        sys.stdout.buffer.write(observed)
                        sys.stdout.buffer.flush()
                else:
                    _stdout_json(_context_output("SessionStart", INACTIVE_CONTEXT), stdout)
                return 0
            mapping = load_mapping(codex_session_id, _state=_state)
            if mapping is None:
                from finishup.cli.observe_hooks import handle_observe

                observe_out = __import__("io").BytesIO()
                handle_observe(
                    event_name="SessionStart",
                    stdin_bytes=raw,
                    stdout=observe_out,
                    workspace=workspace,
                    _state=_state,
                    connect=connect,
                    run_async=run_async,
                    _session_lock_owned=True,
                )
                observed = observe_out.getvalue()
                if observed and observed not in {b"{}\n", b"{}\r\n"}:
                    if stdout is not None:
                        stdout.write(observed)
                        stdout.flush()
                    else:
                        sys.stdout.buffer.write(observed)
                        sys.stdout.buffer.flush()
                    return 0
                _stdout_json(_context_output("SessionStart", INACTIVE_CONTEXT), stdout)
                return 0

            selection = resolve_session_workspace(workspace, payload)

            async def _run() -> StatusOutcome:
                return await _read_status(
                    mapping,
                    connect=connect,
                    workspace_locator=selection.locator,
                    recap=source == "compact",
                    recap_time_left=lambda: entered + _RECAP_WINDOW_SECONDS - time.monotonic(),
                )

            pending_before = (
                _local_pending_rows(codex_session_id, _state=_state)
                if source == "compact"
                else None
            )
            outcome = cast(StatusOutcome, runner(_run))
            kind, updated = outcome.kind, outcome.mapping
            from finishup.cli.observe_hooks import handle_observe

            handle_observe(
                event_name="SessionStart",
                stdin_bytes=raw,
                stdout=__import__("io").BytesIO(),
                workspace=workspace,
                _state=_state,
                connect=connect,
                run_async=run_async,
                _session_lock_owned=True,
                _include_admission_notice=False,
                # This call only records the SessionStart; its output is discarded, so it must
                # not read the recap's views a second time.
                _include_recap=False,
            )
            if kind == "active" and updated is not None:
                from finishup.cli.host_hold_advisory import PrivacyConnector
                from finishup.cli.host_startup_advisory import append_admission_notice

                store_mapping(updated, _state=_state)
                context = append_admission_notice(
                    _active_context(updated, updated.last_frontier),
                    "codex",
                    selection.locator,
                    connect=None if connect is None else cast(PrivacyConnector, connect),
                    run_async=runner,
                    deadline=entered + 3.1,
                    max_chars=2_000,
                )
                context_limit = None
                if outcome.recap is not None:
                    # ADR-044: the compaction start also carries the receipt-style recap of
                    # what FinishUP recorded, after the held-ids cue and the admission notice.
                    context, context_limit = _with_compaction_recap(
                        context, outcome.recap, pending_rows=pending_before
                    )
                _stdout_json(
                    _context_output("SessionStart", context)
                    if context_limit is None
                    else _context_output("SessionStart", context, limit=context_limit),
                    stdout,
                )
                return 0
            if kind == "stale":
                from finishup.cli.hook_diagnostics import record_hook_diagnostic

                # The delegated observation path cannot reacquire the session lock
                # held here, so this branch owns the resume event's diagnostic.
                with contextlib.suppress(Exception):
                    record_hook_diagnostic("mapping_stale", "SessionStart", _state=_state)
                _stdout_json(
                    _context_output(
                        "SessionStart", _stale_mapping_context(mapping, outcome.replacement)
                    ),
                    stdout,
                )
                return 0
            if kind in {"workspace_unbound", "workspace_mismatch"}:
                from finishup.cli.hook_diagnostics import record_hook_diagnostic

                # The daemon refused to bind this read to a repository; the mapping
                # is kept untouched and is deliberately not reported as stale (#578).
                # The companion row names where the probe's locator came from, so an
                # absent locator, a supplied one that failed to canonicalize, and a
                # resolved one the daemon still refused are distinguishable (#659).
                with contextlib.suppress(Exception):
                    record_hook_diagnostic(f"status_{kind}", "SessionStart", _state=_state)
                    record_hook_diagnostic(
                        selection.diagnostic_reason, "SessionStart", _state=_state
                    )
                _stdout_json(
                    _context_output(
                        "SessionStart",
                        _WORKSPACE_UNBOUND_CONTEXT
                        if kind == "workspace_unbound"
                        else _WORKSPACE_MISMATCH_CONTEXT,
                    ),
                    stdout,
                )
                return 0
            if kind == "locked":
                _stdout_json(_context_output("SessionStart", _LOCKED_CONTEXT), stdout)
                return 0
            if kind == "retry":
                _stdout_json(_context_output("SessionStart", _RETRY_CONTEXT), stdout)
                return 0
            if kind == "privacy":
                _stdout_json(_context_output("SessionStart", _PRIVACY_CONTEXT), stdout)
                return 0
            if kind in {"storage_unsafe", "storage_corrupt"}:
                from finishup.cli.hook_diagnostics import record_hook_diagnostic

                with contextlib.suppress(Exception):
                    record_hook_diagnostic(kind, "SessionStart", _state=_state)
                _stdout_json(
                    _context_output(
                        "SessionStart",
                        _STORAGE_UNSAFE_CONTEXT
                        if kind == "storage_unsafe"
                        else _STORAGE_CORRUPT_CONTEXT,
                    ),
                    stdout,
                )
                return 0
            _stdout_json(_context_output("SessionStart", _UNAVAILABLE_CONTEXT), stdout)
            return 0
    except Exception as exc:
        _note_oversize_hook_ingress(exc, "SessionStart", workspace=workspace, _state=_state)
        _stderr_line("hook_degraded: session-start")
        _stdout_json(_context_output("SessionStart", INACTIVE_CONTEXT), stdout)
        return 0


def handle_observe(
    *,
    event_name: str,
    stdin_bytes: bytes | None = None,
    stdout: BinaryIO | None = None,
    workspace: str | None = None,
    _state: Path | None = None,
) -> int:
    """Compatibility export for the unified observe ingress."""

    from finishup.cli.observe_hooks import handle_observe as _handle

    return _handle(
        event_name=event_name,
        stdin_bytes=stdin_bytes,
        stdout=stdout,
        workspace=workspace,
        _state=_state,
    )
