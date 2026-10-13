"""MCP stdio bridge: workflow tools plus read-only guidance and closure preparation."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
import sys
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast
from urllib.parse import unquote_to_bytes, urlsplit

import anyio
from mcp import types
from mcp.server import InitializationOptions, NotificationOptions, Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import request_ctx
from mcp.shared.exceptions import McpError
from mcp.shared.version import SUPPORTED_PROTOCOL_VERSIONS
from pydantic import AnyUrl, BaseModel, ValidationError

from yoetz import __version__
from yoetz.adapters.integrations.cursor_project_mcp import (
    CursorProjectMcpError,
    CursorProjectMcpRegistrationSnapshot,
    inspect_project_mcp_registration,
)
from yoetz.adapters.integrations.yoetz_call_rejections import record_rejected_yoetz_call
from yoetz.adapters.mcp_stdio import MAX_JSON_FRAME_BYTES, bounded_stdio_server
from yoetz.adapters.workspace_binding import (
    MAX_WORKSPACE_LOCATOR_BYTES,
    canonical_workspace_locator,
)
from yoetz.config.load import load_config
from yoetz.config.models import LoggingConfig
from yoetz.domain.check_totals import render_check_totals
from yoetz.domain.closure import PREPARATION_REMEDIATIONS, prepare_closure
from yoetz.domain.review_input_render import render_review_input_manifest_compact
from yoetz.mcp.descriptors import (
    TOOL_DESCRIPTORS,
    McpRouteProfile,
    ToolDescriptor,
    descriptor_for,
    server_instructions,
)
from yoetz.mcp.errors import (
    authoring_hint,
    build_last_resort_internal_error_result,
    build_public_error_result,
    safe_validation_locations,
    sanitize_unknown_tool_name,
    tool_error_envelope,
)
from yoetz.mcp.resources import (
    DEFAULT_GUIDANCE_PAGE_SIZE,
    GUIDANCE_RESOURCES,
    MAX_GUIDANCE_PAGE_SIZE,
    GuidanceResource,
    GuidanceResourceError,
    GuidanceResourcePage,
    resolve_guidance_topic_uri,
)
from yoetz.mcp.resources import (
    list_resources as list_guidance_resources,
)
from yoetz.mcp.resources import (
    read_resource as read_guidance_resource,
)
from yoetz.mcp.resources import (
    resource_for_uri as guidance_resource_for_uri,
)
from yoetz.mcp.semantic_destination import (
    SemanticDestinationDisclosure,
    read_semantic_destination_disclosure,
)
from yoetz.mcp.summaries import (
    render_check_reviewer_output,
    render_publish_action_notices,
    render_publish_blocker_notices,
    render_safe_compact_summary_detailed,
    summary_for_check_awaiting,
    summary_for_read_guidance,
)
from yoetz.observability.logging import (
    LogMode,
    configure_logging,
    record_public_error_without_raising,
    record_unexpected_exception_without_raising,
)
from yoetz.ports.control import (
    ControlClientKind,
    ControlError,
    McpHostProfile,
    ServiceState,
    WorkspaceLocator,
)
from yoetz.ports.integrations import YOETZ_MCP_TOOL_NAMES
from yoetz.protocol.canonical import JsonValue, canonical_encode
from yoetz.protocol.consent import CONSENT_PENDING_TTL_SECONDS
from yoetz.protocol.errors import (
    SERVICE_STARTUP_PHASES,
    PublicErrorCode,
    PublicOperationError,
    SafeDetailValue,
)
from yoetz.protocol.guidance_uris import (
    ALL_GUIDANCE_URIS,
    FOCUSED_GUIDANCE_URIS,
    GUIDANCE_DOCUMENT_URIS,
    GUIDANCE_TOPIC_URIS,
)
from yoetz.protocol.ids import IdKind, new_id, safe_request_id_from
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    ClosurePrepareRequest,
    ClosurePrepareResult,
    PublishWorkRequest,
    PublishWorkResult,
    ReadGuidanceRequest,
    ReadGuidanceResult,
    ReceiptRequest,
    ReceiptResult,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
    public_model_to_wire,
)
from yoetz.protocol.recovery import (
    READ_ONLY_CHECK_MODES,
    REASON_REMEDIES,
    WRITE_OPERATIONS,
    continuation_for_reason,
    timeout_operation_kind,
)
from yoetz.service.client import (
    ServiceClient,
    accepted_but_unresponsive,
    connect_service,
    connect_service_on_demand,
    handshake_failure,
    holder_version_order,
    service_holder_identity,
)

__all__ = [
    "BRIDGE_RUNTIME",
    "BridgeRuntime",
    "build_bridge_runtime",
    "call_tool",
    "close_bridge_runtime",
    "dispatch_check",
    "dispatch_closure_prepare",
    "dispatch_publish_work",
    "dispatch_read_guidance",
    "dispatch_receipt",
    "dispatch_respond",
    "dispatch_start",
    "dispatch_status",
    "ensure_service_client",
    "list_resources",
    "list_tools",
    "main",
    "read_resource",
    "result_from_public_model",
    "run_stdio",
    "server",
    "structured_error_result",
]

_SERVER_NAME: Final = "yoetz"
_WORKFLOW_RPC_DEADLINE_MS: Final = 30_000
# Respond and receipt no longer replay the ledger per call (issue #886). Their default stays
# below the common 60-second host MCP tool limit (Codex ``tool_timeout_sec``) so the bridge's own
# typed timeout, with its operation handle, reaches the agent before the host gives up.
_RECEIPT_RESPONSE_RPC_DEADLINE_MS: Final = 50_000
_SEMANTIC_CHECK_RPC_DEADLINE_MS: Final = 300_000
_DEFAULT_RPC_DEADLINES_MS: Final = MappingProxyType(
    {
        "start": _WORKFLOW_RPC_DEADLINE_MS,
        "publish_work": _WORKFLOW_RPC_DEADLINE_MS,
        "status": _WORKFLOW_RPC_DEADLINE_MS,
        "respond": _RECEIPT_RESPONSE_RPC_DEADLINE_MS,
        "receipt": _RECEIPT_RESPONSE_RPC_DEADLINE_MS,
        "check": _SEMANTIC_CHECK_RPC_DEADLINE_MS,
    }
)
# ``YOETZ_MCP_DEADLINE_MS_<TOOL>`` sets one tool; ``YOETZ_MCP_DEADLINE_MS`` sets every tool except
# ``check``, whose semantic-review budget is only changed by its own variable. Values are integer
# milliseconds, clamped to a sane range; anything unparsable keeps the default.
_RPC_DEADLINE_ENV: Final = "YOETZ_MCP_DEADLINE_MS"
_MIN_RPC_DEADLINE_MS: Final = 1_000
_MAX_RPC_DEADLINE_MS: Final = 900_000
# A write that timed out is probed once for its durable operation state with this budget.
_TIMEOUT_PROBE_DEADLINE_MS: Final = 5_000
_CURSOR_ROOTS_REQUEST_TIMEOUT_SECONDS: Final = 5.0
_MAX_CURSOR_ROOTS: Final = 32
_MAX_CURSOR_ROOT_URI_BYTES: Final = MAX_WORKSPACE_LOCATOR_BYTES * 2
# Leave room for the JSON-RPC method, id, and MCP result wrapper. A complete closure inventory is
# useful only when the bridge can deliver it as one bounded frame; refusing before projection
# prevents the transport from clipping a superficially successful preparation (#953/#950).
# The transport checks the serialized JSON-RPC payload before it appends the JSONL newline. The
# closure helper performs the same check after host projection below; this constant remains an
# inexpensive pre-projection refusal for very large preparations.
_MAX_CLOSURE_RESULT_BYTES: Final = MAX_JSON_FRAME_BYTES - 65_536
# ``ReadGuidanceSuccessModel`` caps the unpaged legacy body at 64 KiB. Oversized registered
# resources must enter the existing bounded page route even when a caller still sends the legacy
# URI-only request shape; otherwise validation fails before the caller receives continuation
# metadata to reconstruct the document.
_MAX_LEGACY_GUIDANCE_DOCUMENT_BYTES: Final = 65_536
# Every closure-preparation reason is a protocol reason code of its own, so the text names the
# selection to correct and its remedy. A mapped code such as ``frontier_changed`` would hand a read
# a write's instruction (set ``expected_frontier``). The two file-output reasons belong to the CLI
# and never cross MCP.
_CLOSURE_CLI_ONLY_REASONS: Final = frozenset(
    {"closure_output_unwritable", "closure_output_not_durable"}
)
_CLOSURE_PUBLIC_REASON_CODES: Final = MappingProxyType(
    {
        reason: reason
        for reason in PREPARATION_REMEDIATIONS
        if reason not in _CLOSURE_CLI_ONLY_REASONS
    }
)
_INVALID_URI_ESCAPE: Final = re.compile(r"%(?![0-9A-Fa-f]{2})", re.ASCII)
_REGISTERED_TOOL_NAMES: Final = frozenset(YOETZ_MCP_TOOL_NAMES)
_GUIDANCE_BY_URI: Mapping[str, GuidanceResource] = MappingProxyType(
    {resource.uri: resource for resource in GUIDANCE_RESOURCES}
)
# Reconnecting only helps when the connection itself is the problem. A projection failure is
# answered by the live service and reconnecting around it drops the session for nothing, so both
# projection reasons are handled in place and surfaced with their own remedy.
_RECONNECT_REASONS: Final = frozenset({"service_unavailable", "service_generation_changed"})
_DISCARD_CLIENT_REASONS: Final = _RECONNECT_REASONS | {"vault_locked"}
# Availability failures describe the host binding (this bridge process, its endpoint, and the
# service holder), not one request. Once one call has reported such a failure, later calls under
# a *new* request identity inherit that terminal state instead of re-probing, re-spawning, or
# minting another diagnostic (issue #469: delegated Cursor workers each retried `start`). The
# first probe is slot-scoped: concurrent arrivals before that result wait for it rather than each
# minting a diagnostic (issue #476). The latch clears when the stamped service holder changes,
# when a quiet handshake succeeds for a retryable class, or when the original request identity
# replays — the sanctioned continuation.
_AVAILABILITY_LATCH_REASONS: Final = frozenset(
    {
        "service_unavailable",
        "service_incompatible",
        "protocol_mismatch",
        "endpoint_unsafe",
        "peer_untrusted",
    }
)
_AVAILABILITY_TERMINAL: Final = "terminal_unavailable"
_INHERITED_AVAILABILITY_SUFFIX: Final = (
    " This bridge already reported this outage under the same correlation_id for an earlier "
    "request; no new diagnostic was recorded for this call. Yoetz remains unavailable for this "
    "host binding until the named repair changes the running service: do not retry with a new "
    "request_id, do not probe with other Yoetz operations, and do not run service lifecycle "
    "commands that the earlier message did not name. Only the original request_id replays after "
    "that repair."
)
# The service's own post-commit projection failure (control reason `response_projection_failed`).
# The operation stands. Replaying the same request_id loads the stored result and is safe, but it
# re-runs the same projection: if that replay also fails the failure is deterministic, so the
# message says to stop replaying and read status instead (tb4n3 RC-2). The remedy is the one the
# text channel renders (`REASON_REMEDIES`), so the two cannot disagree.
_RESPONSE_PROJECTION_FAILED_MESSAGE: Final = (
    "The operation completed on the local service. " + REASON_REMEDIES["response_projection_failed"]
)
_RESPONSE_PROJECTION_FAILED_DETAILS: Final = {"reason_code": "response_projection_failed"}
# A text section that failed to render is recorded, but one runaway renderer must not write an
# unbounded run of diagnostics for a single response.
_MAX_RECORDED_SUMMARY_FAILURES: Final = 3
# Issue #512: when the vault has never been initialized, the natural start-first flow must hand
# the agent a typed initialization-required continuation instead of an ordinary terminal dead
# end. Every value below is a repository literal mirrored by the closed token sets in
# ``yoetz.protocol.errors``; the prepared pending from `yoetz consent prepare` then carries the
# exact danger text, danger digest, expiry, and decision commands the user's decision binds to.
_VAULT_INITIALIZATION_CONTINUATION: Final = "vault_initialization_required"
_VAULT_INITIALIZE_PREPARE_COMMAND: Final = "yoetz consent prepare vault_initialize"
_CONSENT_REVIEW_COMMAND: Final = "yoetz consent review"
_CONSENT_AUTHORIZE_COMMAND: Final = "yoetz consent authorize"
# A read never appended, so there is no stored result and no operation record to replay against.
# Telling the caller to reuse the request_id would send it after a recovery that cannot exist.
_READ_PROJECTION_FAILED_MESSAGE: Final = (
    "The read completed on the local service, but its response could not be shaped. No durable "
    "state changed. Repeat the request with a new request_id, or read status view=versions for "
    "the authoritative frontier."
)
_READ_PROJECTION_FAILED_DETAILS: Final = {"reason_code": "read_projection_failed"}
# Each unexpected bridge failure names the stage that failed and what the agent can safely do next
# (tb4n3 RC-2): a bare "the bridge could not complete the operation" told the agent nothing about
# whether its write had been recorded. The remedy text is shared with the text channel through
# ``REASON_REMEDIES`` so the structured message and the text projection cannot disagree.
_INTERNAL_STAGE_HEADS: Final = MappingProxyType(
    {
        "bridge_request_validation_failed": "The bridge could not validate the request (stage: request validation).",
        "bridge_invoke_failed": "The bridge could not complete the operation (stage: service call).",
        "bridge_error_mapping_failed": "The bridge could not translate the service's failure (stage: error mapping).",
        "closure_prepare_failed": "Closure preparation failed unexpectedly (stage: preparation).",
        "bridge_result_wire_failed": "The bridge could not serialize the result (stage: wire).",
        "bridge_result_validate_failed": "The result failed its response schema (stage: validate).",
    }
)
_INTERNAL_STAGE_MESSAGES: Final = MappingProxyType(
    {reason: f"{head} {REASON_REMEDIES[reason]}" for reason, head in _INTERNAL_STAGE_HEADS.items()}
)


# Stages whose remedy is a replay or a repeat. A ``retryable: false`` error is terminal except for
# its typed continuation (guidance workflow.md "Errors and continuations"), so the remedy text alone
# would leave a compliant agent stopped: each of these carries the same operation-kind continuation a
# timeout does (read: repeat under a new id; write: look the operation up, replay only when absent;
# start: replay under the same id). The result-serialization stages differ for start: a replayed
# start would fail the same way and has no ids to look up, so no continuation travels there.
_REPLAYABLE_STAGES: Final = frozenset(
    {"bridge_request_validation_failed", "bridge_invoke_failed", "bridge_error_mapping_failed"}
)
_RECORDED_RESULT_STAGES: Final = frozenset(
    {"bridge_result_wire_failed", "bridge_result_validate_failed"}
)


def _stage_continuation(
    reason: str, operation: str | None, check_mode: object = None
) -> str | None:
    if reason not in _REPLAYABLE_STAGES and reason not in _RECORDED_RESULT_STAGES:
        return None
    kind = timeout_operation_kind(
        operation, write_operations=_WRITE_OPERATIONS, check_mode=check_mode
    )
    if kind is None or (kind == "start" and reason in _RECORDED_RESULT_STAGES):
        return None
    return continuation_for_reason("request_timeout", operation_kind=kind)


def _internal_stage_error(
    reason: str,
    *,
    request_id: str | None,
    correlation_id: str | None,
    host_profile: McpHostProfile,
    operation: str | None = None,
    check_mode: object = None,
) -> types.CallToolResult:
    """An unexpected bridge failure as INTERNAL_ERROR with a typed stage, a remedy and, where the
    remedy is a replay or a lookup, the typed continuation that authorizes it."""

    safe_details: dict[str, SafeDetailValue] = {"reason_code": reason}
    continuation = _stage_continuation(reason, operation, check_mode)
    if continuation is not None:
        safe_details["continuation"] = continuation
    return structured_error_result(
        PublicErrorCode.INTERNAL_ERROR,
        _INTERNAL_STAGE_MESSAGES[reason],
        retryable=False,
        request_id=request_id,
        correlation_id=correlation_id,
        safe_details=safe_details,
        host_profile=host_profile,
    )


# Two facts are known for certain when envelope-first recovery cannot answer: this body failed
# bridge-local validation, and the recovery oracle could not be reached. The certain, actionable
# one leads; the durability caveat is stated plainly beside it rather than in place of it (issues
# #65, #239). The remedy is always safe: the service is the authority on request identity and will
# replay or reject the id itself.
_PUBLISH_RECOVERY_UNCHECKED_CAVEAT: Final = (
    " A prior operation under this request_id could not be checked; the local service was "
    "unreachable. Correct the named fields and resubmit; the service will replay or reject the "
    "request_id itself if it already names a committed operation."
)
_PUBLISH_RECOVERY_UNAVAILABLE_REASON: Final = "operation_recovery_unavailable"
_WRITE_OPERATIONS: Final = WRITE_OPERATIONS
_REQUEST_TEMPLATES_GUIDANCE_URI: Final = "yoetz://guidance/request-templates.md"
_GUIDANCE_BY_OPERATION: Final = MappingProxyType(
    {
        "start": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "publish_work": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "check": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "respond": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "status": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "receipt": _REQUEST_TEMPLATES_GUIDANCE_URI,
        "closure_prepare": "yoetz://guidance/workflow.md",
    }
)

# The host profile is part of the serving command, rather than inferred from the MCP client.
# ``generic`` is deliberately unknown; only an explicit ``codex`` profile may be compared with
# the Codex applied-route record. Native Claude and Cursor carriers identify themselves explicitly
# so that record cannot be applied to another host.


def _authoring_hint_for(operation: str, locations: Sequence[Mapping[str, str]]) -> str:
    """Look up the frozen presentation schema for one tool and hint from it, or say nothing."""

    try:
        hint = authoring_hint(descriptor_for(operation).input_schema, locations, tool=operation)
    except Exception:
        # A hint is a convenience. Never let building one turn a clear validation error into an
        # internal error.
        hint = ""
    guidance = _GUIDANCE_BY_OPERATION.get(operation)
    if guidance is None:
        return hint
    # Only the registered URI — never synthesized prose. Manifest verification happens at read.
    suffix = f" Guidance: {guidance}."
    if hint.endswith("."):
        return hint[:-1] + ";" + suffix
    if hint:
        return hint + suffix
    return " Hint:" + suffix


def invalid_request_message(operation: str, locations: Sequence[Mapping[str, str]]) -> str:
    """Compose the public INVALID_REQUEST message (schema hint + guidance URI when known)."""

    return "The tool arguments are invalid." + _authoring_hint_for(operation, locations)


@dataclass(slots=True)
class _AvailabilityLatch:
    """One terminal availability result latched for the host binding of this bridge process.

    ``holder`` is the advisory singleton-holder identity stamped when the failure was observed;
    a different stamp later means the service was started, stopped, or replaced and the binding
    must be probed afresh. ``inherited`` counts later calls answered from the latch.
    """

    request_id: str | None
    reason: str
    code: PublicErrorCode
    message: str
    retryable: bool
    correlation_id: str
    safe_details: dict[str, object]
    holder: tuple[int, str | None, str | None, str | None] | None
    inherited: int = 0


@dataclass(slots=True)
class _ClientSlot:
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    client: ServiceClient | None = None
    availability: _AvailabilityLatch | None = None
    # Cursor's native MCP process is often launched from the host home directory. Its ordinary
    # process cwd therefore cannot be a repository authority. A Cursor slot starts unresolved and
    # is bound once from the host's MCP roots/list response; generic slots retain the build-time
    # cwd in BridgeRuntime.
    workspace_locator: WorkspaceLocator | None = None
    workspace_root_identity: tuple[int, int] | None = None
    cursor_registration_snapshot: CursorProjectMcpRegistrationSnapshot | None = None
    cursor_registration_invalid: bool = False
    workspace_binding_state: Literal["unresolved", "bound", "failed"] = "unresolved"
    workspace_binding_source: Literal["injected", "mcp_roots", "registered_project"] = "mcp_roots"
    workspace_binding_correlation_id: str | None = None
    workspace_binding_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    # Concurrent first arrivals share one on-demand probe: the owner sets attempting, waiters
    # park on attempt_finished, then re-check the completed latch (issue #476).
    attempting: bool = False
    attempt_finished: asyncio.Event | None = None


@dataclass(frozen=True, slots=True)
class BridgeRuntime:
    """Verified static surface plus one private, initially empty ordinary-client slot."""

    route_profile: McpRouteProfile
    descriptors: tuple[ToolDescriptor, ...]
    resources: tuple[GuidanceResource, ...]
    instructions: str
    host_profile: McpHostProfile = "generic"
    workspace_locator: WorkspaceLocator | None = field(
        default_factory=lambda: WorkspaceLocator(os.fspath(Path.cwd().resolve(strict=True))),
        repr=False,
        compare=False,
    )
    _slot: _ClientSlot = field(default_factory=_ClientSlot, repr=False, compare=False)
    # Desktop selectors disambiguate native roots. An explicitly approved CLI registration
    # binds its exact project only when the mode occurs in the owned registration.
    # Neither path participates in generic/Codex/Claude routes.
    cursor_project_root: str | None = field(default=None, repr=False, compare=False)
    # Keep the opened Cursor folder separate from the canonical repository selector: its
    # ``.cursor/mcp.json`` is the registration being fenced, while roots/list supplies the
    # canonical service authority.
    cursor_project_directory: str | None = field(default=None, repr=False, compare=False)
    cursor_launcher: tuple[str, ...] | None = field(default=None, repr=False, compare=False)
    cursor_isolation_root: str | None = field(default=None, repr=False, compare=False)
    cursor_project_binding: Literal["mcp-roots", "registered-project"] = "mcp-roots"


def _valid_runtime_launcher(value: object) -> bool:
    if type(value) is not tuple or not value:
        return False
    parts = cast(tuple[object, ...], value)
    for part in parts:
        if type(part) is not str or not part:
            return False
        try:
            if len(part.encode("utf-8")) > MAX_WORKSPACE_LOCATOR_BYTES:
                return False
        except UnicodeEncodeError:
            return False
        if any(ord(character) < 32 or ord(character) == 127 for character in part):
            return False
    first = parts[0]
    assert isinstance(first, str)
    return Path(first).is_absolute()


def _runtime_launcher_from_argv() -> tuple[str, ...] | None:
    """Recover the exact launcher prefix from the process that is serving MCP."""

    argv = tuple(sys.argv)
    serve_index = next(
        (
            index
            for index, token in enumerate(argv[:-1])
            if token == "mcp" and argv[index + 1] == "serve"
        ),
        None,
    )
    if serve_index is None or not argv[:serve_index]:
        return None
    prefix = argv[:serve_index]
    from yoetz.adapters.release_runtime import original_module_launcher

    original = original_module_launcher(Path(prefix[0]))
    if original is not None:
        prefix = (*original, *prefix[1:])
        return prefix if _valid_runtime_launcher(prefix) else None
    try:
        package_main = (Path(__file__).resolve().parents[1] / "__main__.py").resolve(strict=True)
        first = Path(prefix[0]).resolve(strict=True)
    except OSError:
        return None
    if first == package_main:
        try:
            executable = str(Path(sys.executable).resolve(strict=True))
        except OSError:
            return None
        prefix = (executable, "-m", "yoetz", *prefix[1:])
    else:
        prefix = (str(first), *prefix[1:])
    return prefix if _valid_runtime_launcher(prefix) else None


def build_bridge_runtime(
    route_profile: McpRouteProfile = "policy",
    *,
    host_profile: McpHostProfile = "generic",
    workspace_locator: WorkspaceLocator | None = None,
    semantic_destination: SemanticDestinationDisclosure | None = None,
    project_root: Path | None = None,
    launcher: tuple[str, ...] | None = None,
    isolation_root: str | None = None,
    project_binding: Literal["mcp-roots", "registered-project"] = "mcp-roots",
) -> BridgeRuntime:
    """Verify every agent-readable byte and construct an unconnected bridge runtime.

    Generic bridges use their process cwd as the ordinary trusted locator. Cursor bridges defer
    binding to the MCP session's client-provided roots/list response because a native Cursor helper
    may start from the user's home directory. ``workspace_locator`` is an internal injection point
    for an already trusted host binding and for transport tests; it is never read from a public
    workflow request.

    On the policy route the initialize instructions name the configured AI-powered review
    destination (issue #479). The bridge reads its configuration once here, at startup, through
    the same tolerant loader the logging sink uses; an unreadable configuration renders as an
    unknown destination rather than blocking serving. ``semantic_destination`` is an internal
    injection point for tests; the strict route never reads configuration and ignores it.
    """

    if route_profile not in TOOL_DESCRIPTORS:
        raise ValueError("mcp_route_profile_invalid")
    if host_profile not in {"generic", "codex", "claude", "cursor"}:
        raise ValueError("mcp_host_profile_invalid")
    if semantic_destination is not None and (
        type(semantic_destination) is not SemanticDestinationDisclosure
    ):
        raise TypeError("semantic_destination_wrong_type")
    resources = list_guidance_resources()
    if route_profile == "policy" and semantic_destination is None:
        semantic_destination = read_semantic_destination_disclosure()
    instructions = server_instructions(
        route_profile,
        semantic_destination=semantic_destination if route_profile == "policy" else None,
        host_profile=host_profile,
    )
    if not instructions:
        raise RuntimeError("mcp_instructions_empty")
    # Accessing every schema verifies its checked-in public identity before serving.
    descriptors = TOOL_DESCRIPTORS[route_profile]
    for descriptor in descriptors:
        descriptor.input_schema
        descriptor.output_schema
    build_last_resort_internal_error_result()
    if workspace_locator is not None and type(workspace_locator) is not WorkspaceLocator:
        raise TypeError("workspace_locator_invalid")
    if project_binding not in {"mcp-roots", "registered-project"} or (
        project_binding == "registered-project"
        and (host_profile != "cursor" or project_root is None or workspace_locator is not None)
    ):
        raise ValueError("mcp_project_binding_invalid")
    if project_root is not None and host_profile != "cursor":
        raise ValueError("mcp_project_root_host_invalid")
    cursor_project_root: str | None = None
    cursor_project_directory: str | None = None
    cursor_launcher: tuple[str, ...] | None = None
    cursor_isolation_root: str | None = None
    if project_root is not None:
        if type(project_root) is not type(Path()):
            raise TypeError("mcp_project_root_invalid")
        text = os.fspath(project_root)
        try:
            encoded = text.encode("utf-8")
        except UnicodeEncodeError:
            raise ValueError("mcp_project_root_invalid") from None
        if (
            not project_root.is_absolute()
            or ".." in project_root.parts
            or not encoded
            or len(encoded) > MAX_WORKSPACE_LOCATOR_BYTES
            or any(ord(character) < 32 or ord(character) == 127 for character in text)
        ):
            raise ValueError("mcp_project_root_invalid")
        cursor_project_root = canonical_workspace_locator(text)
        if cursor_project_root is None:
            raise ValueError("mcp_project_root_invalid")
        if not _valid_runtime_launcher(launcher):
            raise ValueError("mcp_project_launcher_invalid")
        if isolation_root is not None and type(isolation_root) is not str:
            raise TypeError("mcp_project_isolation_root_invalid")
        cursor_project_directory = text
        cursor_launcher = launcher
        cursor_isolation_root = isolation_root
    if host_profile != "cursor" and workspace_locator is None:
        workspace_locator = WorkspaceLocator(os.fspath(Path.cwd().resolve(strict=True)))
    slot = _ClientSlot()
    if host_profile == "cursor" and workspace_locator is not None:
        slot.workspace_locator = workspace_locator
        slot.workspace_binding_state = "bound"
        slot.workspace_binding_source = "injected"
    return BridgeRuntime(
        route_profile,
        descriptors,
        resources,
        instructions,
        host_profile,
        workspace_locator,
        slot,
        cursor_project_root,
        cursor_project_directory,
        cursor_launcher,
        cursor_isolation_root,
        project_binding,
    )


BRIDGE_RUNTIME: Final = build_bridge_runtime()


class _RootsSession(Protocol):
    """The MCP session capability needed to ask a host for its project roots."""

    async def list_roots(self) -> types.ListRootsResult: ...


class _RawListRootsResult(BaseModel):
    """Raw roots/list envelope used for Cursor's non-conforming POSIX root representation."""

    # MCP 1.28.1 models ``Root.uri`` as ``FileUrl`` and rejects Cursor's raw ``/absolute/path``
    # before the bridge can apply its narrow host-specific compatibility rule.  Keep this model
    # intentionally shallow; root shape and URI safety are checked below without retaining raw
    # host content.
    roots: object


class _RawRootsSession(Protocol):
    async def send_request(
        self, request: object, result_type: type[_RawListRootsResult]
    ) -> _RawListRootsResult: ...


async def _cursor_list_roots(session: _RootsSession) -> object:
    """Request Cursor roots without letting the SDK's ``FileUrl`` validator discard raw paths."""

    sender = getattr(session, "send_request", None)
    if callable(sender):
        raw_session = cast(_RawRootsSession, session)
        return await raw_session.send_request(
            types.ServerRequest(types.ListRootsRequest()), _RawListRootsResult
        )
    # Small transport fakes and older adapters expose only the typed helper.  They remain valid
    # test inputs; production ServerSession always takes the raw path above.
    return await session.list_roots()


class _CursorWorkspaceBindingError(Exception):
    """The native Cursor bridge has no trusted project locator for this MCP session."""


def _cursor_root_uri(root: object) -> str | None:
    if isinstance(root, types.Root):
        return str(root.uri)
    if isinstance(root, Mapping):
        uri = cast(Mapping[object, object], root).get("uri")
        return uri if type(uri) is str else None
    return None


def _cursor_root_path(root: object) -> str | None:
    """Decode one safe Cursor root, including its observed raw POSIX compatibility form."""

    uri = _cursor_root_uri(root)
    if uri is None:
        return None
    try:
        if len(uri.encode("utf-8")) > _MAX_CURSOR_ROOT_URI_BYTES:
            return None
    except UnicodeEncodeError:
        return None

    # Cursor 3.19 sends ``workspaceFolder.uri.toString()`` as a bare POSIX path.  This branch is
    # deliberately host-local and strict: a single-root absolute path with no URI metadata is
    # accepted as path text; authority-bearing, relative, query-bearing, or fragment-bearing
    # values continue through the rejecting URI branch below.
    if uri.startswith("/") and not uri.startswith("//"):
        try:
            path_bytes = uri.encode("utf-8")
        except UnicodeEncodeError:
            return None
        if len(path_bytes) > MAX_WORKSPACE_LOCATOR_BYTES or "?" in uri or "#" in uri:
            return None
        if any(ord(character) < 32 or ord(character) == 127 for character in uri):
            return None
        return uri
    try:
        parsed = urlsplit(uri)
    except TypeError, ValueError:
        return None
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or parsed.query
        or parsed.fragment
        or not parsed.path.startswith("/")
        or _INVALID_URI_ESCAPE.search(parsed.path) is not None
    ):
        return None
    try:
        path = unquote_to_bytes(parsed.path).decode("utf-8", errors="strict")
    except UnicodeDecodeError, ValueError:
        return None
    try:
        path_bytes = path.encode("utf-8")
    except UnicodeEncodeError:
        return None
    if (
        not path
        or len(path_bytes) > MAX_WORKSPACE_LOCATOR_BYTES
        or any(ord(character) < 32 or ord(character) == 127 for character in path)
    ):
        return None
    return path


def _cursor_roots_value(result: object) -> object | None:
    if isinstance(result, types.ListRootsResult):
        return result.roots
    if isinstance(result, _RawListRootsResult):
        return result.roots
    if isinstance(result, Mapping):
        return cast(Mapping[object, object], result).get("roots")
    return None


def _cursor_workspace_binding(
    result: object, selector: str | None = None
) -> tuple[WorkspaceLocator, str] | None:
    """Convert a host roots/list result to one canonical repository locator.

    The roots capability is a host-session input, not a workflow field. Every root must be a
    local, safe directory. Without a project selector, all roots must resolve to one canonical
    repository. With a selector, it may disambiguate a multi-root response only when that
    selector's canonical identity is present in the validated roots; it cannot create authority.
    """

    roots = _cursor_roots_value(result)
    if type(roots) is not list:
        return None
    root_items = cast(list[object], roots)
    if not root_items or len(root_items) > _MAX_CURSOR_ROOTS:
        return None
    canonical: list[str] = []
    for root in root_items:
        path = _cursor_root_path(root)
        if path is None:
            return None
        resolved = canonical_workspace_locator(path)
        if resolved is None:
            return None
        canonical.append(resolved)
    fingerprints = tuple(sorted(set(canonical), key=str.encode))
    selected = fingerprints[0] if len(fingerprints) == 1 else None
    if selector is not None:
        if selector not in fingerprints:
            return None
        selected = selector
    elif selected is None:
        return None
    try:
        assert selected is not None
        return WorkspaceLocator(selected), selected
    except ValueError:
        return None


def _cursor_workspace_locator(  # pyright: ignore[reportUnusedFunction]
    result: object, selector: str | None = None
) -> WorkspaceLocator | None:
    binding = _cursor_workspace_binding(result, selector)
    return None if binding is None else binding[0]


def _cursor_workspace_identity(path: str) -> tuple[int, int] | None:
    """Return the selected directory identity without following a replacement symlink."""

    try:
        facts = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISDIR(facts.st_mode):
        return None
    return facts.st_dev, facts.st_ino


async def _close_client(client: ServiceClient) -> None:
    try:
        await client.close()
    except Exception:
        pass


async def _discard_client(runtime: BridgeRuntime, client: ServiceClient) -> None:
    async with runtime._slot.lock:  # pyright: ignore[reportPrivateUsage]
        if runtime._slot.client is client:  # pyright: ignore[reportPrivateUsage]
            runtime._slot.client = None  # pyright: ignore[reportPrivateUsage]
    await _close_client(client)


async def ensure_service_client(
    runtime: BridgeRuntime = BRIDGE_RUNTIME,
    *,
    request_id: str | None = None,
    retain_availability_failure_for_latch: bool = False,
) -> ServiceClient:
    """Return one live ordinary client, lazily connecting without starting the service.

    On-demand connect is slot-scoped: concurrent callers share one probe (issue #476), including
    the path where a previously live client then fails its handshake and must reconnect.
    Failures release the gate so the next caller cannot be stranded. The ordinary dispatch path
    opts into retaining an availability failure only long enough for ``_latch_availability`` to
    store the shared public result. The original request identity still replays through a latched
    outage (issue #469).
    """

    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    workspace_locator = _workspace_locator_for_runtime(runtime)
    if workspace_locator is None:
        raise _CursorWorkspaceBindingError()
    keep_gate = False
    try:
        while True:
            waiter: asyncio.Event | None = None
            connected: ServiceClient | None = None
            async with slot.lock:
                if slot.availability is not None:
                    latch = slot.availability
                    if request_id is None or request_id != latch.request_id:
                        raise ControlError(latch.reason, retryable=latch.retryable)
                existing = slot.client
                if existing is not None:
                    try:
                        await existing.connect()
                    except Exception:
                        slot.client = None
                        await _close_client(existing)
                    else:
                        return existing
                if slot.attempting:
                    waiter = slot.attempt_finished
                else:
                    slot.attempting = True
                    slot.attempt_finished = asyncio.Event()
                    connected_attempt: ServiceClient | None = None
                    try:
                        connected_attempt = await connect_service_on_demand(
                            ControlClientKind.MCP_BRIDGE,
                            workspace_locator=workspace_locator,
                        )
                        await connected_attempt.connect()
                    except BaseException as exc:
                        slot.client = None
                        if connected_attempt is not None:
                            await _close_client(connected_attempt)
                        keep_gate = (
                            retain_availability_failure_for_latch
                            and isinstance(exc, ControlError)
                            and exc.reason in _AVAILABILITY_LATCH_REASONS
                        )
                        raise
                    slot.client = connected_attempt
                    connected = connected_attempt
            if connected is not None:
                await _finish_availability_attempt(runtime)
                return connected
            if waiter is None:
                continue
            await waiter.wait()
    except BaseException:
        if not keep_gate:
            await _finish_availability_attempt(runtime)
        raise


async def close_bridge_runtime(runtime: BridgeRuntime = BRIDGE_RUNTIME) -> None:
    """Close only this bridge's local client connection, never the persistent service."""

    async with runtime._slot.lock:  # pyright: ignore[reportPrivateUsage]
        client = runtime._slot.client  # pyright: ignore[reportPrivateUsage]
        runtime._slot.client = None  # pyright: ignore[reportPrivateUsage]
    if client is not None:
        await _close_client(client)


def _record_summary_degradation(
    failures: Sequence[tuple[str, BaseException]],
    *,
    request_id: str | None,
    operation: str | None,
) -> str:
    """Record which builder or clause of a text projection failed; return the agent-facing note.

    The structured result is complete when this runs, so a text failure is a diagnostic, never an
    error: each distinct site gets its own durable diagnostic line (component, operation, the
    ``<builder>.<clause>`` site as the phase, exception class and ``yoetz`` origin) and the first
    correlation id is named on the text so the failure is resolvable from what the agent sees.
    """

    seen: set[str] = set()
    first_correlation: str | None = None
    first_site: str | None = None
    for site, exc in failures:
        if site in seen or len(seen) >= _MAX_RECORDED_SUMMARY_FAILURES:
            continue
        seen.add(site)
        builder = site.partition(".")[0]
        correlation = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation=(
                f"{operation}_summary_degraded"
                if operation is not None and _SINK_OPERATION.fullmatch(operation) is not None
                else f"{builder}_summary_degraded"
            ),
            request_id=request_id,
            phase=site,
        )
        if first_correlation is None:
            first_correlation, first_site = correlation, site
    if first_correlation is None or first_site is None:
        return ""
    return (
        f"Text summary degraded at {first_site} (diagnostic correlation_id: {first_correlation}); "
        "the structured result is complete and is the record to read."
    )


def _guarded_text(
    site: str, build: Callable[[], str], failures: list[tuple[str, BaseException]]
) -> str:
    try:
        return build()
    except Exception as exc:  # noqa: BLE001 - a text section is optional; the record is structured
        failures.append((site, exc))
        return ""


def _result_text(
    wire: Mapping[str, object],
    *,
    host_profile: McpHostProfile = "generic",
    request_id: str | None = None,
    operation: str | None = None,
) -> str:
    """Project one result onto the model-visible text channel for the selected host.

    Cursor 3.17.x does not reliably deliver MCP ``structuredContent`` to the model. Its native
    plugin therefore opts into an exact canonical-JSON copy in ``content`` while retaining the
    structured result. Other hosts keep the privacy-minimized bounded summary. The Cursor copy
    adds no fields: it is byte-for-byte a second encoding of the already-authorized wire body.

    This function does not raise for a result it was handed (tb4n3 RC-2): the operation has
    committed by the time it runs, so a text section that fails to render is omitted, named in the
    text, and recorded as a service diagnostic -- the structured result is returned either way.
    """

    if host_profile not in {"generic", "codex", "claude", "cursor"}:
        raise ValueError("mcp_host_profile_invalid")
    failures: list[tuple[str, BaseException]] = []
    if host_profile == "cursor":
        try:
            return canonical_encode(cast(JsonValue, dict(wire))).decode("utf-8")
        except Exception as exc:  # noqa: BLE001 - fall back to the bounded summary below
            failures.append(("cursor.canonical_json", exc))
    rendered = render_safe_compact_summary_detailed(wire)
    failures.extend(rendered.failures)
    compact = rendered.text
    if wire.get("preparatory_only") is True:
        parts: tuple[str, ...] = (compact,)
    else:
        awaiting = _guarded_text("awaiting", lambda: summary_for_check_awaiting(wire), failures)
        if awaiting:
            # A paused check has no verdict; its continuation is the only actionable fact, so it
            # leads.
            compact = f"{awaiting}\n{compact}" if compact else awaiting
        reviewer = _guarded_text(
            "reviewer_output", lambda: render_check_reviewer_output(wire), failures
        )
        totals = _guarded_text("totals", lambda: render_check_totals(wire.get("totals")), failures)
        manifest = _guarded_text(
            "manifest",
            lambda: render_review_input_manifest_compact(wire.get("review_input_manifest")),
            failures,
        )
        if manifest and manifest in compact:
            manifest = ""
        # #985: a publish result's fixed yoetz-blocker challenge reaches the model, dry runs
        # included.
        blocker_notices = _guarded_text(
            "blocker_notices", lambda: render_publish_blocker_notices(wire), failures
        )
        # tb4n5 follow-up: an action the batch recorded with no result naming it, dry runs included.
        action_notices = _guarded_text(
            "action_notices", lambda: render_publish_action_notices(wire), failures
        )
        parts = (compact, totals, manifest, reviewer, blocker_notices, action_notices)
    note = (
        _record_summary_degradation(failures, request_id=request_id, operation=operation)
        if failures
        else ""
    )
    return "\n".join(part for part in (*parts, note) if part)


def result_from_public_model(
    result: object,
    *,
    host_profile: McpHostProfile = "generic",
    request_id: str | None = None,
    operation: str | None = None,
) -> types.CallToolResult:
    """Validate and project one public result to structured plus host-compatible text."""

    wire = public_model_to_wire(result)
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=_result_text(
                    wire, host_profile=host_profile, request_id=request_id, operation=operation
                ),
            )
        ],
        structuredContent=cast(dict[str, object], wire),
        isError=wire.get("ok") is False,
    )


def _serialized_mcp_result_bytes(
    result: types.CallToolResult,
    *,
    transport_request_id: types.RequestId | None,
) -> int:
    """Measure the exact JSON-RPC payload that ``bounded_stdio_server`` will write."""

    # Direct dispatcher tests have no transport envelope id. The live handler supplies the
    # context request ID; zero keeps the direct path measurable without fabricating user data.
    wire_id: types.RequestId = 0 if transport_request_id is None else transport_request_id
    response = types.JSONRPCResponse(
        jsonrpc="2.0",
        id=wire_id,
        result=result.model_dump(by_alias=True, mode="json", exclude_none=True),
    )
    return len(response.model_dump_json(by_alias=True, exclude_none=True).encode("utf-8"))


def _result_from_wire(
    wire: Mapping[str, object],
    *,
    host_profile: McpHostProfile = "generic",
) -> types.CallToolResult:
    structured = dict(wire)
    return types.CallToolResult(
        content=[
            types.TextContent(
                type="text",
                text=_result_text(structured, host_profile=host_profile),
            )
        ],
        structuredContent=structured,
        isError=True,
    )


# Bridge operation names are repository literals ("check", "publish_work", …); the guard keeps a
# malformed one from silently voiding the sink record, whose ``operation`` field is required.
_SINK_OPERATION: Final = re.compile(r"^[a-z][a-z0-9_]{0,47}$", re.ASCII)


def _public_error_operation(operation: str | None) -> str:
    """Return the bounded sink operation token for a bridge-minted public error."""

    if type(operation) is str and _SINK_OPERATION.fullmatch(operation) is not None:
        return f"{operation}_public_error"
    return "public_error"


def structured_error_result(
    code: PublicErrorCode,
    message: str,
    *,
    retryable: bool = False,
    request_id: str | None = None,
    safe_details: object | None = None,
    details_reason_code: str | None = None,
    correlation_id: str | None = None,
    operation: str | None = None,
    diagnostic_reason: str | None = None,
    host_profile: McpHostProfile = "generic",
) -> types.CallToolResult:
    """Build a bounded structured tool error with a prevalidated nested fallback.

    ``correlation_id`` is an id some sink already recorded — service-minted, or returned by the
    exception recorder — and is reused verbatim. When it is absent this mints the id *and* writes
    the durable diagnostic line under it, because an id minted straight into the envelope resolves
    to nothing (issue #191). ``operation`` only names the failing tool in that record; it never
    reaches the wire. ``details_reason_code`` rides beside field locations, which no other
    ``safe_details`` shape can carry. ``diagnostic_reason`` names the sink ``reason`` when this
    boundary mints the id; it must be a bounded token. Unrecognized values fall back to the
    lowercased public code.
    """

    sink_reason = (
        diagnostic_reason
        if type(diagnostic_reason) is str
        and _SINK_OPERATION.fullmatch(diagnostic_reason) is not None
        else code.value.lower()
    )
    resolved_correlation_id = (
        correlation_id
        if correlation_id is not None
        else record_public_error_without_raising(
            component="mcp.bridge",
            operation=_public_error_operation(operation),
            reason=sink_reason,
            request_id=request_id,
        )
    )
    try:
        wire = build_public_error_result(
            code,
            message,
            retryable,
            resolved_correlation_id,
            request_id=request_id,
            safe_details=safe_details,
            details_reason_code=details_reason_code,
        )
        return _result_from_wire(wire, host_profile=host_profile)
    except Exception:
        fallback = build_last_resort_internal_error_result()
        try:
            return _result_from_wire(fallback, host_profile=host_profile)
        except Exception:
            text = (
                canonical_encode(cast(JsonValue, fallback)).decode("utf-8")
                if host_profile == "cursor"
                else "Error INTERNAL_ERROR."
            )
            return types.CallToolResult(
                content=[types.TextContent(type="text", text=text)],
                structuredContent=fallback,
                isError=True,
            )


def _cursor_workspace_error(
    runtime: BridgeRuntime,
    request_id: str | None,
    operation: str,
    *,
    binding_changed: bool = False,
    registration_invalid: bool = False,
) -> types.CallToolResult:
    """Return one bounded, repeatable error for an unbound native Cursor session."""

    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    if binding_changed:
        message = (
            "Cursor's registered project or selected repository changed during this MCP "
            "session. Reconnect the MCP server with that project open, then retry in a fresh "
            "conversation. Hook workspace data and CLI CWD cannot substitute for roots/list."
        )
    elif registration_invalid:
        message = (
            "Cursor's project MCP registration is missing or does not match the exact Yoetz "
            "launcher, route, project selector, or isolated root. Reconnect the MCP server "
            "with that project open, then retry in a fresh conversation."
        )
    elif runtime.cursor_project_root is not None:
        message = (
            "Cursor did not provide one safe local project root matching the registered project "
            "selector through MCP roots/list. Reconnect the MCP server with that project open, "
            "then retry in a fresh conversation. Hook workspace data and CLI CWD cannot "
            "substitute for roots/list."
        )
    else:
        message = (
            "Cursor did not provide one safe local project root through MCP roots/list. "
            "If a plugin-managed server has no roots, use yoetz integrate cursor project-mcp "
            "to register one project .cursor/mcp.json entry with an external-registration "
            "plugin and no duplicate Yoetz MCP sources. Reconnect the MCP server with that "
            "project open, then retry in a fresh conversation. Hook workspace data and CLI "
            "CWD cannot substitute for roots/list."
        )
    result = structured_error_result(
        PublicErrorCode.SESSION_CONFLICT,
        message,
        request_id=request_id,
        correlation_id=slot.workspace_binding_correlation_id,
        operation=operation,
        diagnostic_reason="repository_identity_required",
        safe_details={
            "host_profile": "cursor",
            "reason_code": "repository_identity_required",
        },
        host_profile=runtime.host_profile,
    )
    # A failed roots/list exchange is session-scoped. Reusing its correlation id keeps repeated
    # delegated calls from minting one diagnostic per tool while preserving the same public fact.
    if slot.workspace_binding_correlation_id is None:
        wire = _wire_error(result)
        if wire is not None and type(wire.get("correlation_id")) is str:
            slot.workspace_binding_correlation_id = cast(str, wire["correlation_id"])
    return result


async def _ensure_cursor_workspace_binding(
    runtime: BridgeRuntime,
    session: _RootsSession | None,
    request_id: str | None,
    operation: str,
) -> types.CallToolResult | None:
    """Bind and revalidate a Cursor bridge against the host's MCP roots/list response.

    Native Cursor helpers can launch from a user home directory, so process cwd is not a valid
    repository selector for this host profile. The binding is fetched only from the active MCP
    session and cached for that bridge process; no workflow request field participates.
    """

    if runtime.host_profile != "cursor":
        return None
    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    retire_client = False
    binding_error: types.CallToolResult | None = None
    async with slot.workspace_binding_lock:
        if (
            slot.workspace_binding_state == "bound"
            and slot.workspace_binding_source == "injected"
            and runtime.cursor_project_directory is None
        ):
            return None
        if slot.workspace_binding_state == "failed":
            return _cursor_workspace_error(
                runtime,
                request_id,
                operation,
                registration_invalid=slot.cursor_registration_invalid,
            )
        was_bound = slot.workspace_binding_state == "bound"
        registration: CursorProjectMcpRegistrationSnapshot | None = None
        registration_invalid = False
        if runtime.cursor_project_directory is not None:
            if runtime.cursor_launcher is None:
                registration_invalid = True
            else:
                try:
                    registration = inspect_project_mcp_registration(
                        Path(runtime.cursor_project_directory),
                        launcher=runtime.cursor_launcher,
                        route_profile=runtime.route_profile,
                        isolation_root=runtime.cursor_isolation_root,
                        project_binding=runtime.cursor_project_binding,
                    )
                except CursorProjectMcpError, OSError, TypeError, ValueError:
                    registration_invalid = True
            if registration_invalid:
                slot.workspace_binding_state = "failed"
                slot.workspace_locator = None
                slot.workspace_root_identity = None
                slot.cursor_registration_snapshot = None
                slot.cursor_registration_invalid = True
                binding_error = _cursor_workspace_error(
                    runtime,
                    request_id,
                    operation,
                    binding_changed=was_bound,
                    registration_invalid=True,
                )
                retire_client = True
            elif was_bound and slot.cursor_registration_snapshot != registration:
                slot.workspace_binding_state = "failed"
                slot.workspace_locator = None
                slot.workspace_root_identity = None
                slot.cursor_registration_snapshot = None
                slot.cursor_registration_invalid = False
                slot.workspace_binding_correlation_id = None
                binding_error = _cursor_workspace_error(
                    runtime,
                    request_id,
                    operation,
                    binding_changed=True,
                )
                retire_client = True
        if (
            binding_error is None
            and session is None
            and runtime.cursor_project_binding == "mcp-roots"
        ):
            slot.workspace_binding_state = "failed"
            slot.workspace_locator = None
            slot.workspace_root_identity = None
            slot.cursor_registration_snapshot = None
            slot.cursor_registration_invalid = False
            binding_error = _cursor_workspace_error(runtime, request_id, operation)
            retire_client = True
        elif binding_error is None:
            try:
                if runtime.cursor_project_binding == "registered-project":
                    # Explicit operator-selected CLI registration; never an automatic
                    # fallback from absent roots or client-supplied identity metadata.
                    assert runtime.cursor_project_root is not None
                    assert runtime.cursor_project_directory is not None
                    selected_path = canonical_workspace_locator(runtime.cursor_project_directory)
                    locator = (
                        WorkspaceLocator(selected_path)
                        if selected_path is not None
                        and selected_path == runtime.cursor_project_root
                        else None
                    )
                else:
                    async with asyncio.timeout(_CURSOR_ROOTS_REQUEST_TIMEOUT_SECONDS):
                        assert session is not None
                        roots = await _cursor_list_roots(session)
                    binding = _cursor_workspace_binding(roots, runtime.cursor_project_root)
                    locator = None if binding is None else binding[0]
                    selected_path = None if binding is None else binding[1]
            except Exception:
                slot.workspace_binding_state = "failed"
                slot.workspace_locator = None
                slot.workspace_root_identity = None
                slot.cursor_registration_snapshot = None
                slot.cursor_registration_invalid = False
                binding_error = _cursor_workspace_error(runtime, request_id, operation)
                retire_client = True
            else:
                selected_identity = (
                    None if selected_path is None else _cursor_workspace_identity(selected_path)
                )
                if (
                    locator is None
                    or selected_identity is None
                    or (was_bound and slot.workspace_locator != locator)
                    or (was_bound and slot.workspace_root_identity != selected_identity)
                ):
                    # Cursor 3.19 advertises roots.listChanged=false, so a notification cannot be
                    # relied on to retire a process after the user switches projects. Revalidate
                    # before every workflow call and retire the old client on any change.
                    slot.workspace_binding_state = "failed"
                    slot.workspace_locator = None
                    slot.workspace_root_identity = None
                    slot.cursor_registration_snapshot = None
                    slot.cursor_registration_invalid = False
                    slot.workspace_binding_correlation_id = None
                    binding_error = _cursor_workspace_error(
                        runtime,
                        request_id,
                        operation,
                        binding_changed=was_bound,
                    )
                    retire_client = True
                else:
                    latest_registration = registration
                    latest_registration_invalid = False
                    if runtime.cursor_project_directory is not None:
                        if runtime.cursor_launcher is None:
                            latest_registration_invalid = True
                        else:
                            try:
                                latest_registration = inspect_project_mcp_registration(
                                    Path(runtime.cursor_project_directory),
                                    launcher=runtime.cursor_launcher,
                                    route_profile=runtime.route_profile,
                                    isolation_root=runtime.cursor_isolation_root,
                                    project_binding=runtime.cursor_project_binding,
                                )
                            except CursorProjectMcpError, OSError, TypeError, ValueError:
                                latest_registration_invalid = True
                        if runtime.cursor_project_binding == "registered-project" and (
                            canonical_workspace_locator(runtime.cursor_project_directory)
                            != runtime.cursor_project_root
                            or _cursor_workspace_identity(runtime.cursor_project_root or "")
                            != selected_identity
                        ):
                            latest_registration_invalid = True
                        if latest_registration_invalid or latest_registration != registration:
                            slot.workspace_binding_state = "failed"
                            slot.workspace_locator = None
                            slot.workspace_root_identity = None
                            slot.cursor_registration_snapshot = None
                            slot.cursor_registration_invalid = latest_registration_invalid
                            slot.workspace_binding_correlation_id = None
                            binding_error = _cursor_workspace_error(
                                runtime,
                                request_id,
                                operation,
                                binding_changed=was_bound,
                                registration_invalid=latest_registration_invalid or not was_bound,
                            )
                            retire_client = True
                    if binding_error is None:
                        slot.workspace_locator = locator
                        slot.workspace_root_identity = selected_identity
                        slot.cursor_registration_snapshot = latest_registration
                        slot.cursor_registration_invalid = False
                        slot.workspace_binding_state = "bound"
                        slot.workspace_binding_source = (
                            "registered_project"
                            if runtime.cursor_project_binding == "registered-project"
                            else "mcp_roots"
                        )
    if retire_client:
        await close_bridge_runtime(runtime)
    if binding_error is not None:
        return binding_error
    return None


async def _invalidate_cursor_workspace_binding(runtime: BridgeRuntime) -> None:
    """Retire this bridge when the host says its project roots changed.

    Rebinding an existing MCP process would let one service-client slot cross repository
    authorities. The safe lifecycle is to discard the old client and require the host to create a
    fresh bridge session, which asks roots/list again.
    """

    if runtime.host_profile != "cursor":
        return
    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    async with slot.workspace_binding_lock:
        slot.workspace_locator = None
        slot.workspace_root_identity = None
        slot.cursor_registration_snapshot = None
        slot.cursor_registration_invalid = False
        slot.workspace_binding_state = "failed"
        slot.workspace_binding_correlation_id = None
    await close_bridge_runtime(runtime)


def _workspace_locator_for_runtime(runtime: BridgeRuntime) -> WorkspaceLocator | None:
    if runtime.host_profile == "cursor":
        return runtime._slot.workspace_locator  # pyright: ignore[reportPrivateUsage]
    return runtime.workspace_locator


def _control_public_error_result(
    error: ControlError,
    request_id: str | None,
    operation: str,
    *,
    code: PublicErrorCode,
    message: str,
    retryable: bool,
    host_profile: McpHostProfile,
    safe_details: Mapping[str, object] | None = None,
    diagnostic_reason: str | None = None,
) -> types.CallToolResult:
    """Map a typed ControlError through the public-error recorder, never the unexpected path."""

    return structured_error_result(
        code,
        message,
        retryable=retryable,
        request_id=request_id,
        correlation_id=error.correlation_id,
        operation=operation,
        safe_details=dict(safe_details) if safe_details is not None else None,
        diagnostic_reason=diagnostic_reason if diagnostic_reason is not None else error.reason,
        host_profile=host_profile,
    )


async def _vault_initialization_continuation(
    runtime: BridgeRuntime, request_id: str | None
) -> dict[str, object] | None:
    """Return the typed initialization-required continuation, or None when it does not apply.

    A non-retryable ``vault_locked`` covers both a hard lock (existing unlock/recovery paths own
    it) and a never-initialized vault (issue #512: the start-first flow dead-ended). The failing
    client was already discarded (`_DISCARD_CLIENT_REASONS`), so the reconnect below performs a
    fresh handshake whose hello-result carries the current structural service status — the one
    surface an ordinary bridge peer is allowed. Any failure here degrades to the plain hard-lock
    error rather than asserting an initialization state this bridge could not read.
    """

    try:
        client = await ensure_service_client(runtime, request_id=request_id)
        status = client.hello_service_status
        applies = (
            status is not None
            and status.state is ServiceState.LOCKED
            and status.vault_mode == "uninitialized"
        )
    except Exception:
        return None
    if not applies:
        return None
    details: dict[str, object] = {
        "continuation": _VAULT_INITIALIZATION_CONTINUATION,
        "pending_ttl_seconds": CONSENT_PENDING_TTL_SECONDS,
        "prepare_command": _VAULT_INITIALIZE_PREPARE_COMMAND,
        "review_command": _CONSENT_REVIEW_COMMAND,
    }
    # Host identity never grants agent-chat attestation. Cursor is never an agent-chat
    # attestation client, and the bridge knows that binding positively. Other profiles may carry
    # the reviewed command, but the elevated authorize path still requires its independent
    # allowlisted client-kind and current-chat facts.
    if runtime.host_profile != "cursor":
        details["authorize_command"] = _CONSENT_AUTHORIZE_COMMAND
    if request_id is not None:
        details["replay_request_id"] = request_id
    return details


def _vault_initialization_required_message(include_authorize: bool) -> str:
    authorize_clause = (
        "If the user gave an exact approval in the current chat and this host is an allowlisted "
        "first-party attestation client, relay that exact pending decision with "
        "`yoetz consent authorize` and the warning acknowledged; otherwise direct"
        if include_authorize
        else "Direct"
    )
    return (
        "The local service vault is uninitialized: first-run initialization must complete before "
        "any Yoetz task can start. This is a bounded initialization-required continuation "
        "(safe_details.continuation), not an ordinary terminal error. Run "
        "`yoetz consent prepare vault_initialize`, show the returned danger text to the user, "
        "and wait for their exact decision; if a pending consent action already exists, read it "
        "with `yoetz consent status` instead of preparing another. Yoetz generates and stores "
        "the initialization secret locally; never request, receive, or transmit a secret or "
        f"recovery material. {authorize_clause} the user to run `yoetz consent review` on a "
        "local terminal. After initialization reports ready, replay this exact request_id and "
        "body once to start the task. On denial or expiry, continue without Yoetz."
    )


def _control_error_result(
    error: ControlError,
    request_id: str | None,
    operation: str,
    *,
    host_profile: McpHostProfile = "generic",
    vault_initialization_details: Mapping[str, object] | None = None,
    timeout_handle: Mapping[str, object] | None = None,
    check_mode: object = None,
) -> types.CallToolResult:
    # ``check_mode`` is the request's ``mode``: a ``check`` that records nothing (ADR-047,
    # ``inspect``) times out as a read, never as a write that may have committed.
    # Prefer the service-minted diagnostic id when present so the agent-facing public error
    # resolves the same durable sink record the daemon already wrote. Never mint a second id for
    # a failure the service already correlated.
    if error.reason == "vault_locked":
        # The daemon's retryable flag distinguishes a soft lock or transient re-unlock
        # failure (heals on a later attempt) from a hard lock or missing setup (needs a
        # trusted ceremony). Asserting the terminal cause for a transient one told agents
        # to abandon evidence and receipts that a single retry would have recorded (#276).
        if not error.retryable and vault_initialization_details is not None:
            return _control_public_error_result(
                error,
                request_id,
                operation,
                code=PublicErrorCode.VAULT_LOCKED,
                message=_vault_initialization_required_message(
                    "authorize_command" in vault_initialization_details
                ),
                retryable=False,
                host_profile=host_profile,
                safe_details=vault_initialization_details,
                diagnostic_reason="vault_initialization_required",
            )
        if error.retryable:
            message = (
                "The local service vault is soft-locked or a transient unlock attempt just "
                "failed; it re-opens automatically. Retry this operation shortly. If the "
                "error persists, on a local terminal run `yoetz service unlock` or "
                "`yoetz service auto-unlock repair`. If those no longer work, run "
                "`yoetz service recovery status` for the supported zero-secret handoff. "
                "Never send secrets or recovery paths over MCP."
            )
        else:
            message = (
                "The local service vault is locked or uninitialized. After trusted setup with "
                "platform auto-unlock, soft locks (idle/session) re-open automatically; this "
                "error means a hard lock or missing setup. On a local terminal run "
                "`yoetz service unlock` (uses the platform credential store when provisioned) "
                "or `yoetz service auto-unlock repair` if that entry is stale. If unlock "
                "authority may be lost, run `yoetz service recovery status`; follow only its "
                "exact trusted command and never send a secret or recovery path through the "
                "agent. If still "
                "uninitialized, run `yoetz setup` or prepare `vault_initialize` via "
                "`yoetz consent catalog` / `prepare` (ADR-015). Never send secrets over MCP."
            )
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.VAULT_LOCKED,
            message=message,
            retryable=error.retryable,
            host_profile=host_profile,
        )
    if error.reason == "request_cancelled":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.CANCELLED,
            message="The operation was cancelled.",
            retryable=False,
            host_profile=host_profile,
        )
    if error.reason == "privacy_projection_blocked":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.PRIVACY_AUTHORITY_REQUIRED,
            message=(
                "The receipt is durably recorded, but JSON projection to agent context is blocked "
                "by the active privacy policy. Re-request with format markdown or text, or widen "
                "the agent-context policy from a local terminal."
            ),
            retryable=False,
            host_profile=host_profile,
            safe_details={
                "reason_code": "receipt_json_projection_blocked",
                "operation": "receipt",
                "field": "format",
            },
        )
    if error.reason == "response_projection_failed":
        # Accepted durable publish_work usually returns the reduced total-acceptance envelope
        # instead. This mapping remains for non-publish writes and for the genuinely impossible
        # case where even the minimal publish envelope cannot be built. When the daemon attached
        # accepted_state (sequence/head_digest/count), surface those structural facts so the
        # agent does not need a second status call to learn where the write landed.
        details: dict[str, object] = dict(_RESPONSE_PROJECTION_FAILED_DETAILS)
        if error.accepted_state:
            details.update(error.accepted_state)
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INTERNAL_ERROR,
            message=_RESPONSE_PROJECTION_FAILED_MESSAGE,
            retryable=True,
            host_profile=host_profile,
            safe_details=details,
        )
    if error.reason == "read_projection_failed":
        details: dict[str, object] = dict(_READ_PROJECTION_FAILED_DETAILS)
        if error.phase is not None:
            details["phase"] = error.phase
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INTERNAL_ERROR,
            message=_READ_PROJECTION_FAILED_MESSAGE,
            retryable=True,
            host_profile=host_profile,
            safe_details=details,
        )
    if error.reason == "privacy_projection_unavailable":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "Receipt projection is temporarily unavailable; retry after the local service is ready."
            ),
            retryable=True,
            host_profile=host_profile,
            safe_details={"reason_code": "privacy_projection_unavailable"},
        )
    if error.reason == "request_timeout":
        operation_kind = timeout_operation_kind(
            operation, write_operations=_WRITE_OPERATIONS, check_mode=check_mode
        )
        if operation_kind == "start":
            # A lost start returns neither session nor writer id, so the operation view the
            # generic write recovery names cannot be queried. The shipped guidance excepts this
            # case explicitly: replay the exact start once under the same request_id.
            message = (
                "The local start timed out and may still have committed. Replay the exact same "
                "start body once with the same request_id; the idempotent start path returns the "
                "stored result or a typed boundary. Do not fabricate session or writer ids for a "
                "status query."
            )
        elif operation_kind == "write":
            message = (
                "The local operation timed out and may still have committed. Retry with the same "
                "request_id to recover the stored outcome; for an existing Yoetz session, status "
                "view=operation can inspect that request_id."
            )
        else:
            message = (
                "The local read timed out and requested no write. Repeat the read with a new "
                "request_id."
            )
        # The read-versus-write distinction above was previously legible only in the free-form
        # message, which the native text channel drops by design; a typed continuation carries it
        # to the model that has to act on it (issue #669).
        timeout_details: dict[str, object] = {"reason_code": "request_timeout"}
        if error.phase is not None:
            timeout_details["phase"] = error.phase
        if operation_kind == "write" and request_id is not None:
            timeout_details["replay_request_id"] = request_id
            if timeout_handle is not None:
                # A pollable handle: status with these ids, view=operation and
                # filter.operation_request_id=replay_request_id returns the stored outcome.
                timeout_details.update(timeout_handle)
        continuation = continuation_for_reason("request_timeout", operation_kind=operation_kind)
        if continuation is not None:
            timeout_details["continuation"] = continuation
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=message,
            retryable=True,
            host_profile=host_profile,
            safe_details=timeout_details,
        )
    if error.reason in {"service_incompatible", "protocol_mismatch"}:
        # The one per-user endpoint is owned by a service of another Yoetz installation (or
        # protocol generation) that rejected this bridge's hello. On-demand startup already
        # tried to replace it; name the exact repair instead of an opaque internal failure.
        # MCP keeps SERVICE_UNAVAILABLE for both; CLI maps protocol_mismatch to INVALID_REQUEST.
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "Yoetz was updated while this session was open, and a newer session already "
                "switched the local service to the new version, which this session's older "
                "bridge cannot use. Ask the user to reopen this session (or restart the agent "
                "app); the new version then attaches automatically. Retry this operation with "
                "the same request_id after that. Do not run service lifecycle commands for this."
            )
            if _holder_is_newer_than_bridge()
            else (
                "The running local Yoetz service belongs to a different Yoetz installation than "
                "this bridge (control schema-manifest or protocol mismatch), and the bridge could "
                "not replace it within its startup budget. On a local terminal run "
                "`yoetz service restart`, then retry this operation with the same request_id. "
                "Do not retry `start` until that repair has run."
            ),
            retryable=error.retryable,
            host_profile=host_profile,
            safe_details={"reason_code": error.reason},
        )
    if error.reason == "service_draining":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message="The local service is draining; retry after it is ready.",
            retryable=True,
            host_profile=host_profile,
            safe_details={"reason_code": "service_draining"},
        )
    if error.reason == "service_unavailable":
        startup = None
        if error.phase in SERVICE_STARTUP_PHASES:
            # Imported here: the bridge's import graph stays the ordinary service client alone.
            from yoetz.service.startup_failure import spawned_startup_failure

            startup = spawned_startup_failure(error.phase, error.correlation_id)
        if startup is not None:
            # The service this bridge spawned exited during startup (#1040). Waiting and
            # retrying cannot help, and "not running; run it" hid why; the record behind the
            # correlation_id names the stage, exception class and origin, and so does this text.
            return _control_public_error_result(
                error,
                request_id,
                operation,
                code=PublicErrorCode.SERVICE_UNAVAILABLE,
                message=(
                    f"The local Yoetz service exited while starting ({startup.describe()}), so "
                    "it is not running and nothing was recorded. Retrying fails the same way "
                    "until the cause is repaired. Give the user this correlation_id; 'yoetz "
                    "service diagnostics --correlation-id' with it shows the bounded record. Do "
                    "not run service lifecycle commands to work around it."
                ),
                retryable=False,
                host_profile=host_profile,
                safe_details={"reason_code": "service_start_failed", "phase": startup.stage},
                diagnostic_reason="service_start_failed",
            )
        handshake = handshake_failure(error)
        if handshake is not None:
            # A running service whose stamp names no other installation closed this bridge's
            # hello without answering (#1040 follow-up). Calling it another installation sent
            # agents to `yoetz service restart`, which cannot replace an identical holder.
            details: dict[str, object] = {
                "reason_code": "service_handshake_failed",
                "phase": handshake,
            }
            if handshake == "handshake_git_version":
                details["continuation"] = "system_git_upgrade_required"
                message = (
                    "The local Yoetz service closed the connection while setting it up, and the "
                    "system Git it reads this workspace's repository with is older than 2.25, "
                    "the oldest Git Yoetz supports. Ask the user to install Git 2.25 or later as "
                    "the system Git; a newer Git elsewhere on PATH does not help. Then retry this "
                    "operation with the same request_id. Do not run service lifecycle commands "
                    "for this."
                )
            else:
                message = (
                    "The local Yoetz service closed the connection while setting it up and "
                    "answered nothing, so nothing was recorded. Its stamp does not show another "
                    "installation, so it was not replaced. It recorded "
                    "why: give the user this correlation_id and ask them to run 'yoetz service "
                    "diagnostics' on a local terminal. Do not run service lifecycle commands for "
                    "this."
                )
            return _control_public_error_result(
                error,
                request_id,
                operation,
                code=PublicErrorCode.SERVICE_UNAVAILABLE,
                message=message,
                retryable=False,
                host_profile=host_profile,
                safe_details=details,
                diagnostic_reason="service_handshake_failed",
            )
        if accepted_but_unresponsive(error):
            # A listener that accepted and then went silent is running. Prescribing
            # `yoetz service run` here sent an operator to a command that must refuse (#237).
            return _control_public_error_result(
                error,
                request_id,
                operation,
                code=PublicErrorCode.SERVICE_UNAVAILABLE,
                message=(
                    "The local Yoetz service is listening but did not answer. Wait and retry; on a "
                    "local terminal run `yoetz service status`. Do not run `yoetz service run` — "
                    "it will refuse while that process holds the singleton. If it is wedged, stop "
                    "it with `yoetz service stop`, then retry this operation with the same "
                    "request_id."
                ),
                retryable=True,
                host_profile=host_profile,
                safe_details={"reason_code": "accepted_but_unresponsive"},
                diagnostic_reason="accepted_but_unresponsive",
            )
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "The local Yoetz service is not running. On a local terminal run "
                "'yoetz service run' under your selected user supervisor, then retry this "
                "operation with the same request_id."
            ),
            retryable=True,
            host_profile=host_profile,
            safe_details={"reason_code": "service_unavailable"},
        )
    if error.reason == "service_generation_changed":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "The local service instance changed after reconnect. Retry this operation with "
                "the same request_id."
            ),
            retryable=True,
            host_profile=host_profile,
            safe_details={"reason_code": "service_generation_changed"},
        )
    if error.reason == "peer_untrusted":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "The local control endpoint identity could not be trusted. Repair the endpoint "
                "on a local terminal; do not retry until that repair has run. Then retry this "
                "operation with the same request_id."
            ),
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": "peer_untrusted"},
        )
    if error.reason == "endpoint_unsafe":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.SERVICE_UNAVAILABLE,
            message=(
                "The local control endpoint is unsafe to use. Repair the endpoint on a local "
                "terminal; do not retry until that repair has run. Then retry this operation "
                "with the same request_id."
            ),
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": "endpoint_unsafe"},
        )
    if error.reason in {"frame_invalid", "invalid_request"}:
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INVALID_REQUEST,
            message="The local control request was invalid.",
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": error.reason},
        )
    if error.reason == "frame_too_large":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INVALID_REQUEST,
            message="The local control frame exceeded the allowed size.",
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": "frame_too_large"},
        )
    if error.reason == "method_forbidden":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INVALID_REQUEST,
            message="The local control method is not allowed.",
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": "method_forbidden"},
        )
    if error.reason == "internal_error":
        return _control_public_error_result(
            error,
            request_id,
            operation,
            code=PublicErrorCode.INTERNAL_ERROR,
            message=_INTERNAL_STAGE_MESSAGES["bridge_invoke_failed"],
            retryable=False,
            host_profile=host_profile,
            safe_details={"reason_code": "bridge_invoke_failed"},
        )
    # Last resort: a ControlError reason this mapper does not yet name. Keep the unexpected
    # recorder so a future vocabulary addition cannot silently ship as a public-error class.
    if error.correlation_id is not None:
        return _internal_stage_error(
            "bridge_invoke_failed",
            request_id=request_id,
            correlation_id=error.correlation_id,
            host_profile=host_profile,
            operation=operation,
        )
    correlation_id = record_unexpected_exception_without_raising(
        error,
        component="mcp.bridge",
        operation=f"{operation}_internal_error",
        request_id=request_id,
    )
    return _internal_stage_error(
        "bridge_invoke_failed",
        request_id=request_id,
        correlation_id=correlation_id,
        host_profile=host_profile,
        operation=operation,
    )


def _mutable_json(value: object) -> object:
    if isinstance(value, Mapping):
        source = cast(Mapping[object, object], value)
        return {str(key): _mutable_json(item) for key, item in source.items()}
    if isinstance(value, tuple | list):
        source_sequence = cast(tuple[object, ...] | list[object], value)
        return [_mutable_json(item) for item in source_sequence]
    return value


def _holder_is_newer_than_bridge() -> bool:
    """True when the stamped holder runs a newer package: this bridge predates an update."""

    try:
        holder = service_holder_identity()
    except Exception:
        return False
    return holder is not None and holder_version_order(holder.service_version) == "newer"


def _holder_snapshot() -> tuple[int, str | None, str | None, str | None] | None:
    """Advisory identity of the stamped live service holder, or ``None`` when unknown."""

    try:
        holder = service_holder_identity()
    except Exception:
        return None
    if holder is None:
        return None
    return (holder.pid, holder.instance_id, holder.schema_manifest_digest, holder.service_version)


def _wire_error(result: types.CallToolResult) -> Mapping[str, object] | None:
    structured = result.structuredContent
    if not isinstance(structured, Mapping):
        return None
    error = cast(Mapping[str, object], structured).get("error")
    return cast(Mapping[str, object], error) if isinstance(error, Mapping) else None


def _availability_details(
    existing: object, host_profile: str, route_profile: str
) -> dict[str, object]:
    details: dict[str, object] = (
        dict(cast(Mapping[str, object], existing)) if isinstance(existing, Mapping) else {}
    )
    details["availability"] = _AVAILABILITY_TERMINAL
    details["host_profile"] = host_profile
    details["route_profile"] = route_profile
    return details


async def _latch_availability(
    runtime: BridgeRuntime,
    request_id: str | None,
    error: ControlError,
    result: types.CallToolResult,
) -> types.CallToolResult:
    """Record a terminal availability result for this binding and return it with that fact."""

    try:
        slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
        wire = _wire_error(result)
        if wire is None:
            return result
        code_value = wire.get("code")
        message = wire.get("message")
        retryable = wire.get("retryable")
        correlation_id = wire.get("correlation_id")
        if (
            type(code_value) is not str
            or type(message) is not str
            or type(retryable) is not bool
            or type(correlation_id) is not str
        ):
            return result
        try:
            code = PublicErrorCode(code_value)
        except ValueError:
            return result
        details = _availability_details(
            wire.get("safe_details"), runtime.host_profile, runtime.route_profile
        )
        latch = _AvailabilityLatch(
            request_id,
            error.reason,
            code,
            message,
            retryable,
            correlation_id,
            details,
            _holder_snapshot(),
        )
        already = False
        async with slot.lock:
            existing = slot.availability
            if (
                existing is not None
                and request_id is not None
                and request_id == existing.request_id
            ):
                slot.availability = latch
            elif existing is not None:
                already = True
            else:
                slot.availability = latch
        if already:
            inherited = await _inherit_terminal_availability(runtime, request_id)
            if inherited is not None:
                return inherited
        return structured_error_result(
            code,
            message,
            retryable=retryable,
            request_id=request_id,
            correlation_id=correlation_id,
            safe_details=details,
            host_profile=runtime.host_profile,
        )
    finally:
        await _finish_availability_attempt(runtime)


async def _clear_availability(runtime: BridgeRuntime) -> None:
    async with runtime._slot.lock:  # pyright: ignore[reportPrivateUsage]
        runtime._slot.availability = None  # pyright: ignore[reportPrivateUsage]


async def _quiet_probe(runtime: BridgeRuntime) -> ServiceClient | None:
    """Handshake with a service that is already listening; never spawn or supersede one."""

    workspace_locator = _workspace_locator_for_runtime(runtime)
    if workspace_locator is None:
        return None
    try:
        client = await connect_service(
            ControlClientKind.MCP_BRIDGE, workspace_locator=workspace_locator
        )
    except Exception:
        return None
    try:
        await client.connect()
    except Exception:
        await _close_client(client)
        return None
    return client


async def _inherit_terminal_availability(
    runtime: BridgeRuntime,
    request_id: str | None,
    *,
    concurrent_waiter: bool = False,
) -> types.CallToolResult | None:
    """Answer a new request identity from the latched availability result, or clear the latch.

    The original request identity always passes through: replaying it after the named repair is
    the sanctioned continuation. A changed service holder stamp clears the latch. For a retryable
    class one quiet handshake (no spawn, no supersede, no diagnostic) is attempted first so a
    service that recovered on its own is not reported as absent.
    """

    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    async with slot.lock:
        latch = slot.availability
        if latch is None:
            return None
        if not concurrent_waiter:
            if request_id is not None and request_id == latch.request_id:
                return None
            if _holder_snapshot() != latch.holder:
                slot.availability = None
                return None
            if latch.retryable:
                probe = await _quiet_probe(runtime)
                if probe is not None:
                    stale = slot.client
                    slot.client = probe
                    slot.availability = None
                    if stale is not None and stale is not probe:
                        await _close_client(stale)
                    return None
        latch.inherited += 1
        details = dict(latch.safe_details)
        details["availability_inherited"] = True
        if latch.request_id is not None:
            details["availability_request_id"] = latch.request_id
        return structured_error_result(
            latch.code,
            latch.message + _INHERITED_AVAILABILITY_SUFFIX,
            retryable=latch.retryable,
            request_id=request_id,
            correlation_id=latch.correlation_id,
            safe_details=details,
            host_profile=runtime.host_profile,
        )


async def _finish_availability_attempt(runtime: BridgeRuntime) -> None:
    """Release the first-probe gate so waiters can inherit the completed latch or proceed."""

    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    async with slot.lock:
        slot.attempting = False
        finished = slot.attempt_finished
        slot.attempt_finished = None
    if finished is not None:
        finished.set()


async def _prepare_availability(
    runtime: BridgeRuntime, request_id: str | None
) -> types.CallToolResult | None:
    """Wait for an in-flight on-demand probe, then inherit a completed latch if one exists."""

    return await _inherit_after_inflight_availability(runtime, request_id)


async def _inherit_after_inflight_availability(
    runtime: BridgeRuntime, request_id: str | None
) -> types.CallToolResult | None:
    """Wait for an in-flight first probe, then inherit a completed latch without claiming one.

    Envelope-first publish recovery is an oracle read: it must not start a second on-demand
    attempt while another tool call already owns the first probe.
    """

    slot = runtime._slot  # pyright: ignore[reportPrivateUsage]
    waited = False
    while True:
        waiter: asyncio.Event | None = None
        async with slot.lock:
            if not slot.attempting:
                break
            waiter = slot.attempt_finished
        if waiter is None:
            break
        waited = True
        await waiter.wait()
    return await _inherit_terminal_availability(runtime, request_id, concurrent_waiter=waited)


def _rpc_deadline_ms(tool: str, environ: Mapping[str, str] | None = None) -> int:
    """Return the bridge-to-service deadline for one workflow tool, honouring env overrides."""

    source = os.environ if environ is None else environ
    names = [f"{_RPC_DEADLINE_ENV}_{tool.upper()}"]
    if tool != "check":
        names.append(_RPC_DEADLINE_ENV)
    for name in names:
        raw = source.get(name)
        if raw is None:
            continue
        text = raw.strip()
        if not text.isascii() or not text.isdigit():
            continue
        return max(_MIN_RPC_DEADLINE_MS, min(_MAX_RPC_DEADLINE_MS, int(text)))
    return _DEFAULT_RPC_DEADLINES_MS[tool]


class _TimeoutPollView(Enum):
    OPERATION = "operation"


class _TimeoutOperationState(Enum):
    ABSENT = "absent"
    PENDING = "pending"
    COMPLETE = "complete"
    QUARANTINED = "quarantined"
    UNKNOWN = "unknown"


_TIMEOUT_PROBED_WRITES: Final = frozenset({"publish_work", "respond", "receipt"})


async def _timeout_operation_state(
    arguments: Mapping[str, object],
    runtime: BridgeRuntime,
    request_id: str | None,
) -> tuple[_TimeoutOperationState, str, str] | None:
    """Probe ``status view=operation`` once for a write whose response deadline expired.

    Returns ``(state, session_id, writer_id)`` for a complete envelope, else ``None``. Any probe
    failure is ``UNKNOWN``: the write outcome stays unknown and nothing is inferred from silence.
    """

    envelope = _publish_envelope_fields(arguments)
    if envelope is None:
        return None
    op_request_id, session_id, writer_id, actor, client = envelope
    try:
        status_request = StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": new_id(IdKind.REQUEST),
                "session_id": session_id,
                "writer_id": writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": op_request_id},
                "actor": dict(actor),
                "client": dict(client),
            }
        )
        status_result = await _invoke_with_reconnect(
            runtime,
            status_request,
            lambda service, request: service.status(
                request, deadline_ms=_TIMEOUT_PROBE_DEADLINE_MS
            ),
            request_id,
        )
        wire = public_model_to_wire(status_result)
        page = wire.get("page") if wire.get("ok") is True else None
        state = cast(dict[str, object], page).get("state") if type(page) is dict else None
        return (
            _TimeoutOperationState(state)
            if type(state) is str and state in {item.value for item in _TimeoutOperationState}
            else _TimeoutOperationState.UNKNOWN,
            session_id,
            writer_id,
        )
    except Exception as exc:  # noqa: BLE001 - a failed probe only leaves the outcome unknown
        if not isinstance(exc, (ControlError, PublicOperationError, ValidationError)):
            record_unexpected_exception_without_raising(
                exc,
                component="mcp.bridge",
                operation="write_timeout_probe_internal_error",
                request_id=request_id,
            )
        return (_TimeoutOperationState.UNKNOWN, session_id, writer_id)


async def _invoke_with_reconnect[RequestT: BaseModel, ResultT: BaseModel](
    runtime: BridgeRuntime,
    request: RequestT,
    invoke: Callable[[ServiceClient, RequestT], Awaitable[ResultT]],
    request_id: str | None,
    *,
    retain_availability_failure_for_latch: bool = False,
) -> ResultT:
    client = await ensure_service_client(
        runtime,
        request_id=request_id,
        retain_availability_failure_for_latch=retain_availability_failure_for_latch,
    )
    try:
        return await invoke(client, request)
    except ControlError as error:
        if error.reason in _DISCARD_CLIENT_REASONS:
            await _discard_client(runtime, client)
        if not error.retryable or error.reason not in _RECONNECT_REASONS:
            raise
        replacement = await ensure_service_client(
            runtime,
            request_id=request_id,
            retain_availability_failure_for_latch=retain_availability_failure_for_latch,
        )
        return await invoke(replacement, request)


async def _dispatch[RequestT: BaseModel, ResultT: BaseModel](
    arguments: Mapping[str, object],
    request_type: type[RequestT],
    result_type: type[ResultT],
    invoke: Callable[[ServiceClient, RequestT], Awaitable[ResultT]],
    runtime: BridgeRuntime,
    operation: str,
) -> types.CallToolResult:
    request_id = safe_request_id_from(arguments)
    # ADR-047: a ``check`` whose mode records nothing (``inspect``) fails as a read, like the
    # daemon classifies it. The value is only compared with a closed set, never echoed.
    check_mode = arguments.get("mode") if operation == "check" else None
    try:
        request = request_type.model_validate(arguments)
    except ValidationError as exc:
        locations = safe_validation_locations(exc)
        return structured_error_result(
            PublicErrorCode.INVALID_REQUEST,
            invalid_request_message(operation, locations),
            request_id=request_id,
            safe_details=locations if locations else None,
            operation=operation,
            host_profile=runtime.host_profile,
        )
    except Exception as exc:
        # Only non-ValidationError failures reach here, so the validator itself crashed. That is an
        # unexpected bridge error, not caller fault.
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation=f"{operation}_request_internal_error",
            request_id=request_id,
        )
        return _internal_stage_error(
            "bridge_request_validation_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
            operation=operation,
            check_mode=check_mode,
        )
    inherited = await _prepare_availability(runtime, request_id)
    if inherited is not None:
        return inherited
    # Invoke first. Once this returns, a write may already be durable; response shaping must not
    # collapse that into a non-retryable INTERNAL_ERROR that steers agents away from same-id resume.
    try:
        result = await _invoke_with_reconnect(
            runtime,
            request,
            invoke,
            request_id,
            retain_availability_failure_for_latch=True,
        )
    except _CursorWorkspaceBindingError:
        return _cursor_workspace_error(runtime, request_id, operation)
    except PublicOperationError as exc:
        # Defense in depth: the ordinary client normally returns ok:false bodies, but if a
        # PublicOperationError escapes the service boundary, keep the exact public code.
        try:
            bound = (
                exc
                if exc.correlation_id is not None
                else exc.bind_correlation_id(
                    record_public_error_without_raising(
                        component="mcp.bridge",
                        operation=_public_error_operation(operation),
                        reason=exc.code.value.lower(),
                        request_id=request_id,
                    )
                )
            )
            return _result_from_wire(
                tool_error_envelope(bound, request_id=request_id),
                host_profile=runtime.host_profile,
            )
        except Exception as mapping_exc:
            correlation_id = record_unexpected_exception_without_raising(
                mapping_exc,
                component="mcp.bridge",
                operation=f"{operation}_public_error_internal_error",
                request_id=request_id,
            )
            return _internal_stage_error(
                "bridge_error_mapping_failed",
                request_id=request_id,
                correlation_id=correlation_id,
                host_profile=runtime.host_profile,
                operation=operation,
                check_mode=check_mode,
            )
    except ControlError as exc:
        if exc.reason in _AVAILABILITY_LATCH_REASONS:
            inherited_failure = await _inherit_terminal_availability(runtime, request_id)
            if inherited_failure is not None:
                return inherited_failure
            failure = _control_error_result(
                exc,
                request_id,
                operation,
                host_profile=runtime.host_profile,
            )
            return await _latch_availability(runtime, request_id, exc, failure)
        vault_initialization_details: dict[str, object] | None = None
        if exc.reason == "vault_locked" and not exc.retryable:
            vault_initialization_details = await _vault_initialization_continuation(
                runtime, request_id
            )
        timeout_handle: dict[str, object] | None = None
        recovered: ResultT | None = None
        if exc.reason == "request_timeout" and operation in _TIMEOUT_PROBED_WRITES:
            probed = await _timeout_operation_state(arguments, runtime, request_id)
            if probed is not None:
                state, session_id, writer_id = probed
                if state is _TimeoutOperationState.COMPLETE:
                    # The write committed after the response deadline. Its same-request replay
                    # is idempotent and returns the stored outcome without appending again.
                    try:
                        recovered = await _invoke_with_reconnect(
                            runtime, request, invoke, request_id
                        )
                    except Exception:  # noqa: BLE001 - fall back to the typed pollable handle
                        recovered = None
                timeout_handle = {
                    "session_id": session_id,
                    "writer_id": writer_id,
                    "view": _TimeoutPollView.OPERATION,
                    "state": state,
                }
        if recovered is None:
            return _control_error_result(
                exc,
                request_id,
                operation,
                host_profile=runtime.host_profile,
                vault_initialization_details=vault_initialization_details,
                timeout_handle=timeout_handle,
                check_mode=check_mode,
            )
        result = recovered
    except Exception as exc:
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation=f"{operation}_internal_error",
            request_id=request_id,
        )
        return _internal_stage_error(
            "bridge_invoke_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
            operation=operation,
            check_mode=check_mode,
        )

    await _clear_availability(runtime)
    stage = "wire"
    try:
        wire = public_model_to_wire(result)
        stage = "validate"
        validated = result_type.model_validate(wire)
        stage = "wire"
        return result_from_public_model(
            validated,
            host_profile=runtime.host_profile,
            request_id=request_id,
            operation=operation,
        )
    except Exception as exc:
        # The operation committed. Only a structural failure reaches here -- the result cannot be
        # serialized or does not match its schema. A failure of the *text* projection never does:
        # `_result_text` omits what it cannot render and the structured result is still returned
        # (tb4n3 RC-2). The stage is named in the message because replay would rebuild the same
        # result and fail the same way.
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation=f"{operation}_response_projection_failed",
            request_id=request_id,
        )
        # A failure the service reported (ok:false) was not a write that succeeded: it has the
        # error-translation remedy, not the recorded-write one.
        reported_failure = getattr(getattr(result, "root", result), "ok", True) is False
        return _internal_stage_error(
            "bridge_error_mapping_failed"
            if reported_failure
            else "bridge_result_validate_failed"
            if stage == "validate"
            else "bridge_result_wire_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
            operation=operation,
            check_mode=check_mode,
        )


async def dispatch_start(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    return await _dispatch(
        arguments,
        StartRequest,
        StartResult,
        lambda client, request: client.start(request, deadline_ms=_rpc_deadline_ms("start")),
        runtime,
        "start",
    )


def _publish_envelope_fields(
    arguments: Mapping[str, object],
) -> tuple[str, str, str, Mapping[str, object], Mapping[str, object]] | None:
    """Return ``(request_id, session_id, writer_id, actor, client)`` when the envelope is complete.

    Recovery is keyed only on these fields. Event drafts are intentionally ignored so a body that
    fails schema validation can still reach the operation-identity recovery path.
    """

    request_id = safe_request_id_from(arguments)
    session_id = arguments.get("session_id")
    writer_id = arguments.get("writer_id")
    actor = arguments.get("actor")
    client = arguments.get("client")
    protocol_version = arguments.get("protocol_version")
    schema_version = arguments.get("schema_version")
    if (
        type(request_id) is not str
        or type(session_id) is not str
        or type(writer_id) is not str
        or not isinstance(actor, Mapping)
        or not isinstance(client, Mapping)
        or protocol_version != "0.1"
        or schema_version != "1.0.0"
    ):
        return None
    return (
        request_id,
        session_id,
        writer_id,
        cast(Mapping[str, object], actor),
        cast(Mapping[str, object], client),
    )


class _PublishRecoveryKind(Enum):
    """Closed tri-state for envelope-first publish recovery lookup."""

    FOUND = "found"
    ABSENT = "absent"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class _PublishRecoveryOutcome:
    """Result of looking up a request_id after body validation failed.

    Only FOUND replaces the authoring diagnostic. ABSENT yields the original field-pointed
    validation result. UNAVAILABLE annotates it with a durability caveat rather than replacing it:
    an uncertain durability claim must never displace the certain authoring one (issue #239).
    """

    kind: _PublishRecoveryKind
    result: types.CallToolResult | None = None


def _publish_is_declared_dry_run(arguments: Mapping[str, object]) -> bool:
    """True only for the exact boolean ``dry_run: true``.

    A dry run appends nothing, so no prior-operation lookup can change the answer to a body that
    already failed local validation, and the oracle's deadline would be pure tax on the authoring
    loop (issues #239, #240). Anything other than the literal boolean is itself a validation
    failure and must not buy a durability shortcut.
    """

    return arguments.get("dry_run") is True


def _publish_validation_recovery_unavailable_result(
    request_id: str | None,
    locations: Sequence[Mapping[str, str]] = (),
    *,
    host_profile: McpHostProfile = "generic",
) -> types.CallToolResult:
    """Field-pointed INVALID_REQUEST primary, unreachable-oracle caveat alongside."""

    message = (
        "The tool arguments are invalid."
        + _PUBLISH_RECOVERY_UNCHECKED_CAVEAT
        + _authoring_hint_for("publish_work", locations)
    )
    if not locations:
        # Nothing locatable: keep the availability signal machine-readable and say no more.
        return structured_error_result(
            PublicErrorCode.INVALID_REQUEST,
            message,
            request_id=request_id,
            safe_details={"reason_code": _PUBLISH_RECOVERY_UNAVAILABLE_REASON},
            operation="publish_work_recovery_unavailable",
            host_profile=host_profile,
        )
    return structured_error_result(
        PublicErrorCode.INVALID_REQUEST,
        message,
        request_id=request_id,
        safe_details=tuple(locations),
        details_reason_code=_PUBLISH_RECOVERY_UNAVAILABLE_REASON,
        operation="publish_work_recovery_unavailable",
        host_profile=host_profile,
    )


async def _publish_recovery_from_envelope(
    arguments: Mapping[str, object],
    runtime: BridgeRuntime,
    request_id: str | None,
) -> _PublishRecoveryOutcome:
    """Look up the envelope request_id without body validation.

    Returns a closed tri-state: FOUND (pending/complete/quarantined), ABSENT (lookup succeeded
    and no operation exists), or UNAVAILABLE (connection, timeout, projection, or unexpected
    recovery failure). Incomplete envelopes that cannot form a recovery read are ABSENT so the
    original field-pointed validation result surfaces.
    """

    envelope = _publish_envelope_fields(arguments)
    if envelope is None:
        return _PublishRecoveryOutcome(_PublishRecoveryKind.ABSENT)
    op_request_id, session_id, writer_id, actor, client = envelope
    recovery_request_id = request_id if request_id is not None else op_request_id
    status_request_id = new_id(IdKind.REQUEST)
    try:
        status_request = StatusRequest.model_validate(
            {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "request_id": status_request_id,
                "session_id": session_id,
                "writer_id": writer_id,
                "view": "operation",
                "limit": "1",
                "filter": {"operation_request_id": op_request_id},
                "actor": dict(actor),
                "client": dict(client),
            }
        )
    except ValidationError:
        # Envelope fields are not a valid status request; fall through to body validation error.
        return _PublishRecoveryOutcome(_PublishRecoveryKind.ABSENT)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="publish_work_recovery_request_internal_error",
            request_id=recovery_request_id,
        )
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)

    try:
        status_result = await _invoke_with_reconnect(
            runtime,
            status_request,
            lambda service, request: service.status(request, deadline_ms=_WORKFLOW_RPC_DEADLINE_MS),
            recovery_request_id,
        )
    except _CursorWorkspaceBindingError:
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
    except PublicOperationError as exc:
        # A nested public failure (session conflict, projection, etc.) does not prove the
        # operation is absent or found. Do not promote it over the outer authoring diagnostic,
        # and do not forward nested "no durable state changed" remedies for a write path.
        del exc
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
    except ControlError as exc:
        # Including read_projection_failed: a failed recovery oracle must not become the outer
        # publish result with a read-only durability claim and a new-request_id remedy.
        del exc
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="publish_work_recovery_status_internal_error",
            request_id=recovery_request_id,
        )
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)

    try:
        wire = public_model_to_wire(status_result)
        if wire.get("ok") is not True:
            return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
        page = wire.get("page")
        if type(page) is not dict:
            return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
        page_map = cast(dict[str, object], page)
        state = page_map.get("state")
        if state == "absent":
            return _PublishRecoveryOutcome(_PublishRecoveryKind.ABSENT)
        if state == "pending":
            return _PublishRecoveryOutcome(
                _PublishRecoveryKind.FOUND,
                structured_error_result(
                    PublicErrorCode.OPERATION_PENDING,
                    "The operation is still pending.",
                    retryable=True,
                    request_id=recovery_request_id,
                    operation="publish_work_recovery",
                    host_profile=runtime.host_profile,
                ),
            )
        if state == "quarantined":
            return _PublishRecoveryOutcome(
                _PublishRecoveryKind.FOUND,
                structured_error_result(
                    PublicErrorCode.STORAGE_CORRUPT,
                    "The stored operation is quarantined.",
                    request_id=recovery_request_id,
                    operation="publish_work_recovery",
                    host_profile=runtime.host_profile,
                ),
            )
        if state != "complete":
            return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
        result_frontier = page_map.get("result_frontier")
        accepted = page_map.get("accepted_events")
        count = len(cast(Sequence[object], accepted)) if isinstance(accepted, Sequence) else 0
        details: dict[str, object] = {"reason_code": "request_identity_conflict", "count": count}
        if type(result_frontier) is dict:
            frontier_map = cast(dict[str, object], result_frontier)
            sequence = frontier_map.get("sequence")
            head_digest = frontier_map.get("head_digest")
            if type(sequence) is str and sequence.isdigit():
                details["sequence"] = int(sequence)
            if type(head_digest) is str:
                details["head_digest"] = head_digest
        return _PublishRecoveryOutcome(
            _PublishRecoveryKind.FOUND,
            structured_error_result(
                PublicErrorCode.REQUEST_IDENTITY_CONFLICT,
                (
                    "The request ID was already used with a different request body. "
                    "Read status view=operation for the stored result of that request_id."
                ),
                request_id=recovery_request_id,
                safe_details=details,
                operation="publish_work_recovery",
                host_profile=runtime.host_profile,
            ),
        )
    except Exception as exc:
        record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="publish_work_recovery_response_internal_error",
            request_id=recovery_request_id,
        )
        return _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)


async def dispatch_publish_work(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    request_id = safe_request_id_from(arguments)
    try:
        PublishWorkRequest.model_validate(arguments)
    except ValidationError as exc:
        # Envelope-first recovery still runs for real submissions so a request_id that already
        # names a commit is never reported as a bare INVALID_REQUEST (PR #47). A declared dry run
        # cannot append, so the lookup can only cost the oracle deadline and confuse the answer
        # (issues #239, #240).
        locations = safe_validation_locations(exc)
        if not _publish_is_declared_dry_run(arguments):
            # The recovery oracle is the service itself. Under a latched availability result a
            # new request identity must not reach it (no startup, supersede, or diagnostic); the
            # lookup is simply unavailable and the certain authoring error leads (#239, #469).
            if await _inherit_after_inflight_availability(runtime, request_id) is not None:
                recovery = _PublishRecoveryOutcome(_PublishRecoveryKind.UNAVAILABLE)
            else:
                recovery = await _publish_recovery_from_envelope(arguments, runtime, request_id)
            if recovery.kind is _PublishRecoveryKind.FOUND and recovery.result is not None:
                return recovery.result
            if recovery.kind is _PublishRecoveryKind.UNAVAILABLE:
                return _publish_validation_recovery_unavailable_result(
                    request_id,
                    locations,
                    host_profile=runtime.host_profile,
                )
        return structured_error_result(
            PublicErrorCode.INVALID_REQUEST,
            invalid_request_message("publish_work", locations),
            request_id=request_id,
            safe_details=locations if locations else None,
            operation="publish_work",
            host_profile=runtime.host_profile,
        )
    except Exception as exc:
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="publish_work_request_internal_error",
            request_id=request_id,
        )
        return _internal_stage_error(
            "bridge_request_validation_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
            operation="publish_work",
        )
    return await _dispatch(
        arguments,
        PublishWorkRequest,
        PublishWorkResult,
        lambda client, request: client.publish_work(
            request, deadline_ms=_rpc_deadline_ms("publish_work")
        ),
        runtime,
        "publish_work",
    )


async def dispatch_check(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    return await _dispatch(
        arguments,
        CheckRequest,
        CheckResult,
        lambda client, request: client.check(
            request,
            # ADR-047: an inspection is a read routed like ``status``, so it takes the status
            # deadline, not the budget of a check that may run an AI-powered review.
            deadline_ms=_rpc_deadline_ms(
                "status" if request.mode in READ_ONLY_CHECK_MODES else "check"
            ),
            route_profile=runtime.route_profile,
            host_profile=runtime.host_profile,
        ),
        runtime,
        "check",
    )


async def dispatch_respond(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    return await _dispatch(
        arguments,
        RespondRequest,
        RespondResult,
        lambda client, request: client.respond(request, deadline_ms=_rpc_deadline_ms("respond")),
        runtime,
        "respond",
    )


async def dispatch_status(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    return await _dispatch(
        arguments,
        StatusRequest,
        StatusResult,
        lambda client, request: client.status(
            request,
            deadline_ms=_rpc_deadline_ms("status"),
            route_profile=runtime.route_profile,
        ),
        runtime,
        "status",
    )


async def dispatch_closure_prepare(
    arguments: Mapping[str, object],
    runtime: BridgeRuntime = BRIDGE_RUNTIME,
    *,
    transport_request_id: types.RequestId | None = None,
) -> types.CallToolResult:
    """Prepare one explicit closure request from a pinned, paginated status inventory."""

    request_id = safe_request_id_from(arguments)
    try:
        request = ClosurePrepareRequest.model_validate(arguments)
    except ValidationError as exc:
        locations = safe_validation_locations(exc)
        return structured_error_result(
            PublicErrorCode.INVALID_REQUEST,
            invalid_request_message("closure_prepare", locations),
            request_id=request_id,
            safe_details=locations if locations else None,
            operation="closure_prepare",
            host_profile=runtime.host_profile,
        )
    except Exception as exc:
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="closure_prepare_request_internal_error",
            request_id=request_id,
        )
        return _internal_stage_error(
            "bridge_request_validation_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
            operation="closure_prepare",
        )

    inherited = await _prepare_availability(runtime, request_id)
    if inherited is not None:
        return inherited

    async def status(status_request: StatusRequest) -> StatusResult:
        return await _invoke_with_reconnect(
            runtime,
            status_request,
            lambda client, current: client.status(
                current,
                deadline_ms=_rpc_deadline_ms("status"),
                route_profile=runtime.route_profile,
            ),
            request_id,
            retain_availability_failure_for_latch=True,
        )

    try:
        prepared = await prepare_closure(
            status,
            request.session_id,
            request.writer_id,
            request.selection,
            client_kind="cooperative_agent",
            integration="cooperative_mcp",
            scope_to_selection=True,
        )
        if len(canonical_encode(cast(JsonValue, prepared))) > _MAX_CLOSURE_RESULT_BYTES:
            raise ValueError("closure_result_too_large")
        result = ClosurePrepareResult.model_validate({"ok": True, **prepared})
    except _CursorWorkspaceBindingError:
        return _cursor_workspace_error(runtime, request_id, "closure_prepare")
    except PublicOperationError as exc:
        try:
            bound = (
                exc
                if exc.correlation_id is not None
                else exc.bind_correlation_id(
                    record_public_error_without_raising(
                        component="mcp.bridge",
                        operation=_public_error_operation("closure_prepare"),
                        reason=exc.code.value.lower(),
                        request_id=request_id,
                    )
                )
            )
            return _result_from_wire(
                tool_error_envelope(bound, request_id=request_id),
                host_profile=runtime.host_profile,
            )
        except Exception as mapping_exc:
            correlation_id = record_unexpected_exception_without_raising(
                mapping_exc,
                component="mcp.bridge",
                operation="closure_prepare_public_error_internal_error",
                request_id=request_id,
            )
            return _internal_stage_error(
                "bridge_error_mapping_failed",
                request_id=request_id,
                correlation_id=correlation_id,
                host_profile=runtime.host_profile,
                operation="closure_prepare",
            )
    except ControlError as exc:
        if exc.reason in _AVAILABILITY_LATCH_REASONS:
            inherited_failure = await _inherit_terminal_availability(runtime, request_id)
            if inherited_failure is not None:
                return inherited_failure
            failure = _control_error_result(
                exc,
                request_id,
                "closure_prepare",
                host_profile=runtime.host_profile,
            )
            return await _latch_availability(runtime, request_id, exc, failure)
        return _control_error_result(
            exc,
            request_id,
            "closure_prepare",
            host_profile=runtime.host_profile,
        )
    except ValueError as exc:
        reason = str(exc)
        remediation = PREPARATION_REMEDIATIONS.get(reason)
        if remediation is None:
            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="mcp.bridge",
                operation="closure_prepare_internal_error",
                request_id=request_id,
            )
            return _internal_stage_error(
                "closure_prepare_failed",
                request_id=request_id,
                correlation_id=correlation_id,
                host_profile=runtime.host_profile,
            )
        error_code = (
            PublicErrorCode.LIMIT_EXCEEDED
            if reason == "closure_result_too_large"
            else PublicErrorCode.INVALID_REQUEST
        )
        return structured_error_result(
            error_code,
            f"{reason}: {remediation}",
            request_id=request_id,
            safe_details={"reason_code": _CLOSURE_PUBLIC_REASON_CODES.get(reason, reason)},
            operation="closure_prepare",
            host_profile=runtime.host_profile,
        )
    except Exception as exc:
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="closure_prepare_internal_error",
            request_id=request_id,
        )
        return _internal_stage_error(
            "closure_prepare_failed",
            request_id=request_id,
            correlation_id=correlation_id,
            host_profile=runtime.host_profile,
        )

    await _clear_availability(runtime)
    try:
        projected = result_from_public_model(
            result,
            host_profile=runtime.host_profile,
            request_id=request_id,
            operation="closure_prepare",
        )
        if (
            _serialized_mcp_result_bytes(
                projected,
                transport_request_id=transport_request_id,
            )
            > MAX_JSON_FRAME_BYTES
        ):
            return structured_error_result(
                PublicErrorCode.LIMIT_EXCEEDED,
                f"closure_result_too_large: {PREPARATION_REMEDIATIONS['closure_result_too_large']}",
                request_id=request_id,
                safe_details={"reason_code": "closure_result_too_large"},
                operation="closure_prepare",
                host_profile=runtime.host_profile,
            )
        return projected
    except Exception as exc:
        # Closure preparation is a read: nothing was recorded, so nothing is committed to replay.
        correlation_id = record_unexpected_exception_without_raising(
            exc,
            component="mcp.bridge",
            operation="closure_prepare_response_projection_failed",
            request_id=request_id,
        )
        return structured_error_result(
            PublicErrorCode.INTERNAL_ERROR,
            _READ_PROJECTION_FAILED_MESSAGE,
            retryable=True,
            request_id=request_id,
            correlation_id=correlation_id,
            safe_details=dict(_READ_PROJECTION_FAILED_DETAILS),
            host_profile=runtime.host_profile,
        )


async def dispatch_receipt(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    return await _dispatch(
        arguments,
        ReceiptRequest,
        ReceiptResult,
        lambda client, request: client.receipt(request, deadline_ms=_rpc_deadline_ms("receipt")),
        runtime,
        "receipt",
    )


def _guidance_page_size_message(raw: object) -> str:
    """Say which way a rejected guidance ``page_size`` is wrong, never echoing the value.

    tb4n1: five reads sent ``"32768"``, ``"20000"``, or ``"16000"`` (three in a row for one page
    sequence); the range sentence alone did not say the value was too large. The class of the
    mistake is computed from the value; only the frozen bounds are printed.
    """

    bounds = f"between 4 and {MAX_GUIDANCE_PAGE_SIZE} bytes inclusive"
    if type(raw) is int:
        problem = 'page_size is a decimal string such as "4096", not a JSON number'
    elif type(raw) is str and raw.isascii() and raw.isdigit() and len(raw) <= 19:
        value = int(raw)
        if value > MAX_GUIDANCE_PAGE_SIZE:
            problem = f"page_size exceeds the maximum of {MAX_GUIDANCE_PAGE_SIZE} bytes"
        elif value < 4:
            problem = "page_size is below the minimum of 4 bytes"
        else:
            problem = "page_size must be canonical, with no leading zeros"
    else:
        problem = 'page_size must be a canonical decimal string such as "4096"'
    return (
        f"Guidance {problem}; it must be a canonical UTF-8 byte count {bounds}. Retry with "
        'page="0" and page_size="4096" or another value in that range, then advance page with '
        "the same page_size, revision, and digest; page numbers depend on page_size, so restart "
        "at page 0 whenever page_size changes."
    )


async def dispatch_read_guidance(
    arguments: Mapping[str, object], runtime: BridgeRuntime = BRIDGE_RUNTIME
) -> types.CallToolResult:
    """Return one registered guidance document or one digest-bound bounded page.

    The legacy ``{"uri": ...}`` body remains a full-document on-demand read when the document fits
    the result cap. An oversized registered document automatically starts at page zero; supplying
    any page field also selects the bounded route, whose structured metadata lets a host
    reconstruct and verify the document even when its model-visible channel clips ordinary tool
    output.
    """

    raw_uri = arguments.get("uri")
    if type(raw_uri) is str and raw_uri not in ALL_GUIDANCE_URIS:
        # tb4n4 (#1049): a guessed anchor that names exactly one catalogued topic of a registered
        # document (its slug, an explicit anchor beside its heading, or words only it contains)
        # reads that topic; the result's ``uri`` is the catalogued one. Anything else is refused
        # below with the registered alternatives.
        resolved = resolve_guidance_topic_uri(raw_uri)
        if resolved is not None:
            arguments = {**arguments, "uri": resolved}
    try:
        request = ReadGuidanceRequest.model_validate(arguments)
    except ValidationError as exc:
        locations = safe_validation_locations(exc)
        if any(
            tuple(error.get("loc", ())) == ("uri",)
            for error in exc.errors(include_url=False, include_context=False, include_input=False)
        ):
            return _unknown_guidance_uri_result(arguments.get("uri"), runtime=runtime)
        page_size_reason = next(
            (
                location.get("reason")
                for location in locations
                if location.get("field") == "/page_size"
            ),
            None,
        )
        if page_size_reason == "guidance_page_size_invalid":
            message = _guidance_page_size_message(arguments.get("page_size"))
        elif page_size_reason == "guidance_page_invalid":
            message = "Guidance page must be a canonical page number; restart at page 0."
        elif page_size_reason == "guidance_revision_digest_mismatch":
            message = "Guidance revision and digest must match; restart at page 0."
        else:
            message = "The read_guidance request is invalid."
        return structured_error_result(
            PublicErrorCode.INVALID_REQUEST,
            message,
            safe_details=locations if locations else {"argument_count": len(arguments)},
            operation="read_guidance",
            host_profile=runtime.host_profile,
        )
    resource = _GUIDANCE_BY_URI.get(request.uri)
    if resource is None:
        try:
            resource = guidance_resource_for_uri(request.uri)
        except GuidanceResourceError:
            resource = None
    if resource is None:
        return _unknown_guidance_uri_result(request.uri, runtime=runtime)
    paged = any(
        value is not None
        for value in (request.page, request.page_size, request.revision, request.digest)
    )
    if not paged and resource.size > _MAX_LEGACY_GUIDANCE_DOCUMENT_BYTES:
        paged = True
    if paged:
        page_number = int(request.page or "0")
        page_size = int(request.page_size or str(DEFAULT_GUIDANCE_PAGE_SIZE))
        try:
            page = read_guidance_page(
                resource,
                page=page_number,
                page_size=page_size,
                expected_revision=request.revision,
                expected_digest=request.digest,
            )
        except GuidanceResourceError as exc:
            return _guidance_page_error(exc, runtime=runtime)
        text = page.text
        result_body: dict[str, object] = {
            "ok": True,
            "uri": resource.uri,
            "media_type": resource.media_type,
            "byte_count": page.byte_count,
            "text": text,
            "document_id": resource.uri,
            "revision": page.revision,
            "digest": page.digest,
            "total_byte_count": page.total_byte_count,
            "page": str(page.page),
            "page_size": str(page.page_size),
            "page_offset": page.offset,
            "page_byte_count": page.byte_count,
            "page_count": str(page.page_count),
            "complete": page.complete,
        }
        if page.continuation is not None:
            result_body["continuation"] = page.continuation
        result = ReadGuidanceResult.model_validate(result_body)
        wire = public_model_to_wire(result)
        content_text = _guidance_page_content_text(
            page, host_profile=runtime.host_profile, wire=wire
        )
    else:
        text = resource.text
        result = ReadGuidanceResult.model_validate(
            {
                "ok": True,
                "uri": resource.uri,
                "media_type": resource.media_type,
                "byte_count": len(text.encode("utf-8")),
                "text": text,
            }
        )
        wire = public_model_to_wire(result)
        content_text = _guidance_text(wire, text, host_profile=runtime.host_profile)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=content_text)],
        structuredContent=cast(dict[str, object], wire),
        isError=False,
    )


def _guidance_topic_anchors(document_uri: str) -> tuple[str, ...]:
    """Return the closed catalog's topic anchors for one registered guidance document."""

    prefix = document_uri + "#"
    return tuple(uri[len(prefix) :] for uri in GUIDANCE_TOPIC_URIS if uri.startswith(prefix))


def _unknown_guidance_uri_result(
    uri: object,
    *,
    runtime: BridgeRuntime,
) -> types.CallToolResult:
    """Reject an unregistered guidance URI with the exact registered alternatives.

    Benchmark transcripts showed agents deriving topic anchors from heading text or tool names
    (``#publish-work``, ``#publish_work-plan-revision``) and receiving a bare INVALID_REQUEST with
    nothing to retry against. The retry options named here are closed-catalog constants: the caller's
    URI is used only to select which registered document's catalog to list and is never echoed.
    """

    document = uri.partition("#")[0] if type(uri) is str else None
    if document in GUIDANCE_DOCUMENT_URIS:
        anchors = _guidance_topic_anchors(document)
        message = (
            f"read_guidance has no topic with that anchor in {document}, and it names no single "
            "topic (as a heading slug, an explicit anchor, or words only one anchor holds). Do "
            "not derive one from a tool or event name. Retry with "
            f"uri {document} to read the whole document, or {document}#<anchor> with one of these "
            f"anchors: {', '.join(anchors)}."
        )
    else:
        message = (
            "read_guidance accepts only a registered guidance URI. Retry with one of these "
            f"documents: {', '.join(GUIDANCE_DOCUMENT_URIS)}; or one focused topic: "
            f"{', '.join(FOCUSED_GUIDANCE_URIS)}."
        )
    result = structured_error_result(
        PublicErrorCode.INVALID_REQUEST,
        message,
        safe_details={"field": "/uri"},
        operation="read_guidance",
        host_profile=runtime.host_profile,
    )
    if runtime.host_profile != "cursor" and len(result.content) == 1:
        # The text channel otherwise omits the message. This one is built only from closed catalog
        # constants, so the model-visible retry options are safe to show. Cursor's text is already
        # the full JSON envelope and must not be duplicated.
        first = result.content[0]
        if isinstance(first, types.TextContent):
            result.content = [
                types.TextContent(type="text", text=f"{first.text}\n{message}"),
            ]
    return result


def read_guidance_page(
    resource: GuidanceResource,
    *,
    page: int,
    page_size: int,
    expected_revision: str | None,
    expected_digest: str | None,
) -> GuidanceResourcePage:
    """Read a page for an already selected registry resource without interpreting caller paths."""

    # Keep URI selection and byte loading in the resource registry. This wrapper makes the bridge
    # call site explicit and gives tests a stable seam without exposing a second path resolver.
    from yoetz.mcp.resources import read_resource_page

    return read_resource_page(
        resource.uri,
        page=page,
        page_size=page_size,
        expected_revision=expected_revision,
        expected_digest=expected_digest,
    )


def _guidance_page_error(
    error: GuidanceResourceError,
    *,
    runtime: BridgeRuntime,
) -> types.CallToolResult:
    """Map page failures to bounded field-local corrections without echoing caller values."""

    reason = str(error)
    if reason in {"guidance_revision_mismatch", "guidance_digest_mismatch"}:
        message = (
            "The guidance revision changed while the document was being reconstructed. "
            "Retry page 0 without the stale token, then carry the new revision and digest."
        )
        field = "/revision" if reason == "guidance_revision_mismatch" else "/digest"
    elif reason == "guidance_page_out_of_range":
        message = "The guidance page is outside the current document; restart at page 0."
        field = "/page"
    elif reason == "guidance_page_size_invalid":
        message = f"Guidance page_size must be between 4 and {MAX_GUIDANCE_PAGE_SIZE} bytes."
        field = "/page_size"
    elif reason == "guidance_page_size_too_small":
        message = "Guidance page_size must leave room for one complete UTF-8 character."
        field = "/page_size"
    elif reason == "guidance_page_count_invalid":
        message = "Guidance page_size is too small for this document; request a larger page_size."
        field = "/page_size"
    elif reason == "guidance_document_too_large":
        message = "The guidance document exceeds the bounded page route capacity."
        field = "/uri"
    else:
        message = "The guidance page could not be read. Restart at page 0."
        field = "/page"
    return structured_error_result(
        PublicErrorCode.INVALID_REQUEST,
        message,
        safe_details={"field": field},
        operation="read_guidance",
        host_profile=runtime.host_profile,
    )


def _guidance_page_content_text(
    page: GuidanceResourcePage,
    *,
    host_profile: McpHostProfile,
    wire: Mapping[str, object],
) -> str:
    """Render a page with explicit boundaries on hosts that consume the text channel."""

    if host_profile == "codex":
        return summary_for_read_guidance(wire)
    next_page = "none" if page.next_page is None else str(page.next_page)
    complete = "yes" if page.complete else "no"
    return (
        f"YOETZ_GUIDANCE_PAGE_BEGIN document={page.resource.uri} page={page.page} "
        f"page_count={page.page_count} offset={page.offset} bytes={page.byte_count} "
        f"total_bytes={page.total_byte_count} revision={page.revision} digest={page.digest}\n"
        f"{page.text}\n"
        f"YOETZ_GUIDANCE_PAGE_END complete={complete} next_page={next_page} "
        f"revision={page.revision} digest={page.digest}"
    )


def _guidance_text(
    wire: Mapping[str, object],
    text: str,
    *,
    host_profile: McpHostProfile,
) -> str:
    """Project one guidance result onto the text channel for the selected host (issue #918).

    The ``codex`` profile already relies on ``structuredContent`` for every other tool's full
    result (its text channel is the bounded summary), and in Codex code mode the whole result stays
    in the script sandbox, so a second full copy in ``content`` costs wire and bridge bytes only.
    That profile therefore gets a bounded pointer to ``structuredContent.text``; the structured
    result, and so the output schema, is unchanged. Generic, Claude and Cursor hosts keep the
    document in ``content``: they may rely on it for the model-visible text (Cursor does not
    reliably deliver ``structuredContent``). Revert this branch if a Codex dogfood run shows extra
    guidance re-reads (issue #918).
    """

    if host_profile == "codex":
        return summary_for_read_guidance(wire)
    return text


async def list_tools(runtime: BridgeRuntime = BRIDGE_RUNTIME) -> list[types.Tool]:
    """Return the exact reviewed tool inventory in stable order."""

    return [
        types.Tool(
            name=descriptor.name,
            title=descriptor.title,
            description=descriptor.description,
            inputSchema=cast(dict[str, object], _mutable_json(descriptor.input_schema)),
            outputSchema=cast(dict[str, object], _mutable_json(descriptor.output_schema)),
            annotations=types.ToolAnnotations(
                title=descriptor.title,
                readOnlyHint=descriptor.annotations.read_only,
                destructiveHint=descriptor.annotations.destructive,
                idempotentHint=descriptor.annotations.idempotent,
                openWorldHint=descriptor.annotations.open_world,
            ),
        )
        for descriptor in runtime.descriptors
    ]


async def call_tool(
    name: str,
    arguments: dict[str, object],
    runtime: BridgeRuntime = BRIDGE_RUNTIME,
    *,
    transport_request_id: types.RequestId | None = None,
) -> types.CallToolResult:
    """Dispatch one registered operation with bridge-owned strict validation.

    Unregistered names raise ``McpError`` so the low-level session answers with a JSON-RPC
    error rather than a tool execution result. Registered-tool validation failures stay as
    structured tool results.
    """

    dispatcher = {
        "start": dispatch_start,
        "publish_work": dispatch_publish_work,
        "check": dispatch_check,
        "respond": dispatch_respond,
        "status": dispatch_status,
        "closure_prepare": dispatch_closure_prepare,
        "receipt": dispatch_receipt,
        "read_guidance": dispatch_read_guidance,
    }.get(name)
    if dispatcher is None:
        raise McpError(
            types.ErrorData(code=types.INVALID_PARAMS, message=sanitize_unknown_tool_name(name))
        )
    if name == "closure_prepare":
        return await dispatch_closure_prepare(
            arguments,
            runtime,
            transport_request_id=transport_request_id,
        )
    return await dispatcher(arguments, runtime)


async def _handle_call_tool_request(
    req: types.CallToolRequest,
    runtime: BridgeRuntime = BRIDGE_RUNTIME,
    *,
    session: _RootsSession | None = None,
) -> types.ServerResult:
    """Own CallToolRequest so unknown names never reach the SDK's name-echoing cache path."""

    name = req.params.name
    if name not in _REGISTERED_TOOL_NAMES:
        # Raise before any logging that would interpolate the caller-controlled name.
        raise McpError(
            types.ErrorData(code=types.INVALID_PARAMS, message=sanitize_unknown_tool_name(name))
        )
    arguments = dict(req.params.arguments or {})
    if name != "read_guidance":
        binding_error = await _ensure_cursor_workspace_binding(
            runtime,
            session,
            safe_request_id_from(arguments),
            name,
        )
        if binding_error is not None:
            _record_rejected_call(name, arguments, binding_error)
            return types.ServerResult(binding_error)
    try:
        transport_request_id = request_ctx.get().request_id
    except LookupError:
        transport_request_id = None
    if name == "closure_prepare":
        result = await call_tool(
            name,
            arguments,
            runtime,
            transport_request_id=transport_request_id,
        )
    else:
        result = await call_tool(name, arguments, runtime)
    _record_rejected_call(name, arguments, result)
    return types.ServerResult(result)


def _record_rejected_call(
    name: str, arguments: Mapping[str, object], result: types.CallToolResult
) -> None:
    """Keep Yoetz's own record of an error answer so its pending hook attempt can close (#1041).

    A host fires no ``PostToolUse`` for an error result, so the call's ``PreToolUse`` would
    otherwise expire as a pipeline loss. Only a commitment to the call (tool, Yoetz session,
    writer and ``request_id``) is written; the call is never delayed or failed by this record.
    """

    if result.isError is not True:
        return
    record_rejected_yoetz_call(name, arguments)


async def list_resources(runtime: BridgeRuntime = BRIDGE_RUNTIME) -> list[types.Resource]:
    """List only static manifest-verified guidance; never touch the service slot.

    The wire listing carries no fractional number. Codex builds its rmcp client with serde_json's
    ``arbitrary_precision`` feature, under which rmcp before modelcontextprotocol/rust-sdk#1300
    cannot decode a buffered float such as ``annotations.priority: 0.9``; the whole
    ``ListResourcesResult`` then falls through to ``CustomResult`` and Codex reports
    ``resources/list failed: Unexpected response type`` (every Codex attempt in the full3
    benchmark). The registry keeps its relative priority, and the listing order already carries
    it, so ``priority`` is omitted for every host rather than advertised to some.
    """

    return [
        types.Resource(
            uri=AnyUrl(resource.uri),
            name=resource.name,
            title=resource.title,
            description=resource.description,
            mimeType=resource.media_type,
            size=resource.size,
            annotations=types.Annotations(
                audience=cast(list[types.Role], list(resource.annotations.audience)),
            ),
        )
        for resource in runtime.resources
    ]


async def read_resource(uri: object) -> list[ReadResourceContents]:
    """Read one exact registered guidance URI without interpreting it as a path."""

    try:
        payload = read_guidance_resource(str(uri)).decode("utf-8", errors="strict")
    except GuidanceResourceError as exc:
        raise ValueError("guidance_resource_unavailable") from exc
    resource = _GUIDANCE_BY_URI.get(str(uri))
    if resource is None:
        try:
            resource = guidance_resource_for_uri(str(uri))
        except GuidanceResourceError as exc:
            raise ValueError("guidance_resource_unavailable") from exc
    return [ReadResourceContents(content=payload, mime_type=resource.media_type)]


def _build_server(runtime: BridgeRuntime) -> Server[object]:
    active: Server[object] = Server(
        _SERVER_NAME,
        version=__version__,
        instructions=runtime.instructions,
    )

    async def runtime_list_tools() -> list[types.Tool]:
        return await list_tools(runtime)

    async def runtime_call_tool(req: types.CallToolRequest) -> types.ServerResult:
        return await _handle_call_tool_request(
            req,
            runtime,
            session=cast(_RootsSession, active.request_context.session),
        )

    async def runtime_roots_changed(_notify: types.RootsListChangedNotification) -> None:
        await _invalidate_cursor_workspace_binding(runtime)

    async def runtime_list_resources() -> list[types.Resource]:
        return await list_resources(runtime)

    active.list_tools()(runtime_list_tools)
    # Register a Yoetz-owned CallToolRequest handler instead of Server.call_tool so an unregistered
    # name becomes a sanitized JSON-RPC error and never reaches the SDK path that logs the raw name.
    active.request_handlers[types.CallToolRequest] = runtime_call_tool
    active.notification_handlers[types.RootsListChangedNotification] = runtime_roots_changed
    active.list_resources()(runtime_list_resources)
    active.read_resource()(read_resource)
    return active


server: Final = _build_server(BRIDGE_RUNTIME)


def _initialization_options(
    runtime: BridgeRuntime,
    active_server: Server[object] = server,
) -> InitializationOptions:
    capabilities = active_server.get_capabilities(NotificationOptions(), {}).model_copy(
        update={"experimental": None}
    )
    return InitializationOptions(
        server_name=_SERVER_NAME,
        server_version=__version__,
        capabilities=capabilities,
        instructions=runtime.instructions,
    )


async def run_stdio(runtime: BridgeRuntime = BRIDGE_RUNTIME) -> None:
    """Run bounded stdio and let the SDK negotiate protocol versions conformantly."""

    active_server = server if runtime is BRIDGE_RUNTIME else _build_server(runtime)
    async with bounded_stdio_server(drain_pending_responses=True) as (read_stream, write_stream):
        try:
            await active_server.run(
                read_stream,
                write_stream,
                _initialization_options(runtime, active_server),
                raise_exceptions=False,
            )
        finally:
            await close_bridge_runtime(runtime)


def _bridge_logging_config() -> LoggingConfig:
    # An unreadable or invalid config must never keep the bridge from installing its
    # stdout-safe sink; the built-in defaults are the same shape the loader would return.
    try:
        return load_config({}, os.environ, None).logging
    except Exception:
        return LoggingConfig()


def record_startup_route_drift(
    serving_profile: str,
    *,
    host_profile: McpHostProfile = "generic",
    _state: Path | None = None,
) -> None:
    """Record `registration_drift` when this bridge's route disagrees with the applied one.

    Issue #537. This is the sole emitter of the diagnostic: the bridge is the one process
    that knows its serving route from its own argv, so the comparison costs no host
    subprocess, while a hook process would have to shell out to `codex mcp get` for a
    weaker answer at a cost the hook budget cannot carry. Recorded under the `mcp_serve`
    event because this is bridge startup, not a host hook event. Fail-soft by contract:
    never raises, never blocks serving, never records content.
    """

    # The applied-route record belongs to the Codex registration adapter. A generic, Claude, or
    # Cursor bridge cannot establish that it is the process described by that record.
    if host_profile != "codex":
        return
    try:
        from yoetz.application.applied_mcp_route import read_applied_route
        from yoetz.cli.hook_diagnostics import record_hook_diagnostic

        try:
            record = read_applied_route(_state=_state)
        except Exception:
            return
        if not isinstance(record, dict):
            return
        applied = record.get("applied_profile")
        if applied not in {"policy", "strict"} or serving_profile not in {"policy", "strict"}:
            return
        if applied == serving_profile:
            return
        with contextlib.suppress(Exception):
            record_hook_diagnostic("registration_drift", "mcp_serve", _state=_state)
    except Exception:
        return


def main(
    *,
    semantic: Literal["on", "off"] = "on",
    host: McpHostProfile = "generic",
    project_root: Path | None = None,
    project_binding: Literal["mcp-roots", "registered-project"] = "mcp-roots",
) -> None:
    """Run the MCP bridge on stdio using the SDK-supported latest protocol contract."""

    if semantic not in {"on", "off"}:
        raise ValueError("mcp_semantic_profile_invalid")
    if host not in {"generic", "codex", "claude", "cursor"}:
        raise ValueError("mcp_host_profile_invalid")
    if types.LATEST_PROTOCOL_VERSION not in SUPPORTED_PROTOCOL_VERSIONS:
        raise RuntimeError("mcp_sdk_protocol_registry_invalid")
    configure_logging(_bridge_logging_config(), LogMode.MCP_STDIO)
    launcher = (
        _runtime_launcher_from_argv() if host == "cursor" and project_root is not None else None
    )
    registration_isolation_root = (
        os.environ.get("YOETZ_ISOLATED_ROOT")
        if host == "cursor" and project_root is not None
        else None
    )
    runtime = build_bridge_runtime(
        "strict" if semantic == "off" else "policy",
        host_profile=host,
        project_root=project_root,
        project_binding=project_binding,
        launcher=launcher,
        isolation_root=registration_isolation_root,
    )
    record_startup_route_drift(runtime.route_profile, host_profile=runtime.host_profile)
    anyio.run(
        run_stdio,
        runtime,
    )
