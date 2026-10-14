"""Ordinary local-service control client boundary."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, Protocol, cast

from yoetz.domain.coordination import CoordinationErrorCode
from yoetz.domain.values import JsonObject, validate_commitment
from yoetz.ports.control_reasons import CONTROL_ERROR_REASONS
from yoetz.protocol.canonical import parse_canonical_integer_string
from yoetz.protocol.errors import SafeDetailValue, normalize_safe_details
from yoetz.protocol.ids import IdKind, validate_id
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    PublishWorkRequest,
    PublishWorkResult,
    ReceiptRequest,
    ReceiptResult,
    RespondRequest,
    RespondResult,
    StartRequest,
    StartResult,
    StatusRequest,
    StatusResult,
)

__all__ = [
    "CONTROL_ERROR_REASONS",
    "ControlCallRequest",
    "ControlCancelRequest",
    "ControlClientKind",
    "ControlClientPort",
    "ControlError",
    "ControlMethod",
    "ProjectionRenderMode",
    "ControlRequest",
    "ControlResult",
    "McpHostProfile",
    "McpRouteProfile",
    "ServiceState",
    "ServiceStopResult",
    "ServiceStatus",
    "RepositoryIdentityKind",
    "RepositoryPrivacyContext",
    "WorkspaceLocator",
]

_CONTROL_PROTOCOL_VERSION = "1.0"
_MAX_DEADLINE_MS = 300_000
_SEMVER_PATTERN = re.compile(
    r"^(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)\."
    r"(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$",
    re.ASCII,
)


class ControlClientKind(str, Enum):  # noqa: UP042 - exact wire enum base
    CLI = "cli"
    MCP_BRIDGE = "mcp_bridge"
    UI = "ui"


class ProjectionRenderMode(str, Enum):  # noqa: UP042 - exact wire enum base
    HUMAN_READABLE = "human_readable"
    MACHINE_READABLE = "machine_readable"


type RepositoryIdentityKind = Literal["git_common_root", "directory"]
type McpHostProfile = Literal["generic", "codex", "claude", "cursor"]


@dataclass(frozen=True, slots=True)
class WorkspaceLocator:
    """Ephemeral client-provided locator consumed only by the service handshake."""

    path: str = field(repr=False)
    schema_version: Literal["1.0.0"] = "1.0.0"

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise ValueError("workspace_locator_schema_version_invalid")
        if type(self.path) is not str or not Path(self.path).is_absolute():
            raise ValueError("workspace_locator_path_invalid")
        try:
            encoded = self.path.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("workspace_locator_path_invalid") from exc
        if not encoded or len(encoded) > 8192 or any(marker in self.path for marker in "\x00\r\n"):
            raise ValueError("workspace_locator_path_invalid")


@dataclass(frozen=True, slots=True)
class RepositoryPrivacyContext:
    """Opaque repository identity safe to retain after handshake completion.

    ``workspace_locator`` is the exact locator the commitment was derived from. It stays in
    service memory for the life of the connection only, never in a result, log, or store, so the
    check-time change capture (ADR-031) reads the same directory the connection proved it is in.
    """

    commitment: str
    identity_kind: RepositoryIdentityKind
    workspace_locator: WorkspaceLocator | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        validate_commitment(self.commitment)
        if self.identity_kind not in {"git_common_root", "directory"}:
            raise ValueError("repository_identity_kind_invalid")
        if self.workspace_locator is not None and type(self.workspace_locator) is not (
            WorkspaceLocator
        ):
            raise TypeError("workspace_locator_invalid")


class ControlMethod(str, Enum):  # noqa: UP042 - exact wire enum base
    START = "start"
    PUBLISH_WORK = "publish_work"
    CHECK = "check"
    RESPOND = "respond"
    STATUS = "status"
    RECEIPT = "receipt"
    IMPORT_CODEX_JSONL = "import_codex_jsonl"
    PROJECT = "project"
    REVIEW = "review"
    BACKUP_PREVIEW = "backup_preview"
    BACKUP_EXECUTE = "backup_execute"
    RESTORE_PREVIEW = "restore_preview"
    RESTORE_EXECUTE = "restore_execute"
    MIGRATE_PREVIEW = "migrate_preview"
    MIGRATE_EXECUTE = "migrate_execute"
    INTEGRATION_PREVIEW = "integration_preview"
    INTEGRATION_EXECUTE = "integration_execute"
    OBSERVATION_INGEST = "observation_ingest"
    OBSERVATION_STATUS = "observation_status"
    OBSERVATION_PAUSE = "observation_pause"
    OBSERVATION_RESUME = "observation_resume"
    OBSERVATION_REVOKE = "observation_revoke"
    SERVICE_STATUS = "service_status"
    SERVICE_LOCK = "service_lock"
    SERVICE_STOP = "service_stop"
    PRIVACY_GET_SETUP = "privacy_get_setup"
    PRIVACY_GET_EFFECTIVE = "privacy_get_effective"
    PRIVACY_PROPOSE_POLICY = "privacy_propose_policy"
    PRIVACY_TIGHTEN_POLICY = "privacy_tighten_policy"
    PRIVACY_PENDING_LIST = "privacy_pending_list"
    PRIVACY_RECEIPTS_LIST = "privacy_receipts_list"
    PRIVACY_RECEIPTS_GET = "privacy_receipts_get"


class ServiceState(str, Enum):  # noqa: UP042 - exact wire enum base
    STARTING = "starting"
    LOCKED = "locked"
    UNLOCKING = "unlocking"
    READY = "ready"
    DRAINING = "draining"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class ServiceStopResult:
    schema_version: Literal["1.0.0"] = "1.0.0"
    state: Literal["draining"] = "draining"
    accepted: Literal[True] = True

    def __post_init__(self) -> None:
        if self.schema_version != "1.0.0":
            raise ValueError("service_stop_schema_version_invalid")
        if self.state != "draining":
            raise ValueError("service_stop_state_invalid")
        if self.accepted is not True:
            raise ValueError("service_stop_acceptance_invalid")


type ControlCallBody = (
    StartRequest
    | PublishWorkRequest
    | CheckRequest
    | RespondRequest
    | StatusRequest
    | ReceiptRequest
    | JsonObject
)
type McpRouteProfile = Literal["policy", "strict"]
type ControlSuccessBody = (
    StartResult
    | PublishWorkResult
    | CheckResult
    | RespondResult
    | StatusResult
    | ReceiptResult
    | JsonObject
    | ServiceStatus
    | ServiceStopResult
)

_WORKFLOW_REQUEST_TYPES: dict[ControlMethod, type[object]] = {
    ControlMethod.START: StartRequest,
    ControlMethod.PUBLISH_WORK: PublishWorkRequest,
    ControlMethod.CHECK: CheckRequest,
    ControlMethod.RESPOND: RespondRequest,
    ControlMethod.STATUS: StatusRequest,
    ControlMethod.RECEIPT: ReceiptRequest,
}
_WORKFLOW_RESULT_TYPES: dict[ControlMethod, type[object]] = {
    ControlMethod.START: StartResult,
    ControlMethod.PUBLISH_WORK: PublishWorkResult,
    ControlMethod.CHECK: CheckResult,
    ControlMethod.RESPOND: RespondResult,
    ControlMethod.STATUS: StatusResult,
    ControlMethod.RECEIPT: ReceiptResult,
}


def _validate_protocol_version(value: object) -> None:
    if type(value) is not str or value != _CONTROL_PROTOCOL_VERSION:
        raise ValueError("control_protocol_version_invalid")


def _validate_generation(value: object) -> None:
    if type(value) is not str:
        raise ValueError("service_generation_invalid")
    try:
        parsed = parse_canonical_integer_string(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("service_generation_invalid") from exc
    if parsed <= 0:
        raise ValueError("service_generation_invalid")


def _validate_deadline(value: object) -> None:
    if value is None:
        return
    if type(value) is not int or not 1 <= value <= _MAX_DEADLINE_MS:
        raise ValueError("deadline_ms_invalid")


@dataclass(frozen=True, slots=True)
class ControlCallRequest:
    kind: Literal["call"]
    protocol_version: Literal["1.0"]
    rpc_id: str
    service_instance_id: str
    service_generation: str
    method: ControlMethod
    body: ControlCallBody
    deadline_ms: int | None = None
    route_profile: McpRouteProfile | None = None
    host_profile: McpHostProfile | None = None

    def __post_init__(self) -> None:
        if self.kind != "call":
            raise ValueError("control_request_kind_invalid")
        _validate_protocol_version(self.protocol_version)
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _validate_generation(self.service_generation)
        if type(self.method) is not ControlMethod:
            raise ValueError("control_method_invalid")
        expected_body_type = _WORKFLOW_REQUEST_TYPES.get(self.method, JsonObject)
        if type(self.body) is not expected_body_type:
            raise ValueError("control_method_body_mismatch")
        _validate_deadline(self.deadline_ms)
        if self.route_profile is not None and (
            self.route_profile not in {"policy", "strict"}
            or self.method not in {ControlMethod.CHECK, ControlMethod.STATUS}
        ):
            raise ValueError("control_route_profile_invalid")
        if self.host_profile is not None and (
            self.host_profile not in {"generic", "codex", "claude", "cursor"}
            or self.method is not ControlMethod.CHECK
        ):
            raise ValueError("control_host_profile_invalid")


@dataclass(frozen=True, slots=True)
class ControlCancelRequest:
    kind: Literal["cancel"]
    protocol_version: Literal["1.0"]
    rpc_id: str
    service_instance_id: str
    service_generation: str
    target_rpc_id: str

    def __post_init__(self) -> None:
        if self.kind != "cancel":
            raise ValueError("control_request_kind_invalid")
        _validate_protocol_version(self.protocol_version)
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _validate_generation(self.service_generation)
        validate_id(IdKind.CONTROL_RPC, self.target_rpc_id)
        if self.rpc_id == self.target_rpc_id:
            raise ValueError("target_rpc_id_not_distinct")


type ControlRequest = ControlCallRequest | ControlCancelRequest


_TRANSPORT_CONTROL_ERROR_REASONS: Final[frozenset[str]] = frozenset(
    {
        "service_unavailable",
        "service_incompatible",
        "peer_untrusted",
        "protocol_mismatch",
        "frame_invalid",
        "frame_too_large",
        "request_cancelled",
        "request_timeout",
        "vault_locked",
        "service_draining",
        "method_forbidden",
        "internal_error",
        "privacy_projection_unavailable",
        "privacy_projection_blocked",
        "response_projection_failed",
        "read_projection_failed",
        "privacy_audit_unreadable",
        "service_generation_changed",
        "endpoint_unsafe",
    }
)
_COORDINATION_CONTROL_ERROR_REASONS: Final[frozenset[str]] = frozenset(
    code.value for code in CoordinationErrorCode
)
_CONTROL_ERROR_REASONS = _TRANSPORT_CONTROL_ERROR_REASONS | _COORDINATION_CONTROL_ERROR_REASONS
_EMPTY_ACCEPTED_STATE: Final[Mapping[str, SafeDetailValue]] = MappingProxyType({})
_CONTROL_ERROR_PHASE_PATTERN: Final = re.compile(r"^[a-z][a-z0-9_]{0,63}$", re.ASCII)
# The exact structural facts a caller needs to continue after a post-commit projection failure:
# where the ledger landed, and how many events it accepted.
ACCEPTED_STATE_KEYS: Final = ("count", "head_digest", "sequence")


class ControlError(Exception):
    """A bounded control failure with no free-form message and only allowlisted details.

    ``accepted_state`` carries the structural facts of an operation that already committed, for
    the one case where the caller cannot otherwise learn them: response projection failed after a
    durable append, so no success body exists. Without it the caller knows only *that* the write
    landed and must spend a second `status` call to learn *where*. Values pass through the same
    ``SAFE_DETAIL_KEYS`` allowlist as public errors, so this stays structural — no user content,
    no free text — and it is admitted only for ``response_projection_failed``.

    Coordination application refusals use the finite ``CoordinationErrorCode`` vocabulary as their
    control reason. They remain non-retryable: the caller must change the command or refresh its
    authorization before trying again. No project title, description, path, or other caller text
    is carried by this exception.

    ``correlation_id`` is the optional service-minted diagnostic identity for an unexpected failure
    the daemon already recorded. It is a structural ``err_…`` token with no caller content; when
    present the MCP bridge must surface this same id to the agent so
    ``yoetz service diagnostics --correlation-id`` resolves the durable sink record. Absence means
    the failure originated without a prior service-side record (deliberate control reasons, or a
    bridge-local fault) and the bridge mints/records under its own id.
    """

    __slots__ = ("accepted_state", "correlation_id", "phase", "reason", "retryable")

    reason: str
    retryable: bool
    accepted_state: Mapping[str, SafeDetailValue]
    correlation_id: str | None
    phase: str | None

    def __init__(
        self,
        reason: str,
        *,
        retryable: bool = False,
        accepted_state: Mapping[str, SafeDetailValue] | None = None,
        correlation_id: str | None = None,
        phase: str | None = None,
    ) -> None:
        if type(reason) is not str or reason not in CONTROL_ERROR_REASONS:
            raise TypeError("control_error_reason_invalid")
        if type(retryable) is not bool:
            raise TypeError("control_error_retryable_invalid")
        if phase is not None and (
            type(phase) is not str or _CONTROL_ERROR_PHASE_PATTERN.fullmatch(phase) is None
        ):
            raise ValueError("control_error_phase_invalid")
        if reason in _COORDINATION_CONTROL_ERROR_REASONS and retryable:
            raise ValueError("coordination_control_error_must_not_be_retryable")
        if reason == "privacy_projection_unavailable" and not retryable:
            raise ValueError("privacy_projection_error_must_be_retryable")
        if reason == "privacy_projection_blocked" and retryable:
            raise ValueError("privacy_projection_blocked_must_not_be_retryable")
        # The operation already committed; only the response could not be shaped. Surfacing it as
        # non-retryable would steer callers away from the same-request_id replay that recovers it.
        if reason == "response_projection_failed" and not retryable:
            raise ValueError("response_projection_error_must_be_retryable")
        # A read never committed anything, so its remedy is a fresh request rather than a
        # same-request_id replay. It stays retryable because repeating the read is the fix.
        if reason == "read_projection_failed" and not retryable:
            raise ValueError("read_projection_error_must_be_retryable")
        # A stored receipt that cannot be read back stays unreadable on the next attempt; calling
        # it retryable would send the operator into a loop instead of to the named receipts.
        if reason == "privacy_audit_unreadable" and retryable:
            raise ValueError("privacy_audit_unreadable_must_not_be_retryable")
        if correlation_id is not None:
            try:
                validate_id(IdKind.CORRELATION, correlation_id)
            except Exception as exc:
                raise ValueError("control_error_correlation_id_invalid") from exc
        normalized = normalize_safe_details(accepted_state) if accepted_state is not None else None
        if normalized:
            # Only a post-commit write has accepted state to report. Attaching it elsewhere would
            # assert durability that never happened.
            if reason != "response_projection_failed":
                raise ValueError("control_error_accepted_state_not_admitted")
            if len(normalized) != len(cast(Mapping[str, object], accepted_state)):
                # normalize_safe_details silently drops unknown or malformed keys. Silently
                # shipping a subset would understate what committed, so refuse instead.
                raise ValueError("control_error_accepted_state_invalid")
        self.reason = reason
        self.retryable = retryable
        self.accepted_state = normalized or _EMPTY_ACCEPTED_STATE
        self.correlation_id = correlation_id
        self.phase = phase
        super().__init__(reason)


@dataclass(frozen=True, slots=True)
class ControlResult:
    protocol_version: Literal["1.0"]
    rpc_id: str
    service_instance_id: str
    service_generation: str
    method: ControlMethod
    outcome: Literal["ok", "error"]
    body: ControlSuccessBody | ControlError

    def __post_init__(self) -> None:
        _validate_protocol_version(self.protocol_version)
        validate_id(IdKind.CONTROL_RPC, self.rpc_id)
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _validate_generation(self.service_generation)
        if type(self.method) is not ControlMethod:
            raise ValueError("control_method_invalid")
        if self.outcome not in {"ok", "error"}:
            raise ValueError("control_outcome_invalid")
        if (self.outcome == "error") is not isinstance(self.body, ControlError):
            raise ValueError("control_outcome_body_mismatch")
        if self.outcome == "ok":
            expected_body_type = _WORKFLOW_RESULT_TYPES.get(self.method, JsonObject)
            if self.method in {ControlMethod.SERVICE_STATUS, ControlMethod.SERVICE_LOCK}:
                expected_body_type = ServiceStatus
            elif self.method is ControlMethod.SERVICE_STOP:
                expected_body_type = ServiceStopResult
            if type(self.body) is not expected_body_type:
                raise ValueError("control_method_body_mismatch")


_SERVICE_STATE_REASON_VALUES = (
    "none",
    "auto_unlock_backend_unavailable",
    "auto_unlock_rejected",
    "auto_unlock_stale",
    "keyring_locked",
    "keyring_unavailable",
    "passphrase_required",
    "human_authority_unavailable",
    "vault_uninitialized",
    "unlock_failed",
    "explicit_lock",
    "idle_relock",
    "user_session_locked",
    "system_suspend",
    "monitor_lost",
    "shutdown_requested",
    "internal_error",
)
_SERVICE_STATE_REASONS = frozenset(_SERVICE_STATE_REASON_VALUES)
_VAULT_MODES = frozenset({"uninitialized", "os_keyring", "passphrase"})
_SERVICE_CAPABILITIES = frozenset(
    {
        "workflow",
        "maintenance",
        "import_review",
        "external_provider",
        "fallback_provider",
        "confidential_ingress",
        "session_event_monitor",
    }
)
_SESSION_MONITOR_STATES = frozenset({"active", "unavailable", "lost"})


@dataclass(frozen=True, slots=True)
class ServiceStatus:
    protocol_version: Literal["1.0"]
    service_version: str
    service_instance_id: str
    service_generation: str
    state: ServiceState
    state_reason: str
    vault_mode: str
    capabilities: tuple[str, ...]
    session_monitor: str
    idle_relock_seconds: int | None = None

    def __post_init__(self) -> None:
        _validate_protocol_version(self.protocol_version)
        if type(self.service_version) is not str or not 5 <= len(self.service_version) <= 128:
            raise ValueError("service_version_invalid")
        if _SEMVER_PATTERN.fullmatch(self.service_version) is None:
            raise ValueError("service_version_invalid")
        validate_id(IdKind.SERVICE_INSTANCE, self.service_instance_id)
        _validate_generation(self.service_generation)
        if type(self.state) is not ServiceState:
            raise ValueError("service_state_invalid")
        if self.state_reason not in _SERVICE_STATE_REASONS:
            raise ValueError("service_state_reason_invalid")
        if self.vault_mode not in _VAULT_MODES:
            raise ValueError("vault_mode_invalid")
        if type(self.capabilities) is not tuple:
            raise ValueError("service_capabilities_invalid")
        if any(type(capability) is not str for capability in self.capabilities):
            raise ValueError("service_capabilities_invalid")
        encoded = tuple(capability.encode("ascii") for capability in self.capabilities)
        if not set(self.capabilities) <= _SERVICE_CAPABILITIES or encoded != tuple(
            sorted(set(encoded))
        ):
            raise ValueError("service_capabilities_invalid")
        if self.session_monitor not in _SESSION_MONITOR_STATES:
            raise ValueError("session_monitor_invalid")
        if self.idle_relock_seconds is not None and (
            type(self.idle_relock_seconds) is not int
            or not 60 <= self.idle_relock_seconds <= 86_400
        ):
            raise ValueError("idle_relock_seconds_invalid")


class ControlClientPort(Protocol):
    async def connect(self) -> None: ...

    async def call(self, request: ControlCallRequest) -> ControlResult: ...

    async def cancel(self, request: ControlCancelRequest) -> None: ...

    async def service_status(self) -> ServiceStatus: ...

    async def lock(self) -> ServiceStatus: ...

    async def stop(self) -> ServiceStopResult: ...

    async def close(self) -> None: ...
