"""Trusted per-user local-service orchestration and ordinary-control dispatch."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import os
import signal
import stat
import struct
import time
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import Final, Literal, Never, Protocol, cast

import anyio
from pydantic import BaseModel

from yoetz import __version__
from yoetz.adapters.control.unix_socket import (
    EndpointKind,
    LocalControlTransportError,
    bind_control_listener,
    bind_human_control_listener,
    bind_secret_listener,
    remove_stale_endpoint,
)
from yoetz.adapters.keys.encrypted_vault import EncryptedVaultStore
from yoetz.adapters.keys.installation_recovery import (
    InstallationRecoveryArtifact,
    InstallationRecoveryMetadata,
    InstallationRecoveryMode,
    InstallationRecoverySecretKind,
)
from yoetz.adapters.keys.os_keyring import AutoUnlockPassphraseStore
from yoetz.adapters.keys.secret_memory import LocalSecretMemory
from yoetz.adapters.keys.vault_passphrase import VaultRootEnvelope
from yoetz.adapters.repository_identity import resolve_repository_privacy_context
from yoetz.adapters.session_events import SessionEventMonitor
from yoetz.application.observation_await import (
    TaskPendingProbe,
    await_observations_bound,
    await_task_observations,
)
from yoetz.application.observation_drain import (
    ObservationDrainSummary,
)
from yoetz.application.publish_work import (
    PublishWorkInternalResult,
    accepted_projection_unavailable_from_internal,
    build_accepted_projection_unavailable_result,
)
from yoetz.application.service import (
    ClientProjectionContext,
    ControlProjectionBinding,
    ProjectedControlBody,
    ProjectionBindingFacts,
    UnprojectedControlBody,
    internal_control_json,
    resolve_client_disclosure_sink,
)
from yoetz.config.installation import (
    InstanceIdentityError,
    read_instance_identity,
    verify_instance_binding,
)
from yoetz.config.load import load_config
from yoetz.config.models import ConfigError, YoetzConfig
from yoetz.config.paths import (
    PathSafetyError,
    bundle_root,
    ensure_owner_only_dir,
    isolated_root,
    read_runtime_pin,
    service_generation_path,
    state_dir,
    unlock_throttle_path,
    verify_private_local_bundle,
)
from yoetz.domain.observation import (
    ObservationIngestRequest,
    observation_ingest_request_from_json,
)
from yoetz.domain.observation_profiles import content_capture_profile_matches_source
from yoetz.domain.privacy import (
    AuthorizationScopeKind,
    EgressChannel,
    LocalDisclosureSink,
)
from yoetz.domain.values import JsonValue as DomainJsonValue
from yoetz.domain.values import frontier_from_json
from yoetz.observability.logging import (
    LogMode,
    configure_logging,
    get_logger,
    record_bounded_counts_without_raising,
    record_bounded_event_without_raising,
    record_public_error_without_raising,
    record_unexpected_exception_without_raising,
)
from yoetz.ports.control import (
    ControlCallRequest,
    ControlClientKind,
    ControlError,
    ControlMethod,
    ControlResult,
    RepositoryPrivacyContext,
    ServiceState,
    ServiceStatus,
    ServiceStopResult,
    WorkspaceLocator,
)
from yoetz.ports.diagnostics import StartupCheckResult
from yoetz.ports.keys import KeyStorePort, MacKeyPurpose
from yoetz.ports.ledger import (
    CheckAdmissionStage,
    CheckObservationsAwaited,
    check_admission_stage,
)
from yoetz.ports.observation import ObservationStoreLockTimeout
from yoetz.ports.secret_memory import (
    HumanAuthorizationProof,
    SecretHandle,
    SecretMemoryError,
    SecretPurpose,
)
from yoetz.protocol.canonical import (
    JsonValue,
    canonical_digest,
    canonical_encode,
    strict_json_parse,
)
from yoetz.protocol.errors import ProtocolValueError, PublicOperationError, SafeDetailValue
from yoetz.protocol.ids import IdKind, new_id, validate_id
from yoetz.protocol.models import (
    CheckRequest,
    CheckResult,
    PublishWorkAcceptedProjectionUnavailableModel,
    PublishWorkDryRunModel,
    PublishWorkResult,
    PublishWorkResultModel,
    PublishWorkSuccessModel,
    ReceiptResult,
    RespondResult,
    StartResult,
    StatusRequest,
    StatusResult,
)
from yoetz.protocol.recovery import READ_ONLY_CHECK_MODES
from yoetz.service.check_waits import EXPLICIT_CONTROL_CANCEL, CheckReadWindow, CheckWaits
from yoetz.service.confidential_protocol import (
    HUMAN_PROTOCOL_MAGIC,
    HUMAN_PROTOCOL_VERSION,
    MAX_HUMAN_CONTROL_FRAME_BYTES,
    ClientActionEnvelope,
    ClientCancelEnvelope,
    ClientOpenEnvelope,
    EmptyVaultTarget,
    HumanCeremonyKind,
    HumanPreview,
    IdleRelockPolicyResult,
    IdleRelockPolicyTarget,
    InstallationRecoveryPreview,
    InstallationRecoveryResult,
    InstallationRecoveryTarget,
    KeyringRetryPreview,
    PortableRecoveryResult,
    PortableRecoveryTarget,
    PrivacyDecisionResult,
    PrivacyDisclosureDecisionPreview,
    PrivacyPendingTarget,
    PrivacyPolicyDecisionPreview,
    PrivacyPolicyTransitionPreviewMember,
    ProviderCredentialResult,
    ProviderCredentialRotatePreview,
    ProviderCredentialSetPreview,
    ProviderCredentialTarget,
    SecretRequiredPhase,
    ServerCloseEnvelope,
    ServerErrorEnvelope,
    ServerResultEnvelope,
    VaultInitializePreview,
    VaultPassphraseRotatePreview,
    VaultStateResult,
    VaultUnlockPreview,
    decode_human_frame,
    encode_human_frame,
    human_target_json,
)
from yoetz.service.control_protocol import (
    CONTROL_FRAME_READ_DEADLINE_SECONDS,
    ControlFrame,
    ControlProtocolError,
    ControlSession,
    ControlStream,
    encode_control_frame,
    parse_control_request,
    read_control_frame,
    server_handshake,
    validate_request,
    validate_result,
    write_control_frame,
)
from yoetz.service.human_control import HumanControlError, HumanControlService
from yoetz.service.installation_recovery import (
    InstallationRecoverySetStore,
    PreparedInstallationSnapshot,
)
from yoetz.service.lifecycle import (
    SINGLETON_LOCK_NAME,
    Admission,
    LifecycleError,
    ServiceLifecycle,
    SessionSecurityEvent,
)
from yoetz.service.loop_health import ControlPlaneWatchdog
from yoetz.service.ready_composition import build_ready_application_factory
from yoetz.service.secret_ingress import SecretIngressService
from yoetz.service.session_routes import SESSION_ROUTE_FILE_NAME, SessionRouteMemory
from yoetz.service.startup_failure import ServiceStartupError, record_startup_failure
from yoetz.service.unlock import UnlockCoordinator, UnlockThrottleRecord, UnlockThrottleStore
from yoetz.service.vault import VaultError, VaultMode, VaultService

__all__ = ["ServiceComposition", "ServiceDaemon", "main", "run_service"]

_INSTALLATION_MARKER_NAME = "installation-state.json"
_INSTALLATION_MARKER_DOMAIN = b"yoetz/installation-state/v1\x00"
_SERVICE_GENERATION_DOMAIN = b"yoetz/service-generation/v1\x00"
_MAX_INSTALLATION_MARKER_BYTES = 65_536
_HUMAN_HEADER = struct.Struct(">4sBBI")
# Ordinary-control connection liveness bounds (private; no wire/config surface).
# Handshake must finish within this wall-clock window, including partial-frame drip.
_CONTROL_HANDSHAKE_DEADLINE_SECONDS: Final = 5.0
# After handshake, a session with no active calls may stay silent for at most this long
# before the stream is closed and the listener admission slot is released.
_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS: Final = 300.0
# Once a frame's first byte arrives, the whole frame must arrive within this window, whether or
# not the session has calls in flight; a stalled partial frame closes the stream (issue #921).
_CONTROL_FRAME_READ_DEADLINE_SECONDS: Final = CONTROL_FRAME_READ_DEADLINE_SECONDS
_OBSERVATION_SWEEP_INTERVAL_SECONDS: Final = 60.0
# Hard stop for one sweep. The sweeper yields on its own budget
# (``DEFAULT_OBSERVATION_SWEEP_BUDGET_SECONDS``, composed in ready_composition) well
# under this, returning its partial summary so progress licenses the immediate
# re-sweep below; this deadline only catches a single ingest that never returns,
# and a pass it cancels reads as no progress (#564).
_OBSERVATION_SWEEP_DEADLINE_SECONDS: Final = 30.0
# Recovery includes a bounded catalog/ledger reconciliation for each active route.  It runs
# before the first ordinary maintenance pass and then at the normal maintenance cadence; a
# damaged or unexpectedly slow route must never pin the READY daemon forever.
_LINEAGE_RECOVERY_DEADLINE_SECONDS: Final = 30.0
# Yield between two immediately consecutive drain passes. One scheduler turn is not a fair share
# when the next pass may take a cross-process store lock a hook process also wants.
_OBSERVATION_SWEEP_PROGRESS_DELAY_SECONDS: Final = 0.05
# Hook ingest is the signal that a host is producing observation input, and a hook drains at most
# a few rows within its own 0.2 s budget. Each hook ingest therefore moves the next sweep forward
# instead of leaving the remainder for the 60 s idle interval (#887). A burst of hook ingests is
# coalesced: the sweeper waits this long after the first wake, so hook-driven passes stay at most
# about one per second and never contend with every hook for the store lock.
_OBSERVATION_SWEEP_INGEST_COALESCE_SECONDS: Final = 1.0
# Some hooks commit a contentless structural row locally and defer delivery without any service
# call, so no ingest wake exists for it. While idle the sweeper polls a lock-free, read-only probe
# at this cadence and sweeps as soon as an unattempted row is waiting. Rows that already failed an
# attempt keep the idle interval, so a retrying row cannot turn this poll into a retry storm.
_OBSERVATION_SWEEP_BACKLOG_POLL_SECONDS: Final = 5.0
_READY_RECOMMENDATION_REFRESH_DEADLINE_SECONDS: Final = 10.0
_READY_RECOMMENDATION_REFRESH_INTERVAL_SECONDS: Final = 3600.0
# Soft locks may re-apply the same scoped auto-unlock / keyring load the service already uses at
# restart. Explicit human lock and hard unlock failures stay locked until a trusted ceremony.
#
# ``monitor_lost`` is deliberately absent. Idle, session lock, and suspend all describe conditions
# the service can observe recovering from, so re-readying restores a state it can keep watching.
# Losing the session monitor is different: the capability that produces those events is gone for
# the life of the process, so auto-re-ready would make that lock momentary and then run on with
# session-lock relock silently no longer applying. Requiring a ceremony there keeps the containment
# ADR-008 describes from disappearing without anyone being told.
_SOFT_LOCK_AUTO_READY_REASONS: Final = frozenset(
    {
        "idle_relock",
        "user_session_locked",
        "system_suspend",
    }
)
# A soft-lock re-ready whose vault unlock already succeeded can still fail while activating the
# ready application for ambient reasons (event-loop saturation, transient contention). Those
# failures keep the soft-lock reason -- and with it auto-ready eligibility, so the next dispatch
# simply tries again -- for this many consecutive attempts before degrading to the terminal
# ``unlock_failed`` that only a trusted ceremony clears. Without the allowance, one transient
# blip demoted a succeeded re-ready into a permanent LOCKED that nothing ever reconsidered
# (#276). Credential-shaped failures are unaffected: they never reach this classification.
_SOFT_REREADY_ACTIVATION_RETRY_LIMIT: Final = 3
# Response-frame send must complete within this wall-clock window. A stalled peer that stops
# reading cannot retain an in-flight entry in ``calls`` (and thus the inactive-session exemption)
# indefinitely via write backpressure on sock_sendall.
_CONTROL_RESPONSE_WRITE_DEADLINE_SECONDS: Final = 300.0

_WORKFLOW_METHODS = frozenset(
    {
        ControlMethod.START,
        ControlMethod.PUBLISH_WORK,
        ControlMethod.CHECK,
        ControlMethod.RESPOND,
        ControlMethod.STATUS,
        ControlMethod.RECEIPT,
    }
)
_STRUCTURAL_METHODS = frozenset(
    {
        ControlMethod.SERVICE_STATUS,
        ControlMethod.SERVICE_LOCK,
        ControlMethod.SERVICE_STOP,
    }
)
_PROJECTION_EXEMPT_METHODS = _STRUCTURAL_METHODS | {
    # Observation ingest returns only disposition, a bounded reason token, and a structural
    # cursor. Running it through result disclosure projection both adds no privacy protection and
    # breaks the exact direct response schema used by hook/outbox clients.
    ControlMethod.OBSERVATION_INGEST,
    # Observation control results are schema-defined wrappers containing only a bounded status
    # object and the request correlation id. They do not carry workflow result branches and must
    # bypass client disclosure projection just like ingest.
    ControlMethod.OBSERVATION_STATUS,
    ControlMethod.OBSERVATION_PAUSE,
    ControlMethod.OBSERVATION_RESUME,
    ControlMethod.OBSERVATION_REVOKE,
    ControlMethod.PRIVACY_PENDING_LIST,
    ControlMethod.PRIVACY_RECEIPTS_LIST,
    ControlMethod.PRIVACY_RECEIPTS_GET,
}
# Methods that never append to the ledger. A projection failure on one of these cannot have left
# a durable write behind, so its remedy is repeating the request, not same-request_id replay.
_READ_ONLY_METHODS: Final[frozenset[ControlMethod]] = frozenset(
    {
        ControlMethod.STATUS,
        ControlMethod.OBSERVATION_STATUS,
        ControlMethod.PRIVACY_GET_SETUP,
        ControlMethod.PRIVACY_GET_EFFECTIVE,
        ControlMethod.PRIVACY_PENDING_LIST,
        ControlMethod.PRIVACY_RECEIPTS_LIST,
        ControlMethod.PRIVACY_RECEIPTS_GET,
    }
)


def _request_is_read_only(request: ControlCallRequest) -> bool:
    """Classify support status as a read while keeping project writes write-shaped."""

    if request.method in _READ_ONLY_METHODS:
        return True
    if (
        request.method is ControlMethod.CHECK
        and type(request.body) is CheckRequest
        and request.body.mode in READ_ONLY_CHECK_MODES
    ):
        # ADR-047: an inspection records nothing, so a failure is a read failure to repeat,
        # never a same-request_id replay of an operation that does not exist. The MCP bridge
        # and the CLI classify a timed-out inspection by the same modes.
        return True
    if request.method is ControlMethod.PROJECT and isinstance(request.body, Mapping):
        return request.body.get("operation") == "status"
    return False


_WORKFLOW_RESULT_MODELS: Final[Mapping[ControlMethod, type[BaseModel]]] = {
    ControlMethod.START: StartResult,
    ControlMethod.PUBLISH_WORK: PublishWorkResult,
    ControlMethod.CHECK: CheckResult,
    ControlMethod.RESPOND: RespondResult,
    ControlMethod.STATUS: StatusResult,
    ControlMethod.RECEIPT: ReceiptResult,
}


async def _acquire_dispatch_gate(gate: asyncio.Lock, deadline_ms: int | None) -> None:
    """Acquire one dispatch gate with the caller's bounded wait, if any."""

    if deadline_ms is None:
        await gate.acquire()
        return
    try:
        await asyncio.wait_for(gate.acquire(), deadline_ms / 1_000)
    except TimeoutError as exc:
        raise ControlError("request_timeout", retryable=True) from exc


def _is_operation_status_read(request: ControlCallRequest) -> bool:
    """Recognize the one read admitted beside a gate-holding semantic check."""

    return (
        request.method is ControlMethod.STATUS
        and type(request.body) is StatusRequest
        and request.body.view == "operation"
    )


def _is_valid_capture_only_observation(request: ControlCallRequest) -> bool:
    """Recognize only a fully parsed native observation capture handoff.

    The observation-gate exemption is deliberately decided from the domain parser rather than a
    body mapping or a caller-supplied ``capture_only`` attribute. Malformed, structural, and
    ordinary observation requests therefore retain the full maintenance/observation exclusion.
    """

    if request.method is not ControlMethod.OBSERVATION_INGEST:
        return False
    try:
        parsed = observation_ingest_request_from_json(cast(DomainJsonValue, request.body))
    except KeyError, ProtocolValueError, TypeError, ValueError:
        return False
    return (
        type(parsed) is ObservationIngestRequest
        and parsed.capture_only is True
        and (
            (
                parsed.envelope.source.value == "codex_hook"
                and parsed.content_capture_profile is None
            )
            or (
                parsed.content_capture_profile is not None
                and content_capture_profile_matches_source(
                    parsed.envelope.source.value,
                    parsed.content_capture_profile,
                )
            )
        )
    )


def _accepted_state(internal: object) -> Mapping[str, SafeDetailValue] | None:
    """Read where a committed operation landed, for an error that has no success body.

    Structural only: the resulting frontier and how many events were accepted. Returns None
    whenever any part is missing or malformed, because a partial answer about durability is worse
    than none — the caller falls back to reading `status`, which is where they were before.
    """

    try:
        source = internal_control_json(cast(UnprojectedControlBody, internal))
        frontier = source["result_frontier"]
        if not isinstance(frontier, Mapping):
            return None
        sequence = int(cast(str, frontier["sequence"]))
        head_digest = frontier["head_digest"]
        events = source.get("accepted_events")
        count = len(cast("tuple[object, ...] | list[object]", events)) if events is not None else 0
        if type(head_digest) is not str or sequence < 0:
            return None
        return MappingProxyType({"count": count, "head_digest": head_digest, "sequence": sequence})
    except BaseException:
        return None


def _publish_accepted_projection_unavailable(
    internal: object,
    *,
    correlation_id: str,
    request_id: str | None,
) -> PublishWorkResult | None:
    """Return the reduced total-acceptance envelope for a committed publish, or None.

    ``correlation_id`` is minted by the caller so the envelope, the diagnostic ring, and any
    fallback ``ControlError`` path share one id. Returns None only when the minimal envelope cannot
    be built — which must be impossible for a valid ``PublishWorkInternalResult``.
    """

    try:
        if type(internal) is PublishWorkInternalResult:
            return accepted_projection_unavailable_from_internal(
                internal, correlation_id=correlation_id
            )
        if type(internal) is PublishWorkResultModel:
            root = internal.root
            if type(root) is PublishWorkAcceptedProjectionUnavailableModel:
                return internal
            if type(root) is PublishWorkSuccessModel:
                return build_accepted_projection_unavailable_result(
                    request_id=root.request_id,
                    outcome=root.outcome,
                    task_id=root.task_id,
                    session_id=root.session_id,
                    writer_id=root.writer_id,
                    subject_frontier=frontier_from_json(
                        root.subject_frontier.model_dump(mode="json")
                    ),
                    result_frontier=frontier_from_json(
                        root.result_frontier.model_dump(mode="json")
                    ),
                    accepted=root.accepted_events,
                    correlation_id=correlation_id,
                )
            # Dry-run previews never append; there is nothing to reduce to an acceptance envelope.
            if type(root) is PublishWorkDryRunModel:
                return None
        return None
    except BaseException as envelope_exc:
        # A second diagnostic for envelope construction only — reuses the same request_id but a
        # distinct operation so operators can see the reduction itself failed after the first log.
        record_unexpected_exception_without_raising(
            envelope_exc,
            component="service.daemon",
            operation="publish_work_accepted_envelope_failed",
            request_id=request_id,
        )
        return None


def _safe_body_request_id(request: ControlCallRequest) -> str | None:
    """Return the caller's already-public request id, or None if the body has no usable one."""

    try:
        candidate = getattr(request.body, "request_id", None)
    except BaseException:
        return None
    return candidate if type(candidate) is str else None


def _read_projection_incident_key(
    request: ControlCallRequest,
) -> tuple[str, str, str, str, str] | None:
    """Return the validated status binding used to join failed polls into one incident."""

    if request.method is not ControlMethod.STATUS or not isinstance(request.body, StatusRequest):
        return None
    return (
        request.method.value,
        request.body.session_id,
        request.body.writer_id,
        request.body.view,
        "" if request.body.task_id is None else request.body.task_id,
    )


def _structural_request_id(body: object) -> str | None:
    """Return a call body's public ``req_`` id, or ``None``; never raises (tb4n2 NEW-8)."""

    try:
        value: object = (
            cast(Mapping[str, object], body).get("request_id")
            if isinstance(body, dict)
            else cast(object, getattr(body, "request_id", None))
        )
        return validate_id(IdKind.REQUEST, value) if isinstance(value, str) else None
    except Exception:
        return None


class _Listener(Protocol):
    async def accept(self) -> ControlStream: ...

    async def aclose(self) -> None: ...


@dataclass(slots=True)
class _ReadProjectionIncident:
    """One transient read incident, independent of the requests that poll it."""

    started_at: float
    attempts: int
    phase: str
    correlation_id: str


class _ServiceLockAuthority(Protocol):
    def assert_held(self) -> None: ...


class _SessionCapability(Protocol):
    @property
    def active(self) -> bool: ...


class _SessionMonitor(Protocol):
    @property
    def capability(self) -> _SessionCapability: ...

    async def start(self, callback: Callable[[SessionSecurityEvent], Awaitable[None]]) -> None: ...

    async def close(self) -> None: ...


class _Vault(Protocol):
    @property
    def ready(self) -> bool: ...

    @property
    def generation(self) -> int: ...

    @property
    def mode(self) -> object: ...

    async def lock(self) -> object: ...

    async def close(self) -> None: ...


class _ReadyApplication(Protocol):
    async def load_publish_response(
        self, result: PublishWorkInternalResult, sink: LocalDisclosureSink
    ) -> PublishWorkResult | None: ...

    async def store_publish_response(
        self,
        result: PublishWorkInternalResult,
        sink: LocalDisclosureSink,
        projected: ProjectedControlBody,
    ) -> PublishWorkResult: ...

    async def projection_binding_facts(
        self,
        method: ControlMethod,
        request: object,
        result: object,
    ) -> ProjectionBindingFacts: ...

    async def project_result_for_client(
        self,
        context: ClientProjectionContext,
        binding: ControlProjectionBinding,
        result: object,
    ) -> ProjectedControlBody: ...

    async def close(self) -> None: ...


class _Closable(Protocol):
    async def close(self) -> None: ...


class _SyncClosable(Protocol):
    def close(self) -> None: ...


class _Diagnostics(Protocol):
    def record(self, result: StartupCheckResult) -> None: ...


type _HumanConnectionHandler = Callable[[ControlStream], Awaitable[None]]
type _ReadyApplicationFactory = Callable[[int, int], Awaitable[_ReadyApplication]]
type _StartupBundleUpgrade = Callable[..., Awaitable[object]]


class _ReadyActivationRelay:
    """Bind UnlockCoordinator to the daemon without exposing application ownership."""

    def __init__(self) -> None:
        self._activate: Callable[[int, int], Awaitable[None]] | None = None

    def bind(self, activate: Callable[[int, int], Awaitable[None]]) -> None:
        if self._activate is not None or not callable(activate):
            raise RuntimeError("ready_activation_relay_invalid")
        self._activate = activate

    async def __call__(self, service_generation: int, vault_generation: int) -> None:
        activate = self._activate
        if activate is None:
            raise RuntimeError("ready_activation_relay_unbound")
        await activate(service_generation, vault_generation)


class _ReadyCloseRelay:
    """Let lifecycle drains close the daemon-owned ready graph exactly once."""

    def __init__(self) -> None:
        self._close: Callable[[], Awaitable[None]] | None = None

    def bind(self, close: Callable[[], Awaitable[None]]) -> None:
        if self._close is not None or not callable(close):
            raise RuntimeError("ready_close_relay_invalid")
        self._close = close

    async def __call__(self) -> None:
        close = self._close
        if close is None:
            raise RuntimeError("ready_close_relay_unbound")
        await close()


class _PrivacyPolicyAppRelay:
    """Late-bound lookup for the ready PrivacyCoordinator (human effects)."""

    def __init__(self) -> None:
        self._getter: Callable[[], object | None] | None = None

    def bind(self, getter: Callable[[], object | None]) -> None:
        if self._getter is not None or not callable(getter):
            raise RuntimeError("privacy_policy_app_relay_invalid")
        self._getter = getter

    def get(self) -> object | None:
        getter = self._getter
        if getter is None:
            return None
        return getter()


@dataclass(frozen=True, slots=True)
class ServiceComposition:
    """One generation's service-owned components, redacted by construction."""

    lifecycle: ServiceLifecycle
    control_listener: _Listener
    secret_ingress_listener: _Listener | None
    human_control_listener: _Listener | None
    human_control_service: _Closable | None
    session_monitor: _SessionMonitor | None
    vault: _Vault
    application: _ReadyApplication | None = None
    ready_application_factory: _ReadyApplicationFactory | None = None
    secret_ingress_service: _Closable | None = None
    unlock_service: _Closable | None = None
    secret_memory: _SyncClosable | None = None
    diagnostics: _Diagnostics | None = None
    human_connection_handler: _HumanConnectionHandler | None = None
    ready_activation_relay: _ReadyActivationRelay | None = None
    ready_close_relay: _ReadyCloseRelay | None = None
    privacy_policy_app_relay: _PrivacyPolicyAppRelay | None = None
    auto_unlock_reason: str = "none"
    auto_unlock_bundle: Path | None = None
    # Where the per-session MCP serving route is remembered (#985); ``None`` keeps it in memory.
    session_route_path: Path | None = None
    maintenance_gate: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)
    # Observation sweeps serialize one row at a time on this gate.  Keep it separate from the
    # installation-wide maintenance lease so a native capture can stage a content ticket while a
    # sweeper is blocked on a different row; structural calls take both in observation-then-
    # maintenance order.
    observation_gate: asyncio.Lock = field(default_factory=asyncio.Lock, repr=False)

    def __repr__(self) -> str:
        return "ServiceComposition(<redacted>)"


class ServiceDaemon:
    """Own lifecycle, listeners, dispatch admission, and bounded teardown."""

    def __init__(self, *, _composition: ServiceComposition) -> None:
        if type(_composition) is not ServiceComposition:
            raise TypeError("service_composition_invalid")
        self._composition = _composition
        relay = _composition.ready_activation_relay
        if relay is not None:
            relay.bind(self.activate_ready_application)
        close_relay = _composition.ready_close_relay
        if close_relay is not None:
            close_relay.bind(self._close_ready_locked)
        self._application = _composition.application
        privacy_relay = _composition.privacy_policy_app_relay
        if privacy_relay is not None:
            privacy_relay.bind(
                lambda: (
                    getattr(self._application, "privacy", None)
                    if self._application is not None
                    else None
                )
            )
        self._started = False
        self._closed = False
        self._stopping = False
        self._state_reason = "none"
        # The serving route each session's MCP bridge last named on a status or check (#985).
        self._session_routes = SessionRouteMemory(_composition.session_route_path)
        # Composition is frozen; keep the live auto-unlock reason on the daemon so soft-lock
        # re-ready can update it without replacing the composition object.
        self._auto_unlock_reason = _composition.auto_unlock_reason
        self._monitor_state = "unavailable"
        self._soft_reready_activation_failures = 0
        self._stop_event = asyncio.Event()
        # ``serve`` owns the accept loops; a daemon driven by ``start`` alone never serves and
        # must never wait on an event nothing will set.
        self._serving = False
        self._accept_armed = asyncio.Event()
        self._start_lock = asyncio.Lock()
        self._activation_lock = asyncio.Lock()
        self._close_lock = asyncio.Lock()
        self._connection_tasks: set[asyncio.Task[None]] = set()
        self._check_waits = CheckWaits()
        self._check_read_window = CheckReadWindow()
        # A transient status projection is one logical incident even when a host polls several
        # times before it recovers. This process-local map contains only bounded structural state;
        # the task/session binding remains authoritative in the ledger and is never rotated here.
        self._read_projection_incidents: dict[
            tuple[str, str, str, str, str], _ReadProjectionIncident
        ] = {}
        # Set when a check was refused behind an outstanding native capture handoff. The check
        # held both dispatch gates, so the handoff's structural delivery could not run; waking the
        # sweeper drains it as soon as those gates are free instead of an idle interval later.
        self._observation_sweep_wake = asyncio.Event()
        # Set by each hook observation ingest; the sweeper coalesces a burst into one early pass.
        self._observation_ingest_wake = asyncio.Event()
        self._ready_maintenance_task: asyncio.Task[None] | None = None

    @property
    def composition(self) -> ServiceComposition:
        return self._composition

    @property
    def started(self) -> bool:
        """True once ``start`` published the endpoints; a later failure is not a startup one."""

        return self._started

    async def start(self) -> None:
        """Acquire singleton authority and publish exactly one admitted state."""

        async with self._start_lock:
            if self._started:
                return
            if self._closed:
                raise LifecycleError("invalid_transition")
            lifecycle = self._composition.lifecycle
            await lifecycle.acquire_singleton()
            try:
                monitor = self._composition.session_monitor
                if monitor is not None:
                    try:
                        await monitor.start(self._on_session_event)
                    except Exception:
                        self._monitor_state = "unavailable"
                    else:
                        self._monitor_state = (
                            "active" if monitor.capability.active else "unavailable"
                        )

                if (
                    self._composition.vault.ready
                    and self._application is None
                    and self._composition.ready_application_factory is not None
                ):
                    await lifecycle.transition(ServiceState.LOCKED)
                    await lifecycle.transition(ServiceState.UNLOCKING)
                    await self.activate_ready_application(
                        lifecycle.instance.generation,
                        self._composition.vault.generation,
                    )

                ready_maintenance_wanted = False
                if self._application is not None and self._composition.vault.ready:
                    if lifecycle.state is not ServiceState.READY:
                        await lifecycle.transition(
                            ServiceState.READY,
                            vault_generation=self._composition.vault.generation,
                        )
                    ready_maintenance_wanted = self._ready_maintenance_task is None
                    self._state_reason = "none"
                else:
                    await lifecycle.transition(ServiceState.LOCKED)
                    self._state_reason = self._locked_reason()
                # Publish last: a socket that exists is a socket that can answer a handshake.
                # The control endpoint is listening from the instant it is bound, so publishing
                # before ready activation let a client connect and then wait out its own
                # handshake deadline against a daemon that had not reached its accept loop.
                # Until this line a connect is refused, which the on-demand connector reads as
                # "still starting" and keeps polling (#235).
                await lifecycle.publish_endpoint()
                if ready_maintenance_wanted and self._application is not None:
                    # Only a composition that supplies its own ready application reaches this:
                    # the cold-start path activated one above, and activation starts maintenance
                    # itself. Placement relative to publish_endpoint decides nothing -- the
                    # _accept_armed gate inside _run_ready_maintenance is the sole thing keeping
                    # the first sweep behind serve()'s accept loops (#235).
                    self._start_ready_maintenance(
                        self._application,
                        lifecycle.instance.generation,
                        self._composition.vault.generation,
                    )
                self._started = True
            except BaseException:
                if lifecycle.state is ServiceState.STARTING:
                    await lifecycle.transition(ServiceState.FAILED)
                await self.close()
                raise

    async def activate_ready_application(
        self, service_generation: int, vault_generation: int
    ) -> None:
        """Construct and publish one generation-bound ready application."""

        async with self._activation_lock:
            await self._activate_ready_application_locked(service_generation, vault_generation)

    async def _activate_ready_application_locked(
        self, service_generation: int, vault_generation: int
    ) -> None:
        """Install ready composition while the caller already holds ``_activation_lock``."""

        partial: _ReadyApplication | None = None
        lifecycle = self._composition.lifecycle
        try:
            if (
                type(service_generation) is not int
                or type(vault_generation) is not int
                or service_generation <= 0
                or vault_generation <= 0
                or lifecycle.state is not ServiceState.UNLOCKING
                or lifecycle.instance.generation != service_generation
                or not self._composition.vault.ready
                or self._composition.vault.generation != vault_generation
                or self._application is not None
            ):
                raise LifecycleError("invalid_transition")
            factory = self._composition.ready_application_factory
            if factory is None:
                raise LifecycleError("invalid_transition")
            partial = await factory(service_generation, vault_generation)
            if not _is_ready_application(partial):
                raise TypeError("ready_application_invalid")
            if (
                lifecycle.state is not ServiceState.UNLOCKING
                or lifecycle.instance.generation != service_generation
                or not self._composition.vault.ready
                or self._composition.vault.generation != vault_generation
            ):
                raise LifecycleError("invalid_transition")
            if getattr(self._composition.vault, "recovery_pending", False) is True:
                verify_recovery = getattr(partial, "verify_recovery_candidate", None)
                if not callable(verify_recovery):
                    raise RuntimeError("installation_recovery_verifier_unavailable")
                observed_verification = await cast(
                    Callable[[], Awaitable[object]], verify_recovery
                )()
                if (
                    type(observed_verification) is not tuple
                    or len(cast(tuple[object, ...], observed_verification)) != 3
                    or any(
                        type(value) is not int or value < 0
                        for value in cast(tuple[object, ...], observed_verification)
                    )
                ):
                    raise RuntimeError("installation_recovery_verifier_invalid")
            commit_recovery = getattr(self._composition.vault, "commit_recovery_marker", None)
            if callable(commit_recovery):
                commit_recovery()
            self._application = partial
            await lifecycle.transition(
                ServiceState.READY,
                vault_generation=vault_generation,
            )
            self._start_ready_maintenance(partial, service_generation, vault_generation)
            self._state_reason = "none"
            self._auto_unlock_reason = "none"
            self._soft_reready_activation_failures = 0
        except BaseException:
            if self._application is partial:
                self._application = None
            if partial is not None:
                try:
                    await partial.close()
                except Exception:
                    pass
            try:
                await self._composition.vault.lock()
            except Exception:
                pass
            if lifecycle.state is ServiceState.UNLOCKING:
                try:
                    await lifecycle.transition(ServiceState.LOCKED)
                except Exception:
                    pass
            self._state_reason = "unlock_failed"
            raise

    async def serve(self) -> None:
        """Serve authenticated ordinary and human-control clients in foreground."""

        self._serving = True
        await self.start()
        self._install_signal_handlers()
        idle = asyncio.create_task(self._composition.lifecycle.run_idle_monitor())
        control = asyncio.create_task(
            self._accept_loop(
                self._composition.control_listener,
                self._serve_control_connection,
                arms_control_plane=True,
            )
        )
        human: asyncio.Task[None] | None = None
        if (
            self._composition.human_control_listener is not None
            and self._composition.human_connection_handler is not None
        ):
            human = asyncio.create_task(
                self._accept_loop(
                    self._composition.human_control_listener,
                    self._composition.human_connection_handler,
                )
            )
        watchdog = ControlPlaneWatchdog(connections_in_flight=lambda: len(self._connection_tasks))
        watchdog.start_thread()
        heartbeat = asyncio.create_task(watchdog.run())
        stop_wait = asyncio.create_task(self._stop_event.wait())
        stop_reason = "shutdown_requested"
        try:
            done, _pending = await asyncio.wait(
                {idle, stop_wait}, return_when=asyncio.FIRST_COMPLETED
            )
            if idle in done:
                await idle
                stop_reason = "idle_shutdown"
        finally:
            try:
                await self.stop(stop_reason)
            finally:
                watchdog.close()
                for task in (idle, control, human, stop_wait, heartbeat):
                    if task is not None:
                        task.cancel()
                for task in (idle, control, human, stop_wait, heartbeat):
                    if task is not None:
                        await asyncio.gather(task, return_exceptions=True)

    async def dispatch(
        self,
        client_kind: ControlClientKind,
        request: ControlCallRequest,
        *,
        projection_context: ClientProjectionContext | None = None,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
        _defer_stop: bool = False,
    ) -> ControlResult:
        """Validate, admit, execute, project, and correlate one ordinary call."""

        try:
            try:
                if type(client_kind) is not ControlClientKind:
                    raise ControlError("method_forbidden")
                if projection_context is None:
                    projection_context = ClientProjectionContext.fail_safe(client_kind)
                elif (
                    type(projection_context) is not ClientProjectionContext
                    or projection_context.client_kind is not client_kind
                ):
                    raise ControlError("frame_invalid")
                if (
                    repository_privacy_context is not None
                    and type(repository_privacy_context) is not RepositoryPrivacyContext
                ):
                    raise ControlError("frame_invalid")
                validate_request(request)
                self._validate_generation(request)
                self._validate_client_method(client_kind, request.method)
            except ControlProtocolError, TypeError, ValueError:
                # Only the validation prefix maps to frame_invalid. Runtime TypeError/ValueError
                # from method dispatch must reach the correlated internal_error branch below.
                return self._error_result(request, ControlError("frame_invalid"))
            if request.method is ControlMethod.SERVICE_STATUS:
                body: object = self.status()
            elif request.method is ControlMethod.SERVICE_LOCK:
                await self.lock("explicit_lock")
                body = self.status()
            elif request.method is ControlMethod.SERVICE_STOP:
                body = ServiceStopResult()
            else:
                body = await self._dispatch_ready(
                    projection_context, request, repository_privacy_context
                )
            result = self._result(request, body)
            if request.method is ControlMethod.SERVICE_STOP and not _defer_stop:
                await self.stop()
            return result
        except asyncio.CancelledError:
            return self._error_result(request, ControlError("request_cancelled", retryable=True))
        except ControlError as exc:
            return self._error_result(request, exc)
        except LifecycleError as exc:
            reason = "service_draining" if exc.reason == "service_draining" else "vault_locked"
            return self._error_result(request, ControlError(reason, retryable=True))
        except PublicOperationError as exc:
            return self._public_operation_failure_result(request, exc)
        except Exception as exc:
            # Unexpected failure outside the post-commit projection window. A read never committed
            # anything, so the remedy is repeating the request with a fresh request_id — the same
            # classification used when projection itself fails for STATUS. Surfacing non-retryable
            # internal_error for a pure status/privacy read is what stranded run-4's
            # status view=operation recovery (AttributeError → retryable: false).
            if _request_is_read_only(request):
                return self._error_result(
                    request,
                    self._read_projection_failure(request, exc, phase="unknown"),
                )
            request_id = _safe_body_request_id(request)
            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="service.daemon",
                operation=f"{request.method.value}_internal_error",
                request_id=request_id,
            )
            return self._error_result(
                request, ControlError("internal_error", correlation_id=correlation_id)
            )

    async def lock(self, reason: str = "explicit_lock") -> None:
        """Drain the ready generation, close it, and remain structurally available."""

        if not self._started or self._closed:
            return
        lifecycle = self._composition.lifecycle
        async with self._activation_lock:
            if lifecycle.state is ServiceState.READY:
                await lifecycle.request_lock(reason)
            elif lifecycle.state is ServiceState.UNLOCKING:
                await self._composition.vault.lock()
                await lifecycle.transition(ServiceState.LOCKED)
            await self._close_ready_locked()
            self._state_reason = (
                reason
                if reason in _SOFT_LOCK_AUTO_READY_REASONS or reason == "explicit_lock"
                else "explicit_lock"
            )

    async def stop(self, reason: str = "shutdown_requested") -> None:
        """Drain, unlink owned endpoints, release singleton authority, and stop serving."""

        async with self._close_lock:
            if self._closed:
                self._stop_event.set()
                return
            self._stopping = True
            await self._check_waits.close()
            self._state_reason = reason if reason == "internal_error" else "shutdown_requested"
            lifecycle = self._composition.lifecycle
            if self._started:
                async with self._activation_lock:
                    if lifecycle.state is ServiceState.UNLOCKING:
                        await self._composition.vault.lock()
                        await lifecycle.transition(ServiceState.LOCKED)
                    if lifecycle.state is not ServiceState.DRAINING:
                        try:
                            await lifecycle.request_stop(reason)
                        except LifecycleError as exc:
                            if exc.reason != "invalid_transition":
                                raise
            await self._close_components()
            await lifecycle.close()
            self._closed = True
            self._stop_event.set()

    async def close(self) -> None:
        """Idempotent alias for bounded service shutdown."""

        await self.stop()

    def status(self) -> ServiceStatus:
        lifecycle = self._composition.lifecycle
        instance = lifecycle.instance
        vault_mode = getattr(self._composition.vault.mode, "value", self._composition.vault.mode)
        if vault_mode not in {"uninitialized", "os_keyring", "passphrase"}:
            vault_mode = "uninitialized"
        capabilities = {"confidential_ingress"}
        if lifecycle.state is ServiceState.READY and self._application is not None:
            capabilities.update({"workflow", "maintenance", "import_review"})
            # Exactly the *configured* provider's credential, not "some provider is connected":
            # operator readiness surfaces read this capability and must not over-report.
            if getattr(self._application, "provider_credential_connected", False) is True:
                capabilities.add("external_provider")
            # The declared fallback endpoint's credential, reported separately so `provider
            # status` can show each endpoint's readiness without conflating the two (#582).
            if getattr(self._application, "fallback_credential_connected", False) is True:
                capabilities.add("fallback_provider")
        if self._monitor_state == "active":
            capabilities.add("session_event_monitor")
        return ServiceStatus(
            protocol_version="1.0",
            service_version=__version__,
            service_instance_id=instance.instance_id,
            service_generation=str(instance.generation),
            state=lifecycle.state,
            state_reason=self._state_reason,
            vault_mode=cast(str, vault_mode),
            capabilities=tuple(sorted(capabilities, key=lambda value: value.encode("ascii"))),
            session_monitor=self._monitor_state,
            idle_relock_seconds=lifecycle.idle_relock_policy.seconds,
        )

    async def _dispatch_ready(
        self,
        projection_context: ClientProjectionContext,
        request: ControlCallRequest,
        repository_privacy_context: RepositoryPrivacyContext | None,
    ) -> object:
        body = request.body
        if request.method is ControlMethod.OBSERVATION_INGEST:
            # Set before dispatch: a busy hook ingest can time out client-side, and the rows it
            # could not drain are exactly the ones the sweep should pick up promptly.
            self._observation_ingest_wake.set()
        awaits_observations = (
            request.method is ControlMethod.CHECK
            and type(body) is CheckRequest
            and body.await_observations is True
        )
        try:
            if (
                request.method is ControlMethod.CHECK
                and type(body) is CheckRequest
                and body.mode not in {"deterministic_only", "inspect"}
            ):
                check_body = body

                async def detached() -> object:
                    # The wait runs inside the detached operation, before either dispatch gate
                    # is taken, so the sweeper can deliver rows while this check waits.
                    awaited = (
                        await self._await_check_observations(check_body, request.deadline_ms)
                        if awaits_observations
                        else None
                    )
                    return await self._dispatch_ready_once(
                        projection_context,
                        request,
                        repository_privacy_context,
                        detached_check=True,
                        observations_awaited=awaited,
                    )

                # The pre-check wait is outside the operation identity, as in the ledger digest.
                identity = body.model_dump(mode="json", exclude={"await_observations"})
                return await self._check_waits.run(
                    (body.writer_id, body.request_id),
                    hashlib.sha256(canonical_encode(identity)).hexdigest(),
                    detached,
                    request.deadline_ms,
                )
            awaited = (
                await self._await_check_observations(cast(CheckRequest, body), request.deadline_ms)
                if awaits_observations
                else None
            )
            return await self._dispatch_ready_once(
                projection_context,
                request,
                repository_privacy_context,
                observations_awaited=awaited,
            )
        except PublicOperationError as exc:
            if (
                request.method is ControlMethod.CHECK
                and check_admission_stage(exc) is CheckAdmissionStage.CAPTURE_HANDOFF_PENDING
            ):
                # Both dispatch gates were released on the way out, so the next sweep can
                # deliver the handoff before the caller's exact replay (issue #838).
                self._observation_sweep_wake.set()
            raise

    async def _await_check_observations(
        self, body: CheckRequest, deadline_ms: int | None
    ) -> CheckObservationsAwaited:
        """Run the optional bounded wait for this task's pending hook rows (issue #1012).

        Runs before the dispatch gates: the sweeper takes the observation gate per row, so a
        wait under the gates could only ever time out. Never raises for the wait itself.
        """

        application = self._application
        sweep = None if application is None else getattr(application, "observation_sweep", None)
        probe = getattr(sweep, "task_pending_probe", None)
        return await await_task_observations(
            cast(TaskPendingProbe, probe) if callable(probe) else None,
            body.session_id,
            wake=self._observation_sweep_wake.set,
            bound_seconds=await_observations_bound(deadline_ms),
        )

    async def _dispatch_ready_once(
        self,
        projection_context: ClientProjectionContext,
        request: ControlCallRequest,
        repository_privacy_context: RepositoryPrivacyContext | None,
        *,
        detached_check: bool = False,
        observations_awaited: CheckObservationsAwaited | None = None,
    ) -> object:
        # A recovery ceremony holds this same lock across an unbounded human wait, so an
        # unbounded acquire would hang every ordinary call for as long as someone stares at a
        # confirmation prompt. The caller's own deadline decides how long it is willing to wait.
        maintenance_gate = self._composition.maintenance_gate
        if _is_operation_status_read(request) and self._check_read_window.admits_readers:
            # A detached check owns both gates and cannot release them until this read drains,
            # so no maintenance or sweep can interleave (issue #571 A2 live progress).
            self._check_read_window.enter()
            try:
                return await self._dispatch_ready_under_maintenance_gate(
                    projection_context, request, repository_privacy_context
                )
            finally:
                self._check_read_window.leave()
        # Real compositions always provide a distinct observation gate. The optional lookup
        # keeps the narrow gate unit tests' intentionally minimal composition doubles valid.
        observation_gate = getattr(self._composition, "observation_gate", None)
        capture_only = _is_valid_capture_only_observation(request)
        observation_acquired = False
        maintenance_acquired = False
        window_opened = False
        if not capture_only and isinstance(observation_gate, asyncio.Lock):
            # Do not let a structural waiter hold maintenance while a sweeper owns the row gate:
            # a following native capture must still be able to stage its ticket.
            await _acquire_dispatch_gate(observation_gate, request.deadline_ms)
            observation_acquired = True
        try:
            await _acquire_dispatch_gate(maintenance_gate, request.deadline_ms)
            maintenance_acquired = True
            if detached_check and observation_acquired:
                self._check_read_window.open()
                window_opened = True
            # Native capture-only handoffs have already been fully parsed and authenticated by the
            # control protocol and only stage a ticket/content blob. They may proceed while a
            # sweeper owns the per-row gate. Every other ordinary call takes both gates in the
            # same observation-then-maintenance order as recovery and maintenance holders.
            return await self._dispatch_ready_under_maintenance_gate(
                projection_context,
                request,
                repository_privacy_context,
                detached_check=detached_check,
                observations_awaited=observations_awaited,
            )
        finally:
            try:
                if window_opened:
                    await self._check_read_window.close()
            finally:
                if maintenance_acquired:
                    maintenance_gate.release()
                if observation_acquired and isinstance(observation_gate, asyncio.Lock):
                    observation_gate.release()

    def _read_projection_failure(
        self,
        request: ControlCallRequest,
        exc: BaseException,
        *,
        phase: str,
        reason: str = "read_projection_failed",
    ) -> ControlError:
        """Classify one read failure and join repeated polls to one bounded incident."""

        request_id = _safe_body_request_id(request)
        key = _read_projection_incident_key(request)
        incident = None if key is None else self._read_projection_incidents.get(key)
        if incident is None:
            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="service.daemon",
                operation=f"{request.method.value}_{reason}",
                request_id=request_id,
                phase=phase,
            )
            if key is not None:
                if len(self._read_projection_incidents) >= 64:
                    oldest_key = min(
                        self._read_projection_incidents,
                        key=lambda candidate: self._read_projection_incidents[candidate].started_at,
                    )
                    self._read_projection_incidents.pop(oldest_key, None)
                incident = _ReadProjectionIncident(time.monotonic(), 1, phase, correlation_id)
                self._read_projection_incidents[key] = incident
        else:
            incident.attempts += 1
            correlation_id = incident.correlation_id
            phase = incident.phase
        return ControlError(
            reason,
            retryable=True,
            correlation_id=correlation_id,
            phase=phase,
        )

    def _read_projection_recovered(self, request: ControlCallRequest) -> None:
        """Record one recovery for a status binding after a successful fresh read."""

        key = _read_projection_incident_key(request)
        if key is None:
            return
        incident = self._read_projection_incidents.pop(key, None)
        if incident is None:
            return
        duration_ms = max(0, min(int((time.monotonic() - incident.started_at) * 1_000), 2**53 - 1))
        record_bounded_counts_without_raising(
            component="service.daemon",
            operation="status_read_projection_recovered",
            outcome="recovered",
            request_id=_safe_body_request_id(request),
            correlation_id=incident.correlation_id,
            counts={
                "duration_ms": duration_ms,
                "operation_count": incident.attempts,
                "phase": incident.phase,
            },
        )

    async def _dispatch_ready_under_maintenance_gate(
        self,
        projection_context: ClientProjectionContext,
        request: ControlCallRequest,
        repository_privacy_context: RepositoryPrivacyContext | None,
        *,
        detached_check: bool = False,
        observations_awaited: CheckObservationsAwaited | None = None,
    ) -> object:
        application = self._application
        if application is None:
            if await self._try_soft_lock_auto_ready():
                application = self._application
        if application is None:
            # Honest retryability: a soft lock -- including a transient re-ready activation
            # failure that kept its soft reason (#276) -- heals on a later attempt, while a
            # hard lock or missing setup needs a trusted ceremony no retry will perform.
            raise ControlError(
                "vault_locked",
                retryable=self._state_reason in _SOFT_LOCK_AUTO_READY_REASONS
                or self._state_reason == "none",
            )
        admission: Admission | None = None
        try:
            admission = await self._composition.lifecycle.admit(request.method.value)
            handler = getattr(application, request.method.value, None)
            if not callable(handler):
                raise ControlError("method_forbidden")
            routed = self._with_session_route(request)
            try:
                if request.deadline_ms is None or detached_check:
                    internal = await self._invoke_ready_handler(
                        handler,
                        routed,
                        repository_privacy_context,
                        observations_awaited=observations_awaited,
                    )
                else:
                    async with asyncio.timeout(request.deadline_ms / 1_000):
                        internal = await self._invoke_ready_handler(
                            handler,
                            routed,
                            repository_privacy_context,
                            observations_awaited=observations_awaited,
                        )
            except TimeoutError as exc:
                # Includes local observation-store contention inside the handler: the wire
                # vocabulary is closed, so it stays the retryable ``request_timeout`` while
                # the store's lock reporter names the contention and its holder (#689).
                if _request_is_read_only(request):
                    raise self._read_projection_failure(
                        request, exc, phase="handler", reason="request_timeout"
                    ) from exc
                raise ControlError("request_timeout", retryable=True) from exc
            except ControlError, LifecycleError, PublicOperationError:
                # Deliberate application outcomes carry their own code, retryability and
                # continuation. Only an untyped exception is a transient projection incident.
                raise
            except Exception as exc:
                if _request_is_read_only(request):
                    raise self._read_projection_failure(request, exc, phase="handler") from exc
                raise
            # Only a call the handler completed teaches the session's route (#985).
            self._remember_session_route(request)
            # The handler has returned, so a write may already be durable. Everything below only
            # shapes the response; an unexpected failure there must not be reported as a failed
            # operation.
            projected = await self._project_completed_response(
                projection_context,
                request,
                application,
                internal,
                repository_privacy_context,
            )
            if _request_is_read_only(request):
                self._read_projection_recovered(request)
            return projected
        finally:
            if admission is not None:
                await self._composition.lifecycle.release(admission)

    def _with_session_route(self, request: ControlCallRequest) -> ControlCallRequest:
        """Give a route-less ``status`` the route the session's own MCP bridge serves (#985).

        The MCP bridge names its serving route (``policy`` or ``strict``) on every ``status`` and
        ``check``; the Stop-hook closure gate and the CLI carry none, so they used to read the
        policy route and could list ``semantic_review_not_requested`` as work the agent's strict
        view never shows. ``SessionRouteMemory`` keeps the route the session's last successful
        route-carrying call named (owner-only file in the service state directory, so it
        survives a restart; last writer wins when two bridges serve one session), and a later
        route-less ``status`` for the same session reads on it. A route-less ``check`` is never
        changed: the route still decides what a check may dispatch. With nothing remembered the
        read keeps the policy route.
        """

        if request.method is not ControlMethod.STATUS or request.route_profile is not None:
            return request
        session_id = getattr(request.body, "session_id", None)
        if type(session_id) is not str:
            return request
        remembered = self._session_routes.get(session_id)
        if remembered is None:
            return request
        return replace(request, route_profile=remembered)

    def _remember_session_route(self, request: ControlCallRequest) -> None:
        if request.route_profile is None or request.method not in {
            ControlMethod.CHECK,
            ControlMethod.STATUS,
        }:
            return
        session_id = getattr(request.body, "session_id", None)
        if type(session_id) is str:
            self._session_routes.remember(session_id, request.route_profile)

    @staticmethod
    async def _invoke_ready_handler(
        handler: object,
        request: ControlCallRequest,
        repository_privacy_context: RepositoryPrivacyContext | None = None,
        *,
        observations_awaited: CheckObservationsAwaited | None = None,
    ) -> object:
        operation = cast(Callable[..., Awaitable[object]], handler)
        kwargs: dict[str, object] = {}
        if request.method in {ControlMethod.CHECK, ControlMethod.STATUS}:
            if request.route_profile is not None:
                kwargs["route_profile"] = request.route_profile
        if request.method is ControlMethod.CHECK and request.host_profile is not None:
            kwargs["host_profile"] = request.host_profile
        if request.method is ControlMethod.CHECK and observations_awaited is not None:
            # Only a request that set ``await_observations`` passes this (issue #1012).
            kwargs["observations_awaited"] = observations_awaited
        if request.method in {
            ControlMethod.START,
            ControlMethod.PUBLISH_WORK,
            ControlMethod.CHECK,
            ControlMethod.RESPOND,
            ControlMethod.STATUS,
            ControlMethod.RECEIPT,
            ControlMethod.IMPORT_CODEX_JSONL,
            ControlMethod.PRIVACY_GET_SETUP,
            ControlMethod.PRIVACY_GET_EFFECTIVE,
            ControlMethod.PRIVACY_PROPOSE_POLICY,
            ControlMethod.PROJECT,
        }:
            kwargs["repository_privacy_context"] = repository_privacy_context
        return await operation(request.body, **kwargs)

    async def _project_completed_response(
        self,
        projection_context: ClientProjectionContext,
        request: ControlCallRequest,
        application: _ReadyApplication,
        internal: object,
        repository_privacy_context: RepositoryPrivacyContext | None,
    ) -> object:
        """Shape one already-completed operation, never collapsing a commit into a plain failure.

        Bounded failures raised deliberately here (``ControlError`` such as
        ``privacy_projection_blocked``, ``LifecycleError``, ``PublicOperationError``) already carry
        an accurate caller-safe meaning and pass through untouched. Only an unexpected exception is
        reclassified, and the reclassification depends on what the method could have changed:

        - a committed ``publish_work`` returns the reduced total-acceptance envelope
          (``response_completeness: accepted_projection_unavailable``) so a durable write is never
          reported as a failure;
        - other writes become ``response_projection_failed`` with same-``request_id`` replay;
        - a read changed nothing, so it becomes ``read_projection_failed`` and the caller is told
          to repeat the request. Advertising same-``request_id`` replay for a read is false: no
          operation record exists to replay against, and the caller waits on a recovery that
          cannot arrive.
        """

        try:
            # Project lifecycle writes remain the structural CLI contract. Project status is the
            # one project operation that delegates to the canonical status projection below.
            if request.method is ControlMethod.PROJECT:
                source = internal_control_json(cast(UnprojectedControlBody, internal))
                if source.get("view") != "project":
                    self._validate_success_body(request, internal)
                    return internal
            if request.method in _PROJECTION_EXEMPT_METHODS:
                self._validate_success_body(request, internal)
                return internal
            # Application-layer fallback already produced the reduced acceptance envelope.
            # Dry-run previews are already public and non-evidential — never project or store them.
            if type(internal) is PublishWorkResultModel and type(internal.root) in (
                PublishWorkAcceptedProjectionUnavailableModel,
                PublishWorkDryRunModel,
            ):
                self._validate_success_body(request, internal)
                return internal
            facts = await application.projection_binding_facts(
                request.method,
                request.body,
                internal,
            )
            publish_replay = (
                (internal, resolve_client_disclosure_sink(projection_context))
                if type(internal) is PublishWorkInternalResult
                else None
            )
            if publish_replay is not None:
                publish_result, publish_sink = publish_replay
                stored = await application.load_publish_response(publish_result, publish_sink)
                if stored is not None:
                    self._validate_success_body(request, stored)
                    return stored
            binding = ControlProjectionBinding(
                rpc_id=request.rpc_id,
                method=request.method,
                service_instance_id=request.service_instance_id,
                service_generation=int(request.service_generation),
                original_request_id=facts.original_request_id,
                route_identity_digest=facts.route_identity_digest,
                control_request_canonical=encode_control_frame(request)[4:],
                repository_privacy_commitment=(
                    None
                    if repository_privacy_context is None
                    else repository_privacy_context.commitment
                ),
            )
            projected = await application.project_result_for_client(
                projection_context,
                binding,
                internal,
            )
            self._validate_success_body(request, projected)
            if publish_replay is not None:
                publish_result, publish_sink = publish_replay
                try:
                    persisted = await application.store_publish_response(
                        publish_result,
                        publish_sink,
                        projected,
                    )
                except PublicOperationError as exc:
                    record_unexpected_exception_without_raising(
                        exc,
                        component="service.daemon",
                        operation=f"{request.method.value}_publish_response_store_failed",
                        request_id=_safe_body_request_id(request),
                    )
                    return projected
                self._validate_success_body(request, persisted)
                return persisted
            return projected
        except ControlError, LifecycleError, PublicOperationError:
            raise
        except (asyncio.CancelledError, Exception) as exc:
            # Cancellation is reclassified here too. `dispatch` already converts a cancelled call
            # into a result rather than propagating, and past this point the operation may be
            # durable — reporting CANCELLED would say the work did not happen and would omit the
            # recovery facts. This changes only how an already-converted cancellation is described.
            request_id = _safe_body_request_id(request)
            reason = (
                "read_projection_failed"
                if _request_is_read_only(request)
                else "response_projection_failed"
            )
            # One correlation id for the unexpected failure path: shared by the reduced publish
            # envelope (when built), the diagnostic ring, and the ControlError raised to the
            # bridge — no second mint when the agent-facing public error is shaped.
            if reason == "read_projection_failed":
                raise self._read_projection_failure(request, exc, phase="projection") from exc
            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="service.daemon",
                operation=f"{request.method.value}_{reason}",
                request_id=request_id,
                phase="projection",
            )
            if request.method is ControlMethod.PUBLISH_WORK:
                reduced = _publish_accepted_projection_unavailable(
                    internal, correlation_id=correlation_id, request_id=request_id
                )
                if reduced is not None:
                    self._validate_success_body(request, reduced)
                    return reduced
            accepted_state = _accepted_state(internal)
            raise ControlError(
                reason,
                retryable=True,
                accepted_state=accepted_state,
                correlation_id=correlation_id,
                phase="projection",
            ) from exc

    async def _accept_loop(
        self,
        listener: _Listener,
        handler: Callable[[ControlStream], Awaitable[None]],
        *,
        arms_control_plane: bool = False,
    ) -> None:
        # Arming happens here rather than at task creation because an unset-then-set event is not
        # a scheduling barrier: a maintenance task created earlier would find it already set and
        # run to completion without ever yielding to this loop.
        try:
            while not self._stop_event.is_set():
                if arms_control_plane:
                    self._accept_armed.set()
                try:
                    stream = await listener.accept()
                except asyncio.CancelledError:
                    raise
                except Exception:
                    if self._stopping or self._closed:
                        return
                    await self.stop("internal_error")
                    return
                task = asyncio.create_task(self._run_handler(handler, stream))
                self._connection_tasks.add(task)
                task.add_done_callback(self._connection_tasks.discard)
        finally:
            if arms_control_plane:
                # A loop that has stopped serving must never leave maintenance waiting on it.
                self._accept_armed.set()

    async def _run_handler(
        self, handler: Callable[[ControlStream], Awaitable[None]], stream: ControlStream
    ) -> None:
        lifecycle = self._composition.lifecycle
        connected = False
        try:
            await lifecycle.client_connected()
            connected = True
            await handler(stream)
        finally:
            if connected:
                try:
                    await lifecycle.client_disconnected()
                except LifecycleError:
                    pass

    async def _resolve_repository_context(
        self, locator: WorkspaceLocator
    ) -> RepositoryPrivacyContext | None:
        """Consume a raw locator only while an installation key is ready."""

        vault = self._composition.vault
        if not vault.ready:
            return None
        key = cast(KeyStorePort, vault).installation_mac_handle(MacKeyPurpose.CATALOG_LOOKUP)
        return await resolve_repository_privacy_context(locator, key)

    async def _serve_control_connection(self, stream: ControlStream) -> None:
        session: ControlSession | None = None
        calls: dict[str, asyncio.Task[None]] = {}
        write_lock = asyncio.Lock()
        try:
            try:
                async with asyncio.timeout(_CONTROL_HANDSHAKE_DEADLINE_SECONDS):
                    session = await server_handshake(
                        stream,
                        stream.peer_identity,
                        self.status(),
                        repository_context_resolver=self._resolve_repository_context,
                    )
            except TimeoutError:
                return
            except ControlProtocolError as exc:
                if exc.reason in {"manifest_mismatch", "protocol_mismatch"}:
                    record_public_error_without_raising(
                        component="service.daemon",
                        operation="control_handshake",
                        reason=exc.reason,
                    )
                return
            while not self._stop_event.is_set():
                try:
                    frame = await self._read_control_frame_idle_aware(stream, calls)
                except TimeoutError:
                    return
                except ControlProtocolError as exc:
                    # A peer that declared an oversized frame or stalled mid-frame is cut off
                    # here and never sees a reply; the structural reason is the only trace.
                    if exc.reason in {"frame_too_large", "frame_read_timeout"}:
                        record_public_error_without_raising(
                            component="service.daemon",
                            operation="control_frame_read",
                            reason=exc.reason,
                        )
                    return
                request = parse_control_request(frame)
                session.admit(request)
                if not isinstance(request, ControlCallRequest):
                    target = calls.get(request.target_rpc_id)
                    if target is not None:
                        target.cancel(EXPLICIT_CONTROL_CANCEL)
                    continue
                task = asyncio.create_task(self._serve_call(stream, session, request, write_lock))
                calls[request.rpc_id] = task
                task.add_done_callback(lambda _task, rpc_id=request.rpc_id: calls.pop(rpc_id, None))
        except asyncio.CancelledError:
            raise
        except Exception:
            return
        finally:
            if session is not None:
                session.close()
            for task in tuple(calls.values()):
                task.cancel()
            await asyncio.gather(*calls.values(), return_exceptions=True)
            await stream.aclose()

    async def _read_control_frame_idle_aware(
        self,
        stream: ControlStream,
        calls: dict[str, asyncio.Task[None]],
    ) -> ControlFrame:
        """Read one frame; apply inactive-session idle only when no calls are active.

        The idle deadline starts immediately when the session has no in-flight calls, and only
        after the final call completes when the session is busy. It covers the complete frame so
        dripped partial bytes cannot retain a listener slot past the bound. Active long-running
        calls are not cancelled merely because no additional frame arrives. Independently, a frame
        that has begun must finish within ``_CONTROL_FRAME_READ_DEADLINE_SECONDS`` even while calls
        are active, so a partial body is never held open-ended (``frame_read_timeout``).
        """

        read_task = asyncio.create_task(
            read_control_frame(stream, frame_deadline_seconds=_CONTROL_FRAME_READ_DEADLINE_SECONDS)
        )
        try:
            while True:
                if calls:
                    done, _pending = await asyncio.wait(
                        {read_task, *calls.values()},
                        return_when=asyncio.FIRST_COMPLETED,
                    )
                    if read_task in done:
                        return await read_task
                    # Done-callbacks that pop from ``calls`` are scheduled via call_soon and may
                    # not have run yet. Prune completed tasks now so idle can start on this turn.
                    for rpc_id, task in tuple(calls.items()):
                        if task.done():
                            calls.pop(rpc_id, None)
                    continue
                try:
                    async with asyncio.timeout(_CONTROL_INACTIVE_SESSION_DEADLINE_SECONDS):
                        return await read_task
                except TimeoutError:
                    read_task.cancel()
                    await asyncio.gather(read_task, return_exceptions=True)
                    raise
        except BaseException:
            if not read_task.done():
                read_task.cancel()
                await asyncio.gather(read_task, return_exceptions=True)
            raise

    async def _serve_call(
        self,
        stream: ControlStream,
        session: ControlSession,
        request: ControlCallRequest,
        write_lock: asyncio.Lock,
    ) -> None:
        call_started = time.monotonic()
        if session.repository_privacy_context is None:
            result = await self.dispatch(
                session.client_kind,
                request,
                projection_context=ClientProjectionContext(
                    session.client_kind,
                    session.projection_render_mode,
                    session.output_is_controlling_tty,
                ),
                _defer_stop=True,
            )
        else:
            result = await self.dispatch(
                session.client_kind,
                request,
                projection_context=ClientProjectionContext(
                    session.client_kind,
                    session.projection_render_mode,
                    session.output_is_controlling_tty,
                ),
                repository_privacy_context=session.repository_privacy_context,
                _defer_stop=True,
            )
        session.correlate(result)
        try:
            async with write_lock:
                async with asyncio.timeout(_CONTROL_RESPONSE_WRITE_DEADLINE_SECONDS):
                    await write_control_frame(stream, result)
        except (LocalControlTransportError, ControlProtocolError) as exc:
            if isinstance(exc, ControlProtocolError) and exc.reason != "transport_failed":
                # A response this service could not encode is its own defect; keep it loud.
                raise
            # The peer went away between dispatch and delivery. That is a transport fact about
            # this connection, not a malformed response, and this task is the only holder of the
            # failure: record the bounded reason and end the call so the daemon reports neither
            # `frame_invalid` nor an unretrieved task exception (issue #678). The read side sees
            # the same dead stream and finalizes the connection.
            # Bounded structural context makes an abandoned write attributable (tb4n2 NEW-8):
            # the closed wire method, the handshake client kind, the call's elapsed time and its
            # public `req_` id when it has one. Never the body, the peer or the rpc id.
            record_bounded_event_without_raising(
                component="service.daemon",
                operation="control_response_write",
                reason=exc.reason,
                request_id=_structural_request_id(request.body),
                context={
                    "control_method": request.method.value,
                    "client_kind": session.client_kind.value,
                    "duration_ms": max(0, int((time.monotonic() - call_started) * 1_000)),
                },
            )
            return
        if request.method is ControlMethod.SERVICE_STOP and result.outcome == "ok":
            # The connection owns only response delivery. If it awaits teardown here, peer EOF
            # makes the connection finalizer cancel this call while singleton release is in flight.
            # Wake the foreground owner instead so disconnect cleanup cannot interrupt shutdown.
            self._stop_event.set()

    def _result(self, request: ControlCallRequest, body: object) -> ControlResult:
        result = ControlResult(
            protocol_version="1.0",
            rpc_id=request.rpc_id,
            service_instance_id=request.service_instance_id,
            service_generation=request.service_generation,
            method=request.method,
            outcome="ok",
            body=body,  # pyright: ignore[reportArgumentType]
        )
        validate_result(result)
        return result

    def _error_result(self, request: ControlCallRequest, error: ControlError) -> ControlResult:
        result = ControlResult(
            protocol_version="1.0",
            rpc_id=request.rpc_id,
            service_instance_id=request.service_instance_id,
            service_generation=request.service_generation,
            method=request.method,
            outcome="error",
            body=error,
        )
        validate_result(result)
        return result

    def _public_operation_failure_result(
        self, request: ControlCallRequest, error: PublicOperationError
    ) -> ControlResult:
        """Frame a bound public application failure as outcome=ok with ok:false body.

        Workflow PublicOperationError values are already client-safe. They must not collapse into
        control ``internal_error``, and they never enter privacy projection (no content-bearing
        success body exists to project).
        """

        result_type = _WORKFLOW_RESULT_MODELS.get(request.method)
        if result_type is None or type(error) is not PublicOperationError:
            correlation_id = record_unexpected_exception_without_raising(
                error,
                component="service.daemon",
                operation=f"{request.method.value}_public_error_internal_error",
                request_id=_safe_body_request_id(request),
            )
            return self._error_result(
                request, ControlError("internal_error", correlation_id=correlation_id)
            )
        try:
            protocol_reason = error.safe_details.get("reason_code")
            bound = (
                error
                if error.correlation_id is not None
                else error.bind_correlation_id(
                    # Mint and record together. A workflow PublicOperationError reaches the wire
                    # without ever raising past a boundary recorder, so an id minted bare here is
                    # one the caller can never resolve (issue #191).
                    record_public_error_without_raising(
                        component="service.daemon",
                        operation=f"{request.method.value}_public_error",
                        reason=error.code.value.lower(),
                        request_id=_safe_body_request_id(request),
                        reason_code=protocol_reason if type(protocol_reason) is str else None,
                    )
                )
            )
            request_id = getattr(request.body, "request_id", None)
            candidate: dict[str, object] = {
                "protocol_version": "0.1",
                "schema_version": "1.0.0",
                "ok": False,
                "error": bound.as_public_dict(),
            }
            if type(request_id) is str:
                candidate["request_id"] = request_id
            body = result_type.model_validate(candidate)
            return self._result(request, body)
        except Exception as exc:
            correlation_id = record_unexpected_exception_without_raising(
                exc,
                component="service.daemon",
                operation=f"{request.method.value}_public_error_internal_error",
                request_id=_safe_body_request_id(request),
            )
            return self._error_result(
                request, ControlError("internal_error", correlation_id=correlation_id)
            )

    def _validate_success_body(self, request: ControlCallRequest, body: object) -> None:
        self._result(request, body)

    def _validate_generation(self, request: ControlCallRequest) -> None:
        instance = self._composition.lifecycle.instance
        if request.service_instance_id != instance.instance_id or request.service_generation != str(
            instance.generation
        ):
            raise ControlError("service_generation_changed", retryable=True)

    @staticmethod
    def _validate_client_method(client_kind: ControlClientKind, method: ControlMethod) -> None:
        if client_kind is ControlClientKind.MCP_BRIDGE and method not in _WORKFLOW_METHODS:
            raise ControlError("method_forbidden")

    async def _on_session_event(self, event: SessionSecurityEvent) -> None:
        if type(event) is not SessionSecurityEvent:
            self._monitor_state = "lost"
            await self.lock("monitor_lost")
            return
        value = event.value
        if value in {"user_session_locked", "system_suspend", "monitor_lost"}:
            if value == "monitor_lost":
                self._monitor_state = "lost"
            await self.lock(value)
            return
        await self._composition.lifecycle.on_session_event(event)

    async def _close_ready(self) -> None:
        async with self._activation_lock:
            await self._close_ready_locked()

    async def _close_ready_locked(self) -> None:
        # Lifecycle idle drain closes ready without calling ``daemon.lock``, so publish the
        # soft-lock reason here when no stronger reason was already set.
        if self._application is not None and self._state_reason == "none":
            self._state_reason = "idle_relock"
        application, self._application = self._application, None
        await self._cancel_ready_maintenance()
        if application is not None:
            await application.close()
        if self._composition.vault.ready:
            await self._composition.vault.lock()

    def _start_ready_maintenance(
        self,
        application: _ReadyApplication,
        service_generation: int,
        vault_generation: int,
    ) -> None:
        """Start one nonblocking maintenance loop owned by this READY generation."""

        if self._ready_maintenance_task is not None:
            raise RuntimeError("ready_maintenance_already_started")
        recommendation_refresh = cast(
            Callable[[], Awaitable[object]] | None,
            getattr(application, "ready_recommendation_refresh", None),
        )
        observation_sweep = cast(
            Callable[[], Awaitable[ObservationDrainSummary]] | None,
            getattr(application, "observation_sweep", None),
        )
        coordination_sweep = cast(
            Callable[[], Awaitable[object]] | None,
            getattr(application, "coordination_sweep", None),
        )
        lineage_recovery = cast(
            Callable[[], Awaitable[object]] | None,
            getattr(application, "recover_lineage", None),
        )
        if (
            not callable(recommendation_refresh)
            and not callable(observation_sweep)
            and not callable(coordination_sweep)
            and not callable(lineage_recovery)
        ):
            return
        self._ready_maintenance_task = asyncio.create_task(
            self._run_ready_maintenance(
                application,
                service_generation,
                vault_generation,
                recommendation_refresh if callable(recommendation_refresh) else None,
                observation_sweep if callable(observation_sweep) else None,
                coordination_sweep if callable(coordination_sweep) else None,
                lineage_recovery if callable(lineage_recovery) else None,
            )
        )

    async def _run_ready_maintenance(
        self,
        application: _ReadyApplication,
        service_generation: int,
        vault_generation: int,
        recommendation_refresh: Callable[[], Awaitable[object]] | None,
        observation_sweep: Callable[[], Awaitable[ObservationDrainSummary]] | None,
        coordination_sweep: Callable[[], Awaitable[object]] | None,
        lineage_recovery: Callable[[], Awaitable[object]] | None,
    ) -> None:
        """Run bounded maintenance only while the exact generation remains published."""

        try:
            if self._serving:
                # Tasks run FIFO and this one is created inside start(), before serve() creates
                # the accept loops. Without this gate the first sweep can run to completion
                # before _accept_loop ever reaches sock_accept, which is the server half of the
                # cold-start window (#235/#238).
                await self._accept_armed.wait()
            summary: ObservationDrainSummary | None = None
            if lineage_recovery is not None:
                # Recovery owns the first maintenance turn.  In particular, an append that
                # reached the ledger immediately before a daemon crash is mirrored into the
                # catalog before a lease sweep can classify its session as lost.
                await self._bounded_lineage_recovery(lineage_recovery)
            if observation_sweep is not None:
                summary = await self._bounded_observation_sweep(observation_sweep)
                await self._note_sweep_liveness(summary)
            next_recommendation_refresh = 0.0
            next_recovery = asyncio.get_running_loop().time() + _OBSERVATION_SWEEP_INTERVAL_SECONDS
            probe = getattr(observation_sweep, "backlog_probe", None)
            backlog_probe = cast(Callable[[], bool], probe) if callable(probe) else None
            while self._ready_generation_is_current(
                application, service_generation, vault_generation
            ):
                if recommendation_refresh is not None and (
                    asyncio.get_running_loop().time() >= next_recommendation_refresh
                ):
                    await self._refresh_ready_recommendations(recommendation_refresh)
                    next_recommendation_refresh = (
                        asyncio.get_running_loop().time()
                        + _READY_RECOMMENDATION_REFRESH_INTERVAL_SECONDS
                    )
                if observation_sweep is None:
                    await asyncio.sleep(_OBSERVATION_SWEEP_INTERVAL_SECONDS)
                else:
                    # Drain until dry: re-sweep immediately only while a pass actually resolved
                    # rows. Progress is the sole licence to skip the interval — a full-limit pass
                    # that resolved nothing would otherwise spin this loop with no delay at all.
                    resolved = 0 if summary is None else summary.acknowledged + summary.quarantined
                    await self._await_observation_sweep_turn(
                        _OBSERVATION_SWEEP_INTERVAL_SECONDS
                        if resolved == 0
                        else _OBSERVATION_SWEEP_PROGRESS_DELAY_SECONDS,
                        backlog_probe,
                    )
                if observation_sweep is not None:
                    summary = await self._bounded_observation_sweep(observation_sweep)
                    await self._note_sweep_liveness(summary)
                now = asyncio.get_running_loop().time()
                if lineage_recovery is not None and now >= next_recovery:
                    # Queued host events are contact evidence. Recovery judges lease expiry and
                    # abandonment only after this turn delivered them; while passes are still
                    # resolving a backlog, the next immediate pass may carry newer evidence, so
                    # wait for it, but never more than one extra interval (#837).
                    resolved = 0 if summary is None else summary.acknowledged + summary.quarantined
                    if resolved == 0 or now >= next_recovery + _OBSERVATION_SWEEP_INTERVAL_SECONDS:
                        await self._bounded_lineage_recovery(lineage_recovery)
                        next_recovery = (
                            asyncio.get_running_loop().time() + _OBSERVATION_SWEEP_INTERVAL_SECONDS
                        )
                if coordination_sweep is not None:
                    await self._bounded_coordination_sweep(coordination_sweep)
        except asyncio.CancelledError:
            raise

    async def _await_observation_sweep_turn(
        self, delay: float, backlog_probe: Callable[[], bool] | None = None
    ) -> None:
        """Wait for the next sweep: the idle or progress delay, or an earlier wake.

        A wake only moves the next bounded pass forward; it never adds a pass or skips the gates
        the sweep takes per row. While idle, ``backlog_probe`` is polled off the loop every
        ``_OBSERVATION_SWEEP_BACKLOG_POLL_SECONDS``: a hook that deferred its structural row
        without contacting the service leaves no wake, so an undelivered row ends the idle wait
        instead of waiting out the full interval (#887).
        """

        wake = self._observation_sweep_wake
        ingest = self._observation_ingest_wake
        loop = asyncio.get_running_loop()
        idle_until = loop.time() + delay
        while not wake.is_set() and not ingest.is_set():
            # Always await at least once, even for a zero progress delay, so consecutive passes
            # yield the loop instead of spinning it.
            remaining = max(0.0, idle_until - loop.time())
            poll = (
                min(remaining, _OBSERVATION_SWEEP_BACKLOG_POLL_SECONDS)
                if backlog_probe is not None
                else remaining
            )
            waiters = {
                asyncio.ensure_future(wake.wait()),
                asyncio.ensure_future(ingest.wait()),
            }
            try:
                done, _pending = await asyncio.wait(
                    waiters, timeout=poll, return_when=asyncio.FIRST_COMPLETED
                )
            finally:
                for waiter in waiters:
                    waiter.cancel()
            if done:
                break
            if wake.is_set() or ingest.is_set():
                # A wake can be set after the wait times out but before this task resumes.
                # Leave it armed so that boundary wake is observed by the next turn.
                return
            if backlog_probe is None or idle_until - loop.time() <= 0.0:
                return
            if await self._observation_backlog_pending(backlog_probe):
                return
        if (
            not wake.is_set()
            and ingest.is_set()
            and delay > _OBSERVATION_SWEEP_INGEST_COALESCE_SECONDS
        ):
            # Coalesce a burst of hook ingests into one early pass; a targeted wake still
            # cuts the coalescing short.
            try:
                await asyncio.wait_for(
                    wake.wait(), timeout=_OBSERVATION_SWEEP_INGEST_COALESCE_SECONDS
                )
            except TimeoutError:
                pass
        ingest.clear()
        wake.clear()

    @staticmethod
    async def _observation_backlog_pending(backlog_probe: Callable[[], bool]) -> bool:
        """Run the read-only backlog probe off the loop; any failure means keep waiting."""

        try:
            async with asyncio.timeout(_OBSERVATION_SWEEP_BACKLOG_POLL_SECONDS):
                return (await asyncio.to_thread(backlog_probe)) is True
        except asyncio.CancelledError:
            raise
        except Exception:
            return False

    async def _refresh_ready_recommendations(
        self, recommendation_refresh: Callable[[], Awaitable[object]]
    ) -> None:
        try:
            # Include both gate waits in the budget: holding observation while maintenance
            # is contended must not strand structural requests beyond the refresh deadline.
            async with asyncio.timeout(_READY_RECOMMENDATION_REFRESH_DEADLINE_SECONDS):
                observation_gate = getattr(self._composition, "observation_gate", None)
                if isinstance(observation_gate, asyncio.Lock):
                    async with observation_gate:
                        async with self._composition.maintenance_gate:
                            await recommendation_refresh()
                else:
                    async with self._composition.maintenance_gate:
                        await recommendation_refresh()
        except Exception:
            # Recommendations are advisory and must never unpublish READY.
            pass

    async def _note_sweep_liveness(self, summary: ObservationDrainSummary | None) -> None:
        """Count resolved outbox rows as activity for the idle relock clock.

        A resolved row is a same-user authenticated write the live workspace just produced —
        the same trust class as an admitted control call, which already resets the clock. A
        harness that follows the prescribed publish cadence can legitimately go far longer than
        the idle interval between control calls while its hooks keep writing rows, and relocking
        underneath that live session costs the run its check and receipt (#291). Only resolution
        counts: each row acknowledges or quarantines at most once, so an abandoned backlog
        extends the unlock by one bounded drain, while a retrying row re-appears every sweep and
        counting it would let one wedged row hold the vault unlocked forever.
        """

        if summary is not None and summary.acknowledged + summary.quarantined > 0:
            await self._composition.lifecycle.note_activity()

    async def _bounded_observation_sweep(
        self, observation_sweep: Callable[[], Awaitable[ObservationDrainSummary]]
    ) -> ObservationDrainSummary | None:
        """Run one deadline-bounded sweep, naming why it produced no summary.

        The production sweep owns the observation gate around each coordinator ingest. Keep the
        daemon from taking either gate around that whole pass, otherwise a backlog turns one
        bounded row loop into a workflow-wide critical section. Small test compositions that do
        not provide the row guard retain whole-pass observation-then-maintenance exclusion.
        """

        if getattr(observation_sweep, "row_gate_bound", False) is True:
            return await self._bounded_observation_sweep_under_gate(observation_sweep)
        observation_gate = getattr(self._composition, "observation_gate", None)
        if isinstance(observation_gate, asyncio.Lock):
            async with observation_gate:
                async with self._composition.maintenance_gate:
                    return await self._bounded_observation_sweep_under_gate(observation_sweep)
        async with self._composition.maintenance_gate:
            return await self._bounded_observation_sweep_under_gate(observation_sweep)

    async def _bounded_coordination_sweep(
        self, coordination_sweep: Callable[[], Awaitable[object]]
    ) -> None:
        """Retry project detection and advice delivery without blocking READY."""

        async with self._composition.maintenance_gate:
            try:
                await asyncio.wait_for(
                    coordination_sweep(), timeout=_OBSERVATION_SWEEP_DEADLINE_SECONDS
                )
            except ObservationStoreLockTimeout:
                # Store contention inside the pass, not its deadline (#689); the lock reporter
                # already recorded the holder's role and phase.
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="coordination_sweep_failed",
                    reason="observation_store_busy",
                )
            except TimeoutError:
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="coordination_sweep_failed",
                    reason="sweep_deadline_exceeded",
                )
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="service.daemon",
                    operation="coordination_sweep_failed",
                )

    async def _bounded_lineage_recovery(
        self, lineage_recovery: Callable[[], Awaitable[object]]
    ) -> None:
        """Run one generation-bound lineage recovery turn without blocking READY."""

        async with self._composition.maintenance_gate:
            try:
                await asyncio.wait_for(
                    lineage_recovery(), timeout=_LINEAGE_RECOVERY_DEADLINE_SECONDS
                )
            except ObservationStoreLockTimeout:
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="lineage_recovery_failed",
                    reason="observation_store_busy",
                )
            except TimeoutError:
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="lineage_recovery_failed",
                    reason="recovery_deadline_exceeded",
                )
            except Exception as exc:
                record_unexpected_exception_without_raising(
                    exc,
                    component="service.daemon",
                    operation="lineage_recovery_failed",
                )

    async def _bounded_observation_sweep_under_gate(
        self, observation_sweep: Callable[[], Awaitable[ObservationDrainSummary]]
    ) -> ObservationDrainSummary | None:
        """Run one sweep while installation-wide snapshot/rotation work is excluded."""

        raised_inside = False

        async def guarded() -> ObservationDrainSummary:
            nonlocal raised_inside
            try:
                return await observation_sweep()
            except Exception:
                # Only an ordinary exception is the sweep's own. The deadline arrives as
                # ``CancelledError``, which is a ``BaseException`` and deliberately not caught
                # here, so it can never be mistaken for something the sweep raised.
                raised_inside = True
                raise

        try:
            return await asyncio.wait_for(guarded(), timeout=_OBSERVATION_SWEEP_DEADLINE_SECONDS)
        except TimeoutError as exc:
            # ``asyncio.TimeoutError`` is the builtin ``TimeoutError``, so any socket or OS
            # timeout raised inside the sweep lands here too and must not be reported as the
            # deadline. The flag above is the discriminator.
            if raised_inside and isinstance(exc, ObservationStoreLockTimeout):
                # Store contention inside the pass (a spool replay batch, for example), not the
                # deadline and not a fault; the lock reporter recorded the holder (#689).
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="observation_sweep_failed",
                    reason="observation_store_busy",
                )
            elif raised_inside:
                record_unexpected_exception_without_raising(
                    exc,
                    component="service.daemon",
                    operation="observation_sweep_failed",
                )
            else:
                record_bounded_event_without_raising(
                    component="service.daemon",
                    operation="observation_sweep_failed",
                    reason="sweep_deadline_exceeded",
                )
        except Exception as exc:
            # The sweep raised on its own: keep the exception's bounded identity (reason and
            # origin) rather than collapsing every distinct fault into one ``sweep_failed``
            # token (issue #278).
            record_unexpected_exception_without_raising(
                exc,
                component="service.daemon",
                operation="observation_sweep_failed",
            )
        return None

    def _ready_generation_is_current(
        self,
        application: _ReadyApplication,
        service_generation: int,
        vault_generation: int,
    ) -> bool:
        lifecycle = self._composition.lifecycle
        return (
            self._application is application
            and lifecycle.state is ServiceState.READY
            and lifecycle.instance.generation == service_generation
            and self._composition.vault.ready
            and self._composition.vault.generation == vault_generation
        )

    async def _cancel_ready_maintenance(self) -> None:
        task, self._ready_maintenance_task = self._ready_maintenance_task, None
        if task is None:
            return
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)

    async def _try_soft_lock_auto_ready(self) -> bool:
        """Re-apply scoped auto-unlock after idle/session soft lock; never after explicit lock."""

        if self._application is not None or not self._started or self._closed:
            return self._application is not None
        if self._state_reason not in _SOFT_LOCK_AUTO_READY_REASONS:
            return False
        lifecycle = self._composition.lifecycle
        if lifecycle.state is not ServiceState.LOCKED:
            return False
        async with self._activation_lock:
            if self._application is not None:
                return True
            if (
                self._state_reason not in _SOFT_LOCK_AUTO_READY_REASONS
                or lifecycle.state is not ServiceState.LOCKED
            ):
                return False
            soft_lock_reason = self._state_reason
            vault = self._composition.vault
            mode = getattr(vault.mode, "value", vault.mode)
            try:
                await lifecycle.transition(ServiceState.UNLOCKING)
            except LifecycleError:
                return False
            unlocked = False
            try:
                if mode == "passphrase":
                    unlocked = await self._soft_unlock_passphrase_locked()
                elif mode == "os_keyring":
                    await cast(VaultService, vault).retry_keyring(None)
                    unlocked = vault.ready
                    if not unlocked:
                        self._state_reason = "keyring_locked"
                else:
                    unlocked = False
                if not unlocked:
                    await self._return_to_locked_after_soft_unlock()
                    return False
                await self._activate_ready_application_locked(
                    lifecycle.instance.generation,
                    vault.generation,
                )
            except Exception:
                try:
                    # Always best-effort lock: unlock may have left transient store state
                    # even when ready is still false.
                    await vault.lock()
                except Exception:
                    pass
                await self._return_to_locked_after_soft_unlock()
                if (
                    unlocked
                    and self._soft_reready_activation_failures
                    < _SOFT_REREADY_ACTIVATION_RETRY_LIMIT
                ):
                    # The vault credential worked; only ready-application activation failed.
                    # Restoring the soft-lock reason keeps auto-ready eligible, so the very
                    # next dispatch retries instead of the service staying LOCKED until a
                    # manual ceremony (#276).
                    self._soft_reready_activation_failures += 1
                    self._state_reason = soft_lock_reason
                    get_logger("service.daemon").warning(
                        "auto_unlock",
                        outcome="failed",
                        reason="activation_failed_retryable",
                    )
                    return False
                get_logger("service.daemon").warning(
                    "auto_unlock",
                    outcome="failed",
                    reason="unlock_failed",
                )
                if (
                    self._state_reason in _SOFT_LOCK_AUTO_READY_REASONS
                    or self._state_reason == "none"
                ):
                    self._state_reason = "unlock_failed"
                return False
            self._soft_reready_activation_failures = 0
            return self._application is not None

    async def _return_to_locked_after_soft_unlock(self) -> None:
        """Best-effort LOCKED transition after a failed soft auto-ready attempt."""

        lifecycle = self._composition.lifecycle
        try:
            if lifecycle.state is ServiceState.UNLOCKING:
                await lifecycle.transition(ServiceState.LOCKED)
        except LifecycleError:
            pass

    async def _soft_unlock_passphrase_locked(self) -> bool:
        """Unlock passphrase vault from the bundle-scoped platform entry under activation lock."""

        bundle = self._composition.auto_unlock_bundle
        memory = self._composition.secret_memory
        vault = cast(VaultService, self._composition.vault)
        if bundle is None or memory is None or not hasattr(memory, "capture"):
            self._state_reason = "auto_unlock_backend_unavailable"
            self._auto_unlock_reason = "auto_unlock_backend_unavailable"
            return False

        store = AutoUnlockPassphraseStore(bundle)
        candidates, load_reason = await asyncio.to_thread(store.load_candidates_with_reason)
        if not candidates:
            reason = (
                load_reason
                if load_reason in {"auto_unlock_backend_unavailable", "auto_unlock_rejected"}
                else "passphrase_required"
            )
            self._state_reason = reason
            self._auto_unlock_reason = load_reason
            get_logger("service.daemon").warning(
                "auto_unlock",
                outcome="skipped" if load_reason == "auto_unlock_absent" else "failed",
                reason=load_reason,
            )
            return False
        try:
            accepted_slot: str | None = None
            for auto_passphrase, slot in candidates:
                try:
                    handle = cast(LocalSecretMemory, memory).capture(
                        SecretPurpose.VAULT_UNLOCK, auto_passphrase
                    )
                    await vault.unlock(handle)
                except VaultError:
                    continue
                accepted_slot = slot
                break
            if accepted_slot is None:
                raise VaultError("unlock_wrong")
        except VaultError:
            self._state_reason = "auto_unlock_stale"
            self._auto_unlock_reason = "auto_unlock_stale"
            get_logger("service.daemon").warning(
                "auto_unlock",
                outcome="failed",
                reason="auto_unlock_stale",
            )
            return False
        except Exception:
            self._state_reason = "auto_unlock_rejected"
            self._auto_unlock_reason = "auto_unlock_rejected"
            get_logger("service.daemon").warning(
                "auto_unlock",
                outcome="failed",
                reason="auto_unlock_rejected",
            )
            return False
        finally:
            for candidate, _slot in candidates:
                for index in range(len(candidate)):
                    candidate[index] = 0
        # The vault is ready from here on. Reconciling the staged keyring entries is
        # credential-store hygiene only: a promote/discard failure must never relock a ready
        # vault, so log it and continue activation (#492 review).
        try:
            await asyncio.to_thread(_reconcile_staged_slots, store, accepted_slot)
        except Exception:
            get_logger("service.daemon").warning(
                "auto_unlock",
                outcome="degraded",
                reason="staged_reconcile_failed",
            )
        if not vault.ready:
            self._state_reason = "unlock_failed"
            return False
        self._auto_unlock_reason = "none"
        get_logger("service.daemon").info(
            "auto_unlock",
            outcome="succeeded",
            reason="soft_lock_reready",
        )
        return True

    async def _close_components(self) -> None:
        await self._close_ready()
        failure: BaseException | None = None
        for listener in (
            self._composition.human_control_listener,
            self._composition.secret_ingress_listener,
            self._composition.control_listener,
        ):
            if listener is not None:
                try:
                    await listener.aclose()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
        for component in (
            self._composition.human_control_service,
            self._composition.unlock_service,
            self._composition.secret_ingress_service,
            self._composition.session_monitor,
        ):
            if component is not None:
                try:
                    await component.close()
                except BaseException as exc:
                    if failure is None:
                        failure = exc
        try:
            await self._composition.vault.close()
        except BaseException as exc:
            if failure is None:
                failure = exc
        if self._composition.secret_memory is not None:
            try:
                self._composition.secret_memory.close()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure

    def _locked_reason(self) -> str:
        mode = getattr(self._composition.vault.mode, "value", self._composition.vault.mode)
        if mode == "uninitialized":
            return "vault_uninitialized"
        if mode == "os_keyring":
            return "keyring_locked"
        reason = self._auto_unlock_reason
        if reason in {
            "auto_unlock_backend_unavailable",
            "auto_unlock_rejected",
            "auto_unlock_stale",
        }:
            return reason
        return "passphrase_required"

    def _install_signal_handlers(self) -> None:
        loop = asyncio.get_running_loop()
        for signum in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(signum, self._stop_event.set)
            except NotImplementedError, RuntimeError:
                continue


def _reconcile_staged_slots(store: AutoUnlockPassphraseStore, accepted_slot: str) -> None:
    """Promote the proven staged entry, then discard staged entries the proof made stale.

    Called only after one candidate unlocked the vault. The envelope authenticates exactly one
    passphrase, so that success disproves every non-equal staged entry, and a staged entry
    byte-equal to the now-active value is a redundant copy from an interrupted promotion.
    Either way, any staged slot still present afterwards is safe to remove; invalid slots are
    left in place for the status surface.
    """

    if accepted_slot == "staged_rotation":
        store.promote_staged_rotation()
    elif accepted_slot == "staged_initialization":
        store.promote_staged_initialization()
    report = store.slot_report()
    if report.get("staged_rotation") == "present":
        store.discard_staged_rotation()
    if report.get("staged_initialization") == "present":
        store.discard_staged_initialization()


def _is_ready_application(value: object) -> bool:
    return (
        callable(getattr(value, "load_publish_response", None))
        and callable(getattr(value, "store_publish_response", None))
        and callable(getattr(value, "projection_binding_facts", None))
        and callable(getattr(value, "project_result_for_client", None))
        and callable(getattr(value, "close", None))
    )


@dataclass(frozen=True, slots=True)
class _InstallationState:
    installation_id: str
    vault_mode: VaultMode
    root_envelope: VaultRootEnvelope | None
    mode_binding_digest: str

    def __post_init__(self) -> None:
        validate_id(IdKind.INSTALLATION, self.installation_id)
        if self.vault_mode is VaultMode.UNINITIALIZED:
            raise ValueError("installation_marker_mode_invalid")
        if (self.vault_mode is VaultMode.PASSPHRASE) != (self.root_envelope is not None):
            raise ValueError("installation_marker_envelope_invalid")
        if not _is_sha256(self.mode_binding_digest):
            raise ValueError("installation_marker_binding_invalid")


@dataclass(frozen=True, slots=True)
class _ProductionPaths:
    bundle: Path
    generation: Path
    throttle: Path
    singleton_lock: Path
    state: Path

    @classmethod
    def canonical(cls, config: YoetzConfig) -> _ProductionPaths:
        root = bundle_root(_data_dir=config.storage.data_dir)
        ensure_owner_only_dir(root)
        verify_private_local_bundle(root)
        generation = service_generation_path()
        throttle = unlock_throttle_path()
        metadata_root = state_dir()
        ensure_owner_only_dir(metadata_root)
        verify_private_local_bundle(metadata_root)
        return cls(root, generation, throttle, metadata_root / SINGLETON_LOCK_NAME, metadata_root)


@dataclass(frozen=True, slots=True)
class _ListenerBinders:
    control: Callable[[], Awaitable[_Listener]]
    secret: Callable[[], Awaitable[_Listener]]
    human: Callable[[], Awaitable[_Listener]]


class _SystemClock:
    def now_utc(self) -> datetime:
        # RFC3339 millis contract rejects sub-millisecond timestamps; truncate like
        # observability._SystemClock so throttle wall-anomaly checks do not false-positive
        # into a 300s unlock lockout on every restart.
        now = datetime.now(UTC)
        return now.replace(microsecond=(now.microsecond // 1_000) * 1_000)

    def monotonic_seconds(self) -> float:
        return time.monotonic()


class _NullDiagnostics:
    def record(self, result: StartupCheckResult) -> None:
        if type(result) is not StartupCheckResult:
            raise TypeError("startup_diagnostic_invalid")


class _DeferredListener:
    def __init__(self) -> None:
        self._listener: _Listener | None = None
        self._closed = False

    def install(self, listener: _Listener) -> None:
        if self._closed or self._listener is not None:
            raise RuntimeError("listener_install_invalid")
        self._listener = listener

    async def accept(self) -> ControlStream:
        listener = self._listener
        if listener is None or self._closed:
            raise RuntimeError("listener_unavailable")
        return await listener.accept()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        listener, self._listener = self._listener, None
        if listener is not None:
            await listener.aclose()


class _ProductionListeners:
    def __init__(self, binders: _ListenerBinders) -> None:
        self.control = _DeferredListener()
        self.secret = _DeferredListener()
        self.human = _DeferredListener()
        self._binders = binders
        self._bound = False

    async def recover_stale(self, service_lock: _ServiceLockAuthority) -> None:
        """Remove only fixed endpoints proven stale under lifecycle singleton authority."""

        for kind in (
            EndpointKind.CONTROL,
            EndpointKind.SECRET,
            EndpointKind.HUMAN_CONTROL,
        ):
            try:
                await remove_stale_endpoint(kind, service_lock)
            except LocalControlTransportError as exc:
                if exc.reason != "endpoint_missing":
                    raise

    async def bind(self, _instance: object) -> None:
        if self._bound:
            raise RuntimeError("listeners_already_bound")
        try:
            self.control.install(await self._binders.control())
            self.secret.install(await self._binders.secret())
            self.human.install(await self._binders.human())
            self._bound = True
        except BaseException:
            await self.close(_instance)
            raise

    async def close(self, _instance: object = None) -> None:
        failure: BaseException | None = None
        for listener in (self.human, self.secret, self.control):
            try:
                await listener.aclose()
            except BaseException as exc:
                if failure is None:
                    failure = exc
        if failure is not None:
            raise failure


class _InstallationStateStore:
    def __init__(
        self,
        path: Path,
        throttle_path: Path,
        generation_path: Path,
        recovery_sets: InstallationRecoverySetStore | None = None,
        *,
        instance_installation_id: str | None = None,
    ) -> None:
        self._path = path
        self._throttle_path = throttle_path
        self._generation_path = generation_path
        self._recovery_sets = recovery_sets
        # The instance-identity marker (issue #604) is minted before the first service start, so
        # it is the highest-precedence candidate; every later record must agree with it.
        self._instance_installation_id = (
            None
            if instance_installation_id is None
            else validate_id(IdKind.INSTALLATION, instance_installation_id)
        )

    def load(self, *, reconcile: bool = True) -> _InstallationState | None:
        if reconcile:
            self._reconcile_root_rotation()
            self._reconcile_recovery_marker()
        try:
            encoded = _read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)
        except FileNotFoundError:
            return None
        if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
            raise RuntimeError("installation_marker_invalid")
        try:
            value = strict_json_parse(encoded[:-1])
            if canonical_encode(value) != encoded[:-1] or type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if set(source) != {
                "schema_version",
                "installation_id",
                "vault_mode",
                "root_envelope_base64",
                "mode_binding_digest",
                "record_digest",
            }:
                raise ValueError
            if source["schema_version"] != "1" or type(source["record_digest"]) is not str:
                raise ValueError
            body = dict(source)
            record_digest = cast(str, body.pop("record_digest"))
            if not hmac.compare_digest(record_digest, _installation_digest(body)):
                raise ValueError
            mode = VaultMode(cast(str, source["vault_mode"]))
            raw_envelope = source["root_envelope_base64"]
            envelope = None
            if raw_envelope is not None:
                if type(raw_envelope) is not str:
                    raise ValueError
                envelope = VaultRootEnvelope(base64.b64decode(raw_envelope, validate=True))
            state = _InstallationState(
                cast(str, source["installation_id"]),
                mode,
                envelope,
                cast(str, source["mode_binding_digest"]),
            )
            return state
        except Exception as exc:
            raise RuntimeError("installation_marker_invalid") from exc

    def select_installation_id(self, state: _InstallationState | None) -> str:
        candidates: list[str] = []
        if self._instance_installation_id is not None:
            candidates.append(self._instance_installation_id)
        if state is not None:
            candidates.append(state.installation_id)
        throttle = self._provisional_throttle()
        if throttle is not None:
            candidates.append(throttle.installation_id)
        generation_id = self._generation_installation_id()
        if generation_id is not None:
            candidates.append(generation_id)
        if candidates and len(set(candidates)) != 1:
            raise RuntimeError("installation_identity_mismatch")
        return candidates[0] if candidates else new_id(IdKind.INSTALLATION)

    def publish(
        self,
        mode: VaultMode,
        envelope: VaultRootEnvelope | None,
        mode_binding_digest: str,
    ) -> None:
        if self._path.exists():
            raise RuntimeError("installation_marker_exists")
        throttle = self._provisional_throttle()
        if mode is VaultMode.OS_KEYRING and throttle is not None:
            raise RuntimeError("installation_mode_ambiguous")
        if mode is VaultMode.PASSPHRASE and (
            throttle is None or throttle.record_digest != mode_binding_digest
        ):
            raise RuntimeError("installation_throttle_binding_invalid")
        installation_id = (
            throttle.installation_id if throttle is not None else self.select_installation_id(None)
        )
        state = _InstallationState(installation_id, mode, envelope, mode_binding_digest)
        _write_private_atomic(self._path, self._encode(state))

    def replace_after_recovery(
        self,
        mode: VaultMode,
        envelope: VaultRootEnvelope,
        mode_binding_digest: str,
        recovery_generation: int,
    ) -> None:
        """Atomically select a recovered passphrase envelope and retain the old marker."""

        if mode is not VaultMode.PASSPHRASE or type(envelope) is not VaultRootEnvelope:
            raise RuntimeError("installation_recovery_marker_invalid")
        if type(recovery_generation) is not int or recovery_generation <= 0:
            raise RuntimeError("installation_recovery_generation_invalid")
        current = self.load()
        if current is None:
            raise RuntimeError("installation_recovery_marker_missing")
        recovery_sets = self._recovery_sets
        if recovery_sets is None:
            raise RuntimeError("installation_recovery_store_unavailable")
        throttle = self._provisional_throttle()
        if throttle is None or throttle.record_digest != mode_binding_digest:
            raise RuntimeError("installation_throttle_binding_invalid")
        rollback_root = self._path.parent / "installation-recovery" / "rollback-markers"
        ensure_owner_only_dir(rollback_root.parent)
        ensure_owner_only_dir(rollback_root)
        rollback = rollback_root / f"generation-{recovery_generation}.json"
        if rollback.exists():
            raise RuntimeError("installation_recovery_generation_exists")
        _write_private_atomic(rollback, self._encode(current))
        recovered = _InstallationState(
            current.installation_id,
            VaultMode.PASSPHRASE,
            envelope,
            mode_binding_digest,
        )
        old_marker = self._encode(current)
        new_marker = self._encode(recovered)
        journal = rollback_root.parent / "marker-recovery-journal.json"
        if journal.exists():
            raise RuntimeError("installation_recovery_generation_exists")
        self._write_recovery_marker_journal(
            journal,
            recovery_generation=recovery_generation,
            old_marker_digest=_bytes_digest(old_marker),
            new_marker_digest=_bytes_digest(new_marker),
        )
        try:
            _write_private_atomic(self._path, new_marker)
            recovery_sets.finalize_committed_recovery(recovery_generation)
            journal.unlink()
            _fsync_directory(journal.parent)
        except BaseException:
            self._reconcile_recovery_marker()
            if hmac.compare_digest(
                _bytes_digest(_read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)),
                _bytes_digest(new_marker),
            ):
                return
            raise

    def replace_passphrase_envelope(self, envelope: VaultRootEnvelope) -> None:
        """Atomically replace only the passphrase envelope while retaining installation identity."""

        if type(envelope) is not VaultRootEnvelope:
            raise RuntimeError("installation_passphrase_envelope_invalid")
        current = self.load()
        if current is None or current.vault_mode is not VaultMode.PASSPHRASE:
            raise RuntimeError("installation_passphrase_envelope_invalid")
        replacement = _InstallationState(
            current.installation_id,
            VaultMode.PASSPHRASE,
            envelope,
            current.mode_binding_digest,
        )
        _write_private_atomic(self._path, self._encode(replacement))

    @staticmethod
    def _write_recovery_marker_journal(
        path: Path,
        *,
        recovery_generation: int,
        old_marker_digest: str,
        new_marker_digest: str,
    ) -> None:
        body: dict[str, JsonValue] = {
            "format": "yoetz-installation-recovery-marker/1",
            "new_marker_digest": new_marker_digest,
            "old_marker_digest": old_marker_digest,
            "recovery_generation": recovery_generation,
        }
        body["record_digest"] = canonical_digest(body)
        _write_private_atomic(path, canonical_encode(body) + b"\n")

    def _reconcile_recovery_marker(self) -> None:
        recovery_sets = self._recovery_sets
        journal = self._path.parent / "installation-recovery" / "marker-recovery-journal.json"
        try:
            encoded = _read_private_file(journal, 16_384)
        except FileNotFoundError:
            return
        if recovery_sets is None:
            raise RuntimeError("installation_recovery_store_unavailable")
        try:
            if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n"):
                raise ValueError
            value = strict_json_parse(encoded[:-1])
            if type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if canonical_encode(source) + b"\n" != encoded or set(source) != {
                "format",
                "new_marker_digest",
                "old_marker_digest",
                "record_digest",
                "recovery_generation",
            }:
                raise ValueError
            body = dict(source)
            record_digest = body.pop("record_digest")
            generation = source["recovery_generation"]
            old_digest = source["old_marker_digest"]
            new_digest = source["new_marker_digest"]
            if (
                source["format"] != "yoetz-installation-recovery-marker/1"
                or type(record_digest) is not str
                or not hmac.compare_digest(record_digest, canonical_digest(body))
                or type(generation) is not int
                or generation <= 0
                or type(old_digest) is not str
                or type(new_digest) is not str
            ):
                raise ValueError
            marker_digest = _bytes_digest(
                _read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)
            )
            if hmac.compare_digest(marker_digest, new_digest):
                recovery_sets.finalize_committed_recovery(generation)
            elif hmac.compare_digest(marker_digest, old_digest):
                recovery_sets.rollback_interrupted_recovery(generation)
            else:
                raise RuntimeError("installation_recovery_marker_ambiguous")
            journal.unlink()
            _fsync_directory(journal.parent)
        except (OSError, TypeError, ValueError) as exc:
            raise RuntimeError("installation_recovery_marker_journal_invalid") from exc

    def replace_after_root_rotation(
        self,
        mode: VaultMode,
        envelope: VaultRootEnvelope,
        mode_binding_digest: str,
        recovery_generation: int,
        staged_vault: Path,
        action: Literal["rotate", "revoke"],
    ) -> None:
        """Switch a fully re-encrypted vault and marker with restart reconciliation."""

        if (
            mode is not VaultMode.PASSPHRASE
            or type(envelope) is not VaultRootEnvelope
            or type(recovery_generation) is not int
            or recovery_generation <= 0
            or action not in {"rotate", "revoke"}
        ):
            raise RuntimeError("installation_root_rotation_invalid")
        current = self.load()
        if current is None:
            raise RuntimeError("installation_recovery_marker_missing")
        throttle = self._provisional_throttle()
        if throttle is None or throttle.record_digest != mode_binding_digest:
            raise RuntimeError("installation_throttle_binding_invalid")
        vault = self._path.parent / "vault"
        if (
            staged_vault.parent != vault.parent
            or not staged_vault.name.startswith(f".{vault.name}.root-{recovery_generation}.")
            or not staged_vault.name.endswith(".tmp")
            or not staged_vault.is_dir()
            or not vault.is_dir()
        ):
            raise RuntimeError("installation_root_rotation_stage_invalid")
        recovery_root = self._path.parent / "installation-recovery"
        rollback_root = recovery_root / "rollback-vaults"
        ensure_owner_only_dir(recovery_root)
        ensure_owner_only_dir(rollback_root)
        backup = rollback_root / f"{action}-generation-{recovery_generation}"
        journal = recovery_root / "root-rotation-journal.json"
        if backup.exists() or journal.exists():
            raise RuntimeError("installation_recovery_generation_exists")
        old_marker = _read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)
        rollback_markers = recovery_root / "rollback-markers"
        ensure_owner_only_dir(rollback_markers)
        rollback_marker = rollback_markers / f"root-{action}-generation-{recovery_generation}.json"
        if rollback_marker.exists():
            raise RuntimeError("installation_recovery_generation_exists")
        _write_private_atomic(rollback_marker, old_marker)
        next_state = _InstallationState(
            current.installation_id,
            VaultMode.PASSPHRASE,
            envelope,
            mode_binding_digest,
        )
        new_marker = self._encode(next_state)
        self._write_root_rotation_journal(
            journal,
            action=action,
            recovery_generation=recovery_generation,
            stage_name=staged_vault.name,
            backup_name=backup.name,
            old_marker_digest=_bytes_digest(old_marker),
            new_marker_digest=_bytes_digest(new_marker),
            phase="prepared",
        )
        try:
            os.rename(vault, backup)
            _fsync_directory(vault.parent)
            os.rename(staged_vault, vault)
            _fsync_directory(vault.parent)
            _write_private_atomic(self._path, new_marker)
            self._write_root_rotation_journal(
                journal,
                action=action,
                recovery_generation=recovery_generation,
                stage_name=staged_vault.name,
                backup_name=backup.name,
                old_marker_digest=_bytes_digest(old_marker),
                new_marker_digest=_bytes_digest(new_marker),
                phase="marker_committed",
            )
            self._finalize_root_rotation(action, recovery_generation)
            journal.unlink()
            _fsync_directory(journal.parent)
        except BaseException:
            self._reconcile_root_rotation()
            if hmac.compare_digest(
                _bytes_digest(_read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)),
                _bytes_digest(new_marker),
            ):
                return
            raise

    def _finalize_root_rotation(
        self, action: Literal["rotate", "revoke"], recovery_generation: int
    ) -> None:
        recovery_sets = self._recovery_sets
        if recovery_sets is None:
            raise RuntimeError("installation_recovery_store_unavailable")
        if action == "rotate":
            recovery_sets.activate(recovery_sets.metadata(recovery_generation))
        else:
            recovery_sets.revoke(recovery_generation)

    @staticmethod
    def _write_root_rotation_journal(
        path: Path,
        *,
        action: Literal["rotate", "revoke"],
        recovery_generation: int,
        stage_name: str,
        backup_name: str,
        old_marker_digest: str,
        new_marker_digest: str,
        phase: Literal["prepared", "marker_committed"],
    ) -> None:
        body: dict[str, JsonValue] = {
            "action": action,
            "backup_name": backup_name,
            "format": "yoetz-installation-root-rotation/1",
            "new_marker_digest": new_marker_digest,
            "old_marker_digest": old_marker_digest,
            "phase": phase,
            "recovery_generation": recovery_generation,
            "stage_name": stage_name,
        }
        body["record_digest"] = canonical_digest(body)
        _write_private_atomic(path, canonical_encode(body) + b"\n")

    def _reconcile_root_rotation(self) -> None:
        recovery_root = self._path.parent / "installation-recovery"
        journal = recovery_root / "root-rotation-journal.json"
        try:
            encoded = _read_private_file(journal, 16_384)
        except FileNotFoundError:
            return
        try:
            value = strict_json_parse(encoded[:-1])
            if not encoded.endswith(b"\n") or encoded.endswith(b"\n\n") or type(value) is not dict:
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            if canonical_encode(source) + b"\n" != encoded or set(source) != {
                "action",
                "backup_name",
                "format",
                "new_marker_digest",
                "old_marker_digest",
                "phase",
                "record_digest",
                "recovery_generation",
                "stage_name",
            }:
                raise ValueError
            body = dict(source)
            record_digest = body.pop("record_digest")
            if (
                source["format"] != "yoetz-installation-root-rotation/1"
                or type(record_digest) is not str
                or not hmac.compare_digest(record_digest, canonical_digest(body))
            ):
                raise ValueError
            action = source["action"]
            phase = source["phase"]
            generation = source["recovery_generation"]
            stage_name = source["stage_name"]
            backup_name = source["backup_name"]
            old_digest = source["old_marker_digest"]
            new_digest = source["new_marker_digest"]
            if (
                action not in {"rotate", "revoke"}
                or phase not in {"prepared", "marker_committed"}
                or type(generation) is not int
                or generation <= 0
                or type(stage_name) is not str
                or not stage_name.startswith(f".vault.root-{generation}.")
                or not stage_name.endswith(".tmp")
                or type(backup_name) is not str
                or backup_name != f"{action}-generation-{generation}"
                or type(old_digest) is not str
                or type(new_digest) is not str
            ):
                raise ValueError
            vault = self._path.parent / "vault"
            stage = vault.parent / stage_name
            backup = recovery_root / "rollback-vaults" / backup_name
            marker_digest = _bytes_digest(
                _read_private_file(self._path, _MAX_INSTALLATION_MARKER_BYTES)
            )
            if hmac.compare_digest(marker_digest, new_digest):
                if not vault.is_dir() or not backup.is_dir():
                    raise RuntimeError("installation_root_rotation_ambiguous")
                self._finalize_root_rotation(cast(Literal["rotate", "revoke"], action), generation)
            elif hmac.compare_digest(marker_digest, old_digest):
                if vault.exists() and backup.is_dir():
                    if stage.exists():
                        raise RuntimeError("installation_root_rotation_ambiguous")
                    os.rename(vault, stage)
                    _fsync_directory(vault.parent)
                if not vault.exists() and backup.is_dir():
                    os.rename(backup, vault)
                    _fsync_directory(vault.parent)
                if not vault.is_dir():
                    raise RuntimeError("installation_root_rotation_ambiguous")
                if stage.exists():
                    _remove_private_tree(stage)
                    _fsync_directory(stage.parent)
            else:
                raise RuntimeError("installation_root_rotation_ambiguous")
            journal.unlink()
            _fsync_directory(journal.parent)
        except (OSError, TypeError, ValueError) as exc:
            raise RuntimeError("installation_root_rotation_journal_invalid") from exc

    @staticmethod
    def _encode(state: _InstallationState) -> bytes:
        body: dict[str, JsonValue] = {
            "schema_version": "1",
            "installation_id": state.installation_id,
            "vault_mode": state.vault_mode.value,
            "root_envelope_base64": (
                None
                if state.root_envelope is None
                else base64.b64encode(state.root_envelope.canonical_bytes).decode("ascii")
            ),
            "mode_binding_digest": state.mode_binding_digest,
        }
        body["record_digest"] = _installation_digest(body)
        return canonical_encode(body) + b"\n"

    def _provisional_throttle(self) -> UnlockThrottleRecord | None:
        try:
            encoded = _read_private_file(self._throttle_path, 16_384)
        except FileNotFoundError:
            return None
        try:
            return UnlockThrottleRecord.decode(encoded)
        except (TypeError, ValueError) as exc:
            raise RuntimeError("installation_throttle_invalid") from exc

    def _generation_installation_id(self) -> str | None:
        try:
            encoded = _read_private_file(self._generation_path, 16_384)
        except FileNotFoundError:
            return None
        try:
            value = strict_json_parse(encoded[:-1])
            if (
                not encoded.endswith(b"\n")
                or encoded.endswith(b"\n\n")
                or canonical_encode(value) != encoded[:-1]
                or type(value) is not dict
            ):
                raise ValueError
            source = cast(dict[str, JsonValue], value)
            body = dict(source)
            record = body.pop("record_digest")
            expected = (
                "sha256:"
                + hashlib.sha256(_SERVICE_GENERATION_DOMAIN + canonical_encode(body)).hexdigest()
            )
            if type(record) is not str or not hmac.compare_digest(record, expected):
                raise ValueError
            installation_id = cast(str, source["installation_id"])
            validate_id(IdKind.INSTALLATION, installation_id)
            return installation_id
        except Exception as exc:
            raise RuntimeError("service_generation_invalid") from exc


class _LockedHumanEffects:
    def __init__(
        self,
        lifecycle: ServiceLifecycle,
        vault: VaultService,
        privacy_relay: _PrivacyPolicyAppRelay,
        recovery_sets: InstallationRecoverySetStore | None = None,
        unlock: UnlockCoordinator | None = None,
        maintenance_gate: asyncio.Lock | None = None,
        observation_gate: asyncio.Lock | None = None,
    ) -> None:
        self._lifecycle = lifecycle
        self._vault = vault
        self._privacy_relay = privacy_relay
        self._recovery_sets = recovery_sets
        self._unlock = unlock
        self._maintenance_gate = maintenance_gate or asyncio.Lock()
        self._observation_gate = observation_gate or asyncio.Lock()
        self._maintenance_request_id: str | None = None
        self._prepared_recovery_snapshots: dict[str, PreparedInstallationSnapshot] = {}
        self._prepared_root_rotations: dict[str, Path] = {}
        self._prepared_recovery_plan_digests: dict[str, str] = {}

    async def _acquire_recovery_maintenance(self, request_id: str) -> None:
        if self._maintenance_request_id is not None:
            raise HumanControlError("state_forbidden")
        await self._observation_gate.acquire()
        try:
            # Recovery excludes the sweeper as well as ordinary calls. Keep the order identical
            # to daemon dispatch so no maintenance/recovery path can form a lock inversion.
            await self._maintenance_gate.acquire()
        except BaseException:
            self._observation_gate.release()
            raise
        self._maintenance_request_id = request_id

    def _release_recovery_maintenance(self, request_id: str) -> None:
        if self._maintenance_request_id != request_id:
            return
        self._maintenance_request_id = None
        self._maintenance_gate.release()
        self._observation_gate.release()

    def _privacy_app(self) -> object:
        coordinator = self._privacy_relay.get()
        # Human effects have always accepted the policy application itself. Credential probing
        # additionally needs the coordinator, so the late-bound relay now exposes the coordinator
        # in production; keep the original application-shaped test and recovery path valid.
        app = getattr(coordinator, "policy_application", coordinator)
        if app is None:
            raise HumanControlError("kind_forbidden")
        return app

    async def prepare(self, request: ClientOpenEnvelope) -> tuple[HumanPreview, str, int | None]:
        target = request.target
        mode = self._vault.mode.value
        if type(target) is EmptyVaultTarget:
            if target.expected_mode != mode:
                raise HumanControlError("target_invalid")
            digest = canonical_digest(human_target_json(target))
            if request.ceremony_kind is HumanCeremonyKind.VAULT_INITIALIZE:
                return VaultInitializePreview(), digest, None
            if request.ceremony_kind is HumanCeremonyKind.VAULT_UNLOCK:
                return VaultUnlockPreview(), digest, None
            if request.ceremony_kind is HumanCeremonyKind.VAULT_PASSPHRASE_ROTATE:
                if not self._vault.ready or mode != "passphrase":
                    raise HumanControlError("state_forbidden")
                return VaultPassphraseRotatePreview(), digest, None
            if request.ceremony_kind is HumanCeremonyKind.KEYRING_RETRY:
                operation = "pristine_create" if mode == "uninitialized" else "existing_load"
                return KeyringRetryPreview(operation), digest, None
            raise HumanControlError("kind_forbidden")
        if type(target) is ProviderCredentialTarget:
            if not self._vault.ready or mode != "passphrase":
                raise HumanControlError("kind_forbidden")
            if request.ceremony_kind not in {
                HumanCeremonyKind.PROVIDER_CREDENTIAL_SET,
                HumanCeremonyKind.PROVIDER_CREDENTIAL_ROTATE,
            }:
                raise HumanControlError("kind_forbidden")
            if (request.ceremony_kind is HumanCeremonyKind.PROVIDER_CREDENTIAL_SET) != (
                target.action == "set"
            ):
                raise HumanControlError("target_invalid")
            digest = target.target_digest()
            preview: HumanPreview
            if target.action == "set":
                preview = ProviderCredentialSetPreview(target)
            else:
                preview = ProviderCredentialRotatePreview(target)
            return preview, digest, None
        if type(target) is InstallationRecoveryTarget:
            if self._recovery_sets is None:
                raise HumanControlError("ceremony_unsupported")
            if request.ceremony_kind is not HumanCeremonyKind.INSTALLATION_RECOVERY:
                raise HumanControlError("kind_forbidden")
            if target.confirmed_plan_digest != target.plan_digest():
                raise HumanControlError("target_invalid")
            if target.operation == "restore":
                if self._vault.ready or mode == "uninitialized":
                    raise HumanControlError("state_forbidden")
                try:
                    artifact = self._recovery_sets.load(target.recovery_generation)
                except FileNotFoundError, OSError, TypeError, ValueError:
                    raise HumanControlError("pending_unavailable") from None
                item_count = 1
                total_bytes = len(artifact.canonical_bytes)
            else:
                if not self._vault.ready:
                    raise HumanControlError("state_forbidden")
                recovery_status = self._recovery_sets.status(
                    installation_exists=True,
                    vault_ready=True,
                    ordinary_unlock_available=True,
                    auto_unlock_repairable=False,
                )
                active_generation = recovery_status.active_generation
                if (
                    target.operation == "provision"
                    and active_generation is not None
                    or target.operation == "rotate"
                    and (
                        active_generation is None
                        or target.recovery_generation != active_generation + 1
                    )
                    or target.operation == "revoke"
                    and (
                        target.recovery_generation != active_generation
                        or recovery_status.reason == "recovery_material_revoked"
                    )
                ):
                    raise HumanControlError("target_invalid")
                if target.request_id in self._prepared_recovery_snapshots:
                    raise HumanControlError("state_forbidden")
                await self._acquire_recovery_maintenance(target.request_id)
                try:
                    vault_override: Path | None = None
                    if target.operation in {"rotate", "revoke"}:
                        vault_override = await self._vault.stage_root_rotation(
                            target.recovery_generation
                        )
                        self._prepared_root_rotations[target.request_id] = vault_override
                    if target.operation == "revoke":
                        item_count, total_bytes = _private_tree_facts(cast(Path, vault_override))
                    elif target.set_mode == "self_contained":
                        snapshot = await asyncio.to_thread(
                            self._recovery_sets.prepare_snapshot,
                            target.recovery_generation,
                            vault_override=vault_override,
                        )
                        self._prepared_recovery_snapshots[target.request_id] = snapshot
                        item_count = snapshot.item_count + 1
                        total_bytes = snapshot.total_bytes
                    else:
                        if vault_override is None:
                            item_count = 1
                            total_bytes = 0
                        else:
                            vault_items, vault_bytes = _private_tree_facts(vault_override)
                            item_count = vault_items + 1
                            total_bytes = vault_bytes
                except BaseException:
                    try:
                        await self._vault.cancel_root_rotation()
                    finally:
                        self._prepared_root_rotations.pop(target.request_id, None)
                        self._release_recovery_maintenance(target.request_id)
                    raise
            snapshot_digest = (
                None
                if target.request_id not in self._prepared_recovery_snapshots
                else self._prepared_recovery_snapshots[target.request_id].manifest_digest
            )
            confirmed_plan_digest = canonical_digest(
                {
                    "item_count": item_count,
                    "requested_plan_digest": target.plan_digest(),
                    "snapshot_manifest_digest": snapshot_digest,
                    "total_bytes": total_bytes,
                    "vault_generation": self._vault.generation,
                }
            )
            if target.operation != "restore":
                self._prepared_recovery_plan_digests[target.request_id] = confirmed_plan_digest
            return (
                InstallationRecoveryPreview(
                    target.operation,
                    target.request_id,
                    confirmed_plan_digest,
                    target.recovery_generation,
                    target.set_mode,
                    target.secret_kind,
                    target.target_envelope,
                    item_count,
                    total_bytes,
                    False,
                ),
                confirmed_plan_digest,
                None,
            )
        if type(target) is PrivacyPendingTarget:
            # Recording an already-bounded disclosure decision does not widen policy, change a
            # credential, or grant new authority — it answers a proposal the running policy
            # already scoped. Requiring passphrase mode here made the ceremony unreachable on a
            # keyring installation, which is the ordinary production configuration. Policy
            # decisions keep the stronger requirement below.
            if not self._vault.ready:
                raise HumanControlError("state_forbidden")
            if target.decision_kind != "disclosure" and mode != "passphrase":
                raise HumanControlError("kind_forbidden")
            expected_kind = (
                HumanCeremonyKind.PRIVACY_POLICY_DECISION
                if target.decision_kind == "policy"
                else HumanCeremonyKind.PRIVACY_DISCLOSURE_DECISION
            )
            if request.ceremony_kind is not expected_kind:
                raise HumanControlError("kind_forbidden")
            if target.decision_kind == "disclosure":
                from yoetz.application.privacy_policy import PrivacyPolicyApplication

                app = self._privacy_app()
                if type(app) is not PrivacyPolicyApplication:
                    # This build cannot run the ceremony at all — distinct from a proposal
                    # problem, and the caller cannot fix it by supplying a different id.
                    raise HumanControlError("ceremony_unsupported")
                proposal = await app.audit.load_disclosure_proposal(target.pending_id)
                if proposal is None or proposal.expires_at <= app.clock.now_utc():
                    # Absent and expired are deliberately one reason: distinguishing them would
                    # confirm whether an unknown id ever existed.
                    raise HumanControlError("pending_unavailable")
                effective = await app.policy_store.effective_policy(proposal.scope)
                if (
                    effective.policy.version != proposal.policy_version
                    or effective.effective_digest != proposal.policy_digest
                ):
                    # The policy moved under the proposal: it can no longer be decided as
                    # prepared, and approving it would authorize bytes against a policy the
                    # user never saw.
                    raise HumanControlError("pending_not_actionable")
                destination: JsonValue
                if proposal.provider_binding is not None:
                    binding = proposal.provider_binding
                    destination = {
                        "endpoint_profile_id": binding.endpoint_profile_id,
                        "endpoint_profile_version": binding.endpoint_profile_version,
                        "model_id": binding.model_id,
                        "provider_id": binding.provider_id,
                        "transport": binding.transport,
                    }
                elif proposal.local_sink is not None:
                    destination = {"local_sink": proposal.local_sink.value}
                else:
                    # A proposal with no committed destination cannot be previewed honestly.
                    raise HumanControlError("pending_not_actionable")
                excerpt_bytes = proposal.prepared_bytes[:4_096]
                try:
                    excerpt = excerpt_bytes.decode("utf-8")
                except UnicodeDecodeError as exc:
                    if len(proposal.prepared_bytes) <= 4_096 or exc.end != len(excerpt_bytes):
                        raise HumanControlError("pending_not_actionable") from exc
                    excerpt = excerpt_bytes[: exc.start].decode("utf-8")
                category = (
                    proposal.approved_categories[0].value.replace("_", "-")
                    if len(proposal.approved_categories) == 1
                    else "mixed"
                )
                digest = canonical_digest(human_target_json(target))
                try:
                    preview_disclosure = PrivacyDisclosureDecisionPreview(
                        target.pending_id,
                        excerpt,
                        proposal.prepared_case_digest,
                        category,
                        canonical_digest(destination),
                        len(proposal.prepared_bytes),
                        proposal.max_tokens,
                        proposal.policy_digest,
                    )
                except (TypeError, ValueError) as exc:
                    raise HumanControlError("pending_not_actionable") from exc
                return preview_disclosure, digest, effective.generation
            from yoetz.application.privacy_policy import (
                privacy_policy_changes,
                private_repository_baseline,
            )

            app = self._privacy_app()
            store = getattr(app, "policy_store", None)
            if store is None:
                raise HumanControlError("kind_forbidden")
            try:
                prepared = await store.load_transition(target.pending_id)
            except ValueError as exc:
                if exc.args == ("privacy_policy_transition_unavailable",):
                    raise HumanControlError("target_invalid") from exc
                raise HumanControlError("target_invalid") from exc
            proposal = prepared.proposal
            # The human approves against this diff, and it is the *same* call that classifies a
            # widen — so a dimension the classifier treats as widening cannot be absent from the
            # screen. The preview type refuses a change set with no widening in it, which turns a
            # future drift here into a closed failure rather than a silently empty approval.
            digest = canonical_digest(human_target_json(target))
            try:
                if proposal.members:
                    preview_members: list[PrivacyPolicyTransitionPreviewMember] = []
                    for member in proposal.members:
                        if (
                            member.scope.kind is AuthorizationScopeKind.MACHINE
                            and member.action == "replace"
                        ):
                            # A machine scope has no ancestor overlay, so this is the exact row
                            # identified by the member's CAS generation and digest.
                            base = await store.effective_policy(member.scope)
                            if (
                                base.generation != member.expected_generation
                                or base.effective_digest != member.expected_policy_digest
                            ):
                                raise ValueError("privacy_policy_preview_member_stale")
                            changes = privacy_policy_changes(base.policy, member.candidate_policy)
                            preview_members.append(
                                PrivacyPolicyTransitionPreviewMember(
                                    "machine_ceiling", "replace", changes
                                )
                            )
                        elif (
                            member.scope.kind is AuthorizationScopeKind.WORKSPACE
                            and member.action == "insert"
                        ):
                            # The exact before-state is an absent row, represented as an explicit
                            # Private/no-egress policy at this repository scope. Never substitute
                            # the inherited machine row: that would falsely claim a repository
                            # grant existed and would hide what the insert newly authorizes.
                            baseline = private_repository_baseline(member.candidate_policy)
                            changes = privacy_policy_changes(baseline, member.candidate_policy)
                            preview_members.append(
                                PrivacyPolicyTransitionPreviewMember(
                                    "repository_grant", "insert", changes
                                )
                            )
                        elif (
                            member.scope.kind is AuthorizationScopeKind.WORKSPACE
                            and member.action == "replace"
                        ):
                            authority = await store.repository_authority(member.scope)
                            base_policy = authority.grant_policy
                            if (
                                base_policy is None
                                or authority.grant_generation != member.expected_generation
                                or authority.grant_policy_digest != member.expected_policy_digest
                            ):
                                raise ValueError("privacy_policy_preview_member_stale")
                            changes = privacy_policy_changes(base_policy, member.candidate_policy)
                            preview_members.append(
                                PrivacyPolicyTransitionPreviewMember(
                                    "repository_grant", "replace", changes
                                )
                            )
                        else:
                            raise ValueError("privacy_policy_preview_member_unrenderable")
                    preview_policy = PrivacyPolicyDecisionPreview(
                        target.pending_id,
                        prepared.exact_diff_digest,
                        (),
                        tuple(preview_members),
                    )
                else:
                    base = await store.effective_policy(proposal.scope)
                    changes = privacy_policy_changes(base.policy, proposal.proposed_policy)
                    preview_policy = PrivacyPolicyDecisionPreview(
                        target.pending_id, prepared.exact_diff_digest, changes
                    )
            except (TypeError, ValueError) as exc:
                # Both the diff and the preview fail closed on malformed policy state, and
                # `open_ceremony` only translates `HumanControlError` — anything else escapes
                # as an unbounded ceremony failure.
                raise HumanControlError("target_invalid") from exc
            return (preview_policy, digest, proposal.expected_generation)
        raise HumanControlError("kind_forbidden")

    async def complete_portable_recovery(
        self, target: PortableRecoveryTarget, secret: SecretHandle
    ) -> PortableRecoveryResult:
        del target, secret
        raise HumanControlError("kind_forbidden")

    async def complete_installation_provision(
        self,
        target: InstallationRecoveryTarget,
        secret: SecretHandle,
        rewrap_secret: SecretHandle | None,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> InstallationRecoveryResult:
        if target.operation not in {"provision", "rotate"}:
            raise HumanControlError("ceremony_unsupported")
        if self._recovery_sets is None:
            raise HumanControlError("ceremony_unsupported")
        snapshot = self._prepared_recovery_snapshots.pop(target.request_id, None)
        confirmed_plan_digest = self._prepared_recovery_plan_digests.pop(target.request_id, None)
        staged_generation: int | None = None
        try:
            if confirmed_plan_digest is None:
                raise HumanControlError("target_invalid")
            if (target.operation == "rotate") != (rewrap_secret is not None):
                raise HumanControlError("target_invalid")
            if (target.set_mode == "self_contained") != (snapshot is not None):
                raise HumanControlError("target_invalid")
            mode = (
                InstallationRecoveryMode.SELF_CONTAINED
                if snapshot is not None
                else InstallationRecoveryMode.COMPACT
            )
            proof.consume(
                "installation_recovery_change",
                confirmed_plan_digest,
                self._lifecycle.instance.generation,
                self._vault.generation,
                None,
                now_monotonic,
            )
            if target.operation == "rotate":
                unlock = self._unlock
                if unlock is None or rewrap_secret is None:
                    raise HumanControlError("ceremony_unsupported")
                throttle_digest = await unlock.stage_root_rotation_throttle()
                await self._vault.prepare_root_rotation_envelope(
                    rewrap_secret,
                    throttle_record_digest=throttle_digest,
                    action="rotate",
                )
            sets = self._recovery_sets
            metadata: InstallationRecoveryMetadata | None = None

            def _stage(
                built: InstallationRecoveryArtifact,
            ) -> InstallationRecoveryArtifact:
                nonlocal metadata, staged_generation
                metadata = sets.stage(built, snapshot)
                staged_generation = metadata.recovery_generation
                # Reopen what was actually persisted, not the in-memory bytes, so the drill also
                # covers a set that staging truncated or corrupted.
                return sets.load(metadata.recovery_generation)

            # Build, stage, and run the ADR-024 step 5 pre-publication drill under one live
            # candidate secret; nothing is advertised until the set has proven it opens this vault.
            artifact = await self._vault.build_and_verify_installation_recovery_artifact(
                secret,
                recovery_generation=target.recovery_generation,
                mode=mode,
                secret_kind=InstallationRecoverySecretKind(target.secret_kind),
                snapshot_manifest_digest=(None if snapshot is None else snapshot.manifest_digest),
                publish=_stage,
            )
            if metadata is None:
                raise HumanControlError("internal_error")
            await self._vault.commit_installation_recovery_metadata(metadata)
            if target.operation == "rotate":
                await self._vault.commit_root_rotation()
            else:
                self._recovery_sets.activate(metadata)
            return InstallationRecoveryResult(
                target.operation,
                "completed",
                target.recovery_generation,
                artifact.artifact_digest,
            )
        except BaseException as exc:
            if snapshot is not None:
                self._recovery_sets.discard_snapshot(snapshot)
            if staged_generation is not None:
                # Nothing published this generation and the retry recomputes the same number, so
                # leaving the stage behind would make every later attempt fail as "exists".
                self._recovery_sets.discard_staged_generation(staged_generation)
            await self._vault.cancel_root_rotation()
            if isinstance(exc, (HumanControlError, asyncio.CancelledError)):
                raise
            raise HumanControlError("internal_error") from exc
        finally:
            self._prepared_root_rotations.pop(target.request_id, None)
            self._release_recovery_maintenance(target.request_id)

    async def revoke_installation_recovery(
        self,
        target: InstallationRecoveryTarget,
        rewrap_secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> InstallationRecoveryResult:
        if target.operation != "revoke" or self._recovery_sets is None:
            raise HumanControlError("ceremony_unsupported")
        confirmed_plan_digest = self._prepared_recovery_plan_digests.pop(target.request_id, None)
        try:
            if confirmed_plan_digest is None:
                raise HumanControlError("target_invalid")
            proof.consume(
                "installation_recovery_change",
                confirmed_plan_digest,
                self._lifecycle.instance.generation,
                self._vault.generation,
                None,
                now_monotonic,
            )
            unlock = self._unlock
            if unlock is None:
                raise HumanControlError("ceremony_unsupported")
            throttle_digest = await unlock.stage_root_rotation_throttle()
            await self._vault.prepare_root_rotation_envelope(
                rewrap_secret,
                throttle_record_digest=throttle_digest,
                action="revoke",
            )
            await self._vault.commit_root_rotation()
            return InstallationRecoveryResult(
                "revoke",
                "completed",
                target.recovery_generation,
                confirmed_plan_digest,
            )
        except BaseException as exc:
            await self._vault.cancel_root_rotation()
            if isinstance(exc, (HumanControlError, asyncio.CancelledError)):
                raise
            raise HumanControlError("internal_error") from exc
        finally:
            self._prepared_root_rotations.pop(target.request_id, None)
            self._release_recovery_maintenance(target.request_id)

    async def cancel_installation_recovery(self, target: InstallationRecoveryTarget) -> None:
        snapshot = self._prepared_recovery_snapshots.pop(target.request_id, None)
        self._prepared_recovery_plan_digests.pop(target.request_id, None)
        if snapshot is not None and self._recovery_sets is not None:
            self._recovery_sets.discard_snapshot(snapshot)
        if target.request_id in self._prepared_root_rotations:
            self._prepared_root_rotations.pop(target.request_id, None)
            await self._vault.cancel_root_rotation()
        self._release_recovery_maintenance(target.request_id)

    def begin_installation_restore(self, target: InstallationRecoveryTarget) -> tuple[object, str]:
        if target.operation != "restore":
            raise HumanControlError("kind_forbidden")
        if self._recovery_sets is None:
            raise HumanControlError("ceremony_unsupported")
        try:
            artifact = self._recovery_sets.load(target.recovery_generation)
            continuation = self._recovery_sets.begin_recovery(target.recovery_generation)
            return artifact, continuation
        except (FileNotFoundError, OSError, RuntimeError, ValueError) as exc:
            raise HumanControlError("pending_unavailable") from exc

    def finish_installation_restore(self, continuation_id: str, *, success: bool) -> None:
        if self._recovery_sets is None:
            raise HumanControlError("ceremony_unsupported")
        try:
            self._recovery_sets.finish_recovery(continuation_id, success=success)
        except (OSError, RuntimeError, ValueError) as exc:
            raise HumanControlError("internal_error") from exc

    async def store_provider_credential(
        self,
        target: ProviderCredentialTarget,
        secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> ProviderCredentialResult:
        from yoetz.service.vault import ProviderCredentialBinding

        binding = ProviderCredentialBinding(
            target.provider_id,
            target.model_id,
            target.endpoint_profile_id,
            target.endpoint_profile_version,
            target.purpose,
            target.scope_digest,
            target.purpose_digest,
        )
        await self._vault.store_provider_credential(
            target.action,
            binding,
            secret,
            proof,
            now_monotonic,
            target_digest=target.target_digest(),
        )
        generation = self._vault._provider_generations.get(binding, 1)  # pyright: ignore[reportPrivateUsage]
        # The credential is the one setup answer nothing downstream can infer. Verify it while
        # the person who can fix it is still here, rather than leaving the first evidence to a
        # failed check hours later whose public reason cannot name authentication.
        if await self._provider_credential_refused(target, binding):
            raise HumanControlError("secret_rejected")
        return ProviderCredentialResult(target.action, generation, "stored")

    async def rotate_vault_passphrase(
        self,
        target: EmptyVaultTarget,
        secret: SecretHandle,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> VaultStateResult:
        target_digest = canonical_digest(human_target_json(target))
        proof.consume(
            "vault_passphrase_rotate",
            target_digest,
            self._lifecycle.instance.generation,
            self._vault.generation,
            None,
            now_monotonic,
        )
        await self._vault.rewrap_passphrase(secret)
        return VaultStateResult("ready", "succeeded")

    async def _provider_credential_refused(
        self, target: ProviderCredentialTarget, binding: object
    ) -> bool:
        """Probe the freshly stored credential; withdraw and report only an outright refusal.

        Returns True only when the provider refused the credential itself. Every other outcome --
        a timeout, an unreachable host, an outage, a model this profile cannot answer for -- keeps
        the credential, because none of them establish that the key is wrong and someone setting
        up on a flaky connection must not lose a good one.
        """

        import os

        from yoetz.adapters.providers.openai_responses_factory import (
            provider_binding_from_config,
        )
        from yoetz.application.egress import (
            PrivacyCoordinator,
            SemanticEgressProviderOutcome,
            SemanticEgressSuccess,
        )
        from yoetz.config.load import load_config
        from yoetz.domain.findings import SemanticFailureClass
        from yoetz.domain.privacy import (
            AuthorizationScope,
            AuthorizationScopeKind,
            CandidateContext,
            CandidateContextItem,
            DataCategory,
        )
        from yoetz.observability.logging import record_bounded_event_without_raising
        from yoetz.ports.semantic import Deadline, SemanticResultInvalid, SemanticResultUnavailable
        from yoetz.protocol.ids import IdKind, new_id

        coordinator = self._privacy_relay.get()
        if type(coordinator) is not PrivacyCoordinator:
            return False
        try:
            provider = load_config({}, os.environ, None).provider
        except Exception:
            return False
        if (
            provider is None
            or provider.provider_id != target.provider_id
            or provider.model != target.model_id
            or provider.endpoint_profile_id != target.endpoint_profile_id
            or provider.endpoint_profile_version != target.endpoint_profile_version
        ):
            # The credential just stored is not the configured destination. Probing would hit a
            # different host or model, so leave the key stored and unverified.
            return False
        try:
            policy_app = coordinator.policy_application
            if policy_app is None or target.repository_privacy_commitment is None:
                return False
            setup_scope = getattr(policy_app, "setup_scope", None)
            if setup_scope is None:
                return False
            request_id = str(new_id(IdKind.REQUEST))
            task_id = str(new_id(IdKind.TASK))
            scope = AuthorizationScope(
                AuthorizationScopeKind.TASK,
                setup_scope.installation_id,
                target.repository_privacy_commitment,
                task_id,
            )
            if not await coordinator.activate_repository(scope):
                return False
            payload = b'{"credential_probe":true}'
            candidate = CandidateContext(
                request_id=request_id,
                channel=EgressChannel.LLM_INFERENCE,
                local_sink=None,
                purpose="credential-probe",
                scope=scope,
                subject_digest="sha256:" + hashlib.sha256(payload).hexdigest(),
                provider_binding=provider_binding_from_config(provider),
                items=(
                    CandidateContextItem(
                        "credential-probe",
                        DataCategory.BOUNDED_STRUCTURAL_METADATA,
                        scope,
                        "/credential-probe",
                        payload,
                    ),
                ),
            )
            result = await coordinator.evaluate_semantic(
                candidate,
                Deadline(
                    policy_app.clock.now_utc(),
                    policy_app.clock.monotonic_seconds() + 30.0,
                ),
            )
        except Exception:
            # A probe must never be why a ceremony fails. An unverified credential is stored.
            return False
        provider_result = result.result if type(result) is SemanticEgressProviderOutcome else None
        failure_class = (
            provider_result.provenance.failure_class if provider_result is not None else None
        )
        rejected = type(provider_result) is SemanticResultUnavailable and failure_class in {
            SemanticFailureClass.AUTHENTICATION,
            SemanticFailureClass.AUTHORIZATION,
        }
        accepted = (
            type(result) is SemanticEgressSuccess
            or type(provider_result) is SemanticResultInvalid
            or (
                type(provider_result) is SemanticResultUnavailable
                and failure_class
                in {SemanticFailureClass.RATE_LIMITED, SemanticFailureClass.QUOTA_EXHAUSTED}
            )
        )
        outcome = "rejected" if rejected else "accepted" if accepted else "unverified"
        record_bounded_event_without_raising(
            component="provider_credential",
            operation=f"credential_probe_{outcome}",
            reason="accepted" if failure_class is None else failure_class.value,
        )
        if not rejected:
            return False
        from yoetz.service.vault import ProviderCredentialBinding

        if type(binding) is ProviderCredentialBinding:
            await self._vault.discard_provider_credential(binding)
        return True

    async def decide_privacy(
        self,
        target: PrivacyPendingTarget,
        decision: str,
        proof: HumanAuthorizationProof | None,
        now_monotonic: float,
    ) -> PrivacyDecisionResult:
        from yoetz.application.privacy_policy import (
            DecidePrivacyPolicyRequest,
            PrivacyPolicyApplication,
            decide_privacy_policy,
        )
        from yoetz.ports.privacy import HumanAuthorityCapability, HumanPolicyDecision

        # Mirrors `prepare`: a bounded disclosure decision needs a ready vault, not passphrase
        # mode. Policy widening, credential changes, and every other elevated operation keep
        # their stronger authority requirement.
        if not self._vault.ready:
            raise HumanControlError("state_forbidden")
        if target.decision_kind != "disclosure" and self._vault.mode.value != "passphrase":
            raise HumanControlError("kind_forbidden")
        app = self._privacy_app()
        if type(app) is not PrivacyPolicyApplication:
            raise HumanControlError("ceremony_unsupported")
        if target.decision_kind == "disclosure":
            from yoetz.domain.privacy import ConsentSource, HumanPrivacyDecision

            proposal = await app.audit.load_disclosure_proposal(target.pending_id)
            now = app.clock.now_utc()
            if proposal is None or proposal.expires_at <= now:
                return PrivacyDecisionResult(
                    "stale", canonical_digest({"pending_id": target.pending_id})
                )
            effective = await app.policy_store.effective_policy(proposal.scope)
            if (
                effective.policy.version != proposal.policy_version
                or effective.effective_digest != proposal.policy_digest
            ):
                return PrivacyDecisionResult("stale", proposal.prepared_case_digest)
            # The proposal must still commit to exactly one destination and to the prepared
            # case the preview bound. Approving one that no longer does would authorize bytes
            # against a destination the user was never shown.
            if proposal.provider_binding is None and proposal.local_sink is None:
                raise HumanControlError("pending_not_actionable")
            if not proposal.prepared_case_digest:
                raise HumanControlError("pending_not_actionable")
            try:
                authority_commitment = self._vault.installation_mac_handle(
                    MacKeyPurpose.PRIVACY_AUDIT
                ).mac(
                    b"yoetz/privacy-audit/local-approval/v1\x00",
                    proposal.prepared_case_digest.encode("ascii"),
                )
                human_decision = HumanPrivacyDecision(
                    proposal.proposal_commitment,
                    decision == "approve",
                    ConsentSource.PER_REQUEST_LOCAL_HUMAN,
                    now,
                    proposal.expires_at if decision == "approve" else None,
                    proposal.prepared_case_digest,
                    authority_commitment,
                )
                await app.audit.record_human_decision(target.pending_id, human_decision)
            except ValueError as exc:
                # The audit record enforces one-use: it accepts a decision only from
                # awaiting_human/reserved, and checks the proposal commitment. A second
                # decision on the same proposal lands here and must not read as a new failure
                # mode — it is a proposal that is no longer decidable.
                raise HumanControlError("pending_not_actionable") from exc
            return PrivacyDecisionResult(
                "committed" if decision == "approve" else "denied",
                proposal.prepared_case_digest,
            )
        if target.decision_kind != "policy":
            raise HumanControlError("kind_forbidden")
        try:
            prepared = await app.policy_store.load_transition(target.pending_id)
        except ValueError as exc:
            if exc.args == ("privacy_policy_transition_unavailable",):
                raise HumanControlError("target_invalid") from exc
            raise HumanControlError("target_invalid") from exc
        target_digest = canonical_digest(human_target_json(target))
        approved = decision == "approve"
        if approved:
            if proof is None:
                raise HumanControlError("reauthentication_unavailable")
            try:
                proof.consume(
                    "privacy_policy_widen",
                    target_digest,
                    self._lifecycle.instance.generation,
                    self._vault.generation,
                    prepared.proposal.expected_generation,
                    now_monotonic,
                )
            except SecretMemoryError as exc:
                raise HumanControlError("stale_generation") from exc
        try:
            authority_commitment = self._vault.installation_mac_handle(
                MacKeyPurpose.PRIVACY_AUDIT
            ).mac(
                b"yoetz/privacy-audit/local-approval/v1\x00",
                prepared.prepared_digest.encode("ascii"),
            )
            service_generation = self._lifecycle.instance.generation
            vault_generation = self._vault.generation
            vault_mode = str(self._vault.mode.value)
            human_decision = HumanPolicyDecision(
                prepared.prepared_digest,
                approved,
                app.clock.now_utc(),
                authority_commitment,
            )
            authority = HumanAuthorityCapability(
                "established_passphrase",
                canonical_digest(
                    {
                        "service_generation": str(service_generation),
                        "source": "established_passphrase",
                        "vault_generation": str(vault_generation),
                        "vault_mode": vault_mode,
                    }
                ),
                service_generation,
                vault_mode,
                vault_generation,
                True,
            )
            await decide_privacy_policy(
                app,
                DecidePrivacyPolicyRequest(prepared, human_decision, authority),
            )
        except ValueError as exc:
            reason = exc.args[0] if exc.args and type(exc.args[0]) is str else ""
            if reason in {
                "privacy_policy_stale",
                "privacy_policy_transition_unavailable",
                "privacy_policy_decision_expired",
                "privacy_policy_decision_mismatch",
            }:
                return PrivacyDecisionResult("stale", prepared.prepared_digest)
            raise HumanControlError("internal_error") from exc
        return PrivacyDecisionResult(
            "committed" if approved else "denied", prepared.prepared_digest
        )

    async def change_idle_relock_policy(
        self,
        target: IdleRelockPolicyTarget,
        proof: HumanAuthorizationProof,
        now_monotonic: float,
    ) -> IdleRelockPolicyResult:
        del target, proof, now_monotonic
        raise HumanControlError("kind_forbidden")

    async def deny_idle_relock_policy(
        self, target: IdleRelockPolicyTarget, now_monotonic: float
    ) -> IdleRelockPolicyResult:
        del target, now_monotonic
        raise HumanControlError("kind_forbidden")


class _HumanConnectionServer:
    def __init__(self, service: HumanControlService) -> None:
        self._service = service

    async def __call__(self, stream: ControlStream) -> None:
        ceremony_id: str | None = None
        error_step: int | None = None
        try:
            opened = await _read_human_envelope(stream)
            if type(opened) is not ClientOpenEnvelope:
                raise HumanControlError("kind_forbidden")
            response: object = await self._service.open_ceremony(opened)
            ceremony_id = cast(str, getattr(response, "ceremony_id"))
            await _write_human_envelope(stream, response)
            while True:
                # ServerOpenedEnvelope (step 1) and later ServerPhaseEnvelope both carry
                # SecretRequiredPhase; the daemon must await YZS1 completion either way,
                # and must still observe a foreground peer that disappears at the prompt.
                phase = getattr(response, "phase", None)
                if isinstance(phase, SecretRequiredPhase):
                    error_step = cast(int, getattr(response, "step")) + 1
                    response = await self._advance_secret_phase(
                        stream, cast(str, getattr(response, "ceremony_id"))
                    )
                else:
                    incoming = await _read_human_envelope(stream)
                    if type(incoming) is ClientActionEnvelope:
                        ceremony_id = incoming.ceremony_id
                        error_step = incoming.step + 1
                        response = await self._service.submit_action(incoming)
                    elif type(incoming) is ClientCancelEnvelope:
                        ceremony_id = incoming.ceremony_id
                        error_step = incoming.step + 1
                        response = await self._service.cancel(incoming.ceremony_id)
                    else:
                        raise HumanControlError("kind_forbidden")
                await _write_human_envelope(stream, response)
                if type(response) is ServerResultEnvelope:
                    await _write_human_envelope(
                        stream,
                        ServerCloseEnvelope(response.ceremony_id, response.step + 1, "completed"),
                    )
                    return
                if type(response) is ServerCloseEnvelope:
                    return
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            code = _human_error_code(exc)
            # Correlation starts only once the client sends an action or the
            # daemon starts a secret ingress step.  A terminal can close just
            # after ServerOpened; that has a ceremony id but no valid next step
            # to put on a correlated error envelope.
            error = ServerErrorEnvelope(
                code,
                False,
                ceremony_id if error_step is not None else None,
                error_step,
            )
            try:
                await _write_human_envelope(stream, error)
                if ceremony_id is not None and error_step is not None:
                    outcome = "cancelled" if code == "cancelled" else "failed"
                    await _write_human_envelope(
                        stream,
                        ServerCloseEnvelope(ceremony_id, error_step + 1, outcome),
                    )
            except Exception:
                pass
        finally:
            # A foreground terminal can disappear between the opened preview and
            # its next action (for example, Ctrl-C at a secret prompt).  The
            # human-control service owns one ceremony globally, so leaving it
            # active would make every later ceremony fail state_forbidden until
            # the daemon is restarted.  A completed/cancelled ceremony has
            # already cleared itself; in that case cancel simply reports replay
            # and is deliberately ignored.
            if ceremony_id is not None:
                try:
                    await self._service.cancel(ceremony_id)
                except Exception:
                    pass
            await stream.aclose()

    async def _advance_secret_phase(self, stream: ControlStream, ceremony_id: str) -> object:
        """Wait for YZS1 or a human-control peer close/cancel, never only the secret socket."""

        secret_wait = asyncio.create_task(self._service.secret_completed(ceremony_id))
        peer_wait = asyncio.create_task(_read_human_envelope(stream))
        done, pending = await asyncio.wait(
            {secret_wait, peer_wait}, return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
        for task in pending:
            try:
                await task
            except asyncio.CancelledError, Exception:
                pass
        if secret_wait in done and not secret_wait.cancelled():
            return secret_wait.result()
        incoming: object | None = None
        if peer_wait in done and not peer_wait.cancelled():
            incoming = peer_wait.result()
        if type(incoming) is ClientCancelEnvelope:
            return await self._service.cancel(incoming.ceremony_id)
        await self._service.cancel(ceremony_id)
        if incoming is None:
            raise HumanControlError("cancelled")
        raise HumanControlError("kind_forbidden")


async def _production_composition(
    *,
    _config: YoetzConfig | None = None,
    _paths: _ProductionPaths | None = None,
    _binders: _ListenerBinders | None = None,
    _ready_application_factory: _ReadyApplicationFactory | None = None,
    _startup_bundle_upgrade: _StartupBundleUpgrade | None = None,
) -> ServiceComposition:
    """Build the real locked-first service graph without opening ready-only state."""

    config = _config or load_config({}, os.environ, None)
    paths = _paths or _ProductionPaths.canonical(config)
    clock = _SystemClock()
    # Instance identity gate (issue #604): an expired disposable instance, a re-pointed runtime
    # pin, or a labeled instance outside its isolated root is refused before the singleton is
    # taken, so the refusal can never replace or contend with another instance's service.
    instance_identity = read_instance_identity(paths.state)
    verify_instance_binding(
        instance_identity,
        isolated=isolated_root() is not None,
        pin=read_runtime_pin(),
        now=clock.now_utc(),
    )
    ensure_owner_only_dir(paths.bundle)
    recovery_sets = InstallationRecoverySetStore(paths.bundle)
    marker_store = _InstallationStateStore(
        paths.bundle / _INSTALLATION_MARKER_NAME,
        paths.throttle,
        paths.generation,
        recovery_sets,
        instance_installation_id=(
            None if instance_identity is None else instance_identity.installation_id
        ),
    )
    # Initial identity discovery is read-only. Reconciliation mutates retained authority and must
    # wait until this process owns the singleton; otherwise a losing second start could interfere
    # with the live service's recovery transaction.
    marker = marker_store.load(reconcile=False)
    installation_id = marker_store.select_installation_id(marker)
    holder_identity: dict[str, str] | None = None
    if instance_identity is not None:
        holder_identity = {"instance_lifecycle": instance_identity.lifecycle}
        if instance_identity.source_ref is not None:
            holder_identity["source_ref"] = instance_identity.source_ref
    production_binders = _binders is None
    listeners = _ProductionListeners(
        _binders
        or _ListenerBinders(
            bind_control_listener,
            bind_secret_listener,
            bind_human_control_listener,
        )
    )
    ready_close_relay = _ReadyCloseRelay()
    lifecycle = ServiceLifecycle(
        clock,
        generation_store=ServiceLifecycle.generation_store(paths.generation, installation_id),
        process_start_identity_commitment=("sha256:" + hashlib.sha256(os.urandom(32)).hexdigest()),
        singleton_lock_path=paths.singleton_lock,
        endpoint_recovery=listeners.recover_stale if production_binders else None,
        endpoint_publisher=listeners.bind,
        endpoint_cleanup=listeners.close,
        close_ready_composition=ready_close_relay,
        holder_identity=holder_identity,
    )
    secret_memory: LocalSecretMemory | None = None
    vault: VaultService | None = None
    try:
        instance = await lifecycle.acquire_singleton()
        reconciled_marker = marker_store.load()
        if marker_store.select_installation_id(reconciled_marker) != installation_id:
            raise RuntimeError("installation_identity_mismatch")
        marker = reconciled_marker
        _discard_orphan_vault_rotation_stages(paths.bundle)
        secret_memory = LocalSecretMemory()
        mode = VaultMode.UNINITIALIZED if marker is None else marker.vault_mode
        vault = VaultService(
            installation_id=installation_id,
            service_generation=instance.generation,
            mode=mode,
            secret_memory=secret_memory,
            clock=clock,
            vault_store_factory=lambda: EncryptedVaultStore(paths.bundle / "vault"),
            root_envelope=None if marker is None else marker.root_envelope,
            user_presence_port=None,
            runtime_support={},
            pristine_state_digest=(
                canonical_digest({"installation_id": installation_id, "state": "pristine"})
                if marker is None
                else None
            ),
            publish_mode=marker_store.publish,
            replace_mode=marker_store.replace_after_recovery,
            replace_passphrase=marker_store.replace_passphrase_envelope,
            replace_root=marker_store.replace_after_root_rotation,
            snapshot_recovery_admission=recovery_sets.admits_clean_restore,
        )
        throttle = UnlockThrottleStore(
            paths.throttle,
            installation_id=installation_id,
            writer_instance_id=instance.instance_id,
            clock=clock,
        )
        auto_unlock_result = "not_applicable"
        auto_unlock_reason = "none"
        if mode is VaultMode.PASSPHRASE:
            # mode_binding_digest is the *initial* throttle digest frozen at passphrase
            # publication (vault.md). Later unlock attempts advance record_digest, so restart
            # must not require equality with the live throttle record — only that passphrase
            # mode has a marker and the throttle store opens for this installation.
            if marker is None:
                raise RuntimeError("installation_throttle_binding_invalid")
            record = throttle.open_for_restart()
            if record.installation_id != installation_id:
                raise RuntimeError("installation_throttle_binding_invalid")
            auto_unlock_store = AutoUnlockPassphraseStore(paths.bundle)
            candidates, load_reason = auto_unlock_store.load_candidates_with_reason()
            if candidates:
                accepted_slot: str | None = None
                try:
                    for auto_passphrase, slot in candidates:
                        try:
                            handle = secret_memory.capture(
                                SecretPurpose.VAULT_UNLOCK, auto_passphrase
                            )
                            await vault.unlock(handle)
                        except VaultError:
                            continue
                        accepted_slot = slot
                        break
                    if accepted_slot is None:
                        auto_unlock_result = "failed"
                        auto_unlock_reason = "auto_unlock_stale"
                except Exception:
                    auto_unlock_result = "failed"
                    auto_unlock_reason = "auto_unlock_rejected"
                finally:
                    for candidate, _slot in candidates:
                        for index in range(len(candidate)):
                            candidate[index] = 0
                if accepted_slot is not None:
                    # Unlock succeeded; the staged keyring entries are hygiene only. A
                    # promote/discard failure must not degrade a ready vault (#492 review).
                    try:
                        _reconcile_staged_slots(auto_unlock_store, accepted_slot)
                    except Exception:
                        get_logger("service.daemon").warning(
                            "auto_unlock",
                            outcome="degraded",
                            reason="staged_reconcile_failed",
                        )
            else:
                auto_unlock_result = (
                    "skipped"
                    if load_reason in {"auto_unlock_absent", "auto_unlock_backend_unavailable"}
                    else "failed"
                )
                auto_unlock_reason = load_reason
            if vault.ready:
                auto_unlock_result = "succeeded"
                auto_unlock_reason = "none"
            if auto_unlock_result != "succeeded":
                get_logger("service.daemon").warning(
                    "auto_unlock",
                    outcome=auto_unlock_result,
                    reason=auto_unlock_reason,
                )
        relay = _ReadyActivationRelay()
        secret_ingress = SecretIngressService(clock, secret_memory, listener=listeners.secret)
        diagnostics = _NullDiagnostics()
        maintenance_gate = asyncio.Lock()
        observation_gate = asyncio.Lock()
        ready_application_factory = (
            _ready_application_factory
            if _ready_application_factory is not None
            else cast(
                _ReadyApplicationFactory,
                build_ready_application_factory(
                    lifecycle=lifecycle,
                    vault=vault,
                    config=config,
                    paths=paths,
                    clock=clock,
                    secret_memory=secret_memory,
                    diagnostics=diagnostics,
                    observation_gate=observation_gate,
                    startup_bundle_upgrade=_startup_bundle_upgrade,
                ),
            )
        )
        unlock = UnlockCoordinator(
            clock=clock,
            throttle=throttle,
            vault=vault,
            lifecycle=lifecycle,
            activate_ready=relay,
        )
        privacy_relay = _PrivacyPolicyAppRelay()
        human = HumanControlService(
            clock=clock,
            lifecycle=lifecycle,
            vault=vault,
            unlock=unlock,
            secret_ingress=secret_ingress,
            effects=_LockedHumanEffects(
                lifecycle,
                vault,
                privacy_relay,
                recovery_sets,
                unlock,
                maintenance_gate,
                observation_gate,
            ),
            user_presence=None,
        )
        return ServiceComposition(
            lifecycle=lifecycle,
            control_listener=listeners.control,
            secret_ingress_listener=listeners.secret,
            human_control_listener=listeners.human,
            human_control_service=human,
            session_monitor=SessionEventMonitor(),
            vault=vault,
            ready_application_factory=ready_application_factory,
            maintenance_gate=maintenance_gate,
            secret_ingress_service=secret_ingress,
            unlock_service=unlock,
            secret_memory=secret_memory,
            diagnostics=diagnostics,
            human_connection_handler=_HumanConnectionServer(human),
            ready_activation_relay=relay,
            ready_close_relay=ready_close_relay,
            privacy_policy_app_relay=privacy_relay,
            auto_unlock_reason=auto_unlock_reason,
            auto_unlock_bundle=paths.bundle,
            session_route_path=paths.state / SESSION_ROUTE_FILE_NAME,
            observation_gate=observation_gate,
        )
    except BaseException:
        await listeners.close()
        if vault is not None:
            await vault.close()
        if secret_memory is not None:
            secret_memory.close()
        try:
            lifecycle_state = lifecycle.state
        except LifecycleError:
            lifecycle_state = None
        if lifecycle_state is ServiceState.STARTING:
            await lifecycle.transition(ServiceState.FAILED)
        await lifecycle.close()
        raise


def _is_sha256(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 71
        and value.startswith("sha256:")
        and all(character in "0123456789abcdef" for character in value[7:])
    )


def _installation_digest(body: dict[str, JsonValue]) -> str:
    return (
        "sha256:" + hashlib.sha256(_INSTALLATION_MARKER_DOMAIN + canonical_encode(body)).hexdigest()
    )


def _read_private_file(path: Path, maximum: int) -> bytes:
    facts = path.lstat()
    if (
        not stat.S_ISREG(facts.st_mode)
        or stat.S_ISLNK(facts.st_mode)
        or facts.st_nlink != 1
        or facts.st_uid != os.geteuid()
        or stat.S_IMODE(facts.st_mode) & 0o077
        or facts.st_size > maximum
    ):
        raise RuntimeError("private_state_unsafe")
    with path.open("rb") as source:
        encoded = source.read(maximum + 1)
    if len(encoded) > maximum:
        raise RuntimeError("private_state_too_large")
    return encoded


def _write_private_atomic(path: Path, encoded: bytes) -> None:
    ensure_owner_only_dir(path.parent)
    temporary = path.with_name(f".{path.name}.{os.urandom(12).hex()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        view = memoryview(encoded)
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
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _bytes_digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_tree_facts(path: Path) -> tuple[int, int]:
    items = 0
    total = 0
    for member in path.rglob("*"):
        facts = member.lstat()
        if stat.S_ISLNK(facts.st_mode) or not (
            stat.S_ISDIR(facts.st_mode) or stat.S_ISREG(facts.st_mode)
        ):
            raise RuntimeError("private_state_unsafe")
        if stat.S_ISREG(facts.st_mode):
            if facts.st_nlink != 1 or stat.S_IMODE(facts.st_mode) & 0o077:
                raise RuntimeError("private_state_unsafe")
            items += 1
            total += facts.st_size
    if items <= 0:
        raise RuntimeError("private_state_empty")
    return items, total


def _remove_private_tree(path: Path) -> None:
    for member in sorted(path.rglob("*"), key=lambda item: len(item.parts), reverse=True):
        facts = member.lstat()
        if stat.S_ISLNK(facts.st_mode):
            raise RuntimeError("private_state_unsafe")
        if stat.S_ISDIR(facts.st_mode):
            member.rmdir()
        elif stat.S_ISREG(facts.st_mode):
            member.unlink()
        else:
            raise RuntimeError("private_state_unsafe")
    path.rmdir()


def _discard_orphan_vault_rotation_stages(bundle: Path) -> None:
    """Remove only trusted-name next-root quarantines after singleton acquisition."""

    for child in bundle.iterdir():
        if not (child.name.startswith(".vault.root-") and child.name.endswith(".tmp")):
            continue
        if not child.is_dir() or child.is_symlink():
            raise RuntimeError("private_state_unsafe")
        _remove_private_tree(child)
    _fsync_directory(bundle)


async def _read_human_envelope(stream: ControlStream) -> object:
    header = await _read_stream_exact(stream, _HUMAN_HEADER.size)
    magic, version, _frame_type, payload_size = _HUMAN_HEADER.unpack(header)
    if (
        magic != HUMAN_PROTOCOL_MAGIC
        or version != HUMAN_PROTOCOL_VERSION
        or payload_size > MAX_HUMAN_CONTROL_FRAME_BYTES
    ):
        raise HumanControlError("phase_invalid")
    payload = await _read_stream_exact(stream, payload_size)
    return decode_human_frame(header + payload)


async def _write_human_envelope(stream: ControlStream, envelope: object) -> None:
    await stream.send_all(encode_human_frame(envelope))  # pyright: ignore[reportArgumentType]


async def _read_stream_exact(stream: ControlStream, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = await stream.receive(remaining)
        if not chunk:
            raise HumanControlError("cancelled")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _human_error_code(exc: Exception) -> str:
    if type(exc) is HumanControlError:
        reason = exc.reason
        if reason in {
            "binding_expired",
            "cancelled",
            # Without these three the mapper collapses them to internal_error, and the bounded
            # ceremony reasons never reach the client that has to act on them.
            "ceremony_unsupported",
            "pending_not_actionable",
            "pending_unavailable",
            "kind_forbidden",
            "phase_invalid",
            "presence_unavailable",
            "reauthentication_unavailable",
            "replay",
            "secret_rejected",
            "stale_generation",
            "state_forbidden",
            "target_invalid",
        }:
            return reason
    return "internal_error"


def _startup_failure(exc: Exception, *, stage: str, correlation_id: str | None) -> Exception:
    """Record a startup failure and return the exception ``run_service`` raises in its place.

    A typed refusal (lifecycle, path-safety, instance-identity or configuration) is recorded under
    its own closed reason token and re-raised unchanged, because the CLI already names each one.
    Anything else is recorded as unexpected and replaced by ``ServiceStartupError``, which the CLI
    renders with its stage, exception class and origin instead of a bare ``internal_error``
    (#1040). Losing the singleton to a live service is not a failure of this start and is not
    recorded: whoever spawned this process connects to the holder instead.
    """

    reason_code: str | None = None
    if isinstance(exc, LifecycleError):
        if exc.reason == "service_already_running":
            return exc
        # ``invalid_transition`` names our own defect; ``yoetz.cli.exits`` keeps it internal.
        reason_code = None if exc.reason == "invalid_transition" else exc.reason
    elif isinstance(exc, PathSafetyError):
        reason_code = exc.reason_code
    elif isinstance(exc, InstanceIdentityError):
        reason_code = exc.reason
    elif isinstance(exc, ConfigError):
        reason_code = exc.reason_code
    failure = record_startup_failure(
        exc, stage=stage, correlation_id=correlation_id, reason_code=reason_code
    )
    return exc if reason_code is not None else ServiceStartupError(failure)


async def run_service(startup_correlation_id: str | None = None) -> Never:
    """Run one foreground service process until a signal requests bounded shutdown.

    ``startup_correlation_id`` is the id a spawning process will look a startup failure up under.
    """

    stage = "configuration"
    daemon: ServiceDaemon | None = None
    try:
        config = load_config({}, os.environ, None)
        configure_logging(config.logging, LogMode.SERVICE)
        stage = "composition"
        composition = await _production_composition(_config=config)
        stage = "activation"
        daemon = ServiceDaemon(_composition=composition)
        await daemon.serve()
    except Exception as exc:
        if daemon is not None and daemon.started:
            stage = "serving"
        replacement = _startup_failure(exc, stage=stage, correlation_id=startup_correlation_id)
        if replacement is exc:
            raise
        raise replacement from exc
    raise SystemExit(0)


def main(*, startup_correlation_id: str | None = None) -> Never:
    """Synchronous installed entry point with one event-loop owner."""

    anyio.run(run_service, startup_correlation_id)
    raise SystemExit(0)
