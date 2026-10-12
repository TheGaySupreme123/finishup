"""CLI controls for live Codex observation consent, status, and stream reconcile."""

from __future__ import annotations

import contextlib
import errno
import functools
import os
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final, Literal, ParamSpec, Protocol, cast

import typer

from yoetz.adapters.approved_checks import ApprovedCheckRunner
from yoetz.adapters.check_sandbox import probe_check_sandbox
from yoetz.adapters.git_subject_state import GitSubjectStateAdapter, open_local_workspace
from yoetz.adapters.integrations.codex_lifecycle import (
    load_mapping,
    scoped_child_session_id,
    validate_codex_session_id,
)
from yoetz.adapters.integrations.codex_marketplace import inspect_activation
from yoetz.adapters.integrations.codex_session_stream import (
    CodexSessionStreamLocator,
    read_codex_child_rollout_header,
    reconcile_session_stream_path,
    resolve_codex_home,
    rollout_filename_matches_token,
)
from yoetz.adapters.integrations.codex_session_stream import (
    reconcile_session_stream as advance_session_stream,
)
from yoetz.adapters.integrations.observation_local import (
    LocalObservationStore,
    ObservationOutboxRow,
    observation_store_lock_scope,
)
from yoetz.adapters.workspace_binding import canonical_workspace_locator
from yoetz.application.observation_check_policy import (
    ObservationCheckPolicyAbsent,
    load_observation_check_policy,
)
from yoetz.application.observation_drain import (
    EXPECTED_OBSERVATION_BACKPRESSURE_REASONS,
    WORKSPACE_GLOBAL_OBSERVATION_STOP_REASONS,
    ObservationControlFailure,
    ObservationDrainAction,
    observation_control_failure,
    route_observation_ingest,
)
from yoetz.application.observation_verification import run_bound_approved_check
from yoetz.cli.exits import exit_code_for, remediation_message
from yoetz.cli.hook_diagnostics import hook_diagnostic_summary
from yoetz.cli.hook_timing import hook_pass_timing_text
from yoetz.cli.render import (
    error_recovery_json,
    local_recovery_json,
    render_error_recovery_lines,
    render_local_recovery_lines,
)
from yoetz.config.paths import PathSafetyError
from yoetz.domain.observation import (
    ObservationControlCommand,
    ObservationGapCode,
    ObservationIngestDisposition,
    ObservationIngestRequest,
    ObservationIngestResult,
    ObservationRevokeCommand,
    ObservationSource,
    ObservationStatusQuery,
    observation_ingest_request_to_json,
    observation_ingest_result_from_json,
    observation_status_to_json,
)
from yoetz.domain.observation_budget import (
    BUDGET_POLICY_VERSION,
    BUDGET_VALIDATION_STATUS,
    LARGEST_CAPACITY,
    BudgetLimits,
    CapacityRequest,
    ObservationCapacity,
    mode_limits,
    no_cap_support,
    parse_capacity_request,
)
from yoetz.domain.observation_capacity_policy import (
    WORKSPACE_PLACEHOLDER,
    capacity_change_disclosure,
    is_closed_token,
    is_safe_command,
    render_capacity_disclosure_lines,
    scope_flag,
)
from yoetz.domain.observation_profiles import validate_content_capture_profile
from yoetz.domain.observation_selection import OBSERVATION_SELECTION_VERSION
from yoetz.domain.observation_settings import (
    DEFAULT_OBSERVATION_SELECTION,
    ObservationDetailProfile,
    ObservationSelection,
    ObservationSelectionResolution,
    ObservationSelectionSetting,
    observation_selection_settings_to_json,
    resolve_observation_selection,
)
from yoetz.domain.values import JsonObject, Timestamp, validate_sha256_digest
from yoetz.domain.values import JsonValue as DomainJsonValue
from yoetz.ports.control import ControlClientKind, ControlError
from yoetz.ports.integrations import IntegrationScope, IntegrationTarget
from yoetz.ports.subject_state import SubjectStateCaptureCommand, SubjectStateFormat
from yoetz.protocol.canonical import JsonValue, canonical_digest, canonical_encode
from yoetz.protocol.errors import ProtocolValueError, PublicErrorCode, PublicOperationError
from yoetz.service.client import connect_service_on_demand

__all__ = [
    "CapacityNoCapUnsupported",
    "apply_selection_preview",
    "build_selection_preview",
    "grant_observation",
    "enable_observation_content",
    "disable_observation_content",
    "observation_content_status",
    "observation_selection_preview",
    "observation_selection_status",
    "protect_observation_read",
    "promote_observation",
    "selection_status_payload",
    "set_observation_selection",
    "revoke_observation_selection",
    "drain_observation",
    "observe_checks_preview",
    "observe_checks_revoke",
    "observe_checks_run",
    "observe_checks_status",
    "observe_checks_trust",
    "observe_status",
    "pause_observation",
    "reconcile_session_stream",
    "resume_observation",
    "revoke_observation",
]

_SETUP_PROBE_SESSION: Final = "yoetz-setup-probe-session"
_DRAIN_DEADLINE_MS: Final = 3_000
_SELECTION_PREVIEW_SCHEMA: Final = "yoetz.observation-selection-preview/2"
_NO_CAP_REASON: Final = "capacity_no_cap_unsupported"
# Structured records a human preview renders as sentences or one summary line.
_HUMAN_RECORD_KEYS: Final = frozenset(
    {"disclosure", "current_effective_budget", "effective_budget"}
)
_CAPACITY_REQUEST_MESSAGES: Final[Mapping[str, str]] = {
    "capacity_queue_count_required": (
        "A custom capacity needs --queue-count between 64 and 8,192."
    ),
    "capacity_queue_count_unsupported": ("The queue count must be between 64 and 8,192 rows."),
}
_CAPACITY_REQUEST_INVALID_MESSAGE: Final = (
    "Capacity must be standard (recommended), larger, largest, custom with --queue-count, or none."
)
_QUEUE_COUNT_WITHOUT_CUSTOM_MESSAGE: Final = "--queue-count is only used with --capacity custom."


class _DrainClient(Protocol):
    async def observation_ingest(
        self, body: DomainJsonValue, *, deadline_ms: int | None = None
    ) -> DomainJsonValue: ...

    async def close(self) -> None: ...


type DrainConnector = Callable[[ControlClientKind], Awaitable[_DrainClient]]


_WORKSPACE_LOCATOR_INVALID: Final = "workspace_locator_invalid"
_UNSAFE_OBSERVATION_STORAGE_ERRNOS: Final = frozenset(
    {
        errno.EISDIR,
        errno.ELOOP,
        errno.ENOTDIR,
    }
)
_P = ParamSpec("_P")


def _session_filename_stem(path: Path) -> str:
    """Remove only admitted stream suffixes while preserving the filename token."""

    name = path.name
    lower_name = name.lower()
    for suffix in (".jsonl.zst", ".jsonl"):
        if lower_name.endswith(suffix):
            return name[: -len(suffix)]
    return path.stem


def _mapped_session_id_from_path(
    path: Path,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    state_root: Path | None,
) -> str | None:
    """Recover one full host session id from an owner-authorized lifecycle mapping.

    Native rollout filenames contain a timestamp prefix and a UUID whose hyphens make
    suffix splitting lossy. A filename is only allowed to select one valid durable
    mapping already bound unambiguously to the selected workspace; an unmapped explicit
    path keeps the legacy recovery fallback below when it is not a native rollout name.
    """

    stem = _session_filename_stem(path)
    if not stem:
        return None
    candidates: list[str] = []
    for session_id in store.unambiguous_codex_sessions_for_workspace(workspace_commitment):
        mapping = load_mapping(session_id, _state=state_root)
        if mapping is None:
            continue
        token = mapping.codex_session_id
        if stem == token or stem.endswith(f"-{token}") or f"-{token}_" in stem:
            candidates.append(token)
    return candidates[0] if len(candidates) == 1 else None


# Closed refusals for a delegated child's own rollout (#841). The token leads so machine readers
# keep one stable prefix; the sentence names the next step without any host or task identity.
_CHILD_ROUTE_REFUSALS: Final[Mapping[str, str]] = {
    "child_identity_invalid": (
        "the rollout declares a delegated child without a usable distinct child and spawning "
        "thread; it cannot be attributed to any task"
    ),
    "child_parent_unmapped": (
        "the session that spawned this child is not mapped to a task in this workspace alone; "
        "reconcile or attach the spawning session first, or select the workspace that owns it"
    ),
    "child_route_missing": (
        "no validated attach is recorded for this child thread; the child must attach with its "
        "delegation handle from a callback that names its own rollout (see observe status hook "
        "diagnostics)"
    ),
    "child_route_ambiguous": (
        "more than one route or workspace claims this child thread; nothing was reconciled"
    ),
}


@dataclass(frozen=True, slots=True)
class _ChildRolloutRoute:
    """Where a delegated child's own rollout may be reconciled, or why it may not.

    ``lane`` is the validated derived child lane; ``reason`` is a closed bounded refusal. Both are
    ``None`` when the file is not a delegated-child rollout, which keeps the ordinary host-session
    recovery rules in charge of it.
    """

    lane: str | None = None
    reason: str | None = None


def _child_rollout_route(
    path: Path,
    *,
    store: LocalObservationStore,
    workspace_commitment: str,
    state_root: Path | None,
) -> _ChildRolloutRoute:
    """Resolve a Codex multi-agent v2 child rollout to its one validated child lane (#841).

    A v2 child rollout is named by the child's own thread, which is never a host session: every
    thread of a delegation tree shares the root ``session_id``, and the accepted child's route is
    the lane derived from that session and the child thread by its validated attach callback.
    Filename matching can therefore never select it. Only the header can: it must name a spawning
    session bound to this workspace alone with a lifecycle mapping, and exactly one lane derived
    from such a session and the header's child thread must already map to a task other than that
    session's own. Nothing here creates a mapping, a task, or an annotation, and no workspace-wide
    stream state or annotation count stands in for that lane.
    """

    result = read_codex_child_rollout_header(path)
    if result.status in {"not_child", "unreadable"}:
        return _ChildRolloutRoute()
    header = result.header
    if result.status != "child" or header is None:
        return _ChildRolloutRoute(reason="child_identity_invalid")
    if not rollout_filename_matches_token(path.name, header.child_thread_id):
        return _ChildRolloutRoute()
    bound = frozenset(store.unambiguous_codex_sessions_for_workspace(workspace_commitment))
    spawning_mapped = False
    lanes: set[str] = set()
    for spawning in header.spawning_sessions:
        if spawning not in bound:
            continue
        spawning_mapping = load_mapping(spawning, _state=state_root)
        if spawning_mapping is None:
            continue
        spawning_mapped = True
        try:
            lane = scoped_child_session_id(
                spawning,
                host="codex",
                identity=header.child_thread_id,
                identity_kind="host",
            )
        except ProtocolValueError:
            continue
        lane_mapping = load_mapping(lane, _state=state_root)
        if lane_mapping is None or lane_mapping.yoetz_task_id == spawning_mapping.yoetz_task_id:
            # No validated child attach published this lane, or the lane still names the
            # spawning session's own task: neither is a child route.
            continue
        if not store.codex_session_workspace_owners(lane) <= {workspace_commitment}:
            return _ChildRolloutRoute(reason="child_route_ambiguous")
        lanes.add(lane)
    if not spawning_mapped:
        return _ChildRolloutRoute(reason="child_parent_unmapped")
    if not lanes:
        return _ChildRolloutRoute(reason="child_route_missing")
    if len(lanes) != 1:
        return _ChildRolloutRoute(reason="child_route_ambiguous")
    return _ChildRolloutRoute(lane=next(iter(lanes)))


def _resolve_workspace(path: str | None) -> Path:
    root = canonical_workspace_locator("." if path is None else path)
    if root is None:
        raise ValueError(_WORKSPACE_LOCATOR_INVALID)
    return Path(root)


def _typed_failure(
    operation: str,
    reason: str,
    *,
    code: PublicErrorCode,
    message: str,
    retryable: bool,
    json_output: bool,
    recovery_lines: Sequence[str] = (),
    recovery_json: Mapping[str, JsonValue] | None = None,
    capacity_json: Mapping[str, JsonValue] | None = None,
) -> int:
    """Report one bounded failure that names its layer, never `internal_error` (#428).

    The token comes first so existing machine-readable expectations hold; the
    remediation follows it, and the typed recovery directive follows that on its
    own lines (ADR-030, issue #741). JSON callers get the same facts as one
    object, with the directive this renderer resolved from the registry under
    ``recovery``; ``recovery.continuation`` is the stable key, the prose is advisory.
    Capacity facts for a no-cap refusal travel beside it under ``capacity``.
    """

    if json_output:
        error: dict[str, JsonValue] = {
            "code": code.value,
            "message": message,
            "operation": operation,
            "reason": reason,
            "retryable": retryable,
        }
        if recovery_json is not None:
            error["recovery"] = dict(recovery_json)
        if capacity_json is not None:
            error["capacity"] = dict(capacity_json)
        _emit({"error": error}, json_output=True)
    else:
        lines = [f"observation_{operation}_failed:{reason}: {message}", *recovery_lines]
        typer.echo("\n".join(lines), err=True)
    return exit_code_for(code)


def _bounded_operation(operation: str) -> Callable[[Callable[_P, int]], Callable[_P, int]]:
    """Map the closed pre-store failures of an observe verb to typed public outcomes.

    An empty, missing, or unsafe `--workspace` locator, an unsafe local state
    path, and a bounded storage refusal each name a true operating condition;
    letting them escape to the process catch-all reported all three as
    `internal_error` exit 70 with no next step (#428).
    """

    def decorate(function: Callable[_P, int]) -> Callable[_P, int]:
        @functools.wraps(function)
        def wrapped(*args: _P.args, **kwargs: _P.kwargs) -> int:
            json_output = kwargs.get("json_output", False) is True
            try:
                # Attribute any store-lock hold or wait to this command (#689).
                with observation_store_lock_scope(role="cli"):
                    return function(*args, **kwargs)
            except ValueError as error:
                if str(error) != _WORKSPACE_LOCATOR_INVALID:
                    raise
                return _typed_failure(
                    operation,
                    "workspace_unresolvable",
                    code=PublicErrorCode.INVALID_REQUEST,
                    message=remediation_message("workspace_unresolvable") or "",
                    retryable=False,
                    json_output=json_output,
                    recovery_lines=render_local_recovery_lines("workspace_unresolvable"),
                    recovery_json=local_recovery_json("workspace_unresolvable"),
                )
            except PathSafetyError:
                return _typed_failure(
                    operation,
                    "storage_unsafe",
                    code=PublicErrorCode.STORAGE_UNSAFE,
                    message=remediation_message("storage_unsafe") or "",
                    retryable=False,
                    json_output=json_output,
                    recovery_lines=render_local_recovery_lines("storage_unsafe"),
                    recovery_json=local_recovery_json("storage_unsafe"),
                )
            except CapacityNoCapUnsupported as error:
                # The explanation is the message; the remaining sentences and
                # the supported alternative precede the typed directive
                # (ADR-030), and JSON carries the facts beside ``recovery``.
                return _typed_failure(
                    operation,
                    _NO_CAP_REASON,
                    code=PublicErrorCode.INVALID_REQUEST,
                    message=error.message,
                    retryable=False,
                    json_output=json_output,
                    recovery_lines=(
                        *(line for line in error.lines if line != error.message),
                        f"Alternative: {error.alternative_command}",
                        *render_local_recovery_lines(_NO_CAP_REASON),
                    ),
                    recovery_json=local_recovery_json(_NO_CAP_REASON),
                    capacity_json=JsonObject(
                        {
                            "no_cap": error.no_cap,
                            "alternative_command": error.alternative_command,
                        }
                    ),
                )
            except PublicOperationError as error:
                return _typed_failure(
                    operation,
                    error.code.value.lower(),
                    code=error.code,
                    message=error.message,
                    retryable=error.retryable,
                    json_output=json_output,
                    recovery_lines=render_error_recovery_lines(error.safe_details),
                    recovery_json=error_recovery_json(error.safe_details),
                )
            except BrokenPipeError:
                # A closed output consumer is not an observation-store failure.
                raise
            except OSError as error:
                if error.errno in _UNSAFE_OBSERVATION_STORAGE_ERRNOS:
                    return _typed_failure(
                        operation,
                        "storage_unsafe",
                        code=PublicErrorCode.STORAGE_UNSAFE,
                        message=remediation_message("storage_unsafe") or "",
                        retryable=False,
                        json_output=json_output,
                        recovery_lines=render_local_recovery_lines("storage_unsafe"),
                        recovery_json=local_recovery_json("storage_unsafe"),
                    )
                return _typed_failure(
                    operation,
                    "storage_unavailable",
                    code=PublicErrorCode.SERVICE_UNAVAILABLE,
                    message=remediation_message("storage_unavailable") or "",
                    retryable=True,
                    json_output=json_output,
                    recovery_lines=render_local_recovery_lines("storage_unavailable"),
                    recovery_json=local_recovery_json("storage_unavailable"),
                )

        return wrapped

    return decorate


def _emit(payload: Mapping[str, JsonValue], *, json_output: bool) -> None:
    if json_output:
        typer.echo(canonical_encode(payload).decode("utf-8"))
        return
    for key, value in payload.items():
        typer.echo(f"{key}: {value}")


def _activation_state(
    root: Path,
    *,
    codex_path: Path | None,
    codex_home: Path | None,
) -> str:
    # Activation is a claim about one selected executable and its corresponding home/cache.
    # Never infer that target from ambient process state.
    if codex_path is None or codex_home is None:
        return "unknown"
    try:
        target = IntegrationTarget(IntegrationScope.TRUSTED_PROJECT, os.fspath(root))
        return inspect_activation(
            target,
            executable_path=os.fspath(codex_path),
            codex_home=codex_home,
        ).state.value
    except Exception:
        return "unknown"


@dataclass(frozen=True, slots=True)
class _DeliveryFacts:
    undelivered: int
    pending_causes: dict[str, int]
    last_drain: str
    mapping_present: bool
    # Receipt time of the oldest pending row (its hook received the host event
    # then), or None when nothing is pending. Read with ``last_successful_drain``:
    # a recent oldest row means delivery is keeping pace with the producer; an
    # old one under a fresh drain means the backlog is being worked through
    # from the head; an old one under a stale drain means delivery is stuck and
    # ``pending_delivery_causes`` names why (#564).
    oldest_pending_receipt: str | None


@dataclass(frozen=True, slots=True)
class _ContentCaptureFacts:
    """Requested ordinary profiles and their current local configuration fences."""

    requested_profiles: tuple[str, ...]
    effective_profiles: tuple[str, ...]
    consent_active: bool
    runtime_enabled: bool

    @property
    def enabled(self) -> bool:
        return bool(self.effective_profiles)


class CapacityNoCapUnsupported(PublicOperationError):
    """Typed outcome for a no-cap request on the structural queue.

    The structural queue has no uncapped mode in this storage revision (the
    local state document has a fixed safety ceiling).  Preview and apply raise
    this instead of changing anything; every owner surface reports it as the
    non-retryable ``capacity_no_cap_unsupported`` reason with the rendered
    explanation and the largest supported finite alternative.
    """

    no_cap: JsonObject
    disclosure: JsonObject
    lines: tuple[str, ...]
    alternative_command: str

    def __init__(self, *, disclosure: JsonObject, alternative_command: str) -> None:
        lines = render_capacity_disclosure_lines(disclosure)
        super().__init__(PublicErrorCode.INVALID_REQUEST, lines[0], retryable=False)
        object.__setattr__(self, "no_cap", no_cap_support())
        object.__setattr__(self, "disclosure", disclosure)
        object.__setattr__(self, "lines", lines)
        object.__setattr__(self, "alternative_command", alternative_command)


def _selection_detail_from_cli(detail: str) -> ObservationDetailProfile:
    """Parse the closed detail vocabulary without trusting free text."""

    try:
        return ObservationDetailProfile.from_value(detail.casefold())
    except (AttributeError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation detail must be focused or detailed.",
            retryable=False,
        ) from exc


def _capacity_request_from_cli(capacity: str, queue_count: int | None) -> CapacityRequest:
    """Parse ``--capacity`` (and ``--queue-count``) into one closed capacity request."""

    try:
        return parse_capacity_request(capacity, queue_count=queue_count)
    except (AttributeError, TypeError, ValueError) as exc:
        message = _CAPACITY_REQUEST_MESSAGES.get(str(exc))
        if message is None:
            message = _CAPACITY_REQUEST_INVALID_MESSAGE
            if queue_count is not None:
                with contextlib.suppress(AttributeError, TypeError, ValueError):
                    parse_capacity_request(capacity)
                    message = _QUEUE_COUNT_WITHOUT_CUSTOM_MESSAGE
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            message,
            retryable=False,
        ) from exc


def _selection_expiry(value: str | None) -> Timestamp | None:
    if value is None:
        return None
    try:
        return Timestamp(value)
    except (TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection expiry is invalid.",
            retryable=False,
        ) from exc


def _validated_selection_session_id(value: str) -> str:
    """Validate the complete host session identity before deriving a commitment."""

    try:
        return validate_codex_session_id(value)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation session id is invalid.",
            retryable=False,
        ) from exc


def _selection_session_commitment(
    store: LocalObservationStore,
    session_id: str | None,
) -> str | None:
    if session_id is None:
        return None
    return store.session_commitment(_validated_selection_session_id(session_id))


def _selection_resolution_payload(
    resolution: ObservationSelectionResolution,
) -> JsonObject:
    selection = resolution.selection
    return JsonObject(
        {
            "detail": selection.detail.value,
            "mode": selection.detail.value,
            "capacity": selection.capacity.queue_count,
            "capacity_profile": selection.capacity.label,
            "queue_count": selection.queue_count,
            "origin": resolution.origin,
            "expires_at": None if resolution.expires_at is None else resolution.expires_at.wire,
        }
    )


def _selection_accounting_payload(
    store: LocalObservationStore,
    commitment: str,
) -> JsonObject:
    accounting = getattr(store, "selection_accounting", None)
    if not callable(accounting):
        return JsonObject({})
    try:
        raw = accounting(commitment)
    except OSError, ProtocolValueError, TypeError, ValueError, RuntimeError:
        return JsonObject({})
    if not isinstance(raw, Mapping):
        return JsonObject({})
    return JsonObject(cast(Mapping[str, JsonValue], raw))


def _selection_authority_digest(
    store: LocalObservationStore,
    commitment: str,
) -> str:
    """Commit the current local consent fence without reading content."""

    consent = store.consent_for(commitment)
    payload: dict[str, JsonValue] = {
        "kind": "observation-selection-authority/v1",
        "workspace_commitment": commitment,
        "runtime_gate_generation": store.runtime_gate_generation(),
        "consent": None,
    }
    if consent is not None:
        payload["consent"] = JsonObject(
            {
                "workspace_commitment": consent.workspace_commitment,
                "granted_at": consent.granted_at.wire,
                "revoked_at": None if consent.revoked_at is None else consent.revoked_at.wire,
                "paused": consent.paused,
                "content_capture_profiles": consent.content_capture_profiles,
            }
        )
    return canonical_digest(JsonObject(payload))


def _selection_runtime_payload(
    store: LocalObservationStore,
    commitment: str,
    session_commitment: str | None,
) -> JsonObject | None:
    """Read the adapter's bounded pressure projection when this revision provides it."""

    runtime_status = getattr(store, "selection_runtime_status", None)
    if not callable(runtime_status):
        return None
    try:
        raw = runtime_status(commitment, session_commitment)
    except OSError, ProtocolValueError, TypeError, ValueError, RuntimeError:
        return None
    if not isinstance(raw, Mapping):
        return None
    snapshot = dict(cast(Mapping[str, JsonValue], raw))
    budget_policy_version = snapshot.get("policy_version", BUDGET_POLICY_VERSION)
    selected_mode = snapshot.get("selected_mode", DEFAULT_OBSERVATION_SELECTION.detail.value)
    effective_mode = snapshot.get("effective_mode", selected_mode)
    selected_capacity = snapshot.get(
        "selected_capacity", DEFAULT_OBSERVATION_SELECTION.capacity.queue_count
    )
    effective_capacity = snapshot.get("effective_capacity", selected_capacity)
    selected_profile = _selection_capacity_profile(selected_capacity)
    effective_profile = _selection_capacity_profile(effective_capacity)
    origin = snapshot.get("selection_origin", "default")
    expires_at = snapshot.get("selection_expires_at")
    selected = JsonObject(
        {
            "detail": selected_mode,
            "mode": selected_mode,
            "capacity": selected_capacity,
            "capacity_profile": selected_profile,
            "queue_count": selected_capacity,
            "origin": origin,
            "expires_at": expires_at,
        }
    )
    effective = JsonObject(
        {
            "detail": effective_mode,
            "mode": effective_mode,
            "capacity": effective_capacity,
            "capacity_profile": effective_profile,
            "queue_count": effective_capacity,
            "origin": origin,
            "expires_at": expires_at,
        }
    )
    snapshot["selected"] = selected
    snapshot["effective"] = effective
    snapshot["effective_reason"] = (
        "pressure_downgrade" if selected_mode != effective_mode else "selected"
    )
    snapshot["accounting"] = _selection_accounting_payload(store, commitment)
    snapshot["session_commitment"] = session_commitment
    snapshot["session_scope"] = session_commitment is not None
    snapshot["policy_version"] = OBSERVATION_SELECTION_VERSION
    snapshot["budget_policy_version"] = budget_policy_version
    snapshot["validation_status"] = snapshot.get("validation_status", BUDGET_VALIDATION_STATUS)
    snapshot["content_authority_changed"] = False
    snapshot["privacy_authority_changed"] = False
    return JsonObject(snapshot)


def _selection_capacity_profile(value: object) -> str:
    try:
        return ObservationCapacity.from_value(value).label
    except TypeError, ValueError:
        return DEFAULT_OBSERVATION_SELECTION.capacity.label


def _validate_selection_scope(
    scope: Literal["workspace", "session"],
    session_commitment: str | None,
) -> None:
    if scope not in {"workspace", "session"}:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection scope is invalid.",
            retryable=False,
        )
    if scope == "session" and session_commitment is None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "A session id is required for a temporary selection.",
            retryable=False,
        )
    if scope == "workspace" and session_commitment is not None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "A workspace selection cannot carry a session id.",
            retryable=False,
        )


def _capacity_request_payload(request: CapacityRequest) -> JsonObject:
    return JsonObject(
        {
            "kind": request.kind,
            "queue_count": None if request.capacity is None else request.capacity.queue_count,
        }
    )


def _selection_disclosure(
    current: ObservationSelectionResolution,
    request: CapacityRequest,
    *,
    scope: Literal["workspace", "session"],
    detail: ObservationDetailProfile,
) -> JsonObject:
    return capacity_change_disclosure(
        current=current.selection.capacity,
        current_origin=current.origin,
        requested=request,
        scope=scope,
        detail=detail,
    )


def _selection_preview_plan(
    store: LocalObservationStore,
    commitment: str,
    selection: ObservationSelection,
    *,
    session_commitment: str | None,
    scope: Literal["workspace", "session"],
    expires_at: Timestamp | None,
    capacity_request: CapacityRequest | None = None,
) -> tuple[JsonObject, str]:
    """Build the exact owner-choice preimage used by preview and apply."""

    _validate_selection_scope(scope, session_commitment)
    request = (
        CapacityRequest.for_capacity(selection.capacity)
        if capacity_request is None
        else capacity_request
    )
    if request.capacity != selection.capacity:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection is invalid.",
            retryable=False,
        )

    settings = store.selection_settings_for(commitment)
    # Constructing the setting validates expiry against the store's trusted wall clock and gives
    # the aggregate-capacity calculation the same candidate that apply will persist.  ``set_at``
    # is deliberately omitted from the digest: it is bookkeeping, while the owner-selected
    # selection/scope/expiry and the current durable setting/authority generations are the
    # reviewed inputs.
    now_fn = getattr(store, "_wall_timestamp", None)
    if not callable(now_fn):
        raise PublicOperationError(
            PublicErrorCode.SERVICE_UNAVAILABLE,
            "Observation selection timing is unavailable.",
            retryable=True,
        )
    set_at = cast(Callable[[], Timestamp], now_fn)()
    try:
        candidate = ObservationSelectionSetting(selection, set_at, expires_at)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection expiry is invalid or already elapsed.",
            retryable=False,
        ) from exc
    proposed = (
        settings.with_workspace(candidate)
        if scope == "workspace"
        else settings.with_session(cast(str, session_commitment), candidate)
    )
    aggregate = proposed.aggregate_capacity(now=set_at)
    limits = BudgetLimits.for_capacity(aggregate)
    mode = mode_limits(selection.detail)
    current = resolve_observation_selection(
        settings,
        session_commitment=session_commitment,
    )
    disclosure = _selection_disclosure(
        current,
        request,
        scope=scope,
        detail=selection.detail,
    )
    runtime = _selection_runtime_payload(store, commitment, session_commitment)
    pressure = "healthy" if runtime is None else runtime.get("pressure_state", "healthy")
    current_budget = None if runtime is None else runtime.get("effective_budget")
    accounting = _selection_accounting_payload(store, commitment)
    authority_digest = _selection_authority_digest(store, commitment)
    settings_digest = canonical_digest(observation_selection_settings_to_json(settings))
    costs: JsonObject = JsonObject(
        {
            "queue_count_limit": limits.queue_count,
            "queue_bytes_limit": limits.queue_bytes,
            "state_bytes_limit": limits.state_bytes,
            "pending_attempt_limit": limits.pending_attempts,
            "capture_ticket_limit": limits.capture_tickets,
            "capture_bytes_limit": limits.capture_bytes,
            "protected_count_reserve": limits.protected_count,
            "protected_bytes_reserve": limits.protected_bytes,
            "session_fair_share": limits.session_fair_share,
            "session_fair_share_bytes": limits.session_fair_share_bytes,
            "max_records_per_summary": mode.max_records_per_summary,
            "max_optional_bytes": mode.max_optional_bytes,
            "max_input_bytes": mode.max_input_bytes,
            "max_output_bytes": mode.max_output_bytes,
        }
    )
    # The acceptance digest binds only owner-selected inputs and stable policy
    # facts, including the requested count and the disclosed change. Live
    # pressure/accounting and the current effective budget are shown below for
    # the owner's decision, but an incoming hook or a drain between preview and
    # apply must not make the exact owner choice unusable. A changed setting or
    # consent fence does invalidate the digest and requires a fresh review.
    stable_plan = JsonObject(
        {
            "schema": _SELECTION_PREVIEW_SCHEMA,
            "selection_policy_version": OBSERVATION_SELECTION_VERSION,
            "budget_policy_version": BUDGET_POLICY_VERSION,
            "validation_status": BUDGET_VALIDATION_STATUS,
            "workspace_commitment": commitment,
            "scope": scope,
            "session_commitment": session_commitment,
            "selection_settings_digest": settings_digest,
            "authority_generation": authority_digest,
            "requested_selection": _selection_resolution_payload(
                ObservationSelectionResolution(selection, scope, expires_at)
            ),
            "capacity_request": _capacity_request_payload(request),
            "current_selection": _selection_resolution_payload(current),
            "aggregate_capacity": aggregate.queue_count,
            "aggregate_capacity_profile": aggregate.label,
            "costs": costs,
            "disclosure": disclosure,
            "content_authority_changed": False,
            "privacy_authority_changed": False,
        }
    )
    display_plan = JsonObject(
        {
            **dict(stable_plan),
            "current_effective_budget": JsonObject(
                cast(Mapping[str, JsonValue], current_budget)
                if isinstance(current_budget, Mapping)
                else {}
            ),
            "pressure_state": pressure,
            "accounting": accounting,
        }
    )
    return display_plan, canonical_digest(stable_plan)


def _no_cap_unsupported(
    store: LocalObservationStore,
    commitment: str,
    *,
    detail: ObservationDetailProfile,
    capacity: CapacityRequest,
    scope: Literal["workspace", "session"],
    session_commitment: str | None,
) -> CapacityNoCapUnsupported:
    current = resolve_observation_selection(
        store.selection_settings_for(commitment),
        session_commitment=session_commitment,
    )
    disclosure = _selection_disclosure(
        current,
        capacity,
        scope=scope,
        detail=detail,
    )
    alternative_command = (
        f"yoetz observe selection-preview --workspace {WORKSPACE_PLACEHOLDER} "
        f"--detail {detail.value} --capacity {LARGEST_CAPACITY.label} {scope_flag(scope)}"
    )
    if not is_safe_command(alternative_command):
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection is invalid.",
            retryable=False,
        )
    return CapacityNoCapUnsupported(
        disclosure=disclosure,
        alternative_command=alternative_command,
    )


def _checked_selection(
    detail: ObservationDetailProfile,
    capacity: CapacityRequest,
) -> ObservationSelection:
    if type(capacity) is not CapacityRequest or capacity.capacity is None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection is invalid.",
            retryable=False,
        )
    try:
        return ObservationSelection(detail, capacity.capacity)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection is invalid.",
            retryable=False,
        ) from exc


def _selection_apply_command(
    selection: ObservationSelection,
    *,
    scope: Literal["workspace", "session"],
    expires_at: Timestamp | None,
    preview_digest: str,
) -> str:
    capacity = selection.capacity
    capacity_arguments = (
        f"--capacity custom --queue-count {capacity.queue_count}"
        if capacity.profile is None
        else f"--capacity {capacity.label}"
    )
    expiry = "" if expires_at is None else f"--expires-at {expires_at.wire} "
    command = (
        f"yoetz observe selection-apply --workspace {WORKSPACE_PLACEHOLDER} "
        f"--detail {selection.detail.value} {capacity_arguments} {scope_flag(scope)} {expiry}"
        f"--accept --preview-digest {preview_digest}"
    )
    if not is_safe_command(command):
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation selection is invalid.",
            retryable=False,
        )
    return command


def build_selection_preview(
    store: LocalObservationStore,
    commitment: str,
    *,
    detail: ObservationDetailProfile,
    capacity: CapacityRequest,
    scope: Literal["workspace", "session"],
    session_commitment: str | None,
    expires_at: Timestamp | None,
) -> JsonObject:
    """Return the owner preview for one detail/capacity request without changing state.

    Shared by the CLI and the terminal interface. The payload carries the
    display plan, the exact ``preview_digest`` that apply must accept, the
    structured capacity-change ``disclosure``, the current effective budget,
    and the apply command. A no-cap request raises
    :class:`CapacityNoCapUnsupported` and changes nothing.
    """

    _validate_selection_scope(scope, session_commitment)
    if type(capacity) is CapacityRequest and capacity.kind == "no_cap":
        raise _no_cap_unsupported(
            store,
            commitment,
            detail=detail,
            capacity=capacity,
            scope=scope,
            session_commitment=session_commitment,
        )
    selection = _checked_selection(detail, capacity)
    plan, preview_digest = _selection_preview_plan(
        store,
        commitment,
        selection,
        session_commitment=session_commitment,
        scope=scope,
        expires_at=expires_at,
        capacity_request=capacity,
    )
    return JsonObject(
        {
            **dict(plan),
            "preview": True,
            "preview_digest": preview_digest,
            "acceptance": "explicit_preview_digest",
            "apply_requires_owner": True,
            "capacity_validation": "provisional",
            "next_command": _selection_apply_command(
                selection,
                scope=scope,
                expires_at=expires_at,
                preview_digest=preview_digest,
            ),
        }
    )


def apply_selection_preview(
    store: LocalObservationStore,
    commitment: str,
    *,
    detail: ObservationDetailProfile,
    capacity: CapacityRequest,
    scope: Literal["workspace", "session"],
    session_commitment: str | None,
    expires_at: Timestamp | None,
    preview_digest: str | None,
    accept: bool,
) -> JsonObject:
    """Apply one owner-accepted preview; the digest must match the current exact plan.

    Requires ``accept`` and the exact ``preview_digest`` from
    :func:`build_selection_preview`; a digest for another plan is refused as
    stale. A no-cap request raises :class:`CapacityNoCapUnsupported` and
    changes nothing. The result carries the applied selection, the
    disclosure, and the effective budget read back after the change.
    """

    _validate_selection_scope(scope, session_commitment)
    if type(capacity) is CapacityRequest and capacity.kind == "no_cap":
        raise _no_cap_unsupported(
            store,
            commitment,
            detail=detail,
            capacity=capacity,
            scope=scope,
            session_commitment=session_commitment,
        )
    selection = _checked_selection(detail, capacity)
    plan, expected_digest = _selection_preview_plan(
        store,
        commitment,
        selection,
        session_commitment=session_commitment,
        scope=scope,
        expires_at=expires_at,
        capacity_request=capacity,
    )
    if accept is not True or preview_digest is None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "An exact observation selection preview must be accepted with --accept and its "
            "--preview-digest.",
            retryable=False,
        )
    try:
        validate_sha256_digest(preview_digest)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "The observation selection preview digest is invalid.",
            retryable=False,
        ) from exc
    if preview_digest != expected_digest:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "The observation selection preview is stale; run selection-preview again.",
            retryable=False,
        )
    setting = (
        store.set_workspace_selection(commitment, selection, expires_at=expires_at)
        if scope == "workspace"
        else store.set_session_selection(
            commitment,
            cast(str, session_commitment),
            selection,
            expires_at=expires_at,
        )
    )
    runtime = _selection_runtime_payload(store, commitment, session_commitment)
    effective_budget = None if runtime is None else runtime.get("effective_budget")
    return JsonObject(
        {
            **dict(plan),
            "workspace_commitment": commitment,
            "selection": _selection_resolution_payload(
                ObservationSelectionResolution(selection, scope, setting.expires_at)
            ),
            "scope": scope,
            "session_commitment": session_commitment,
            "preview_digest": expected_digest,
            "accepted_preview_digest": preview_digest,
            "applied": True,
            "capacity_validation": "provisional",
            "effective_budget": JsonObject(
                cast(Mapping[str, JsonValue], effective_budget)
                if isinstance(effective_budget, Mapping)
                else {}
            ),
            "content_authority_changed": False,
            "privacy_authority_changed": False,
        }
    )


def selection_status_payload(
    store: LocalObservationStore,
    commitment: str,
    *,
    session_id: str | None = None,
) -> JsonObject:
    """Build a read-only selected/effective projection for owner status surfaces."""

    session_commitment = _selection_session_commitment(store, session_id)
    settings = store.selection_settings_for(commitment)
    resolution = resolve_observation_selection(
        settings,
        session_commitment=session_commitment,
    )
    runtime = _selection_runtime_payload(store, commitment, session_commitment)
    if runtime is not None:
        return runtime
    selected = _selection_resolution_payload(resolution)
    # Keep this fallback structural and conservative when an older local store has no pressure
    # projection: selection alone never widens content or privacy authority.
    effective = selected
    accounting = _selection_accounting_payload(store, commitment)
    return JsonObject(
        {
            "policy_version": OBSERVATION_SELECTION_VERSION,
            "selected": selected,
            "effective": effective,
            "effective_reason": "selected",
            "session_scope": session_id is not None,
            "session_commitment": session_commitment,
            "accounting": accounting,
            "privacy_authority_changed": False,
            "content_authority_changed": False,
        }
    )


def _content_capture_facts(store: LocalObservationStore, commitment: str) -> _ContentCaptureFacts:
    """Read the local consent and runtime fences as one status snapshot."""

    authority = store.content_capture_authority(commitment)
    if authority is None:
        return _ContentCaptureFacts((), (), False, store.runtime_enabled())
    effective = authority.profiles if authority.active and authority.runtime_enabled else ()
    return _ContentCaptureFacts(
        requested_profiles=authority.profiles,
        effective_profiles=effective,
        consent_active=authority.active,
        runtime_enabled=authority.runtime_enabled,
    )


def _delivery_facts(
    store: LocalObservationStore, commitment: str, *, state_root: Path | None
) -> _DeliveryFacts:
    rows = store.list_pending_outbox_rows(commitment)
    causes: dict[str, int] = {}
    for row in rows:
        reason = row.last_reason or "not_attempted"
        causes[reason] = causes.get(reason, 0) + 1
    last_mono = store.last_successful_drain_mono(commitment)
    last = "never" if last_mono is None else f"{max(0.0, time.monotonic() - last_mono):.1f}s ago"
    mapping_present = any(
        load_mapping(session, _state=state_root) is not None
        for session in store.codex_sessions_for_workspace(commitment)
    )
    oldest = min((row.envelope.receipt_time for row in rows), default=None)
    return _DeliveryFacts(
        undelivered=len(rows),
        pending_causes=dict(sorted(causes.items())),
        last_drain=last,
        mapping_present=mapping_present,
        oldest_pending_receipt=None if oldest is None else oldest.wire,
    )


def _capture_handoff_retirement_text(retirements: JsonObject) -> str:
    """Render the bounded handoff-retirement account on one status line."""

    count = retirements.get("retired_count")
    recent = retirements.get("recent")
    entries: tuple[Mapping[str, object], ...] = ()
    if isinstance(recent, tuple):
        entries = tuple(
            cast(Mapping[str, object], item)
            for item in cast(tuple[object, ...], recent)
            if isinstance(item, Mapping)
        )
    if not count:
        return "none"
    details = "; ".join(
        f"{entry.get('stage')} {entry.get('ticket_state')} {entry.get('source')} "
        f"reason {entry.get('reason')}"
        + (
            f" ({entry.get('quarantine_reason')})"
            if entry.get("quarantine_reason") is not None
            else ""
        )
        + f" age {entry.get('age_ms')}ms at {entry.get('retired_at')}"
        for entry in entries[-4:]
    )
    return f"{count} (recent: {details or 'none'})"


@_bounded_operation("status")
def observe_status(
    *,
    workspace: str | None,
    json_output: bool,
    codex_path: Path | None = None,
    codex_home: Path | None = None,
    _state: Path | None = None,
) -> int:
    store = LocalObservationStore(_state=_state)
    root = _resolve_workspace(workspace)
    commitment = store.workspace_commitment(str(root))
    consent = store.consent_for(commitment)
    content_facts = _content_capture_facts(store, commitment)
    content_profiles = content_facts.requested_profiles
    selection_status = selection_status_payload(store, commitment)
    with contextlib.suppress(Exception):
        store.refresh_advice(commitment)
    status = store.status(ObservationStatusQuery(commitment))
    snapshot = store.advice_snapshot_for(commitment)
    delivery = _delivery_facts(store, commitment, state_root=_state)
    undelivered = delivery.undelivered
    pending_delivery_causes = delivery.pending_causes
    last_drain = delivery.last_drain
    mapping_present = delivery.mapping_present
    quarantine_depth, quarantine_evicted, quarantine_reclaimed = store.quarantine_facts(commitment)
    # Per-reason depth, so a destroyed-and-replaced-by-gap event (e.g. cursor_stale, #272)
    # is visible as its cause instead of hiding inside one opaque depth number.
    quarantine_causes: dict[str, int] = {}
    for entry in store.list_quarantine(commitment):
        quarantine_causes[entry[2]] = quarantine_causes.get(entry[2], 0) + 1
    quarantine_causes = dict(sorted(quarantine_causes.items()))
    delivery_causes = dict(pending_delivery_causes)
    for reason, count in quarantine_causes.items():
        delivery_causes[reason] = delivery_causes.get(reason, 0) + count
    delivery_causes = dict(sorted(delivery_causes.items()))
    plugin_activation = _activation_state(
        root,
        codex_path=codex_path,
        codex_home=codex_home,
    )
    diagnostics = hook_diagnostic_summary(_state=_state)
    # A refused routine-read summary costs only its lane's bounded account, but
    # an operator must be able to name that cause instead of reading a bare
    # "incomplete or stale" coverage note (issue #753).
    summary_refusals = store.summary_refusals(commitment)
    # A retired native capture handoff names the stage, ticket state, and reason
    # that stranded it, so a retained ticket that held capture pressure can be
    # traced to its transition (issue #836).
    handoff_retirements = store.capture_handoff_retirements(commitment)
    reclaim_guidance = (
        "reclaim with 'yoetz observe reclaim --workspace .'"
        if root == Path.cwd().resolve()
        else (
            "reclaim by changing to the selected workspace and running "
            "'yoetz observe reclaim --workspace .'"
        )
    )
    consent_label = (
        "absent"
        if consent is None
        else (
            "revoked"
            if consent.revoked_at is not None
            else ("paused" if consent.paused else "active")
        )
    )
    advice_payload: dict[str, JsonValue]
    if snapshot is None:
        advice_payload = {"present": False}
    else:
        top = snapshot.ranked_items[0] if snapshot.ranked_items else None
        advice_payload = {
            "present": True,
            "recommended_next_action": snapshot.recommended_next_action,
            "freshness_frontier": snapshot.freshness_frontier,
            "top_summary": None if top is None else top.summary,
            "top_detail": None if top is None else top.detail,
            "top_evidence": None if top is None or not top.evidence_refs else top.evidence_refs[0],
            "finding_ids": tuple(str(item) for item in snapshot.ranked_finding_ids[:8]),
        }
    if json_output:
        _emit(
            {
                "workspace_commitment": commitment,
                "consent": consent_label,
                "content_capture_scope": "ordinary_profiles",
                "codex_hook_capture_scope": "observation_consent",
                "content_capture_profiles": content_profiles,
                "effective_content_capture_profiles": content_facts.effective_profiles,
                "content_capture_enabled": content_facts.enabled,
                "content_capture_consent_active": content_facts.consent_active,
                "content_capture_runtime_enabled": content_facts.runtime_enabled,
                "selection": selection_status,
                "status": observation_status_to_json(status),
                "advice": advice_payload,
                "undelivered_count": undelivered,
                "delivery_causes": delivery_causes,
                "pending_delivery_causes": pending_delivery_causes,
                "oldest_pending_receipt": delivery.oldest_pending_receipt,
                "last_successful_drain": last_drain,
                "quarantine_count": quarantine_depth,
                "quarantine_causes": quarantine_causes,
                "quarantine_evicted_count": quarantine_evicted,
                "quarantine_reclaimed_count": quarantine_reclaimed,
                "mapping_present": mapping_present,
                "hook_diagnostics": diagnostics,
                "summary_refusals": summary_refusals,
                "capture_handoff_retirements": handoff_retirements,
                "plugin_activation": plugin_activation,
            },
            json_output=True,
        )
        return 0
    payload: dict[str, JsonValue] = {
        "workspace_commitment": commitment,
        "consent": consent_label,
        "selection": canonical_encode(selection_status).decode("utf-8"),
        "content_capture_scope": "ordinary profiles; Codex hooks follow observation consent",
        "content_profiles": ",".join(content_profiles) if content_profiles else "none",
        "effective_content_profiles": (
            ",".join(content_facts.effective_profiles)
            if content_facts.effective_profiles
            else "none"
        ),
        "lifecycle": status.lifecycle.value,
        "lag_events": status.lag_events,
        "undelivered": (
            f"{undelivered} (cause: "
            f"{','.join(f'{key}={value}' for key, value in pending_delivery_causes.items()) or 'none'}; "
            f"oldest: {delivery.oldest_pending_receipt or 'none'}; "
            f"last successful drain: {last_drain})"
        ),
        "quarantine": (
            f"{quarantine_depth} (cause: "
            f"{','.join(f'{key}={value}' for key, value in quarantine_causes.items()) or 'none'}; "
            f"evicted: {quarantine_evicted}; "
            f"reclaimed: {quarantine_reclaimed}; "
            f"{reclaim_guidance})"
            if quarantine_depth or quarantine_evicted or quarantine_reclaimed
            else "0"
        ),
        "mapping_present": str(mapping_present),
        "plugin_activation": plugin_activation,
        # The per-pass timing aggregate gets its own readable line; the diagnostics
        # blob keeps its historical content (#915).
        "hook_diagnostics": canonical_encode(
            JsonObject({key: value for key, value in diagnostics.items() if key != "pass_timings"})
        ).decode("utf-8"),
        "hook_pass_timing": hook_pass_timing_text(
            cast(Mapping[str, DomainJsonValue], diagnostics["pass_timings"])
        ),
        "advice_frontier": status.advice_frontier or "none",
        "gaps": ",".join(status.gaps) if status.gaps else "none",
        "summary_refusals": (
            "none"
            if not summary_refusals
            else "; ".join(
                f"{entry.get('source')} generation {entry.get('source_generation')} "
                f"identity {entry.get('source_identity')} position {entry.get('event_position')} "
                f"inputs {entry.get('input_count')} reason {entry.get('reason')} "
                f"({entry.get('disposition')})"
                for entry in summary_refusals[-4:]
            )
        ),
        "capture_handoff_retirements": _capture_handoff_retirement_text(handoff_retirements),
        "hook_coverage": str(status.source_coverage.get(ObservationSource.CODEX_HOOK, False)),
        "stream_coverage": str(
            status.source_coverage.get(ObservationSource.CODEX_SESSION_STREAM, False)
        ),
        "recommendation": ("none" if snapshot is None else snapshot.recommended_next_action),
        "advice_summary": (
            "none"
            if snapshot is None or not snapshot.ranked_items
            else snapshot.ranked_items[0].summary
        ),
    }
    _emit(payload, json_output=False)
    if plugin_activation == "installed_not_activated":
        typer.echo("plugin installed but not activated in Codex — run 'yoetz setup'")
    return 0


_DRAIN_TERMINAL_DRAINED: Final = "drained"
_DRAIN_TERMINAL_RETRY_PENDING: Final = "retry_pending"
_DRAIN_TERMINAL_SERVICE_UNAVAILABLE: Final = "service_unavailable"
_DRAIN_TERMINAL_PASS_LIMIT: Final = "pass_limit"


@dataclass(slots=True)
class _DrainTally:
    control_failed: bool = False
    attempted: int = 0
    acknowledged: int = 0
    retry_pending: int = 0
    quarantined: int = 0
    reasons: dict[str, int] = field(default_factory=dict[str, int])

    def note_reason(self, reason: str, count: int = 1) -> None:
        self.reasons[reason] = self.reasons.get(reason, 0) + count

    def summary(self, *, passes: int, pending_after: int, terminal: str) -> JsonObject:
        return JsonObject(
            {
                "attempted": self.attempted,
                "acknowledged": self.acknowledged,
                "retry_pending": self.retry_pending,
                "quarantined": self.quarantined,
                "reasons": JsonObject(dict(sorted(self.reasons.items()))),
                "passes": passes,
                "pending_after": pending_after,
                "terminal": terminal,
            }
        )


def _collect_deliverable(
    store: LocalObservationStore, workspaces: tuple[str, ...], tally: _DrainTally
) -> list[tuple[str, ObservationOutboxRow]]:
    """Snapshot every pending row, quarantining setup-probe rows on the way."""

    deliverable: list[tuple[str, ObservationOutboxRow]] = []
    for commitment in workspaces:
        for row in store.list_pending_outbox_rows(commitment):
            if row.codex_session_id == _SETUP_PROBE_SESSION:
                if store.quarantine_outbox_row(commitment, row, "setup_probe"):
                    tally.quarantined += 1
                    tally.note_reason("setup_probe")
                continue
            deliverable.append((commitment, row))
    return deliverable


async def _drain_pass(
    store: LocalObservationStore,
    client: _DrainClient,
    deliverable: list[tuple[str, ObservationOutboxRow]],
    tally: _DrainTally,
    *,
    _state: Path | None,
) -> int:
    """Attempt one FIFO pass over the snapshot; return the rows it resolved.

    A retryable rejection retires its lane for the pass (delivering a later
    row of the same session would advance the ingest cursor past the failed
    head, #272), and a workspace-global reason stops that workspace.
    """

    resolved = 0
    retired_lanes: set[tuple[str, str]] = set()
    stopped_workspaces: set[str] = set()
    for commitment, row in deliverable:
        lane = (commitment, row.codex_session_id)
        if commitment in stopped_workspaces or lane in retired_lanes:
            continue
        tally.attempted += 1
        stage = "request_encode"
        try:
            body = observation_ingest_request_to_json(
                ObservationIngestRequest(
                    codex_session_id=row.codex_session_id, envelope=row.envelope
                )
            )
            stage = "control"
            raw = await client.observation_ingest(body, deadline_ms=_DRAIN_DEADLINE_MS)
            stage = "response_decode"
            result = observation_ingest_result_from_json(raw)
        except ControlError as exc:
            result = observation_control_failure(exc)
        except ProtocolValueError, TypeError, ValueError:
            reason = "invalid_request" if stage == "request_encode" else "frame_invalid"
            result = ObservationControlFailure(
                ObservationIngestDisposition.REJECTED,
                "control_" + reason,
                None,
                reason,
                False,
                None,
                stage,
            )
        except Exception:
            result = ObservationIngestResult(
                ObservationIngestDisposition.REJECTED,
                ObservationGapCode.SERVICE_UNAVAILABLE.value,
                None,
            )
        decision = route_observation_ingest(result, row=row)
        updated = store.bump_outbox_row_attempt(commitment, row, reason=decision.reason)
        if updated is None:
            retired_lanes.add(lane)
            continue
        if decision.reason is not None:
            tally.note_reason(decision.reason)
            if decision.reason not in EXPECTED_OBSERVATION_BACKPRESSURE_REASONS:
                store.note_coverage_gap(commitment, decision.reason)
        if decision.action is ObservationDrainAction.RETRY:
            retired_lanes.add(lane)
            if decision.reason == ObservationGapCode.MAPPING_MISSING.value:
                # Terminalization takes the session's lifecycle lock so an
                # attach still persisting its mapping wins (#275). A lock or
                # store failure is this lane's problem only: the rows stay
                # pending for the next run and the other lanes keep draining,
                # as in the hook drain (#554).
                moved = 0
                with contextlib.suppress(Exception):
                    moved = store.quarantine_ended_unmapped_session(
                        commitment,
                        row.codex_session_id,
                        decision.reason,
                    )
                if moved:
                    tally.quarantined += moved
                    resolved += moved
                    continue
            tally.retry_pending += 1
            if decision.reason is not None:
                # Stamp the retired siblings with the shared cause so
                # `observe status` never reports them as not_attempted.
                with contextlib.suppress(Exception):
                    store.note_outbox_session_reason(
                        commitment,
                        row.codex_session_id,
                        decision.reason,
                    )
            if decision.reason in WORKSPACE_GLOBAL_OBSERVATION_STOP_REASONS:
                stopped_workspaces.add(commitment)
        elif decision.action is ObservationDrainAction.QUARANTINE:
            if store.quarantine_outbox_row(
                commitment,
                updated,
                decision.reason or ObservationGapCode.SERVICE_UNAVAILABLE.value,
            ):
                tally.quarantined += 1
                resolved += 1
        elif store.acknowledge_outbox_row(commitment, updated):
            tally.acknowledged += 1
            resolved += 1
        if (
            decision.reason is not None
            and decision.reason not in EXPECTED_OBSERVATION_BACKPRESSURE_REASONS
        ):
            from yoetz.cli.hook_diagnostics import record_drain_failure

            if not record_drain_failure(result, row.envelope, decision.action.value, _state=_state):
                store.note_coverage_gap(commitment, "drain_diagnostic_unavailable")
        if isinstance(result, ObservationControlFailure):
            # The connection is no longer trustworthy for another lane or workspace.
            tally.control_failed = True
            break
    return resolved


async def _drain_observation_async(
    *,
    workspace: str | None,
    _state: Path | None,
    connect: DrainConnector = cast(DrainConnector, connect_service_on_demand),
) -> tuple[int, JsonObject]:
    """Drain to a documented terminal condition without sleeping (#564).

    One pass retires a lane at its first retryable head, so a single pass over
    a busy backlog cleared only the rows ahead of the first back-pressure
    answer and stopped. Passes now repeat while the previous one resolved at
    least one row and rows remain; the pass count is bounded by the backlog
    size at entry, so a still-running producer cannot keep this loop alive.
    ``terminal`` names why the loop ended:

    - ``drained``: no pending row remains in the selected workspaces;
    - ``retry_pending``: a full pass resolved nothing; every remaining lane
      head is retryable and ``reasons`` names why (a check barrier's
      ``operation_pending`` clears when the check completes, ``mapping_missing``
      when the session maps or ends, ``paused``/``vault_locked`` when lifted);
    - ``service_unavailable``: no connection could be opened (exit 20);
    - ``pass_limit``: passes kept resolving rows until the bound, so a producer
      is still adding rows faster than they were listed; run again once it
      stops.
    """

    store = LocalObservationStore(_state=_state)
    if workspace is None:
        workspaces = store.pending_workspaces()
    else:
        workspaces = (store.workspace_commitment(str(_resolve_workspace(workspace))),)
    tally = _DrainTally()
    # READY and the explicit drain command both converge lifecycle intents;
    # SessionStart has no deliverable outbox row of its own.
    for commitment in workspaces:
        with contextlib.suppress(Exception):
            store.reconcile_pending_session_lifecycles(commitment)
    passes = 0
    terminal = _DRAIN_TERMINAL_DRAINED
    client: _DrainClient | None = None
    try:
        deliverable = _collect_deliverable(store, workspaces, tally)
        pass_limit = max(1, len(deliverable))
        while deliverable:
            if client is None:
                try:
                    client = await connect(ControlClientKind.CLI)
                except Exception:
                    tally.note_reason(
                        ObservationGapCode.SERVICE_UNAVAILABLE.value, len(deliverable)
                    )
                    tally.retry_pending += len(deliverable)
                    return 20, tally.summary(
                        passes=passes,
                        pending_after=len(deliverable),
                        terminal=_DRAIN_TERMINAL_SERVICE_UNAVAILABLE,
                    )
            passes += 1
            resolved = await _drain_pass(store, client, deliverable, tally, _state=_state)
            if tally.control_failed or resolved == 0:
                terminal = _DRAIN_TERMINAL_RETRY_PENDING
                break
            if passes >= pass_limit:
                deliverable = _collect_deliverable(store, workspaces, tally)
                if deliverable:
                    terminal = _DRAIN_TERMINAL_PASS_LIMIT
                break
            deliverable = _collect_deliverable(store, workspaces, tally)
    finally:
        if client is not None:
            with contextlib.suppress(Exception):
                await client.close()
    pending_after = sum(store.pending_outbox_count(commitment) for commitment in workspaces)
    if pending_after == 0:
        terminal = _DRAIN_TERMINAL_DRAINED
    return 0, tally.summary(passes=passes, pending_after=pending_after, terminal=terminal)


@_bounded_operation("drain")
def drain_observation(
    *, workspace: str | None, json_output: bool, _state: Path | None = None
) -> int:
    """User-invoked delivery pass; starts the service when necessary."""

    import anyio

    async def run() -> tuple[int, JsonObject]:
        return await _drain_observation_async(workspace=workspace, _state=_state)

    code, summary = anyio.run(run)
    if json_output:
        _emit(summary, json_output=True)
    else:
        typer.echo(
            "observation drain: "
            f"attempted={summary['attempted']} acknowledged={summary['acknowledged']} "
            f"retry_pending={summary['retry_pending']} quarantined={summary['quarantined']} "
            f"passes={summary['passes']} pending_after={summary['pending_after']} "
            f"terminal={summary['terminal']}"
        )
        reasons = summary["reasons"]
        assert isinstance(reasons, Mapping)
        typer.echo(
            "reasons: " + (", ".join(f"{key}={value}" for key, value in reasons.items()) or "none")
        )
    return code


@_bounded_operation("reclaim")
def reclaim_observation(*, workspace: str, json_output: bool, _state: Path | None = None) -> int:
    """Operator-initiated drop of quarantined observation detail (#211).

    Quarantine detail is a diagnostic aid whose only ongoing effect is
    per-hook parse/encode tax; once the underlying delivery failure is fixed,
    this is how a recovered install sheds it. The drop extends the aggregate
    eviction commitment chain and is counted separately from involuntary
    evictions, never silent and never conflated with data loss.
    """

    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    reclaimed = store.reclaim_quarantine(commitment)
    depth, evicted, total_reclaimed = store.quarantine_facts(commitment)
    if json_output:
        _emit(
            {
                "workspace_commitment": commitment,
                "reclaimed": reclaimed,
                "quarantine_count": depth,
                "quarantine_evicted_count": evicted,
                "quarantine_reclaimed_count": total_reclaimed,
            },
            json_output=True,
        )
        return 0
    typer.echo(f"observation_quarantine_reclaimed:{reclaimed} (reclaimed total: {total_reclaimed})")
    return 0


@_bounded_operation("grant")
def grant_observation(*, workspace: str, _state: Path | None = None) -> int:
    store = LocalObservationStore(_state=_state)
    root = _resolve_workspace(workspace)
    commitment = store.workspace_commitment(str(root))
    # A repeated grant keeps already-approved native content arms and the unchanged
    # content fence; only content-disable or revoke removes an arm (issue #835).
    grant = store.grant_consent(commitment)
    # Never log the raw path — only the commitment.
    typer.echo(f"observation_consent_granted:{commitment}")
    kept = grant.consent.content_capture_profiles
    if kept:
        typer.echo(f"observation_content_capture_kept:{','.join(kept)}")
    return 0


@_bounded_operation("content_enable")
def enable_observation_content(
    *, profile: str, workspace: str, _state: Path | None = None, json_output: bool = False
) -> int:
    """Enable one explicit native-host content profile for a consented workspace."""

    validate_content_capture_profile(profile)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    store.enable_content_capture(commitment, profile)
    content_facts = _content_capture_facts(store, commitment)
    if json_output:
        _emit(
            {
                "workspace_commitment": commitment,
                "content_capture_profile": profile,
                "content_capture_scope": "ordinary_profiles",
                "codex_hook_capture_scope": "observation_consent",
                "content_capture_profiles": content_facts.requested_profiles,
                "effective_content_capture_profiles": content_facts.effective_profiles,
                "consent_active": content_facts.consent_active,
                "runtime_enabled": content_facts.runtime_enabled,
                "enabled": content_facts.enabled,
            },
            json_output=True,
        )
    else:
        typer.echo(
            f"observation_content_capture_configured:{profile}:"
            f"effective={'active' if content_facts.enabled else 'inactive'}"
        )
    return 0


@_bounded_operation("content_disable")
def disable_observation_content(
    *,
    workspace: str,
    profile: str | None = None,
    _state: Path | None = None,
    json_output: bool = False,
) -> int:
    """Disable one native-host content profile, or all profiles when omitted."""

    if profile is not None:
        validate_content_capture_profile(profile)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    store.disable_content_capture(commitment, profile)
    content_facts = _content_capture_facts(store, commitment)
    if json_output:
        _emit(
            {
                "workspace_commitment": commitment,
                "content_capture_profile": profile,
                "content_capture_scope": "ordinary_profiles",
                "codex_hook_capture_scope": "observation_consent",
                "content_capture_profiles": content_facts.requested_profiles,
                "effective_content_capture_profiles": content_facts.effective_profiles,
                "consent_active": content_facts.consent_active,
                "runtime_enabled": content_facts.runtime_enabled,
                "enabled": content_facts.enabled,
            },
            json_output=True,
        )
    else:
        typer.echo(
            "observation_content_capture_disabled:" + (profile if profile is not None else "all")
        )
    return 0


@_bounded_operation("content_status")
def observation_content_status(
    *, workspace: str, json_output: bool, _state: Path | None = None
) -> int:
    """Show the exact native-host content arms enabled for a workspace."""

    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    content_facts = _content_capture_facts(store, commitment)
    payload = {
        "workspace_commitment": commitment,
        "content_capture_scope": "ordinary_profiles",
        "codex_hook_capture_scope": "observation_consent",
        "content_capture_profiles": content_facts.requested_profiles,
        "effective_content_capture_profiles": content_facts.effective_profiles,
        "consent_active": content_facts.consent_active,
        "runtime_enabled": content_facts.runtime_enabled,
        "enabled": content_facts.enabled,
    }
    if json_output:
        _emit(payload, json_output=True)
    else:
        typer.echo(
            "observation_content_capture_status:scope=ordinary_profiles; "
            + (", ".join(content_facts.effective_profiles) if content_facts.enabled else "disabled")
            + " (configured: "
            + (
                ", ".join(content_facts.requested_profiles)
                if content_facts.requested_profiles
                else "none"
            )
            + "); Codex hook capture follows observation consent. "
            "This status does not prove captured evidence or AI-powered selection."
        )
    return 0


def _output_token(value: object) -> str:
    return value if is_closed_token(value) else "unknown"


def _output_count(value: object) -> str:
    return str(value) if type(value) is int and value >= 0 else "unknown"


def _effective_budget_line(budget: object) -> str:
    """Render the bounded effective-budget summary; unknown when the store has none."""

    record: Mapping[str, object] = (
        cast(Mapping[str, object], budget) if isinstance(budget, Mapping) else {}
    )
    no_cap_raw = record.get("no_cap")
    no_cap: Mapping[str, object] = (
        cast(Mapping[str, object], no_cap_raw) if isinstance(no_cap_raw, Mapping) else {}
    )
    available = no_cap.get("available")
    no_cap_state = (
        "available"
        if available is True
        else f"unavailable({_output_token(no_cap.get('reason'))})"
        if available is False
        else "unknown"
    )
    return (
        "effective_budget:"
        f"selected={_output_count(record.get('selected_queue_count'))}"
        f"({_output_token(record.get('selected_capacity_label'))}); "
        f"effective={_output_count(record.get('effective_queue_count'))}"
        f"({_output_token(record.get('effective_capacity_label'))}); "
        f"reason={_output_token(record.get('effective_reason'))}; "
        f"limiting={_output_token(record.get('limiting_dimension'))} "
        f"{_output_count(record.get('utilization_bps'))}bps; "
        f"no_cap={no_cap_state}; "
        "lower=yoetz observe selection-revoke or selection-apply --capacity standard; "
        "pause=yoetz observe pause"
    )


@_bounded_operation("selection_status")
def observation_selection_status(
    *,
    workspace: str,
    session_id: str | None = None,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Show selected/effective detail and capacity without changing state."""

    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    payload = selection_status_payload(store, commitment, session_id=session_id)
    if json_output:
        _emit(payload, json_output=True)
    else:
        selected = cast(Mapping[str, JsonValue], payload["selected"])
        effective = cast(Mapping[str, JsonValue], payload["effective"])
        accounting = payload.get("accounting")
        accounting_map: Mapping[str, JsonValue] = (
            cast(Mapping[str, JsonValue], accounting) if isinstance(accounting, Mapping) else {}
        )

        def counter(name: str) -> str:
            value = accounting_map.get(name)
            return str(value) if type(value) is int else "unknown"

        typer.echo(
            "observation_selection_status:"
            f"selected={selected.get('mode')}/{selected.get('capacity_profile')}; "
            f"effective={effective.get('mode')}/{effective.get('capacity_profile')}; "
            f"origin={selected.get('origin')}; reason={payload['effective_reason']}; "
            f"pressure={payload.get('pressure_state', 'unknown')}; "
            "accounting="
            f"observed:{counter('observed_count')},"
            f"admitted:{counter('admitted_input_count')},"
            f"delivered:{counter('delivered_input_count')},"
            f"summarized:{counter('summarized_input_count')},"
            f"omitted:{counter('intentionally_omitted_input_count')},"
            f"unrecoverable:{counter('unrecoverable_input_count')}; "
            "content_authority_unchanged; privacy_authority_unchanged"
        )
        typer.echo(_effective_budget_line(payload.get("effective_budget")))
    return 0


def _selection_cli_scope(
    store: LocalObservationStore,
    *,
    session_id: str | None,
    persist: bool,
) -> tuple[Literal["workspace", "session"], str | None]:
    if persist:
        return "workspace", None
    return "session", _selection_session_commitment(store, session_id)


@_bounded_operation("selection_preview")
def observation_selection_preview(
    *,
    workspace: str,
    detail: str,
    capacity: str,
    queue_count: int | None = None,
    session_id: str | None = None,
    persist: bool = False,
    expires_at: str | None = None,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Preview a detail/capacity choice without changing local state."""

    if persist and session_id is not None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "A workspace selection cannot carry a session id.",
            retryable=False,
        )
    parsed_detail = _selection_detail_from_cli(detail)
    request = _capacity_request_from_cli(capacity, queue_count)
    expiry = _selection_expiry(expires_at)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    scope, session_commitment = _selection_cli_scope(store, session_id=session_id, persist=persist)
    payload = build_selection_preview(
        store,
        commitment,
        detail=parsed_detail,
        capacity=request,
        scope=scope,
        session_commitment=session_commitment,
        expires_at=expiry,
    )
    if json_output:
        _emit(payload, json_output=True)
        return 0
    # The structured disclosure and the current effective budget are rendered
    # as the shared owner sentences and the bounded summary line instead of a
    # raw key/value dump.
    _emit(
        {key: value for key, value in payload.items() if key not in _HUMAN_RECORD_KEYS},
        json_output=False,
    )
    typer.echo(_effective_budget_line(payload.get("current_effective_budget")))
    for line in render_capacity_disclosure_lines(cast(Mapping[str, object], payload["disclosure"])):
        typer.echo(line)
    return 0


@_bounded_operation("selection_apply")
def set_observation_selection(
    *,
    workspace: str,
    detail: str,
    capacity: str,
    queue_count: int | None = None,
    session_id: str | None = None,
    persist: bool = False,
    expires_at: str | None = None,
    accept: bool = False,
    preview_digest: str | None = None,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Apply an owner-selected setting after exact preview-digest acceptance."""

    if persist and session_id is not None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "A workspace selection cannot carry a session id.",
            retryable=False,
        )
    parsed_detail = _selection_detail_from_cli(detail)
    request = _capacity_request_from_cli(capacity, queue_count)
    expiry = _selection_expiry(expires_at)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    scope, session_commitment = _selection_cli_scope(store, session_id=session_id, persist=persist)
    payload = apply_selection_preview(
        store,
        commitment,
        detail=parsed_detail,
        capacity=request,
        scope=scope,
        session_commitment=session_commitment,
        expires_at=expiry,
        preview_digest=preview_digest,
        accept=accept,
    )
    if json_output:
        _emit(payload, json_output=True)
        return 0
    selection = cast(Mapping[str, object], payload["selection"])
    typer.echo(
        "observation_selection_applied:"
        f"scope={scope}; detail={parsed_detail.value}; "
        f"capacity={_output_token(selection.get('capacity_profile'))}"
        f"({_output_count(selection.get('queue_count'))}); "
        "content_authority_unchanged; privacy_authority_unchanged"
    )
    typer.echo(_effective_budget_line(payload.get("effective_budget")))
    disclosure = cast(Mapping[str, object], payload["disclosure"])
    lines = render_capacity_disclosure_lines(disclosure)
    hints = [line for line in lines if line.startswith(("Lower it later with:", "Resume with:"))]
    if not hints:
        hints = [
            f"Revoke it with: {disclosure['revoke_command']}. "
            f"Pause new observation ingest with: {disclosure['pause_command']}.",
            f"Resume with: {disclosure['resume_command']}.",
        ]
    for line in hints:
        typer.echo(line)
    return 0


@_bounded_operation("selection_revoke")
def revoke_observation_selection(
    *,
    workspace: str,
    session_id: str | None = None,
    persist: bool = False,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Revoke one temporary or persisted selection and fall back safely."""

    if persist and session_id is not None:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "A workspace selection cannot carry a session id.",
            retryable=False,
        )
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    if persist:
        settings = store.clear_workspace_selection(commitment)
        scope = "workspace"
        session_commitment = None
    else:
        if session_id is None:
            raise PublicOperationError(
                PublicErrorCode.INVALID_REQUEST,
                "A session id is required to revoke a temporary selection.",
                retryable=False,
            )
        session_commitment = _selection_session_commitment(store, session_id)
        assert session_commitment is not None
        settings = store.clear_session_selection(commitment, session_commitment)
        scope = "session"
    resolution = resolve_observation_selection(
        settings,
        session_commitment=session_commitment,
    )
    payload: Mapping[str, JsonValue] = {
        "workspace_commitment": commitment,
        "scope": scope,
        "session_commitment": session_commitment,
        "revoked": True,
        "fallback": _selection_resolution_payload(resolution),
        "content_authority_changed": False,
        "privacy_authority_changed": False,
    }
    _emit(payload, json_output=json_output)
    return 0


@_bounded_operation("protect_read")
def protect_observation_read(
    *,
    workspace: str,
    session_id: str,
    reference: str,
    count: int = 1,
    expires_at: str | None = None,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Protect the next bounded read identities for one active session.

    This is a narrowing hint for early selection.  It does not grant native
    content capture, privacy egress, or a provider route; the admission owner
    still checks the current consent and authority generation.
    """

    if type(count) is not int or not 1 <= count <= 32:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Read protection count is outside its bound.",
            retryable=False,
        )
    if type(reference) is not str or not reference:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Read protection reference is invalid.",
            retryable=False,
        )
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    session_commitment = _selection_session_commitment(store, session_id)
    assert session_commitment is not None
    expiry = _selection_expiry(expires_at)
    protect = getattr(store, "protect_next_reads", None)
    if not callable(protect):
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Read protection is unavailable.",
            retryable=False,
        )
    try:
        result = protect(
            commitment,
            session_commitment,
            reference,
            count=count,
            expires_at=expiry,
        )
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Read protection request is invalid.",
            retryable=False,
        ) from exc
    if isinstance(result, Mapping):
        payload: Mapping[str, JsonValue] = cast(Mapping[str, JsonValue], result)
    else:
        payload = {
            "workspace_commitment": commitment,
            "session_commitment": session_commitment,
            "reference": reference,
            "count": count,
            "expires_at": None if expiry is None else expiry.wire,
            "protected": True,
        }
    _emit(
        {
            **dict(payload),
            "content_authority_changed": False,
            "privacy_authority_changed": False,
        },
        json_output=json_output,
    )
    return 0


@_bounded_operation("promote")
def promote_observation(
    *,
    workspace: str,
    source_identity: str,
    json_output: bool = False,
    _state: Path | None = None,
) -> int:
    """Promote retained native identity metadata when it is still available."""

    if type(source_identity) is not str or not source_identity:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation source identity is invalid.",
            retryable=False,
        )
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    promote = getattr(store, "promote_buffered_observation", None)
    if not callable(promote):
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation promotion is unavailable.",
            retryable=False,
        )
    try:
        result = promote(commitment, source_identity)
    except (ProtocolValueError, TypeError, ValueError) as exc:
        raise PublicOperationError(
            PublicErrorCode.INVALID_REQUEST,
            "Observation promotion request is invalid.",
            retryable=False,
        ) from exc
    if isinstance(result, Mapping):
        payload: Mapping[str, JsonValue] = cast(Mapping[str, JsonValue], result)
    else:
        payload = {
            "workspace_commitment": commitment,
            "source_identity": source_identity,
            "promoted": bool(result),
        }
    _emit(payload, json_output=json_output)
    return 0


@_bounded_operation("pause")
def pause_observation(*, workspace: str, _state: Path | None = None) -> int:
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    status = store.pause(ObservationControlCommand(commitment))
    typer.echo(f"observation_paused:{status.lifecycle.value}")
    return 0


@_bounded_operation("resume")
def resume_observation(*, workspace: str, _state: Path | None = None) -> int:
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    status = store.resume(ObservationControlCommand(commitment))
    typer.echo(f"observation_resumed:{status.lifecycle.value}")
    return 0


@_bounded_operation("revoke")
def revoke_observation(*, workspace: str, _state: Path | None = None) -> int:
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(_resolve_workspace(workspace)))
    status = store.revoke(ObservationRevokeCommand(commitment, retain_evidence=True))
    typer.echo(f"observation_revoked:{status.lifecycle.value}:evidence_retained")
    return 0


def _check_policy_context(workspace: str | None, *, _state: Path | None):
    root = _resolve_workspace(workspace)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(root))
    policy, _raw = load_observation_check_policy(root)
    return root, commitment, store, policy


# Approved workspace checks are an optional owner feature. A workspace without
# `.yoetz/checks.toml` is "not configured", never an invalid policy. Configuring or trusting a
# policy is the owner's choice and no finding asks the agent for it, so a policy-route failure is
# never a reason to stop or a `yoetz-blocker`; the continuation says so in fixed text, in the same
# order as every other blocker text (#984): repair first, a Yoetz limit is self-verified and
# answered `self_verified`, `acknowledged_not_done` is the last resort, and `yoetz-blocker` is only
# for an open obligation genuinely blocked outside the agent's control.
_CHECK_POLICY_NOT_CONFIGURED: Final = "not_configured"
_CHECK_POLICY_CONTINUATION: Final = (
    "Approved workspace checks are optional owner configuration (.yoetz/checks.toml); no "
    "finding asks you to configure or trust them. This is a Yoetz limit, not a task blocker: "
    "never record a yoetz-blocker for it. Finish and verify the task yourself; if a finding "
    "stays unresolved only because Yoetz cannot prove your repair, record your evidence and "
    "respond self_verified. The receipt discloses what Yoetz could not prove."
)


def _check_policy_failure(operation: str, error: BaseException) -> int:
    if isinstance(error, ObservationCheckPolicyAbsent):
        reason = "policy_not_configured"
    elif (
        isinstance(error, ProtocolValueError)
        and error.reason_code == "invalid_approved_check_policy"
    ):
        reason = "invalid_policy"
    else:
        # Workspace, store, or other local faults are not policy faults; name them neutrally.
        typer.echo(f"observation_checks_{operation}_failed:unavailable", err=True)
        return 20
    typer.echo(f"observation_checks_{operation}_failed:{reason}", err=True)
    typer.echo(_CHECK_POLICY_CONTINUATION, err=True)
    return 20


def observe_checks_preview(
    *, workspace: str | None, json_output: bool, _state: Path | None = None
) -> int:
    try:
        _root, commitment, store, policy = _check_policy_context(workspace, _state=_state)
    except Exception as error:
        return _check_policy_failure("preview", error)
    checks = tuple(
        {
            "id": item.approval_id,
            "argv": item.argv,
            "timeout_seconds": int(item.timeout_seconds),
            "network": item.allow_network,
            "approval_commitment": item.approval_commitment,
        }
        for item in policy.checks
    )
    _emit(
        {
            "workspace_commitment": commitment,
            "policy_digest": policy.raw_digest,
            "trusted": store.policy_digest_is_trusted(commitment, policy.raw_digest),
            "checks": checks,
        },
        json_output=json_output,
    )
    return 0


def observe_checks_trust(
    *,
    workspace: str | None,
    policy_digest: str,
    _state: Path | None = None,
) -> int:
    try:
        _root, commitment, store, policy = _check_policy_context(workspace, _state=_state)
    except Exception as error:
        return _check_policy_failure("trust", error)
    if policy_digest != policy.raw_digest:
        typer.echo("observation_checks_trust_failed:digest_mismatch", err=True)
        return 20
    store.trust_policy_digest(commitment, policy.raw_digest)
    typer.echo(f"observation_checks_trusted:{policy.raw_digest}")
    return 0


def observe_checks_status(
    *, workspace: str | None, json_output: bool, _state: Path | None = None
) -> int:
    try:
        root = _resolve_workspace(workspace)
        store = LocalObservationStore(_state=_state)
        commitment = store.workspace_commitment(str(root))
    except Exception as error:
        return _check_policy_failure("status", error)
    try:
        policy, _raw = load_observation_check_policy(root)
    except ObservationCheckPolicyAbsent:
        policy = None
    except Exception as error:
        return _check_policy_failure("status", error)
    if policy is None:
        # Absence is the ordinary state of an opt-in feature: report it, do not fail.
        _emit(
            {
                "workspace_commitment": commitment,
                "policy_digest": None,
                "state": _CHECK_POLICY_NOT_CONFIGURED,
                "sandbox": probe_check_sandbox().as_json(),
                "executable_checks": (),
                "network_check_state": "not_requested",
                "note": _CHECK_POLICY_CONTINUATION,
            },
            json_output=json_output,
        )
        return 0
    trusted = store.policy_digest_is_trusted(commitment, policy.raw_digest)
    _emit(
        {
            "workspace_commitment": commitment,
            "policy_digest": policy.raw_digest,
            "state": "trusted" if trusted else "untrusted",
            # Host-level answer, named once here rather than per rejected run (issue #720).
            "sandbox": probe_check_sandbox().as_json(),
            "executable_checks": (
                tuple(item.approval_id for item in policy.checks if not item.allow_network)
                if trusted
                else ()
            ),
            "network_check_state": (
                ObservationGapCode.NETWORK_CHECK_UNSUPPORTED.value
                if any(item.allow_network for item in policy.checks)
                else "not_requested"
            ),
        },
        json_output=json_output,
    )
    return 0


def observe_checks_revoke(*, workspace: str | None, _state: Path | None = None) -> int:
    root = _resolve_workspace(workspace)
    store = LocalObservationStore(_state=_state)
    commitment = store.workspace_commitment(str(root))
    store.revoke_policy_trust(commitment)
    typer.echo("observation_checks_revoked")
    return 0


def observe_checks_run(
    *, workspace: str | None, json_output: bool, _state: Path | None = None
) -> int:
    try:
        root, commitment, store, policy = _check_policy_context(workspace, _state=_state)
    except Exception as error:
        return _check_policy_failure("run", error)
    try:
        if not store.policy_digest_is_trusted(commitment, policy.raw_digest):
            store.note_coverage_gap(commitment, ObservationGapCode.POLICY_UNTRUSTED.value)
            typer.echo("observation_checks_run_failed:policy_untrusted", err=True)
            return 20
        handle = open_local_workspace(root)
        capture = GitSubjectStateAdapter()

        def subject_digest(_handle: object) -> str:
            result = capture.capture(
                SubjectStateCaptureCommand(handle, SubjectStateFormat.GIT_STRUCTURAL_V1)
            )
            if result.subject_state is None:
                raise ValueError("subject_state_unavailable")
            return canonical_digest(
                {
                    "tree_digest": result.subject_state.tree_digest,
                    "diff_digest": result.subject_state.diff_digest,
                }
            )

        expected = subject_digest(handle)
        runner = ApprovedCheckRunner({item.approval_commitment: item for item in policy.checks})
        results: list[dict[str, JsonValue]] = []
        for index, approval in enumerate(policy.checks, 1):
            result, fact = run_bound_approved_check(
                runner=runner,
                workspace=handle,
                approval=approval,
                expected_subject_state_digest=expected,
                capture_subject_state=subject_digest,
                cursor_event_position=index,
            )
            if result.outcome.value == "network_denied":
                store.note_coverage_gap(
                    commitment, ObservationGapCode.NETWORK_CHECK_UNSUPPORTED.value
                )
            results.append(
                {
                    "id": approval.approval_id,
                    "status": result.status.value,
                    "outcome": result.outcome.value,
                    "result_digest": result.result_digest,
                    "output_digest": result.output_digest,
                    "output_bytes": result.output_bytes,
                    "is_current": False if fact is None else fact.is_current,
                }
            )
        _emit(
            {
                "workspace_commitment": commitment,
                "policy_digest": policy.raw_digest,
                "subject_state_digest": expected,
                "results": tuple(results),
            },
            json_output=json_output,
        )
        return 0 if all(item["status"] == "passed" for item in results) else 20
    except Exception:
        typer.echo("observation_checks_run_failed:unavailable", err=True)
        return 20


@_bounded_operation("reconcile")
def reconcile_session_stream(
    *,
    session_file: str,
    workspace: str | None,
    json_output: bool,
    _state: Path | None = None,
) -> int:
    """Manual recovery/diagnostic reconcile; automatic reconcile is hook-driven."""

    store = LocalObservationStore(_state=_state)
    root = _resolve_workspace(workspace)
    workspace_commitment = store.workspace_commitment(str(root))
    consent = store.consent_for(workspace_commitment)
    if consent is None or not consent.active:
        typer.echo("observation_reconcile_failed:consent_missing", err=True)
        return 20
    path = Path(session_file)
    if not path.is_file() or path.is_symlink():
        typer.echo("observation_reconcile_failed:session_file_unreadable", err=True)
        return 20
    # Prefer the full host id from one durable lifecycle mapping. Native rollout filenames
    # include hyphenated UUIDs; suffix splitting would orphan the mapped session. Unmapped
    # explicit paths retain the established opaque-token recovery behavior.
    session_token = _mapped_session_id_from_path(
        path,
        store=store,
        workspace_commitment=workspace_commitment,
        state_root=_state,
    )
    if session_token is None:
        child = _child_rollout_route(
            path,
            store=store,
            workspace_commitment=workspace_commitment,
            state_root=_state,
        )
        if child.reason is not None:
            typer.echo(
                f"observation_reconcile_failed:{child.reason}: "
                f"{_CHILD_ROUTE_REFUSALS[child.reason]}",
                err=True,
            )
            return 20
        if child.lane is not None:
            # The child's own rollout drains to its validated child lane, sharing the cursor,
            # profile, and pairing persistence the automatic child-lane reconcile uses. Its
            # header is then the child-observed delegation signal that binds the parent's
            # provisional annotation to this child under admitted catalog lineage.
            session_commitment = store.bind_codex_session(workspace_commitment, child.lane)
            payload = reconcile_session_stream_path(
                store,
                workspace_commitment=workspace_commitment,
                session_commitment=session_commitment,
                codex_session_id=child.lane,
                path=path,
            )
            _emit({**payload, "mode": "recovery_child_lane"}, json_output=json_output)
            return 0
        if path.stem.startswith("rollout-"):
            typer.echo("observation_reconcile_failed:mapping_missing", err=True)
            return 20
        session_token = path.stem if path.stem else "session"
        if "-" in session_token:
            session_token = session_token.rsplit("-", 1)[-1] or session_token
    session_commitment = store.session_commitment(session_token[:128])
    store.bind_session(workspace_commitment, session_commitment)
    locator = CodexSessionStreamLocator(resolve_codex_home())
    validated = locator.resolve(session_id=session_token[:128], hook_provided_path=str(path))
    if validated is not None:
        payload = advance_session_stream(
            store,
            workspace_commitment=workspace_commitment,
            session_commitment=session_commitment,
            codex_session_id=session_token[:128],
            locator=locator,
            hook_provided_path=str(validated),
        )
        payload = {**payload, "mode": "locator"}
        _emit(payload, json_output=json_output)
        return 0
    # Explicit recovery shares cursor/profile, source identity, and pairing persistence with
    # locator-driven reconciliation, including blocked delivery and mapping upgrades.
    payload = reconcile_session_stream_path(
        store,
        workspace_commitment=workspace_commitment,
        session_commitment=session_commitment,
        codex_session_id=session_token[:128],
        path=path,
    )
    payload = {**payload, "mode": "recovery_explicit_path"}
    _emit(payload, json_output=json_output)
    return 0
